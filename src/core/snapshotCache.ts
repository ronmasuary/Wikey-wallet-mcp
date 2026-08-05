// Server-side snapshot store + bounded query (B2 / H14).
//
// HARD INVARIANT: raw safe/profile snapshot JSON NEVER crosses the tool
// boundary. `wallet-cli query snapshot` runs inside the server; we parse + cache
// it here and only ever return byte-budgeted, derived answers. The boundary is
// SIZE-bounded, not shape-bounded: every field stays reachable (via `fields` /
// object()), and any cut — dropped rows or dropped fields — is explicitly
// reported ({truncated,total,returned,nextOffset} / omittedFields), never
// silent. A host that silently truncates a large tool result can therefore
// never feed the model a corrupted snapshot.
//
// Storage is in-memory (the MCP server is long-lived): last-N snapshots + a TTL
// + a total-bytes heap cap.

import {
  parseSnapshot,
  rowsOfClass,
  type NestedObject,
  type ParsedSnapshot,
  type SnapshotGroup,
} from './snapshot.js';

export interface SafeIndexEntry {
  address: string;
  name: string;
  /** nestedObject count per class, across all groups (incl. deleted). */
  counts: Record<string, number>;
}

export interface SnapshotIndex {
  snapshotId: string;
  /** profile address the snapshot was taken for (data.address). */
  address: string;
  /** byte length of the raw JSON (never returned, just reported). */
  bytes: number;
  ts: number;
  safes: SafeIndexEntry[];
  /**
   * Discoverability: class → sorted union of object payload keys seen across
   * ALL safes (field NAMES only, never values). Tells the model which fields
   * it can request via wallet_snapshot_object / the query `fields` param
   * without guessing. Top-level (not per-safe) — the map is near-identical
   * per safe and would only bloat the index.
   */
  fields: Record<string, string[]>;
  /**
   * Node-level keys requestable via `fields` on top of the payload map above —
   * always SIBLING_FIELDS, so it is listed once here rather than merged into
   * every class array. Kept a separate namespace on purpose: payload wins on a
   * name clash (see selectFields), e.g. `policy` carries its own `name` payload
   * key, so `fields:['name']` on a policy returns that and never the sibling.
   * A merged per-class list could not express that difference.
   */
  siblings: string[];
}

/**
 * Field selection for query/page rows: explicit object payload keys, or '*'
 * for all of them (budget permitting). Omitted → the default 8-field summary
 * row, byte-identical to the historical shape.
 */
export type FieldSelector = string[] | '*';

/**
 * Node-level siblings of `object` (see snapshot.ts). They are NOT payload keys,
 * so `fields:'*'` — which means "the whole object payload" — does not include
 * them; they must be named explicitly. `process` carries the governance state
 * (`process.currentPhase`), which is why naming it must be possible: it is the
 * single largest thing on a typical transaction and therefore the first field
 * the budget drops, and a narrowed request is the only way to get it back.
 */
export const SIBLING_FIELDS = ['process', 'name', 'isValid'] as const;

/** Target of a `fields` selection — the shape shared by rows and object reads. */
interface Selectable {
  object?: Record<string, unknown>;
  process?: Record<string, unknown>;
  name?: string;
  isValid?: boolean;
  unknownFields?: string[];
}

/**
 * Write the selected payload keys and siblings of `node` onto `target`.
 * `'*'` selects the whole payload; siblings must always be named explicitly.
 * A requested key the node does not carry goes to `unknownFields` — so an
 * empty `object` can never be mistaken for "the field exists but is empty".
 */
function selectFields(target: Selectable, node: NestedObject, fields: FieldSelector): void {
  const keys = fields === '*' ? Object.keys(node.object) : fields;
  const object: Record<string, unknown> = {};
  const unknown: string[] = [];
  for (const k of keys) {
    if (k in node.object) {
      object[k] = node.object[k]; // copy — never expose the cached parse to mutation
    } else if (k === 'process' && node.process !== undefined) {
      target.process = { ...node.process };
    } else if (k === 'name' && node.name !== undefined) {
      target.name = node.name;
    } else if (k === 'isValid' && node.isValid !== undefined) {
      target.isValid = node.isValid;
    } else {
      unknown.push(k);
    }
  }
  target.object = object;
  if (unknown.length > 0) target.unknownFields = unknown;
}

export interface SnapshotRow {
  safe: string;
  group: string;
  groupName: string;
  class: string;
  id: string;
  isDeleted: boolean;
  parentGroup: string;
  SIGNATURE: string;
  /** Selected object payload keys (only when `fields` was requested). Nested
   * so a payload field named `id`/`class` can never collide with the row's own. */
  object?: Record<string, unknown>;
  /** Siblings, present only when named in `fields`. */
  process?: Record<string, unknown>;
  name?: string;
  isValid?: boolean;
  /** Fields dropped from `object` to fit the byte budget — always named. */
  omittedFields?: OmittedField[];
  /** Requested keys this object does not have — so an empty result is never
   * mistakable for "the field exists but is empty". */
  unknownFields?: string[];
}

export interface QueryFilter {
  safe?: string;
  class?: string;
  id?: string;
  isDeleted?: boolean;
  parentGroup?: string;
}

export interface QueryResult {
  rows: SnapshotRow[];
  total: number;
  returned: number;
  truncated: boolean;
  nextOffset?: number;
}

export interface PageResult {
  rows: SnapshotRow[];
  offset: number;
  limit: number;
  /** Rows actually returned — may be fewer than the slice when wide rows hit the byte budget. */
  returned: number;
  total: number;
  truncated: boolean;
}

/** A field dropped to fit the byte budget — a dropped field is ALWAYS named. */
export interface OmittedField {
  key: string;
  bytes: number;
}

/** Complete single-object read: full object payload + parser-preserved siblings. */
export interface ObjectResult {
  safe: string;
  group: string;
  groupName: string;
  class: string;
  id: string;
  isDeleted: boolean;
  name?: string;
  isValid?: boolean;
  process?: Record<string, unknown>;
  object: Record<string, unknown>;
  omittedFields?: OmittedField[];
  /** Requested keys this object does not have (only when `fields` was used). */
  unknownFields?: string[];
}

interface CacheEntry {
  parsed: ParsedSnapshot;
  address: string;
  bytes: number;
  ts: number;
}

export interface SnapshotCacheOpts {
  maxResultBytes?: number;
  ttlMs?: number;
  max?: number;
  /** Heap guard: total raw bytes across cached snapshots (proxy for parse size).
   * Oldest evicted first; the newest entry is always kept. Default 64 MB. */
  maxTotalBytes?: number;
}

export class SnapshotCache {
  private readonly maxResultBytes: number;
  private readonly ttlMs: number;
  private readonly max: number;
  private readonly maxTotalBytes: number;
  private readonly store = new Map<string, CacheEntry>();
  private counter = 0;

  constructor(opts: SnapshotCacheOpts = {}) {
    // Default conservatively below the smallest known host limit
    // (ragent MAX_TOOL_RESULT_CHARS=6000) — 4 KB.
    this.maxResultBytes = opts.maxResultBytes ?? 4096;
    this.ttlMs = opts.ttlMs ?? 15 * 60 * 1000;
    this.max = opts.max ?? 3;
    this.maxTotalBytes = opts.maxTotalBytes ?? 64 * 1024 * 1024;
  }

  /** Parse + cache a raw snapshot; return ONLY the small index. */
  ingest(raw: string, now = Date.now()): SnapshotIndex {
    const parsed = parseSnapshot(raw);
    const address = extractProfileAddress(raw);
    const id = `snap-${++this.counter}`;
    this.store.set(id, { parsed, address, bytes: Buffer.byteLength(raw), ts: now });
    this.evict(now);
    return this.indexOf(id)!;
  }

  /** Build the small index for a cached snapshot. */
  private indexOf(id: string): SnapshotIndex | null {
    const e = this.store.get(id);
    if (!e) return null;
    // class → union of object payload keys (names only — H14: never values).
    const fieldSets: Record<string, Set<string>> = {};
    const safes: SafeIndexEntry[] = e.parsed.safes.map((safe) => {
      const counts: Record<string, number> = {};
      for (const g of safe.groups) {
        for (const n of g.nestedObjects) {
          counts[n.class] = (counts[n.class] ?? 0) + 1;
          const set = (fieldSets[n.class] ??= new Set());
          for (const key of Object.keys(n.object)) set.add(key);
        }
      }
      return { address: safe.address, name: safe.name, counts };
    });
    const fields: Record<string, string[]> = {};
    for (const cls of Object.keys(fieldSets).sort()) {
      fields[cls] = [...fieldSets[cls]!].sort();
    }
    return {
      snapshotId: id,
      address: e.address,
      bytes: e.bytes,
      ts: e.ts,
      safes,
      fields,
      siblings: [...SIBLING_FIELDS],
    };
  }

  private evict(now: number): void {
    // Drop expired first.
    for (const [id, e] of this.store) {
      if (now - e.ts > this.ttlMs) this.store.delete(id);
    }
    // Then enforce last-N (Map preserves insertion order).
    while (this.store.size > this.max) {
      const oldest = this.store.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.store.delete(oldest);
    }
    // Heap guard: snapshots grow with on-chain history, so a count cap alone is
    // unbounded. Evict oldest while total raw bytes (proxy for the retained
    // parse) exceed the cap — but always keep the newest entry.
    const totalBytes = () => [...this.store.values()].reduce((sum, e) => sum + e.bytes, 0);
    while (this.store.size > 1 && totalBytes() > this.maxTotalBytes) {
      const oldest = this.store.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.store.delete(oldest);
    }
  }

  private get(id: string, now = Date.now()): CacheEntry {
    const e = this.store.get(id);
    if (!e) {
      throw new Error(
        `snapshotId "${id}" not found (expired or evicted; cache holds last ${this.max}, TTL ${Math.round(this.ttlMs / 60000)}m). Call wallet_snapshot again.`,
      );
    }
    if (now - e.ts > this.ttlMs) {
      this.store.delete(id);
      throw new Error(`snapshotId "${id}" expired (TTL ${Math.round(this.ttlMs / 60000)}m). Call wallet_snapshot again.`);
    }
    return e;
  }

  /**
   * Single projection site for query() and page(). Without `fields`: the exact
   * historical 8-field summary row (byte-identical). With `fields`: the picked
   * object payload keys nested under `object:`; each row is individually
   * trimmed to the byte budget so no single row can exceed it (dropped keys
   * are named in the row's omittedFields).
   */
  private projectRow(
    safeAddress: string,
    group: SnapshotGroup,
    node: NestedObject,
    fields?: FieldSelector,
  ): SnapshotRow {
    const row: SnapshotRow = {
      safe: safeAddress,
      group: group.id,
      groupName: group.name,
      class: node.class,
      id: node.id,
      isDeleted: node.isDeleted,
      parentGroup: node.object.parentGroup,
      SIGNATURE: node.object.SIGNATURE,
    };
    if (fields !== undefined) {
      selectFields(row, node, fields);
      // Headroom (16 B) for the surrounding array/result envelope so a lone
      // max-size row still leaves the whole response under budget.
      this.trimToBudget(row as SnapshotRow & { object: Record<string, unknown> }, this.maxResultBytes - 16);
    }
    return row;
  }

  private allRows(entry: CacheEntry, filter: QueryFilter = {}, fields?: FieldSelector): SnapshotRow[] {
    const rows: SnapshotRow[] = [];
    for (const safe of entry.parsed.safes) {
      if (filter.safe && safe.address !== filter.safe) continue;
      for (const group of safe.groups) {
        for (const node of group.nestedObjects) {
          if (filter.class && node.class !== filter.class) continue;
          if (filter.id && node.id !== filter.id) continue;
          if (filter.isDeleted !== undefined && node.isDeleted !== filter.isDeleted) continue;
          if (filter.parentGroup && node.object.parentGroup !== filter.parentGroup) continue;
          rows.push(this.projectRow(safe.address, group, node, fields));
        }
      }
    }
    return rows;
  }

  /**
   * Filtered query, byte-budgeted. A point lookup ({id}) is complete in ROW
   * COUNT (it is small — the delete-user/delete-policy path); when `fields`
   * widens the rows, per-row trimming may still drop payload keys, each named
   * in the row's omittedFields. A broad match returns as many rows as fit
   * under maxResultBytes plus explicit {truncated,total,returned,nextOffset}
   * — never a silent cut.
   */
  query(id: string, filter: QueryFilter = {}, fields?: FieldSelector, now = Date.now()): QueryResult {
    const entry = this.get(id, now);
    const all = this.allRows(entry, filter, fields);
    const total = all.length;

    // Point lookup: all matching rows are returned. Without `fields` the rows
    // are tiny summary rows; with `fields` each row is already trimmed to the
    // budget (omittedFields), so this can never return an unbounded blob.
    if (filter.id) {
      return { rows: all, total, returned: all.length, truncated: false };
    }

    const { rows, returned } = this.budget(all);
    const truncated = returned < total;
    return {
      rows,
      total,
      returned,
      truncated,
      ...(truncated ? { nextOffset: returned } : {}),
    };
  }

  /**
   * Complete single-object read: the FULL object payload plus the siblings the
   * parser preserves (name, isValid, process — i.e. governance state). Point
   * lookup by id, first match wins (Phase 1a invariant: id is unique per
   * group-membership); optional safe narrows the search. Byte-bounded: if the
   * serialized result exceeds maxResultBytes, the largest values are dropped
   * first and each is NAMED in omittedFields — never a silent cut (H14).
   *
   * `opts.fields` NARROWS the read to the named payload keys and/or siblings
   * (see SIBLING_FIELDS). This is the recovery path for a field the budget
   * dropped from the full read: the whole object may not fit, but one field
   * almost always does. Asking for less is how you get more.
   */
  object(
    id: string,
    objectId: string,
    opts: { safe?: string; fields?: FieldSelector } = {},
    now = Date.now(),
  ): ObjectResult {
    const entry = this.get(id, now);
    for (const safe of entry.parsed.safes) {
      if (opts.safe && safe.address !== opts.safe) continue;
      for (const group of safe.groups) {
        for (const node of group.nestedObjects) {
          if (node.id !== objectId) continue;
          const result: ObjectResult = {
            safe: safe.address,
            group: group.id,
            groupName: group.name,
            class: node.class,
            id: node.id,
            isDeleted: node.isDeleted,
            object: {},
          };
          if (opts.fields !== undefined) {
            selectFields(result, node, opts.fields);
          } else {
            // copies — trimming must never mutate the cached parse
            result.object = { ...node.object };
            if (node.name !== undefined) result.name = node.name;
            if (node.isValid !== undefined) result.isValid = node.isValid;
            if (node.process !== undefined) result.process = { ...node.process };
          }
          return this.trimToBudget(result);
        }
      }
    }
    // Bounded not-found error: class counts, never an id dump (real snapshots
    // hold 1000+ objects).
    const counts: Record<string, number> = {};
    for (const safe of entry.parsed.safes) {
      if (opts.safe && safe.address !== opts.safe) continue;
      for (const group of safe.groups) {
        for (const node of group.nestedObjects) counts[node.class] = (counts[node.class] ?? 0) + 1;
      }
    }
    const summary = Object.entries(counts)
      .map(([cls, n]) => `${cls}:${n}`)
      .join(', ');
    throw new Error(
      `object ${objectId} not found in snapshot ${id}${opts.safe ? ` (safe ${opts.safe})` : ''}. ` +
        `Objects present: {${summary}}. Use wallet_snapshot_query to enumerate ids.`,
    );
  }

  /**
   * Fit a single-object result under the byte budget by dropping the largest
   * values first (object payload entries, then the process sibling). Every
   * dropped field is named in omittedFields with its serialized size.
   */
  private trimToBudget<T extends { object: Record<string, unknown>; process?: Record<string, unknown>; omittedFields?: OmittedField[] }>(
    result: T,
    maxBytes = this.maxResultBytes,
  ): T {
    const size = () => Buffer.byteLength(JSON.stringify(result));
    if (size() <= maxBytes) return result;

    const bytesOf = (v: unknown) => Buffer.byteLength(JSON.stringify(v) ?? 'null');
    const candidates: { key: string; bytes: number; drop: () => void }[] = Object.entries(result.object).map(
      ([key, v]) => ({ key, bytes: bytesOf(v), drop: () => delete result.object[key] }),
    );
    if (result.process !== undefined) {
      candidates.push({ key: 'process', bytes: bytesOf(result.process), drop: () => delete result.process });
    }
    // Deterministic: largest first, then key order.
    candidates.sort((a, b) => b.bytes - a.bytes || (a.key < b.key ? -1 : 1));

    const omitted: OmittedField[] = (result.omittedFields ??= []);
    for (const c of candidates) {
      if (size() <= maxBytes) break;
      c.drop();
      omitted.push({ key: c.key, bytes: c.bytes });
    }
    return result;
  }

  /**
   * Explicit pagination for a (safe, class) over offset/limit. The slice is
   * additionally byte-budgeted (wide `fields` rows can exceed what a row count
   * alone would bound): `returned` may be < the slice, and truncated reflects
   * both cuts — never a silent one.
   */
  page(
    id: string,
    safe: string,
    cls: string,
    offset: number,
    limit: number,
    fields?: FieldSelector,
    now = Date.now(),
  ): PageResult {
    const entry = this.get(id, now);
    const matchSafe = entry.parsed.safes.find((s) => s.address === safe);
    if (!matchSafe) {
      throw new Error(
        `safe ${safe} not in snapshot ${id}. Available: ${entry.parsed.safes.map((s) => s.address).join(', ')}`,
      );
    }
    const all = rowsOfClass(matchSafe, cls).map(({ node, group }) =>
      this.projectRow(matchSafe.address, group, node, fields),
    );
    const total = all.length;
    const slice = all.slice(offset, offset + limit);
    const { rows, returned } = this.budget(slice);
    return {
      rows,
      offset,
      limit,
      returned,
      total,
      truncated: offset + returned < total,
    };
  }

  /** Greedily take rows while the serialized array stays under the budget. */
  private budget(all: SnapshotRow[]): { rows: SnapshotRow[]; returned: number } {
    const rows: SnapshotRow[] = [];
    let size = 2; // for "[]"
    for (const row of all) {
      // bytes, not chars — payload values selected via `fields` may be non-ASCII
      const rowSize = Buffer.byteLength(JSON.stringify(row)) + 1; // +1 for the comma
      if (rows.length > 0 && size + rowSize > this.maxResultBytes) break;
      rows.push(row);
      size += rowSize;
    }
    return { rows, returned: rows.length };
  }
}

// data.address — the profile the snapshot was taken for. Tolerant of the URL
// line prefix and envelope variants.
function extractProfileAddress(raw: string): string {
  try {
    const start = raw.search(/[[{]/);
    const body = start >= 0 ? raw.slice(start) : raw;
    const parsed = JSON.parse(body) as { data?: { address?: unknown }; address?: unknown };
    const addr = parsed?.data?.address ?? parsed?.address;
    return typeof addr === 'string' ? addr : '';
  } catch {
    return '';
  }
}
