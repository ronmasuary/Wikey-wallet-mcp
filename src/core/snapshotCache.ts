// Server-side snapshot store + bounded query (B2 / H14).
//
// HARD INVARIANT: raw safe/profile snapshot JSON NEVER crosses the tool
// boundary. `wallet-cli query snapshot` runs inside the server; we parse + cache
// it here and only ever return small, byte-budgeted, complete-or-explicitly-
// paged derived answers. A host that silently truncates a large tool result can
// therefore never feed the model a corrupted snapshot.
//
// Storage is in-memory (the MCP server is long-lived): last-N snapshots + a TTL.

import { parseSnapshot, rowsOfClass, type ParsedSnapshot } from './snapshot.js';

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
  total: number;
  truncated: boolean;
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
}

export class SnapshotCache {
  private readonly maxResultBytes: number;
  private readonly ttlMs: number;
  private readonly max: number;
  private readonly store = new Map<string, CacheEntry>();
  private counter = 0;

  constructor(opts: SnapshotCacheOpts = {}) {
    // Default conservatively below the smallest known host limit
    // (ragent MAX_TOOL_RESULT_CHARS=6000) — 4 KB.
    this.maxResultBytes = opts.maxResultBytes ?? 4096;
    this.ttlMs = opts.ttlMs ?? 15 * 60 * 1000;
    this.max = opts.max ?? 3;
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
    return { snapshotId: id, address: e.address, bytes: e.bytes, ts: e.ts, safes, fields };
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

  private allRows(entry: CacheEntry, filter: QueryFilter = {}): SnapshotRow[] {
    const rows: SnapshotRow[] = [];
    for (const safe of entry.parsed.safes) {
      if (filter.safe && safe.address !== filter.safe) continue;
      for (const group of safe.groups) {
        for (const node of group.nestedObjects) {
          if (filter.class && node.class !== filter.class) continue;
          if (filter.id && node.id !== filter.id) continue;
          if (filter.isDeleted !== undefined && node.isDeleted !== filter.isDeleted) continue;
          if (filter.parentGroup && node.object.parentGroup !== filter.parentGroup) continue;
          rows.push({
            safe: safe.address,
            group: group.id,
            groupName: group.name,
            class: node.class,
            id: node.id,
            isDeleted: node.isDeleted,
            parentGroup: node.object.parentGroup,
            SIGNATURE: node.object.SIGNATURE,
          });
        }
      }
    }
    return rows;
  }

  /**
   * Filtered query, byte-budgeted. A point lookup ({id}) is always returned
   * complete (it is small — the delete-user/delete-policy path). A broad match
   * returns as many rows as fit under maxResultBytes plus explicit
   * {truncated,total,returned,nextOffset} — never a silent cut.
   */
  query(id: string, filter: QueryFilter = {}, now = Date.now()): QueryResult {
    const entry = this.get(id, now);
    const all = this.allRows(entry, filter);
    const total = all.length;

    // Point lookup: always complete.
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

  /** Explicit pagination for a (safe, class) over offset/limit. */
  page(
    id: string,
    safe: string,
    cls: string,
    offset: number,
    limit: number,
    now = Date.now(),
  ): PageResult {
    const entry = this.get(id, now);
    const matchSafe = entry.parsed.safes.find((s) => s.address === safe);
    if (!matchSafe) {
      throw new Error(
        `safe ${safe} not in snapshot ${id}. Available: ${entry.parsed.safes.map((s) => s.address).join(', ')}`,
      );
    }
    const all = rowsOfClass(matchSafe, cls).map(({ node, group }) => ({
      safe: matchSafe.address,
      group: group.id,
      groupName: group.name,
      class: node.class,
      id: node.id,
      isDeleted: node.isDeleted,
      parentGroup: node.object.parentGroup,
      SIGNATURE: node.object.SIGNATURE,
    }));
    const total = all.length;
    const slice = all.slice(offset, offset + limit);
    return { rows: slice, offset, limit, total, truncated: offset + slice.length < total };
  }

  /** Greedily take rows while the serialized array stays under the budget. */
  private budget(all: SnapshotRow[]): { rows: SnapshotRow[]; returned: number } {
    const rows: SnapshotRow[] = [];
    let size = 2; // for "[]"
    for (const row of all) {
      const rowSize = JSON.stringify(row).length + 1; // +1 for the comma
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
