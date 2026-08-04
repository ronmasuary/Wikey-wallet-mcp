// Snapshot parser + resolvers — ported verbatim from the skill's
// snapshotResolver.ts (the verified design reference). Single mechanism for
// create-user / delete-user / delete-policy resolution and for the B2 snapshot
// store (snapshotCache.ts).
//
// Shape contract (see docs / snapshot-fixture-shape.md): `query snapshot` returns
//   { success, data: { address, snapshot[] } }
// where each `snapshot[]` element IS a safe directly (NO `.safe` wrapper):
//   safe: { address, name, isMain, balance, assets, lastActive, groups[] }
//     group: { id, name, isDeleted, isValid, object, process, nestedObjects[] }
//       nestedObject: { class, id, name, isDeleted, isValid, process,
//                       object: { SIGNATURE, parentGroup, ... } }
// group.nestedPolicies / group.nestedUsers are deliberately NOT parsed — they
// are strict subsets of nestedObjects (identical ids, no unique data).
//
// wallet-cli prints a snapshot URL line on stdout BEFORE the JSON body, so
// parseSnapshot tolerates leading non-JSON text.

export interface SnapshotObject {
  SIGNATURE: string;
  parentGroup: string;
  [k: string]: unknown;
}

export interface NestedObject {
  class: string;
  id: string;
  isDeleted: boolean;
  object: SnapshotObject;
  // Siblings preserved for fidelity (present only when the source carries them).
  // `process.currentPhase` is the governance state of the object.
  name?: string;
  isValid?: boolean;
  process?: Record<string, unknown>;
}

export interface SnapshotGroup {
  id: string;
  name: string;
  isDeleted: boolean;
  nestedObjects: NestedObject[];
  isValid?: boolean;
  object?: Record<string, unknown>;
  process?: Record<string, unknown>;
}

export interface SafeEntry {
  address: string;
  name: string;
  groups: SnapshotGroup[];
  isMain?: boolean;
  balance?: unknown;
  assets?: unknown;
  lastActive?: unknown;
}

export interface ParsedSnapshot {
  safes: SafeEntry[];
}

export interface GroupRef {
  id: string;
  name: string;
}

// ─── parsing ──────────────────────────────────────────────────────────────────

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function asObject(v: unknown): SnapshotObject {
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return { ...o, SIGNATURE: str(o.SIGNATURE), parentGroup: str(o.parentGroup) };
  }
  return { SIGNATURE: '', parentGroup: '' };
}

// Plain-record coercion for pass-through fields (process, group object).
function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

function asNestedObject(v: unknown): NestedObject {
  const o = (v && typeof v === 'object' ? v : {}) as Record<string, unknown>;
  const node: NestedObject = {
    class: str(o.class),
    id: str(o.id),
    isDeleted: o.isDeleted === true,
    object: asObject(o.object),
  };
  // Fidelity: keep siblings when present, omit when absent (absence stays meaningful).
  if (typeof o.name === 'string') node.name = o.name;
  if (typeof o.isValid === 'boolean') node.isValid = o.isValid;
  const process = asRecord(o.process);
  if (process) node.process = process;
  return node;
}

function asGroup(v: unknown): SnapshotGroup {
  const o = (v && typeof v === 'object' ? v : {}) as Record<string, unknown>;
  const nested = Array.isArray(o.nestedObjects) ? o.nestedObjects.map(asNestedObject) : [];
  const group: SnapshotGroup = {
    id: str(o.id),
    name: str(o.name),
    isDeleted: o.isDeleted === true,
    nestedObjects: nested,
  };
  if (typeof o.isValid === 'boolean') group.isValid = o.isValid;
  const object = asRecord(o.object);
  if (object) group.object = object;
  const process = asRecord(o.process);
  if (process) group.process = process;
  return group;
}

function asSafe(v: unknown): SafeEntry {
  const o = (v && typeof v === 'object' ? v : {}) as Record<string, unknown>;
  const groups = Array.isArray(o.groups) ? o.groups.map(asGroup) : [];
  const safe: SafeEntry = { address: str(o.address), name: str(o.name), groups };
  if (typeof o.isMain === 'boolean') safe.isMain = o.isMain;
  if (o.balance !== undefined) safe.balance = o.balance;
  if (o.assets !== undefined) safe.assets = o.assets;
  if (o.lastActive !== undefined) safe.lastActive = o.lastActive;
  return safe;
}

// Extract the snapshot[] array from any of the known envelope shapes.
function unwrapSnapshotArray(parsed: unknown): unknown[] {
  if (Array.isArray(parsed)) return parsed;
  if (parsed && typeof parsed === 'object') {
    const root = parsed as { data?: { snapshot?: unknown }; snapshot?: unknown };
    const fromData =
      root.data && typeof root.data === 'object'
        ? (root.data as { snapshot?: unknown }).snapshot
        : undefined;
    if (Array.isArray(fromData)) return fromData;
    if (Array.isArray(root.snapshot)) return root.snapshot;
  }
  return [];
}

export function parseSnapshot(raw: string): ParsedSnapshot {
  // wallet-cli emits a URL line before the JSON on stdout — slice from first { or [.
  const start = (() => {
    const brace = raw.indexOf('{');
    const bracket = raw.indexOf('[');
    if (brace === -1) return bracket;
    if (bracket === -1) return brace;
    return Math.min(brace, bracket);
  })();
  const body = start >= 0 ? raw.slice(start) : raw;

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error(`failed to parse snapshot JSON. Raw tail: ${raw.slice(-200)}`);
  }

  const safes = unwrapSnapshotArray(parsed).map(asSafe);
  return { safes };
}

// ─── safe / group lookup ────────────────────────────────────────────────────────

function safeBullets(safes: SafeEntry[]): string {
  return safes.map((s) => `  - ${s.address} (${s.name})`).join('\n');
}

export function findSafe(snapshot: ParsedSnapshot, destination: string): SafeEntry {
  const match = snapshot.safes.find((s) => s.address === destination);
  if (match) return match;
  throw new Error(
    `destination ${destination} not in profile snapshot. Available safes:\n${safeBullets(snapshot.safes)}`,
  );
}

export function extractGroupsFromSafe(safe: SafeEntry): GroupRef[] {
  return safe.groups.filter((g) => !g.isDeleted).map((g) => ({ id: g.id, name: g.name }));
}

function formatGroupLabel(g: GroupRef): string {
  return g.id === g.name ? g.id : `${g.id} (${g.name})`;
}

function groupBullets(groups: GroupRef[]): string {
  return groups.map((g) => `  - ${formatGroupLabel(g)}`).join('\n');
}

// ─── create-user ─────────────────────────────────────────────────────────────────

export function resolveCreateUserTarget(args: {
  destination: string;
  group?: string;
  groups: GroupRef[];
}): string {
  const { destination, group, groups } = args;

  if (group === undefined || group === null || group === '') {
    if (groups.length === 0) return 'Primary';
    if (groups.length === 1) return groups[0]!.id;
    throw new Error(
      `group ambiguous in safe ${destination} — specify \`group\` (pass the id, not the name):\n${groupBullets(groups)}`,
    );
  }

  const match = groups.find((g) => g.id === group);
  if (match) return match.id;

  throw new Error(
    `group "${group}" not a valid group id in safe ${destination}. Valid ids (pass the id, not the name):\n${groupBullets(groups)}`,
  );
}

// ─── deletion resolvers ───────────────────────────────────────────────────────────

// Walk every group in the safe, collect nestedObjects of the given class.
// Each row keeps a reference to its containing group for labelling.
export function rowsOfClass(
  safe: SafeEntry,
  cls: string,
): { node: NestedObject; group: SnapshotGroup }[] {
  const rows: { node: NestedObject; group: SnapshotGroup }[] = [];
  for (const group of safe.groups) {
    for (const node of group.nestedObjects) {
      if (node.class === cls) rows.push({ node, group });
    }
  }
  return rows;
}

function liveIdBullets(rows: { node: NestedObject; group: SnapshotGroup }[]): string {
  return rows
    .filter((r) => !r.node.isDeleted)
    .map((r) => `  - ${r.node.id} (${formatGroupLabel({ id: r.group.id, name: r.group.name })})`)
    .join('\n');
}

function resolveDeletion(args: {
  destination: string;
  objectId: string;
  safe: SafeEntry;
  cls: 'user' | 'policy';
  noun: 'userId' | 'policyId';
  plural: 'users' | 'policies';
}): { signature: string; parentGroup: string } {
  const { destination, objectId, safe, cls, noun, plural } = args;
  const rows = rowsOfClass(safe, cls);

  // id is unique per group-membership (Phase 1a invariant) — first match wins.
  const match = rows.find((r) => r.node.id === objectId);

  if (!match) {
    throw new Error(
      `${noun} ${objectId} not found in safe ${destination} — available ${plural}:\n${liveIdBullets(rows)}`,
    );
  }
  if (match.node.isDeleted) {
    throw new Error(`${noun} ${objectId} is already deleted in safe ${destination}, refusing`);
  }
  return { signature: match.node.object.SIGNATURE, parentGroup: match.node.object.parentGroup };
}

export function resolveUserDeletion(args: {
  destination: string;
  userId: string;
  safe: SafeEntry;
}): { signature: string; parentGroup: string } {
  return resolveDeletion({
    destination: args.destination,
    objectId: args.userId,
    safe: args.safe,
    cls: 'user',
    noun: 'userId',
    plural: 'users',
  });
}

export function resolvePolicyDeletion(args: {
  destination: string;
  policyId: string;
  safe: SafeEntry;
}): { signature: string; parentGroup: string } {
  return resolveDeletion({
    destination: args.destination,
    objectId: args.policyId,
    safe: args.safe,
    cls: 'policy',
    noun: 'policyId',
    plural: 'policies',
  });
}
