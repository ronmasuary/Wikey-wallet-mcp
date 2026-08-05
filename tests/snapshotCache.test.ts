import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SnapshotCache, SIBLING_FIELDS } from '../src/core/snapshotCache.js';

const FIXTURE = readFileSync(new URL('./fixtures/snapshot-fixture.json', import.meta.url), 'utf8');
const SAFE = 'omnistar1lveyec7dqdt7ypad3fxj0y8wxsyjdjx7vq70n2';
const LIVE_USER = 'a6c3dccb-bfe5-4f08-835b-72437b3bf4da';
const DELETED_POLICY = 'cb691d75-3cce-46de-ac38-243f370b8912';

// Build a synthetic snapshot with `n` users in one safe (for byte-budget tests).
function bigSnapshot(n: number): string {
  const nested = Array.from({ length: n }, (_, i) => ({
    class: 'user',
    id: `user-${i}`,
    isDeleted: false,
    object: { SIGNATURE: `SIG${String(i).padStart(60, '0')}`, parentGroup: 'Primary', public_key: `omnistar1user${i}` },
  }));
  return JSON.stringify({
    success: true,
    data: {
      address: 'omnistar1prof',
      snapshot: [{ address: 'omnistar1bigsafe', name: 'big.safe', groups: [{ id: 'Primary', name: 'Primary', isDeleted: false, nestedObjects: nested }] }],
    },
  });
}

test('H14: ingest returns the small index, never raw JSON', () => {
  const cache = new SnapshotCache();
  const index = cache.ingest(FIXTURE);
  assert.ok(index.snapshotId);
  assert.equal(index.address, 'omnistar1e27zadsdt7y0cl7zj95d2n7d7a0ygexkvdhqf4');
  assert.ok(index.bytes > 100000);
  assert.ok(index.safes.length >= 1);
  const safe = index.safes.find((s) => s.address === SAFE)!;
  assert.ok(safe.counts['user']! >= 1);
  // The index must NOT carry raw object material (SIGNATUREs / public keys).
  const serialized = JSON.stringify(index);
  assert.doesNotMatch(serialized, /41F0435AD59584393F916033A845BDE374EC928ECB9B44597E932475D35F3686/);
  // Check for SIGNATURE *values* (64-hex tokens), not the string "SIGNATURE" —
  // the index legitimately lists field NAMES (class → keys map) for discoverability.
  assert.doesNotMatch(serialized, /\b[0-9a-fA-F]{64}\b/);
});

test('object(): returns the complete object payload + governance siblings', () => {
  const cache = new SnapshotCache();
  const { snapshotId } = cache.ingest(FIXTURE);
  const res = cache.object(snapshotId, 'policy-genesis');
  assert.equal(res.safe, SAFE);
  assert.equal(res.class, 'policy');
  // The full payload — conditions were previously unreachable through any tool.
  assert.ok(Array.isArray(res.object.conditions) || typeof res.object.conditions === 'object');
  assert.ok(res.object.SIGNATURE);
  // Governance state survives end-to-end.
  const phase = (res.process as { currentPhase?: { name?: string } })?.currentPhase;
  assert.equal(typeof phase?.name, 'string');
  assert.equal(res.omittedFields, undefined); // small object: nothing dropped
});

test('object(): oversized object drops largest fields and NAMES them', () => {
  const cache = new SnapshotCache({ maxResultBytes: 600 });
  const raw = JSON.stringify({
    success: true,
    data: {
      address: 'omnistar1prof',
      snapshot: [{
        address: 'omnistar1bigsafe', name: 'big.safe',
        groups: [{
          id: 'Primary', name: 'Primary', isDeleted: false,
          nestedObjects: [{
            class: 'policy', id: 'p-huge', isDeleted: false, isValid: true,
            process: { currentPhase: { index: '3', name: 'Validated' } },
            object: {
              SIGNATURE: 'S'.repeat(64), parentGroup: 'Primary',
              pending_objects: Array.from({ length: 50 }, (_, i) => `obj-${i}`),
              conditions: [{ if: 'x', then: 'y' }],
            },
          }],
        }],
      }],
    },
  });
  const { snapshotId } = cache.ingest(raw);
  const res = cache.object(snapshotId, 'p-huge');
  assert.ok(res.omittedFields && res.omittedFields.length > 0, 'dropped fields are named');
  assert.equal(res.omittedFields![0]!.key, 'pending_objects'); // largest first
  assert.ok(res.omittedFields![0]!.bytes > 0);
  assert.ok(Buffer.byteLength(JSON.stringify(res)) <= 600, 'stays under budget');
  // Small fields survive the trim.
  assert.ok(res.object.conditions);
  // The cached parse must NOT have been mutated by trimming.
  const again = cache.object(snapshotId, 'p-huge');
  assert.deepEqual(again.omittedFields, res.omittedFields);
});

// A node whose COMPLETE read busts the budget because `process` is the single
// largest value — the real shape of a mainnet transaction (payload ~1.6 KB,
// process ~2.4 KB), where the full read drops exactly the governance state.
function processHeavySnapshot(): string {
  return JSON.stringify({
    success: true,
    data: {
      address: 'omnistar1prof',
      snapshot: [{
        address: 'omnistar1bigsafe', name: 'big.safe',
        groups: [{
          id: 'Primary', name: 'Primary', isDeleted: false,
          nestedObjects: [{
            class: 'transaction', id: 'tx-1', isDeleted: false, isValid: true, name: 'tx one',
            process: { currentPhase: { index: '3', name: 'Executed', data: 'D'.repeat(380) } },
            object: {
              SIGNATURE: 'S'.repeat(64), parentGroup: 'Primary',
              amount: '1000', asset: 'OST', message: 'M'.repeat(300),
            },
          }],
        }],
      }],
    },
  });
}

test('object(): fields recovers a sibling the full read had to drop', () => {
  const cache = new SnapshotCache({ maxResultBytes: 1000 });
  const { snapshotId } = cache.ingest(processHeavySnapshot());

  // The complete read cannot fit — process is the largest value, so it goes.
  const full = cache.object(snapshotId, 'tx-1');
  assert.equal(full.process, undefined, 'process dropped from the full read');
  assert.ok(full.omittedFields!.some((f) => f.key === 'process'), 'and is named');

  // Repeating the full read is useless — the point of the narrowing path.
  assert.equal(cache.object(snapshotId, 'tx-1').process, undefined);

  // Asking for LESS returns the field the full read could not carry.
  const narrowed = cache.object(snapshotId, 'tx-1', { fields: ['process'] });
  const phase = (narrowed.process as { currentPhase?: { name?: string } })?.currentPhase;
  assert.equal(phase?.name, 'Executed', 'governance state recovered');
  assert.equal(narrowed.omittedFields, undefined, 'nothing dropped from the narrow read');
  assert.deepEqual(narrowed.object, {}, 'payload not requested, so not returned');
  assert.ok(Buffer.byteLength(JSON.stringify(narrowed)) <= 1000);
});

test('object(): fields selects payload keys and leaves the rest out', () => {
  const cache = new SnapshotCache();
  const { snapshotId } = cache.ingest(processHeavySnapshot());
  const res = cache.object(snapshotId, 'tx-1', { fields: ['amount', 'asset', 'name'] });
  assert.deepEqual(Object.keys(res.object).sort(), ['amount', 'asset']);
  assert.equal(res.object.amount, '1000');
  assert.equal(res.name, 'tx one', 'sibling selected by name');
  assert.equal(res.process, undefined, 'unrequested sibling absent');
  assert.equal(res.unknownFields, undefined);
});

test('object(): an unknown field is reported, never a silent empty object', () => {
  const cache = new SnapshotCache();
  const { snapshotId } = cache.ingest(processHeavySnapshot());
  const res = cache.object(snapshotId, 'tx-1', { fields: ['no_such_field'] });
  assert.deepEqual(res.object, {});
  assert.deepEqual(res.unknownFields, ['no_such_field']);
});

test("object(): '*' means the whole payload, siblings still need naming", () => {
  const cache = new SnapshotCache();
  const { snapshotId } = cache.ingest(processHeavySnapshot());
  const star = cache.object(snapshotId, 'tx-1', { fields: '*' });
  assert.ok(star.object.amount && star.object.SIGNATURE);
  assert.equal(star.process, undefined, "'*' does not imply siblings");
  const both = cache.object(snapshotId, 'tx-1', { fields: ['*'] as unknown as string[] });
  assert.deepEqual(both.unknownFields, ['*'], "'*' inside an array is not a wildcard");
});

test('query(): fields reaches the process sibling too', () => {
  const cache = new SnapshotCache();
  const { snapshotId } = cache.ingest(processHeavySnapshot());
  const res = cache.query(snapshotId, { id: 'tx-1' }, ['process']);
  const row = res.rows[0]!;
  const phase = (row.process as { currentPhase?: { name?: string } })?.currentPhase;
  assert.equal(phase?.name, 'Executed');
  assert.deepEqual(row.object, {});
  // and the legacy summary columns are still there
  assert.equal(row.id, 'tx-1');
  assert.ok(row.SIGNATURE);
});

test('object(): not found -> bounded error with class counts, no id dump', () => {
  const cache = new SnapshotCache();
  const { snapshotId } = cache.ingest(FIXTURE);
  assert.throws(
    () => cache.object(snapshotId, 'nope-does-not-exist'),
    (e: Error) =>
      /not found/.test(e.message) &&
      /policy:\d+/.test(e.message) &&
      /wallet_snapshot_query/.test(e.message) &&
      !/policy-genesis/.test(e.message), // no id enumeration
  );
});

test('index.fields maps class -> object field names (discoverability)', () => {
  const cache = new SnapshotCache();
  const index = cache.ingest(FIXTURE);
  assert.ok(index.fields['policy']!.includes('conditions'));
  assert.ok(index.fields['user']!.includes('public_key'));
  // Names only, sorted, and the whole index stays under the default budget.
  assert.deepEqual(index.fields['policy'], [...index.fields['policy']!].sort());
  assert.ok(Buffer.byteLength(JSON.stringify(index)) < 4096);
});

test('index.siblings names the node-level keys, which fields does NOT carry', () => {
  const cache = new SnapshotCache();
  const index = cache.ingest(FIXTURE);
  // Single source of truth with the resolver — the two can never drift.
  assert.deepEqual(index.siblings, [...SIBLING_FIELDS]);
  // The gap this closes: siblings are not payload keys, so no class lists them.
  for (const cls of Object.keys(index.fields)) {
    assert.ok(!index.fields[cls]!.includes('process'), `${cls} must not list process`);
    assert.ok(!index.fields[cls]!.includes('isValid'), `${cls} must not list isValid`);
  }
  // Everything named in siblings is actually selectable on a node that has it.
  const row = cache.object(index.snapshotId, 'policy-genesis', { fields: [...SIBLING_FIELDS] });
  assert.equal(row?.unknownFields, undefined);
});

// Why `siblings` is its own key and not merged into the per-class field lists:
// the two namespaces can collide, and a flat merged list could not say which
// one a given name resolves to.
test('a payload key shadows the same-named sibling', () => {
  const cache = new SnapshotCache();
  const { snapshotId } = cache.ingest(JSON.stringify({
    success: true,
    data: {
      address: 'omnistar1prof',
      snapshot: [{
        address: 'omnistar1safe', name: 'safe',
        groups: [{
          id: 'Primary', name: 'Primary', isDeleted: false,
          nestedObjects: [{
            class: 'policy', id: 'p-1', isDeleted: false, isValid: true,
            name: 'node-level name',
            object: { SIGNATURE: 'S', parentGroup: 'Primary', name: 'payload name' },
          }],
        }],
      }],
    },
  }));

  const res = cache.object(snapshotId, 'p-1', { fields: ['name'] });
  assert.equal(res?.object!['name'], 'payload name'); // payload wins
  assert.equal(res?.name, undefined); // sibling unreachable on this class
  assert.equal(res?.unknownFields, undefined); // and NOT reported as unknown
});

test('H14: point lookup {id} is always complete', () => {
  const cache = new SnapshotCache({ maxResultBytes: 10 }); // tiny budget — point lookup ignores it
  const { snapshotId } = cache.ingest(FIXTURE);
  const res = cache.query(snapshotId, { id: LIVE_USER });
  assert.equal(res.truncated, false);
  assert.equal(res.rows.length, 1);
  assert.equal(res.rows[0]!.id, LIVE_USER);
  assert.equal(res.rows[0]!.SIGNATURE, '41F0435AD59584393F916033A845BDE374EC928ECB9B44597E932475D35F3686');
  assert.equal(res.rows[0]!.isDeleted, false);
});

test('H14: isDeleted filter finds the deleted policy', () => {
  const cache = new SnapshotCache();
  const { snapshotId } = cache.ingest(FIXTURE);
  const res = cache.query(snapshotId, { class: 'policy', isDeleted: true });
  assert.ok(res.rows.some((r) => r.id === DELETED_POLICY));
});

test('H14: broad match over budget → explicit truncation + nextOffset, never silent', () => {
  const cache = new SnapshotCache({ maxResultBytes: 512 });
  const { snapshotId } = cache.ingest(bigSnapshot(100));
  const res = cache.query(snapshotId, { class: 'user' });
  assert.equal(res.total, 100);
  assert.ok(res.truncated, 'should be truncated under a 512B budget');
  assert.ok(res.returned < 100 && res.returned > 0);
  assert.equal(res.nextOffset, res.returned);
  assert.ok(JSON.stringify(res.rows).length <= 512 + 200); // roughly bounded
});

test('H14: paging retrieves all rows', () => {
  const cache = new SnapshotCache();
  const { snapshotId } = cache.ingest(bigSnapshot(25));
  const collected: string[] = [];
  let offset = 0;
  const limit = 10;
  for (;;) {
    const page = cache.page(snapshotId, 'omnistar1bigsafe', 'user', offset, limit);
    collected.push(...page.rows.map((r) => r.id));
    if (!page.truncated) break;
    offset += limit;
  }
  assert.equal(collected.length, 25);
  assert.equal(new Set(collected).size, 25);
});

test('fields: requested object payload keys come back nested under object:', () => {
  const cache = new SnapshotCache();
  const { snapshotId } = cache.ingest(FIXTURE);
  const res = cache.query(snapshotId, { id: 'policy-genesis' }, ['conditions', 'applyOn']);
  assert.equal(res.rows.length, 1);
  const row = res.rows[0]!;
  assert.ok(row.object, 'object payload present when fields requested');
  assert.ok('conditions' in row.object!);
  // Row's own summary keys are untouched (collision-safe nesting).
  assert.equal(row.class, 'policy');
  assert.ok(row.SIGNATURE);
});

test('fields omitted: rows are byte-identical to the historical 8-field shape', () => {
  const cache = new SnapshotCache();
  const { snapshotId } = cache.ingest(FIXTURE);
  const res = cache.query(snapshotId, { id: LIVE_USER });
  assert.deepEqual(Object.keys(res.rows[0]!), [
    'safe', 'group', 'groupName', 'class', 'id', 'isDeleted', 'parentGroup', 'SIGNATURE',
  ]);
});

test("fields '*': broad match truncates by rows with correct nextOffset", () => {
  const cache = new SnapshotCache({ maxResultBytes: 2048 });
  const { snapshotId } = cache.ingest(bigSnapshot(100));
  const res = cache.query(snapshotId, { class: 'user' }, '*');
  assert.equal(res.total, 100);
  assert.ok(res.truncated);
  assert.ok(res.returned < 100);
  assert.equal(res.nextOffset, res.returned);
  assert.ok(res.rows[0]!.object!.public_key, 'payload keys present');
  assert.ok(Buffer.byteLength(JSON.stringify(res.rows)) <= 2048);
});

test("page with fields '*' respects the byte budget (returned < limit)", () => {
  const cache = new SnapshotCache({ maxResultBytes: 2048 });
  const { snapshotId } = cache.ingest(bigSnapshot(100));
  const page = cache.page(snapshotId, 'omnistar1bigsafe', 'user', 0, 100, '*');
  assert.ok(page.returned < 100, 'byte budget cut the slice');
  assert.equal(page.rows.length, page.returned);
  assert.ok(page.truncated);
  assert.ok(Buffer.byteLength(JSON.stringify(page.rows)) <= 2048);
  // Paging by `returned` still reaches every row.
  const next = cache.page(snapshotId, 'omnistar1bigsafe', 'user', page.returned, 100, '*');
  assert.equal(next.rows[0]!.id, `user-${page.returned}`);
});

test('fields + point lookup: an oversized row is trimmed with named omissions, never a blob', () => {
  const cache = new SnapshotCache({ maxResultBytes: 400 });
  const raw = JSON.stringify({
    success: true,
    data: {
      address: 'omnistar1prof',
      snapshot: [{
        address: 'omnistar1bigsafe', name: 'big.safe',
        groups: [{
          id: 'Primary', name: 'Primary', isDeleted: false,
          nestedObjects: [{
            class: 'policy', id: 'p-wide', isDeleted: false,
            object: {
              SIGNATURE: 'S'.repeat(64), parentGroup: 'Primary',
              affected_by: Array.from({ length: 80 }, (_, i) => `dep-${i}`),
              name: 'small',
            },
          }],
        }],
      }],
    },
  });
  const { snapshotId } = cache.ingest(raw);
  const res = cache.query(snapshotId, { id: 'p-wide' }, '*');
  const row = res.rows[0]!;
  assert.ok(row.omittedFields?.some((f) => f.key === 'affected_by'), 'dropped field is named');
  assert.equal(row.object!.name, 'small'); // small fields survive
  assert.ok(Buffer.byteLength(JSON.stringify(res.rows)) <= 400);
});

test('H14: TTL expiry errors clearly', () => {
  const cache = new SnapshotCache({ ttlMs: 1000 });
  const { snapshotId } = cache.ingest(bigSnapshot(2), 0);
  assert.doesNotThrow(() => cache.query(snapshotId, {}, undefined, 500));
  assert.throws(() => cache.query(snapshotId, {}, undefined, 2000), /expired/);
});

test('H14: last-3 eviction', () => {
  const cache = new SnapshotCache({ max: 3 });
  const a = cache.ingest(bigSnapshot(1)).snapshotId;
  cache.ingest(bigSnapshot(1));
  cache.ingest(bigSnapshot(1));
  cache.ingest(bigSnapshot(1)); // evicts `a`
  assert.throws(() => cache.query(a, {}), /not found|evicted/);
});

test('size-aware eviction: total-bytes cap evicts oldest, always keeps newest', () => {
  const one = bigSnapshot(50);
  const cap = Buffer.byteLength(one) * 2 + 100; // fits two snapshots, not three
  const cache = new SnapshotCache({ max: 10, maxTotalBytes: cap });
  const a = cache.ingest(one).snapshotId;
  const b = cache.ingest(bigSnapshot(50)).snapshotId;
  const c = cache.ingest(bigSnapshot(50)).snapshotId; // pushes total over cap -> evicts a
  assert.throws(() => cache.query(a, {}), /not found|evicted/);
  assert.doesNotThrow(() => cache.query(b, {}));
  assert.doesNotThrow(() => cache.query(c, {}));

  // A single snapshot larger than the cap is still kept (newest survives).
  const tiny = new SnapshotCache({ max: 10, maxTotalBytes: 64 });
  const d = tiny.ingest(bigSnapshot(5)).snapshotId;
  assert.doesNotThrow(() => tiny.query(d, {}));
});
