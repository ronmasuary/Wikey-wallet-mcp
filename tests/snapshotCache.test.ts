import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SnapshotCache } from '../src/core/snapshotCache.js';

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

test('H14: TTL expiry errors clearly', () => {
  const cache = new SnapshotCache({ ttlMs: 1000 });
  const { snapshotId } = cache.ingest(bigSnapshot(2), 0);
  assert.doesNotThrow(() => cache.query(snapshotId, {}, 500));
  assert.throws(() => cache.query(snapshotId, {}, 2000), /expired/);
});

test('H14: last-3 eviction', () => {
  const cache = new SnapshotCache({ max: 3 });
  const a = cache.ingest(bigSnapshot(1)).snapshotId;
  cache.ingest(bigSnapshot(1));
  cache.ingest(bigSnapshot(1));
  cache.ingest(bigSnapshot(1)); // evicts `a`
  assert.throws(() => cache.query(a, {}), /not found|evicted/);
});
