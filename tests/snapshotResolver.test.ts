import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  parseSnapshot,
  findSafe,
  extractGroupsFromSafe,
  resolveCreateUserTarget,
  resolveUserDeletion,
  resolvePolicyDeletion,
  type SafeEntry,
} from '../src/core/snapshot.js';

function makeSafe(): SafeEntry {
  return {
    address: 'omnistar1safe',
    name: 'test.safe',
    groups: [
      {
        id: 'Primary',
        name: 'Primary',
        isDeleted: false,
        nestedObjects: [
          { class: 'user', id: 'u-live', isDeleted: false, object: { SIGNATURE: 'SIG-LIVE', parentGroup: 'Primary' } },
          { class: 'user', id: 'u-dead', isDeleted: true, object: { SIGNATURE: 'SIG-DEAD', parentGroup: 'Primary' } },
          { class: 'policy', id: 'p-live', isDeleted: false, object: { SIGNATURE: 'PSIG-LIVE', parentGroup: 'Primary' } },
          { class: 'policy', id: 'p-dead', isDeleted: true, object: { SIGNATURE: 'PSIG-DEAD', parentGroup: 'Primary' } },
        ],
      },
      {
        id: '7f3c-uuid',
        name: 'Engineering',
        isDeleted: false,
        nestedObjects: [
          { class: 'user', id: 'u-eng', isDeleted: false, object: { SIGNATURE: 'SIG-ENG', parentGroup: '7f3c-uuid' } },
        ],
      },
      { id: 'a9b1-uuid', name: 'Archived', isDeleted: true, nestedObjects: [] },
    ],
  };
}

function wrap(safe: SafeEntry): string {
  return JSON.stringify({ success: true, data: { address: 'omnistar1prof', snapshot: [safe] } });
}

test('parseSnapshot accepts {success,data:{snapshot}} wrapper', () => {
  const p = parseSnapshot(wrap(makeSafe()));
  assert.equal(p.safes.length, 1);
  assert.equal(p.safes[0]!.address, 'omnistar1safe');
  assert.equal(p.safes[0]!.groups.length, 3);
});

test('parseSnapshot accepts bare array variant', () => {
  const p = parseSnapshot(JSON.stringify([makeSafe()]));
  assert.equal(p.safes.length, 1);
  assert.equal(p.safes[0]!.name, 'test.safe');
});

test('parseSnapshot strips leading URL line on stdout', () => {
  const raw = 'https://reverse-proxy.example/snapshot?x=1\n' + wrap(makeSafe());
  const p = parseSnapshot(raw);
  assert.equal(p.safes.length, 1);
  assert.equal(p.safes[0]!.address, 'omnistar1safe');
});

test('parseSnapshot malformed JSON throws', () => {
  assert.throws(() => parseSnapshot('not-json-at-all'), /failed to parse snapshot JSON/);
});

test('findSafe matches by address', () => {
  const p = parseSnapshot(wrap(makeSafe()));
  assert.equal(findSafe(p, 'omnistar1safe').name, 'test.safe');
});

test('findSafe not-found lists available safes', () => {
  const p = parseSnapshot(wrap(makeSafe()));
  assert.throws(() => findSafe(p, 'omnistar1ghost'), /not in profile snapshot[\s\S]*omnistar1safe \(test\.safe\)/);
});

test('extractGroupsFromSafe returns live groups only', () => {
  assert.deepEqual(extractGroupsFromSafe(makeSafe()), [
    { id: 'Primary', name: 'Primary' },
    { id: '7f3c-uuid', name: 'Engineering' },
  ]);
});

test('createUser: 1 group, no group arg → returns its id', () => {
  assert.equal(resolveCreateUserTarget({ destination: 'omnistar1safe', groups: [{ id: 'only', name: 'Only' }] }), 'only');
});

test('createUser: 0 groups, no group arg → returns "Primary"', () => {
  assert.equal(resolveCreateUserTarget({ destination: 'omnistar1safe', groups: [] }), 'Primary');
});

test('createUser: group="Primary" literal passes through', () => {
  const groups = extractGroupsFromSafe(makeSafe());
  assert.equal(resolveCreateUserTarget({ destination: 'omnistar1safe', group: 'Primary', groups }), 'Primary');
});

test('createUser: group=<uuid> matches an id → passes through', () => {
  const groups = extractGroupsFromSafe(makeSafe());
  assert.equal(resolveCreateUserTarget({ destination: 'omnistar1safe', group: '7f3c-uuid', groups }), '7f3c-uuid');
});

test('createUser: group="Engineering" (name, not id) → throws', () => {
  const groups = extractGroupsFromSafe(makeSafe());
  assert.throws(() => resolveCreateUserTarget({ destination: 'omnistar1safe', group: 'Engineering', groups }), /group "Engineering" not a valid group id/);
});

test('createUser: 2+ groups, no group → ambiguity excludes soft-deleted', () => {
  const groups = extractGroupsFromSafe(makeSafe());
  let err: Error | null = null;
  try {
    resolveCreateUserTarget({ destination: 'omnistar1safe', groups });
  } catch (e) {
    err = e as Error;
  }
  assert.ok(err);
  assert.match(err!.message, /group ambiguous/);
  assert.match(err!.message, /7f3c-uuid \(Engineering\)/);
  assert.doesNotMatch(err!.message, /a9b1-uuid|Archived/);
});

test('resolveUserDeletion: live match returns sig + parentGroup', () => {
  assert.deepEqual(resolveUserDeletion({ destination: 'omnistar1safe', userId: 'u-live', safe: makeSafe() }), {
    signature: 'SIG-LIVE',
    parentGroup: 'Primary',
  });
});

test('resolveUserDeletion: deleted match throws "already deleted"', () => {
  assert.throws(() => resolveUserDeletion({ destination: 'omnistar1safe', userId: 'u-dead', safe: makeSafe() }), /already deleted in safe omnistar1safe, refusing/);
});

test('resolveUserDeletion: no match lists live user ids (not policy ids)', () => {
  let err: Error | null = null;
  try {
    resolveUserDeletion({ destination: 'omnistar1safe', userId: 'p-live', safe: makeSafe() });
  } catch (e) {
    err = e as Error;
  }
  assert.ok(err);
  assert.match(err!.message, /available users/);
  assert.match(err!.message, /u-live \(Primary\)/);
  assert.match(err!.message, /u-eng \(7f3c-uuid \(Engineering\)\)/);
  assert.doesNotMatch(err!.message, /u-dead/);
});

test('resolvePolicyDeletion: live match returns sig + parentGroup', () => {
  assert.deepEqual(resolvePolicyDeletion({ destination: 'omnistar1safe', policyId: 'p-live', safe: makeSafe() }), {
    signature: 'PSIG-LIVE',
    parentGroup: 'Primary',
  });
});

test('resolvePolicyDeletion: no match lists live policy ids (not user ids)', () => {
  let err: Error | null = null;
  try {
    resolvePolicyDeletion({ destination: 'omnistar1safe', policyId: 'u-live', safe: makeSafe() });
  } catch (e) {
    err = e as Error;
  }
  assert.ok(err);
  assert.match(err!.message, /available policies/);
  assert.match(err!.message, /p-live \(Primary\)/);
});

// e2e against the committed fixture (refresh when snapshot-fixture.json regenerates)
const FIXTURE = new URL('./fixtures/snapshot-fixture.json', import.meta.url);
const SAFE_ADDR = 'omnistar1lveyec7dqdt7ypad3fxj0y8wxsyjdjx7vq70n2';

test('e2e: resolveUserDeletion against fixture known live user', () => {
  const snap = parseSnapshot(readFileSync(FIXTURE, 'utf8'));
  const safe = findSafe(snap, SAFE_ADDR);
  const r = resolveUserDeletion({ destination: SAFE_ADDR, userId: 'a6c3dccb-bfe5-4f08-835b-72437b3bf4da', safe });
  assert.equal(r.signature, '41F0435AD59584393F916033A845BDE374EC928ECB9B44597E932475D35F3686');
  assert.equal(r.parentGroup, 'Primary');
});

test('e2e: resolveUserDeletion against fixture deleted user throws', () => {
  const snap = parseSnapshot(readFileSync(FIXTURE, 'utf8'));
  const safe = findSafe(snap, SAFE_ADDR);
  assert.throws(() => resolveUserDeletion({ destination: SAFE_ADDR, userId: '1b95e3e7-ca38-4446-8426-e3b8176679aa', safe }), /already deleted/);
});

test('e2e: parser preserves node siblings (name, isValid, process) — field fidelity', () => {
  const snap = parseSnapshot(readFileSync(FIXTURE, 'utf8'));
  const safe = findSafe(snap, SAFE_ADDR);
  const node = safe.groups
    .flatMap((g) => g.nestedObjects)
    .find((n) => n.id === 'a6c3dccb-bfe5-4f08-835b-72437b3bf4da')!;
  assert.ok(node, 'known live user present in fixture');
  // Governance state must survive parsing — it was previously discarded.
  const phase = (node.process as { currentPhase?: { name?: string } }).currentPhase;
  assert.equal(phase?.name, 'Validatad');
  assert.equal(typeof node.isValid, 'boolean');
  assert.equal(typeof node.name, 'string');
});

test('parser omits absent siblings instead of emitting defaults', () => {
  const snap = parseSnapshot(wrap(makeSafe()));
  const node = snap.safes[0]!.groups[0]!.nestedObjects[0]!;
  // makeSafe() nodes carry no name/isValid/process — they must stay absent.
  assert.equal('name' in node, false);
  assert.equal('isValid' in node, false);
  assert.equal('process' in node, false);
});
