import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildPolicyQueue, buildEditHelpersQueue, extractUsernameFromProfile } from '../src/core/signing.js';

// ─── buildPolicyQueue (ported) ────────────────────────────────────────────────

test('applyOn=transaction with voting+amount+symbols → full queue', () => {
  const q = buildPolicyQueue({
    applyOn: 'transaction',
    conditions: [
      { type: 'voting', votingQty: 60 },
      { type: 'amount', minAmount: 1, maxAmount: 100 },
      { type: 'symbols', symbols: ['BTC', 'ETH'] },
    ],
    name: 'p1',
    description: 'desc',
  });
  assert.equal(q.length, 7);
  assert.equal(q[0]!.respond(), '1,2,3\n');
  assert.equal(q[1]!.respond(), '60\n');
  assert.equal(q[2]!.respond(), '1\n');
  assert.equal(q[3]!.respond(), '100\n');
  assert.equal(q[4]!.respond(), 'BTC,ETH\n');
  assert.equal(q[5]!.respond(), 'p1\n');
  assert.equal(q[6]!.respond(), 'desc\n');
});

test('applyOn=group with voting only → selection=1', () => {
  const q = buildPolicyQueue({ applyOn: 'group', conditions: [{ type: 'voting', votingQty: 100 }] });
  assert.equal(q.length, 4);
  assert.equal(q[0]!.respond(), '1\n');
  assert.equal(q[2]!.respond(), '\n');
  assert.equal(q[3]!.respond(), '\n');
});

test('mixed applyOn (transaction,group) drops amount/symbols', () => {
  const q = buildPolicyQueue({
    applyOn: 'transaction,group',
    conditions: [{ type: 'voting', votingQty: 50 }, { type: 'amount', minAmount: 1, maxAmount: 2 }],
  });
  assert.equal(q.length, 4);
  assert.equal(q[0]!.respond(), '1\n');
});

// ─── buildEditHelpersQueue (ported) ────────────────────────────────────────────

test('add 2 helpers, no removes', () => {
  const q = buildEditHelpersQueue(['alice', 'bob'], [], 3)('');
  assert.equal(q.length, 7);
  assert.equal(q[0]!.respond(), 'y\n');
  assert.equal(q[1]!.respond(), 'alice\n');
  assert.equal(q[2]!.respond(), 'y\n');
  assert.equal(q[3]!.respond(), 'bob\n');
  assert.equal(q[4]!.respond(), 'n\n');
  assert.equal(q[5]!.respond(), 'n\n');
  assert.equal(q[6]!.respond(), '3\n');
});

test('remove 1 helper → index lookup against `all`', () => {
  const q = buildEditHelpersQueue([], ['carol'], 1)('1) alice (omnistar1abc)\n2) carol (omnistar1xyz)\n3) bob (omnistar1def)\n');
  assert.equal(q[2]!.match, 'Enter the number of the helper to remove');
  assert.equal(q[2]!.respond(), '2\n');
});

test('remove target not in list → throws helpful error', () => {
  const q = buildEditHelpersQueue([], ['ghost'], 1)('1. alice\n2. bob\n');
  const step = q.find((s) => s.match === 'Enter the number of the helper to remove')!;
  assert.throws(() => step.respond(), /helper not found in list: "ghost"/);
});

test('no adds and no removes → 3 steps', () => {
  const q = buildEditHelpersQueue([], [], 2)('');
  assert.equal(q.length, 3);
  assert.equal(q[2]!.respond(), '2\n');
});

// ─── extractUsernameFromProfile (ported) ────────────────────────────────────────

test('wrapped JSON with data.profile.name → returns name', () => {
  assert.equal(extractUsernameFromProfile(JSON.stringify({ data: { profile: { name: 'alice' } } })), 'alice');
});

test('flat JSON with profile.name → returns name', () => {
  assert.equal(extractUsernameFromProfile(JSON.stringify({ profile: { name: 'bob' } })), 'bob');
});

test('missing profile → throws', () => {
  assert.throws(() => extractUsernameFromProfile(JSON.stringify({ data: {} })), /profile\.name not found/);
});

test('malformed JSON → throws with raw tail', () => {
  assert.throws(() => extractUsernameFromProfile('not-json'), /failed to parse profile JSON/);
});
