import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveSignerArgs } from '../src/core/signing.js';

// A known `keys get` payload shape: { success, data: { ..., pubkeyBase64 } }.
const KEYS_GET_OK = JSON.stringify({
  success: true,
  data: { id: 'omnistar1funded', publicKey: 'deadbeef', pubkeyBase64: 'UABC123==' },
});

function fakeQuery(byArgs: (args: string[]) => string): (args: string[]) => Promise<string> {
  return async (args: string[]) => byArgs(args);
}

test('omitted signingKey → no --creator/--pubkey (back-compat)', async () => {
  let called = false;
  const q = fakeQuery(() => {
    called = true;
    return '{}';
  });
  assert.deepEqual(await resolveSignerArgs(q, undefined), []);
  assert.deepEqual(await resolveSignerArgs(q, null), []);
  assert.deepEqual(await resolveSignerArgs(q, ''), []);
  assert.equal(called, false, 'no key lookup when signingKey is omitted');
});

test('provided signingKey → resolves pubkey and returns --creator/--pubkey', async () => {
  const seen: string[][] = [];
  const q = fakeQuery((args) => {
    seen.push(args);
    return KEYS_GET_OK;
  });
  const out = await resolveSignerArgs(q, 'omnistar1funded');
  assert.deepEqual(out, ['--creator', 'omnistar1funded', '--pubkey', 'UABC123==']);
  assert.deepEqual(seen[0], ['keys', 'get', '--id', 'omnistar1funded'], 'looks up the given id');
});

test('unknown signingKey (no pubkey in payload) → throws, no signer args', async () => {
  const q = fakeQuery(() => JSON.stringify({ success: true, data: { id: 'x' } }));
  await assert.rejects(resolveSignerArgs(q, 'omnistar1missing'), /no pubkey found/);
});

test('non-JSON keys-get output → throws a clear error', async () => {
  const q = fakeQuery(() => 'Key not found: omnistar1bad');
  await assert.rejects(resolveSignerArgs(q, 'omnistar1bad'), /could not parse keys-get output/);
});
