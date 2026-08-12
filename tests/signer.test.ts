import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fetchPubkey } from '../src/core/signing.js';
import { signerArgsFor } from '../src/core/accounts.js';

// A known `keys get` payload shape: { success, data: { ..., pubkeyBase64 } }.
const KEYS_GET_OK = JSON.stringify({
  success: true,
  data: { id: 'omnistar1funded', publicKey: 'deadbeef', pubkeyBase64: 'UABC123==' },
});

function fakeQuery(byArgs: (args: string[]) => string): (args: string[]) => Promise<string> {
  return async (args: string[]) => byArgs(args);
}

test('fetchPubkey looks the key up by id and returns its base64 pubkey', async () => {
  const seen: string[][] = [];
  const q = fakeQuery((args) => {
    seen.push(args);
    return KEYS_GET_OK;
  });
  assert.equal(await fetchPubkey(q, 'omnistar1funded'), 'UABC123==');
  assert.deepEqual(seen[0], ['keys', 'get', '--id', 'omnistar1funded'], 'looks up the given id');
});

test('unknown key (no pubkey in payload) → throws rather than signing with something else', async () => {
  const q = fakeQuery(() => JSON.stringify({ success: true, data: { id: 'x' } }));
  await assert.rejects(fetchPubkey(q, 'omnistar1missing'), /no pubkey found/);
});

test('non-JSON keys-get output → throws a clear error', async () => {
  const q = fakeQuery(() => 'Key not found: omnistar1bad');
  await assert.rejects(fetchPubkey(q, 'omnistar1bad'), /could not parse keys-get output/);
});

test('signerArgsFor emits --creator/--pubkey from an already-resolved account', () => {
  const account = { address: 'omnistar1funded', pubkey: 'UABC123==' };
  assert.deepEqual(signerArgsFor(account), ['--creator', 'omnistar1funded', '--pubkey', 'UABC123==']);
});

test('signerArgsFor pubkeyOnly drops --creator (tx send derives it from --from)', () => {
  const account = { address: 'omnistar1funded', pubkey: 'UABC123==' };
  assert.deepEqual(signerArgsFor(account, { pubkeyOnly: true }), ['--pubkey', 'UABC123==']);
});
