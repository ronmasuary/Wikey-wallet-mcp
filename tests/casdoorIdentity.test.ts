import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  resolveWalletIdentity,
  createFidoObjectArgs,
  signChallengeViaSSP,
  waitForObjectValid,
  loadCredential,
  saveCredential,
  type QueryFn,
} from '../src/core/casdoorIdentity.js';
import type { IdentityBundle } from '../src/core/identityRegistry.js';

const EC_PUK =
  '04fd6d3b271916ee3833382e4ae016460510636eb4ee2daba196ceae04cfc75cdd73aa7b0f2de6bf4124299b592ecc24ef8fe6bf722f57088aa3c786eed253450b';

const SNAPSHOT_OK = JSON.stringify({
  success: true,
  data: {
    address: 'omnistar1account',
    snapshot: [
      { name: 'wally.a_safe', address: 'omnistar1safe', isMain: true, assets: { ecPuk: EC_PUK } },
    ],
  },
});

function q(byArgs: (args: string[]) => string): QueryFn {
  return async (args) => byArgs(args);
}

const BUNDLE: IdentityBundle = {
  alias: 'work', host: 'http://localhost:8000', rpId: 'localhost', origin: 'http://localhost:8000',
  org: 'org', user: 'u', app: 'app', clientId: 'cid', snapshotNode: 'node:9093', env: 'main',
  redirectUri: 'http://localhost:9000/callback', scope: 'read', snapshotSecure: false,
};

test('resolveWalletIdentity reads account, main safe, and ecPuk (x/y split)', async () => {
  const id = await resolveWalletIdentity(q(() => SNAPSHOT_OK));
  assert.equal(id.account, 'omnistar1account');
  assert.equal(id.safe, 'omnistar1safe');
  assert.equal(id.ecPuk, EC_PUK);
  assert.equal(id.x.length, 32);
  assert.equal(id.y.length, 32);
});

test('resolveWalletIdentity tolerates a leading URL line and a safe with no ecPuk errors', async () => {
  const withPrefix = 'https://node/snapshot/client?x=1\n' + SNAPSHOT_OK;
  const id = await resolveWalletIdentity(q(() => withPrefix));
  assert.equal(id.safe, 'omnistar1safe');

  const noPuk = JSON.stringify({ data: { address: 'a', snapshot: [{ address: 'omnistar1safe', isMain: true, assets: {} }] } });
  await assert.rejects(resolveWalletIdentity(q(() => noPuk)), /no assets\.ecPuk/);
});

test('createFidoObjectArgs emits exact flag order incl. signer args', () => {
  assert.deepEqual(
    createFidoObjectArgs('omnistar1safe', 'the-uuid', 'deadbeef', ['--creator', 'omnistar1k', '--pubkey', 'B64']),
    [
      'tx', 'create-fido-object',
      '--destination', 'omnistar1safe',
      '--id', 'the-uuid',
      '--payload', 'deadbeef',
      '--broadcast',
      '--creator', 'omnistar1k', '--pubkey', 'B64',
    ],
  );
  // default key → no signer args appended.
  assert.deepEqual(createFidoObjectArgs('s', 'u', 'p').slice(-1), ['--broadcast']);
});

test('signChallengeViaSSP resolves the compressed pubkey via keys get and calls signRaw', async () => {
  const COMPRESSED = '02' + 'ab'.repeat(32);
  const seen: { hex?: string; pk?: string } = {};
  const signer = {
    async signRaw(hex: string, pk: string) {
      seen.hex = hex;
      seen.pk = pk;
      return 'DERSIG';
    },
  };
  const query = q((args) => {
    assert.deepEqual(args, ['keys', 'get', '--id', 'omnistar1account']);
    return JSON.stringify({ success: true, data: { id: 'omnistar1account', publicKey: COMPRESSED } });
  });
  const sig = await signChallengeViaSSP(signer, query, 'omnistar1account', 'cafe01');
  assert.equal(sig, 'DERSIG');
  assert.equal(seen.hex, 'cafe01');
  assert.equal(seen.pk, COMPRESSED, 'passes the compressed pubkey hex to signRaw');
});

test('signChallengeViaSSP errors when keys get has no publicKey', async () => {
  const signer = { async signRaw() { return 'x'; } };
  const query = q(() => JSON.stringify({ success: true, data: { id: 'a' } }));
  await assert.rejects(signChallengeViaSSP(signer, query, 'a', 'aa'), /no publicKey/);
});

test('waitForObjectValid resolves when the object is valid, throws on timeout', async () => {
  let calls = 0;
  const fetchValid = (async () => {
    calls++;
    return { ok: true, json: async () => ({ groups: [{ nestedObjects: [{ id: 'U', isValid: true, isDeleted: false }] }] }) };
  }) as unknown as typeof fetch;
  await waitForObjectValid(BUNDLE, 'omnistar1safe', 'U', { fetchImpl: fetchValid, attempts: 3, intervalMs: 1 });
  assert.equal(calls, 1, 'returns on the first valid poll');

  const fetchInvalid = (async () => ({
    ok: true,
    json: async () => ({ groups: [{ nestedObjects: [{ id: 'U', isValid: false, isDeleted: false }] }] }),
  })) as unknown as typeof fetch;
  await assert.rejects(
    waitForObjectValid(BUNDLE, 'omnistar1safe', 'U', { fetchImpl: fetchInvalid, attempts: 2, intervalMs: 1 }),
    /not valid/,
  );
});

test('credential store round-trips per alias under the state root', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-cred-'));
  try {
    const root = () => dir;
    assert.equal(loadCredential('work', root), null, 'absent → null');
    const cred = {
      credentialIdB64url: 'Y3JlZA', safe: 'omnistar1safe', account: 'omnistar1account',
      org: 'org', user: 'u', registeredAt: '2026-06-17T00:00:00.000Z',
    };
    saveCredential('work', cred, root);
    assert.deepEqual(loadCredential('work', root), cred);
    assert.equal(loadCredential('other', root), null, 'isolated per alias');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
