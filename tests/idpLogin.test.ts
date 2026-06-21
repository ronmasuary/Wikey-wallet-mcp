import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Secp256k1 } from '@cosmjs/crypto';
import { toHex } from '@cosmjs/encoding';
import { gatewayLogin, type LoginSigner } from '../src/core/idp/login.js';
import { omnistarAddress } from '../src/core/idp/identity.js';

// Config is resolved from the state root + CASDOOR_*/WIKEY_* env. Clear every knob
// so a developer's shell can't leak into the assertions, then set only what we want.
const ENV_KEYS = [
  'CASDOOR_HOST', 'CASDOOR_RP_ID', 'CASDOOR_ORIGIN', 'CASDOOR_ORG', 'CASDOOR_USER',
  'CASDOOR_APP', 'CASDOOR_CLIENT_ID', 'CASDOOR_CLIENT_SECRET', 'CASDOOR_REDIRECT_URI',
  'CASDOOR_ACCOUNT', 'CASDOOR_SCOPE', 'CASDOOR_STATE',
  'WIKEY_NODE', 'WIKEY_ENV', 'WIKEY_SECURE', 'WIKEY_SSP_DIR',
];

const b64url = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
const fakeJwt = (payload: object): string => [b64url({ alg: 'RS256', typ: 'JWT' }), b64url(payload), 'sig'].join('.');
const jsonRes = (obj: unknown, headers?: Record<string, string>): Response =>
  new Response(JSON.stringify(obj), { status: 200, headers: { 'content-type': 'application/json', ...(headers ?? {}) } });

async function withFixture(fn: (dir: string) => Promise<void>): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  const savedFetch = globalThis.fetch;
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-idp-login-'));
  try {
    await fn(dir);
  } finally {
    globalThis.fetch = savedFetch;
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    rmSync(dir, { recursive: true, force: true });
  }
}

function writeTarget(dir: string, extra: Record<string, string> = {}): void {
  const idp = path.join(dir, 'idp');
  mkdirSync(idp, { recursive: true });
  writeFileSync(
    path.join(idp, 'gateway-target.json'),
    JSON.stringify({
      host: 'https://gateway.test',
      rpId: 'gateway.test',
      origin: 'https://gateway.test',
      organization: 'organization_xyz',
      username: 'xyz_bot',
      application: 'application_openrouter',
      clientId: 'client123',
      redirectUri: 'http://localhost:9000/callback',
      ...extra,
    }),
  );
}

function writeCredential(dir: string, cred: object): void {
  const idp = path.join(dir, 'idp');
  mkdirSync(idp, { recursive: true });
  writeFileSync(path.join(idp, 'casdoor-credential.json'), JSON.stringify(cred));
}

test('gatewayLogin: passkey login mints amr:fido token + creates the on-chain object', async () => {
  await withFixture(async (dir) => {
    process.env.WIKEY_SSP_DIR = dir;
    const account = 'omnistar1acct00000000000000000000000000000000';
    process.env.CASDOOR_ACCOUNT = account; // skip reading wallet-cli config for the account

    // A real key so resolveWalletIdentity's ecPuk→safe self-check passes.
    const kp = await Secp256k1.makeKeypair(Buffer.from('11'.repeat(32), 'hex'));
    const ecPukHex = toHex(kp.pubkey); // 65-byte uncompressed (04||X||Y)
    const safe = omnistarAddress(ecPukHex);

    writeTarget(dir);
    writeCredential(dir, {
      credentialIdB64url: Buffer.from('cred-id-bytes').toString('base64url'),
      safe,
      account,
      organization: 'organization_xyz',
      username: 'xyz_bot',
      registeredAt: new Date().toISOString(),
    });

    let capturedUuid: string | undefined;
    let createCalls = 0;
    let signCalls = 0;
    const signer: LoginSigner = {
      createFidoObject: async ({ uuid }) => {
        capturedUuid = uuid;
        createCalls++;
        return JSON.stringify({ data: { txHash: 'TXHASH1' } });
      },
      signChallenge: async () => {
        signCalls++;
        return JSON.stringify({ data: { signature: 'aabbcc' } });
      },
    };

    const seen = { finishUrl: '', tokenForm: '' };
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const u = new URL(url);
      if (u.pathname === '/snapshot/safe') {
        const pk = u.searchParams.get('publickey');
        if (pk === account) {
          return jsonRes({ groups: [{ nestedObjects: [{ class: 'profile', object: { safes: [{ safe_address: safe }] } }] }] });
        }
        // safe snapshot: ecPuk always; the on-chain object only after create-fido-object
        const nested = capturedUuid ? [{ id: capturedUuid, isValid: true, isDeleted: false }] : [];
        return jsonRes({ assets: { ecPuk: ecPukHex }, groups: [{ nestedObjects: nested }] });
      }
      if (u.pathname === '/api/webauthn/signin/begin') {
        return jsonRes(
          { publicKey: { challenge: Buffer.from('challenge-bytes').toString('base64url'), rpId: 'gateway.test' } },
          { 'set-cookie': 'casdoor_session_id=xyz' },
        );
      }
      if (u.pathname === '/api/webauthn/signin/finish') {
        seen.finishUrl = url;
        return jsonRes({ status: 'ok', data: 'authcode-123' });
      }
      if (u.pathname === '/api/login/oauth/access_token') {
        seen.tokenForm = String(init?.body ?? '');
        return jsonRes({
          access_token: fakeJwt({ amr: ['fido'], aud: ['client123'], sub: 'sub-1', scope: 'read' }),
          token_type: 'Bearer',
          expires_in: 3600,
        });
      }
      if (u.pathname === '/api/userinfo') {
        return jsonRes({ sub: 'sub-1', aud: 'client123' });
      }
      throw new Error('unexpected fetch ' + url);
    }) as unknown as typeof fetch;

    const res = await gatewayLogin({}, signer);

    assert.equal(res.ok, true);
    assert.equal(res.safe, safe);
    assert.equal(res.account, account);
    assert.equal(res.txHash, 'TXHASH1');
    assert.equal(res.objectId, capturedUuid);
    assert.equal(res.objectValid, true);
    assert.deepEqual((res.claims as { amr?: unknown })?.amr, ['fido']);
    assert.match(res.accessToken, /^eyJ/);
    assert.equal(res.expiresIn, 3600);
    assert.equal(createCalls, 1, 'exactly one on-chain object created');
    assert.equal(signCalls, 1, 'exactly one assertion signed');

    // signin/finish carries PKCE S256
    assert.match(seen.finishUrl, /code_challenge_method=S256/);
    assert.match(seen.finishUrl, /code_challenge=/);
    // token exchange: authorization_code + PKCE verifier, public client (no secret)
    assert.match(seen.tokenForm, /grant_type=authorization_code/);
    assert.match(seen.tokenForm, /code_verifier=/);
    assert.ok(!/client_secret/.test(seen.tokenForm), 'public PKCE client sends no client_secret');
  });
});

test('gatewayLogin: rejects when the stored credential is for a different user', async () => {
  await withFixture(async (dir) => {
    process.env.WIKEY_SSP_DIR = dir;
    writeTarget(dir);
    writeCredential(dir, {
      credentialIdB64url: 'x',
      safe: 'omnistar1safe',
      account: 'omnistar1acct',
      organization: 'organization_xyz',
      username: 'someone_else',
      registeredAt: 't',
    });
    const signer: LoginSigner = { createFidoObject: async () => '{}', signChallenge: async () => '{}' };
    await assert.rejects(gatewayLogin({}, signer), /enrolled credential is for/);
  });
});

test('gatewayLogin: rejects when no credential is enrolled', async () => {
  await withFixture(async (dir) => {
    process.env.WIKEY_SSP_DIR = dir;
    writeTarget(dir);
    const signer: LoginSigner = { createFidoObject: async () => '{}', signChallenge: async () => '{}' };
    await assert.rejects(gatewayLogin({}, signer), /no enrolled credential/);
  });
});
