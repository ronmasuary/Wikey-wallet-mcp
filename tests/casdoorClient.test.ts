import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { CasdoorClient, makeCookieJar, pkcePair, decodeJwt, type GatewayDeps } from '../src/core/casdoorClient.js';
import { buildAssertion } from '../src/core/webauthn.js';
import type { IdentityBundle } from '../src/core/identityRegistry.js';
import type { StoredCredential } from '../src/core/casdoorIdentity.js';

const EC_PUK =
  '04fd6d3b271916ee3833382e4ae016460510636eb4ee2daba196ceae04cfc75cdd73aa7b0f2de6bf4124299b592ecc24ef8fe6bf722f57088aa3c786eed253450b';
const SNAPSHOT_OK = JSON.stringify({
  data: { address: 'omnistar1account', snapshot: [{ address: 'omnistar1safe', isMain: true, assets: { ecPuk: EC_PUK } }] },
});
const KEYS_GET = JSON.stringify({ data: { id: 'omnistar1account', publicKey: '02' + 'ab'.repeat(32) } });
const FIXED_CHALLENGE = 'Y2hhbGxlbmdlLXZlY3Rvcg';
// A throwaway 3-segment JWT (exp far in the future).
const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ3IiwiZXhwIjo5OTk5OTk5OTk5fQ.c2ln';

interface Req {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function startCasdoor(opts: { consent?: boolean; gatewayStatus?: number }): Promise<{
  bundle: IdentityBundle;
  requests: Req[];
  close: () => Promise<void>;
}> {
  const requests: Req[] = [];
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        requests.push({ method: req.method ?? '', url: req.url ?? '', headers: req.headers, body });
        const send = (code: number, obj: unknown, headers: Record<string, string> = {}) => {
          res.writeHead(code, { 'content-type': 'application/json', ...headers });
          res.end(typeof obj === 'string' ? obj : JSON.stringify(obj));
        };
        const port = (server.address() as AddressInfo).port;
        const origin = `http://127.0.0.1:${port}`;
        const u = req.url ?? '';
        const m = req.method ?? '';
        if (m === 'POST' && u === '/api/login') return send(200, { status: 'ok' }, { 'set-cookie': 'sid=abc; Path=/' });
        if (m === 'GET' && u.startsWith('/api/webauthn/signup/begin'))
          return send(200, { publicKey: { challenge: FIXED_CHALLENGE, rp: { id: 'localhost' } } });
        if (m === 'POST' && u === '/api/webauthn/signup/finish') return send(200, { status: 'ok' });
        if (m === 'GET' && u.startsWith('/api/webauthn/signin/begin'))
          return send(200, { publicKey: { challenge: FIXED_CHALLENGE, rpId: 'localhost' } }, { 'set-cookie': 'sid=sess; Path=/' });
        if (m === 'POST' && u.startsWith('/api/webauthn/signin/finish'))
          return send(200, opts.consent ? { status: 'ok', data: { required: true } } : { status: 'ok', data: 'AUTHCODE' });
        if (m === 'POST' && u === '/api/login/oauth/access_token') return send(200, { access_token: JWT, expires_in: 3600 });
        if (m === 'GET' && u.startsWith('/snapshot/safe')) {
          const uuid = buildAssertion({ rpId: 'rp', origin, challengeB64url: FIXED_CHALLENGE, credentialId: Buffer.from([1]) }).uuid;
          return send(200, { groups: [{ nestedObjects: [{ id: uuid, isValid: true, isDeleted: false }] }] });
        }
        if (m === 'POST' && u.startsWith('/api/server/')) {
          const st = opts.gatewayStatus ?? 200;
          if (st !== 200) return send(st, { error: 'Unauthorized operation' });
          return send(200, { jsonrpc: '2.0', id: 1, result: { tools: [{ name: 'search' }] } });
        }
        send(404, {});
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port;
      const base = `http://127.0.0.1:${port}`;
      const bundle: IdentityBundle = {
        alias: 'work', host: base, rpId: 'localhost', origin: base, org: 'org_k', user: 'user_k',
        app: 'app_k', clientId: 'cid123', snapshotNode: `127.0.0.1:${port}`, env: 'main',
        redirectUri: 'http://localhost:9000/callback', scope: 'read', snapshotSecure: false,
      };
      resolve({ bundle, requests, close: () => new Promise<void>((r) => server.close(() => r())) });
    });
  });
}

function deps(): GatewayDeps {
  return {
    session: {
      signPrompted: async () => '{"data":{"txHash":"0xabc"}}',
      signRaw: async () => 'aabbccddeeff',
    },
    query: async (args) => (args[0] === 'keys' ? KEYS_GET : SNAPSHOT_OK),
    waitOpts: { attempts: 3, intervalMs: 5 },
  };
}

const CRED: StoredCredential = {
  credentialIdB64url: Buffer.from('cred-id').toString('base64url'),
  safe: 'omnistar1safe', account: 'omnistar1account', org: 'org_k', user: 'user_k', registeredAt: 'x',
};

test('makeCookieJar parses Set-Cookie and emits a Cookie header; pkcePair + decodeJwt', () => {
  const jar = makeCookieJar();
  jar.absorb({ headers: { getSetCookie: () => ['a=1; Path=/', 'b=2; HttpOnly'] } } as unknown as Response);
  assert.equal(jar.header(), 'a=1; b=2');
  const { codeVerifier, codeChallenge } = pkcePair();
  assert.ok(codeVerifier.length > 20 && codeChallenge.length > 20 && codeVerifier !== codeChallenge);
  assert.equal(decodeJwt(JWT)?.sub, 'w');
});

test('register: password-login → signup/begin → signup/finish, returns the safe + credentialId', async () => {
  const { bundle, requests, close } = await startCasdoor({});
  try {
    const c = new CasdoorClient(deps());
    const res = await c.register(bundle, 'bootstrap-pw');
    assert.equal(res.registered, true);
    assert.equal(res.safe, 'omnistar1safe');
    assert.ok(res.credentialIdB64url.length > 0);
    const login = requests.find((r) => r.url === '/api/login');
    assert.ok(login && JSON.parse(login.body).password === 'bootstrap-pw', 'bootstrap password sent only to /api/login');
    assert.ok(requests.some((r) => r.url.startsWith('/api/webauthn/signup/finish')));
  } finally {
    await close();
  }
});

test('login: full PKCE dance → token; no client_secret sent, code_verifier present, cookie carried', async () => {
  const { bundle, requests, close } = await startCasdoor({});
  try {
    const c = new CasdoorClient(deps());
    const res = await c.login(bundle, CRED);
    assert.equal(res.token, JWT);
    assert.ok(res.expiresAt > Date.now(), 'expiresAt in the future');
    assert.equal(res.safe, 'omnistar1safe');

    const tok = requests.find((r) => r.url === '/api/login/oauth/access_token');
    assert.ok(tok, 'token exchange happened');
    const form = new URLSearchParams(tok!.body);
    assert.ok(form.get('code_verifier'), 'PKCE verifier present');
    assert.equal(form.get('client_secret'), null, 'NO client_secret (public client)');
    assert.equal(form.get('code'), 'AUTHCODE');

    const finish = requests.find((r) => r.url.startsWith('/api/webauthn/signin/finish'));
    assert.equal(finish!.headers.cookie, 'sid=sess', 'cookie from signin/begin carried to finish');
  } finally {
    await close();
  }
});

test('login: a consent requirement throws a clear "disable custom scopes" error', async () => {
  const { bundle, close } = await startCasdoor({ consent: true });
  try {
    const c = new CasdoorClient(deps());
    await assert.rejects(c.login(bundle, CRED), /consent step|custom OAuth scopes/);
  } finally {
    await close();
  }
});

test('gatewayCall returns the upstream result; 403 is surfaced clearly', async () => {
  const ok = await startCasdoor({});
  try {
    const c = new CasdoorClient(deps());
    const out = (await c.gatewayCall(ok.bundle, JWT, 'org_k/sales-mcp', 'tools/list', {})) as { result?: { tools?: unknown[] } };
    assert.deepEqual(out.result?.tools, [{ name: 'search' }]);
    const call = ok.requests.find((r) => r.url === '/api/server/org_k/sales-mcp');
    assert.equal(call!.headers.authorization, `Bearer ${JWT}`, 'bearer attached');
  } finally {
    await ok.close();
  }

  const denied = await startCasdoor({ gatewayStatus: 403 });
  try {
    const c = new CasdoorClient(deps());
    await assert.rejects(c.gatewayCall(denied.bundle, JWT, 'org_k/secret', 'tools/list', {}), /HTTP 403|lacks a Casdoor permission/);
  } finally {
    await denied.close();
  }
});
