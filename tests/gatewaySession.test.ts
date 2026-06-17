import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { GatewaySession } from '../src/core/gatewaySession.js';
import { CasdoorClient, type LoginResult, type RegisterResult } from '../src/core/casdoorClient.js';
import { IdentityRegistry } from '../src/core/identityRegistry.js';
import { saveCredential } from '../src/core/casdoorIdentity.js';

const ENV = (aliases: string): NodeJS.ProcessEnv => {
  const out: NodeJS.ProcessEnv = { WIKEY_CASDOOR_ALIASES: aliases };
  for (const a of aliases.split(',')) {
    const A = a.toUpperCase();
    Object.assign(out, {
      [`WIKEY_CASDOOR_HOST__${A}`]: `http://localhost:8000`,
      [`WIKEY_CASDOOR_RP_ID__${A}`]: 'localhost',
      [`WIKEY_CASDOOR_ORIGIN__${A}`]: 'http://localhost:8000',
      [`WIKEY_CASDOOR_ORG__${A}`]: `org_${a}`,
      [`WIKEY_CASDOOR_USER__${A}`]: `user_${a}`,
      [`WIKEY_CASDOOR_APP__${A}`]: `app_${a}`,
      [`WIKEY_CASDOOR_CLIENT_ID__${A}`]: `cid_${a}`,
      [`WIKEY_CASDOOR_SNAPSHOT_NODE__${A}`]: 'node:9093',
      [`WIKEY_CASDOOR_ENV__${A}`]: 'main',
      [`WIKEY_CASDOOR_REDIRECT_URI__${A}`]: 'http://localhost:9000/callback',
      [`WIKEY_CASDOOR_BOOTSTRAP_PASSWORD__${A}`]: `pw_${a}`,
    });
  }
  return out;
};

// A fake client: counts logins per alias and returns a token expiring in `ttlMs`.
function fakeClient(ttlMs: number): { client: CasdoorClient; logins: Record<string, number> } {
  const logins: Record<string, number> = {};
  const client = {
    async register(bundle: { org: string }): Promise<RegisterResult> {
      return { registered: true, safe: 'omnistar1safe', account: 'omnistar1acct', credentialIdB64url: `cred_${bundle.org}` };
    },
    async login(bundle: { org: string }): Promise<LoginResult> {
      logins[bundle.org] = (logins[bundle.org] ?? 0) + 1;
      return { token: `tok-${bundle.org}-${logins[bundle.org]}`, expiresAt: Date.now() + ttlMs, account: 'a', safe: 'omnistar1safe' };
    },
    async gatewayCall(_b: unknown, token: string, owner: string, method: string): Promise<unknown> {
      return { token, owner, method };
    },
  } as unknown as CasdoorClient;
  return { client, logins };
}

function setup(ttlMs = 3600_000) {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-gw-'));
  const root = () => dir;
  const registry = new IdentityRegistry({ env: ENV('work,team'), stateRoot: root });
  const { client, logins } = fakeClient(ttlMs);
  const gw = new GatewaySession(client, registry, { stateRoot: root });
  return { dir, root, registry, gw, logins };
}

test('status lists every approved alias with no token; unregistered → registered:false', () => {
  const { dir, gw } = setup();
  try {
    const all = gw.status() as ReturnType<typeof gw.status> & Array<{ alias: string }>;
    assert.deepEqual((all as { alias: string }[]).map((s) => s.alias).sort(), ['team', 'work']);
    for (const s of all as { authenticated: boolean; registered: boolean }[]) {
      assert.equal(s.authenticated, false);
      assert.equal(s.registered, false);
      assert.ok(!('token' in s), 'status never carries a token');
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('login authenticates one alias only; status reflects per-alias auth, no token leaks', async () => {
  const { dir, root, gw } = setup();
  try {
    saveCredential('work', { credentialIdB64url: 'c', safe: 'omnistar1safe', account: 'a', org: 'org_work', user: 'u', registeredAt: 'x' }, root);
    const st = await gw.login('work');
    assert.equal(st.alias, 'work');
    assert.equal(st.authenticated, true);
    assert.equal(st.registered, true);
    assert.ok((st.expiresInSec ?? 0) > 0);
    assert.ok(!JSON.stringify(st).includes('tok-'), 'no token in status output');

    const team = gw.status('team') as { authenticated: boolean };
    assert.equal(team.authenticated, false, "team is unaffected by work's login");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a cached unexpired token is reused; an expired one triggers exactly one re-login', async () => {
  // ttl below the 30s skew → every ensureToken treats it as expired and re-logs in.
  const { dir, root, gw, logins } = setup(1);
  try {
    saveCredential('work', { credentialIdB64url: 'c', safe: 'omnistar1safe', account: 'a', org: 'org_work', user: 'u', registeredAt: 'x' }, root);
    await gw.call('work', 'org_work/mcp', 'search', {});
    await gw.call('work', 'org_work/mcp', 'search', {});
    assert.equal(logins['org_work'], 2, 'expired token forces a fresh login each call');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  const big = setup(3600_000);
  try {
    saveCredential('work', { credentialIdB64url: 'c', safe: 'omnistar1safe', account: 'a', org: 'org_work', user: 'u', registeredAt: 'x' }, big.root);
    await big.gw.call('work', 'org_work/mcp', 'search', {});
    await big.gw.call('work', 'org_work/mcp', 'search', {});
    assert.equal(big.logins['org_work'], 1, 'unexpired token reused — single login');
  } finally {
    rmSync(big.dir, { recursive: true, force: true });
  }
});

test('register persists a per-alias credential; shutdown clears all tokens', async () => {
  const { dir, gw } = setup();
  try {
    const r = await gw.register('team');
    assert.equal(r.registered, true);
    assert.equal((gw.status('team') as { registered: boolean }).registered, true);

    await gw.login('team');
    assert.equal((gw.status('team') as { authenticated: boolean }).authenticated, true);
    gw.shutdown();
    assert.equal((gw.status('team') as { authenticated: boolean }).authenticated, false, 'tokens dropped on shutdown');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
