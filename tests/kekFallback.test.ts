import { test } from 'node:test';
import { TEST_ACCOUNT } from './fixtures/testAccount.js';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { SessionManager } from '../src/core/session.js';

const SIGNING = fileURLToPath(new URL('./fixtures/fake-signing-server.mjs', import.meta.url));
const SSP = fileURLToPath(new URL('./fixtures/fake-ssp-util.mjs', import.meta.url));
const WC_PATH = fileURLToPath(new URL('./fixtures/fake-wallet-cli.mjs', import.meta.url));
// wallet-cli launcher: run the .mjs stub via node (matches the real Windows path
// where wallet-cli is a Node CLI, and is cross-platform spawnable).
const WC = { command: process.execPath, prefixArgs: [WC_PATH], display: WC_PATH };

const SIGN_SCENARIO = JSON.stringify({
  sign: { unsignedData: 'AA', signingPubKey: 'PK' },
  requireStdinEnd: false,
  stdout: '{"ok":true}',
  exit: 0,
});

const ENV_KEYS = [
  'STUB_PORT',
  'STUB_WC',
  'WIKEY_SSP_DIR',
  'STUB_SPAWN_LOG',
  'STUB_KEK_FAIL',
  'STUB_BOOT_FAIL',
  'isDevEnv',
  'WIKEY_IS_DEV_ENV',
];

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      s.close(() => resolve(port));
    });
    s.on('error', reject);
  });
}

interface Ctx {
  dir: string;
  spawnLog: string;
  prev: Record<string, string | undefined>;
}

function setup(port: number, extra: Record<string, string> = {}): Ctx {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-kekfb-'));
  const spawnLog = path.join(dir, 'spawns.log');
  const prev: Record<string, string | undefined> = {};
  for (const k of ENV_KEYS) {
    prev[k] = process.env[k];
    delete process.env[k];
  }
  process.env.STUB_PORT = String(port);
  process.env.STUB_WC = SIGN_SCENARIO;
  process.env.WIKEY_SSP_DIR = dir;
  process.env.STUB_SPAWN_LOG = spawnLog;
  for (const [k, v] of Object.entries(extra)) process.env[k] = v;
  return { dir, spawnLog, prev };
}

function teardown(ctx: Ctx): void {
  for (const k of ENV_KEYS) {
    if (ctx.prev[k] === undefined) delete process.env[k];
    else process.env[k] = ctx.prev[k];
  }
  rmSync(ctx.dir, { recursive: true, force: true });
}

function spawns(ctx: Ctx): string[] {
  return existsSync(ctx.spawnLog)
    ? readFileSync(ctx.spawnLog, 'utf8').trim().split('\n').filter(Boolean)
    : [];
}

function makeSession(port: number, dir: string) {
  const logs: string[] = [];
  const s = new SessionManager({
    bins: { signingServer: SIGNING, sspUtil: SSP, walletCli: WC },
    nonceFile: path.join(dir, '.nonce'),
    port,
    probeTimeoutMs: 3000,
    rotationMs: 60_000,
    log: (m) => logs.push(m),
  });
  return { s, logs };
}

test('no-KEK on hardware (marker on STDOUT) → retries once with env + SSP_KEK, succeeds', async () => {
  const port = await freePort();
  const ctx = setup(port, { STUB_KEK_FAIL: 'stdout' });
  try {
    const { s, logs } = makeSession(port, ctx.dir);
    const out = await s.signPrompted(TEST_ACCOUNT, [], []);
    assert.equal(out, '{"ok":true}');

    const sp = spawns(ctx);
    assert.equal(sp.length, 2, `expected hardware attempt + software retry, got: ${sp.join(' | ')}`);
    assert.match(sp[0]!, /kek=auto sspkek=unset/, 'first attempt is hardware, no SSP_KEK');
    assert.match(sp[1]!, /kek=env sspkek=set/, 'retry is software with SSP_KEK injected');

    const st = s.status();
    assert.equal(st.active, true);
    assert.equal(st.kekProvider, 'env');
    assert.equal(st.kekFallback, true, 'fallback flag set (no hardware, not isDevEnv)');
    assert.ok(existsSync(path.join(ctx.dir, 'dev.kek')), 'software KEK persisted for restart-stability');
    assert.ok(logs.some((l) => l.includes('falling back to persisted software KEK')));
    s.shutdown();
  } finally {
    teardown(ctx);
  }
});

test('no-KEK marker on STDERR also triggers the fallback (both streams scanned)', async () => {
  const port = await freePort();
  const ctx = setup(port, { STUB_KEK_FAIL: 'stderr' });
  try {
    const { s } = makeSession(port, ctx.dir);
    assert.equal(await s.signPrompted(TEST_ACCOUNT, [], []), '{"ok":true}');
    const sp = spawns(ctx);
    assert.equal(sp.length, 2);
    assert.match(sp[1]!, /kek=env sspkek=set/);
    assert.equal(s.status().kekProvider, 'env');
    s.shutdown();
  } finally {
    teardown(ctx);
  }
});

test('a non-KEK boot failure does NOT trigger fallback and surfaces the output tail', async () => {
  const port = await freePort();
  const ctx = setup(port, { STUB_BOOT_FAIL: '1' });
  try {
    const { s } = makeSession(port, ctx.dir);
    await assert.rejects(s.signPrompted(TEST_ACCOUNT, [], []), /address already in use/);
    const sp = spawns(ctx);
    assert.equal(sp.length, 1, `non-KEK failure must not retry, got: ${sp.join(' | ')}`);
    assert.match(sp[0]!, /kek=auto/);
    s.shutdown();
  } finally {
    teardown(ctx);
  }
});

test('isDevEnv=true goes straight to software KEK (no hardware attempt)', async () => {
  const port = await freePort();
  // STUB_KEK_FAIL=stdout would fail a hardware attempt — but there must be none.
  const ctx = setup(port, { STUB_KEK_FAIL: 'stdout', isDevEnv: 'true' });
  try {
    const { s } = makeSession(port, ctx.dir);
    assert.equal(await s.signPrompted(TEST_ACCOUNT, [], []), '{"ok":true}');
    const sp = spawns(ctx);
    assert.equal(sp.length, 1, `dev mode must spawn once (software), got: ${sp.join(' | ')}`);
    assert.match(sp[0]!, /kek=env sspkek=set/);
    const st = s.status();
    assert.equal(st.kekProvider, 'env');
    assert.equal(st.kekFallback, false, 'forced software via isDevEnv is not a runtime fallback');
    s.shutdown();
  } finally {
    teardown(ctx);
  }
});
