import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { mkdtempSync as mkdtemp, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { SessionManager } from '../src/core/session.js';

const SIGNING = fileURLToPath(new URL('./fixtures/fake-signing-server.mjs', import.meta.url));
const SSP = fileURLToPath(new URL('./fixtures/fake-ssp-util.mjs', import.meta.url));
const WC = fileURLToPath(new URL('./fixtures/fake-wallet-cli.mjs', import.meta.url));

const SIGN_SCENARIO = JSON.stringify({
  sign: { unsignedData: 'AA', signingPubKey: 'PK' },
  requireStdinEnd: false,
  stdout: '{"ok":true}',
  exit: 0,
});

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

function tmpDir(): string {
  return mkdtemp(path.join(tmpdir(), 'wmcp-sess-'));
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

interface Ctx {
  dir: string;
  prev: Record<string, string | undefined>;
}

function setupEnv(port: number, extra: Record<string, string> = {}): Ctx {
  const dir = tmpDir();
  const keys = ['STUB_PORT', 'STUB_WC', 'WIKEY_SSP_DIR', 'STUB_SPAWN_LOG', 'STUB_ROTATE_EXIT', 'STUB_CONCUR_FILE'];
  const prev: Record<string, string | undefined> = {};
  for (const k of keys) prev[k] = process.env[k];
  process.env.STUB_PORT = String(port);
  process.env.STUB_WC = SIGN_SCENARIO;
  process.env.WIKEY_SSP_DIR = dir; // no dev.kek here → kek provider 'auto'
  for (const [k, v] of Object.entries(extra)) process.env[k] = v;
  return { dir, prev };
}

function teardownEnv(ctx: Ctx): void {
  for (const [k, v] of Object.entries(ctx.prev)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  rmSync(ctx.dir, { recursive: true, force: true });
}

function makeSession(port: number, dir: string, over: Partial<ConstructorParameters<typeof SessionManager>[0]> = {}) {
  const logs: string[] = [];
  const s = new SessionManager({
    bins: { signingServer: SIGNING, sspUtil: SSP, walletCli: WC },
    nonceFile: path.join(dir, '.nonce'),
    port,
    probeTimeoutMs: 4000,
    rotationMs: 60_000,
    log: (m) => logs.push(m),
    ...over,
  });
  return { s, logs };
}

test('lazy: a fresh session spawns nothing and reports no-session', async () => {
  const port = await freePort();
  const ctx = setupEnv(port);
  try {
    const { s } = makeSession(port, ctx.dir);
    const st = s.status();
    assert.equal(st.active, false);
    assert.equal(st.pid, null);
    assert.equal(st.state, 'no-session');
    s.shutdown();
  } finally {
    teardownEnv(ctx);
  }
});

test('first signing call brings up exactly one signing-server (H8 concurrent)', async () => {
  const port = await freePort();
  const spawnLog = path.join(tmpDir(), 'spawns.log');
  const ctx = setupEnv(port, { STUB_SPAWN_LOG: spawnLog });
  try {
    const { s } = makeSession(port, ctx.dir);
    // two concurrent first-calls
    const [a, b] = await Promise.all([s.signPrompted([], []), s.signPrompted([], [])]);
    assert.equal(a, '{"ok":true}');
    assert.equal(b, '{"ok":true}');
    const spawns = existsSync(spawnLog) ? readFileSync(spawnLog, 'utf8').trim().split('\n').filter(Boolean) : [];
    assert.equal(spawns.length, 1, `expected exactly one signing-server spawn, got ${spawns.length}`);
    assert.ok(s.status().active);
    s.shutdown();
  } finally {
    rmSync(path.dirname(spawnLog), { recursive: true, force: true });
    teardownEnv(ctx);
  }
});

test('shutdown kills only our own child; a second dummy signing-server survives (H5)', async () => {
  const sessionPort = await freePort();
  const dummyPort = await freePort();
  const ctx = setupEnv(sessionPort);
  // a second, independent signing-server "-spawned-by-agent" belonging to another tenant
  const dummy = spawn(process.execPath, [SIGNING, '-spawned-by-agent'], {
    env: { ...process.env, STUB_PORT: String(dummyPort) },
    stdio: 'ignore',
  });
  try {
    await sleep(200);
    const { s } = makeSession(sessionPort, ctx.dir);
    await s.signPrompted([], []);
    const ownPid = s.status().pid!;
    assert.ok(alive(ownPid));
    assert.ok(alive(dummy.pid!));

    s.shutdown();
    // wait for our child to die
    for (let i = 0; i < 50 && alive(ownPid); i++) await sleep(20);
    assert.equal(alive(ownPid), false, 'our own child should be killed');
    assert.equal(alive(dummy.pid!), true, 'the dummy (other tenant) must survive — never pkill');
  } finally {
    try {
      dummy.kill('SIGKILL');
    } catch {
      /* ignore */
    }
    teardownEnv(ctx);
  }
});

test('rotateNow swaps the key and records lastRotation; serialized with signing', async () => {
  const port = await freePort();
  const concur = path.join(tmpDir(), 'concur.log');
  const ctx = setupEnv(port, { STUB_ROTATE_EXIT: '0', STUB_CONCUR_FILE: concur });
  try {
    const { s } = makeSession(port, ctx.dir);
    await s.signPrompted([], []); // bring up + first proof
    // race a sign and a rotation — the mutex must serialize the two ssp-util calls
    await Promise.all([s.signPrompted([], []), s.rotateNow()]);
    const st = s.status();
    assert.ok(st.lastRotation && st.lastRotation > 0);
    assert.equal(st.wedged, false);

    // verify ssp-util invocations never overlapped (no nested START/END)
    const events = readFileSync(concur, 'utf8').trim().split('\n').filter(Boolean);
    let depth = 0;
    for (const ev of events) {
      depth += ev.startsWith('START') ? 1 : -1;
      assert.ok(depth === 0 || depth === 1, `ssp-util calls overlapped: ${events.join(' | ')}`);
    }
    s.shutdown();
  } finally {
    rmSync(path.dirname(concur), { recursive: true, force: true });
    teardownEnv(ctx);
  }
});

test('runWithSession (keys create): answers the y/n, returns JSON, no hang', async () => {
  // Regression: keys create signs over the signer HTTP API and ends with a
  // `Set as default? (y/n)` prompt. Routed through the prompt engine with an
  // empty queue it deadlocked on that prompt and rode the timeout (key created,
  // client errors, model retries → duplicate keys). runWithSession answers the
  // y/n via `input` so wallet-cli prints its JSON and exits.
  const port = await freePort();
  const ctx = setupEnv(port, { STUB_WC: JSON.stringify({ keysCreate: true }) });
  try {
    const { s } = makeSession(port, ctx.dir);

    // default ('n') — key created, not set as default
    const outNo = await s.runWithSession(['keys', 'create'], { input: 'n\n' });
    const parsedNo = JSON.parse(outNo);
    assert.equal(parsedNo.success, true);
    assert.equal(parsedNo.data.id, 'omnistar1xyz');
    assert.equal(parsedNo.data.setAsDefault, false);
    assert.ok(s.status().active, 'session should be up after a session-gated run');

    // 'y' — set as default
    const outYes = await s.runWithSession(['keys', 'create'], { input: 'y\n' });
    assert.equal(JSON.parse(outYes).data.setAsDefault, true);

    s.shutdown();
  } finally {
    teardownEnv(ctx);
  }
});

test('fatal rotation (exit 4) wedges the session; further signing is refused', async () => {
  const port = await freePort();
  const ctx = setupEnv(port, { STUB_ROTATE_EXIT: '4' });
  try {
    const { s } = makeSession(port, ctx.dir);
    await s.signPrompted([], []); // proof path ignores STUB_ROTATE_EXIT
    await assert.rejects(s.rotateNow(), /SSP unreachable/);
    assert.equal(s.status().wedged, true);
    assert.equal(s.status().state, 'wedged');
    await assert.rejects(s.signPrompted([], []), /wedged/);
    s.shutdown();
  } finally {
    teardownEnv(ctx);
  }
});
