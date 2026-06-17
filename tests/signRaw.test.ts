import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { SessionManager } from '../src/core/session.js';

const SIGNING_HTTP = fileURLToPath(new URL('./fixtures/fake-signing-server-http.mjs', import.meta.url));
const SSP = fileURLToPath(new URL('./fixtures/fake-ssp-util.mjs', import.meta.url));
const WC = fileURLToPath(new URL('./fixtures/fake-wallet-cli.mjs', import.meta.url));

const DER = '3045022100aabbccdd0220ffeeddcc';

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const a = s.address();
      const p = typeof a === 'object' && a ? a.port : 0;
      s.close(() => resolve(p));
    });
    s.on('error', reject);
  });
}

interface Ctx {
  dir: string;
  prev: Record<string, string | undefined>;
}

function setupEnv(port: number, extra: Record<string, string> = {}): Ctx {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-sr-'));
  const keys = ['STUB_PORT', 'WIKEY_SSP_DIR', 'STUB_SIGN_DER', 'STUB_SIGN_LOG', 'STUB_CONCUR_FILE'];
  const prev: Record<string, string | undefined> = {};
  for (const k of keys) prev[k] = process.env[k];
  process.env.STUB_PORT = String(port);
  process.env.WIKEY_SSP_DIR = dir;
  process.env.STUB_SIGN_DER = DER;
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

function makeSession(port: number, dir: string) {
  return new SessionManager({
    bins: { signingServer: SIGNING_HTTP, sspUtil: SSP, walletCli: WC },
    nonceFile: path.join(dir, '.nonce'),
    port,
    probeTimeoutMs: 4000,
    rotationMs: 60_000,
    log: () => {},
  });
}

test('signRaw computes a proof, POSTs §3a-shaped body, returns the DER signature', async () => {
  const port = await freePort();
  const signLog = path.join(tmpdir(), `sr-${port}.log`);
  const ctx = setupEnv(port, { STUB_SIGN_LOG: signLog });
  try {
    const s = makeSession(port, ctx.dir);
    const sig = await s.signRaw('aabbcc', '02' + 'ab'.repeat(32));
    assert.equal(sig, DER, 'returns the signer DER signature');

    const lines = existsSync(signLog) ? readFileSync(signLog, 'utf8').trim().split('\n').filter(Boolean) : [];
    assert.equal(lines.length, 1, 'exactly one /v1/sign call');
    const body = JSON.parse(lines[0]!);
    assert.equal(body.unsignedData, 'aabbcc', 'unsignedData passed through verbatim');
    assert.equal(body.signingPubKey, '02' + 'ab'.repeat(32), 'signingPubKey passed through');
    assert.ok(typeof body.requestId === 'string' && body.requestId.length > 0, 'requestId present');
    assert.ok('proof' in body, 'proof present');
    s.shutdown();
  } finally {
    rmSync(signLog, { force: true });
    teardownEnv(ctx);
  }
});

test('concurrent signRaw calls are serialized (nonce not raced)', async () => {
  const port = await freePort();
  const concur = path.join(tmpdir(), `sr-concur-${port}.log`);
  const ctx = setupEnv(port, { STUB_CONCUR_FILE: concur });
  try {
    const s = makeSession(port, ctx.dir);
    await Promise.all([
      s.signRaw('aa', '02' + 'cd'.repeat(32)),
      s.signRaw('bb', '02' + 'cd'.repeat(32)),
    ]);
    // ssp-util proof windows must never overlap: depth stays 0/1 (no nesting).
    const events = readFileSync(concur, 'utf8').trim().split('\n').filter(Boolean);
    assert.ok(events.length >= 4, 'both proof calls recorded START/END');
    let depth = 0;
    for (const ev of events) {
      depth += ev.startsWith('START') ? 1 : -1;
      assert.ok(depth === 0 || depth === 1, `ssp-util proof calls overlapped: ${events.join(' | ')}`);
    }
    s.shutdown();
  } finally {
    rmSync(concur, { force: true });
    teardownEnv(ctx);
  }
});
