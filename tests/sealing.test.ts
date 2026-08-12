import { test } from 'node:test';
import { TEST_ACCOUNT } from './fixtures/testAccount.js';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import { SessionManager } from '../src/core/session.js';

const SIGNING = fileURLToPath(new URL('./fixtures/fake-signing-server.mjs', import.meta.url));
const SSP = fileURLToPath(new URL('./fixtures/fake-ssp-util.mjs', import.meta.url));
const WC_PATH = fileURLToPath(new URL('./fixtures/fake-wallet-cli.mjs', import.meta.url));
// wallet-cli launcher: run the .mjs stub via node (matches the real Windows path
// where wallet-cli is a Node CLI, and is cross-platform spawnable).
const WC = { command: process.execPath, prefixArgs: [WC_PATH], display: WC_PATH };
const HEX64 = /[0-9a-fA-F]{64}/;
const SIGN_SCENARIO = JSON.stringify({ sign: { unsignedData: 'AA', signingPubKey: 'PK' }, stdout: '{"ok":true}', exit: 0 });

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const a = s.address();
      const port = typeof a === 'object' && a ? a.port : 0;
      s.close(() => resolve(port));
    });
    s.on('error', reject);
  });
}

test('H11: the HMAC key never appears in logs, status, output, or the child argv; zeroized on shutdown', async () => {
  const port = await freePort();
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-seal-'));
  const prev = { STUB_PORT: process.env.STUB_PORT, STUB_WC: process.env.STUB_WC, WIKEY_SSP_DIR: process.env.WIKEY_SSP_DIR, STUB_ROTATE_EXIT: process.env.STUB_ROTATE_EXIT };
  process.env.STUB_PORT = String(port);
  process.env.STUB_WC = SIGN_SCENARIO;
  process.env.WIKEY_SSP_DIR = dir;
  process.env.STUB_ROTATE_EXIT = '0';

  const logs: string[] = [];
  const s = new SessionManager({
    bins: { signingServer: SIGNING, sspUtil: SSP, walletCli: WC },
    nonceFile: path.join(dir, '.nonce'),
    port,
    probeTimeoutMs: 4000,
    rotationMs: 60_000,
    log: (m) => logs.push(m),
  });

  // observe zeroize: spy on Buffer.fill for 64-byte buffers (the key)
  const origFill = Buffer.prototype.fill;
  let zeroed = false;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (Buffer.prototype as any).fill = function (this: Buffer, ...a: unknown[]) {
    if (this.length === 64 && a[0] === 0) zeroed = true;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (origFill as any).apply(this, a);
  };

  try {
    const out = await s.signPrompted(TEST_ACCOUNT, [], []);
    await s.rotateNow();

    // 1. tool output carries no key
    assert.doesNotMatch(out, HEX64);

    // 2. status carries no key material
    const statusJson = JSON.stringify(s.status());
    assert.doesNotMatch(statusJson, HEX64);
    assert.doesNotMatch(statusJson, /SSP_HMAC_KEY|hmac/i);

    // 3. logs carry no key
    for (const line of logs) assert.doesNotMatch(line, HEX64, `log line leaked a 64-hex token: ${line}`);

    // 4. the child's argv (ps) carries no key — the key is injected via env, never argv
    const pid = s.status().pid!;
    const argv = execFileSync('ps', ['-p', String(pid), '-o', 'args='], { encoding: 'utf8' });
    assert.doesNotMatch(argv, HEX64, `child argv leaked a key: ${argv}`);

    // 5. zeroize on shutdown
    s.shutdown();
    assert.ok(zeroed, 'the key Buffer should be zeroized (fill(0)) on rotate/shutdown');
  } finally {
    Buffer.prototype.fill = origFill;
    s.shutdown();
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete (process.env as Record<string, string | undefined>)[k];
      else process.env[k] = v;
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
