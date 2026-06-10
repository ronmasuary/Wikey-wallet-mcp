import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { SessionManager } from '../src/core/session.js';
import { stateRoot, keystoreDir, walletHome, walletCliEnv } from '../src/core/binPaths.js';

const SIGNING = fileURLToPath(new URL('./fixtures/fake-signing-server.mjs', import.meta.url));
const SSP = fileURLToPath(new URL('./fixtures/fake-ssp-util.mjs', import.meta.url));
const WC = fileURLToPath(new URL('./fixtures/fake-wallet-cli.mjs', import.meta.url));

const SIGN_SCENARIO = JSON.stringify({
  sign: { unsignedData: 'AA', signingPubKey: 'PK' },
  requireStdinEnd: false,
  stdout: '{"ok":true}',
  exit: 0,
});

const ENV_KEYS = ['STUB_PORT', 'STUB_WC', 'WIKEY_SSP_DIR', 'STUB_SPAWN_LOG', 'STUB_WC_ENV_LOG'];

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

// ── unit: path derivation ──────────────────────────────────────────────────

test('stateRoot/keystoreDir/walletHome all derive from WIKEY_SSP_DIR', () => {
  const prev = process.env.WIKEY_SSP_DIR;
  try {
    process.env.WIKEY_SSP_DIR = '/tmp/wmcp-root-x';
    assert.equal(stateRoot(), '/tmp/wmcp-root-x');
    assert.equal(keystoreDir(), path.join('/tmp/wmcp-root-x', 'keystore'));
    assert.equal(walletHome(), '/tmp/wmcp-root-x');
    assert.equal(walletCliEnv().HOME, '/tmp/wmcp-root-x');
  } finally {
    if (prev === undefined) delete process.env.WIKEY_SSP_DIR;
    else process.env.WIKEY_SSP_DIR = prev;
  }
});

test('stateRoot defaults to ~/.ssp when WIKEY_SSP_DIR is unset', () => {
  const prev = process.env.WIKEY_SSP_DIR;
  try {
    delete process.env.WIKEY_SSP_DIR;
    assert.equal(stateRoot(), path.join(homedir(), '.ssp'));
    assert.equal(keystoreDir(), path.join(homedir(), '.ssp', 'keystore'));
  } finally {
    if (prev === undefined) delete process.env.WIKEY_SSP_DIR;
    else process.env.WIKEY_SSP_DIR = prev;
  }
});

// ── integration: SSP keystore-dir + wallet-cli HOME pinning ─────────────────

test('doInit pins -keystore-dir <root>/keystore and HOME=<root>; wallet-cli inherits HOME=<root>', async () => {
  const port = await freePort();
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-root-'));
  const spawnLog = path.join(dir, 'spawns.log');
  const wcEnvLog = path.join(dir, 'wc-env.log');
  const prev: Record<string, string | undefined> = {};
  for (const k of ENV_KEYS) prev[k] = process.env[k];
  process.env.STUB_PORT = String(port);
  process.env.STUB_WC = SIGN_SCENARIO;
  process.env.WIKEY_SSP_DIR = dir;
  process.env.STUB_SPAWN_LOG = spawnLog;
  process.env.STUB_WC_ENV_LOG = wcEnvLog;
  try {
    const s = new SessionManager({
      bins: { signingServer: SIGNING, sspUtil: SSP, walletCli: WC },
      nonceFile: path.join(dir, '.nonce'),
      port,
      probeTimeoutMs: 3000,
      rotationMs: 60_000,
      log: () => {},
    });
    assert.equal(await s.signPrompted([], []), '{"ok":true}');

    const spawn0 = readFileSync(spawnLog, 'utf8').trim();
    assert.match(spawn0, new RegExp(`ksdir=${dir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/keystore`),
      `SSP must be pinned to the state-root keystore: ${spawn0}`);
    assert.match(spawn0, new RegExp(`home=${dir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    assert.ok(existsSync(keystoreDir()), 'keystore dir created before spawn');

    const wcEnv = readFileSync(wcEnvLog, 'utf8').trim();
    assert.match(wcEnv, new RegExp(`home=${dir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`),
      `wallet-cli must run with HOME pinned to the state root: ${wcEnv}`);

    s.shutdown();
  } finally {
    for (const k of ENV_KEYS) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
