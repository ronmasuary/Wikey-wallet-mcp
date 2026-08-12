import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { clearDefaultKeyPointer } from '../src/core/migrateDefaultKey.js';

const ADDR = 'omnistar1legacypointer00000';

function withConfig(contents: unknown, fn: (file: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-mig-'));
  try {
    mkdirSync(path.join(dir, '.wallet-cli'), { recursive: true });
    const file = path.join(dir, '.wallet-cli', 'config.json');
    writeFileSync(file, JSON.stringify(contents, null, 2), 'utf-8');
    fn(file);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const read = (f: string) => JSON.parse(readFileSync(f, 'utf-8')) as Record<string, never>;

test('clears a legacy pointer and reports what it cleared', () => {
  withConfig({ user: { address: ADDR, pubkey: 'UABC123==', name: 'me' } }, (file) => {
    const cleared = clearDefaultKeyPointer(file);
    assert.deepEqual(cleared, { address: ADDR, pubkey: 'UABC123==' });

    const after = read(file) as unknown as { user: { address: string; pubkey: string; name: string } };
    assert.equal(after.user.address, '');
    assert.equal(after.user.pubkey, '');
    // Blanked, not deleted — this is the shape wallet-cli's own defaults use.
    assert.equal(after.user.name, 'me', 'unrelated user fields survive');
  });
});

test('never touches anything but the two pointer fields', () => {
  const cfg = {
    rpcUrl: 'https://rpc.example',
    chainId: 'omnistar-1',
    signer: { url: 'http://127.0.0.1:8080', type: 'http', signTimeout: 60000 },
    defaults: { gas: '200000' },
    user: { address: ADDR, pubkey: 'UABC123==', name: '' },
  };
  withConfig(cfg, (file) => {
    clearDefaultKeyPointer(file);
    const after = read(file) as unknown as typeof cfg;
    assert.deepEqual(after.signer, cfg.signer, 'signer.url must survive — SSP is pinned to loopback');
    assert.deepEqual(after.defaults, cfg.defaults);
    assert.equal(after.rpcUrl, cfg.rpcUrl);
    assert.equal(after.chainId, cfg.chainId);
  });
});

test('is idempotent: a second run reports nothing to do', () => {
  withConfig({ user: { address: ADDR, pubkey: 'UABC123==' } }, (file) => {
    assert.notEqual(clearDefaultKeyPointer(file), null);
    assert.equal(clearDefaultKeyPointer(file), null, 'no repeat write on every startup');
  });
});

test('a fresh install (no pointer) is a no-op', () => {
  withConfig({ user: { address: '', pubkey: '', name: '' } }, (file) => {
    assert.equal(clearDefaultKeyPointer(file), null);
  });
});

test('an absent or corrupt config never fails startup', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-mig-'));
  try {
    assert.equal(clearDefaultKeyPointer(path.join(dir, 'nope.json')), null);

    const corrupt = path.join(dir, 'corrupt.json');
    writeFileSync(corrupt, '{ this is not json', 'utf-8');
    assert.equal(clearDefaultKeyPointer(corrupt), null);
    // Left exactly as found — a config we cannot parse is not ours to rewrite.
    assert.equal(readFileSync(corrupt, 'utf-8'), '{ this is not json');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
