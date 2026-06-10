import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  resolveKekPolicy,
  isDevEnv,
  hardwareKekPolicy,
  softwareKekPolicy,
  SSP_NO_KEK_MARKER,
} from '../src/core/binPaths.js';

const KEYS = ['isDevEnv', 'WIKEY_IS_DEV_ENV', 'WIKEY_SSP_DIR'];

function setEnv(env: Record<string, string | undefined>): Record<string, string | undefined> {
  const prev: Record<string, string | undefined> = {};
  for (const k of KEYS) {
    prev[k] = process.env[k];
    if (env[k] === undefined) delete process.env[k];
    else process.env[k] = env[k];
  }
  return prev;
}
function restoreEnv(prev: Record<string, string | undefined>): void {
  for (const k of KEYS) {
    if (prev[k] === undefined) delete process.env[k];
    else process.env[k] = prev[k];
  }
}

test('isDevEnv: honors `isDevEnv` and legacy `WIKEY_IS_DEV_ENV`, truthy only on true/1', () => {
  for (const [val, expected] of [['true', true], ['1', true], ['false', false], ['0', false], [undefined, false]] as const) {
    const prev = setEnv({ isDevEnv: val });
    try {
      assert.equal(isDevEnv(), expected, `isDevEnv=${val}`);
    } finally {
      restoreEnv(prev);
    }
  }
});

test('resolveKekPolicy: prod (isDevEnv unset) → hardware-preferred, no file written', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-kek-'));
  const prev = setEnv({ isDevEnv: undefined, WIKEY_SSP_DIR: dir });
  try {
    const p = resolveKekPolicy();
    assert.equal(p.provider, 'auto');
    assert.deepEqual(p.flags, ['-kek-provider', 'auto']);
    assert.deepEqual(p.env, {});
    assert.equal(p.devKekPresent, false);
    assert.equal(existsSync(path.join(dir, 'dev.kek')), false, 'prod must not write dev.kek');
  } finally {
    restoreEnv(prev);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveKekPolicy: dev generates + persists dev.kek (0600) and injects SSP_KEK', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-kek-'));
  const kekFile = path.join(dir, 'dev.kek');
  const prev = setEnv({ isDevEnv: 'true', WIKEY_SSP_DIR: dir });
  try {
    const p = resolveKekPolicy();
    assert.equal(p.provider, 'env');
    assert.deepEqual(p.flags, ['-kek-provider', 'env']);
    assert.equal(p.devKekPresent, true);
    assert.equal(existsSync(kekFile), true, 'dev mode must persist dev.kek');
    const material = readFileSync(kekFile, 'utf8').trim();
    assert.ok(material.length > 0);
    assert.equal(p.env.SSP_KEK, material, 'injected SSP_KEK must equal the file contents');
    // 32 random bytes base64 → 44 chars
    assert.equal(material.length, 44);
    if (process.platform !== 'win32') {
      assert.equal(statSync(kekFile).mode & 0o777, 0o600);
    }
  } finally {
    restoreEnv(prev);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveKekPolicy: dev reuses an existing dev.kek (restart-stable)', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-kek-'));
  const kekFile = path.join(dir, 'dev.kek');
  writeFileSync(kekFile, 'PINNED_DEV_KEK_VALUE');
  const prev = setEnv({ isDevEnv: '1', WIKEY_SSP_DIR: dir });
  try {
    const p = resolveKekPolicy();
    assert.equal(p.env.SSP_KEK, 'PINNED_DEV_KEK_VALUE');
    assert.equal(readFileSync(kekFile, 'utf8'), 'PINNED_DEV_KEK_VALUE', 'must not overwrite an existing KEK');
  } finally {
    restoreEnv(prev);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('hardwareKekPolicy: auto provider, no file written regardless of isDevEnv', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-kek-'));
  const prev = setEnv({ isDevEnv: 'true', WIKEY_SSP_DIR: dir });
  try {
    const p = hardwareKekPolicy();
    assert.equal(p.provider, 'auto');
    assert.deepEqual(p.flags, ['-kek-provider', 'auto']);
    assert.deepEqual(p.env, {});
    assert.equal(existsSync(path.join(dir, 'dev.kek')), false);
  } finally {
    restoreEnv(prev);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('softwareKekPolicy: persists + reuses dev.kek even when isDevEnv is unset (runtime fallback)', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-kek-'));
  const kekFile = path.join(dir, 'dev.kek');
  const prev = setEnv({ isDevEnv: undefined, WIKEY_SSP_DIR: dir });
  try {
    const first = softwareKekPolicy();
    assert.equal(first.provider, 'env');
    assert.deepEqual(first.flags, ['-kek-provider', 'env']);
    assert.ok(existsSync(kekFile), 'fallback persists the software KEK');
    const material = readFileSync(kekFile, 'utf8').trim();
    assert.equal(first.env.SSP_KEK, material);
    assert.equal(material.length, 44); // 32 random bytes base64

    const second = softwareKekPolicy();
    assert.equal(second.env.SSP_KEK, material, 'second call reuses the persisted KEK (restart-stable)');
  } finally {
    restoreEnv(prev);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('SSP_NO_KEK_MARKER matches the real SSP error string as a substring', () => {
  // Real SSP message (main.go:289), abbreviated. A substring match must hit.
  const real =
    'no usable KEK provider in -spawned-by-agent mode: no hardware-backed provider (sgx/tpm/keychain/dpapi) is available';
  assert.ok(real.includes(SSP_NO_KEK_MARKER));
});
