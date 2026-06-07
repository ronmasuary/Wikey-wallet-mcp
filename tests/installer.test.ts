import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import {
  locateInstallScript,
  bundledInstallScriptPath,
  defaultInstallScriptPath,
  binsComplete,
  InstallScriptMissingError,
} from '../src/core/installer.js';

const execFileP = promisify(execFile);
const RUNNER = fileURLToPath(new URL('./fixtures/run-installer.ts', import.meta.url));
const NOISY = fileURLToPath(new URL('./fixtures/noisy-installer.cjs', import.meta.url));

function withEnv(env: Record<string, string | undefined>, fn: () => void): void {
  const keys = ['WIKEY_INSTALL_SCRIPT', 'WIKEY_SSP_DIR'];
  const prev: Record<string, string | undefined> = {};
  for (const k of keys) prev[k] = process.env[k];
  for (const k of keys) {
    if (env[k] === undefined) delete process.env[k];
    else process.env[k] = env[k];
  }
  try {
    fn();
  } finally {
    for (const k of keys) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
  }
}

test('locateInstallScript: WIKEY_INSTALL_SCRIPT takes precedence', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-inst-'));
  const explicit = path.join(dir, 'custom-install.cjs');
  writeFileSync(explicit, '// stub');
  try {
    withEnv({ WIKEY_INSTALL_SCRIPT: explicit, WIKEY_SSP_DIR: dir }, () => {
      assert.equal(locateInstallScript(), explicit);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('locateInstallScript: package-bundled script resolves before the ~/.ssp fallback', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-inst-'));
  withEnv({ WIKEY_INSTALL_SCRIPT: undefined, WIKEY_SSP_DIR: dir }, () => {
    const bundled = bundledInstallScriptPath();
    assert.equal(bundled, path.resolve(fileURLToPath(new URL('../', import.meta.url)), 'install-child-mode.cjs'));
    const fallback = defaultInstallScriptPath();
    assert.equal(fallback, path.join(dir, 'install-child-mode.cjs'));

    if (existsSync(bundled)) {
      // Local/dev: the gitignored installer is bundled at the package root → it wins.
      assert.equal(locateInstallScript(), bundled);
    } else {
      // Clean checkout (installer not yet placed): no env, no bundle → ~/.ssp fallback.
      assert.equal(locateInstallScript(), null);
      writeFileSync(fallback, '// stub');
      assert.equal(locateInstallScript(), fallback);
    }
  });
  rmSync(dir, { recursive: true, force: true });
});

test('binsComplete: all three required', () => {
  assert.equal(binsComplete({ signingServer: 'a', sspUtil: 'b', walletCli: 'c' }), true);
  assert.equal(binsComplete({ signingServer: 'a', sspUtil: null, walletCli: 'c' }), false);
  assert.equal(binsComplete({ signingServer: null, sspUtil: null, walletCli: null }), false);
});

test('InstallScriptMissingError is actionable (env var + fallback path + download placeholder)', () => {
  const e = new InstallScriptMissingError();
  assert.match(e.message, /WIKEY_INSTALL_SCRIPT/);
  assert.match(e.message, /install-child-mode\.cjs/);
  assert.match(e.message, /download link/);
});

test('runInstallScript: installer output goes to stderr only — MCP stdout stays clean', async () => {
  const { stdout, stderr } = await execFileP(process.execPath, ['--import', 'tsx', RUNNER, NOISY]);
  assert.equal(stdout.trim(), '', `nothing must leak to stdout, got: ${stdout}`);
  assert.match(stderr, /INSTALLER_STDOUT_LINE/); // child stdout redirected into stderr
  assert.match(stderr, /INSTALLER_STDERR_LINE/);
});
