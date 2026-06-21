import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import {
  locateInstallScript,
  resolveInstallScript,
  bundledInstallScriptPath,
  defaultInstallScriptPath,
  binsComplete,
  InstallScriptMissingError,
} from '../src/core/installer.js';
import { createServer } from 'node:http';

const execFileP = promisify(execFile);
const RUNNER = fileURLToPath(new URL('./fixtures/run-installer.ts', import.meta.url));
const NOISY = fileURLToPath(new URL('./fixtures/noisy-installer.cjs', import.meta.url));

const ENV_KEYS = [
  'WIKEY_INSTALL_SCRIPT',
  'WIKEY_INSTALL_SCRIPT_URL',
  'WIKEY_SSP_DIR',
  'installationScriptPath',
  'installationScriptUrl',
];

function setEnv(env: Record<string, string | undefined>): Record<string, string | undefined> {
  const prev: Record<string, string | undefined> = {};
  for (const k of ENV_KEYS) {
    prev[k] = process.env[k];
    if (env[k] === undefined) delete process.env[k];
    else process.env[k] = env[k];
  }
  return prev;
}

function restoreEnv(prev: Record<string, string | undefined>): void {
  for (const k of ENV_KEYS) {
    if (prev[k] === undefined) delete process.env[k];
    else process.env[k] = prev[k];
  }
}

function withEnv(env: Record<string, string | undefined>, fn: () => void): void {
  const prev = setEnv(env);
  try {
    fn();
  } finally {
    restoreEnv(prev);
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
  const wc = { command: 'c', prefixArgs: [], display: 'c' };
  assert.equal(binsComplete({ signingServer: 'a', sspUtil: 'b', walletCli: wc }), true);
  assert.equal(binsComplete({ signingServer: 'a', sspUtil: null, walletCli: wc }), false);
  assert.equal(binsComplete({ signingServer: null, sspUtil: null, walletCli: null }), false);
});

test('InstallScriptMissingError is actionable (path flag + fallback path + url flag)', () => {
  const e = new InstallScriptMissingError();
  assert.match(e.message, /installationScriptPath/);
  assert.match(e.message, /install-child-mode\.cjs/);
  assert.match(e.message, /installationScriptUrl/);
});

test('locateInstallScript: installationScriptPath takes precedence', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-inst-'));
  const explicit = path.join(dir, 'custom-install.cjs');
  writeFileSync(explicit, '// stub');
  try {
    withEnv({ installationScriptPath: explicit, WIKEY_SSP_DIR: dir }, () => {
      assert.equal(locateInstallScript(), explicit);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveInstallScript: downloads from installationScriptUrl when no local file exists', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-inst-'));
  const body = '// downloaded installer stub\n';
  const server = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/javascript' });
    res.end(body);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as { port: number };

  // WIKEY_SSP_DIR points the bundled/~.ssp fallbacks at an empty temp dir so the
  // only resolvable source is the URL. (bundledInstallScriptPath may still exist
  // in a dev checkout, so we also assert the dir is empty of it first.)
  const prev = setEnv({
    installationScriptPath: undefined,
    installationScriptUrl: `http://127.0.0.1:${port}/install-child-mode.cjs`,
    WIKEY_INSTALL_SCRIPT: undefined,
    WIKEY_SSP_DIR: dir,
  });
  try {
    // Only meaningful when no bundled script shadows the URL (skip if a dev
    // checkout has the gitignored installer next to dist/).
    if (existsSync(bundledInstallScriptPath())) {
      assert.equal(locateInstallScript(), bundledInstallScriptPath());
    } else {
      assert.equal(locateInstallScript(), null);
      const resolved = await resolveInstallScript();
      assert.equal(resolved, defaultInstallScriptPath());
      assert.equal(existsSync(resolved!), true);
      assert.equal(readFileSync(resolved!, 'utf8'), body);
    }
  } finally {
    restoreEnv(prev);
    await new Promise<void>((r) => server.close(() => r()));
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveInstallScript: returns null when neither a local file nor a URL is set', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-inst-'));
  const prev = setEnv({
    installationScriptPath: undefined,
    installationScriptUrl: undefined,
    WIKEY_INSTALL_SCRIPT: undefined,
    WIKEY_SSP_DIR: dir,
  });
  try {
    if (!existsSync(bundledInstallScriptPath())) {
      assert.equal(await resolveInstallScript(), null);
    }
  } finally {
    restoreEnv(prev);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('runInstallScript: installer output goes to stderr only — MCP stdout stays clean', async () => {
  const { stdout, stderr } = await execFileP(process.execPath, ['--import', 'tsx', RUNNER, NOISY]);
  assert.equal(stdout.trim(), '', `nothing must leak to stdout, got: ${stdout}`);
  assert.match(stderr, /INSTALLER_STDOUT_LINE/); // child stdout redirected into stderr
  assert.match(stderr, /INSTALLER_STDERR_LINE/);
});
