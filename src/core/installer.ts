// External install-script locator + auto-runner (Distribution, resolved this
// session). The installer (`install-child-mode.cjs`) carries the GitLab deploy
// token and therefore must NOT live in this open-source repo. It lives on the
// VM/machine. We locate it via the WIKEY_INSTALL_SCRIPT env var, falling back to
// ~/.ssp/install-child-mode.cjs, and auto-run it on startup when binaries are
// missing.
//
// Critical: the installer's output goes to STDERR only — stdout is the MCP
// JSON-RPC channel and must never be polluted.

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { resolveBins, type ResolvedBins } from './binPaths.js';

/** Default fallback location for the install script. */
export function defaultInstallScriptPath(): string {
  return path.join(process.env.WIKEY_SSP_DIR ?? path.join(os.homedir(), '.ssp'), 'install-child-mode.cjs');
}

/**
 * Locate the install script: WIKEY_INSTALL_SCRIPT env var, then the
 * ~/.ssp fallback. Returns the path only if the file exists, else null.
 */
export function locateInstallScript(): string | null {
  const fromEnv = process.env.WIKEY_INSTALL_SCRIPT;
  if (fromEnv && existsSync(fromEnv)) return fromEnv;
  const fallback = defaultInstallScriptPath();
  if (existsSync(fallback)) return fallback;
  return null;
}

export function binsComplete(bins: ResolvedBins): boolean {
  return Boolean(bins.signingServer && bins.sspUtil && bins.walletCli);
}

function missingList(bins: ResolvedBins): string[] {
  const missing: string[] = [];
  if (!bins.signingServer) missing.push('signing-server');
  if (!bins.sspUtil) missing.push('ssp-util');
  if (!bins.walletCli) missing.push('wallet-cli');
  return missing;
}

/** Where we looked for the install script, for actionable errors. */
function lookedAt(): string {
  const env = process.env.WIKEY_INSTALL_SCRIPT;
  return [
    env ? `WIKEY_INSTALL_SCRIPT=${env}` : 'WIKEY_INSTALL_SCRIPT (unset)',
    defaultInstallScriptPath(),
  ].join('; ');
}

/** Run the install script with the current Node, streaming its output to stderr. */
export function runInstallScript(scriptPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    process.stderr.write(`[wikey-wallet-mcp] running install script: ${scriptPath}\n`);
    const child = spawn(process.execPath, [scriptPath], {
      // stdout/stderr both to OUR stderr — never to stdout (JSON-RPC channel).
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', (c: Buffer) => process.stderr.write(c));
    child.stderr.on('data', (c: Buffer) => process.stderr.write(c));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`install script exited ${code}`));
    });
  });
}

export class InstallScriptMissingError extends Error {
  constructor() {
    super(
      `wikey-wallet-mcp: required binaries are missing and no install script was found.\n` +
        `Looked at: ${lookedAt()}\n` +
        `Set WIKEY_INSTALL_SCRIPT to the path of install-child-mode.cjs, or place it at ` +
        `${defaultInstallScriptPath()}.\n` +
        `(A public download link for the install script is planned; v1 uses the env var + local fallback.)`,
    );
    this.name = 'InstallScriptMissingError';
  }
}

/**
 * Ensure the child binaries are present. If any are missing, locate and run the
 * external install script, then re-resolve. Returns the resolved binaries.
 * Throws InstallScriptMissingError if binaries are missing and no script exists.
 */
export async function ensureBinaries(): Promise<ResolvedBins> {
  let bins = resolveBins();
  if (binsComplete(bins)) return bins;

  const script = locateInstallScript();
  if (!script) throw new InstallScriptMissingError();

  process.stderr.write(
    `[wikey-wallet-mcp] missing binaries: ${missingList(bins).join(', ')} — auto-installing.\n`,
  );
  await runInstallScript(script);

  bins = resolveBins();
  if (!binsComplete(bins)) {
    throw new Error(
      `wikey-wallet-mcp: binaries still missing after running the install script ` +
        `(${missingList(bins).join(', ')}). Check the installer output above.`,
    );
  }
  return bins;
}
