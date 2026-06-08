// External install-script locator + auto-runner. The installer
// (`install-child-mode.cjs`) carries the GitLab deploy token and therefore must
// NOT be committed to this open-source repo — it is gitignored and shipped
// alongside the package. The MCP server OWNS it: we resolve it next to the
// package root (one beside `dist/`) so no consumer (e.g. ragent) needs to know
// where it lives. We still honor a WIKEY_INSTALL_SCRIPT override and the
// historical ~/.ssp fallback, then auto-run it on startup when binaries are
// missing.
//
// Critical: the installer's output goes to STDERR only — stdout is the MCP
// JSON-RPC channel and must never be polluted.

import { spawn } from 'node:child_process';
import { createWriteStream, existsSync, mkdirSync, unlinkSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveBins, type ResolvedBins } from './binPaths.js';

/**
 * Explicit local install-script path from the MCP env. The product interface is
 * `installationScriptPath`; `WIKEY_INSTALL_SCRIPT` is the legacy alias.
 */
function installScriptPathOverride(): string | undefined {
  return process.env.installationScriptPath ?? process.env.WIKEY_INSTALL_SCRIPT;
}

/**
 * Install-script download URL from the MCP env. Product interface is
 * `installationScriptUrl`; `WIKEY_INSTALL_SCRIPT_URL` is the legacy alias.
 */
function installScriptUrl(): string | undefined {
  return process.env.installationScriptUrl ?? process.env.WIKEY_INSTALL_SCRIPT_URL;
}

/**
 * The install script bundled with the package itself (the MCP server owns it).
 * This module compiles to `dist/core/installer.js`, so the package root — where
 * `install-child-mode.cjs` sits beside `dist/` — is two levels up.
 */
export function bundledInstallScriptPath(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, '..', '..', 'install-child-mode.cjs');
}

/** Default fallback location for the install script. */
export function defaultInstallScriptPath(): string {
  return path.join(process.env.WIKEY_SSP_DIR ?? path.join(os.homedir(), '.ssp'), 'install-child-mode.cjs');
}

/**
 * Locate the install script LOCALLY (no network): the explicit
 * `installationScriptPath` override, then the package-bundled script, then the
 * `~/.ssp` fallback. Returns the path only if the file exists, else null.
 * Network download (installationScriptUrl) is handled by `resolveInstallScript`.
 */
export function locateInstallScript(): string | null {
  const override = installScriptPathOverride();
  if (override && existsSync(override)) return override;
  const bundled = bundledInstallScriptPath();
  if (existsSync(bundled)) return bundled;
  const fallback = defaultInstallScriptPath();
  if (existsSync(fallback)) return fallback;
  return null;
}

/**
 * Download the install script from `url` to the `~/.ssp` cache path (so a later
 * run finds it locally) and return that path. Follows redirects. The body is a
 * Node CJS script run via `node <path>` — no execute bit needed.
 */
export function downloadInstallScript(url: string): Promise<string> {
  const dest = defaultInstallScriptPath();
  mkdirSync(path.dirname(dest), { recursive: true });
  process.stderr.write(`[wikey-wallet-mcp] downloading install script: ${url}\n`);

  const fetchTo = (u: string, redirectsLeft: number): Promise<void> =>
    new Promise((resolve, reject) => {
      const mod = u.startsWith('http://') ? http : https;
      const req = mod.get(u, (res) => {
        const status = res.statusCode ?? 0;
        if (status >= 300 && status < 400 && res.headers.location) {
          res.resume();
          if (redirectsLeft <= 0) return reject(new Error('too many redirects'));
          const next = new URL(res.headers.location, u).toString();
          return fetchTo(next, redirectsLeft - 1).then(resolve, reject);
        }
        if (status !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${status} for ${u}`));
        }
        const file = createWriteStream(dest);
        res.pipe(file);
        file.on('finish', () => file.close((err) => (err ? reject(err) : resolve())));
        file.on('error', (err) => {
          try { unlinkSync(dest); } catch { /* best effort */ }
          reject(err);
        });
      });
      req.on('error', reject);
    });

  return fetchTo(url, 5).then(() => dest);
}

/**
 * Resolve the install script with the product precedence: a LOCAL file first
 * (`installationScriptPath` → bundled → `~/.ssp`), then a download from
 * `installationScriptUrl`. Returns null when neither a local file nor a URL is
 * available (→ no install will be attempted).
 */
export async function resolveInstallScript(): Promise<string | null> {
  const local = locateInstallScript();
  if (local) return local;
  const url = installScriptUrl();
  if (url) return downloadInstallScript(url);
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
  const override = installScriptPathOverride();
  const url = installScriptUrl();
  return [
    override ? `installationScriptPath=${override}` : 'installationScriptPath (unset)',
    bundledInstallScriptPath(),
    defaultInstallScriptPath(),
    url ? `installationScriptUrl=${url}` : 'installationScriptUrl (unset)',
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
        `Set installationScriptPath to the path of install-child-mode.cjs (or place it at ` +
        `${defaultInstallScriptPath()}), or set installationScriptUrl to a download link for it.`,
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

  const script = await resolveInstallScript();
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
