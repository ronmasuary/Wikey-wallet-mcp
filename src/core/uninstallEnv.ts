// The impure half of uninstall: everything that has to look at the real machine
// — how this server was installed, npm's global bin directory, where the MCP
// client keeps its config, and actually running `npm uninstall -g`.
//
// Kept apart from `uninstall.ts` so the audit and the gate order stay unit-
// testable with plain fakes, and so the one function here that MUTATES the
// machine (`npmUninstall`) sits by itself where it is easy to find and review.

import { execFile } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, realpathSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { PACKAGE_NAME, type FsOps, type InstallMode } from './uninstall.js';

const run = promisify(execFile);
const isWin = process.platform === 'win32';
const npmCmd = isWin ? 'npm.cmd' : 'npm';

/**
 * Run npm.
 *
 * `shell: true` on Windows is REQUIRED, not incidental: since the fix for
 * CVE-2024-27980, Node refuses to spawn a `.cmd`/`.bat` without it and fails
 * with a bare EINVAL. Without this the uninstall silently degraded — install
 * mode `unknown`, package never removed — and every error path here swallows
 * exceptions, so nothing would have surfaced the cause.
 *
 * A shell is only safe here because NO argument is caller-controlled: every
 * value passed to this helper is a literal in this file. Never widen it to
 * accept user or model input.
 */
async function npm(args: string[], timeout: number): Promise<{ stdout: string; stderr: string }> {
  return run(npmCmd, args, { timeout, windowsHide: true, ...(isWin ? { shell: true } : {}) });
}

/** Real filesystem ops for the uninstall planner. */
export const realFs: FsOps = {
  exists: (p) => existsSync(p),
  readdir: (p) => readdirSync(p),
  // maxRetries covers the brief window after the signing child is killed but
  // before Windows releases its handles on the keystore.
  remove: (p) => rmSync(p, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }),
};

/**
 * The directory this package occupies — `dist/core/uninstallEnv.js` is two
 * levels below the package root.
 */
export function packageDir(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
}

/** Ask npm where things live. Authoritative; `npm root -g` is not guessable. */
async function npmPath(arg: 'root' | 'prefix'): Promise<string | undefined> {
  try {
    const { stdout } = await npm([arg, '-g'], 20_000);
    const v = stdout.trim().split('\n').pop()?.trim();
    return v || undefined;
  } catch {
    return undefined;
  }
}

export interface InstallInfo {
  mode: InstallMode;
  packageDir: string;
  /** Where npm's bin shims live, when known. */
  binDir?: string;
  /** The global install path (`<npm root -g>/wikey-wallet-mcp`), when present. */
  globalEntry?: string;
}

/**
 * Classify the install so the uninstall can say what removing it will and will
 * not touch.
 *
 * The npm prefix is NOT derivable from `process.execPath` — on Windows node
 * lives in `Program Files\nodejs` while the global prefix is
 * `%APPDATA%\npm` — so this asks npm rather than guessing.
 *
 * `global-linked` is the case worth separating: `npm i -g .` puts a SYMLINK in
 * the global node_modules pointing at a working tree, so `npm uninstall -g`
 * removes the link and leaves the tree. Reporting that as "package removed"
 * without qualification invites either of two wrong beliefs — that the source
 * was deleted, or that nothing happened.
 */
export async function detectInstall(): Promise<InstallInfo> {
  const pkg = packageDir();
  const norm = (p: string) => path.resolve(p).replace(/[\\/]+$/, '').toLowerCase();

  if (norm(pkg).includes(`${path.sep}_npx${path.sep}`.toLowerCase()) || norm(pkg).includes('/_npx/')) {
    return { mode: 'npx', packageDir: pkg };
  }

  const [root, prefix] = await Promise.all([npmPath('root'), npmPath('prefix')]);
  const binDir = prefix ? (process.platform === 'win32' ? prefix : path.join(prefix, 'bin')) : undefined;
  if (!root) return { mode: 'unknown', packageDir: pkg, ...(binDir ? { binDir } : {}) };

  const globalEntry = path.join(root, PACKAGE_NAME);
  const common = { packageDir: pkg, ...(binDir ? { binDir } : {}), globalEntry };
  if (!existsSync(globalEntry)) return { mode: 'unknown', ...common };

  // Linked when the global entry resolves somewhere outside the global root —
  // i.e. it is a symlink into a working tree.
  try {
    if (!norm(realpathSync(globalEntry)).startsWith(norm(root))) return { mode: 'global-linked', ...common };
  } catch {
    /* unresolvable — fall through to the containment test */
  }
  return { mode: norm(pkg).startsWith(norm(root)) ? 'global-real' : 'global-linked', ...common };
}

/**
 * Run `npm uninstall -g <pkg>`. The ONLY machine-mutating call in this module.
 * Never throws — the caller verifies the outcome ON DISK rather than trusting
 * the exit code, which is a claim about what npm attempted, not about what the
 * filesystem now holds (a wrong prefix, a permission failure or an antivirus
 * hold all exit 0 with files left behind).
 */
export async function npmUninstall(): Promise<{ ok: boolean; detail: string }> {
  try {
    const { stdout, stderr } = await npm(['uninstall', '-g', PACKAGE_NAME], 120_000);
    const out = (stdout || stderr).trim().split('\n').slice(-3).join(' ').trim();
    return { ok: true, detail: out || `npm uninstall -g ${PACKAGE_NAME} completed.` };
  } catch (e) {
    const err = e as { message?: string; stderr?: string };
    return { ok: false, detail: (err.stderr || err.message || 'npm failed').trim().split('\n').slice(0, 3).join(' ') };
  }
}

/**
 * Client config files that actually mention this server.
 *
 * Returns PATHS ONLY. These files list every MCP server the user has, along
 * with their credentials — so this reads a file solely to test for a marker
 * string and never returns, logs, or summarizes any of its contents. A file it
 * cannot read is skipped rather than reported.
 */
export function findClientConfigs(): string[] {
  const home = os.homedir();
  const appData = process.env.APPDATA ?? path.join(home, 'AppData', 'Roaming');
  const candidates = [
    // Claude Desktop (win / macOS / linux)
    path.join(appData, 'Claude', 'claude_desktop_config.json'),
    path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    path.join(home, '.config', 'Claude', 'claude_desktop_config.json'),
    // Claude Code
    path.join(home, '.claude.json'),
    path.join(process.cwd(), '.mcp.json'),
    // Other common hosts
    path.join(home, '.cursor', 'mcp.json'),
    path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
  ];

  const hits: string[] = [];
  for (const p of candidates) {
    try {
      if (!existsSync(p)) continue;
      const text = readFileSync(p, 'utf8');
      if (text.includes(PACKAGE_NAME) || text.includes('wikey-wallet')) hits.push(p);
    } catch {
      /* unreadable — not ours to report */
    }
  }
  return hits;
}
