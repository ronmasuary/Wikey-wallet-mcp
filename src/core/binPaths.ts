// Binary resolution + keys-at-rest KEK policy (H4).
//
// The three child binaries are installed by the external install script
// (`install-child-mode.cjs`, see installer.ts) into:
//   - ~/.ssp/bin      → signing-server, ssp-util  (Go binaries)
//   - npm global bin  → wallet-cli                (Node CLI, installed -g)
// We resolve from those locations first, then fall back to PATH. We never
// hardcode a single absolute path the way the skill did — the installer owns
// placement and we discover it.

import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { accessSync, constants, readFileSync, readdirSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const IS_WINDOWS = process.platform === 'win32';
const EXE = IS_WINDOWS ? '.exe' : '';

/**
 * How to launch wallet-cli. wallet-cli is a Node CLI, not a native binary: npm
 * installs it as an extensionless shell shim on POSIX and as `wallet-cli.cmd`
 * (plus `.ps1`) on Windows — never `wallet-cli.exe`. Node 22 also refuses to
 * `spawn`/`execFile` a `.cmd`/`.bat` directly without `shell: true` (the
 * CVE-2024-27980 mitigation → EINVAL). So we resolve the underlying JS entry and
 * run it via `node <js>` on Windows. On POSIX the extensionless shim is directly
 * executable, so we run it as-is. Callers spawn `command` with
 * `[...prefixArgs, ...theirArgs]`.
 */
export interface WalletCliLauncher {
  /** Executable to spawn (the shim on POSIX; the node binary on Windows). */
  command: string;
  /** Args prepended before the caller's args (the JS entry on Windows; [] on POSIX). */
  prefixArgs: string[];
  /** Human-readable resolved path, for doctor display (the shim or the JS entry). */
  display: string;
}

export interface ResolvedBins {
  signingServer: string | null;
  sspUtil: string | null;
  walletCli: WalletCliLauncher | null;
}

/**
 * The single MCP-owned state root. ONE volume on this path makes the whole
 * stack restart-stable: the SSP keystore, dev.kek, the child binaries, AND
 * wallet-cli's config (the default-key pointer) all live underneath it, so the
 * key material and the "which key is default" pointer can never desync (P2).
 * Override with WIKEY_SSP_DIR; defaults to ~/.ssp.
 */
export function stateRoot(): string {
  return process.env.WIKEY_SSP_DIR ?? path.join(os.homedir(), '.ssp');
}

/** Directory the SSP secure keystore is pinned to (`-keystore-dir`). */
export function keystoreDir(): string {
  return path.join(stateRoot(), 'keystore');
}

// A keystore entry is named after the address it holds: `<address>.enc` (secure
// format) or a legacy `<address>.json`. Non-key files (`kek.dpapi`, `dev.kek`)
// don't start with the address prefix, so this pattern skips them.
const KEYSTORE_FILE_RE = /^(omnistar1[0-9a-z]{6,})\.(enc|json)$/i;

/**
 * List signing-key addresses by reading the keystore directory directly, WITHOUT
 * the signing-server. The address IS the filename, so a key's *identity* is
 * available from the filesystem with zero decryption and no running SSP session
 * (only *using* a key — decrypting its private material to sign — needs the
 * server + KEK). This lets read-only callers (e.g. wallet_getting_started) count
 * keys accurately even when SSP is idle, instead of misreading an unreachable
 * signer as "no keys". Returns [] when the keystore dir is absent/unreadable —
 * which for key-counting genuinely means "no keys yet".
 */
export function listKeystoreAddresses(): string[] {
  let entries: string[];
  try {
    entries = readdirSync(keystoreDir());
  } catch {
    return [];
  }
  const addrs = new Set<string>();
  for (const name of entries) {
    const m = KEYSTORE_FILE_RE.exec(name);
    if (m?.[1]) addrs.add(m[1]);
  }
  return [...addrs];
}

/**
 * HOME we pin on every wallet-cli (and SSP) child so wallet-cli's config loader
 * (which derives `~/.wallet-cli` from homedir()) writes under the state root
 * instead of the real home. Co-locates the default-key pointer with the keystore.
 */
export function walletHome(): string {
  return stateRoot();
}

/** The account a wallet-cli child should act as. `pubkey` is base64. */
export interface AccountEnv {
  address: string;
  /** Required to SIGN; omit for reads (see the blanking note in walletCliEnv). */
  pubkey?: string;
}

/**
 * Child env for every wallet-cli invocation. Two jobs:
 *
 * 1. RELOCATE THE CONFIG HOME under the state root. wallet-cli derives
 *    `~/.wallet-cli` via Node's `os.homedir()`, which reads `HOME` on POSIX but
 *    `USERPROFILE` on Windows (libuv `uv_os_homedir`). Pinning only `HOME`
 *    therefore has NO effect on Windows: the config lands in the real profile
 *    dir, desyncs from the keystore, and — because ensureWalletConfig's
 *    never-clobber guard checks the state-root path — gets wiped (re-`config
 *    init`) on every restart. Pin both to fix all OSes.
 *
 * 2. ROUTE THE SIGNING KEY per child process. wallet-cli's config loader layers
 *    env OVER the config file (config/loader.ts), and `WALLET_ADDRESS` /
 *    `WALLET_PUBKEY` populate `config.user` — the same fields `keys create`
 *    used to write as the "default key". Injecting them here targets one
 *    account for the lifetime of this child ONLY, with no shared-file mutation
 *    and no cross-call race, and it reaches the commands that have no
 *    `--creator/--pubkey` flags (`keys sign-challenge`, `notification
 *    configure`, `query assets`) because they all read the same loader.
 *
 * Two behaviours worth knowing:
 *
 * - INHERITED VALUES ARE DROPPED. Any `WALLET_ADDRESS`/`WALLET_PUBKEY` in the
 *   MCP's own environment is deleted before we set ours. Left in place they
 *   would be an ambient default key by another name — exactly what this design
 *   removes — and one set by the operator rather than the caller.
 * - OMITTING `pubkey` BLANKS IT. wallet-cli's loader builds `config.user` from
 *   whichever of the two vars is present and fills the other with `''`, so
 *   there is no way to inject an address while inheriting the file's pubkey.
 *   That is deliberate: a read (`query assets`) needs no pubkey, and a signing
 *   command that reaches here without one fails loudly instead of quietly
 *   signing with whatever the file happened to hold.
 */
export function walletCliEnv(account?: AccountEnv): NodeJS.ProcessEnv {
  const home = walletHome();
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home };
  delete env.WALLET_ADDRESS;
  delete env.WALLET_PUBKEY;
  if (account?.address) {
    env.WALLET_ADDRESS = account.address;
    env.WALLET_PUBKEY = account.pubkey ?? '';
  }
  return env;
}

function sspBinDir(): string {
  return path.join(stateRoot(), 'bin');
}

let npmGlobalBinCache: string | null | undefined;
function npmGlobalBin(): string | null {
  if (npmGlobalBinCache !== undefined) return npmGlobalBinCache;
  try {
    const prefix = execFileSync(IS_WINDOWS ? 'npm.cmd' : 'npm', ['prefix', '-g'], {
      stdio: ['ignore', 'pipe', 'ignore'],
    })
      .toString()
      .trim();
    npmGlobalBinCache = IS_WINDOWS ? prefix : path.join(prefix, 'bin');
  } catch {
    npmGlobalBinCache = null;
  }
  return npmGlobalBinCache;
}

function isExecutable(p: string): boolean {
  try {
    accessSync(p, IS_WINDOWS ? constants.F_OK : constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Find an executable by name across the given preferred dirs, then PATH. */
function findExecutable(name: string, preferredDirs: Array<string | null>): string | null {
  const fileName = name + EXE;
  for (const dir of preferredDirs) {
    if (!dir) continue;
    const candidate = path.join(dir, fileName);
    if (isExecutable(candidate)) return candidate;
  }
  const pathDirs = (process.env.PATH ?? '').split(path.delimiter).filter(Boolean);
  for (const dir of pathDirs) {
    const candidate = path.join(dir, fileName);
    if (isExecutable(candidate)) return candidate;
  }
  return null;
}

/**
 * Resolve the JS entry behind npm's `wallet-cli.cmd` shim on Windows. The shim's
 * launch line names the package's JS entry relative to the shim dir
 * (`"%dp0%\node_modules\…\index.js"` / `"%~dp0\…"`). We extract the last quoted
 * `.js`/`.cjs`/`.mjs` token, strip the `%dp0%`/`%~dp0%` prefix, and resolve it
 * against the shim dir — robust to the package's internal layout and name.
 */
function walletCliJsFromShim(dir: string): string | null {
  const shim = path.join(dir, 'wallet-cli.cmd');
  if (!existsSync(shim)) return null;
  let text: string;
  try {
    text = readFileSync(shim, 'utf8');
  } catch {
    return null;
  }
  const matches = [...text.matchAll(/"([^"]*\.[mc]?js)"/gi)];
  const token = matches.at(-1)?.[1];
  if (!token) return null;
  const rel = token.replace(/^%~?dp0%?[\\/]/i, '').replace(/[\\/]/g, path.sep);
  const resolved = path.isAbsolute(rel) ? rel : path.join(dir, rel);
  return existsSync(resolved) ? resolved : null;
}

/**
 * Resolve wallet-cli into a cross-platform launcher (see WalletCliLauncher). A
 * real native `wallet-cli.exe`, if present, is preferred and run directly;
 * otherwise on Windows we run the package's JS entry via `node`, and on POSIX we
 * run the directly-executable shim.
 */
function resolveWalletCli(): WalletCliLauncher | null {
  // A real native executable (rare) is spawnable directly on any platform.
  if (IS_WINDOWS) {
    const exe = findExecutable('wallet-cli', [npmGlobalBin()]); // appends .exe on win
    if (exe) return { command: exe, prefixArgs: [], display: exe };

    const dirs = [npmGlobalBin(), ...(process.env.PATH ?? '').split(path.delimiter).filter(Boolean)];
    for (const dir of dirs) {
      if (!dir) continue;
      const js = walletCliJsFromShim(dir);
      if (js) return { command: process.execPath, prefixArgs: [js], display: js };
    }
    return null;
  }

  // POSIX: the extensionless shim is directly executable.
  const shim = findExecutable('wallet-cli', [npmGlobalBin()]);
  return shim ? { command: shim, prefixArgs: [], display: shim } : null;
}

export function resolveBins(): ResolvedBins {
  const sspDir = sspBinDir();
  return {
    signingServer: findExecutable('signing-server', [sspDir]),
    sspUtil: findExecutable('ssp-util', [sspDir]),
    walletCli: resolveWalletCli(),
  };
}

// ─── KEK policy (H4) ──────────────────────────────────────────────────────────
//
// Always `-keystore secure`. The active provider is chosen by the `isDevEnv`
// flag in the MCP's environment (set via the host's mcp.json `env` block):
//
//   - isDevEnv truthy  → DEV: a software KEK persisted to `dev.kek`. We generate
//     one on first use and reuse it, so the at-rest signing keystore survives a
//     container/agent restart (losing it every restart is worse, and an
//     enclave-less VM has no hardware provider to fall back on).
//   - isDevEnv unset/false → PROD: hardware-preferred (`-kek-provider auto` picks
//     Keychain/TPM/DPAPI/Secure-Enclave). No file is written or read.
//
// The KEK never reaches the model regardless of provider; it lives inside SSP.
// We only surface *which* provider is active (via `doctor`).

/** Whether the MCP is running in a dev environment (env-flag driven). */
export function isDevEnv(): boolean {
  const v = process.env.isDevEnv ?? process.env.WIKEY_IS_DEV_ENV;
  return v === 'true' || v === '1';
}

export interface KekPolicy {
  /** 'auto' = hardware-preferred; 'env' = persisted software fallback. */
  provider: 'auto' | 'env';
  /** kek-related flags to append to the signing-server argv. */
  flags: string[];
  /** extra env to inject at spawn (SSP_KEK when on the env fallback). */
  env: Record<string, string>;
  /** whether a persisted KEK file was found (operator-facing, not the value). */
  devKekPresent: boolean;
}

/**
 * Substring SSP emits when, in -spawned-by-agent mode, no hardware-backed KEK
 * provider is available and no software KEK is configured (main.go:289). SSP
 * logs this via its slog JSON handler on os.Stdout (main.go:40), NOT stderr —
 * the session must scan the child's STDOUT for it. We match it as a substring,
 * so it still hits inside the JSON-escaped `"error":"…"` value.
 */
export const SSP_NO_KEK_MARKER = 'no usable KEK provider';

function devKekPath(): string {
  return path.join(stateRoot(), 'dev.kek');
}

/** Hardware-preferred policy (prod default): `-kek-provider auto`, no file. */
export function hardwareKekPolicy(): KekPolicy {
  return { provider: 'auto', flags: ['-kek-provider', 'auto'], env: {}, devKekPresent: false };
}

/**
 * Persisted software-KEK policy (`-kek-provider env`). Reads the persisted KEK,
 * generating + writing it (0600) on first use so the at-rest keystore survives a
 * restart. Used both for explicit dev mode and as the runtime fallback when no
 * hardware KEK is available. The 32-byte base64 value is exactly what SSP's env
 * provider expects (kek/env.go).
 */
export function softwareKekPolicy(): KekPolicy {
  const kekFile = devKekPath();
  let material = '';
  if (existsSync(kekFile)) {
    try {
      material = readFileSync(kekFile, 'utf8').trim();
    } catch {
      material = '';
    }
  }
  if (!material) {
    material = randomBytes(32).toString('base64');
    try {
      mkdirSync(path.dirname(kekFile), { recursive: true });
      writeFileSync(kekFile, material, { mode: 0o600 });
    } catch {
      // Can't persist (read-only fs): fall back to a one-shot in-memory KEK for
      // this run — still a valid software KEK, just not restart-stable.
    }
  }
  return {
    provider: 'env',
    flags: ['-kek-provider', 'env'],
    env: { SSP_KEK: material },
    devKekPresent: true,
  };
}

/**
 * The KEK policy to try FIRST. `isDevEnv` forces software (an explicit
 * force-software override); otherwise hardware-preferred. When hardware reports
 * no usable KEK at spawn time, the session falls back to softwareKekPolicy()
 * once (see session.ts doInit).
 */
export function resolveKekPolicy(): KekPolicy {
  return isDevEnv() ? softwareKekPolicy() : hardwareKekPolicy();
}
