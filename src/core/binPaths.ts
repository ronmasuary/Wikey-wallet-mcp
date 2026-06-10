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
import { accessSync, constants, readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const IS_WINDOWS = process.platform === 'win32';
const EXE = IS_WINDOWS ? '.exe' : '';

export interface ResolvedBins {
  signingServer: string | null;
  sspUtil: string | null;
  walletCli: string | null;
}

function sspBinDir(): string {
  return path.join(process.env.WIKEY_SSP_DIR ?? path.join(os.homedir(), '.ssp'), 'bin');
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

export function resolveBins(): ResolvedBins {
  const sspDir = sspBinDir();
  return {
    signingServer: findExecutable('signing-server', [sspDir]),
    sspUtil: findExecutable('ssp-util', [sspDir]),
    walletCli: findExecutable('wallet-cli', [npmGlobalBin()]),
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
  return path.join(process.env.WIKEY_SSP_DIR ?? path.join(os.homedir(), '.ssp'), 'dev.kek');
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
