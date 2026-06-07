// Binary resolution + keys-at-rest KEK policy (H4).
//
// The three child binaries are installed by the external install script
// (`install-child-mode.cjs`, see installer.ts) into:
//   - ~/.ssp/bin      → signing-server, ssp-util  (Go binaries)
//   - npm global bin  → wallet-cli                (Node CLI, installed -g)
// We resolve from those locations first, then fall back to PATH. We never
// hardcode a single absolute path the way the skill did — the installer owns
// placement and we discover it.

import { execFileSync } from 'node:child_process';
import { accessSync, constants, readFileSync, existsSync } from 'node:fs';
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
// Always `-keystore secure`. Prefer a hardware-backed KEK (`-kek-provider auto`
// picks Keychain/TPM/DPAPI/Secure-Enclave where present). On an enclave-less VM,
// a persisted env/passphrase KEK is an *allowed* fallback so the at-rest signing
// key survives an agent restart — losing it every restart is worse. The KEK
// never reaches the model regardless of provider; it lives inside SSP. We only
// surface *which* provider is active (via `doctor`).

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

function devKekPath(): string {
  return path.join(process.env.WIKEY_SSP_DIR ?? path.join(os.homedir(), '.ssp'), 'dev.kek');
}

export function resolveKekPolicy(): KekPolicy {
  const kekFile = devKekPath();
  if (existsSync(kekFile)) {
    let material = '';
    try {
      material = readFileSync(kekFile, 'utf8').trim();
    } catch {
      material = '';
    }
    if (material) {
      return {
        provider: 'env',
        flags: ['-kek-provider', 'env'],
        env: { SSP_KEK: material },
        devKekPresent: true,
      };
    }
  }
  return { provider: 'auto', flags: ['-kek-provider', 'auto'], env: {}, devKekPresent: false };
}
