// Persistent "which gateway am I targeting" profile + registered credential for
// the wallet MCP's Casdoor/gateway flow.
//
// One source of truth — host / org / user / app / OAuth client — shared by
// register, login and api-call (through the cfg resolver). This is what stops
// drift where a stale credential is for one user while defaults point at another.
//
// Everything lives under the single state root (WIKEY_SSP_DIR) in an `idp/`
// subdir, alongside the keystore + wallet-cli config, so a target/credential and
// the keys they bind to are co-located and survive restarts together.

import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { stateRoot } from '../binPaths.js';

function idpDir(): string {
  return path.join(stateRoot(), 'idp');
}
export function targetFile(): string {
  return path.join(idpDir(), 'gateway-target.json');
}
export function targetPrevFile(): string {
  return path.join(idpDir(), 'gateway-target.prev.json');
}
export function credStore(): string {
  return path.join(idpDir(), 'casdoor-credential.json');
}

// The fields a target carries. Secrets (clientSecret) live here too (local,
// state-root runtime). Bootstrap passwords / invitation codes are NEVER persisted.
export const TARGET_FIELDS = [
  'host',
  'rpId',
  'origin',
  'organization',
  'username',
  'application',
  'clientId',
  'clientSecret',
  'redirectUri',
  // Wikey proxy base URL used for the pre-passkey sponsor-fund call (funding goes
  // direct to the proxy, not through the gateway). Overridable via WIKEY_PROXY_URL.
  'proxyUrl',
] as const;

export type TargetField = (typeof TARGET_FIELDS)[number];
export type Target = Partial<Record<TargetField, string>>;

export interface Credential {
  credentialIdB64url: string;
  safe: string;
  account: string;
  organization: string;
  username: string;
  registeredAt: string;
}

function readJson<T>(file: string): T | null {
  try {
    return JSON.parse(readFileSync(file, 'utf-8')) as T;
  } catch {
    return null;
  }
}

/** Load a target profile (active by default). Returns null if absent/unreadable. */
export function loadTarget(file = targetFile()): Target | null {
  return readJson<Target>(file);
}

/** Persist a target profile, keeping only known, non-empty fields. */
export function saveTarget(target: Target, file = targetFile()): Target {
  mkdirSync(idpDir(), { recursive: true });
  const clean: Target = {};
  for (const k of TARGET_FIELDS) {
    const v = target[k];
    if (v != null && String(v).length > 0) clean[k] = String(v);
  }
  writeFileSync(file, JSON.stringify(clean, null, 2));
  return clean;
}

/** Clear the active target. By default it is first copied to the .prev file so a
 *  later re-register can offer the previous values as defaults. */
export function clearTarget({ keepPrev = true } = {}): Target | null {
  const current = loadTarget();
  if (current && keepPrev) saveTarget(current, targetPrevFile());
  try {
    rmSync(targetFile());
  } catch {
    /* already gone */
  }
  return current;
}

export function loadCredential(): Credential | null {
  return readJson<Credential>(credStore());
}

export function saveCredential(cred: Credential): void {
  mkdirSync(idpDir(), { recursive: true });
  writeFileSync(credStore(), JSON.stringify(cred, null, 2));
}

export function clearCredential(): boolean {
  if (!existsSync(credStore())) return false;
  try {
    rmSync(credStore());
    return true;
  } catch {
    return false;
  }
}
