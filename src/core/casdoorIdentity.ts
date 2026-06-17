// Wallet ↔ Casdoor bridge (P-FIDO). Gateway-specific glue that stays OUT of the
// generic signing core: it (1) reads the safe's EC public key from a wallet-cli
// snapshot, (2) polls the chain until the on-chain FIDO object is valid, (3)
// signs the WebAuthn challenge via the generic SessionManager.signRaw, and (4)
// builds the create-fido-object tx args. It holds NO signing secrets — it only
// calls the generic SessionManager methods and the operator registry's bundles.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { stateRoot } from './binPaths.js';
import { xyFromUncompressed } from './webauthn.js';
import type { IdentityBundle } from './identityRegistry.js';

/** Minimal view of SessionManager we depend on (keeps this module unit-testable). */
export interface RawSigner {
  signRaw(unsignedDataHex: string, signingPubKey: string): Promise<string>;
}

export type QueryFn = (args: string[]) => Promise<string>;

export interface WalletIdentity {
  /** The SSP key address (the profile/account). */
  account: string;
  /** The asset-holding safe linked to the account (survives recovery). */
  safe: string;
  /** The safe's uncompressed EC public key hex (04‖X‖Y) — the WebAuthn credential key. */
  ecPuk: string;
  x: Buffer;
  y: Buffer;
}

// Slice from the first JSON delimiter — wallet-cli prints a URL line before the
// body (same tolerance as snapshot.ts:parseSnapshot).
function sliceJson(raw: string): string {
  const brace = raw.indexOf('{');
  const bracket = raw.indexOf('[');
  const start = brace === -1 ? bracket : bracket === -1 ? brace : Math.min(brace, bracket);
  return start >= 0 ? raw.slice(start) : raw;
}

/**
 * Resolve the agent's wallet identity from a `wallet-cli query snapshot` of the
 * configured account. We read `assets.ecPuk` directly from the raw snapshot —
 * the typed parseSnapshot (snapshot.ts) intentionally models only group/nested
 * structure for the deletion resolvers and drops `assets`, so reusing it here
 * would lose the pubkey. No @cosmjs derive-check: the on-chain FIDO object is
 * the real gate (plan §8).
 */
export async function resolveWalletIdentity(query: QueryFn): Promise<WalletIdentity> {
  const raw = await query(['query', 'snapshot']);
  let parsed: unknown;
  try {
    parsed = JSON.parse(sliceJson(raw));
  } catch {
    throw new Error(`failed to parse query snapshot JSON. Raw tail: ${raw.slice(-200)}`);
  }
  const root = parsed as { data?: { address?: unknown; snapshot?: unknown } };
  const account = typeof root.data?.address === 'string' ? root.data.address : undefined;
  const snaps = Array.isArray(root.data?.snapshot) ? (root.data!.snapshot as Record<string, unknown>[]) : [];
  if (!account) throw new Error('query snapshot: no data.address (account) — is a default key configured?');
  if (snaps.length === 0) throw new Error(`query snapshot for ${account}: no safes found`);

  const main = snaps.find((s) => s.isMain === true) ?? snaps[0]!;
  const safe = typeof main.address === 'string' ? main.address : undefined;
  const assets = (main.assets ?? {}) as { ecPuk?: unknown };
  const ecPuk = typeof assets.ecPuk === 'string' ? assets.ecPuk : undefined;
  if (!safe) throw new Error(`query snapshot for ${account}: main safe has no address`);
  if (!ecPuk) throw new Error(`safe ${safe} has no assets.ecPuk (needed for the WebAuthn credential key)`);

  const { x, y } = xyFromUncompressed(ecPuk);
  return { account, safe, ecPuk, x, y };
}

/** Build the `tx create-fido-object` argument array. signerArgs = [] for the default key. */
export function createFidoObjectArgs(
  safe: string,
  uuid: string,
  payloadHex: string,
  signerArgs: string[] = [],
): string[] {
  return [
    'tx', 'create-fido-object',
    '--destination', safe,
    '--id', uuid,
    '--payload', payloadHex,
    '--broadcast',
    ...signerArgs,
  ];
}

/**
 * Sign the WebAuthn challenge bytes with the SSP-held account key via /v1/sign.
 * Resolves the account's 33-byte compressed pubkey (hex) from `keys get` — which
 * is exactly what /v1/sign needs to locate the key — then defers to signRaw.
 */
export async function signChallengeViaSSP(
  signer: RawSigner,
  query: QueryFn,
  account: string,
  signedDataHex: string,
): Promise<string> {
  const raw = await query(['keys', 'get', '--id', account]);
  let pubKeyHex: string | undefined;
  try {
    const j = JSON.parse(raw) as { data?: { publicKey?: unknown } };
    if (typeof j.data?.publicKey === 'string') pubKeyHex = j.data.publicKey;
  } catch {
    throw new Error(`keys get ${account}: could not parse output to resolve the compressed pubkey`);
  }
  if (!pubKeyHex) throw new Error(`keys get ${account}: no publicKey (is the account key present in the signer?)`);
  return signer.signRaw(signedDataHex, pubKeyHex);
}

export interface WaitOpts {
  attempts?: number;
  intervalMs?: number;
  /** Injectable fetch for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

/**
 * Poll the safe snapshot (a fresh GET /snapshot/safe against the bundle's node —
 * the SAME endpoint Casdoor's ValidateObject reads, distinct from wallet-cli's
 * /snapshot/client) until the FIDO object `uuid` is valid & not deleted.
 */
export async function waitForObjectValid(
  bundle: IdentityBundle,
  safe: string,
  uuid: string,
  opts: WaitOpts = {},
): Promise<void> {
  const attempts = opts.attempts ?? 20;
  const intervalMs = opts.intervalMs ?? 3000;
  const doFetch = opts.fetchImpl ?? fetch;
  const proto = bundle.snapshotSecure ? 'https' : 'http';
  const url = `${proto}://${bundle.snapshotNode}/snapshot/safe?publickey=${encodeURIComponent(safe)}&env=${encodeURIComponent(bundle.env)}`;

  for (let i = 0; i < attempts; i++) {
    let snap: { groups?: { nestedObjects?: { id?: string; isValid?: boolean; isDeleted?: boolean }[] }[] };
    try {
      const res = await doFetch(url);
      if (!res.ok) throw new Error(`snapshot/safe HTTP ${res.status}`);
      snap = (await res.json()) as typeof snap;
      for (const g of snap.groups ?? []) {
        for (const o of g.nestedObjects ?? []) {
          if (o.id === uuid) {
            if (o.isValid && !o.isDeleted) return;
          }
        }
      }
    } catch {
      /* transient — retry until attempts exhausted */
    }
    if (i < attempts - 1) await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`FIDO object ${uuid} not valid on safe ${safe} after ${attempts} polls`);
}

// ─── per-identity credential store ────────────────────────────────────────────

export interface StoredCredential {
  credentialIdB64url: string;
  safe: string;
  account: string;
  org: string;
  user: string;
  registeredAt: string;
}

function credPath(alias: string, rootFn: () => string = stateRoot): string {
  return path.join(rootFn(), 'casdoor-credentials', `${alias}.json`);
}

export function loadCredential(alias: string, rootFn: () => string = stateRoot): StoredCredential | null {
  try {
    return JSON.parse(readFileSync(credPath(alias, rootFn), 'utf8')) as StoredCredential;
  } catch {
    return null;
  }
}

export function saveCredential(alias: string, cred: StoredCredential, rootFn: () => string = stateRoot): void {
  const file = credPath(alias, rootFn);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(cred, null, 2), { mode: 0o600 });
}
