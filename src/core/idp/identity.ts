// Wallet identity + on-chain snapshot resolution for the Casdoor passkey flow.
//
// Resolves a wallet identity exactly the way Casdoor's ValidateObject does:
//   - account: the signing-key address (the profile/account) the CALLER named —
//     never a default; see resolveWalletIdentity.
//   - safe:    the asset-holding safe linked to the account (survives recovery).
//   - ecPuk:   the safe's EC public key — the WebAuthn credential public key;
//     Casdoor derives the bound (safe) address from it.

import { Secp256k1, ripemd160, sha256 } from '@cosmjs/crypto';
import { toBech32, fromHex } from '@cosmjs/encoding';
import type { Cfg } from './config.js';

export interface WalletIdentity {
  account: string;
  safe: string;
  ecPukHex: string;
  x: Buffer;
  y: Buffer;
}

interface SnapshotObject {
  id?: string;
  class?: string;
  isValid?: boolean;
  isDeleted?: boolean;
  object?: { safes?: { safe_address?: string }[] };
  process?: { currentPhase?: { name?: string } };
}
interface Snapshot {
  groups?: { nestedObjects?: SnapshotObject[] }[];
  assets?: { ecPuk?: string };
}

/** Fetch an omnistar safe/profile snapshot from the WiKey node Casdoor uses. */
export async function fetchSnapshot(cfg: Cfg, address: string): Promise<Snapshot> {
  const s = cfg.snapshotSecure ? 's' : '';
  const url = `http${s}://${cfg.snapshotNode}/snapshot/safe?publickey=${address}&env=${cfg.env}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`snapshot ${address} HTTP ${res.status}`);
  return (await res.json()) as Snapshot;
}

/** Derive the omnistar (bech32) address from a secp256k1 public key (compressed/uncompressed hex). */
export function omnistarAddress(pubHex: string): string {
  const comp = Secp256k1.compressPubkey(fromHex(pubHex.startsWith('0x') ? pubHex.slice(2) : pubHex));
  return toBech32('omnistar', ripemd160(sha256(comp)));
}

/** Find the first object in a snapshot's groups matching a predicate. */
function findObject(snapshot: Snapshot, predicate: (o: SnapshotObject) => boolean): SnapshotObject | null {
  for (const g of snapshot.groups ?? []) {
    for (const o of g.nestedObjects ?? []) {
      if (predicate(o)) return o;
    }
  }
  return null;
}

/**
 * Resolve a wallet identity (account, safe, ecPuk, x/y) for Casdoor.
 *
 * `account` is REQUIRED — there is no default key and no config pointer to fall
 * back to. It used to be optional, resolving to whatever `user.address` happened
 * to hold, which meant enrollment could bind a passkey to a different account
 * than the caller intended (and did, whenever a key creation or recovery had
 * moved the pointer). The caller now states which account it means; the MCP
 * settles that with resolveAccount before getting here.
 */
export async function resolveWalletIdentity(cfg: Cfg, account: string): Promise<WalletIdentity> {
  if (!account) {
    throw new Error(
      'resolveWalletIdentity requires an account address — this wallet has no default key. ' +
        'Resolve one first (wallet_accounts lists them).',
    );
  }

  const accountSnap = await fetchSnapshot(cfg, account);
  const profile = findObject(accountSnap, (o) => o.class === 'profile' && !!o.object?.safes?.length);
  const safe = profile?.object?.safes?.[0]?.safe_address;
  if (!safe) throw new Error(`could not resolve safe address from account ${account} profile`);

  const safeSnap = await fetchSnapshot(cfg, safe);
  const ecPukHex = safeSnap.assets?.ecPuk;
  if (!ecPukHex) throw new Error(`safe ${safe} has no assets.ecPuk`);

  const derived = omnistarAddress(ecPukHex);
  if (derived !== safe) throw new Error(`safe ecPuk derives to ${derived}, expected ${safe}`);

  const buf = fromHex(ecPukHex.startsWith('0x') ? ecPukHex.slice(2) : ecPukHex);
  return {
    account,
    safe,
    ecPukHex,
    x: Buffer.from(buf.subarray(1, 33)),
    y: Buffer.from(buf.subarray(33, 65)),
  };
}

/**
 * Poll until `account`'s profile → safe → ecPuk chain resolves on-chain.
 *
 * create-safe broadcasts and returns before the safe is queryable — validation
 * takes ~30s — so anything that must run immediately after it (notably passkey
 * enrollment, which needs the safe's ecPuk as the credential public key) has to
 * wait rather than fail. Every attempt is retried, including a snapshot HTTP
 * error: right after broadcast the node legitimately has nothing to serve yet.
 * The last error is re-thrown once the budget runs out, so a genuine failure
 * still surfaces its real cause.
 *
 * `initialDelayMs` skips the doomed early polls entirely: the first requests can
 * only fail, so waiting first cuts pointless round-trips (and the identical "no
 * profile" errors they log) without delaying success. It also keeps `lastError`
 * meaningful: the reported cause is then a real post-validation failure, not the
 * first "nothing on chain yet" blip.
 *
 * Budget sizing — the safe does NOT appear ~30s after broadcast, as the original
 * estimate here assumed. The profile's `safes[]` is written by a SEPARATE, LATER
 * `addSafe` tx than the create-safe tx, and a mainnet onboarding on 2026-07-21
 * took ~2min end to end. The previous ≈110s budget therefore expired on a
 * perfectly healthy onboarding and reported it as `created-enroll-failed`, even
 * though a manual enroll moments later succeeded. Default budget is now
 * ≈ 30s + 42×5s = 240s (4min) — roughly 2× the observed worst case. Timing out
 * here is not fatal: the caller keeps the on-chain work and retries only the
 * enrollment, so a generous budget costs nothing but a slower failure.
 */
export async function waitForWalletIdentity(
  cfg: Cfg,
  account: string,
  { attempts = 43, intervalMs = 5000, initialDelayMs = 30_000 } = {},
): Promise<WalletIdentity> {
  if (initialDelayMs > 0) await new Promise((r) => setTimeout(r, initialDelayMs));

  let lastError: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await resolveWalletIdentity(cfg, account);
    } catch (e) {
      lastError = e;
      // No sleep after the final attempt — it would just delay the throw.
      if (i < attempts - 1) await new Promise((r) => setTimeout(r, intervalMs));
    }
  }
  throw new Error(
    `safe for account ${account} did not become queryable in time: ${(lastError as Error)?.message ?? lastError}`,
  );
}

/** Poll the safe snapshot until an object with the given id is valid & not deleted. */
export async function waitForObjectValid(
  cfg: Cfg,
  safe: string,
  objectId: string,
  { attempts = 20, intervalMs = 3000 } = {},
): Promise<SnapshotObject> {
  for (let i = 0; i < attempts; i++) {
    const snap = await fetchSnapshot(cfg, safe);
    const obj = findObject(snap, (o) => o.id === objectId);
    if (obj && obj.isValid && !obj.isDeleted) return obj;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`FIDO object ${objectId} not valid on safe ${safe} after ${attempts} polls`);
}
