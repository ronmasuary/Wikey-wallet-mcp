// Wallet identity + on-chain snapshot resolution for the Casdoor passkey flow.
//
// Resolves the agent's identity exactly the way Casdoor's ValidateObject does:
//   - account: the SSP default-key address (the profile/account), read from the
//     co-located wallet-cli config under the state root.
//   - safe:    the asset-holding safe linked to the account (survives recovery).
//   - ecPuk:   the safe's EC public key — the WebAuthn credential public key;
//     Casdoor derives the bound (safe) address from it.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { Secp256k1, ripemd160, sha256 } from '@cosmjs/crypto';
import { toBech32, fromHex } from '@cosmjs/encoding';
import { walletHome } from '../binPaths.js';
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

/** Account address: CASDOOR_ACCOUNT override, else the co-located default-key pointer. */
export function readAccountAddress(cfg: Cfg): string {
  if (cfg.account) return cfg.account;
  const cfgPath = path.join(walletHome(), '.wallet-cli', 'config.json');
  try {
    const wc = JSON.parse(readFileSync(cfgPath, 'utf-8')) as { user?: { address?: string } };
    const addr = wc.user?.address;
    if (addr) return addr;
  } catch {
    /* fall through to the clear error below */
  }
  throw new Error(
    'no account address — set a default key (wallet_keys_create setDefault:true) or pass CASDOOR_ACCOUNT',
  );
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

/** Resolve the agent's wallet identity (account, safe, ecPuk, x/y) for Casdoor. */
export async function resolveWalletIdentity(cfg: Cfg): Promise<WalletIdentity> {
  const account = readAccountAddress(cfg);

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
