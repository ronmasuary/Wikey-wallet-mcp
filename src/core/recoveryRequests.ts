// Local breadcrumb of recovery requests this machine has broadcast, so the
// onboarding guide can tell "waiting on my helpers" apart from "brand-new key
// with no account".
//
// WHY THIS EXISTS — and why it is NOT a poll:
//
// Recovery is an open-ended, multi-party governance process. The helpers are
// independent people who approve on their own schedule; completion can be hours,
// days or weeks away, and there is no upper bound to wait against. So nothing
// here ever blocks or polls. Instead we record that a recovery is OUTSTANDING and
// let each read of the guide answer the question cheaply, on demand.
//
// Without this record the guide sees a funded key with no safe and classifies it
// as `no-safe` — whose next step is "create a safe + username". For someone
// mid-recovery that advice is actively harmful: following it mints a SECOND safe
// (or fails on a taken handle) on a recovery that was going to succeed on its own.
// The whole point of the breadcrumb is to suppress that one instruction.
//
// COMPLETION NEEDS NO EXTRA CALL. `query snapshot --address <newKey>` resolves by
// public key, and the chain follows the updateUserAddress indirection itself — so
// the recovered safe appears under the NEW key the moment recovery finalizes.
// A non-empty safe list IS the completion signal; the guide clears the breadcrumb
// when it sees one.
//
// Best-effort, exactly like sponsorGrants: the chain stays authoritative. A write
// failure must never fail a recovery that otherwise broadcast fine, and a missing
// breadcrumb only costs a less specific report — never a wrong on-chain action.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { stateRoot } from './binPaths.js';

export interface RecoveryRequestRecord {
  /** The NEW key the account is being recovered onto (the one that signed the request). */
  newAddress: string;
  /** Account handle being recovered — the only handle the user still has. */
  username: string;
  /** ISO timestamp of the request, so a long wait can be reported as such. */
  requestedAt: string;
}

/** Keyed by the new address: one outstanding recovery per key. */
type RecoveryFile = Record<string, RecoveryRequestRecord>;

function requestsFile(): string {
  return path.join(stateRoot(), 'recovery-requests.json');
}

function readAll(): RecoveryFile {
  try {
    return JSON.parse(readFileSync(requestsFile(), 'utf-8')) as RecoveryFile;
  } catch {
    return {};
  }
}

/** The outstanding recovery this machine requested for `newAddress`, if any. */
export function loadRecoveryRequest(newAddress: string): RecoveryRequestRecord | null {
  return readAll()[newAddress] ?? null;
}

/** Record an outstanding recovery. Best-effort — never throws. */
export function saveRecoveryRequest(record: Omit<RecoveryRequestRecord, 'requestedAt'>): void {
  try {
    mkdirSync(path.dirname(requestsFile()), { recursive: true });
    const all = readAll();
    all[record.newAddress] = { ...record, requestedAt: new Date().toISOString() };
    writeFileSync(requestsFile(), JSON.stringify(all, null, 2));
  } catch {
    /* non-fatal — the guide simply falls back to its address-only report */
  }
}

/** Drop the breadcrumb once the recovered account is visible. Best-effort. */
export function clearRecoveryRequest(newAddress: string): void {
  try {
    const all = readAll();
    if (!(newAddress in all)) return;
    delete all[newAddress];
    writeFileSync(requestsFile(), JSON.stringify(all, null, 2));
  } catch {
    /* non-fatal — a stale breadcrumb self-clears on the next successful pass */
  }
}

/** Whole-days elapsed since `requestedAt`, or undefined if unparseable. */
export function daysSince(requestedAt: string, now: Date = new Date()): number | undefined {
  const then = Date.parse(requestedAt);
  if (Number.isNaN(then)) return undefined;
  return Math.max(0, Math.floor((now.getTime() - then) / 86_400_000));
}
