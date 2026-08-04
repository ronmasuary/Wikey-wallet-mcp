// Local breadcrumb of sponsor grants this machine has funded, so an interrupted
// onboarding can RESUME instead of starting a second identity.
//
// Sponsor onboarding moves real value (the airdrop) before the safe exists, and
// the proxy's grant is two-phase: reserved-and-airdropped, then committed. If the
// run dies between those points — a transient create-safe failure, a killed
// agent, a lost connection — the gas is sitting on a key in THIS keystore and the
// grant is resumable by that address alone. Without a local record, a re-run mints
// a fresh key, gets refused by the proxy (the grant is reserved to the old
// address), and cannot tell that refusal apart from a genuinely spent invite.
// This store is that record.
//
// SECRET HANDLING: the invitation code is a bearer secret and is NEVER persisted
// (same rule as target.ts). Entries are keyed by SHA-256 of the code, which is
// enough to look up "have I funded this invite?" without storing anything that
// could redeem it. The stored address is public (it is on-chain).

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { stateRoot } from '../binPaths.js';

/** How far a grant got. Each stage is resumable from the next step. */
export type GrantStage = 'funded' | 'created' | 'committed' | 'enrolled';

export interface SponsorGrantRecord {
  /** The funded key — the ONLY address that can resume this grant. */
  address: string;
  /** Wallet handle (username@organization) the safe is/was created under. */
  username: string;
  stage: GrantStage;
  /**
   * Whether this invite wants gateway enrollment. `false` marks the
   * fund-and-create-only variant, whose TERMINAL stage is `committed` (it never
   * reaches `enrolled`). Absent means `true` — back-compat with grants written
   * before the no-enroll variant existed, all of which were enrol flows. The
   * resume logic reads this to tell a finished no-enroll grant from one still
   * mid-flight at `committed`.
   */
  enroll?: boolean;
  updatedAt: string;
}

type GrantFile = Record<string, SponsorGrantRecord>;

function grantsFile(): string {
  return path.join(stateRoot(), 'idp', 'sponsor-grants.json');
}

/** Stable, non-reversible lookup key for an invitation code. */
export function grantKey(invitationCode: string): string {
  return createHash('sha256').update(invitationCode).digest('hex');
}

function readAll(): GrantFile {
  try {
    return JSON.parse(readFileSync(grantsFile(), 'utf-8')) as GrantFile;
  } catch {
    return {};
  }
}

/** The grant this machine funded for `invitationCode`, if any. */
export function loadGrant(invitationCode: string): SponsorGrantRecord | null {
  return readAll()[grantKey(invitationCode)] ?? null;
}

/**
 * Record (or advance) the grant for `invitationCode`. Best-effort: the store is a
 * convenience for resuming, never a correctness dependency — the proxy's ledger
 * and the chain remain authoritative — so a write failure must not fail an
 * onboarding that otherwise succeeded.
 */
export function saveGrant(
  invitationCode: string,
  record: Omit<SponsorGrantRecord, 'updatedAt'>,
): void {
  try {
    mkdirSync(path.dirname(grantsFile()), { recursive: true });
    const all = readAll();
    all[grantKey(invitationCode)] = { ...record, updatedAt: new Date().toISOString() };
    writeFileSync(grantsFile(), JSON.stringify(all, null, 2));
  } catch {
    /* non-fatal — resume simply falls back to the proxy's reservedAddress */
  }
}
