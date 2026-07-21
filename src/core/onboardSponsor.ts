// Sponsor onboarding orchestrator: turn a single invitation link into a funded,
// created AND enrolled account — the employee/invitee never funds anything and
// never runs a second tool.
//
// Sequence (mirrors the individual flow, funding step swapped for a sponsor grant):
//   1. mint a FRESH signing key for the invitee and set it as default
//   2. sponsor-fund that new key against the invite's one-time code (proxy airdrops gas)
//   3. create the invitee's account + safe using the invite's username@organization handle
//   4. commit the grant (only now is it spent — a failed create-safe never burns it)
//   5. enroll the wallet passkey against the gateway with the SAME invitation code
//
// A sponsor invite always provisions a NEW identity, so step 1 never reuses an
// existing default key/account. Reusing one would graft the invitee's safe onto a
// pre-existing account (wrong owner + wrong name — the create-safe user_name
// message is a no-op when the profile already exists) AND re-fund an
// already-funded address. We therefore mint a new key even when a default already
// exists; the displaced default is reported back so a shared/test machine can
// switch back. NOTE: the wallet-cli stack has no HD-index "extra account on the
// same key" concept (keys create mints an independent keypair; create-safe binds
// to one address), so here "new identity" == "new key". Index-derived accounts on
// an existing key would be a separate wallet-cli/signer capability.
//
// RESUME, not restart. Steps 2-5 move real value and real on-chain state, so a
// run that dies part-way must continue where it stopped. Minting a second key
// instead would strand the airdropped gas on the first one and — because the
// proxy reserves a grant to exactly one address — make every later attempt look
// like a spent invite. Two independent signals let us find the funded key again:
// the local grant breadcrumb (sponsorGrants.ts) and, if that is lost, the
// `reservedAddress` the proxy returns with its 409. Either way we adopt that key,
// skip the steps already done (checked against the CHAIN, not the breadcrumb),
// and finish. Only a COMMITTED grant (proxy 403) means the invite truly onboarded
// someone — that alone routes to recovery.

import { sponsorFund, sponsorCommit, parseInvite } from './idp/sponsorFund.js';
import { loadGrant, saveGrant } from './idp/sponsorGrants.js';
import { parseDefaultAddress } from './gettingStarted.js';

export interface OnboardSponsorDeps {
  /** Non-signing wallet-cli runner (same one the read tools use). */
  query: (args: string[]) => Promise<string>;
  /** Create a new signing key and set it as default; returns wallet-cli output. */
  createDefaultKey: () => Promise<string>;
  /**
   * Broadcast create-safe for `username`, signed by `address` explicitly (never
   * the ambient default — on a resumed run the funded key may not be the
   * default). `allowOrg` permits an @ in the handle.
   */
  createSafe: (username: string, allowOrg: boolean, address: string) => Promise<string>;
  /** Addresses present in the local keystore — used to tell "our key" from someone else's. */
  listKeys: () => string[];
  /** True once `address` has a profile + safe on-chain (create-safe already done). */
  safeExists: (address: string) => Promise<boolean>;
  /**
   * Bind the wallet passkey for `address` to the gateway using the invite.
   * `safeIsNew` is true when create-safe just ran, so the safe still needs its
   * ~30s on-chain validation before it can be read; false on a resumed run whose
   * safe was already confirmed queryable (no reason to wait again).
   */
  enroll: (
    invite: string,
    address: string,
    opts: { safeIsNew: boolean },
  ) => Promise<{ safe: string; username: string; organization: string }>;
}

export type OnboardStage =
  /** Everything done: funded, safe created, grant committed, passkey enrolled. */
  | 'funded-created-enrolled'
  /** Safe exists and the grant is committed, but the passkey did not bind. */
  | 'created-enroll-failed'
  /** The invite already onboarded an account — this is a recovery, not a new safe. */
  | 'recovery-required';

export interface OnboardSponsorResult {
  stage: OnboardStage;
  address: string;
  username: string;
  organization: string;
  funded: boolean;
  keyCreated: boolean;
  /** True when this run continued a previous, interrupted onboarding. */
  resumed: boolean;
  enrolled: boolean;
  safe?: string;
  createSafeOutput?: string;
  message: string;
  next?: string;
  /** Non-fatal problems worth surfacing (e.g. an uncommitted ledger entry). */
  warnings?: string[];
}

async function currentDefaultAddress(
  query: (args: string[]) => Promise<string>,
): Promise<string | undefined> {
  try {
    return parseDefaultAddress(await query(['config', 'get', 'user.address']));
  } catch {
    return undefined;
  }
}

export async function onboardSponsor(
  invite: string,
  deps: OnboardSponsorDeps,
): Promise<OnboardSponsorResult> {
  const parsed = parseInvite(invite);
  if (!parsed.username) {
    throw new Error(
      'invite link has no &username= — the idp must include the wallet handle, e.g. &username=kehat@wikey',
    );
  }
  const warnings: string[] = [];
  const owned = (addr?: string): boolean => Boolean(addr) && deps.listKeys().includes(addr as string);

  // 1. Pick the key to onboard.
  //
  // Prefer resuming the key a previous run already funded for this invite — the
  // breadcrumb is checked BEFORE minting anything, so the common interrupted-run
  // case costs no stray key and no wasted airdrop. Only when there is no local
  // record of this invite do we mint a fresh key.
  const priorGrant = loadGrant(parsed.invitationCode);
  let address: string;
  let keyCreated = false;
  let resumed = false;
  let switched = '';

  if (priorGrant && owned(priorGrant.address)) {
    address = priorGrant.address;
    resumed = true;
  } else {
    const priorDefault = await currentDefaultAddress(deps.query);
    await deps.createDefaultKey();
    const created = await currentDefaultAddress(deps.query);
    if (!created) throw new Error('signing key created but no default address is set');
    if (created === priorDefault) {
      throw new Error('expected a new default key after key creation, but the default is unchanged');
    }
    address = created;
    keyCreated = true;
    switched = priorDefault ? ` (default switched from ${priorDefault} to the new key)` : '';
  }

  // 2. Sponsor-fund against the one-time invitation code.
  let fund = await sponsorFund(invite, deps.query, address);

  // 2a. Reserved to a DIFFERENT address that we hold locally: a previous run
  //     funded that key and the breadcrumb is gone (or was never written).
  //     Adopt it — the gas is there and only it can finish this grant. The key we
  //     just minted is left behind unused; say so, because it is now the default.
  if (!fund.funded && !fund.alreadySpent && owned(fund.reservedAddress)) {
    const adopted = fund.reservedAddress as string;
    if (keyCreated) {
      warnings.push(
        `This invite was already funded onto ${adopted} by an earlier run, so onboarding resumed on that key. ` +
          `The key minted this run (${address}) is unused but is now the wallet's default — ` +
          `create a new default or re-run onboarding if you expected ${address} to be your account.`,
      );
    }
    address = adopted;
    resumed = true;
    keyCreated = false;
    switched = '';
    // Re-issue the fund call for the adopted address: idempotent on the proxy
    // (already reserved to it, no second airdrop) and it re-confirms the grant.
    fund = await sponsorFund(invite, deps.query, address);
  }

  // 2b. Genuinely committed (or reserved to a key we do not hold) → recovery.
  if (!fund.funded) {
    const elsewhere = fund.reservedAddress && !owned(fund.reservedAddress);
    return {
      stage: 'recovery-required',
      address,
      username: parsed.username,
      organization: parsed.organization,
      funded: false,
      keyCreated,
      resumed,
      enrolled: false,
      message: elsewhere
        ? `Invitation "${parsed.username}" is already funded onto ${fund.reservedAddress}, which is not a key on this ` +
          `machine — onboarding for it was started elsewhere and only that key can finish it${switched}.`
        : `Invitation "${parsed.username}" was already used to onboard an account — its one-time ` +
          `funding grant is spent, so the key ${address} could not be funded${switched}. ` +
          `Treat re-onboarding as a recovery onto this key.`,
      next: 'Recover the existing account onto this key: wallet_tx_request_recovery (then approve/vote per the account helpers).',
      ...(warnings.length ? { warnings } : {}),
    };
  }
  saveGrant(parsed.invitationCode, { address, username: parsed.username, stage: 'funded' });

  // 3. Create the account + safe — unless the chain says it already exists (a
  //    resumed run whose create-safe actually landed before the failure). The
  //    CHAIN is the authority here, not the breadcrumb: create-safe can succeed
  //    and the process die before anything is recorded.
  const allowOrg = parsed.username.includes('@');
  let createSafeOutput: string | undefined;
  const alreadyCreated = resumed && (await deps.safeExists(address));
  if (!alreadyCreated) {
    try {
      createSafeOutput = await deps.createSafe(parsed.username, allowOrg, address);
    } catch (e) {
      const msg = (e as Error).message || String(e);
      // create-safe rejects a taken username → the identity already exists → recovery.
      // (Rare on a fresh grant, but possible if the handle was created out-of-band.)
      if (/taken|already|exist/i.test(msg)) {
        return {
          stage: 'recovery-required',
          address,
          username: parsed.username,
          organization: parsed.organization,
          funded: true,
          keyCreated,
          resumed,
          enrolled: false,
          message:
            `The username "${parsed.username}" already has an on-chain account, but this invite's ` +
            `grant funded the key ${address}${switched}. Re-onboarding is a recovery, not a new safe.`,
          next: 'Recover the existing account onto this key: wallet_tx_request_recovery (then approve/vote per the account helpers).',
          ...(warnings.length ? { warnings } : {}),
        };
      }
      // The grant is RESERVED (not spent) and the key is funded, but no safe was
      // created. Re-running this same tool with the same link resumes on this key
      // — that is the supported retry, and it is why we say "reserved", not
      // "consumed": nothing is lost.
      throw new Error(
        `create-safe did not complete and no safe "${parsed.username}" exists yet: ${msg}. ` +
          `The sponsor grant is RESERVED (not spent) for the funded key ${address}, so nothing is lost — ` +
          `re-run wallet_onboard_sponsor with the same invitation link to resume on that key.`,
      );
    }
  }
  saveGrant(parsed.invitationCode, { address, username: parsed.username, stage: 'created' });

  // 4. Finalize (commit) the grant now that the safe exists. sponsorFund only
  //    RESERVED + airdropped; committing here is what actually spends the
  //    one-time grant — so a create-safe failure above never burns it.
  //    Best-effort: a failed commit doesn't undo the created safe, but we surface
  //    it so the ledger can be reconciled.
  const commit = await sponsorCommit(invite, address);
  if (!commit.committed) {
    warnings.push(
      `Sponsor grant not finalized on the proxy: ${commit.message ?? 'commit failed'} — the safe exists, ` +
        `but the sponsorships ledger still shows this invite as unspent. Reconcile it.`,
    );
  } else {
    saveGrant(parsed.invitationCode, { address, username: parsed.username, stage: 'committed' });
  }

  const base = {
    address,
    username: parsed.username,
    organization: parsed.organization,
    funded: true,
    keyCreated,
    resumed,
    createSafeOutput,
  };
  const created =
    `${alreadyCreated ? 'Resumed onboarding on the already-funded key' : 'Funded new invitee key'} ${address}` +
    ` and ${alreadyCreated ? 'confirmed' : 'created'} account + safe "${parsed.username}"${switched}.`;

  // 5. Enroll the wallet passkey with the SAME invitation code. Casdoor tracks
  //    enrollment on its own ledger (UsedCount/Quota) and the register path is
  //    idempotent (it falls back to logging in with the code if the invite
  //    already created the user), so this is safe on a resumed run.
  //
  //    A failure here does NOT undo steps 1-4: the funded key, the safe and the
  //    committed grant all still exist and are exactly what enrollment needs.
  //    Report the partial success and point at the standalone tool rather than
  //    throwing away a completed on-chain onboarding.
  try {
    const reg = await deps.enroll(invite, address, { safeIsNew: !alreadyCreated });
    saveGrant(parsed.invitationCode, { address, username: parsed.username, stage: 'enrolled' });
    return {
      ...base,
      stage: 'funded-created-enrolled',
      enrolled: true,
      safe: reg.safe,
      message: `${created} Wallet passkey enrolled against the gateway for ${reg.username}@${reg.organization} (safe ${reg.safe}).`,
      ...(warnings.length ? { warnings } : {}),
    };
  } catch (e) {
    return {
      ...base,
      stage: 'created-enroll-failed',
      enrolled: false,
      message:
        `${created} The account is fully set up on-chain, but binding the gateway passkey failed: ` +
        `${(e as Error).message || String(e)}`,
      next: 'Retry just the enrollment step: wallet_gateway_register with the same invitation link (the on-chain work is already done and is not repeated).',
      ...(warnings.length ? { warnings } : {}),
    };
  }
}
