// Sponsor onboarding orchestrator: turn a single invitation link into a funded,
// created AND enrolled account — the employee/invitee never funds anything and
// never runs a second tool.
//
// Sequence (mirrors the individual flow, funding step swapped for a sponsor grant):
//   1. mint a FRESH signing key for the invitee
//   2. sponsor-fund that new key against the invite's one-time code (proxy airdrops gas)
//   3. create the invitee's account + safe using the invite's username@organization handle
//   4. commit the grant (only now is it spent — a failed create-safe never burns it)
//   5. enroll the wallet passkey against the gateway with the SAME invitation code
//
// A sponsor invite always provisions a NEW identity, so step 1 never reuses an
// existing key/account. Reusing one would graft the invitee's safe onto a
// pre-existing account (wrong owner + wrong name — the create-safe user_name
// message is a no-op when the profile already exists) AND re-fund an
// already-funded address. We therefore always mint a new key.
//
// Every step below names the address it acts on explicitly. That used to be
// impossible: the new key's address was learned by reading back the config
// default pointer that `keys create` had just moved, so onboarding both depended
// on and disturbed global signing identity — an existing account on the same
// machine silently lost its default to the invitee's key. Now `keys create`
// reports its own address, onboarding carries it through, and nothing else on
// the machine changes.
//
// NOTE: the wallet-cli stack has no HD-index "extra account on the same key"
// concept (keys create mints an independent keypair; create-safe binds to one
// address), so here "new identity" == "new key". Index-derived accounts on an
// existing key would be a separate wallet-cli/signer capability.
//
// PRE-FLIGHT: is this handle already ours? Before minting or funding anything we
// ask whether some key in THIS keystore already owns an account named for the
// invite's username. If one does, the invite was already redeemed here and the
// only honest answer is to say so — minting a key and calling the proxy would
// burn a keypair to be told the same thing by an HTTP 403. This check is local
// and read-only (no proxy, no signing), which is exactly why it goes first.
//
// The carve-out: an INTERRUPTED run also leaves a local account for the handle,
// and that one must still resume (the grant is reserved, possibly uncommitted,
// and the passkey may not be bound). So the short-circuit fires only when the
// breadcrumb agrees the work is finished — no grant for this code, or one that
// already reached `enrolled`. A grant sitting at `funded`/`created` means work is
// genuinely outstanding and falls through to the resume path below.
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
import { loadGrant, saveGrant, type GrantStage } from './idp/sponsorGrants.js';
import { buildRecoveryDeeplink } from './recoveryDeeplink.js';

export interface OnboardSponsorDeps {
  /** Non-signing wallet-cli runner (same one the read tools use). */
  query: (args: string[]) => Promise<string>;
  /**
   * Mint a fresh signing key and return its identity. It is NOT made a default
   * (there is none): the address comes back from `keys create`'s own output, so
   * onboarding knows exactly which key it minted without consulting any pointer.
   */
  createKey: () => Promise<{ address: string; pubkey: string }>;
  /**
   * Broadcast create-safe for `username`, signed by `address` explicitly (never
   * the ambient default — on a resumed run the funded key may not be the
   * default). `allowOrg` permits an @ in the handle.
   */
  createSafe: (username: string, allowOrg: boolean, address: string) => Promise<string>;
  /** Addresses present in the local keystore — used to tell "our key" from someone else's. */
  listKeys: () => string[];
  /**
   * The local key whose on-chain profile is already named `username`, if any.
   * Read-only and signing-free. Keys with no profile yet (freshly created,
   * unfunded, or never create-safe'd) are simply not matches, so this must
   * swallow their lookup failures rather than propagate them.
   */
  findLocalAccount: (username: string) => Promise<string | undefined>;
  /** True once `address` has a profile + safe on-chain (create-safe already done). */
  safeExists: (address: string) => Promise<boolean>;
  /**
   * Poll until `address`'s safe is queryable on-chain, resolving to the safe's
   * address. `safeIsNew` carries the same meaning as in `enroll` — false on a
   * resumed run whose safe was already confirmed, so the poll can skip its
   * initial delay and answer immediately.
   *
   * Resolves `undefined` on timeout rather than throwing: by the time this runs
   * the funding, the safe and the grant commit have all succeeded, and none of
   * them is retried, so a slow chain must not turn a completed onboarding into a
   * failure.
   */
  awaitSafe: (address: string, opts: { safeIsNew: boolean }) => Promise<string | undefined>;
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
  /**
   * The no-enroll variant's success terminal: funded, safe created, grant
   * committed, and enrollment INTENTIONALLY skipped (invite carried
   * `enroll=false`). The account is fully usable on-chain; a passkey can still be
   * bound later with wallet_gateway_register.
   */
  | 'funded-created'
  /** Safe exists and the grant is committed, but the passkey did not bind. */
  | 'created-enroll-failed'
  /**
   * This machine already holds the account for the invite's handle — the link was
   * redeemed here. Nothing was minted, funded or signed. Distinct from
   * `recovery-required`: the account is ALREADY OURS, so there is nothing to
   * recover, only something to report.
   */
  | 'already-onboarded'
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
  /**
   * `recovery-required` only, and only when the key IS funded: the link the
   * recovering user forwards to their recovery helpers. Emitted here because
   * this branch already knows both inputs — the funded new address (`pk`) and
   * the account name being recovered (`tn`) — so the caller never has to run a
   * second tool just to obtain a link we could already build. Absent on an
   * unfunded recovery branch, where the key could not broadcast the request
   * anyway.
   */
  recoveryDeeplink?: string;
  /** Non-fatal problems worth surfacing (e.g. an uncommitted ledger entry). */
  warnings?: string[];
}

export async function onboardSponsor(
  invite: string,
  deps: OnboardSponsorDeps,
): Promise<OnboardSponsorResult> {
  const parsed = parseInvite(invite);
  // Wrong tool for this link. Checked before anything else because every step
  // below has a cost: minting a key displaces the wallet's default, and the
  // funding call is a real value transfer. An enroll-only invite carries no
  // grant, so running on regardless could only end in a confusing failure after
  // leaving a stray key behind.
  //
  // This is routing, NOT enforcement — the parameter is trivially strippable.
  // Nothing here is what keeps an invitee from self-funding; the idp seeds no
  // grant for these codes, so the proxy refuses the airdrop no matter what the
  // link says (and the branch below reports that refusal honestly).
  if (parsed.enrollOnly) {
    throw new Error(
      'this is an ENROLL-ONLY invitation (enroll=only): it binds a gateway passkey to an account you ' +
        'already have, and funds/creates nothing — so there is nothing for this tool to onboard. ' +
        'Run wallet_gateway_register { invite } instead. If you do not have a wallet account and safe ' +
        'yet, this is the wrong link: ask your organization for a sponsored onboarding invitation.',
    );
  }
  if (!parsed.username) {
    throw new Error(
      'invite link has no &username= — the idp must include the wallet handle, e.g. &username=kehat@wikey',
    );
  }
  const warnings: string[] = [];
  const owned = (addr?: string): boolean => Boolean(addr) && deps.listKeys().includes(addr as string);

  // 0. Already ours? Cheapest possible answer, and it costs no key and no grant.
  //    Skipped only while a grant for this code is still mid-flight (see the
  //    pre-flight note above) — that case has real work left and must resume.
  //
  //    "Finished" depends on the invite variant: an enrol invite is done at
  //    `enrolled`, a no-enroll invite (enroll:false) is done at `committed`. We
  //    read the PRIOR run's recorded intent, not this link's, so a completed
  //    no-enroll grant short-circuits to already-onboarded rather than being
  //    mistaken for an interrupted enrol grant and driven into recovery.
  const priorGrant = loadGrant(parsed.invitationCode);
  const priorTerminal: GrantStage = priorGrant?.enroll === false ? 'committed' : 'enrolled';
  const grantInFlight = priorGrant !== null && priorGrant.stage !== priorTerminal;
  if (!grantInFlight) {
    const mine = await deps.findLocalAccount(parsed.username);
    if (mine) {
      return {
        stage: 'already-onboarded',
        address: mine,
        username: parsed.username,
        organization: parsed.organization,
        funded: false,
        keyCreated: false,
        resumed: false,
        enrolled: false,
        message:
          `The account "${parsed.username}" already exists on this machine, owned by the key ${mine}. ` +
          `This invitation link was already redeemed here, so its one-time code is almost certainly spent — ` +
          `no key was created and no funding was attempted.`,
        next:
          `Nothing to do: use the existing account. Check its gateway passkey with wallet_gateway_status, ` +
          `and if the passkey was never bound, re-run just wallet_gateway_register with this link.`,
      };
    }
  }

  // 1. Pick the key to onboard.
  //
  // Prefer resuming the key a previous run already funded for this invite — the
  // breadcrumb is checked BEFORE minting anything, so the common interrupted-run
  // case costs no stray key and no wasted airdrop. Only when there is no local
  // record of this invite do we mint a fresh key.
  let address: string;
  let keyCreated = false;
  let resumed = false;

  if (priorGrant && owned(priorGrant.address)) {
    address = priorGrant.address;
    resumed = true;
  } else {
    address = (await deps.createKey()).address;
    keyCreated = true;
  }

  // 2. Sponsor-fund against the one-time invitation code.
  let fund = await sponsorFund(invite, address);

  // 2a. Reserved to a DIFFERENT address that we hold locally: a previous run
  //     funded that key and the breadcrumb is gone (or was never written).
  //     Adopt it — the gas is there and only it can finish this grant. The key we
  //     just minted is left behind unused; say so, since it still exists.
  if (!fund.funded && !fund.alreadySpent && owned(fund.reservedAddress)) {
    const adopted = fund.reservedAddress as string;
    if (keyCreated) {
      warnings.push(
        `This invite was already funded onto ${adopted} by an earlier run, so onboarding resumed on that key. ` +
          `The key minted this run (${address}) is unused and unfunded; it is simply an extra key in the ` +
          `keystore and affects nothing else, since no key is a default.`,
      );
    }
    address = adopted;
    resumed = true;
    keyCreated = false;
    // Re-issue the fund call for the adopted address: idempotent on the proxy
    // (already reserved to it, no second airdrop) and it re-confirms the grant.
    fund = await sponsorFund(invite, address);
  }

  // 2a-bis. No grant exists for this code AT ALL — nothing was ever spent and
  //     nobody was ever onboarded, so this is not a recovery. The proxy reports
  //     it with committed:false and no reservedAddress (and, on a proxy that
  //     knows the marker, sponsored:false for the enroll-only case).
  //
  //     Worth separating from the branch below because `recovery-required` tells
  //     the user their account already exists and to go find recovery helpers —
  //     advice that is actively wrong here and sends them chasing an account
  //     nobody created. The two are indistinguishable by HTTP status alone; only
  //     the body tells them apart.
  if (!fund.funded && !fund.alreadySpent && !fund.reservedAddress) {
    // Only the proxy can answer "is there a grant?", so the key is already minted
    // by the time we find out. Say so plainly, but it displaces nothing.
    const stray = keyCreated
      ? ` Note: the signing key ${address} was created before this was known. It is unfunded and unused — ` +
        `an extra key in the keystore, nothing more.`
      : '';
    throw new Error(
      (fund.sponsored === false
        ? `This invitation carries no funding grant — it is an ENROLL-ONLY invite, meant for someone who ` +
          `already has a wallet account and safe. Run wallet_gateway_register { invite } instead of onboarding.`
        : `The proxy has no funding grant for this invitation code, so it cannot fund a key. The invite was ` +
          `never armed for sponsored onboarding (or its grant was removed) — nothing has been spent and no ` +
          `account was created, so this is NOT a recovery. Ask your organization to re-issue the invitation.`) + stray,
    );
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
          `machine — onboarding for it was started elsewhere and only that key can finish it.`
        : `Invitation "${parsed.username}" was already used to onboard an account — its one-time ` +
          `funding grant is spent, so the key ${address} could not be funded. ` +
          `Treat re-onboarding as a recovery onto this key.`,
      next:
        `See who must approve a recovery with wallet_recovery_helpers { address: "${parsed.username}" } ` +
        `(it takes the account NAME, so the lost key is not needed). This key is NOT funded, so it cannot ` +
        `broadcast wallet_tx_request_recovery yet — it needs gas first.`,
      ...(warnings.length ? { warnings } : {}),
    };
  }
  saveGrant(parsed.invitationCode, { address, username: parsed.username, stage: 'funded', enroll: parsed.enroll });

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
            `grant funded the key ${address}. Re-onboarding is a recovery, not a new safe.`,
          recoveryDeeplink: buildRecoveryDeeplink({
            newAccount: address,
            accountName: parsed.username,
          }),
          next:
            `Recovery: see who must approve with wallet_recovery_helpers { address: "${parsed.username}" } ` +
            `(it takes the account NAME — the lost key is not needed), then broadcast the request with ` +
            `wallet_tx_request_recovery. Forward recoveryDeeplink to each helper; they approve with ` +
            `wallet_tx_approve_recovery { deeplink }.`,
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
  saveGrant(parsed.invitationCode, { address, username: parsed.username, stage: 'created', enroll: parsed.enroll });

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
    saveGrant(parsed.invitationCode, { address, username: parsed.username, stage: 'committed', enroll: parsed.enroll });
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
    ` and ${alreadyCreated ? 'confirmed' : 'created'} account + safe "${parsed.username}".`;

  // 5a. No-enroll variant (invite carried enroll=false): fund + create the safe
  //     only, then stop. The breadcrumb's terminal stage is `committed` (set
  //     above) and its enroll:false flag marks that as done, so a re-run
  //     short-circuits to already-onboarded rather than resuming. Enrollment is
  //     not lost, only deferred: the Casdoor enrollment ledger (UsedCount/Quota)
  //     is untouched, so wallet_gateway_register with the same link binds a
  //     passkey on demand later.
  if (!parsed.enroll) {
    // Wait for the safe to become READABLE before reporting success. create-safe
    // returns once broadcast, but the profile's safes[] is written by a separate,
    // later addSafe tx — so `query snapshot` keeps returning an empty safes[] for
    // minutes afterwards. The enrol variant absorbs that wait incidentally inside
    // enrollment (waitForSafe, step 5); this branch has no such step, so without
    // an explicit wait it returns "done" while wallet_getting_started still reads
    // stage `no-safe` and instructs the user to create the safe they already have
    // — following that would mint a SECOND safe on the funded key. Waiting here is
    // what makes the success we report agree with the read tools.
    const safe = await deps.awaitSafe(address, { safeIsNew: !alreadyCreated });
    if (!safe) {
      warnings.push(
        `The safe for "${parsed.username}" was created and the sponsor grant committed, but it has not ` +
          `become queryable within the wait budget. Onboarding is COMPLETE — no step needs re-running. ` +
          `Until the chain catches up, wallet_getting_started may report stage "no-safe": re-check in a ` +
          `few minutes rather than calling wallet_tx_create_safe, which would create a second safe on ` +
          `this key.`,
      );
    }
    return {
      ...base,
      stage: 'funded-created',
      enrolled: false,
      safe,
      message:
        `${created} Gateway enrollment was skipped as requested by the invitation (enroll=false); ` +
        `the account is fully set up on-chain${safe ? ` (safe ${safe})` : ''}.`,
      next: 'Optional: bind a gateway passkey any time with wallet_gateway_register using the same invitation link.',
      ...(warnings.length ? { warnings } : {}),
    };
  }

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
    saveGrant(parsed.invitationCode, { address, username: parsed.username, stage: 'enrolled', enroll: parsed.enroll });
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
