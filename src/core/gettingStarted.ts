// State-aware onboarding guide (the "what can I do next?" tool).
//
// Reads-only: it probes the wallet's current state through the SAME non-signing
// `query` runner every other read uses (never brings up SSP, never touches the
// HMAC key), classifies where the user is in the onboarding sequence, and returns
// an ordered list of next actions naming the exact tool to call. Every probe is
// defensive — a failing/absent probe degrades the report instead of throwing, so
// a brand-new install (no keys, no config, no chain state) still gets a clean map.
//
// PER-ACCOUNT. There is no default key, so "what stage am I at?" is a question
// about an ACCOUNT, not about the machine: with two keys, one can be ready while
// another is mid-recovery. Each key gets its own stage in `accounts[]`. The
// top-level `stage` is that account's stage when there is exactly one (the
// common case, unchanged for callers), and `multiple-accounts` when there are
// several — deliberately NOT a collapsed "best" stage, which would let a ready
// account mask another one's unfinished recovery.
//
// The pure classifier (`classifyAccount`) and the small output parsers are
// exported so they can be unit-tested with a fake `query`.

import { listAccounts, type AccountSummary, type QueryRunner } from './accounts.js';
import { daysSince, type RecoveryRequestRecord } from './recoveryRequests.js';
import { detectStaleBuild, type RestartNotice } from './restartNotice.js';

/** Where an individual (unsponsored) user buys the OST gas a new key needs. */
export const WIKEY_STORE_URL = 'https://store.wikey.io/';

/**
 * The store link for a SPECIFIC key. The store reads `?address=` and prefills its
 * "User address" field, which removes the one step of this flow a human can get
 * wrong in an unrecoverable way: hand-copying a 40+ character bech32 address into
 * a payment form. A typo there sends real OST to an address nobody holds.
 *
 * Only ever called with an address that came back from the keystore or from
 * `keys create`, but the shape is checked anyway — a malformed value would
 * produce a link that silently prefills garbage, which is worse than no prefill.
 * `encodeURIComponent` for the same reason: the address goes in a query string,
 * so it gets encoded like any other untrusted-position value.
 */
export function storeFundingUrl(address?: string): string {
  if (!address || !/^omnistar1[0-9a-z]+$/.test(address)) return WIKEY_STORE_URL;
  return `${WIKEY_STORE_URL}?address=${encodeURIComponent(address)}`;
}

/** Where a SINGLE account sits in the onboarding sequence. */
export type AccountStage = 'unfunded' | 'no-safe' | 'recovery-pending' | 'ready';

/** Overall report stage. `no-key` and `multiple-accounts` are machine-level. */
export type Stage = 'no-key' | AccountStage | 'multiple-accounts';

export interface NextStep {
  /** Human-readable instruction the agent can relay verbatim. */
  action: string;
  /** The tool the agent should call to perform it, when there is one. */
  tool?: string;
  /** Suggested arguments for that tool. */
  args?: Record<string, unknown>;
}

/** One local key, its chain state, and the stage that follows from them. */
export interface AccountReport extends AccountSummary {
  stage: AccountStage;
  /** Present while a recovery this machine requested is still awaiting helpers. */
  pendingRecovery?: { username: string; requestedAt: string };
  /** The single most important next move FOR THIS ACCOUNT. */
  next: NextStep[];
}

export interface GettingStartedReport {
  server: string;
  /** The version of the code actually SERVING this call (not what is on disk). */
  version?: string;
  /**
   * Set when the package on disk is newer than the running process — i.e. the
   * user upgraded while their AI client was up. Until the client is restarted
   * every answer here comes from the OLD build.
   */
  restartRequired?: RestartNotice;
  stage: Stage;
  summary: string;
  keyCount: number;
  /** Every local key. Empty only at stage `no-key`. */
  accounts: AccountReport[];
  /** Ordered — the first entry is the single most important next move. */
  next: NextStep[];
  /** Populated once some account is ready: the full menu of things the user can do. */
  capabilities?: string[];
  notes?: string[];
}

// ─── classifier (pure) ──────────────────────────────────────────────────────────
// The output parsers (extractAddresses, parseFunded) moved to accounts.ts — the
// guide is built on top of listAccounts now, so keeping them here would make the
// two modules import each other.

export interface AccountProbe extends AccountSummary {
  /** An outstanding recovery this machine requested for this key. */
  pendingRecovery?: RecoveryRequestRecord;
}

export function classifyAccount(p: AccountProbe): AccountStage {
  // A visible safe ends every other question — including a pending recovery,
  // whose completion is precisely "the safe now resolves under the new key".
  if (p.safes.length > 0) return 'ready';
  // Before anything that could advise creating a safe: a recovery in flight
  // means the account already exists and must NOT be recreated.
  if (p.pendingRecovery) return 'recovery-pending';
  if (p.funded === false) return 'unfunded';
  // NOTE: a failed snapshot probe cannot be distinguished from a genuinely
  // absent account here — the upstream returns 502 for BOTH a missing account
  // and a real outage (verified 2026-08-05). So "no safe" stays the fallback,
  // and the protection against acting on it wrongly lives in the no-safe
  // next-steps (which warn about recovery) rather than in a separate stage.
  return 'no-safe';
}

const CAPABILITIES = [
  'Inspect your safe: wallet_snapshot, wallet_profile, wallet_assets',
  'Send assets out of a safe: wallet_tx_create_transaction (check it first with wallet_tx_check — the network fee comes out of the same balance, so the full balance is never sendable; use its maxSuggested for "send everything", and its feeChoice to ask the user which fee priority they want)',
  'Add or remove users on a safe: wallet_tx_create_user / wallet_tx_delete_user',
  'Create or edit governance policies: wallet_tx_create_policy / wallet_tx_edit_policy',
  'View recovery helpers + threshold: wallet_recovery_helpers (read this first — helpers are the policy allowed_source; threshold is a % of the total helper count). Edit them: wallet_tx_edit_helpers',
  'Vote on governed objects: wallet_tx_vote',
  'Configure notifications: wallet_notification_configure',
  'Enroll a passkey to call 3rd-party APIs/MCPs through the gateway: wallet_gateway_register → wallet_gateway_login',
];

/** How to refer to an account in prose: its name if it has one, else its address. */
function who(a: AccountSummary): string {
  return a.name ? `"${a.name}" (${a.address})` : a.address;
}

function stepsForAccount(stage: AccountStage, p: AccountProbe): NextStep[] {
  switch (stage) {
    case 'unfunded':
      return [
        {
          action:
            `OPTION 1 — INDIVIDUAL (self-funded): buy OST for this key at ${storeFundingUrl(p.address)} — GIVE THE ` +
            `USER THAT EXACT LINK, do not shorten it to the bare store address: it prefills the store's "User ` +
            `address" field with ${p.address}, so they never have to copy the address by hand and cannot mistype ` +
            `it. (An exchange, a faucet, or another funded key via wallet_tx_send work too.) Then run ` +
            `wallet_getting_started again — it moves on to creating your account (safe).`,
        },
        {
          action:
            'OPTION 2 — SPONSORED / EMPLOYEE: if your organization gave you an invitation link you do NOT fund ' +
            'anything yourself — paste the link and this tool funds a key, creates your account (safe), and ' +
            'enrolls your gateway passkey in one call. NOTE that an invite always provisions a FRESH identity, ' +
            `so it will not adopt ${p.address}: that key stays behind, unfunded and unused. That is harmless, ` +
            'but from then on it shows up alongside the real account in wallet_accounts, so confirm with the ' +
            'user that the invite is the path they want before redeeming it.',
          tool: 'wallet_onboard_sponsor',
          args: { invite: '<the invitation link from your organization>' },
        },
        { action: 'Check the balance to confirm funds arrived.', tool: 'wallet_balance', args: { address: p.address } },
      ];
    case 'no-safe':
      return [
        {
          action: `Create this key's safe + on-chain profile with a username (letters, numbers, dots only). Takes ~30s to validate.`,
          tool: 'wallet_tx_create_safe',
          args: { username: '<your-username>', account: p.address },
        },
        // Stateless safety net for the case the breadcrumb cannot cover: a
        // recovery requested from ANOTHER machine leaves no local record, so
        // this stage is reached with an account that already exists. Creating a
        // safe would be the wrong move and is hard to walk back.
        {
          action:
            'RECOVERING an existing account (lost key)? Do NOT create a safe — that makes a second, separate account. Ask wallet_recovery_helpers for the account name to see who can approve, then use wallet_tx_request_recovery.',
          tool: 'wallet_recovery_helpers',
          args: { address: '<your-existing-account-name>' },
        },
      ];
    case 'recovery-pending': {
      const rec = p.pendingRecovery!;
      return [
        {
          action:
            'See who must approve and how many approvals are still required (threshold is a % of the total helper count).',
          tool: 'wallet_recovery_helpers',
          args: { address: rec.username },
        },
        {
          action:
            'Re-send the recovery deeplink to any helper who has not acted yet. Re-running the request is safe and returns the same link.',
          tool: 'wallet_tx_request_recovery',
          args: { username: rec.username, account: p.address },
        },
        { action: 'Check back later — run wallet_getting_started again; it reports "ready" as soon as the recovery lands.' },
      ];
    }
    case 'ready':
      return [
        { action: 'Inspect this safe to see users, policies, and assets.', tool: 'wallet_snapshot', args: { address: p.address } },
        { action: 'Move assets out of the safe.', tool: 'wallet_tx_create_transaction', args: { account: p.address } },
        { action: 'Enroll a wallet passkey to authorize 3rd-party API/MCP calls.', tool: 'wallet_gateway_register', args: { account: p.address } },
      ];
  }
}

function summarizeAccount(stage: AccountStage, p: AccountProbe): string {
  switch (stage) {
    case 'unfunded':
      return (
        `${who(p)} has no OST. It needs gas before it can create anything on-chain. Two ways to get it: buy ` +
        `OST at ${storeFundingUrl(p.address)} — that link already carries this key's address, so the store ` +
        `fills it in for the user — or, if your organization gave you an invitation link, redeem that instead ` +
        `and the sponsor funds everything for you.`
      );
    case 'no-safe':
      return `${who(p)} is funded but has no safe yet. Create its account (safe + username).`;
    case 'recovery-pending': {
      const rec = p.pendingRecovery!;
      const days = daysSince(rec.requestedAt);
      const waited = days === undefined ? '' : days === 0 ? ' (requested today)' : ` (requested ${days} day(s) ago)`;
      // Two different situations land here and this stage cannot tell them
      // apart without an extra call: helpers still outstanding, and the last
      // approval already in with the safe still settling. Name both, so the
      // reader neither reports completion early nor treats the delay as a
      // fault. The safe appearing under the new key remains the ONLY completion
      // signal (see classifyAccount).
      return (
        `Recovery of "${rec.username}" onto key ${p.address} is IN PROGRESS${waited} — NOT finished yet. ` +
        `Either the account's recovery helpers still need to approve (each approves on their own schedule, ` +
        `so this can take a while), or the last approval has just landed and the safe is still settling — ` +
        `after the final approval it usually appears here within about a minute, occasionally several ` +
        `minutes longer. Nothing is wrong in either case. Do NOT create a safe — the account already ` +
        `exists — and do not attempt anything involving its safe until this reports stage "ready" with ` +
        `the safe listed, which happens automatically.`
      );
    }
    case 'ready': {
      const list = p.safes.map((s) => `${s.name || '(unnamed)'} → ${s.address}`).join(', ');
      return `${who(p)} is set up. Safe(s): ${list}.`;
    }
  }
}

// ─── builder (impure — takes the injected query runner) ─────────────────────────

/**
 * Probe live state and produce the guide. `query` is the non-signing wallet-cli
 * runner (same one the read tools use). Every probe is wrapped so a failure at
 * any stage (no config yet, chain unreachable, empty profile) still yields a
 * usable report pointing at the earliest unmet step.
 */
export async function buildGettingStarted(
  query: QueryRunner,
  serverName: string,
  listKeys: () => string[],
  /**
   * Access to the local recovery breadcrumb. Injected (not imported) so the
   * classifier stays unit-testable with a fake. Omitted → the guide behaves
   * exactly as before, minus the recovery-pending stage.
   */
  recovery?: {
    load: (address: string) => RecoveryRequestRecord | null;
    clear: (address: string) => void;
  },
  /**
   * Build identity, injected for the same reason as `recovery` — testability.
   * `running` is the version this PROCESS started with; `installed` is what is
   * on disk right now. A mismatch means an in-place upgrade under a live client.
   */
  build?: { running?: string; installed?: string },
): Promise<GettingStartedReport> {
  const notes: string[] = [];

  // Attached to every report, whatever stage: a user asking "what's next?" while
  // unknowingly talking to a pre-upgrade build needs to hear that before they
  // act on anything else the report says.
  const restartRequired = detectStaleBuild(build?.running, build?.installed);
  const common = {
    ...(build?.running ? { version: build.running } : {}),
    ...(restartRequired ? { restartRequired } : {}),
  };
  if (restartRequired) notes.push(restartRequired.message);

  // Keys are counted from the keystore DIRECTORY (the address is the filename),
  // never via `keys list` — an HTTP call into the signing-server that fails when
  // SSP is idle. This is what stops an unreachable signer from being misreported
  // as "no-key". Only *using* a key needs the server; asking "what do I have"
  // does not. listAccounts applies the same discipline to each key's chain state.
  const summaries = await listAccounts(query, listKeys);
  const keyCount = summaries.length;

  if (keyCount === 0) {
    // A BRAND-NEW install. There are exactly two ways in, and they are not two
    // orderings of the same steps: the sponsored path MINTS ITS OWN KEY
    // (onboardSponsor never adopts an existing one — an invite always provisions
    // a fresh identity). So creating a key first and only then producing an
    // invitation link strands the key it just made: unfunded, safeless, and
    // indistinguishable from the real one in `wallet_accounts` forever after.
    // That is why the fork is the FIRST step here and neither option is the
    // default — the question has to reach the user before anything is created.
    return {
      server: serverName,
      ...common,
      stage: 'no-key',
      summary:
        'Nothing is set up yet — this wallet has no signing key. There are TWO ways to start, and the ' +
        'right one depends on where the funding comes from: (1) INDIVIDUAL — create your own key and fund ' +
        `it yourself with OST gas from the Wikey store ${WIKEY_STORE_URL}, then create your account (safe); ` +
        'or (2) SPONSORED — you were given an invitation link by your organization or a sponsor, and that ' +
        'one link does everything (creates the key, funds it from the sponsor, and creates your account + ' +
        'safe on-chain). ASK THE USER WHICH ONE THEY HAVE before creating anything: the sponsored path ' +
        'mints its own key, so a key created up front would be left over, unfunded and unusable.',
      keyCount: 0,
      accounts: [],
      next: [
        {
          action:
            'ASK THE USER FIRST: "Do you have an invitation link from your organization/sponsor, or are you ' +
            'setting yourself up as an individual?" Do not pick for them and do not create a key until they ' +
            'answer — the two options below mint the key differently.',
        },
        {
          action:
            `OPTION 1 — INDIVIDUAL (self-funded). Step 1 of 3: create your first signing key. That call returns ` +
            `a ready-made \`fundingUrl\` — the Wikey store (${WIKEY_STORE_URL}) with the new key's address ` +
            `already filled in. GIVE THE USER THAT LINK VERBATIM so they never have to copy the address by ` +
            `hand; buying OST there is step 2 (gas is required before anything can be broadcast on-chain). ` +
            `Then run wallet_getting_started again and it will walk you through creating your account ` +
            `(safe + username).`,
          tool: 'wallet_keys_create',
        },
        {
          action:
            'OPTION 2 — SPONSORED (invitation link from your organization/sponsor). Ask the user to paste the ' +
            'link and pass it straight to this tool: it does the WHOLE onboarding in one call — creates a new ' +
            'signing key, funds it from the sponsor grant (the user never buys or sends gas themselves), and ' +
            'creates their account + safe on-chain under the invite\'s username@organization handle, usually ' +
            'also enrolling their gateway passkey. Takes a few minutes. Do NOT call wallet_keys_create first.',
          tool: 'wallet_onboard_sponsor',
          args: { invite: '<the invitation link from your organization/sponsor>' },
        },
      ],
      // Only ever the stale-build notice at this stage (no account to report on),
      // but it is the stage a freshly-upgraded install lands on most often.
      ...(notes.length ? { notes } : {}),
    };
  }

  // Keep each account's probe alongside its report: the probe carries the live
  // recovery record, which the single-account summary needs and which must not
  // be re-read (the breadcrumb may have just been cleared).
  const built = summaries.map((s) => {
    // A recovery in flight is the one state where "you have no safe" must not
    // become "create a safe". Completion needs no extra call: the recovered safe
    // resolves under the NEW key as soon as the chain finalizes updateUserAddress,
    // so a non-empty safe list IS the completion signal — clear the breadcrumb.
    let pendingRecovery = recovery?.load(s.address) ?? undefined;
    if (pendingRecovery && s.safes.length > 0) {
      recovery!.clear(s.address);
      notes.push(`Recovery of "${pendingRecovery.username}" is complete — ${s.address} now owns the account.`);
      pendingRecovery = undefined;
    }
    const probe: AccountProbe = { ...s, ...(pendingRecovery ? { pendingRecovery } : {}) };
    const stage = classifyAccount(probe);
    const report: AccountReport = {
      ...s,
      stage,
      ...(pendingRecovery
        ? { pendingRecovery: { username: pendingRecovery.username, requestedAt: pendingRecovery.requestedAt } }
        : {}),
      next: stepsForAccount(stage, probe),
    };
    return { report, probe };
  });
  const accounts = built.map((b) => b.report);

  if (built.length === 1) {
    const { report, probe } = built[0]!;
    return {
      server: serverName,
      ...common,
      stage: report.stage,
      summary: summarizeAccount(report.stage, probe),
      keyCount,
      accounts,
      next: report.next,
      ...(report.stage === 'ready' ? { capabilities: CAPABILITIES } : {}),
      ...(notes.length ? { notes } : {}),
    };
  }

  // Several keys: refuse to collapse them into one stage. Each account's own
  // stage and next steps are in accounts[]; the top-level next step is to find
  // out which account the user means, because every signing tool will ask.
  const ready = accounts.filter((a) => a.stage === 'ready');
  const pending = accounts.filter((a) => a.stage === 'recovery-pending');
  return {
    server: serverName,
    ...common,
    stage: 'multiple-accounts',
    summary:
      `This machine holds ${keyCount} keys, so there is no single answer — each account has its own stage ` +
      `in accounts[]. ${ready.length} ready, ${pending.length} awaiting recovery, ` +
      `${accounts.length - ready.length - pending.length} still in setup. There is no default account: ` +
      `every signing tool needs to be told which one to act as, so ASK THE USER before acting.` +
      (pending.length
        ? ` NOTE: a recovery is still in progress on ${pending.map((a) => a.address).join(', ')} — that account is NOT ready even though another one is.`
        : ''),
    keyCount,
    accounts,
    next: [
      {
        action:
          'Show the user their accounts and ask which one they mean. Their answer is what you pass as `account` to every subsequent tool.',
        tool: 'wallet_accounts',
      },
      ...accounts.flatMap((a) => a.next.slice(0, 1).map((s) => ({ ...s, action: `[${a.name ?? a.address}] ${s.action}` }))),
    ],
    ...(ready.length ? { capabilities: CAPABILITIES } : {}),
    ...(notes.length ? { notes } : {}),
  };
}
