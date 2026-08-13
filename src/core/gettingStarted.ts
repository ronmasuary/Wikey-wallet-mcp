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
  'Send assets out of a safe: wallet_tx_create_transaction (check it first with wallet_tx_check — the network fee comes out of the same balance, so the full balance is never sendable; use its maxSuggested for "send everything")',
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
          action: `Individual: fund this key by sending OST to ${p.address} (from an exchange, faucet, or another funded key via wallet_tx_send), then run wallet_getting_started again.`,
        },
        {
          action:
            'Sponsored / employee: if your organization gave you an invitation link, you do NOT fund the key yourself — give that link to your agent and it will call wallet_onboard_sponsor with it. That one call funds a NEW key, creates your account (safe), and enrolls your gateway passkey.',
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
      return `${who(p)} has no OST. It needs gas before it can create anything on-chain — fund it yourself, or have your organization sponsor it.`;
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
): Promise<GettingStartedReport> {
  const notes: string[] = [];

  // Keys are counted from the keystore DIRECTORY (the address is the filename),
  // never via `keys list` — an HTTP call into the signing-server that fails when
  // SSP is idle. This is what stops an unreachable signer from being misreported
  // as "no-key". Only *using* a key needs the server; asking "what do I have"
  // does not. listAccounts applies the same discipline to each key's chain state.
  const summaries = await listAccounts(query, listKeys);
  const keyCount = summaries.length;

  if (keyCount === 0) {
    return {
      server: serverName,
      stage: 'no-key',
      summary:
        'No signing key yet. This is step 1 of onboarding — the same for individual and sponsored/employee users; only the later funding step differs.',
      keyCount: 0,
      accounts: [],
      next: [
        {
          action:
            'Create your first signing key. A key is required either way; whether you fund it yourself or your organization sponsors it is decided at the funding step.',
          tool: 'wallet_keys_create',
        },
      ],
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
