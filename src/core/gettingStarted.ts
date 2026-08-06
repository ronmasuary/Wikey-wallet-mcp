// State-aware onboarding guide (the "what can I do next?" tool).
//
// Reads-only: it probes the wallet's current state through the SAME non-signing
// `query` runner every other read uses (never brings up SSP, never touches the
// HMAC key), classifies where the user is in the onboarding sequence, and returns
// an ordered list of next actions naming the exact tool to call. Every probe is
// defensive — a failing/absent probe degrades the report instead of throwing, so
// a brand-new install (no keys, no config, no chain state) still gets a clean map.
//
// The pure classifier (`classifyStage`) and the small output parsers are exported
// so they can be unit-tested with a fake `query`.

import { parseSnapshot } from './snapshot.js';
import { daysSince, type RecoveryRequestRecord } from './recoveryRequests.js';

export type Stage = 'no-key' | 'no-default' | 'unfunded' | 'no-safe' | 'recovery-pending' | 'ready';

export interface NextStep {
  /** Human-readable instruction the agent can relay verbatim. */
  action: string;
  /** The tool the agent should call to perform it, when there is one. */
  tool?: string;
  /** Suggested arguments for that tool. */
  args?: Record<string, unknown>;
}

export interface GettingStartedReport {
  server: string;
  stage: Stage;
  summary: string;
  keyCount: number;
  defaultKey?: string;
  funded?: boolean;
  safes: { address: string; name: string }[];
  /** Present while a recovery this machine requested is still awaiting helpers. */
  pendingRecovery?: { username: string; requestedAt: string };
  /** Ordered — the first entry is the single most important next move. */
  next: NextStep[];
  /** Populated once a safe exists: the full menu of things the user can do. */
  capabilities?: string[];
  notes?: string[];
}

// ─── output parsers (lenient — wallet-cli shapes vary by subcommand) ────────────

const ADDR_RE = /omnistar1[0-9a-z]{6,}/g;

/** Unique omnistar1… addresses appearing anywhere in a wallet-cli payload. */
export function extractAddresses(raw: string): string[] {
  return Array.from(new Set(raw.match(ADDR_RE) ?? []));
}

/** The configured default signing address, or undefined if none is set. */
export function parseDefaultAddress(raw: string): string | undefined {
  // `config get user.address` may print the bare value or a JSON envelope.
  const [first] = extractAddresses(raw);
  return first;
}

/**
 * Whether an address holds any positive balance. Handles the `{data:{balances:
 * [{amount}]}}` envelope and a bare amount; returns undefined when the shape is
 * unrecognizable (so the caller can say "verify funding" rather than assert).
 */
export function parseFunded(raw: string): boolean | undefined {
  const amounts = Array.from(raw.matchAll(/"amount"\s*:\s*"?(\d+)"?/g)).map((m) => Number(m[1]));
  if (amounts.length > 0) return amounts.some((n) => n > 0);
  // Fallback: a bare integer line (e.g. "1000nost").
  const bare = raw.match(/(\d+)\s*n?ost/i);
  if (bare) return Number(bare[1]) > 0;
  return undefined;
}

// ─── classifier (pure) ──────────────────────────────────────────────────────────

export interface ProbeResult {
  keyCount: number;
  defaultKey?: string;
  funded?: boolean;
  safes: { address: string; name: string }[];
  /** An outstanding recovery this machine requested for the default key. */
  pendingRecovery?: RecoveryRequestRecord;
}

export function classifyStage(p: ProbeResult): Stage {
  if (p.keyCount === 0) return 'no-key';
  if (!p.defaultKey) return 'no-default';
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
  'Send assets out of a safe: wallet_tx_create_transaction',
  'Add or remove users on a safe: wallet_tx_create_user / wallet_tx_delete_user',
  'Create or edit governance policies: wallet_tx_create_policy / wallet_tx_edit_policy',
  'View recovery helpers + threshold: wallet_recovery_helpers (read this first — helpers are the policy allowed_source; threshold is a % of the total helper count). Edit them: wallet_tx_edit_helpers',
  'Vote on governed objects: wallet_tx_vote',
  'Configure notifications: wallet_notification_configure',
  'Enroll a passkey to call 3rd-party APIs/MCPs through the gateway: wallet_gateway_register → wallet_gateway_login',
];

function stepsFor(stage: Stage, p: ProbeResult): { summary: string; next: NextStep[] } {
  switch (stage) {
    case 'no-key':
      return {
        summary:
          'No signing key yet. This is step 1 of onboarding — the same for individual and sponsored/employee users; only the later funding step differs.',
        next: [
          {
            action:
              'Create your first signing key (set it as the default so signing works automatically). A key is required either way; whether you fund it yourself or your organization sponsors it is decided at the funding step.',
            tool: 'wallet_keys_create',
            args: { setDefault: true },
          },
        ],
      };
    case 'no-default':
      return {
        summary: `${p.keyCount} key(s) exist but none is set as the default. Signing needs a default key.`,
        next: [
          {
            action:
              'Create a new key as the default (user.address is locked, so the default is set at key-creation time).',
            tool: 'wallet_keys_create',
            args: { setDefault: true },
          },
        ],
      };
    case 'unfunded':
      return {
        summary: `Default key ${p.defaultKey} has no OST. It needs gas before it can create anything on-chain — fund it yourself, or have your organization sponsor it.`,
        next: [
          {
            action: `Individual: fund the key by sending OST to ${p.defaultKey} (from an exchange, faucet, or another funded key via wallet_tx_send), then run wallet_getting_started again.`,
          },
          {
            action:
              'Sponsored / employee: if your organization gave you an invitation link, you do NOT fund the key yourself — give that link to your agent and it will call wallet_onboard_sponsor with it. That one call funds the key, creates your account (safe), and enrolls your gateway passkey.',
            tool: 'wallet_onboard_sponsor',
            args: { invite: '<the invitation link from your organization>' },
          },
          {
            action: 'Check the balance to confirm funds arrived.',
            tool: 'wallet_balance',
            args: { address: p.defaultKey },
          },
        ],
      };
    case 'no-safe':
      return {
        summary: `Default key ${p.defaultKey} is funded but has no safe yet. Create your account (safe + username).`,
        next: [
          {
            action: 'Create your safe + on-chain profile with a username (letters, numbers, dots only). Takes ~30s to validate.',
            tool: 'wallet_tx_create_safe',
            args: { username: '<your-username>' },
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
        ],
      };
    case 'recovery-pending': {
      const rec = p.pendingRecovery!;
      const days = daysSince(rec.requestedAt);
      const waited =
        days === undefined ? '' : days === 0 ? ' (requested today)' : ` (requested ${days} day(s) ago)`;
      return {
        // Two different situations land here and this stage cannot tell them
        // apart without an extra call: helpers still outstanding, and the last
        // approval already in with the safe still settling. Name both, so the
        // reader neither reports completion early nor treats the delay as a
        // fault. The safe appearing under the new key remains the ONLY
        // completion signal (see classifyStage).
        summary:
          `Recovery of "${rec.username}" onto key ${p.defaultKey} is IN PROGRESS${waited} — NOT finished yet. ` +
          `Either the account's recovery helpers still need to approve (each approves on their own schedule, ` +
          `so this can take a while), or the last approval has just landed and the safe is still settling — ` +
          `after the final approval it usually appears here within about a minute, occasionally several ` +
          `minutes longer. Nothing is wrong in either case. Do NOT create a safe — the account already ` +
          `exists — and do not attempt anything involving its safe until this reports stage "ready" with ` +
          `the safe listed, which happens automatically.`,
        next: [
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
            args: { username: rec.username },
          },
          {
            action: 'Check back later — run wallet_getting_started again; it reports "ready" as soon as the recovery lands.',
          },
        ],
      };
    }
    case 'ready': {
      const list = p.safes.map((s) => `${s.name || '(unnamed)'} → ${s.address}`).join(', ');
      return {
        summary: `You're set up. Safe(s): ${list}. Here's everything you can do now.`,
        next: [
          { action: 'Inspect your safe to see users, policies, and assets.', tool: 'wallet_snapshot' },
          { action: 'Move assets out of the safe.', tool: 'wallet_tx_create_transaction' },
          { action: 'Enroll a wallet passkey to authorize 3rd-party API/MCP calls.', tool: 'wallet_gateway_register' },
        ],
      };
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
  query: (args: string[]) => Promise<string>,
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

  // Count keys from the keystore DIRECTORY, not via `keys list` (which is an HTTP
  // call into the signing-server and fails when SSP is idle). The address is the
  // key filename, so this read is accurate whether or not the signer is up — and
  // it never brings SSP up. This is what stops an unreachable signer from being
  // misreported as "no-key" (an empty keystore genuinely means no keys). Only
  // *signing* needs the server; asking "what do I have" does not.
  const keyAddresses = listKeys();
  const keyCount = keyAddresses.length;

  let defaultKey: string | undefined;
  if (keyCount > 0) {
    try {
      defaultKey = parseDefaultAddress(await query(['config', 'get', 'user.address']));
    } catch {
      /* no default configured — treated as no-default below */
    }
  }

  let funded: boolean | undefined;
  if (defaultKey) {
    try {
      funded = parseFunded(await query(['query', 'balance', '--address', defaultKey]));
    } catch {
      notes.push('Could not read balance; funding status unknown.');
    }
  }

  let safes: { address: string; name: string }[] = [];
  if (defaultKey) {
    try {
      const snap = parseSnapshot(await query(['query', 'snapshot']));
      safes = snap.safes.map((s) => ({ address: s.address, name: s.name }));
    } catch {
      // No safe yet, or profile not on-chain — safes stays []. This CANNOT be
      // split into "absent" vs "lookup failed": the snapshot upstream answers
      // 502 for a missing account, the same status a genuine outage produces
      // (verified 2026-08-05). Treating a failure as "unknown" here would put
      // every brand-new user into an unknown state and break first-run
      // onboarding, so the ambiguity is left where it is and handled by the
      // recovery breadcrumb + the no-safe warning instead.
    }
  }

  // A recovery in flight is the one state where "you have no safe" must not
  // become "create a safe". Completion needs no extra call: the recovered safe
  // resolves under the NEW key as soon as the chain finalizes updateUserAddress,
  // so a non-empty safe list IS the completion signal — clear the breadcrumb.
  let pendingRecovery: RecoveryRequestRecord | undefined;
  if (defaultKey && recovery) {
    pendingRecovery = recovery.load(defaultKey) ?? undefined;
    if (pendingRecovery && safes.length > 0) {
      recovery.clear(defaultKey);
      notes.push(`Recovery of "${pendingRecovery.username}" is complete — this key now owns the account.`);
      pendingRecovery = undefined;
    }
  }

  const probe: ProbeResult = { keyCount, defaultKey, funded, safes, pendingRecovery };
  const stage = classifyStage(probe);
  const { summary, next } = stepsFor(stage, probe);

  return {
    server: serverName,
    stage,
    summary,
    keyCount,
    defaultKey,
    funded,
    safes,
    ...(pendingRecovery
      ? { pendingRecovery: { username: pendingRecovery.username, requestedAt: pendingRecovery.requestedAt } }
      : {}),
    next,
    ...(stage === 'ready' ? { capabilities: CAPABILITIES } : {}),
    ...(notes.length ? { notes } : {}),
  };
}
