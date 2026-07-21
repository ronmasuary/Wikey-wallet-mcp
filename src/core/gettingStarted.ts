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

export type Stage = 'no-key' | 'no-default' | 'unfunded' | 'no-safe' | 'ready';

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
}

export function classifyStage(p: ProbeResult): Stage {
  if (p.keyCount === 0) return 'no-key';
  if (!p.defaultKey) return 'no-default';
  if (p.safes.length > 0) return 'ready';
  if (p.funded === false) return 'unfunded';
  // funded === true (or unknown) but no safe yet → the next move is the safe.
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
        ],
      };
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
      /* no safe yet, or profile not on-chain — safes stays [] */
    }
  }

  const probe: ProbeResult = { keyCount, defaultKey, funded, safes };
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
    next,
    ...(stage === 'ready' ? { capabilities: CAPABILITIES } : {}),
    ...(notes.length ? { notes } : {}),
  };
}
