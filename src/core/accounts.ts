// Explicit account selection — the replacement for the "default key".
//
// The old model kept a pointer (`user.address`/`user.pubkey`) in wallet-cli's
// config and let every unrouted command fall back to it. That made `keys create`
// mutate global signing identity as a side effect, which is why key creation and
// recovery kept re-pointing unrelated operations at the wrong key.
//
// The model here: a caller either NAMES the account, or there is exactly one and
// the choice is not a choice, or the call FAILS with the list of accounts and an
// instruction to ask the user. Nothing is remembered between calls — no ambient
// state to drift, and the agent (which is talking to the user anyway) is the
// thing that carries the choice through a conversation.
//
// Resolution rule:
//   0 keys              → onboarding error (create a key first)
//   1 key,  none asked  → use it silently
//   1 key,  asked       → validate it is that key
//   N keys, none asked  → throw, listing the accounts
//   N keys, asked       → validate it is one of them
//
// Reads stay free: resolveAccountAddress never touches the signer. Only the
// pubkey lookup in resolveAccount does, and it runs after the address is settled
// — so an ambiguous call fails without waking SSP.

import { extractUsernameFromProfile, fetchPubkey } from './signing.js';
import { parseSnapshot } from './snapshot.js';

export type QueryRunner = (args: string[]) => Promise<string>;

// ─── output parsers (lenient — wallet-cli shapes vary by subcommand) ─────────
// These live here rather than in gettingStarted.ts because the guide is now
// built ON TOP of listAccounts; keeping them there would make the two modules
// import each other.

const ADDR_RE = /omnistar1[0-9a-z]{6,}/g;

/** Unique omnistar1… addresses appearing anywhere in a wallet-cli payload. */
export function extractAddresses(raw: string): string[] {
  return Array.from(new Set(raw.match(ADDR_RE) ?? []));
}

/**
 * Whether a string is a chain address rather than an account name. The two are
 * never interchangeable at a wallet-cli flag: `--address` takes an address, and
 * several commands answer a NAME with an empty result instead of an error.
 */
export function isChainAddress(s: string): boolean {
  return /^omnistar1[0-9a-z]{6,}$/.test(s.trim());
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

/** One local signing key and what the chain says about it. */
export interface AccountSummary {
  /** omnistar1… address of the key — its identity, and the keystore filename. */
  address: string;
  /** On-chain profile name (e.g. alice@acme), when the key has an account. */
  name?: string;
  /** Whether the key holds gas. `undefined` when the balance could not be read. */
  funded?: boolean;
  /** Safes owned by this key's profile. Empty until create-safe lands. */
  safes: { address: string; name: string }[];
}

/** An account resolved far enough to sign with. */
export interface ResolvedAccount {
  address: string;
  /** base64, from the signer — see fetchPubkey. */
  pubkey: string;
}

/**
 * Thrown when the account cannot be settled from the inputs. Carries the
 * candidate list so a caller can render a choice; the message is written to be
 * relayed verbatim, because the MCP tool boundary passes only `.message`.
 */
export class AccountResolutionError extends Error {
  readonly accounts: AccountSummary[];
  constructor(message: string, accounts: AccountSummary[] = []) {
    super(message);
    this.name = 'AccountResolutionError';
    this.accounts = accounts;
  }
}

// ─── listing ────────────────────────────────────────────────────────────────

/** `name (address)` when the account has a profile, else the bare address. */
function label(a: AccountSummary): string {
  const bits: string[] = [];
  if (a.safes.length > 0) bits.push(`safe ${a.safes[0]!.address}`);
  if (a.funded === false) bits.push('unfunded');
  const detail = bits.length ? ` — ${bits.join(', ')}` : '';
  return a.name ? `${a.name} (${a.address})${detail}` : `${a.address} (no account yet)${detail}`;
}

/**
 * Every local signing key, annotated with the chain state a user needs in order
 * to pick one. Read-only and signing-free: keys are counted from the keystore
 * DIRECTORY (the address is the filename), so an idle SSP session is never
 * misread as "no keys".
 *
 * Every per-account probe is best-effort and independent — a key with no profile
 * yet (fresh, unfunded, or never create-safe'd) is a normal state, not an error,
 * so its failed lookups degrade to absent fields rather than failing the list.
 */
export async function listAccounts(
  query: QueryRunner,
  listKeys: () => string[],
): Promise<AccountSummary[]> {
  return Promise.all(
    listKeys().map(async (address): Promise<AccountSummary> => {
      const [name, funded, safes] = await Promise.all([
        query(['query', 'profile', '--address', address])
          .then((raw) => extractUsernameFromProfile(raw))
          .catch(() => undefined),
        query(['query', 'balance', '--address', address])
          .then((raw) => parseFunded(raw))
          .catch(() => undefined),
        query(['query', 'snapshot', '--address', address])
          .then((raw) => parseSnapshot(raw).safes.map((s) => ({ address: s.address, name: s.name })))
          .catch(() => []),
      ]);
      return {
        address,
        ...(name ? { name } : {}),
        ...(funded !== undefined ? { funded } : {}),
        safes,
      };
    }),
  );
}

// ─── resolution ─────────────────────────────────────────────────────────────

/**
 * Settle which account a call acts as, WITHOUT the signer. `requested` may be a
 * keystore address or an on-chain account name (alice@acme) — the name matters
 * because it is what the user actually says, and forcing the agent to translate
 * it invites exactly the mix-up this module exists to prevent.
 *
 * The name lookup runs only when `requested` is not already a known address, so
 * the common paths (nothing requested, or an address requested) cost no network.
 */
export async function resolveAccountAddress(
  query: QueryRunner,
  listKeys: () => string[],
  requested?: unknown,
): Promise<string> {
  const keys = listKeys();

  if (keys.length === 0) {
    throw new AccountResolutionError(
      'No signing key exists on this machine, so there is no account to act as. Create one with ' +
        'wallet_keys_create — or, if your organization sent you an invitation link, redeem it with ' +
        'wallet_onboard_sponsor, which creates and funds a key for you.',
    );
  }

  const asked = requested === undefined || requested === null ? '' : String(requested).trim();

  if (asked) {
    if (keys.includes(asked)) return asked;
    // Not a local address — try it as an account name before giving up.
    const accounts = await listAccounts(query, listKeys);
    const byName = accounts.find((a) => a.name && a.name.toLowerCase() === asked.toLowerCase());
    if (byName) return byName.address;
    throw new AccountResolutionError(
      `"${asked}" is not a signing key on this machine, and no local account is named that. ` +
        `Available account(s):\n${accounts.map((a) => `  - ${label(a)}`).join('\n')}\n` +
        `Pass one of these addresses (or its account name). If the key you want is missing, it lives ` +
        `on another machine — this wallet holds no copy of it.`,
      accounts,
    );
  }

  if (keys.length === 1) return keys[0]!;

  // Ambiguous: the whole point is NOT to guess. Pay for the annotated list here
  // (only on this path) so the agent can put a real choice in front of the user
  // instead of two opaque addresses.
  const accounts = await listAccounts(query, listKeys);
  throw new AccountResolutionError(
    `This machine holds ${keys.length} signing keys and the call did not say which to use. ` +
      `ASK THE USER which account to act as, then pass it — do not pick one for them.\n` +
      `${accounts.map((a, i) => `  ${i + 1}. ${label(a)}`).join('\n')}\n` +
      `Call wallet_accounts for the same list as structured data.`,
    accounts,
  );
}

/**
 * Settle the account AND fetch the pubkey needed to sign as it.
 *
 * The address is settled first and signing-free, so an ambiguous or unknown
 * account fails before SSP is woken. `ensureSession` is injected (not imported)
 * to keep core/ transport-agnostic, and is awaited only once an address is
 * settled, so a call that is going to fail never wakes SSP.
 */
export async function resolveAccount(
  query: QueryRunner,
  listKeys: () => string[],
  requested?: unknown,
  opts: { ensureSession?: () => Promise<void> } = {},
): Promise<ResolvedAccount> {
  const address = await resolveAccountAddress(query, listKeys, requested);
  if (opts.ensureSession) await opts.ensureSession();
  return { address, pubkey: await fetchPubkey(query, address) };
}

/**
 * The account a `keys create` run just minted, read from its own stdout.
 *
 * This is how a caller learns the new key's identity now that key creation does
 * NOT touch the config. Reading it back from `user.address` (what onboarding
 * used to do) was only ever correct because `keys create` moved that pointer as
 * a side effect — the very coupling this work removes. wallet-cli prints
 * `{ success, data: { id, publicKey, pubkeyBase64, … } }`, where `id` IS the
 * address, so the answer is already in the output we have.
 */
export function parseCreatedKey(stdout: string): ResolvedAccount {
  let data: { id?: string; pubkeyBase64?: string } | undefined;
  try {
    data = (JSON.parse(stdout) as { data?: { id?: string; pubkeyBase64?: string } }).data;
  } catch {
    throw new Error(`could not parse \`keys create\` output as JSON: ${stdout.slice(0, 200)}`);
  }
  if (!data?.id || !data.pubkeyBase64) {
    throw new Error(
      `\`keys create\` output has no id/pubkeyBase64 — cannot identify the new key: ${stdout.slice(0, 200)}`,
    );
  }
  return { address: data.id, pubkey: data.pubkeyBase64 };
}

/**
 * `--creator <addr> --pubkey <b64>` for wallet-cli's dynamic tx builder, derived
 * from an already-resolved account — no second `keys get`.
 *
 * Belt-and-braces alongside the env routing: the flags are what wallet-cli's tx
 * path reads first, the env is what reaches the commands that have no flags. One
 * resolution feeds both, so they can never disagree.
 *
 * `pubkeyOnly` emits just `--pubkey` for commands whose signer is fixed by
 * another flag — `tx send` derives its creator from `--from` and rejects an
 * unknown `--creator` option. Passing the matching pubkey is what actually
 * routes the SSP proof to that key.
 */
export function signerArgsFor(
  account: ResolvedAccount,
  opts: { pubkeyOnly?: boolean } = {},
): string[] {
  return opts.pubkeyOnly
    ? ['--pubkey', account.pubkey]
    : ['--creator', account.address, '--pubkey', account.pubkey];
}
