/**
 * Recipient resolution — turning "transfer 2 BTC to op20" into a chain-native
 * `--to` address.
 *
 * PURE. No I/O, no spawn, no HTTP: the safes arrive already read
 * (core/assetInfo.ts `fetchRecipientSafes`) and the name already resolved
 * (wallet-cli's own username resolver). That is what makes every guard here
 * testable against a fixture rather than against mainnet.
 *
 * WHY IT EXISTS. `--to` is the CHAIN-NATIVE recipient address, and wallet-cli
 * does not validate it: `to` is declared `string` while `destination` is
 * `address`, so only the SOURCE safe is address-checked. A safe's omnistar
 * address passed as `--to` for BTC is accepted, broadcast and lost. OST is the
 * trap that hides this — OST's receive address genuinely IS the safe's omnistar
 * address, so "just pass the safe address" passes an OST test and loses money on
 * the first BTC transfer.
 *
 * THE RULE THAT SHAPES THE REST: with more than one safe, this module REFUSES
 * and hands back a menu. An account's safe list is the safes it PARTICIPATES in,
 * not the ones it owns — `isMain` is `true` on all of them and no field
 * distinguishes ownership. The `<name>_safe` convention is system-derived and
 * unique, so it does identify the account's own safe reliably; auto-selecting on
 * that was proposed and REJECTED (2026-08-19). Its reliability was the argument
 * for auto-selecting, so it is not grounds to revisit: the user sees the
 * destination before the money moves.
 *
 * REFUSALS ARE RETURNED, NOT THROWN. The read-only tool's whole job is
 * enumeration — an agent exploring on the user's behalf should not have to catch
 * an error to see a list. The signing path turns the same value into a refusal.
 * One decision, two surfaces, no chance of them disagreeing.
 */

import type { RecipientSafe } from './assetInfo.js';
// `RecipientSafe.assets` rows are structurally AssetInfo (symbol + address), so
// findAsset consumes them directly — no cast, and no second alias matcher.
import { findAsset, nativeCoinForChain } from './txFeasibility.js';

// ─── shared shapes ──────────────────────────────────────────────────────────

/** A safe as a menu presents it. Full addresses — the prose is truncated, this is not. */
export interface SafeChoice {
  address: string;
  name: string;
  /** Is this `<accountName>_safe`? A label and a sort key, never a selection. */
  nameMatchesAccount: boolean;
  lastActive?: string;
  /** Receive address for the asset in question, when one was named and exists. */
  to?: string;
  /** Symbols this safe has a receive address for. NOT balances. */
  canReceive: string[];
}

export type RefusalKind =
  | 'no-safes'
  | 'needs-choice'
  | 'unknown-name'
  | 'unknown-safe'
  | 'duplicate-name'
  | 'cannot-receive'
  | 'unknown-chain'
  | 'self-send'
  | 'wrong-address-family';

export interface Refusal {
  ok: false;
  kind: RefusalKind;
  /** Written to be relayed to the user verbatim. */
  message: string;
  safes?: SafeChoice[];
  canReceive?: string[];
  /** Near-miss account names, when the refusal is `unknown-name`. Questions, never answers. */
  candidates?: NameCandidate[];
}

/** A local account whose name resembles the one asked for. Never a selection — a question. */
export interface NameCandidate {
  name: string;
  address: string;
  /**
   * `handle` — the part before `@` matches exactly (`sponsorTest2` →
   * `sponsorTest2@organization_xyz`), which is how users normally refer to
   * these. `prefix` — the name merely starts with what was asked, a far weaker
   * signal that is listed but never leant on.
   */
  why: 'handle' | 'prefix';
}


// ─── the naming convention ──────────────────────────────────────────────────

/**
 * Does this safe carry the name the system derives from `accountName`?
 *
 * Case-insensitive: the convention is a system-generated string, but the account
 * name reaching us came from a human typing it at a prompt.
 */
export function nameMatchesAccount(safeName: string, accountName: string): boolean {
  const account = accountName.trim().toLowerCase();
  if (!account) return false;
  return safeName.trim().toLowerCase() === `${account}_safe`;
}

/** Head and tail, so two safes are still distinguishable in a menu line. */
function short(address: string): string {
  return address.length > 24 ? `${address.slice(0, 14)}…${address.slice(-6)}` : address;
}

/**
 * `lastActive` as milliseconds since the epoch.
 *
 * The snapshot reports it as epoch MILLIS INSIDE A STRING — `"1786370716000"`,
 * confirmed live 2026-08-19. Not a date string, which is what a menu wants and
 * what an unwary `slice(0, 10)` turns into a meaningless run of digits. An
 * ISO-shaped value is tolerated too, so a change of producer degrades to a
 * worse sort rather than to nonsense on screen.
 */
function lastActiveMs(v: string | undefined): number | undefined {
  if (!v) return undefined;
  const raw = v.trim();
  if (/^\d+$/.test(raw)) {
    const n = Number(raw);
    // Seconds vs milliseconds: anything below ~1e12 predates 2001 as millis and
    // is far likelier to be a seconds-precision stamp.
    return Number.isFinite(n) ? (n < 1e12 ? n * 1000 : n) : undefined;
  }
  const parsed = Date.parse(raw);
  return Number.isNaN(parsed) ? undefined : parsed;
}

/** `lastActive` as YYYY-MM-DD, for a human reading a menu. */
export function lastActiveDate(v: string | undefined): string | undefined {
  const ms = lastActiveMs(v);
  return ms === undefined ? undefined : new Date(ms).toISOString().slice(0, 10);
}

function toChoice(safe: RecipientSafe, accountName: string, asset?: string): SafeChoice {
  const row = asset ? findAsset(safe.assets, asset) : undefined;
  return {
    address: safe.address,
    name: safe.name,
    nameMatchesAccount: nameMatchesAccount(safe.name, accountName),
    ...(safe.lastActive ? { lastActive: safe.lastActive } : {}),
    ...(row?.address ? { to: row.address } : {}),
    canReceive: safe.assets.map((a) => a.symbol),
  };
}

/**
 * Menu order: the account's own safe first, then most recently active.
 *
 * Ordering is a hint, never an answer — the caller still has to ask. Recency
 * beats nothing at all: a shared safe last touched in March is less likely to be
 * what "send to op20" meant than one touched last week.
 */
function rank(a: SafeChoice, b: SafeChoice): number {
  if (a.nameMatchesAccount !== b.nameMatchesAccount) return a.nameMatchesAccount ? -1 : 1;
  // Numeric, not lexicographic: these are epoch stamps, and string ordering
  // only happens to agree while every value has the same digit count.
  return (lastActiveMs(b.lastActive) ?? 0) - (lastActiveMs(a.lastActive) ?? 0);
}

function menuLine(c: SafeChoice, i: number, asset?: string): string {
  const bits: string[] = [`  ${i + 1}. ${c.name} (${short(c.address)})`];
  if (asset) {
    bits.push(c.to ? `${asset.toUpperCase()} → ${short(c.to)}` : `CANNOT receive ${asset.toUpperCase()}`);
  }
  if (c.nameMatchesAccount) bits.push('[matches the account name]');
  else {
    const when = lastActiveDate(c.lastActive);
    if (when) bits.push(`last active ${when}`);
  }
  return bits.join('  ');
}

// ─── G8 — the name did not resolve ──────────────────────────────────────────

/**
 * Local accounts whose names resemble `asked`.
 *
 * WHY THIS EXISTS: WITHOUT IT THE AGENT GUESSES. An account handle is
 * `name@organization`; users say the bare `name`; the resolver answers a bare
 * name with a flat "could not resolve" and nothing else. Faced with that, plus
 * a keystore holding exactly one plausible account, an agent completes the
 * handle itself and sends. That happened on 2026-08-20 — `sponsorTest2` was
 * silently read as `sponsorTest2@organization_xyz`, real funds moved, and the
 * user learned of the substitution only after the broadcast.
 *
 * So this returns CANDIDATES and the caller REFUSES. A single near-certain
 * candidate is still a question, for the same reason decision 3 forbids
 * auto-selecting a safe on an exact name match: the user, not the agent,
 * decides who gets paid. The convention being reliable was the argument for
 * guessing, so reliability is not grounds to start.
 *
 * LOCAL ACCOUNTS ONLY — a real limit, which the refusal states rather than
 * hides. A recipient this machine holds no key for cannot be suggested here at
 * all, so a short list is not evidence that the name is wrong.
 */
export function suggestAccountNames(
  asked: string,
  known: ReadonlyArray<{ name?: string | undefined; address: string }>,
  limit = 8,
): NameCandidate[] {
  const want = asked.trim().toLowerCase();
  if (!want) return [];

  const out: NameCandidate[] = [];
  for (const a of known) {
    const name = (a.name ?? '').trim();
    if (!name) continue;
    const lower = name.toLowerCase();
    // The handle's local part: `sponsorTest2@organization_xyz` → `sponsorTest2`.
    const localPart = lower.split('@')[0] ?? '';
    if (localPart === want) out.push({ name, address: a.address, why: 'handle' });
    else if (lower.startsWith(want)) out.push({ name, address: a.address, why: 'prefix' });
  }

  // Handle matches first — an exact local part is a far stronger signal than a
  // shared prefix. Then by name, so the same inputs always render the same list.
  out.sort((a, b) => (a.why !== b.why ? (a.why === 'handle' ? -1 : 1) : a.name.localeCompare(b.name)));
  return out.slice(0, limit);
}

/**
 * The refusal for a name that did not resolve.
 *
 * Worded so that an agent reading it cannot mistake a candidate for an answer.
 * The imperative comes FIRST, before the list: an instruction printed under a
 * numbered menu is read after the reader has already picked a number.
 */
export function unknownNameRefusal(input: {
  asked: string;
  candidates: NameCandidate[];
  /** The resolver's own error — kept so a transport failure is not read as "no such account". */
  underlying?: string | undefined;
}): Refusal {
  const { asked, candidates, underlying } = input;

  const head = `"${asked}" is not a registered account name, so there is nowhere to send.`;
  const tail =
    `If "${asked}" is a SAFE name rather than an account name, name its OWNER instead ` +
    `(the safe of account X is X_safe).` +
    (underlying ? `\nUnderlying error: ${underlying}` : '');

  if (candidates.length === 0) {
    return { ok: false, kind: 'unknown-name', message: `${head} ${tail}`, candidates: [] };
  }

  const lines = candidates.map(
    (c, i) =>
      `  ${i + 1}. ${c.name} (${short(c.address)})` +
      (c.why === 'handle' ? '  [identical before the "@" — the likely match]' : ''),
  );

  return {
    ok: false,
    kind: 'unknown-name',
    message:
      `${head}\n` +
      `DO NOT PICK ONE OF THESE FOR THE USER. ASK which they meant, then pass that name in full.\n` +
      `Account handles are "name@organization", and the bare "name" does not resolve — so a close ` +
      `match below is a plausible guess, never a confirmed identity. Accounts on THIS machine whose ` +
      `names resemble "${asked}":\n` +
      `${lines.join('\n')}\n` +
      `Only local accounts can appear here, so this list being short or unconvincing does not mean ` +
      `"${asked}" does not exist elsewhere.\n${tail}`,
    candidates,
  };
}

// ─── G4 / the choice ────────────────────────────────────────────────────────

export type SafePick = { ok: true; safe: RecipientSafe; choice: SafeChoice } | Refusal;

/**
 * Which side of the transfer is being chosen.
 *
 * The mechanics are identical — an account's safe list, the same ranking, the
 * same refusal — but the WORDING cannot be: "which safe to send to" and "which
 * safe the money leaves from" are opposite questions, and they are answered
 * through different parameters. Getting that wrong would have the agent ask the
 * user about a recipient when the ambiguity is in their own wallet.
 */
export type SafeRole = 'recipient' | 'source';

const ROLE = {
  recipient: {
    param: 'toSafe',
    ask: 'ASK THE USER which safe, then pass it as `toSafe` — do not pick one for them.',
    lead: (who: string, n: number) => `${who} is in ${n} safes and the call did not say which to send to.`,
    note: 'Call wallet_resolve_recipient for the same list as structured data.',
  },
  source: {
    param: 'destination',
    ask: 'ASK THE USER which safe the funds should leave from, then pass it as `destination` — do not pick one for them.',
    lead: (who: string, n: number) => `${who} holds ${n} safes and the call did not say which to send FROM.`,
    // NOT wallet_resolve_recipient: these are the USER'S OWN safes, and pointing
    // at the recipient tool sends the agent to look up the wrong party.
    note: 'Call wallet_accounts for the same list as structured data.',
  },
} as const;

/**
 * Which of the recipient's safes to send to.
 *
 * `requested` is the caller's `toSafe` — an address or a safe name. Without it:
 * one safe is used (asking about a one-item list is noise, and the answer could
 * only ever be "yes"), and two or more REFUSE with the menu.
 */
export function pickRecipientSafe(input: {
  safes: RecipientSafe[];
  /** The recipient's account name, for the convention and the wording. */
  accountName: string;
  requested?: string | undefined;
  /** Annotates the menu with each safe's receive address for this asset. */
  asset?: string | undefined;
  /** Whose side of the transfer this is. Wording only — see SafeRole. */
  role?: SafeRole | undefined;
}): SafePick {
  const { safes, accountName, requested, asset } = input;
  const words = ROLE[input.role ?? 'recipient'];
  const who = accountName.trim() || 'that account';
  const choices = safes.map((s) => toChoice(s, accountName, asset)).sort(rank);
  const byAddress = new Map(safes.map((s) => [s.address.toLowerCase(), s]));

  // G4. A name that resolved is an account that EXISTS; saying "unknown account"
  // here would send the user hunting for a typo in a name that is correct.
  if (safes.length === 0) {
    return {
      ok: false,
      kind: 'no-safes',
      message:
        input.role === 'source'
          ? `${who} has no safe, so there is nothing to send FROM. A safe created in the last few ` +
            `minutes is not queryable yet — a fresh create-safe takes roughly 2-8 minutes to appear. ` +
            `If it was just created, wait and retry; otherwise create one with wallet_tx_create_safe.`
          : `${who} exists on-chain but has no safe, so there is nowhere to send to. ` +
            `A safe created in the last few minutes is not queryable yet — a fresh create-safe ` +
            `takes roughly 2-8 minutes to appear. If it was just created, wait and retry; ` +
            `otherwise ${who} needs to create one before they can be paid.`,
    };
  }

  const asked = (requested ?? '').trim();
  if (asked) {
    const hit = byAddress.get(asked.toLowerCase());
    if (hit) return { ok: true, safe: hit, choice: toChoice(hit, accountName, asset) };

    const named = safes.filter((s) => s.name.trim().toLowerCase() === asked.toLowerCase());
    // Two safes answering to one name means the naming invariant is broken. A
    // menu of two identical names cannot be chosen from — say what is wrong.
    if (named.length > 1) {
      return {
        ok: false,
        kind: 'duplicate-name',
        message:
          `${named.length} of ${who}'s safes are named "${asked}". Safe names are derived from the ` +
          `account name and are meant to be unique, so this should not happen. Do not guess — ` +
          `pass the safe ADDRESS instead, and have the duplicate investigated.`,
        safes: choices.filter((c) => c.name.trim().toLowerCase() === asked.toLowerCase()),
      };
    }
    if (named.length === 1) {
      return { ok: true, safe: named[0]!, choice: toChoice(named[0]!, accountName, asset) };
    }

    return {
      ok: false,
      kind: 'unknown-safe',
      message:
        `"${asked}" is not one of ${who}'s safes. Pass one of these (address or name), ` +
        `or drop ${words.param} to be shown the choice:\n` +
        `${choices.map((c, i) => menuLine(c, i, asset)).join('\n')}\n${words.note}`,
      safes: choices,
    };
  }

  // Nothing to choose from: every safe is unable to receive this asset. Distinct
  // from "pick one", because no answer to that question would help.
  if (asset && choices.every((c) => !c.to)) {
    return {
      ok: false,
      kind: 'cannot-receive',
      message:
        `None of ${who}'s ${choices.length} safe(s) can receive ${asset.toUpperCase()}. ` +
        `A safe receives an asset only if it carries a receive address for it. ` +
        `Between them they can receive: ${[...new Set(choices.flatMap((c) => c.canReceive))].join(', ') || '(nothing)'}.`,
      safes: choices,
      canReceive: [...new Set(choices.flatMap((c) => c.canReceive))],
    };
  }

  // Decision 1: one safe is used, and the ECHO carries the warning. Refusing
  // here would make an account whose only safe is a shared one unsendable-to.
  if (safes.length === 1) {
    const only = safes[0]!;
    return { ok: true, safe: only, choice: toChoice(only, accountName, asset) };
  }

  // Decision 3: 2+ safes always ask, even when exactly one matches the naming
  // convention. Same refusal shape as the no-default-account error.
  const matches = choices.filter((c) => c.nameMatchesAccount);
  const tail = !accountName.trim()
    ? // Identified by ADDRESS: the account's name was never learned, so the
      // convention cannot be applied. Saying "none is named after them" here
      // would be a claim about data we do not have — and it read as exactly
      // that against a live account whose own safe was sitting at #1.
      `\nThe naming convention could NOT be checked: this call identified the recipient by ADDRESS, ` +
      `so their account name is unknown. Pass the account NAME instead and the menu will mark which ` +
      `safe carries it.`
    : matches.length === 1
      ? `\nOnly #${choices.indexOf(matches[0]!) + 1} is named after ${who}; the others are safes ${who} is a member of.`
      : matches.length > 1
        ? `\nWARNING: ${matches.length} safes are named ${who}_safe. Names are system-derived and unique, ` +
          `so this should not happen — have it investigated before sending.`
        : // Not "none of these is theirs": a safe predating the naming
          // convention can be their own under an unrelated name (rare, legacy).
          `\nNone of these is named ${who}_safe, so none can be confirmed as ${who}'s own. Ask which they mean.`;

  return {
    ok: false,
    kind: 'needs-choice',
    message:
      `${words.lead(who, safes.length)}\n${words.ask}\n` +
      `${choices.map((c, i) => menuLine(c, i, asset)).join('\n')}${tail}\n${words.note}`,
    safes: choices,
  };
}

// ─── G2 / G5 / G6 — the receive address ─────────────────────────────────────

export type AddressPick = { ok: true; to: string; symbolUsed: string } | Refusal;

/**
 * The chain-native address this safe receives `asset` at.
 *
 * G5 (aliases) is `findAsset`'s job, deliberately: the feasibility ladder
 * resolves MATIC→POL through it, and a second matcher that resolved it
 * differently would address the transfer to a different chain than the one the
 * balance was checked on.
 *
 * G6 (ERC20): a token has no receive row of its own — the safe carries chain
 * COINS. A USDC transfer on Polygon is addressed to the safe's POL address, so
 * `chain` decides the lookup and the token symbol is not used at all.
 */
export function pickReceiveAddress(input: {
  safe: RecipientSafe;
  asset: string;
  chain?: string | undefined;
  tokenAddress?: string | undefined;
}): AddressPick {
  const { safe, asset, chain, tokenAddress } = input;
  const isToken = !!(tokenAddress ?? '').trim();

  let want = asset;
  if (isToken) {
    const coin = nativeCoinForChain(chain ?? '');
    if (!coin) {
      return {
        ok: false,
        kind: 'unknown-chain',
        message:
          `${asset.toUpperCase()} was given a token address but ${chain ? `chain "${chain}"` : 'no chain'}, ` +
          `so there is no way to tell which coin's receive address it lands at. ` +
          `Pass chain as one of: ethereum, polygon, base.`,
      };
    }
    want = coin;
  }

  const row = findAsset(safe.assets, want);
  if (!row?.address) {
    // G2. A receive row means an address exists; its absence is not a zero
    // balance and must not be worded like one.
    const forToken = isToken ? ` (an ERC20 on ${chain} is received at the safe's ${want} address)` : '';
    return {
      ok: false,
      kind: 'cannot-receive',
      message:
        `${safe.name || safe.address} cannot receive ${want.toUpperCase()}${forToken}. ` +
        `It has receive addresses for: ${safe.assets.map((a) => a.symbol).join(', ') || '(nothing)'}.`,
      canReceive: safe.assets.map((a) => a.symbol),
    };
  }

  return { ok: true, to: row.address, symbolUsed: row.symbol };
}

// ─── G1 — address family ────────────────────────────────────────────────────

export type AddressFamily = 'omnistar' | 'bitcoin' | 'evm' | 'cardano' | 'dogecoin' | 'ripple';

const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/;
const BECH32 = /^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/;

/**
 * Which family an address belongs to, or `undefined` when it cannot be told.
 *
 * "Cannot be told" is a real answer here and is returned freely — see
 * `checkAddressFamily` for why guessing would be worse than not knowing.
 *
 * SOLANA IS DELIBERATELY UNCLASSIFIED. A Solana address is bare base58 with no
 * prefix, so any rule broad enough to catch it also catches Dogecoin and Ripple
 * addresses. The length windows below exist for the same reason: a 43-character
 * base58 string starting `D` is a Solana key, not a Dogecoin address.
 */
export function addressFamily(to: string): AddressFamily | undefined {
  const a = to.trim();
  if (!a) return undefined;

  if (/^omnistar1[0-9a-z]{6,}$/.test(a)) return 'omnistar';
  if (/^0x[0-9a-fA-F]{40}$/.test(a)) return 'evm';
  if (/^bc1[qp][0-9a-z]{20,}$/.test(a) && BECH32.test(a.slice(4))) return 'bitcoin';
  if (/^addr1[0-9a-z]{20,}$/.test(a) && BECH32.test(a.slice(5))) return 'cardano';
  if (/^[13]/.test(a) && BASE58.test(a) && a.length >= 26 && a.length <= 35) return 'bitcoin';
  if (/^D/.test(a) && BASE58.test(a) && a.length >= 30 && a.length <= 36) return 'dogecoin';
  if (/^r/.test(a) && BASE58.test(a) && a.length >= 25 && a.length <= 35) return 'ripple';
  return undefined;
}

/**
 * Which family an asset is paid into, or `undefined` when we do not know.
 *
 * Unknown is the correct answer for anything not listed — a new chain must not
 * be refused by a table that has not heard of it yet. SOL is absent on purpose;
 * see `addressFamily`.
 */
export function assetFamily(asset: string, opts: { chain?: string | undefined; tokenAddress?: string | undefined } = {}): AddressFamily | undefined {
  // A token is paid into its CHAIN's address, whatever the token is called.
  if ((opts.tokenAddress ?? '').trim()) {
    return nativeCoinForChain(opts.chain ?? '') ? 'evm' : undefined;
  }
  switch (asset.trim().toUpperCase()) {
    case 'OST':
      return 'omnistar';
    case 'BTC':
      return 'bitcoin';
    case 'ETH':
    case 'BASE':
    case 'AVAX':
    case 'POL':
    case 'MATIC':
      return 'evm';
    case 'ADA':
      return 'cardano';
    case 'DOGE':
      return 'dogecoin';
    case 'XRP':
      return 'ripple';
    default:
      return undefined;
  }
}

/**
 * G1. Refuse a `to` that provably belongs to a different chain than the asset.
 *
 * OPEN-WORLD, and that is the whole design: a refusal requires BOTH sides to be
 * known and to disagree. An unrecognised asset, or an address whose family
 * cannot be told, passes through untouched. This guard is being added to `to`, a
 * parameter that already works — a closed-world rule would retroactively refuse
 * sends that succeed today, for assets missing from a table that lives in this
 * repo rather than on the chain.
 *
 * NO OVERRIDE, which open-world is what makes safe: a refusal means two KNOWN
 * families disagree, and no legitimate transfer sends BTC to an `omnistar1…`
 * address. An override would exist to correct our own misclassification, and
 * that is precisely what cannot trigger this.
 *
 * IT IS NOT A WRONG-NETWORK GUARANTEE. Ethereum, Base, Polygon and Avalanche
 * share one address format, so sending ETH to a Polygon address is invisible
 * here. Do not describe it as more than a shape check.
 */
export function checkAddressFamily(
  asset: string,
  to: string,
  opts: { chain?: string | undefined; tokenAddress?: string | undefined } = {},
): { ok: true } | Refusal {
  const want = assetFamily(asset, opts);
  const got = addressFamily(to);
  if (!want || !got || want === got) return { ok: true };

  const extra =
    got === 'omnistar'
      ? ` That is an omnistar address — a SAFE's own address. Only OST is received there; ` +
        `every other asset has its own chain-native receive address on that safe.`
      : '';
  return {
    ok: false,
    kind: 'wrong-address-family',
    message:
      `Refusing to send ${asset.toUpperCase()} to ${to}: that address is ${got}, and ` +
      `${asset.toUpperCase()} is received at a ${want} address.${extra} ` +
      `A transfer to the wrong chain cannot be recovered, so this cannot be forced.`,
  };
}

// ─── G3 — self-send ─────────────────────────────────────────────────────────

/**
 * Is `to` an address the SOURCE safe itself owns?
 *
 * Compared case-insensitively. EVM addresses carry an optional EIP-55 checksum
 * expressed as capitalisation, so the same address legitimately appears in two
 * casings and a case-sensitive check would miss it. The cost of the trade is
 * theoretical — two base58 addresses differing only in case — and its worst
 * outcome is a refusal, while the miss it prevents is a real (if merely
 * wasteful) self-transfer.
 */
export function checkSelfSend(input: {
  to: string;
  /** The source safe, read the same way the recipient's was. */
  sourceSafe?: RecipientSafe | undefined;
  asset: string;
}): { ok: true } | Refusal {
  const { to, sourceSafe, asset } = input;
  if (!sourceSafe) return { ok: true };

  const mine = new Set(
    [sourceSafe.address, ...sourceSafe.assets.map((a) => a.address)]
      .filter(Boolean)
      .map((a) => a.toLowerCase()),
  );
  if (!mine.has(to.trim().toLowerCase())) return { ok: true };

  return {
    ok: false,
    kind: 'self-send',
    message:
      `Refusing to send ${asset.toUpperCase()} from ${sourceSafe.name || sourceSafe.address} to ` +
      `${to} — that address belongs to the source safe itself. The transfer would pay a network ` +
      `fee to move the asset nowhere. Check the recipient: this is what happens when a safe ` +
      `address is passed as the destination by mistake.`,
  };
}
