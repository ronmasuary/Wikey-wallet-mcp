// Pre-flight feasibility for asset transfers (docs/TX-FEE-FEASIBILITY-PLAN.md).
//
// WHY THIS IS NOT A FEE ESTIMATOR. The fee that actually settles a transfer is
// computed by the signing engine, downstream of everything the agent can see.
// The one number reachable from here — `estimated-fee`'s `qty`, which wallet-cli
// stores as `fee_rate` — is masked and normalized, and per chain it is not even
// the same KIND of quantity (sat/vByte for BTC, a 0|1|2 priority index for the
// ETH family, real drops for XRP). Subtracting it would be arithmetic on three
// different units. Recomputing the real fee from the network instead would put a
// SECOND fee implementation in the MCP, producing a number the signer never sees
// and can disagree with.
//
// So this module answers a different, answerable question: will this transfer
// fail? Most real failures are structural and provable with no fee value at all
// (R1-R5 below). Exactly one band is a judgement call (R6), and it is reported as
// a probability rather than dressed up as a number.
//
// Pure and transport-agnostic: it takes already-parsed assets and returns a
// verdict. No spawning, no I/O, no session.

/**
 * `will-fail` — structural, proven from balances alone. Not overridable.
 * `at-risk`   — the heuristic headroom band (R6). Overridable with acknowledgeRisk.
 * `likely-pass` — nothing known to be wrong. A PROBABILITY, not a guarantee:
 *                 a fee spike between this check and the broadcast can still
 *                 fail it.
 */
export type Verdict = 'will-fail' | 'at-risk' | 'likely-pass';

export type Rule = 'R1-not-held' | 'R2-over-balance' | 'R3-full-drain' | 'R4-no-gas' | 'R5-reserve' | 'R6-headroom' | 'R7-ok';

export interface Layer2Data {
  contractAddress?: string;
  chain?: string;
  smallCoin?: string;
  transactionType?: string;
}

/** One asset row as `query assets` reports it (wallet-cli AssetInfo). */
export interface AssetInfo {
  symbol: string;
  name?: string;
  address?: string;
  /** Balance in DISPLAY units, as a decimal string. */
  value?: string;
  /** USD price per display unit, as a decimal string. */
  priceValue?: string;
  /** Divisor from display units to smallest units, as a string. */
  smallCoin?: string;
  layer2data?: Layer2Data;
}

export interface SafeAssets {
  safeAddress: string;
  assets: AssetInfo[];
  /**
   * Every symbol the safe holds, INCLUDING any not priced in `assets`.
   *
   * Exists because a narrowed read (core/assetInfo.ts) prices only the asset
   * being sent, so `assets` is no longer the safe's inventory. R1 reports what
   * the safe holds when the requested asset is missing; without this it would
   * read "(nothing)" off a one-element list and tell the user a full safe is
   * empty. Optional: absent on the wallet-cli envelope, where `assets` IS the
   * full inventory.
   */
  heldSymbols?: string[];
}

export interface FeasibilityInput {
  /** Every safe of the account, as returned by `query assets`. */
  safes: SafeAssets[];
  /** The safe the transfer leaves from (`destination` on create-transaction). */
  safe: string;
  /** Asset symbol being sent. */
  asset: string;
  /** Requested amount in SMALLEST units. */
  amount: bigint;
}

export interface Feasibility {
  verdict: Verdict;
  rule: Rule;
  reason: string;
  asset: string;
  safe: string;
  /** All amounts are SMALLEST units, as strings — wei exceeds Number precision. */
  balance: string | null;
  requested: string;
  remaining: string | null;
  /**
   * The largest amount this check would not flag. Deliberately conservative and
   * NOT a real fee: a transfer that lands slightly short beats one that fails.
   * null when no amount would pass (e.g. the asset is not held).
   */
  maxSuggested: string | null;
  /** For tokens: the native coin that actually pays the fee, and its balance. */
  gasAsset?: { symbol: string; balance: string | null };
  /** Always present. States the limits of the verdict. */
  note: string;
}

// ─── Chain table ────────────────────────────────────────────────────────────
//
// Every chain the proxy supports (actions/transactions/index.ts). Values are in
// DISPLAY units, because that is the unit the reasoning is in — the conversion to
// smallest units happens once, against the asset's own smallCoin.

interface ChainRule {
  /**
   * Balance that can NEVER be spent: XRP's account reserve, Solana's
   * rent-exempt minimum, Cardano's min-UTXO. Leaving less than this is a
   * structural failure (R5), not a fee question.
   *
   * XRP's reserve is network-voted (it has been 20, then 10, now 1) — if the
   * chain votes it up, this constant is what needs changing.
   */
  reserve: number;
  /**
   * Absolute floor for the R6 headroom band, used when the derived floor
   * is smaller (or when no price is available).
   */
  minHeadroom: number;
  /**
   * Worst-case fee for a simple transfer, in DISPLAY units — set ONLY for chains
   * whose fee is DETERMINISTIC rather than priced by block-space demand.
   *
   * When present it replaces the USD band entirely (see headroomFloor). The USD
   * band exists because a demand-priced fee genuinely costs dollars and varies;
   * converting $2 through the coin's price is a reasonable proxy there. On a
   * chain where the fee is a fixed arithmetic product, that proxy is not
   * conservative, it is simply wrong: it invents a number thousands of times the
   * real cost and, for a cheap coin, exceeds the entire balance.
   */
  maxFee?: number;
  /** Alternative symbols the same coin appears under. */
  aliases?: string[];
}

const CHAINS: Record<string, ChainRule> = {
  BTC: { reserve: 0, minHeadroom: 0.00002 },
  DOGE: { reserve: 0, minHeadroom: 1 },
  ETH: { reserve: 0, minHeadroom: 0.0002 },
  POL: { reserve: 0, minHeadroom: 0.05, aliases: ['MATIC'] },
  AVAX: { reserve: 0, minHeadroom: 0.005 },
  SOL: { reserve: 0.001, minHeadroom: 0.00001 },
  ADA: { reserve: 1, minHeadroom: 0.2 },
  XRP: { reserve: 1, minHeadroom: 0.0001 },
  // Omnistar's fee is gas LIMIT × gas PRICE, both fixed: the three priority
  // tiers select the limit (200k / 300k / 400k) and share one gas price of 11
  // (wallet-cli config `defaults.gas` / `defaults.gasPrice`; see feeChoice.ts).
  // Worst case is therefore 400_000 × 11 = 4_400_000 nost = 0.0044 OST, which
  // matches fees observed on real transfers. If the chain's gas price changes,
  // this constant is what needs changing.
  OST: { reserve: 0, minHeadroom: 0.001, maxFee: 0.0044 },
};

/**
 * Fees on demand-priced chains track block-space demand, not your balance — so
 * the floor is USD-shaped. Applies only to chains with no `maxFee`.
 */
const USD_HEADROOM = 2;

/**
 * Multiple of a KNOWN worst-case fee to keep as headroom. Three covers a gas
 * price nudged upward or a heavier-than-expected message while staying in the
 * same order of magnitude as the real cost — which is the entire point of
 * treating a deterministic fee differently from a speculative one.
 */
const FEE_SAFETY = 3;

/**
 * layer2data.chain → the native coin that pays that chain's gas. Base is the one
 * that surprises people: its gas is ETH, not a token of its own.
 */
const TOKEN_GAS: Record<string, string> = {
  ETHEREUM: 'ETH', ETH: 'ETH', ERC20: 'ETH',
  POLYGON: 'POL', MATIC: 'POL', POL: 'POL', PERC20: 'POL',
  BASE: 'ETH', BERC20: 'ETH',
  AVALANCHE: 'AVAX', AVAX: 'AVAX',
};

function chainRule(symbol: string): ChainRule {
  const s = symbol.toUpperCase();
  if (CHAINS[s]) return CHAINS[s];
  for (const [, rule] of Object.entries(CHAINS)) {
    if (rule.aliases?.includes(s)) return rule;
  }
  return { reserve: 0, minHeadroom: 0 };
}

// ─── Decimal → smallest units ───────────────────────────────────────────────

/**
 * `value` (display, decimal string) × `smallCoin` → smallest units.
 *
 * String math, not floating point: `0.00123 * 1e8` is 123000.00000000001 in
 * IEEE-754, and R3 turns on an EXACT balance comparison — an off-by-one there
 * would let the full-drain case through, which is the whole bug this module
 * exists to catch.
 */
export function toSmallest(value: string | undefined, smallCoin: string | undefined): bigint | null {
  if (value === undefined || value === null || String(value).trim() === '') return null;
  const raw = String(value).trim();
  const div = String(smallCoin ?? '1').trim();

  // Scientific notation ("1e-8") has no clean string form — fall back to float.
  if (/[eE]/.test(raw) || /[eE]/.test(div)) {
    const n = Number(raw) * Number(div || 1);
    return Number.isFinite(n) ? BigInt(Math.round(n)) : null;
  }
  if (!/^-?\d*(\.\d+)?$/.test(raw) || raw === '' || raw === '.') return null;

  const neg = raw.startsWith('-');
  const [intPart = '0', fracPart = ''] = (neg ? raw.slice(1) : raw).split('.');

  // The divisor is a power of ten for every asset we know of, which makes this a
  // decimal-point shift rather than a multiplication.
  if (/^10*$/.test(div)) {
    const decimals = div.length - 1;
    const frac = fracPart.padEnd(decimals, '0').slice(0, decimals);
    const out = BigInt((intPart || '0') + frac);
    return neg ? -out : out;
  }

  // Anything else: scale to an integer first, then divide back down exactly.
  const scale = BigInt(10) ** BigInt(fracPart.length);
  const scaled = BigInt((intPart || '0') + fracPart);
  const d = BigInt(div || '1');
  const out = (scaled * d) / scale;
  return neg ? -out : out;
}

function displayToSmallest(display: number, smallCoin: string | undefined): bigint {
  // A JS float is fine here: these are our own table constants, not user money.
  const v = toSmallest(display.toFixed(18).replace(/0+$/, '').replace(/\.$/, '') || '0', smallCoin);
  return v ?? BigInt(0);
}

// ─── Lookups ────────────────────────────────────────────────────────────────

function findSafe(safes: SafeAssets[], safe: string): SafeAssets | undefined {
  const want = safe.trim().toLowerCase();
  return safes.find((s) => (s.safeAddress ?? '').trim().toLowerCase() === want);
}

/**
 * Symbol → the row that represents it, alias-aware in both directions (asked for
 * MATIC, safe reports POL, and vice versa). Exported because the narrowed asset
 * fetch in assetInfo.ts must pick the SAME row this ladder will later look up —
 * if the two disagreed, a narrowed read could omit the very asset being sent and
 * the ladder would call it not-held.
 */
export function findAsset(assets: AssetInfo[], symbol: string): AssetInfo | undefined {
  const want = symbol.trim().toUpperCase();
  const direct = assets.find((a) => (a.symbol ?? '').trim().toUpperCase() === want);
  if (direct) return direct;
  const rule = CHAINS[want];
  if (rule?.aliases) {
    return assets.find((a) => rule.aliases!.includes((a.symbol ?? '').trim().toUpperCase()));
  }
  // The other direction: asked for MATIC, the safe reports POL.
  for (const [canon, r] of Object.entries(CHAINS)) {
    if (r.aliases?.includes(want)) {
      return assets.find((a) => (a.symbol ?? '').trim().toUpperCase() === canon);
    }
  }
  return undefined;
}

/**
 * Is this a token whose fee is paid in a DIFFERENT coin? Exported so a narrowed
 * fetch can tell whether it still owes a second request for the gas coin: R4
 * reads the gas balance, so narrowing to the sent asset ALONE would silently
 * drop the no-gas check.
 */
export function gasSymbolFor(asset: AssetInfo): string | null {
  const l2 = asset.layer2data;
  if (!l2 || !l2.contractAddress) return null;
  const chain = (l2.chain ?? '').trim().toUpperCase();
  return TOKEN_GAS[chain] ?? null;
}

/**
 * The R6 floor, in smallest units.
 *
 * A flat percentage is wrong at both ends — 0.5% of a dust balance is nothing,
 * 0.5% of 10 BTC is absurd — which is why this is denominated the way fees
 * actually are. But "the way fees actually are" differs by chain:
 *
 * - DETERMINISTIC fee (`maxFee` set): the cost is known arithmetic, so the floor
 *   is that cost times a safety multiple. No price lookup, no guessing.
 * - DEMAND-PRICED fee: the cost really does move with block space and really is
 *   dollar-shaped, so $2 converted through the coin's own price is a fair proxy.
 *
 * Using the USD band on a deterministic chain was a real bug: OST's fee is
 * 0.0044 OST, but at $0.20/OST the band demanded 10 OST of headroom — about
 * 2000x the fee, and more than most test safes hold, so EVERY OST transfer came
 * back 'at-risk' with maxSuggested 0.
 */
function headroomFloor(asset: AssetInfo): bigint {
  const rule = chainRule(asset.symbol);
  if (rule.maxFee !== undefined) {
    return displayToSmallest(Math.max(rule.minHeadroom, rule.maxFee * FEE_SAFETY), asset.smallCoin);
  }
  const price = Number(asset.priceValue ?? '');
  const byUsd = Number.isFinite(price) && price > 0 ? USD_HEADROOM / price : 0;
  return displayToSmallest(Math.max(rule.minHeadroom, byUsd), asset.smallCoin);
}

const NOTE_STRUCTURAL = 'Proven from balances alone — no fee estimate involved.';
const NOTE_HEURISTIC =
  'Heuristic: the exact fee is computed by the signing engine and is not visible here. ' +
  'Lower the amount, or pass acknowledgeRisk to send it anyway.';
const NOTE_PASS =
  'No known problem. This is a probability, not a guarantee — a fee spike between ' +
  'this check and the broadcast can still fail the transfer.';

// ─── The rule ladder ────────────────────────────────────────────────────────

export function checkFeasibility(input: FeasibilityInput): Feasibility {
  const { safe, amount } = input;
  const symbol = input.asset.trim().toUpperCase();
  const base = { asset: symbol, safe, requested: amount.toString() };

  const safeRow = findSafe(input.safes, safe);
  const asset = safeRow ? findAsset(safeRow.assets ?? [], symbol) : undefined;

  // ── R1: the safe does not hold this asset at all ──
  if (!safeRow || !asset) {
    // Prefer the full inventory: under a narrowed read `assets` is only what was
    // asked for, so reading the held list off it would report "(nothing)".
    const held = (safeRow?.heldSymbols ?? (safeRow?.assets ?? []).map((a) => a.symbol)).filter(Boolean);
    return {
      ...base,
      verdict: 'will-fail',
      rule: 'R1-not-held',
      reason: safeRow
        ? `Safe ${safe} holds no ${symbol}. It holds: ${held.length ? held.join(', ') : '(nothing)'}.`
        : `No safe ${safe} in this account's asset list. Call wallet_assets for the safes it owns.`,
      balance: null,
      remaining: null,
      maxSuggested: null,
      note: NOTE_STRUCTURAL,
    };
  }

  const balance = toSmallest(asset.value, asset.smallCoin) ?? BigInt(0);
  const gasSymbol = gasSymbolFor(asset);
  const rule = chainRule(symbol);
  const reserve = displayToSmallest(rule.reserve, asset.smallCoin);

  // ── R2: more than the balance. Certain, and unoverridable. ──
  if (amount > balance) {
    return {
      ...base,
      verdict: 'will-fail',
      rule: 'R2-over-balance',
      reason: `Requested ${amount} ${symbol} (smallest units) but the safe holds ${balance}.`,
      balance: balance.toString(),
      remaining: null,
      maxSuggested: maxFor(balance, reserve, asset, gasSymbol).toString(),
      note: NOTE_STRUCTURAL,
    };
  }

  // ── Tokens: the fee is NOT paid in the asset being sent ──
  //
  // So the full token balance IS legitimately sendable, and R3 must not fire on
  // it. What can fail instead is gas: a safe with plenty of USDC and no ETH fails
  // every time, and the failure LOOKS like an amount problem — so it gets "fixed"
  // by lowering the amount, forever.
  if (gasSymbol) {
    const gas = findAsset(safeRow.assets ?? [], gasSymbol);
    const gasBalance = gas ? toSmallest(gas.value, gas.smallCoin) ?? BigInt(0) : null;

    if (gasBalance === null || gasBalance === BigInt(0)) {
      return {
        ...base,
        verdict: 'will-fail',
        rule: 'R4-no-gas',
        reason:
          `${symbol} is a token on ${(asset.layer2data?.chain ?? '').toUpperCase() || 'its chain'}: its fee is paid in ` +
          `${gasSymbol}, not in ${symbol}. Safe ${safe} holds no ${gasSymbol}, so this transfer cannot settle ` +
          `at any amount. Fund the safe with ${gasSymbol} first.`,
        balance: balance.toString(),
        remaining: (balance - amount).toString(),
        maxSuggested: null,
        gasAsset: { symbol: gasSymbol, balance: gasBalance === null ? null : gasBalance.toString() },
        note: NOTE_STRUCTURAL,
      };
    }

    // Gas exists but may not be enough — the heuristic band, applied to the GAS
    // asset rather than to the token.
    if (gas && gasBalance < headroomFloor(gas)) {
      return {
        ...base,
        verdict: 'at-risk',
        rule: 'R6-headroom',
        reason:
          `${symbol} is a token whose fee is paid in ${gasSymbol}, and the safe's ${gasSymbol} balance ` +
          `(${gasBalance}) is low enough that the fee may not cover. The ${symbol} amount itself is fine.`,
        balance: balance.toString(),
        remaining: (balance - amount).toString(),
        maxSuggested: balance.toString(),
        gasAsset: { symbol: gasSymbol, balance: gasBalance.toString() },
        note: NOTE_HEURISTIC,
      };
    }

    return {
      ...base,
      verdict: 'likely-pass',
      rule: 'R7-ok',
      reason: `Safe holds ${balance} ${symbol}; fee is paid separately in ${gasSymbol} (balance ${gasBalance}).`,
      balance: balance.toString(),
      remaining: (balance - amount).toString(),
      maxSuggested: balance.toString(),
      gasAsset: { symbol: gasSymbol, balance: gasBalance.toString() },
      note: NOTE_PASS,
    };
  }

  // ── Native assets: the fee comes out of THIS balance ──
  const remaining = balance - amount;
  const maxSuggested = maxFor(balance, reserve, asset, gasSymbol);

  // ── R3: the reported bug. Sending exactly the balance leaves the fee nowhere
  // to come from. Certain, and needs no fee value to know. ──
  if (remaining === BigInt(0)) {
    return {
      ...base,
      verdict: 'will-fail',
      rule: 'R3-full-drain',
      reason:
        `This sends the ENTIRE ${symbol} balance (${balance}). The network fee is deducted from the same ` +
        `${symbol} balance, so nothing is left to pay it and the transfer cannot settle. ` +
        `Send at most ${maxSuggested} instead.`,
      balance: balance.toString(),
      remaining: '0',
      maxSuggested: maxSuggested.toString(),
      note: NOTE_STRUCTURAL,
    };
  }

  // ── R5: chains where part of the balance can never be spent ──
  if (reserve > BigInt(0) && remaining < reserve) {
    return {
      ...base,
      verdict: 'will-fail',
      rule: 'R5-reserve',
      reason:
        `${symbol} keeps a permanent on-chain reserve of ${reserve} (smallest units) that can never be ` +
        `spent. This would leave ${remaining}, below that reserve. Send at most ${maxSuggested}.`,
      balance: balance.toString(),
      remaining: remaining.toString(),
      maxSuggested: maxSuggested.toString(),
      note: NOTE_STRUCTURAL,
    };
  }

  // ── R6: the one judgement call ──
  const floor = headroomFloor(asset);
  if (remaining < reserve + floor) {
    return {
      ...base,
      verdict: 'at-risk',
      rule: 'R6-headroom',
      reason:
        `This leaves ${remaining} ${symbol} (smallest units) to cover a fee taken from the same balance, ` +
        `below the ${reserve + floor} floor for ${symbol}, so the transfer may fail. ` +
        `Send at most ${maxSuggested} to stay clear of it.`,
      balance: balance.toString(),
      remaining: remaining.toString(),
      maxSuggested: maxSuggested.toString(),
      note: NOTE_HEURISTIC,
    };
  }

  // ── R7 ──
  return {
    ...base,
    verdict: 'likely-pass',
    rule: 'R7-ok',
    reason: `Leaves ${remaining} ${symbol} (smallest units) after the transfer, enough to cover a fee.`,
    balance: balance.toString(),
    remaining: remaining.toString(),
    maxSuggested: maxSuggested.toString(),
    note: NOTE_PASS,
  };
}

/** balance − reserve − headroom, clamped at 0. Tokens keep their full balance. */
function maxFor(balance: bigint, reserve: bigint, asset: AssetInfo, gasSymbol: string | null): bigint {
  if (gasSymbol) return balance;
  const max = balance - reserve - headroomFloor(asset);
  return max > BigInt(0) ? max : BigInt(0);
}

// ─── Bank sends (wallet_tx_send) ────────────────────────────────────────────
//
// Same bug, different data source: `tx send` moves OST directly between KEY
// addresses, so its balance comes from `query balance` (one denom, already in
// smallest units) rather than from the per-safe `query assets`. The gas is the
// OST being sent, so draining the address is the same guaranteed failure R3
// catches for native safe assets.

/** Gas headroom per denom, in that denom's own smallest units. */
const DENOM_HEADROOM: Record<string, bigint> = {
  nost: BigInt(1_000_000), // 0.001 OST
};

export interface BankSendInput {
  /** Key address the OST leaves from. */
  address: string;
  /** Balance of `denom` at that address, in smallest units. */
  balance: bigint;
  amount: bigint;
  denom: string;
}

export function checkBankSend(input: BankSendInput): Feasibility {
  const { address, balance, amount, denom } = input;
  // An unknown denom gets the structural rules only. Inventing a headroom for a
  // denom we know nothing about would refuse valid sends on a guess.
  const headroom = DENOM_HEADROOM[denom.toLowerCase()] ?? BigInt(0);
  const maxSuggested = balance - headroom > BigInt(0) ? balance - headroom : BigInt(0);
  const base = {
    asset: denom,
    safe: address,
    balance: balance.toString(),
    requested: amount.toString(),
    maxSuggested: maxSuggested.toString(),
  };

  if (amount > balance) {
    return {
      ...base,
      verdict: 'will-fail',
      rule: 'R2-over-balance',
      reason: `Requested ${amount}${denom} but ${address} holds ${balance}${denom}.`,
      remaining: null,
      note: NOTE_STRUCTURAL,
    };
  }

  const remaining = balance - amount;
  if (remaining === BigInt(0)) {
    return {
      ...base,
      verdict: 'will-fail',
      rule: 'R3-full-drain',
      reason:
        `This sends the ENTIRE ${denom} balance (${balance}). The gas for this very transaction is paid ` +
        `in ${denom}, so nothing is left to pay it. Send at most ${maxSuggested} instead.`,
      remaining: '0',
      note: NOTE_STRUCTURAL,
    };
  }

  if (headroom > BigInt(0) && remaining < headroom) {
    return {
      ...base,
      verdict: 'at-risk',
      rule: 'R6-headroom',
      reason:
        `This leaves ${remaining}${denom} to cover gas paid in the same denom, below the conservative ` +
        `floor of ${headroom}. Send at most ${maxSuggested} to stay clear of it.`,
      remaining: remaining.toString(),
      note: NOTE_HEURISTIC,
    };
  }

  return {
    ...base,
    verdict: 'likely-pass',
    rule: 'R7-ok',
    reason: `Leaves ${remaining}${denom} after the transfer, enough to cover gas.`,
    remaining: remaining.toString(),
    note: NOTE_PASS,
  };
}

/** `1000nost` → { amount: 1000n, denom: 'nost' }. Null when it isn't that shape. */
export function parseDenomAmount(v: string): { amount: bigint; denom: string } | null {
  const m = /^\s*(\d+)\s*([a-zA-Z][a-zA-Z0-9/:._-]*)\s*$/.exec(v);
  if (!m) return null;
  return { amount: BigInt(m[1]!), denom: m[2]! };
}

/** The `amount` out of `query balance`'s `{ success, data: { amount, denom } }`. */
export function parseBalanceAmount(raw: string): bigint | null {
  try {
    const j = JSON.parse(raw) as { data?: { amount?: unknown }; amount?: unknown };
    const amt = j?.data?.amount ?? j?.amount;
    if (amt === undefined || amt === null) return null;
    const s = String(amt).trim();
    return /^\d+$/.test(s) ? BigInt(s) : null;
  } catch {
    return null;
  }
}

// ─── Parsing `query assets` ─────────────────────────────────────────────────

/**
 * Pull SafeAssets[] out of wallet-cli's `{ success, data: { assets } }` envelope.
 * Returns [] rather than throwing on an unexpected shape — the caller decides
 * whether an empty list is fatal, and a feasibility check must never be the
 * thing that breaks a transfer.
 */
export function parseAssets(raw: string): SafeAssets[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  const root = parsed as { data?: { assets?: unknown }; assets?: unknown };
  const list = root?.data?.assets ?? root?.assets;
  if (!Array.isArray(list)) return [];
  return list
    .filter((s): s is SafeAssets => !!s && typeof s === 'object')
    .map((s) => ({
      safeAddress: String((s as SafeAssets).safeAddress ?? ''),
      assets: Array.isArray((s as SafeAssets).assets) ? (s as SafeAssets).assets : [],
    }));
}
