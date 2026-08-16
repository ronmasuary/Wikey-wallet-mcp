// The fee priority menu. Fee priority is the USER's decision, and this module is
// what makes it reach them instead of being guessed by the model.
//
// WHY THIS SHOWS TIME AND NOT MONEY. A priority is a BID, not a price. What a
// transfer actually costs is that bid multiplied by how big the transaction
// turns out to be — vBytes once the UTXOs are selected, gas units once the
// message is built — and that size is not known until the signing engine builds
// it (proxy rpc/ethereum/index.ts even says so: "today we are calculating fee in
// the safe"). The one fee service in the stack, `/api/transaction/estimated-fee`,
// does return a `usd` field, but per chain it is:
//   - BTC   (others/BTC.ts)          usd PER vBYTE — multiply by a vsize nobody knows yet
//   - POL   (nownodes/Polygon.ts)    usd PER GAS UNIT, with no gas limit applied
//   - OST   (cosmos/omnistar)        the SAME number for all three tiers
//   - ADA   (blockfrost/cardano)     a hardcoded placeholder ({qty:2, usd:10})
//   - BTC   (nownodes/BTC.ts)        hardcoded 0
// None of those is what the transfer will cost. Quoting one to a user would be
// inventing precision, which is the failure mode this whole area already guards
// against (see txFeasibility.ts). Target confirmation TIME is the one axis that
// is both honest and the thing a human is actually choosing between.
//
// Where the times come from is recorded per chain in `basis`: 'oracle-window'
// means the stack literally asks the fee oracle for that confirmation target, so
// the number is sourced; 'typical' means it is a representative figure for the
// chain and nothing more.
//
// Pure and transport-agnostic: a symbol in, a menu out. No I/O, no session.

export type FeePriority = 'low' | 'medium' | 'high';

/** Cheapest first — the order the menu is shown in, and the order of the 1/2/3 keys. */
export const FEE_PRIORITIES: readonly FeePriority[] = ['low', 'medium', 'high'] as const;

export interface FeeOption {
  priority: FeePriority;
  /** Target confirmation time. Never a price — see the header. */
  eta: string;
}

export interface FeeChoice {
  options: FeeOption[];
  /** 'oracle-window' — the stack requests this confirmation target. 'typical' — representative. */
  basis: 'oracle-window' | 'typical';
  /**
   * False when the chain's three tiers are known to resolve to the same fee, so
   * the choice changes nothing. Say so rather than staging a fake decision.
   */
  tiersDiffer: boolean;
  /** What a tier means on THIS chain, and why no cost is quoted. */
  note: string;
  /** The standing rule for the model. */
  instruction: string;
}

interface FeeProfile {
  eta: Record<FeePriority, string>;
  basis: 'oracle-window' | 'typical';
  tiersDiffer: boolean;
  note: string;
  aliases?: string[];
}

const SIZE_NOTE =
  'Fees here are charged per byte of transaction data. The final cost also depends on how many ' +
  'coins get combined to fund the transfer, which is only settled when the signer builds it — so ' +
  'these are target confirmation times, not prices.';

const GAS_NOTE =
  'A priority sets the gas price bid. The final cost is that bid multiplied by the gas the ' +
  'transaction actually uses, which is only known once the signer builds it — so these are target ' +
  'confirmation times, not prices.';

// Keyed by the coin that PAYS the fee (for a token, that is its chain's native
// coin, not the token). Every entry states where its tier semantics come from.
const PROFILES: Record<string, FeeProfile> = {
  // proxy others/BTC.ts asks bitcoiner.live for the 1440 / 180 / 30-minute
  // windows, so these three numbers are the request itself.
  BTC: {
    eta: { low: '~24 hours', medium: '~3 hours', high: '~30 minutes' },
    basis: 'oracle-window',
    tiersDiffer: true,
    note: SIZE_NOTE,
  },
  // proxy nownodes/DOGE.ts asks estimatefee for 9 / 3 / 1 block targets; Doge
  // blocks are ~1 minute.
  DOGE: {
    eta: { low: '~9 minutes', medium: '~3 minutes', high: '~1 minute' },
    basis: 'oracle-window',
    tiersDiffer: true,
    note: SIZE_NOTE,
  },
  ETH: {
    eta: { low: '~5 minutes', medium: '~1 minute', high: '~30 seconds' },
    basis: 'typical',
    tiersDiffer: true,
    note: GAS_NOTE,
  },
  // Fast-block EVM chains: the tier still matters under congestion, but the
  // spread between tiers is seconds, not minutes.
  POL: {
    eta: { low: '~1 minute', medium: '~30 seconds', high: '~10 seconds' },
    basis: 'typical',
    tiersDiffer: true,
    note: GAS_NOTE,
    aliases: ['MATIC'],
  },
  AVAX: {
    eta: { low: '~1 minute', medium: '~30 seconds', high: '~10 seconds' },
    basis: 'typical',
    tiersDiffer: true,
    note: GAS_NOTE,
  },
  // proxy solana/solana.ts returns ONE Total for all three tiers: Solana's fee
  // is a flat per-signature cost.
  SOL: {
    eta: { low: '~5 seconds', medium: '~5 seconds', high: '~5 seconds' },
    basis: 'typical',
    tiersDiffer: false,
    note:
      "Solana's fee is a flat per-signature cost — all three priorities resolve to the same fee, " +
      'so the choice changes nothing here.',
  },
  // proxy rpc/xrp/index.ts likewise returns the same Total for all three.
  XRP: {
    eta: { low: '~5 seconds', medium: '~5 seconds', high: '~5 seconds' },
    basis: 'typical',
    tiersDiffer: false,
    note:
      "XRP's fee is the network base fee — all three priorities resolve to the same fee, so the " +
      'choice changes nothing here.',
  },
  // proxy blockfrost/cardano returns {qty:2, usd:10} for every tier — a
  // placeholder, not three real bids. Say that plainly.
  ADA: {
    eta: { low: '~20 seconds', medium: '~20 seconds', high: '~20 seconds' },
    basis: 'typical',
    tiersDiffer: false,
    note:
      'The fee service does not differentiate Cardano tiers — it returns the same placeholder for ' +
      'all three, so the choice changes nothing here.',
  },
  // proxy cosmos/omnistar returns gas LIMITS 200k/300k/400k with an identical
  // price on all three: a higher tier raises the ceiling, not the speed.
  OST: {
    eta: { low: '~5 seconds', medium: '~5 seconds', high: '~5 seconds' },
    basis: 'typical',
    tiersDiffer: false,
    note:
      'On Omnistar the priority selects the gas LIMIT (200k / 300k / 400k) and the gas price is the ' +
      'same for all three, so a higher tier raises the ceiling rather than the speed.',
  },
};

const UNKNOWN: FeeProfile = {
  eta: { low: 'slowest', medium: 'moderate', high: 'fastest' },
  basis: 'typical',
  tiersDiffer: true,
  note:
    'The exact cost is computed by the signing engine when it builds the transaction and is not ' +
    'known here, so these are relative speeds, not prices.',
};

const INSTRUCTION =
  'ASK THE USER which fee priority they want — do not pick one for them. If they already said how ' +
  'fast they want it ("urgent", "cheap", "no rush"), map that to a tier instead of asking again.';

function profileFor(symbol: string): FeeProfile {
  const s = symbol.trim().toUpperCase();
  if (PROFILES[s]) return PROFILES[s]!;
  for (const p of Object.values(PROFILES)) {
    if (p.aliases?.includes(s)) return p;
  }
  return UNKNOWN;
}

/**
 * The menu for one transfer.
 *
 * `gasSymbol` is the coin that actually pays — pass `Feasibility.gasAsset.symbol`
 * for a token, so a USDC transfer is priced by ETH's profile and not by a made-up
 * USDC one. Omit it for a native asset.
 */
export function buildFeeChoice(asset: string, gasSymbol?: string): FeeChoice {
  const profile = profileFor(gasSymbol || asset);
  return {
    options: FEE_PRIORITIES.map((priority) => ({ priority, eta: profile.eta[priority] })),
    basis: profile.basis,
    tiersDiffer: profile.tiersDiffer,
    note: profile.note,
    instruction: INSTRUCTION,
  };
}

/**
 * Accepts what a user's answer actually looks like coming back through an agent:
 * the word in any case, or the 1/2/3 they were shown. Intent words ("urgent",
 * "cheap") are deliberately NOT mapped here — that reading is the model's job,
 * and silently guessing at "fast enough" in the wrapper is the behaviour this
 * module exists to stop. Returns null for anything else, including undefined.
 */
export function normalizeFeePriority(v: unknown): FeePriority | null {
  if (typeof v === 'number') return FEE_PRIORITIES[v - 1] ?? null;
  if (typeof v !== 'string') return null;
  const s = v.trim().toLowerCase();
  if (!s) return null;
  if ((FEE_PRIORITIES as readonly string[]).includes(s)) return s as FeePriority;
  if (s === '1' || s === '2' || s === '3') return FEE_PRIORITIES[Number(s) - 1]!;
  return null;
}

/**
 * The refusal that puts the choice in front of the user.
 *
 * Shaped like the no-default-account refusal in accounts.ts, and for the same
 * reason: a REQUIRED parameter does not produce a question, it produces a guess.
 * Only a refusal that hands back the options reliably reaches the human.
 */
export function feePriorityRefusal(choice: FeeChoice, asset: string): string {
  const menu = choice.options
    .map((o, i) => `  ${i + 1}. ${o.priority.padEnd(6)} — ${o.eta}`)
    .join('\n');
  const sameFee = choice.tiersDiffer
    ? ''
    : `\nTell them the tiers are equivalent on this chain, so any answer is fine.`;
  return (
    `Refusing to broadcast — no feePriority was given, and this tool does not choose one for the user.\n` +
    `${choice.instruction}\n` +
    `Fee priority for this ${asset.toUpperCase()} transfer:\n${menu}\n` +
    `${choice.note}${sameFee}\n` +
    `Then retry with feePriority set to their answer. No cost is quoted because it is not knowable ` +
    `here — do not invent one.\n` +
    `To stop being asked every time, the user can set a standing default: ` +
    `wallet_config_set feePriority medium.`
  );
}

/** The error for a priority that was given but is not one of the three. */
export function feePriorityInvalid(v: unknown): string {
  return (
    `feePriority "${String(v)}" is not valid. Use one of: ${FEE_PRIORITIES.join(', ')} ` +
    `(or 1 / 2 / 3). Ask the user which they want rather than picking for them.`
  );
}
