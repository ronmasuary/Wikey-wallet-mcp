import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkFeasibility,
  checkBankSend,
  parseAssets,
  parseBalanceAmount,
  parseDenomAmount,
  toSmallest,
  type SafeAssets,
} from '../src/core/txFeasibility.js';

const SAFE = 'omnistar1safe000000000000000000000000000000000';

/** One safe holding 0.5 BTC (50_000_000 sat) at $60k. */
function btcSafe(value = '0.5'): SafeAssets[] {
  return [
    {
      safeAddress: SAFE,
      assets: [{ symbol: 'BTC', value, smallCoin: '100000000', priceValue: '60000' }],
    },
  ];
}

const BTC_BALANCE = BigInt(50_000_000);

// ─── toSmallest ─────────────────────────────────────────────────────────────

test('toSmallest is exact where floating point is not', () => {
  // 0.00123 * 1e8 is 123000.00000000001 in IEEE-754. R3 turns on an exact
  // comparison, so this has to be a decimal shift, not a multiplication.
  assert.equal(toSmallest('0.00123', '100000000'), BigInt(123000));
  assert.equal(toSmallest('0.1', '1000000000000000000'), BigInt('100000000000000000'));
  assert.equal(toSmallest('0.5', '100000000'), BigInt(50_000_000));
  assert.equal(toSmallest('12', '1000000'), BigInt(12_000_000));
});

test('toSmallest truncates beyond the asset precision rather than rounding up', () => {
  // Rounding up would invent money the safe does not hold.
  assert.equal(toSmallest('0.123456789', '100000000'), BigInt(12345678));
});

test('toSmallest returns null for junk, not 0', () => {
  assert.equal(toSmallest(undefined, '100000000'), null);
  assert.equal(toSmallest('', '100000000'), null);
  assert.equal(toSmallest('abc', '100000000'), null);
});

// ─── R1-R3: the structural rules ────────────────────────────────────────────

test('R1: asset the safe does not hold', () => {
  const r = checkFeasibility({ safes: btcSafe(), safe: SAFE, asset: 'ETH', amount: BigInt(1) });
  assert.equal(r.verdict, 'will-fail');
  assert.equal(r.rule, 'R1-not-held');
  assert.equal(r.maxSuggested, null);
});

test('R1: unknown safe address names the tool that lists them', () => {
  const r = checkFeasibility({ safes: btcSafe(), safe: 'omnistar1other', asset: 'BTC', amount: BigInt(1) });
  assert.equal(r.rule, 'R1-not-held');
  assert.match(r.reason, /wallet_assets/);
});

test('R2: more than the balance', () => {
  const r = checkFeasibility({ safes: btcSafe(), safe: SAFE, asset: 'BTC', amount: BTC_BALANCE + BigInt(1) });
  assert.equal(r.verdict, 'will-fail');
  assert.equal(r.rule, 'R2-over-balance');
});

test('R3: the reported bug — sending the entire balance of a native asset', () => {
  const r = checkFeasibility({ safes: btcSafe(), safe: SAFE, asset: 'BTC', amount: BTC_BALANCE });
  assert.equal(r.verdict, 'will-fail');
  assert.equal(r.rule, 'R3-full-drain');
  assert.equal(r.remaining, '0');
  // The point of the whole exercise: it hands back a usable amount.
  assert.ok(BigInt(r.maxSuggested!) > BigInt(0));
  assert.ok(BigInt(r.maxSuggested!) < BTC_BALANCE);
});

test('R3 fires on the balance parsed from a decimal string, not a rounded float', () => {
  // 0.00123 BTC — the float path would compute 123000.00000000001 and miss the
  // exact-equality test, letting a guaranteed-failing drain through.
  const safes: SafeAssets[] = [
    { safeAddress: SAFE, assets: [{ symbol: 'BTC', value: '0.00123', smallCoin: '100000000', priceValue: '60000' }] },
  ];
  const r = checkFeasibility({ safes, safe: SAFE, asset: 'BTC', amount: BigInt(123000) });
  assert.equal(r.rule, 'R3-full-drain');
});

test('maxSuggested from R3 is itself accepted', () => {
  const first = checkFeasibility({ safes: btcSafe(), safe: SAFE, asset: 'BTC', amount: BTC_BALANCE });
  const retry = checkFeasibility({
    safes: btcSafe(),
    safe: SAFE,
    asset: 'BTC',
    amount: BigInt(first.maxSuggested!),
  });
  assert.equal(retry.verdict, 'likely-pass');
});

// ─── R4: tokens pay their fee in a different coin ───────────────────────────

const usdcOnBase = (ethValue?: string): SafeAssets[] => [
  {
    safeAddress: SAFE,
    assets: [
      {
        symbol: 'USDC',
        value: '100',
        smallCoin: '1000000',
        priceValue: '1',
        layer2data: { contractAddress: '0xa0b8', chain: 'base', smallCoin: '1000000', transactionType: 'BERC20' },
      },
      ...(ethValue === undefined
        ? []
        : [{ symbol: 'ETH', value: ethValue, smallCoin: '1000000000000000000', priceValue: '3000' }]),
    ],
  },
];

test('R4: token with no native gas coin fails at any amount', () => {
  const r = checkFeasibility({ safes: usdcOnBase(), safe: SAFE, asset: 'USDC', amount: BigInt(1_000_000) });
  assert.equal(r.verdict, 'will-fail');
  assert.equal(r.rule, 'R4-no-gas');
  assert.equal(r.maxSuggested, null);
  // Base's gas is ETH, which is the part that surprises people.
  assert.equal(r.gasAsset?.symbol, 'ETH');
});

test('R4: zero gas balance is as fatal as no gas row at all', () => {
  const r = checkFeasibility({ safes: usdcOnBase('0'), safe: SAFE, asset: 'USDC', amount: BigInt(1_000_000) });
  assert.equal(r.rule, 'R4-no-gas');
});

test('a token CAN be sent in full — its fee is not taken from it', () => {
  // The R3 drain rule must not fire here, or every legitimate "send all my
  // USDC" would be refused.
  const r = checkFeasibility({ safes: usdcOnBase('0.05'), safe: SAFE, asset: 'USDC', amount: BigInt(100_000_000) });
  assert.equal(r.verdict, 'likely-pass');
  assert.equal(r.maxSuggested, '100000000');
});

test('token with dust gas is at-risk, and says the amount itself is fine', () => {
  const r = checkFeasibility({ safes: usdcOnBase('0.0000001'), safe: SAFE, asset: 'USDC', amount: BigInt(1_000_000) });
  assert.equal(r.verdict, 'at-risk');
  assert.match(r.reason, /ETH/);
});

// ─── R5: balances that can never be fully spent ─────────────────────────────

const xrpSafe: SafeAssets[] = [
  { safeAddress: SAFE, assets: [{ symbol: 'XRP', value: '5', smallCoin: '1000000', priceValue: '2' }] },
];

test('R5: XRP cannot be left below its account reserve', () => {
  // 5 XRP held, sending 4.5 leaves 0.5 — under the 1 XRP reserve.
  const r = checkFeasibility({ safes: xrpSafe, safe: SAFE, asset: 'XRP', amount: BigInt(4_500_000) });
  assert.equal(r.verdict, 'will-fail');
  assert.equal(r.rule, 'R5-reserve');
});

test('R5: maxSuggested keeps the reserve intact', () => {
  const r = checkFeasibility({ safes: xrpSafe, safe: SAFE, asset: 'XRP', amount: BigInt(4_500_000) });
  assert.ok(BigInt(r.maxSuggested!) <= BigInt(4_000_000));
});

// ─── R6 / R7 ────────────────────────────────────────────────────────────────

test('R6: a near-drain is at-risk rather than refused outright', () => {
  const r = checkFeasibility({ safes: btcSafe(), safe: SAFE, asset: 'BTC', amount: BTC_BALANCE - BigInt(10) });
  assert.equal(r.verdict, 'at-risk');
  assert.equal(r.rule, 'R6-headroom');
});

test('R7: an ordinary transfer passes and says it is not a guarantee', () => {
  const r = checkFeasibility({ safes: btcSafe(), safe: SAFE, asset: 'BTC', amount: BigInt(1_000_000) });
  assert.equal(r.verdict, 'likely-pass');
  assert.match(r.note, /not a guarantee/);
});

test('symbol and safe lookups are case-insensitive', () => {
  const r = checkFeasibility({ safes: btcSafe(), safe: SAFE.toUpperCase(), asset: 'btc', amount: BigInt(1_000_000) });
  assert.equal(r.verdict, 'likely-pass');
});

test('POL and MATIC resolve to the same coin', () => {
  const safes: SafeAssets[] = [
    { safeAddress: SAFE, assets: [{ symbol: 'POL', value: '100', smallCoin: '1000000000000000000', priceValue: '0.4' }] },
  ];
  const r = checkFeasibility({ safes, safe: SAFE, asset: 'MATIC', amount: BigInt('1000000000000000000') });
  assert.equal(r.verdict, 'likely-pass');
});

test('every verdict carries a note stating what it is worth', () => {
  const cases = [BigInt(1_000_000), BTC_BALANCE, BTC_BALANCE - BigInt(10), BTC_BALANCE + BigInt(1)];
  for (const amount of cases) {
    const r = checkFeasibility({ safes: btcSafe(), safe: SAFE, asset: 'BTC', amount });
    assert.ok(r.note.length > 0, `no note for amount ${amount}`);
    assert.ok(r.reason.length > 0, `no reason for amount ${amount}`);
  }
});

// ─── Bank sends ─────────────────────────────────────────────────────────────

test('bank send: draining the address cannot pay its own gas', () => {
  const r = checkBankSend({ address: SAFE, balance: BigInt(5_000_000), amount: BigInt(5_000_000), denom: 'nost' });
  assert.equal(r.verdict, 'will-fail');
  assert.equal(r.rule, 'R3-full-drain');
});

test('bank send: an unknown denom gets the structural rules only', () => {
  // No invented headroom for a denom we know nothing about.
  const near = checkBankSend({ address: SAFE, balance: BigInt(1000), amount: BigInt(999), denom: 'uatom' });
  assert.equal(near.verdict, 'likely-pass');
  const drain = checkBankSend({ address: SAFE, balance: BigInt(1000), amount: BigInt(1000), denom: 'uatom' });
  assert.equal(drain.verdict, 'will-fail');
});

test('bank send: ordinary gas funding passes', () => {
  const r = checkBankSend({ address: SAFE, balance: BigInt(1_000_000_000), amount: BigInt(2_000_000), denom: 'nost' });
  assert.equal(r.verdict, 'likely-pass');
});

// ─── Parsers ────────────────────────────────────────────────────────────────

test('parseAssets reads the wallet-cli success envelope', () => {
  const raw = JSON.stringify({
    success: true,
    data: { assets: [{ safeAddress: SAFE, assets: [{ symbol: 'BTC', value: '1' }] }] },
  });
  const parsed = parseAssets(raw);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0]!.assets[0]!.symbol, 'BTC');
});

test('parseAssets returns [] on junk instead of throwing', () => {
  // A feasibility check must never be the thing that breaks a transfer.
  assert.deepEqual(parseAssets('not json'), []);
  assert.deepEqual(parseAssets('{"success":true}'), []);
});

test('parseDenomAmount splits amount from denom', () => {
  assert.deepEqual(parseDenomAmount('1000nost'), { amount: BigInt(1000), denom: 'nost' });
  assert.deepEqual(parseDenomAmount(' 42uatom '), { amount: BigInt(42), denom: 'uatom' });
  assert.equal(parseDenomAmount('nost'), null);
  assert.equal(parseDenomAmount('1000'), null);
});

test('parseBalanceAmount reads query balance output', () => {
  assert.equal(
    parseBalanceAmount(JSON.stringify({ success: true, data: { address: SAFE, denom: 'nost', amount: '12345' } })),
    BigInt(12345),
  );
  assert.equal(parseBalanceAmount('nope'), null);
});

// ─── Narrowed reads (core/assetInfo.ts) ─────────────────────────────────────

test('R1 names the safe\'s real holdings even when the read was narrowed', () => {
  // Under narrowing `assets` holds only what was asked for, so without
  // heldSymbols this told a user with a full safe that it holds "(nothing)".
  const r = checkFeasibility({
    safes: [{ safeAddress: SAFE, assets: [], heldSymbols: ['BTC', 'ETH', 'XRP'] }],
    safe: SAFE,
    asset: 'OST',
    amount: BigInt(1),
  });
  assert.equal(r.verdict, 'will-fail');
  assert.equal(r.rule, 'R1-not-held');
  assert.match(r.reason, /BTC, ETH, XRP/);
  assert.doesNotMatch(r.reason, /\(nothing\)/);
});

test('R1 still falls back to assets[] on the wallet-cli envelope (no heldSymbols)', () => {
  const r = checkFeasibility({
    safes: [{ safeAddress: SAFE, assets: [{ symbol: 'BTC', value: '1', smallCoin: '100000000' }] }],
    safe: SAFE,
    asset: 'OST',
    amount: BigInt(1),
  });
  assert.equal(r.rule, 'R1-not-held');
  assert.match(r.reason, /BTC/);
});

test('a narrowed read still reaches every non-R1 rule (BTC path unchanged)', () => {
  // The ladder only ever needed the sent asset's row plus, for a token, its gas
  // coin. Narrowing must not change any verdict for a plain native transfer.
  const narrowed: SafeAssets[] = [
    {
      safeAddress: SAFE,
      assets: [{ symbol: 'BTC', value: '0.5', smallCoin: '100000000', priceValue: '60000' }],
      heldSymbols: ['BTC', 'ETH', 'MATIC', 'POL'],
    },
  ];
  const full: SafeAssets[] = [
    {
      safeAddress: SAFE,
      assets: [
        { symbol: 'BTC', value: '0.5', smallCoin: '100000000', priceValue: '60000' },
        { symbol: 'ETH', value: '2', smallCoin: '1000000000', priceValue: '1900' },
        { symbol: 'POL', value: '5', smallCoin: '1000000000', priceValue: '0.4' },
      ],
    },
  ];

  for (const amount of [BigInt(1), BigInt(10_000_000), BigInt(50_000_000), BigInt(60_000_000)]) {
    const a = checkFeasibility({ safes: narrowed, safe: SAFE, asset: 'BTC', amount });
    const b = checkFeasibility({ safes: full, safe: SAFE, asset: 'BTC', amount });
    assert.equal(a.verdict, b.verdict, `verdict matches at ${amount}`);
    assert.equal(a.rule, b.rule, `rule matches at ${amount}`);
    assert.equal(a.maxSuggested, b.maxSuggested, `maxSuggested matches at ${amount}`);
  }
});
