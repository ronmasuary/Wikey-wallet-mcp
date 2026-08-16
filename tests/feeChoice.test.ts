import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildFeeChoice,
  normalizeFeePriority,
  feePriorityRefusal,
  feePriorityInvalid,
  FEE_PRIORITIES,
} from '../src/core/feeChoice.js';

// ─── the menu ───────────────────────────────────────────────────────────────

test('every menu offers exactly the three tiers, cheapest first', () => {
  for (const symbol of ['BTC', 'ETH', 'OST', 'ADA', 'WHATEVER']) {
    const choice = buildFeeChoice(symbol);
    assert.deepEqual(
      choice.options.map((o) => o.priority),
      ['low', 'medium', 'high'],
      symbol,
    );
    assert.equal(choice.options.length, FEE_PRIORITIES.length);
    for (const o of choice.options) assert.ok(o.eta.length > 0, `${symbol} ${o.priority}`);
  }
});

test('BTC reports the confirmation windows the fee oracle is actually asked for', () => {
  // proxy others/BTC.ts requests bitcoiner.live's 1440 / 180 / 30-minute
  // estimates. If those change there, this table is what needs changing here.
  const choice = buildFeeChoice('BTC');
  assert.equal(choice.basis, 'oracle-window');
  assert.equal(choice.options[0]!.eta, '~24 hours');
  assert.equal(choice.options[1]!.eta, '~3 hours');
  assert.equal(choice.options[2]!.eta, '~30 minutes');
});

test('no menu quotes a cost, on any chain', () => {
  // The whole point: a tier is a bid, and the fee is bid × a size nobody knows
  // until the signer builds the transaction. A currency symbol here would mean
  // someone started inventing precision again.
  for (const symbol of ['BTC', 'DOGE', 'ETH', 'POL', 'AVAX', 'SOL', 'XRP', 'ADA', 'OST', 'NOPE']) {
    const choice = buildFeeChoice(symbol);
    const text = JSON.stringify(choice);
    assert.ok(!/[$€£]/.test(text), `${symbol} menu quotes a currency`);
    assert.ok(!/\busd\b/i.test(text), `${symbol} menu quotes USD`);
  }
});

test('chains whose tiers resolve to one fee say so instead of staging a fake choice', () => {
  // SOL (flat per-signature), XRP (base fee) and ADA (placeholder) all return
  // the same value for all three tiers upstream; OST varies only the gas limit.
  for (const symbol of ['SOL', 'XRP', 'ADA', 'OST']) {
    assert.equal(buildFeeChoice(symbol).tiersDiffer, false, symbol);
  }
  for (const symbol of ['BTC', 'DOGE', 'ETH', 'POL', 'AVAX']) {
    assert.equal(buildFeeChoice(symbol).tiersDiffer, true, symbol);
  }
});

test('a token is priced by the coin that pays its gas, not by the token', () => {
  // USDC on Base: the fee is ETH's, so the menu must be ETH's.
  assert.deepEqual(buildFeeChoice('USDC', 'ETH'), buildFeeChoice('ETH'));
  assert.notDeepEqual(buildFeeChoice('USDC', 'ETH').options, buildFeeChoice('BTC').options);
});

test('MATIC and POL share one profile', () => {
  assert.deepEqual(buildFeeChoice('MATIC'), buildFeeChoice('POL'));
});

test('an unknown symbol still yields a usable menu', () => {
  const choice = buildFeeChoice('NEWCOIN');
  assert.equal(choice.options.length, 3);
  assert.ok(choice.note.includes('signing engine'));
});

// ─── the answer coming back ─────────────────────────────────────────────────

test('normalizeFeePriority accepts the word in any case', () => {
  assert.equal(normalizeFeePriority('low'), 'low');
  assert.equal(normalizeFeePriority('HIGH'), 'high');
  assert.equal(normalizeFeePriority('  Medium '), 'medium');
});

test('normalizeFeePriority accepts the 1/2/3 the user was shown', () => {
  assert.equal(normalizeFeePriority('1'), 'low');
  assert.equal(normalizeFeePriority(2), 'medium');
  assert.equal(normalizeFeePriority('3'), 'high');
  assert.equal(normalizeFeePriority(4), null);
  assert.equal(normalizeFeePriority(0), null);
});

test('normalizeFeePriority refuses to guess at intent words', () => {
  // Reading "urgent" as high is the model's job. Doing it here would quietly
  // re-introduce the guessing this module exists to stop.
  for (const v of ['urgent', 'fast', 'cheap', 'asap', 'default'])
    assert.equal(normalizeFeePriority(v), null, v);
});

test('normalizeFeePriority answers null — never a default — for empty input', () => {
  for (const v of [undefined, null, '', '   ', {}, []]) assert.equal(normalizeFeePriority(v), null);
});

// ─── the refusal ────────────────────────────────────────────────────────────

test('the refusal carries the numbered menu, the times, and how to retry', () => {
  const msg = feePriorityRefusal(buildFeeChoice('BTC'), 'BTC');
  assert.match(msg, /Refusing to broadcast/);
  assert.match(msg, /ASK THE USER/);
  assert.match(msg, /1\. low/);
  assert.match(msg, /2\. medium/);
  assert.match(msg, /3\. high/);
  assert.match(msg, /~30 minutes/);
  assert.match(msg, /BTC transfer/);
  assert.match(msg, /wallet_config_set feePriority/);
  // It must not hand the model a cost to repeat, or a tier to fall back on.
  assert.ok(!/[$€£]/.test(msg));
  assert.match(msg, /do not invent one/);
});

test('the refusal tells the user when the tiers are equivalent anyway', () => {
  assert.match(feePriorityRefusal(buildFeeChoice('XRP'), 'XRP'), /equivalent on this chain/);
  assert.ok(!/equivalent on this chain/.test(feePriorityRefusal(buildFeeChoice('BTC'), 'BTC')));
});

test('an invalid priority is named, not silently corrected', () => {
  const msg = feePriorityInvalid('urgent');
  assert.match(msg, /"urgent"/);
  assert.match(msg, /low, medium, high/);
});
