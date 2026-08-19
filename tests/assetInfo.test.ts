import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fetchSafeAssets, fetchPortfolio, type AssetInfoDeps, type FetchLike } from '../src/core/assetInfo.js';

const SAFE = 'omnistar1safe000000000000000000000000000000000';
const ADDR = 'omnistar1key0000000000000000000000000000000000';

interface Call {
  url: string;
  method: string;
  /** Symbols asked for, when this is a pricing POST. */
  symbols: string[];
  safeAddress?: string;
}

/**
 * A stub endpoint that records every request. `priced` maps symbol → the row the
 * pricing endpoint returns for it; a symbol absent from it comes back empty.
 */
function stub(opts: {
  held: Array<{ symbol: string; address: string }>;
  priced: Record<string, Record<string, unknown>>;
  failOn?: string;
}): { deps: AssetInfoDeps; calls: Call[] } {
  const calls: Call[] = [];

  const fetchImpl: FetchLike = async (url, init) => {
    const i = (init ?? {}) as { method?: string; body?: string };
    const method = i.method ?? 'GET';

    if (method === 'GET') {
      calls.push({ url, method, symbols: [] });
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        text: async () => JSON.stringify([{ address: SAFE, assets: { assets: opts.held } }]),
      };
    }

    const body = JSON.parse(i.body ?? '{}') as {
      assets: Array<{ symbol: string }>;
      safe_address: string;
    };
    const symbols = body.assets.map((a) => a.symbol);
    calls.push({ url, method, symbols, safeAddress: body.safe_address });

    if (opts.failOn && symbols.includes(opts.failOn)) {
      return { ok: false, status: 502, statusText: 'Bad Gateway', text: async () => '' };
    }

    const rows = symbols.map((s) => opts.priced[s]).filter(Boolean);
    return { ok: true, status: 200, statusText: 'OK', text: async () => JSON.stringify({ assets: rows }) };
  };

  return {
    calls,
    deps: {
      snapshotUrl: 'https://proxy.test/mainnet/node',
      apiServerUrl: 'https://proxy.test/mainnet/proxy',
      apiKey: 'k',
      fetchImpl,
    },
  };
}

const OST = { symbol: 'OST', name: 'OmniStar', value: '3', smallCoin: '1000000000', priceValue: '0.2' };
const POL = { symbol: 'POL', name: 'Polygon', value: '5', smallCoin: '1000000000000000000', priceValue: '0.4' };
const USDC = {
  symbol: 'USDC',
  name: 'USD Coin',
  value: '10',
  smallCoin: '1000000',
  priceValue: '1',
  layer2data: { contractAddress: '0xabc', chain: 'POLYGON', smallCoin: '1000000' },
};

// ─── The whole point: don't ask for what you don't need ─────────────────────

test('narrowing asks the pricing endpoint for ONLY the requested asset', async () => {
  // The bug this module exists for: a safe holding a slow asset (MATIC/POL took
  // 17-22s each) made EVERY transfer time out, because `query assets` priced the
  // entire list in one serial request. Sending OST must not price POL.
  const { deps, calls } = stub({
    held: [
      { symbol: 'OST', address: 'omnistar1x' },
      { symbol: 'POL', address: '0x1' },
      { symbol: 'BTC', address: 'bc1q' },
    ],
    priced: { OST, POL },
  });

  const safes = await fetchSafeAssets(deps, ADDR, ['OST']);

  const posts = calls.filter((c) => c.method === 'POST');
  assert.equal(posts.length, 1, 'one pricing request, not one per asset held');
  assert.deepEqual(posts[0]!.symbols, ['OST']);
  assert.deepEqual(
    safes[0]!.assets.map((a) => a.symbol),
    ['OST'],
  );
});

test('each asset is priced in its OWN request, never batched', async () => {
  // Batching is what makes the endpoint slow: it prices a list serially, so a
  // batch costs the SUM. Fanning out makes the wall-clock the MAX instead.
  const { deps, calls } = stub({
    held: [
      { symbol: 'OST', address: 'omnistar1x' },
      { symbol: 'POL', address: '0x1' },
    ],
    priced: { OST, POL },
  });

  await fetchSafeAssets(deps, ADDR, '*');

  const posts = calls.filter((c) => c.method === 'POST');
  assert.equal(posts.length, 2);
  assert.ok(posts.every((p) => p.symbols.length === 1), 'no request carries more than one asset');
});

// ─── Agreeing with the ladder ───────────────────────────────────────────────

test('an alias resolves the way the feasibility ladder resolves it', async () => {
  // Asked for MATIC, safe reports POL. If the narrowed read missed it, the
  // ladder would report R1-not-held — an unoverridable will-fail on an asset
  // the safe actually holds.
  const { deps, calls } = stub({
    held: [{ symbol: 'POL', address: '0x1' }],
    priced: { POL },
  });

  const safes = await fetchSafeAssets(deps, ADDR, ['MATIC']);

  assert.deepEqual(calls.filter((c) => c.method === 'POST')[0]!.symbols, ['POL']);
  assert.deepEqual(
    safes[0]!.assets.map((a) => a.symbol),
    ['POL'],
  );
});

test("a token also pulls in its chain's gas coin", async () => {
  // R4 fails a transfer whose gas balance is zero, so narrowing to the token
  // alone would silently drop that check. USDC on Polygon pays gas in POL.
  const { deps, calls } = stub({
    held: [
      { symbol: 'USDC', address: '0x2' },
      { symbol: 'POL', address: '0x1' },
      { symbol: 'BTC', address: 'bc1q' },
    ],
    priced: { USDC, POL },
  });

  const safes = await fetchSafeAssets(deps, ADDR, ['USDC']);

  assert.deepEqual(
    safes[0]!.assets.map((a) => a.symbol).sort(),
    ['POL', 'USDC'],
    'the token and its gas coin, and nothing else',
  );
  assert.equal(calls.filter((c) => c.method === 'POST').length, 2);
});

test('a native coin pulls in no gas coin at all', async () => {
  const { deps, calls } = stub({
    held: [
      { symbol: 'OST', address: 'omnistar1x' },
      { symbol: 'POL', address: '0x1' },
    ],
    priced: { OST, POL },
  });

  await fetchSafeAssets(deps, ADDR, ['OST']);
  assert.equal(calls.filter((c) => c.method === 'POST').length, 1);
});

test('a gas coin the safe does not hold stays absent rather than invented', async () => {
  // R4 reads the absence as "no gas" and fails the transfer, which is correct.
  const { deps } = stub({ held: [{ symbol: 'USDC', address: '0x2' }], priced: { USDC } });

  const safes = await fetchSafeAssets(deps, ADDR, ['USDC']);
  assert.deepEqual(
    safes[0]!.assets.map((a) => a.symbol),
    ['USDC'],
  );
});

// ─── Parity: the narrowing is not OST-specific ──────────────────────────────

test('every native asset narrows the same way — nothing is OST-specific', async () => {
  const held = [
    { symbol: 'BTC', address: 'bc1q' },
    { symbol: 'ETH', address: '0x1' },
    { symbol: 'OST', address: 'omnistar1x' },
    { symbol: 'XRP', address: 'r1' },
  ];
  const priced = Object.fromEntries(
    held.map((h) => [h.symbol, { symbol: h.symbol, value: '1', smallCoin: '100000000' }]),
  );

  for (const symbol of ['BTC', 'ETH', 'OST', 'XRP']) {
    const { deps, calls } = stub({ held, priced });
    const safes = await fetchSafeAssets(deps, ADDR, [symbol]);
    assert.deepEqual(safes[0]!.assets.map((a) => a.symbol), [symbol], `${symbol} resolves`);
    assert.equal(calls.filter((c) => c.method === 'POST').length, 1, `${symbol} costs one request`);
  }
});

test('a narrowed read still reports the full inventory when the asset is NOT held', async () => {
  // Regression: `assets` is no longer the safe's inventory under narrowing, so
  // reading the held list off it told the user a full safe held "(nothing)".
  const { deps } = stub({
    held: [
      { symbol: 'BTC', address: 'bc1q' },
      { symbol: 'ETH', address: '0x1' },
    ],
    priced: {},
  });

  const safes = await fetchSafeAssets(deps, ADDR, ['OST']);
  assert.deepEqual(safes[0]!.assets, []);
  assert.deepEqual(safes[0]!.heldSymbols, ['BTC', 'ETH'], 'the real inventory survives narrowing');
});

// ─── Failure must not look like a balance ───────────────────────────────────

test('a failed read throws instead of returning an empty asset list', async () => {
  // An empty list is indistinguishable from "holds nothing", which the ladder
  // reports as R1-not-held — an UNOVERRIDABLE will-fail. A read that could not
  // be performed must never masquerade as a balance that was.
  const { deps } = stub({
    held: [{ symbol: 'OST', address: 'omnistar1x' }],
    priced: { OST },
    failOn: 'OST',
  });

  await assert.rejects(() => fetchSafeAssets(deps, ADDR, ['OST']), /502|Bad Gateway/);
});

test('a portfolio read REPORTS a failed asset instead of failing the whole read', async () => {
  // The opposite policy from the signing path, on purpose: losing the other
  // assets because one is slow serves nobody on a display read.
  const { deps } = stub({
    held: [
      { symbol: 'OST', address: 'omnistar1x' },
      { symbol: 'POL', address: '0x1' },
    ],
    priced: { OST, POL },
    failOn: 'POL',
  });

  const { safes, unavailable } = await fetchPortfolio(deps, ADDR);

  assert.deepEqual(
    safes[0]!.assets.map((a) => a.symbol),
    ['OST'],
    'the assets that priced are still returned',
  );
  assert.equal(unavailable.length, 1);
  assert.equal(unavailable[0]!.symbol, 'POL');
  assert.equal(unavailable[0]!.safeAddress, SAFE);
});

test('the signing path still throws on the same failure a portfolio tolerates', async () => {
  // Guards the asymmetry: on the signing path a missing row is indistinguishable
  // from a zero balance, and R1-not-held is an unoverridable will-fail.
  const { deps } = stub({
    held: [{ symbol: 'POL', address: '0x1' }],
    priced: { POL },
    failOn: 'POL',
  });

  await assert.rejects(() => fetchSafeAssets(deps, ADDR, ['POL']));
});

test('a portfolio read holds concurrency down instead of firing everything at once', async () => {
  // An unthrottled fan-out made the endpoint contend: a 21.8s asset went past
  // 30s when 22 requests went out together.
  let inFlight = 0;
  let peak = 0;
  const held = Array.from({ length: 12 }, (_, i) => ({ symbol: `A${i}`, address: `0x${i}` }));
  const priced = Object.fromEntries(held.map((h) => [h.symbol, { symbol: h.symbol, value: '1' }]));

  const base = stub({ held, priced });
  const inner = base.deps.fetchImpl!;
  base.deps.fetchImpl = async (url, init) => {
    const isPost = ((init ?? {}) as { method?: string }).method === 'POST';
    if (!isPost) return inner(url, init);
    inFlight++;
    peak = Math.max(peak, inFlight);
    await new Promise((r) => setTimeout(r, 5));
    inFlight--;
    return inner(url, init);
  };

  const { unavailable } = await fetchPortfolio(base.deps, ADDR);
  assert.equal(unavailable.length, 0);
  assert.ok(peak <= 4, `peak concurrency ${peak} should stay within the cap`);
  assert.ok(peak > 1, 'but still overlap — a serial read would be slower than the CLI it replaces');
});

test('a 200 carrying no row for the asset is a FAILED read, not "not held"', async () => {
  // The endpoint really does answer 200 with {"assets":[]} for an asset it
  // cannot price (observed live for MATIC/POL). Letting that through would
  // reach the ladder as R1-not-held — an unoverridable will-fail — on an asset
  // the safe demonstrably holds, with a message listing that very asset.
  const { deps } = stub({
    held: [{ symbol: 'OST', address: 'omnistar1x' }],
    priced: {}, // 200, but no row comes back
  });

  await assert.rejects(
    () => fetchSafeAssets(deps, ADDR, ['OST']),
    /no row for OST/,
    'the signing path must refuse rather than report a phantom zero',
  );
});

test('a 200-with-no-row is REPORTED on the portfolio path', async () => {
  const { deps } = stub({
    held: [
      { symbol: 'OST', address: 'omnistar1x' },
      { symbol: 'MATIC', address: '0x1' },
    ],
    priced: { OST },
  });

  const { safes, unavailable } = await fetchPortfolio(deps, ADDR);
  assert.deepEqual(safes[0]!.assets.map((a) => a.symbol), ['OST']);
  assert.equal(unavailable.length, 1);
  assert.equal(unavailable[0]!.symbol, 'MATIC');
  assert.match(unavailable[0]!.reason, /no row for MATIC/);
});

test('an alias answer is NOT mistaken for a missing row', async () => {
  // Asking for MATIC legitimately answers with a row labelled POL. If the
  // emptiness check were not alias-aware it would reject every MATIC read.
  const { deps } = stub({ held: [{ symbol: 'MATIC', address: '0x1' }], priced: { MATIC: POL } });

  const safes = await fetchSafeAssets(deps, ADDR, ['MATIC']);
  assert.deepEqual(safes[0]!.assets.map((a) => a.symbol), ['POL']);
});

test('a token whose GAS coin prices empty fails loudly instead of reporting no-gas', async () => {
  // R4 would otherwise say "safe holds no POL" about a safe that holds POL.
  const { deps } = stub({
    held: [
      { symbol: 'USDC', address: '0x2' },
      { symbol: 'POL', address: '0x1' },
    ],
    priced: { USDC },
  });

  await assert.rejects(() => fetchSafeAssets(deps, ADDR, ['USDC']), /no row for POL/);
});

test('two names for one coin yield ONE row, not a duplicate', async () => {
  // A safe lists both MATIC and POL; the endpoint answers both with a POL row.
  // One request per asset would otherwise show POL twice — something the old
  // single-batch call could never do.
  const { deps } = stub({
    held: [
      { symbol: 'MATIC', address: '0x1' },
      { symbol: 'POL', address: '0x1' },
      { symbol: 'OST', address: 'omnistar1x' },
    ],
    priced: { MATIC: POL, POL, OST },
  });

  const { safes, unavailable } = await fetchPortfolio(deps, ADDR);
  assert.equal(unavailable.length, 0);
  assert.deepEqual(safes[0]!.assets.map((a) => a.symbol), ['POL', 'OST']);
});

test('an empty account address is refused before any request', async () => {
  const { deps, calls } = stub({ held: [], priced: {} });
  await assert.rejects(() => fetchSafeAssets(deps, '  ', ['OST']), /no account address/);
  assert.equal(calls.length, 0);
});

// ─── Shape ──────────────────────────────────────────────────────────────────

test('a safe that holds none of the requested asset is kept, with an empty list', async () => {
  // "No such safe" and "safe holds no X" are different verdicts. Dropping the
  // safe would turn the second into the first.
  const { deps, calls } = stub({ held: [{ symbol: 'BTC', address: 'bc1q' }], priced: {} });

  const safes = await fetchSafeAssets(deps, ADDR, ['OST']);
  assert.deepEqual(safes, [{ safeAddress: SAFE, assets: [], heldSymbols: ['BTC'] }]);
  assert.equal(calls.filter((c) => c.method === 'POST').length, 0, 'nothing to price, nothing asked');
});

test('the pricing request carries the safe address and the configured endpoint', async () => {
  const { deps, calls } = stub({ held: [{ symbol: 'OST', address: 'omnistar1x' }], priced: { OST } });

  await fetchSafeAssets(deps, ADDR, ['OST']);

  const post = calls.find((c) => c.method === 'POST')!;
  assert.equal(post.safeAddress, SAFE);
  assert.equal(post.url, 'https://proxy.test/mainnet/proxy/api/assets/');
  assert.match(calls[0]!.url, /\/mainnet\/node\/snapshot\/client\?env=main&publickey=/);
});
