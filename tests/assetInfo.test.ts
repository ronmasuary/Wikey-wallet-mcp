import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  fetchSafeAssets,
  fetchPortfolio,
  fetchRecipientSafes,
  type AssetInfoDeps,
  type SnapshotDeps,
  type FetchLike,
} from '../src/core/assetInfo.js';

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

// ─── Recipient safes: the read behind "transfer 2 BTC to op20" ──────────────
//
// The fixture is the RAW /snapshot/client top-level array — five safes, all
// isMain:true, one named after the account — modelled on the live op20 response
// of 2026-08-17 with fabricated but FORMAT-VALID addresses (real bech32/hex/
// base58 shapes, so the address-family guard can be tested against it).
//
// It is deliberately NOT tests/fixtures/snapshot-fixture.json, which is the
// wallet-cli `{success, data}` envelope: this module parses the HTTP body.

const RECIPIENT_FIXTURE = readFileSync(
  new URL('./fixtures/recipient-snapshot.json', import.meta.url),
  'utf8',
);

const OP20_SAFE = 'omnistar1g7f4k2m9x3vd8w0s5jn6h2ce4mua7lqp8hall4';

interface SnapReq {
  url: string;
  method: string;
  headers: Record<string, string>;
}

/**
 * An endpoint that serves ONE snapshot body — and nothing else. The deps are
 * typed `SnapshotDeps`, so this stub cannot supply an apiServerUrl or an
 * apiKey: if the recipient path ever grew a pricing call, this would not compile.
 */
function snapshotStub(body: string, ok = true): { deps: SnapshotDeps; reqs: SnapReq[] } {
  const reqs: SnapReq[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    const i = (init ?? {}) as { method?: string; headers?: Record<string, string> };
    reqs.push({ url, method: i.method ?? 'GET', headers: i.headers ?? {} });
    return {
      ok,
      status: ok ? 200 : 502,
      statusText: ok ? 'OK' : 'Bad Gateway',
      text: async () => body,
    };
  };
  return { reqs, deps: { snapshotUrl: 'https://proxy.test/mainnet/node', fetchImpl } };
}

test('every safe comes back with its name and its receive addresses', async () => {
  const { deps } = snapshotStub(RECIPIENT_FIXTURE);

  const safes = await fetchRecipientSafes(deps, ADDR);

  assert.deepEqual(
    safes.map((s) => s.name),
    ['op20_safe', 'treasury_safe', 'treasuryAcc_safe', 'trExecutor_safe', 'createTest3_safe'],
    'names — which the account profile does NOT carry, and a menu cannot be built without',
  );
  assert.equal(safes[0]!.address, OP20_SAFE);
  // Carried through verbatim — epoch millis in a string, as the endpoint
  // reports it (confirmed live 2026-08-19). Formatting is the menu's job.
  assert.equal(safes[0]!.lastActive, '1769591640000');
  assert.equal(
    safes[0]!.assets.find((a) => a.symbol === 'BTC')!.address,
    'bc1qg7f4k2m9x3vd8w0s5jn6h2ce4mua7lqp9tnpga',
  );
});

test("OST's receive address IS the safe's own address — every other asset's is not", async () => {
  // The trap this whole feature exists to avoid. Passing the safe address as
  // --to PASSES an OST test and loses money on the first BTC transfer, because
  // wallet-cli does not validate --to (it is declared `string`, not `address`).
  const { deps } = snapshotStub(RECIPIENT_FIXTURE);

  const safes = await fetchRecipientSafes(deps, ADDR);

  for (const safe of safes) {
    const ost = safe.assets.find((a) => a.symbol === 'OST');
    assert.equal(ost!.address, safe.address, `${safe.name}: OST is received at the safe address`);

    const btc = safe.assets.find((a) => a.symbol === 'BTC');
    if (btc) {
      assert.notEqual(btc.address, safe.address, `${safe.name}: BTC is NOT`);
      assert.equal(
        btc.address.slice(4, 36),
        safe.address.slice(9, 41),
        `${safe.name}: …yet shares a data part, which is why a wrong --to looks plausible`,
      );
    }
  }
});

test('a recipient read prices NOTHING and sends no api-key', async () => {
  // A recipient needs an address, not a balance. Pricing would also be the slow
  // part: the endpoint that times out is /api/assets/, which this never calls.
  const { deps, reqs } = snapshotStub(RECIPIENT_FIXTURE);

  await fetchRecipientSafes(deps, ADDR);

  assert.equal(reqs.length, 1, 'one request, total');
  assert.equal(reqs[0]!.method, 'GET');
  assert.match(reqs[0]!.url, /\/mainnet\/node\/snapshot\/client\?env=main&publickey=/);
  assert.ok(!('api-key' in reqs[0]!.headers), 'no credential leaves the process for a public read');
});

test('both names of an aliased coin survive to the recipient list', async () => {
  // The pricing path DEDUPES MATIC/POL, because two names for one coin would
  // show a duplicate balance. A receive address is not a balance: dropping one
  // label here would make a send addressed to the dropped symbol unresolvable.
  const { deps } = snapshotStub(RECIPIENT_FIXTURE);

  const symbols = (await fetchRecipientSafes(deps, ADDR))[0]!.assets.map((a) => a.symbol);

  assert.ok(symbols.includes('MATIC') && symbols.includes('POL'), 'both labels kept');
});

test('a row naming no address is dropped rather than offered as a destination', async () => {
  const { deps } = snapshotStub(
    JSON.stringify([
      {
        name: 'x_safe',
        address: 'omnistar1x',
        assets: { assets: [{ symbol: 'BTC', address: '' }, { symbol: 'OST', address: 'omnistar1x' }] },
      },
    ]),
  );

  const safes = await fetchRecipientSafes(deps, ADDR);
  assert.deepEqual(safes[0]!.assets.map((a) => a.symbol), ['OST']);
});

// ─── "No safes" and "could not read" are opposite answers ───────────────────

test('an account with no safes returns an empty list — a real answer', async () => {
  // Distinct from a failed read, and the caller reports it as "this account has
  // no safe yet; a fresh create-safe takes ~2-8 min to appear".
  const { deps } = snapshotStub('[]');
  assert.deepEqual(await fetchRecipientSafes(deps, ADDR), []);
});

test('a body that is not a list THROWS instead of reporting zero safes', async () => {
  // Returning [] for an unrecognised shape would tell the user "op20 has no
  // safe" on the strength of a response we did not understand — and the fix for
  // that is to wait for a safe that already exists.
  const { deps } = snapshotStub('{"error":"nope"}');
  await assert.rejects(() => fetchRecipientSafes(deps, ADDR), /failed read, not an account without safes/);
});

test('a non-2xx read throws, and does not imply the account is empty', async () => {
  const { deps } = snapshotStub(RECIPIENT_FIXTURE, false);
  await assert.rejects(() => fetchRecipientSafes(deps, ADDR), /snapshot read failed: 502/);
});

test('malformed JSON throws rather than parsing to nothing', async () => {
  const { deps } = snapshotStub('<html>gateway timeout</html>');
  await assert.rejects(() => fetchRecipientSafes(deps, ADDR), /malformed JSON/);
});

test('an empty account address is refused before any request', async () => {
  const { deps, reqs } = snapshotStub(RECIPIENT_FIXTURE);
  await assert.rejects(() => fetchRecipientSafes(deps, '  '), /no account address/);
  assert.equal(reqs.length, 0);
});
