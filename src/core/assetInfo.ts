/**
 * Narrowed asset-info reads.
 *
 * WHY THIS EXISTS, AND WHY IT DOES NOT GO THROUGH wallet-cli
 * ---------------------------------------------------------
 * `wallet-cli query assets` sends a safe's ENTIRE asset list to
 * `POST /api/assets/` as ONE request, and that endpoint prices the list
 * SERIALLY — so its latency is the SUM over every asset held, not the max.
 * wallet-cli then aborts the request at a hardcoded 10s
 * (`api-client.ts` DEFAULT_TIMEOUT) and reports `API_TIMEOUT`, which reads
 * like an upstream outage but is a self-inflicted abort of a request that
 * would have returned 200.
 *
 * Measured 2026-08-17 against a safe holding 11 assets:
 *
 *     MATIC 21803ms   POL 17185ms   BTC 2374ms   BASE 736ms   ETH 457ms
 *     OST     427ms   XRP   411ms   DOGE 359ms   SOL  231ms   ADA 250ms
 *     AVAX    291ms
 *     all 11 in one request → 52429ms  (aborted at 10000ms)
 *     OST alone             →   427ms
 *
 * A transfer needs ONE asset's row — plus, for a token, its chain's gas coin.
 * Asking for only those turns a 52s request that always times out into a
 * sub-second one. The same trick fixes the full portfolio read: one request
 * PER ASSET, issued in parallel, makes the wall-clock the MAX (~22s) instead
 * of the SUM (~52s).
 *
 * This lives MCP-side because wallet-cli cannot be shipped here: a running
 * agent installs the released tarball, so a CLI-side fix would never reach it.
 *
 * The transport is deliberately thin — no retries, no caching. A stale price
 * is a wrong feasibility verdict, and this sits on the signing path.
 */

import { AssetInfo, SafeAssets, findAsset, gasSymbolFor } from './txFeasibility.js';

/** Minimal shape of the global `fetch`, so tests can inject a stub. */
export type FetchLike = (url: string, init?: unknown) => Promise<{
  ok: boolean;
  status: number;
  statusText: string;
  text(): Promise<string>;
}>;

export interface AssetInfoDeps {
  /** wallet-cli config `snapshotUrl` (e.g. https://…/mainnet/node). */
  snapshotUrl: string;
  /** wallet-cli config `apiServerUrl` (e.g. https://…/mainnet/proxy). */
  apiServerUrl: string;
  /** wallet-cli config `apiKey`. */
  apiKey: string;
  /**
   * Budget for ONE request. Generous on purpose: the point of narrowing is that
   * a single asset answers in well under a second, so this is a backstop for a
   * genuinely wedged endpoint, not a latency budget to tune. It is deliberately
   * higher than wallet-cli's 10s, which is the bug this module routes around.
   */
  timeoutMs?: number;
  fetchImpl?: FetchLike;
}

const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * How many pricing requests may be in flight at once for a PORTFOLIO read.
 *
 * Measured, not guessed: firing all 22 (11 assets × 2 safes) at once made MATIC
 * — 21.8s on its own — exceed 30s, so the endpoint contends rather than
 * parallelising. A small window keeps the slow assets under their solo latency
 * while still overlapping the fast ones. The signing path never comes near this:
 * it asks for one or two assets.
 */
const PORTFOLIO_CONCURRENCY = 4;

/** Promise.all with a ceiling on how many run at once. Order is preserved. */
async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/** An asset whose price could not be read. Reported, never silently dropped. */
export interface UnavailableAsset {
  safeAddress: string;
  symbol: string;
  reason: string;
}

/** One asset as the snapshot lists it. No prices, no layer2data — see below. */
interface SnapshotAsset {
  symbol: string;
  address: string;
  algo?: string;
}

interface SnapshotEntry {
  address: string;
  assets?: { assets?: SnapshotAsset[] };
}

class AssetInfoError extends Error {}

function trimSlash(u: string): string {
  return u.replace(/\/+$/, '');
}

async function withTimeout<T>(
  timeoutMs: number,
  label: string,
  run: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await run(controller.signal);
  } catch (e) {
    if ((e as Error)?.name === 'AbortError') {
      throw new AssetInfoError(`${label} timed out after ${timeoutMs}ms`);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The account's safes and the symbols each holds.
 *
 * NOTE the snapshot carries only `{symbol, address, algo}` — no `layer2data`,
 * so it cannot tell a token from a native coin. That is why the gas coin can
 * only be resolved AFTER a priced row comes back (see resolveGas below).
 */
async function fetchSnapshot(deps: AssetInfoDeps, address: string): Promise<SafeSymbols[]> {
  const url =
    `${trimSlash(deps.snapshotUrl)}/snapshot/client` +
    `?env=main&publickey=${encodeURIComponent(address)}`;

  const body = await withTimeout(deps.timeoutMs ?? DEFAULT_TIMEOUT_MS, 'snapshot read', async (signal) => {
    const fetchImpl = deps.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
    const res = await fetchImpl(url, { signal });
    if (!res.ok) {
      throw new AssetInfoError(`snapshot read failed: ${res.status} ${res.statusText}`);
    }
    return res.text();
  });

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new AssetInfoError('snapshot read returned malformed JSON');
  }
  if (!Array.isArray(parsed)) return [];

  return (parsed as SnapshotEntry[])
    .filter((e) => !!e && typeof e === 'object')
    .map((e) => ({
      safeAddress: String(e.address ?? ''),
      assets: Array.isArray(e.assets?.assets) ? e.assets!.assets! : [],
    }));
}

interface SafeSymbols {
  safeAddress: string;
  assets: SnapshotAsset[];
}

/**
 * Price ONE asset for ONE safe. Never batches: batching is precisely what makes
 * the endpoint slow, because it prices the list serially.
 */
async function fetchOne(
  deps: AssetInfoDeps,
  safeAddress: string,
  asset: SnapshotAsset,
): Promise<AssetInfo[]> {
  const url = `${trimSlash(deps.apiServerUrl)}/api/assets/`;
  const label = `asset read (${asset.symbol})`;

  const body = await withTimeout(deps.timeoutMs ?? DEFAULT_TIMEOUT_MS, label, async (signal) => {
    const fetchImpl = deps.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
    const res = await fetchImpl(url, {
      method: 'POST',
      signal,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        env: 'main',
        'api-key': deps.apiKey,
      },
      body: JSON.stringify({
        assets: [{ symbol: asset.symbol, address: asset.address }],
        safe_address: safeAddress,
        isMain: 'true',
      }),
    });
    if (!res.ok) {
      throw new AssetInfoError(`${label} failed: ${res.status} ${res.statusText}`);
    }
    return res.text();
  });

  let parsed: unknown;
  try {
    parsed = body ? JSON.parse(body) : {};
  } catch {
    throw new AssetInfoError(`${label} returned malformed JSON`);
  }
  const list = (parsed as { assets?: unknown })?.assets;
  return Array.isArray(list) ? (list as AssetInfo[]) : [];
}

/**
 * Which snapshot rows to price for a given request.
 *
 * `'*'` means the whole portfolio. Otherwise the match runs through
 * txFeasibility's own `findAsset`, so a request for MATIC finds a safe that
 * reports POL — the ladder resolves it that way, and a narrowed read that
 * resolved it differently would drop the asset being sent.
 */
function select(held: SnapshotAsset[], want: string[] | '*'): SnapshotAsset[] {
  if (want === '*') return held;
  const out: SnapshotAsset[] = [];
  for (const symbol of want) {
    const hit = findAsset(held as unknown as AssetInfo[], symbol) as SnapshotAsset | undefined;
    if (hit && !out.some((a) => a.symbol === hit.symbol)) out.push(hit);
  }
  return out;
}

/**
 * Second pass: a token's fee is paid in its chain's native coin, and R4 fails a
 * transfer whose gas balance is zero. Narrowing to the sent asset alone would
 * drop that check, so any priced row that turns out to be a token pulls its gas
 * coin in as well — one extra small request, and only when it is actually a
 * token. Native coins (the OST case) never reach here.
 */
async function resolveGas(
  deps: AssetInfoDeps,
  safeAddress: string,
  held: SnapshotAsset[],
  priced: AssetInfo[],
  price: (a: SnapshotAsset) => Promise<AssetInfo[]>,
): Promise<AssetInfo[]> {
  const missing = new Set<string>();
  for (const row of priced) {
    const gas = gasSymbolFor(row);
    if (gas && !findAsset(priced, gas)) missing.add(gas);
  }
  if (missing.size === 0) return priced;

  const extra = await Promise.all(
    [...missing].map(async (symbol) => {
      const hit = findAsset(held as unknown as AssetInfo[], symbol) as SnapshotAsset | undefined;
      // Not held at all: leave it absent. R4 reads that as "no gas" and fails
      // the transfer, which is the correct answer — inventing a row would not be.
      return hit ? price(hit) : [];
    }),
  );
  return [...priced, ...extra.flat()];
}

/**
 * Priced asset rows for every safe of `address`, in the same shape
 * `wallet-cli query assets` returns — so `checkFeasibility` and `parseAssets`
 * consume it unchanged.
 *
 * `want` is the narrowing: a list of symbols for the signing path, or `'*'` for
 * the full portfolio. Throws rather than returning an empty list on failure:
 * an empty list is indistinguishable from "this safe holds nothing", which the
 * ladder reports as R1-not-held — an UNOVERRIDABLE will-fail. A read that could
 * not be performed must not masquerade as a balance that was.
 */
export async function fetchSafeAssets(
  deps: AssetInfoDeps,
  address: string,
  want: string[] | '*',
): Promise<SafeAssets[]> {
  return (await collect(deps, address, want, null)).safes;
}

/**
 * The full portfolio, for `wallet_assets`.
 *
 * Differs from the signing path in ONE deliberate way: an asset whose price
 * cannot be read is reported in `unavailable` instead of failing the call. A
 * portfolio is a display read, and losing the other ten assets because MATIC is
 * slow serves nobody. The signing path must NOT do this — there, a missing row
 * is indistinguishable from a zero balance, so it throws.
 *
 * Requests are also throttled (see PORTFOLIO_CONCURRENCY): the endpoint contends
 * under a wide fan-out, which is what made an unthrottled attempt push a 21.8s
 * asset past 30s.
 */
export async function fetchPortfolio(
  deps: AssetInfoDeps,
  address: string,
): Promise<{ safes: SafeAssets[]; unavailable: UnavailableAsset[] }> {
  const unavailable: UnavailableAsset[] = [];
  const safes = (await collect(deps, address, '*', unavailable)).safes;
  return { safes, unavailable };
}

/**
 * Shared body of both reads. `unavailable` non-null switches on skip-on-error
 * (portfolio); null means any failure propagates (signing path).
 */
async function collect(
  deps: AssetInfoDeps,
  address: string,
  want: string[] | '*',
  unavailable: UnavailableAsset[] | null,
): Promise<{ safes: SafeAssets[] }> {
  if (!address.trim()) throw new AssetInfoError('no account address to read assets for');

  const snapshot = await fetchSnapshot(deps, address);

  const safes = await Promise.all(
    snapshot.map(async ({ safeAddress, assets }) => {
      // The safe's real inventory, carried alongside the narrowed rows so R1 can
      // still tell the user what the safe DOES hold (see SafeAssets.heldSymbols).
      const heldSymbols = assets.map((a) => a.symbol).filter(Boolean);

      const selected = select(assets, want);
      // Nothing to price for this safe. Return the row anyway: the ladder
      // distinguishes "no such safe" from "safe holds no X", and swallowing the
      // safe would turn the second into the first.
      if (selected.length === 0) return { safeAddress, assets: [], heldSymbols };

      const price = async (a: SnapshotAsset): Promise<AssetInfo[]> => {
        try {
          return await fetchOne(deps, safeAddress, a);
        } catch (e) {
          if (!unavailable) throw e;
          unavailable.push({ safeAddress, symbol: a.symbol, reason: (e as Error).message });
          return [];
        }
      };

      const priced = unavailable
        ? (await mapLimit(selected, PORTFOLIO_CONCURRENCY, price)).flat()
        : (await Promise.all(selected.map(price))).flat();

      return {
        safeAddress,
        assets: await resolveGas(deps, safeAddress, assets, priced, price),
        heldSymbols,
      };
    }),
  );

  return { safes };
}
