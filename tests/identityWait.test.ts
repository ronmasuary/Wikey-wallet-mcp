import { test } from 'node:test';
import assert from 'node:assert/strict';

import { waitForWalletIdentity } from '../src/core/idp/identity.js';
import type { Cfg } from '../src/core/idp/config.js';

// Minimal cfg — only the snapshot fields matter here; the fetch is stubbed.
const CFG = { snapshotNode: 'node.test', snapshotSecure: true, env: 'test' } as Cfg;
const ACCOUNT = 'omnistar1acct0000000000000';

async function withStubFetch(
  handler: (url: string) => Response,
  fn: (calls: number[]) => Promise<void>,
): Promise<void> {
  const saved = globalThis.fetch;
  const calls: number[] = [];
  const t0 = Date.now();
  globalThis.fetch = (async (url: string | URL) => {
    calls.push(Date.now() - t0);
    return handler(String(url));
  }) as typeof fetch;
  try {
    await fn(calls);
  } finally {
    globalThis.fetch = saved;
  }
}

const notFound = (): Response => new Response('nope', { status: 404 });

test('waitForWalletIdentity holds off the first poll until initialDelayMs', async () => {
  await withStubFetch(notFound, async (calls) => {
    await assert.rejects(
      waitForWalletIdentity(CFG, ACCOUNT, { attempts: 1, intervalMs: 5, initialDelayMs: 120 }),
      /did not become queryable in time/,
    );
    assert.equal(calls.length, 1, 'attempts:1 → exactly one poll');
    const first = calls[0] ?? -1;
    assert.ok(first >= 110, `first poll at ${first}ms — must wait out the initial delay`);
  });
});

test('waitForWalletIdentity re-throws the real snapshot cause, not a bare timeout', async () => {
  await withStubFetch(
    () => new Response('boom', { status: 500 }),
    async () => {
      await assert.rejects(
        waitForWalletIdentity(CFG, ACCOUNT, { attempts: 2, intervalMs: 1, initialDelayMs: 0 }),
        /HTTP 500/,
      );
    },
  );
});

test('waitForWalletIdentity does not sleep after the final attempt', async () => {
  await withStubFetch(notFound, async () => {
    const t0 = Date.now();
    await assert.rejects(
      waitForWalletIdentity(CFG, ACCOUNT, { attempts: 3, intervalMs: 60, initialDelayMs: 0 }),
      /did not become queryable/,
    );
    // 3 attempts → at most 2 gaps (~120ms). A trailing sleep would push it past 180ms.
    const elapsed = Date.now() - t0;
    assert.ok(elapsed < 180, `took ${elapsed}ms — a sleep after the last attempt is wasted time`);
  });
});
