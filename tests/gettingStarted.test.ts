import { test } from 'node:test';
import assert from 'node:assert/strict';

import { classifyAccount, buildGettingStarted } from '../src/core/gettingStarted.js';
import { extractAddresses, parseFunded } from '../src/core/accounts.js';

const ADDR = 'omnistar1abcdef0123456789';
const ADDR2 = 'omnistar1zzzzzz9876543210';
const SAFE = 'omnistar1safe0000000000000';

test('extractAddresses dedups omnistar1 addresses', () => {
  assert.deepEqual(extractAddresses(`${ADDR} foo ${ADDR}`), [ADDR]);
  assert.deepEqual(extractAddresses('nothing here'), []);
});

test('parseFunded handles balances envelope, bare denom, and unknown', () => {
  assert.equal(parseFunded('{"data":{"balances":[{"denom":"nost","amount":"1000"}]}}'), true);
  assert.equal(parseFunded('{"data":{"balances":[{"denom":"nost","amount":"0"}]}}'), false);
  assert.equal(parseFunded('1000nost'), true);
  assert.equal(parseFunded('garbage'), undefined);
});

test('classifyAccount walks one account through the onboarding sequence', () => {
  assert.equal(classifyAccount({ address: ADDR, funded: false, safes: [] }), 'unfunded');
  assert.equal(classifyAccount({ address: ADDR, funded: true, safes: [] }), 'no-safe');
  assert.equal(
    classifyAccount({ address: ADDR, funded: true, safes: [{ address: SAFE, name: 'me' }] }),
    'ready',
  );
});

test('classifyAccount treats unknown funding (no safe) as no-safe, not stuck', () => {
  assert.equal(classifyAccount({ address: ADDR, funded: undefined, safes: [] }), 'no-safe');
});

// ── query fakes ───────────────────────────────────────────────────────────────
// listAccounts probes profile/balance/snapshot per --address, so the fakes are
// keyed the same way.

function queryFor(state: Record<string, { name?: string; funded?: boolean; safe?: string }>) {
  return async (args: string[]): Promise<string> => {
    const addr = args[args.indexOf('--address') + 1] ?? '';
    const s = state[addr];
    if (!s) throw new Error('unknown account');
    if (args[1] === 'profile') {
      if (!s.name) throw new Error('no profile on-chain yet');
      return JSON.stringify({ data: { profile: { name: s.name } } });
    }
    if (args[1] === 'balance') {
      return JSON.stringify({ data: { balances: [{ denom: 'nost', amount: s.funded ? '5000' : '0' }] } });
    }
    if (args[1] === 'snapshot') {
      if (!s.safe) throw new Error('no profile on-chain yet');
      return JSON.stringify({ data: { snapshot: [{ address: s.safe, name: s.name ?? '', groups: [] }] } });
    }
    return '';
  };
}

test('buildGettingStarted: brand-new install classifies no-key and names the create tool', async () => {
  const r = await buildGettingStarted(async () => '', 'wikey-wallet-mcp', () => []);
  assert.equal(r.stage, 'no-key');
  assert.equal(r.keyCount, 0);
  assert.deepEqual(r.accounts, []);
  assert.equal(r.next[0]?.tool, 'wallet_keys_create');
  // setDefault is gone — creating a key no longer changes global signing identity.
  assert.equal(r.next[0]?.args, undefined);
  assert.equal(r.capabilities, undefined);
});

test('buildGettingStarted: one ready key reports its stage at top level', async () => {
  const q = queryFor({ [ADDR]: { name: 'alice', funded: true, safe: SAFE } });
  const r = await buildGettingStarted(q, 'wikey-wallet-mcp', () => [ADDR]);
  assert.equal(r.stage, 'ready');
  assert.equal(r.accounts[0]?.safes[0]?.address, SAFE);
  assert.ok(r.capabilities && r.capabilities.length > 0);
});

test('buildGettingStarted: funded key without a safe points at create-safe FOR THAT KEY', async () => {
  const q = queryFor({ [ADDR]: { funded: true } });
  const r = await buildGettingStarted(q, 'wikey-wallet-mcp', () => [ADDR]);
  assert.equal(r.stage, 'no-safe');
  assert.equal(r.next[0]?.tool, 'wallet_tx_create_safe');
  // The step names the key, so following it cannot create the safe on another one.
  assert.equal((r.next[0]?.args as { account?: string })?.account, ADDR);
});

test('buildGettingStarted: counts keys from the keystore even when the signer is DOWN', async () => {
  // Regression: a `keys list` that throws (signing-server unreachable) must NOT
  // be misread as an empty wallet. Key count comes from the keystore directory,
  // so existing keys are still seen and the stage is never a false no-key.
  const inner = queryFor({ [ADDR]: { name: 'alice', funded: true, safe: SAFE } });
  const q = async (args: string[]): Promise<string> => {
    if (args[0] === 'keys') throw new Error('fetch failed'); // signer down
    return inner(args);
  };
  const r = await buildGettingStarted(q, 'wikey-wallet-mcp', () => [ADDR]);
  assert.equal(r.keyCount, 1);
  assert.equal(r.stage, 'ready');
});

// ── recovery-pending ──────────────────────────────────────────────────────────
// Recovery is open-ended: independent helpers approve on their own schedule, so
// a request can sit outstanding for weeks. Throughout that window the guide must
// NOT tell the user to create a safe — the account already exists, and creating
// one makes a second, separate account.

const REC = { newAddress: ADDR, username: 'alice@acme', requestedAt: new Date().toISOString() };

test('classifyAccount: a pending recovery outranks no-safe', () => {
  assert.equal(classifyAccount({ address: ADDR, funded: true, safes: [], pendingRecovery: REC }), 'recovery-pending');
});

test('classifyAccount: a visible safe ends a pending recovery (completion signal)', () => {
  assert.equal(
    classifyAccount({
      address: ADDR,
      funded: true,
      safes: [{ address: SAFE, name: 'alice' }],
      pendingRecovery: REC,
    }),
    'ready',
  );
});

test('buildGettingStarted: mid-recovery NEVER recommends create-safe', async () => {
  const q = queryFor({ [ADDR]: { funded: true } });
  const r = await buildGettingStarted(q, 'wikey-wallet-mcp', () => [ADDR], {
    load: () => REC,
    clear: () => {},
  });
  assert.equal(r.stage, 'recovery-pending');
  assert.equal(r.accounts[0]?.pendingRecovery?.username, 'alice@acme');
  // The invariant this whole change exists to protect.
  assert.ok(
    !r.next.some((s) => s.tool === 'wallet_tx_create_safe'),
    'a pending recovery must never surface wallet_tx_create_safe',
  );
  assert.equal(r.next[0]?.tool, 'wallet_recovery_helpers');
  assert.deepEqual(r.next[0]?.args, { address: 'alice@acme' });
});

test('buildGettingStarted: recovery completing clears the breadcrumb exactly once', async () => {
  const q = queryFor({ [ADDR]: { name: 'alice', funded: true, safe: SAFE } });
  const cleared: string[] = [];
  const r = await buildGettingStarted(q, 'wikey-wallet-mcp', () => [ADDR], {
    load: () => REC,
    clear: (a) => cleared.push(a),
  });
  assert.equal(r.stage, 'ready');
  assert.deepEqual(cleared, [ADDR]);
  assert.equal(r.accounts[0]?.pendingRecovery, undefined, 'a completed recovery is no longer reported as pending');
});

test('buildGettingStarted: no-safe warns against create-safe when recovering', async () => {
  // Stateless safety net: a recovery requested on ANOTHER machine leaves no
  // local breadcrumb, so this stage is still reachable for an existing account.
  const q = queryFor({ [ADDR]: { funded: true } });
  const r = await buildGettingStarted(q, 'wikey-wallet-mcp', () => [ADDR]);
  assert.equal(r.stage, 'no-safe');
  assert.equal(r.next[0]?.tool, 'wallet_tx_create_safe');
  assert.ok(
    r.next.some((s) => s.tool === 'wallet_recovery_helpers' && /do not create a safe/i.test(s.action)),
    'no-safe must warn a recovering user not to create a safe',
  );
});

test('buildGettingStarted: omitting the recovery accessor preserves old behaviour', async () => {
  const q = queryFor({ [ADDR]: { funded: true } });
  const r = await buildGettingStarted(q, 'wikey-wallet-mcp', () => [ADDR]);
  assert.equal(r.stage, 'no-safe');
  assert.equal(r.accounts[0]?.pendingRecovery, undefined);
});

// ── several keys ──────────────────────────────────────────────────────────────

test('several keys: no single stage is invented, and each account keeps its own', async () => {
  const q = queryFor({
    [ADDR]: { name: 'alice', funded: true, safe: SAFE }, // ready
    [ADDR2]: { funded: false }, // unfunded
  });
  const r = await buildGettingStarted(q, 'wikey-wallet-mcp', () => [ADDR, ADDR2]);

  assert.equal(r.stage, 'multiple-accounts');
  assert.equal(r.keyCount, 2);
  assert.equal(r.accounts.find((a) => a.address === ADDR)?.stage, 'ready');
  assert.equal(r.accounts.find((a) => a.address === ADDR2)?.stage, 'unfunded');
  assert.equal(r.next[0]?.tool, 'wallet_accounts', 'first move is to ask the user which account');
  assert.match(r.summary, /ASK THE USER/);
});

test("several keys: a ready account never masks another's unfinished recovery", async () => {
  // The exact shape sponsor onboarding produces mid-recovery: one working
  // account plus a fresh key waiting on helpers. Collapsing these to a single
  // "ready" would report the recovery as done.
  const q = queryFor({
    [ADDR]: { name: 'alice', funded: true, safe: SAFE },
    [ADDR2]: { funded: true },
  });
  const r = await buildGettingStarted(q, 'wikey-wallet-mcp', () => [ADDR, ADDR2], {
    load: (a) => (a === ADDR2 ? { ...REC, newAddress: ADDR2 } : null),
    clear: () => {},
  });

  assert.equal(r.stage, 'multiple-accounts');
  assert.notEqual(r.stage as string, 'ready');
  assert.equal(r.accounts.find((a) => a.address === ADDR2)?.stage, 'recovery-pending');
  assert.match(r.summary, new RegExp(`recovery is still in progress on ${ADDR2}`));
});
