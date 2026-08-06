import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyStage,
  extractAddresses,
  parseDefaultAddress,
  parseFunded,
  buildGettingStarted,
} from '../src/core/gettingStarted.js';

const ADDR = 'omnistar1abcdef0123456789';
const SAFE = 'omnistar1safe0000000000000';

test('extractAddresses dedups omnistar1 addresses', () => {
  assert.deepEqual(extractAddresses(`${ADDR} foo ${ADDR}`), [ADDR]);
  assert.deepEqual(extractAddresses('nothing here'), []);
});

test('parseDefaultAddress reads bare and enveloped output', () => {
  assert.equal(parseDefaultAddress(ADDR), ADDR);
  assert.equal(parseDefaultAddress(`{"success":true,"data":{"user":{"address":"${ADDR}"}}}`), ADDR);
  assert.equal(parseDefaultAddress(''), undefined);
});

test('parseFunded handles balances envelope, bare denom, and unknown', () => {
  assert.equal(parseFunded('{"data":{"balances":[{"denom":"nost","amount":"1000"}]}}'), true);
  assert.equal(parseFunded('{"data":{"balances":[{"denom":"nost","amount":"0"}]}}'), false);
  assert.equal(parseFunded('1000nost'), true);
  assert.equal(parseFunded('garbage'), undefined);
});

test('classifyStage walks the onboarding sequence', () => {
  assert.equal(classifyStage({ keyCount: 0, safes: [] }), 'no-key');
  assert.equal(classifyStage({ keyCount: 1, safes: [] }), 'no-default');
  assert.equal(classifyStage({ keyCount: 1, defaultKey: ADDR, funded: false, safes: [] }), 'unfunded');
  assert.equal(classifyStage({ keyCount: 1, defaultKey: ADDR, funded: true, safes: [] }), 'no-safe');
  assert.equal(
    classifyStage({ keyCount: 1, defaultKey: ADDR, funded: true, safes: [{ address: SAFE, name: 'me' }] }),
    'ready',
  );
});

test('classifyStage treats unknown funding (no safe) as no-safe, not stuck', () => {
  assert.equal(classifyStage({ keyCount: 1, defaultKey: ADDR, funded: undefined, safes: [] }), 'no-safe');
});

test('buildGettingStarted: brand-new install classifies no-key and names the create tool', async () => {
  const query = async () => '';
  const r = await buildGettingStarted(query, 'wikey-wallet-mcp', () => []); // empty keystore
  assert.equal(r.stage, 'no-key');
  assert.equal(r.keyCount, 0);
  const [firstStep] = r.next;
  assert.ok(firstStep);
  assert.equal(firstStep.tool, 'wallet_keys_create');
  assert.deepEqual(firstStep.args, { setDefault: true });
  assert.equal(r.capabilities, undefined);
});

test('buildGettingStarted: ready state lists capabilities', async () => {
  const query = async (args: string[]): Promise<string> => {
    if (args[0] === 'config') return ADDR; // config get user.address
    if (args[1] === 'balance') return '{"data":{"balances":[{"amount":"5000"}]}}';
    if (args[1] === 'snapshot')
      return JSON.stringify({ data: { snapshot: [{ address: SAFE, name: 'alice', groups: [] }] } });
    return '';
  };
  const r = await buildGettingStarted(query, 'wikey-wallet-mcp', () => [ADDR]);
  assert.equal(r.stage, 'ready');
  assert.equal(r.safes[0]?.address, SAFE);
  assert.ok(r.capabilities && r.capabilities.length > 0);
});

test('buildGettingStarted: funded key without a safe points at create-safe', async () => {
  const query = async (args: string[]): Promise<string> => {
    if (args[0] === 'config') return ADDR;
    if (args[1] === 'balance') return '{"data":{"balances":[{"amount":"5000"}]}}';
    if (args[1] === 'snapshot') throw new Error('no profile on-chain yet');
    return '';
  };
  const r = await buildGettingStarted(query, 'wikey-wallet-mcp', () => [ADDR]);
  assert.equal(r.stage, 'no-safe');
  assert.equal(r.next[0]?.tool, 'wallet_tx_create_safe');
});

test('buildGettingStarted: counts keys from the keystore even when the signer is DOWN', async () => {
  // Regression: a `keys list` that throws (signing-server unreachable) must NOT
  // be misread as an empty wallet. Key count comes from the keystore directory,
  // so existing keys are still seen and the stage is never a false no-key.
  const query = async (args: string[]): Promise<string> => {
    if (args[0] === 'keys') throw new Error('fetch failed'); // signer down
    if (args[0] === 'config') return ADDR; // local config read still works
    if (args[1] === 'balance') return '{"data":{"balances":[{"amount":"5000"}]}}';
    if (args[1] === 'snapshot')
      return JSON.stringify({ data: { snapshot: [{ address: SAFE, name: 'alice', groups: [] }] } });
    return '';
  };
  const r = await buildGettingStarted(query, 'wikey-wallet-mcp', () => [ADDR]);
  assert.equal(r.keyCount, 1);
  assert.notEqual(r.stage, 'no-key');
  assert.equal(r.stage, 'ready');
});

// ── recovery-pending ──────────────────────────────────────────────────────────
// Recovery is open-ended: independent helpers approve on their own schedule, so
// a request can sit outstanding for weeks. Throughout that window the guide must
// NOT tell the user to create a safe — the account already exists, and creating
// one makes a second, separate account.

const REC = { newAddress: ADDR, username: 'alice@acme', requestedAt: new Date().toISOString() };

/** Funded default key whose account is not (yet) visible on-chain. */
const noSafeQuery = async (args: string[]): Promise<string> => {
  if (args[0] === 'config') return ADDR;
  if (args[1] === 'balance') return '{"data":{"balances":[{"amount":"5000"}]}}';
  if (args[1] === 'snapshot') throw new Error('no profile on-chain yet');
  return '';
};

test('classifyStage: a pending recovery outranks no-safe', () => {
  assert.equal(
    classifyStage({ keyCount: 1, defaultKey: ADDR, funded: true, safes: [], pendingRecovery: REC }),
    'recovery-pending',
  );
});

test('classifyStage: a visible safe ends a pending recovery (completion signal)', () => {
  assert.equal(
    classifyStage({
      keyCount: 1,
      defaultKey: ADDR,
      funded: true,
      safes: [{ address: SAFE, name: 'alice' }],
      pendingRecovery: REC,
    }),
    'ready',
  );
});

test('buildGettingStarted: mid-recovery NEVER recommends create-safe', async () => {
  const r = await buildGettingStarted(noSafeQuery, 'wikey-wallet-mcp', () => [ADDR], {
    load: () => REC,
    clear: () => {},
  });
  assert.equal(r.stage, 'recovery-pending');
  assert.equal(r.pendingRecovery?.username, 'alice@acme');
  // The invariant this whole change exists to protect.
  assert.ok(
    !r.next.some((s) => s.tool === 'wallet_tx_create_safe'),
    'a pending recovery must never surface wallet_tx_create_safe',
  );
  assert.equal(r.next[0]?.tool, 'wallet_recovery_helpers');
  assert.deepEqual(r.next[0]?.args, { address: 'alice@acme' });
});

test('buildGettingStarted: recovery completing clears the breadcrumb exactly once', async () => {
  const readyQuery = async (args: string[]): Promise<string> => {
    if (args[0] === 'config') return ADDR;
    if (args[1] === 'balance') return '{"data":{"balances":[{"amount":"5000"}]}}';
    if (args[1] === 'snapshot')
      return JSON.stringify({ data: { snapshot: [{ address: SAFE, name: 'alice', groups: [] }] } });
    return '';
  };
  const cleared: string[] = [];
  const r = await buildGettingStarted(readyQuery, 'wikey-wallet-mcp', () => [ADDR], {
    load: () => REC,
    clear: (a) => cleared.push(a),
  });
  assert.equal(r.stage, 'ready');
  assert.deepEqual(cleared, [ADDR]);
  assert.equal(r.pendingRecovery, undefined, 'a completed recovery is no longer reported as pending');
});

test('buildGettingStarted: no-safe warns against create-safe when recovering', async () => {
  // Stateless safety net: a recovery requested on ANOTHER machine leaves no
  // local breadcrumb, so this stage is still reachable for an existing account.
  const r = await buildGettingStarted(noSafeQuery, 'wikey-wallet-mcp', () => [ADDR]);
  assert.equal(r.stage, 'no-safe');
  assert.equal(r.next[0]?.tool, 'wallet_tx_create_safe');
  assert.ok(
    r.next.some((s) => s.tool === 'wallet_recovery_helpers' && /do not create a safe/i.test(s.action)),
    'no-safe must warn a recovering user not to create a safe',
  );
});

test('buildGettingStarted: omitting the recovery accessor preserves old behaviour', async () => {
  const r = await buildGettingStarted(noSafeQuery, 'wikey-wallet-mcp', () => [ADDR]);
  assert.equal(r.stage, 'no-safe');
  assert.equal(r.pendingRecovery, undefined);
});
