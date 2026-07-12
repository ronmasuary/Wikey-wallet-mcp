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
  const query = async () => ''; // keys list empty
  const r = await buildGettingStarted(query, 'wikey-wallet-mcp');
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
    if (args[0] === 'keys' && args[1] === 'list') return ADDR;
    if (args[0] === 'config') return ADDR; // config get user.address
    if (args[1] === 'balance') return '{"data":{"balances":[{"amount":"5000"}]}}';
    if (args[1] === 'snapshot')
      return JSON.stringify({ data: { snapshot: [{ address: SAFE, name: 'alice', groups: [] }] } });
    return '';
  };
  const r = await buildGettingStarted(query, 'wikey-wallet-mcp');
  assert.equal(r.stage, 'ready');
  assert.equal(r.safes[0]?.address, SAFE);
  assert.ok(r.capabilities && r.capabilities.length > 0);
});

test('buildGettingStarted: funded key without a safe points at create-safe', async () => {
  const query = async (args: string[]): Promise<string> => {
    if (args[0] === 'keys' && args[1] === 'list') return ADDR;
    if (args[0] === 'config') return ADDR;
    if (args[1] === 'balance') return '{"data":{"balances":[{"amount":"5000"}]}}';
    if (args[1] === 'snapshot') throw new Error('no profile on-chain yet');
    return '';
  };
  const r = await buildGettingStarted(query, 'wikey-wallet-mcp');
  assert.equal(r.stage, 'no-safe');
  assert.equal(r.next[0]?.tool, 'wallet_tx_create_safe');
});
