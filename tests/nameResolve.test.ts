import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseHelperLines, pickResolvedAddress } from '../src/core/signing.js';
import { isChainAddress } from '../src/core/accounts.js';

const A1 = 'omnistar1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const A2 = 'omnistar1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

// ─── isChainAddress ──────────────────────────────────────────────────────────

test('isChainAddress accepts an address and rejects names', () => {
  assert.equal(isChainAddress(A1), true);
  assert.equal(isChainAddress(`  ${A1}  `), true);
  assert.equal(isChainAddress('createTest1'), false);
  assert.equal(isChainAddress('alice@acme'), false);
  // A name that merely CONTAINS an address must not pass — it is not one.
  assert.equal(isChainAddress(`helper ${A1}`), false);
});

// ─── parseHelperLines ────────────────────────────────────────────────────────

test('parseHelperLines reads the numbered displayHelpers rows', () => {
  const out = parseHelperLines(
    `Current helpers:\n  1. wikeyMCP (${A1})\n  2. sponsorTest7@organization_xyz (${A2})\n`,
  );
  assert.deepEqual(out, [
    { name: 'wikeyMCP', address: A1 },
    { name: 'sponsorTest7@organization_xyz', address: A2 },
  ]);
});

test('parseHelperLines returns [] for the empty-list message', () => {
  assert.deepEqual(parseHelperLines('\nNo helpers configured.\n'), []);
});

// ─── pickResolvedAddress ─────────────────────────────────────────────────────

test('resolves via set difference when a new row appears', () => {
  const before = `Current helpers:\n  1. wikeyMCP (${A1})\n`;
  const after = `${before}Enter helper address or username: Current helpers:\n  1. wikeyMCP (${A1})\n  2. createTest1 (${A2})\n`;
  assert.equal(pickResolvedAddress(before, after, 'createTest1'), A2);
});

test('resolves from an empty starting list', () => {
  const before = '\nNo helpers configured.\n';
  const after = `${before}Current helpers:\n  1. createTest1 (${A2})\n`;
  assert.equal(pickResolvedAddress(before, after, 'createTest1'), A2);
});

test('resolves via the already-a-helper message, where no new row is printed', () => {
  const before = `Current helpers:\n  1. createTest1 (${A2})\n`;
  const after = `${before}Helper ${A2} is already in the list.\nCurrent helpers:\n  1. createTest1 (${A2})\n`;
  assert.equal(pickResolvedAddress(before, after, 'createTest1'), A2);
});

test('set difference survives the CLI printing the address as the name', () => {
  // resolveHelperName falls back to the address when the profile lookup fails.
  const before = `Current helpers:\n  1. wikeyMCP (${A1})\n`;
  const after = `${before}Current helpers:\n  1. wikeyMCP (${A1})\n  2. ${A2} (${A2})\n`;
  assert.equal(pickResolvedAddress(before, after, 'createTest1'), A2);
});

test('falls back to a name match when before/after cannot be differenced', () => {
  const after = `Current helpers:\n  1. wikeyMCP (${A1})\n  2. createTest1 (${A2})\n`;
  assert.equal(pickResolvedAddress(after, after, 'CREATETEST1'), A2);
});

test('returns null when nothing resolved — never a silent empty answer', () => {
  const before = `Current helpers:\n  1. wikeyMCP (${A1})\n`;
  assert.equal(pickResolvedAddress(before, before, 'createTest1'), null);
});
