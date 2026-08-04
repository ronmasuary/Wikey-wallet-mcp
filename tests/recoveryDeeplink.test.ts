import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildRecoveryDeeplink,
  parseRecoveryDeeplink,
  RECOVERY_DEEPLINK_BASE,
} from '../src/core/recoveryDeeplink.js';

test('build → parse round-trips new account + @-handle account name', () => {
  const newAccount = 'omnistar1e2eq2l8wesg6n6vx9a4fnr52w09l6hedgnjwvh';
  const accountName = 'sponsorTest4@organization_xyz';
  const link = buildRecoveryDeeplink({ newAccount, accountName });

  assert.ok(link.startsWith(`${RECOVERY_DEEPLINK_BASE}?`));
  assert.ok(link.includes('t=recover'));

  const parts = parseRecoveryDeeplink(link);
  assert.equal(parts.type, 'recover');
  assert.equal(parts.newAccount, newAccount);
  assert.equal(parts.accountName, accountName);
});

test('parse rejects a link that is not t=recover', () => {
  const link = `${RECOVERY_DEEPLINK_BASE}?t=setup&pk=omnistar1abc&tn=alice`;
  assert.throws(() => parseRecoveryDeeplink(link), /t=recover/);
});

test('parse rejects a link missing pk or tn', () => {
  assert.throws(
    () => parseRecoveryDeeplink(`${RECOVERY_DEEPLINK_BASE}?t=recover&tn=alice`),
    /missing pk/,
  );
  assert.throws(
    () => parseRecoveryDeeplink(`${RECOVERY_DEEPLINK_BASE}?t=recover&pk=omnistar1abc`),
    /missing tn/,
  );
});

test('parse rejects a non-URL string', () => {
  assert.throws(() => parseRecoveryDeeplink('not a url'), /valid recovery deeplink/);
});

test('build requires both fields', () => {
  assert.throws(() => buildRecoveryDeeplink({ newAccount: '', accountName: 'a' }), /newAccount/);
  assert.throws(() => buildRecoveryDeeplink({ newAccount: 'omnistar1abc', accountName: '' }), /accountName/);
});
