import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isLockedConfigKey,
  assertConfigSetAllowed,
  lockedConfigCategory,
  configLockDisabled,
} from '../src/core/configLock.js';

test('H10: signer.url is locked', () => {
  assert.ok(isLockedConfigKey('signer.url'));
  assert.equal(lockedConfigCategory('signer.url'), 'signer.*');
  assert.throws(() => assertConfigSetAllowed('signer.url'), /locked/);
});

test('H10: any signer.* key is locked', () => {
  assert.ok(isLockedConfigKey('signer.timeout'));
  assert.throws(() => assertConfigSetAllowed('signer.apiKey'), /locked/);
});

test('H10: *.url, apiKey, kek*, keystore*, user.* are locked', () => {
  for (const k of ['wikeyAuthUrl.url', 'apiKey', 'apikey', 'kek-provider', 'kekProvider', 'keystore', 'keystoreType', 'user.address']) {
    assert.ok(isLockedConfigKey(k), `${k} should be locked`);
    assert.throws(() => assertConfigSetAllowed(k), /locked/, `${k} should throw`);
  }
});

test('H10: case-insensitive and trims', () => {
  assert.ok(isLockedConfigKey('  SIGNER.URL  '));
  assert.ok(isLockedConfigKey('KEYSTORE'));
});

test('H10: unrelated keys pass through', () => {
  for (const k of ['feePriority', 'defaultChain', 'theme', 'verbose']) {
    assert.equal(isLockedConfigKey(k), false, `${k} should pass`);
    assert.doesNotThrow(() => assertConfigSetAllowed(k));
  }
});

test('WIKEY_UNLOCK_CONFIG opts out of the lock', (t) => {
  const prev = process.env.WIKEY_UNLOCK_CONFIG;
  t.after(() => {
    if (prev === undefined) delete process.env.WIKEY_UNLOCK_CONFIG;
    else process.env.WIKEY_UNLOCK_CONFIG = prev;
  });

  for (const v of ['1', 'true', 'yes', 'on', 'TRUE', '  On  ']) {
    process.env.WIKEY_UNLOCK_CONFIG = v;
    assert.equal(configLockDisabled(), true, `${JSON.stringify(v)} should disable the lock`);
    // Even the most dangerous keys now pass the gate.
    assert.doesNotThrow(() => assertConfigSetAllowed('signer.url'));
    assert.doesNotThrow(() => assertConfigSetAllowed('user.address'));
    assert.doesNotThrow(() => assertConfigSetAllowed('keystore'));
    // Classifiers still report the key as security-critical (enforcement is what's overridden).
    assert.ok(isLockedConfigKey('signer.url'));
  }

  for (const v of ['0', 'false', 'no', '', 'off']) {
    process.env.WIKEY_UNLOCK_CONFIG = v;
    assert.equal(configLockDisabled(), false, `${JSON.stringify(v)} should keep the lock on`);
    assert.throws(() => assertConfigSetAllowed('signer.url'), /locked/);
  }
});
