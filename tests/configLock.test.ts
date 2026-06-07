import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isLockedConfigKey, assertConfigSetAllowed, lockedConfigCategory } from '../src/core/configLock.js';

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
