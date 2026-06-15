import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CONCEPTS, conceptsText, lookupConcept } from '../src/core/concepts.js';

test('lookupConcept() with no arg returns the full glossary', () => {
  const all = lookupConcept();
  for (const k of ['profile', 'safe', 'signature-vs-transferid', 'balance-vs-balances-vs-assets']) {
    assert.ok(k in all, `${k} should be present`);
  }
  assert.equal(Object.keys(all).length, Object.keys(CONCEPTS).length);
});

test('lookupConcept(key) returns only that concept', () => {
  const r = lookupConcept('profile');
  assert.deepEqual(Object.keys(r), ['profile']);
  assert.match(r.profile ?? '', /address/i);
});

test('lookupConcept is case- and whitespace-insensitive', () => {
  assert.deepEqual(Object.keys(lookupConcept('  SAFE ')), ['safe']);
});

test('lookupConcept(unknown) returns an error listing known keys', () => {
  const r = lookupConcept('bogus');
  assert.deepEqual(Object.keys(r), ['error']);
  assert.match(r.error ?? '', /Unknown concept "bogus"/);
  assert.match(r.error ?? '', /profile/);
  assert.match(r.error ?? '', /safe/);
});

test('conceptsText() is non-empty and names the core terms', () => {
  const t = conceptsText();
  assert.ok(t.length > 0);
  assert.match(t, /Profile/);
  assert.match(t, /Safe/);
});
