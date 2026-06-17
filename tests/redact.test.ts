import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact } from '../src/core/redact.js';

const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ3IiwiZXhwIjo5OTk5OTk5OTk5fQ.c2lnbmF0dXJl';

test('scrubs an explicit secret (e.g. a live token / bootstrap password)', () => {
  const out = redact('error near s3cret-bootstrap-pw and tok=' + JWT, ['s3cret-bootstrap-pw', JWT]);
  assert.ok(!out.includes('s3cret-bootstrap-pw'));
  assert.ok(!out.includes(JWT));
  assert.ok(out.includes('[REDACTED]'));
});

test('blanket-scrubs a JWT even when not passed as an explicit secret', () => {
  const out = redact(`gateway said: Bearer ${JWT} rejected`);
  assert.ok(!out.includes(JWT), 'JWT pattern catches an unexpected token leak');
  assert.match(out, /Bearer \[REDACTED\] rejected/);
});

test('still scrubs a 64-hex token and leaves ordinary text intact', () => {
  const hex = 'a'.repeat(64);
  const out = redact(`key ${hex} done; nothing else changes here`);
  assert.ok(!out.includes(hex));
  assert.ok(out.includes('nothing else changes here'));
});

test('undefined/empty explicit secrets are ignored (no crash, no empty-split)', () => {
  const out = redact('plain text', [undefined, '']);
  assert.equal(out, 'plain text');
});
