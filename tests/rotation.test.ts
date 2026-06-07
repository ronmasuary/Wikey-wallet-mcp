import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runHmacRotation, mintKey } from '../src/core/rotation.js';

const SSP = fileURLToPath(new URL('./fixtures/fake-ssp-util.mjs', import.meta.url));

function tmp(): string {
  return mkdtempSync(path.join(tmpdir(), 'wmcp-rot-'));
}

test('exit 0 → returns a fresh 64-hex key Buffer', async () => {
  const dir = tmp();
  try {
    const env = { ...process.env };
    delete (env as Record<string, string>).STUB_ROTATE_EXIT;
    process.env.STUB_ROTATE_EXIT = '0';
    const { newKey } = await runHmacRotation({ sspUtil: SSP, nonceFile: path.join(dir, 'n'), currentKey: mintKey() });
    assert.equal(newKey.length, 64); // 64 hex chars as utf8 bytes
    assert.match(newKey.toString('utf8'), /^[0-9a-f]{64}$/);
  } finally {
    delete process.env.STUB_ROTATE_EXIT;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('exit 6 then 0 → retries within grace deadline and succeeds', async () => {
  const dir = tmp();
  const seqFile = path.join(dir, 'seq');
  try {
    process.env.STUB_SEQ = '6,6,0';
    process.env.STUB_SEQ_FILE = seqFile;
    const { newKey } = await runHmacRotation({
      sspUtil: SSP,
      nonceFile: path.join(dir, 'n'),
      currentKey: mintKey(),
      deadlineMs: 5000,
      backoffMs: 20,
    });
    assert.equal(newKey.length, 64);
  } finally {
    delete process.env.STUB_SEQ;
    delete process.env.STUB_SEQ_FILE;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('exit 4 → fatal "SSP unreachable"', async () => {
  const dir = tmp();
  try {
    process.env.STUB_ROTATE_EXIT = '4';
    await assert.rejects(
      runHmacRotation({ sspUtil: SSP, nonceFile: path.join(dir, 'n'), currentKey: mintKey() }),
      /SSP unreachable/,
    );
  } finally {
    delete process.env.STUB_ROTATE_EXIT;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('persistent exit 6 past the deadline → wedged', async () => {
  const dir = tmp();
  try {
    process.env.STUB_ROTATE_EXIT = '6';
    await assert.rejects(
      runHmacRotation({ sspUtil: SSP, nonceFile: path.join(dir, 'n'), currentKey: mintKey(), deadlineMs: 250, backoffMs: 40 }),
      /wedged/,
    );
  } finally {
    delete process.env.STUB_ROTATE_EXIT;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('exit 8 (internal crypto) → fatal with the code', async () => {
  const dir = tmp();
  try {
    process.env.STUB_ROTATE_EXIT = '8';
    await assert.rejects(
      runHmacRotation({ sspUtil: SSP, nonceFile: path.join(dir, 'n'), currentKey: mintKey() }),
      /rotate exit 8/,
    );
  } finally {
    delete process.env.STUB_ROTATE_EXIT;
    rmSync(dir, { recursive: true, force: true });
  }
});
