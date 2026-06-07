#!/usr/bin/env node
// Stub for `ssp-util` used in tests. Handles `proof` and `rotate`.
//
// Env knobs:
//   STUB_ROTATE_EXIT   fixed exit code for `rotate`
//   STUB_SEQ           comma-separated exit codes for successive `rotate` calls
//   STUB_SEQ_FILE      counter file backing STUB_SEQ
//   STUB_HANG=1        never exit (per-attempt timeout testing)
//   STUB_CONCUR_FILE   append START/END markers around a 120ms window (serialization test)
import fs from 'node:fs';

const mode = process.argv[2];

// drain stdin (the key / old+new keys arrive here)
const chunks = [];
process.stdin.on('data', (c) => chunks.push(c));

async function withConcurrencyMarker(fn) {
  const file = process.env.STUB_CONCUR_FILE;
  if (file) fs.appendFileSync(file, `START ${mode} ${Date.now()}\n`);
  await new Promise((r) => setTimeout(r, file ? 120 : 0));
  const res = await fn();
  if (file) fs.appendFileSync(file, `END ${mode} ${Date.now()}\n`);
  return res;
}

process.stdin.on('end', async () => {
  if (process.env.STUB_HANG === '1') {
    setTimeout(() => {}, 60_000);
    return;
  }

  if (mode === 'proof') {
    await withConcurrencyMarker(async () => process.stdout.write('PROOF-' + Date.now()));
    process.exit(0);
  }

  if (mode === 'rotate') {
    const code = await withConcurrencyMarker(async () => resolveRotateExit());
    process.exit(code);
  }

  process.stderr.write(`unknown mode: ${mode}\n`);
  process.exit(1);
});

function resolveRotateExit() {
  if (process.env.STUB_SEQ) {
    const seq = process.env.STUB_SEQ.split(',').map((s) => parseInt(s, 10));
    const file = process.env.STUB_SEQ_FILE;
    let i = 0;
    if (file) {
      try {
        i = parseInt(fs.readFileSync(file, 'utf8').trim(), 10) || 0;
      } catch {
        i = 0;
      }
      fs.writeFileSync(file, String(i + 1));
    }
    return seq[Math.min(i, seq.length - 1)] ?? 0;
  }
  return parseInt(process.env.STUB_ROTATE_EXIT ?? '0', 10);
}
