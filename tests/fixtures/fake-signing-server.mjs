#!/usr/bin/env node
// Stub for `signing-server`. Binds 127.0.0.1:STUB_PORT and stays alive until
// killed. Records its startup (one line per spawn) to STUB_SPAWN_LOG so tests
// can assert exactly-one-spawn (H8). The HMAC key arrives via SSP_HMAC_KEY env
// (never argv) — we deliberately do NOT print it.
//
// KEK-failure simulation (Phase 1 auto-fallback). The MCP appends
// `-kek-provider auto|env` to argv. To mimic real SSP:
//   STUB_KEK_FAIL=stdout  → when spawned with `-kek-provider auto`, print the
//       no-KEK marker to STDOUT (mirroring SSP's slog-JSON-on-os.Stdout) and
//       exit non-zero WITHOUT binding. When later spawned with `-kek-provider
//       env`, bind normally (the software retry succeeds).
//   STUB_KEK_FAIL=stderr  → same but the marker is printed to STDERR (proves
//       both streams are scanned).
//   STUB_BOOT_FAIL=1      → exit non-zero with a NON-KEK message on stderr,
//       regardless of provider (a failure that must NOT trigger fallback).
import net from 'node:net';
import fs from 'node:fs';

const port = parseInt(process.env.STUB_PORT ?? '8080', 10);
const argv = process.argv.slice(2);
const provider = (() => {
  const i = argv.indexOf('-kek-provider');
  return i >= 0 ? argv[i + 1] : null;
})();

if (process.env.STUB_SPAWN_LOG) {
  const sspkek = process.env.SSP_KEK ? 'set' : 'unset';
  fs.appendFileSync(
    process.env.STUB_SPAWN_LOG,
    `spawn pid=${process.pid} port=${port} kek=${provider} sspkek=${sspkek}\n`,
  );
}

const MARKER =
  'no usable KEK provider in -spawned-by-agent mode: no hardware-backed provider is available';

if (process.env.STUB_BOOT_FAIL === '1') {
  process.stderr.write('signing-server: bind: address already in use (not a KEK problem)\n');
  process.exit(1);
}

const kekFail = process.env.STUB_KEK_FAIL; // 'stdout' | 'stderr' | undefined
if (kekFail && provider === 'auto') {
  // Mirror SSP: the failure is logged as a JSON line; we wrap the marker in a
  // JSON-escaped "error" value so the substring match is exercised realistically.
  const line = JSON.stringify({ level: 'ERROR', msg: 'failed to build key store', error: MARKER }) + '\n';
  if (kekFail === 'stderr') process.stderr.write(line);
  else process.stdout.write(line);
  process.exit(1);
}

const server = net.createServer((s) => s.end());
const delay = parseInt(process.env.STUB_SPAWN_DELAY ?? '0', 10);
setTimeout(() => server.listen(port, '127.0.0.1'), delay);

// Stay alive; default SIGTERM handling exits the process.
setInterval(() => {}, 1 << 30);
