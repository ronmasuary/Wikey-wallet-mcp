#!/usr/bin/env node
// Stub for `signing-server`. Binds 127.0.0.1:STUB_PORT and stays alive until
// killed. Records its startup (one line per spawn) to STUB_SPAWN_LOG so tests
// can assert exactly-one-spawn (H8). The HMAC key arrives via SSP_HMAC_KEY env
// (never argv) — we deliberately do NOT print it.
import net from 'node:net';
import fs from 'node:fs';

const port = parseInt(process.env.STUB_PORT ?? '8080', 10);

if (process.env.STUB_SPAWN_LOG) {
  fs.appendFileSync(process.env.STUB_SPAWN_LOG, `spawn pid=${process.pid} port=${port}\n`);
}

const server = net.createServer((s) => s.end());
const delay = parseInt(process.env.STUB_SPAWN_DELAY ?? '0', 10);
setTimeout(() => server.listen(port, '127.0.0.1'), delay);

// Stay alive; default SIGTERM handling exits the process.
setInterval(() => {}, 1 << 30);
