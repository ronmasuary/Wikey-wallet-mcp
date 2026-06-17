#!/usr/bin/env node
// HTTP stub for `signing-server` used by the signRaw tests. Binds
// 127.0.0.1:STUB_PORT as a real HTTP server and answers POST /v1/sign by
// echoing a DER signature, so SessionManager.signRaw exercises the full
// proof → POST → response path. A plain TCP listen also satisfies the session
// port-probe. The HMAC key arrives via SSP_HMAC_KEY env (never printed).
//
// Env knobs:
//   STUB_PORT       port to bind (default 8080)
//   STUB_SIGN_DER   the signature hex to return (default a fixed DER blob)
//   STUB_SIGN_LOG   append each received /v1/sign body (one JSON line) for assertions
import http from 'node:http';
import fs from 'node:fs';

const port = parseInt(process.env.STUB_PORT ?? '8080', 10);
const DER = process.env.STUB_SIGN_DER ?? '3045022100deadbeef022012345678';

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/v1/sign') {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      if (process.env.STUB_SIGN_LOG) {
        try {
          fs.appendFileSync(process.env.STUB_SIGN_LOG, body.replace(/\n/g, ' ') + '\n');
        } catch {
          /* best effort */
        }
      }
      let requestId = '';
      let signingPubKey = '';
      try {
        const j = JSON.parse(body);
        requestId = j.requestId ?? '';
        signingPubKey = j.signingPubKey ?? '';
      } catch {
        /* echo empties */
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ requestId, signature: DER, signingPubKey }));
    });
    return;
  }
  res.writeHead(404);
  res.end('not found');
});

server.listen(port, '127.0.0.1');
setInterval(() => {}, 1 << 30);
