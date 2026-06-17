// Stderr/stdout/log scrubber (H11). The HMAC session key is the only secret the
// server process holds; `ssp-util` should never echo the stdin key, but a crash
// or usage error might surface argv/env, so we defensively scrub any secret we
// know about before any string crosses the tool boundary or reaches a log.
//
// We also blanket-redact anything that *looks* like a 64-hex HMAC key, so an
// unknown-shaped leak (e.g. SSP printing a key from elsewhere) is still caught.

const HEX64_RE = /\b[0-9a-fA-F]{64}\b/g;
// JWT: header.payload.signature, all base64url; the header begins `eyJ` (base64
// of `{"`). Scrubs an OAuth access token if one ever surfaces in a gateway
// result or log. The explicit-secret path (passing the live token) is the real
// guard; this is the defensive net (plan risk #6 — may over-match benign dotted
// base64, which is acceptable for an error/log string).
const JWT_RE = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;
const REDACTED = '[REDACTED]';

/**
 * Scrub `text` of any provided secrets plus any 64-hex token.
 * `secrets` may contain `undefined`/empty entries (ignored).
 */
export function redact(text: string, secrets: Array<string | undefined> = []): string {
  let out = text;
  for (const s of secrets) {
    if (!s) continue;
    out = out.split(s).join(REDACTED);
  }
  out = out.replace(JWT_RE, REDACTED);
  out = out.replace(HEX64_RE, REDACTED);
  return out;
}
