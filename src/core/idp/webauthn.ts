// Synthetic FIDO3 (WebAuthn) authenticator for the wallet MCP.
//
// Headless equivalent of the WiKey mobile wallet acting as a cross-platform
// authenticator. Builds the exact attestation (registration) and assertion
// (login) artifacts Casdoor's `webauthn.go` consumes, using the *safe's* EC
// public key (assets.ecPuk) as the credential public key.
//
// Why the safe key and not the account key: Casdoor derives the bound address
// from the credential public key (compress → sha256 → ripemd160 → bech32
// "omnistar"). Registering the safe's ecPuk binds the SAFE address, so the
// on-chain FIDO object Casdoor validates lives on the safe — and login keeps
// working after account recovery (recovery swaps the account key, keeps the safe).
//
// Casdoor cannot cryptographically verify ES256K (go-webauthn supports only
// ES256/384/512), so the WebAuthn signature never authorizes login — the on-chain
// FIDO object does. The signature is filled with a real account-key signature for
// faithfulness, but is not security-relevant.

import { createHash } from 'node:crypto';

// WIKEY_AAGUID — must match idp/controllers/webauthn.go exactly.
export const WIKEY_AAGUID = Buffer.from([
  180, 99, 125, 190, 71, 164, 168, 212, 54, 241, 198, 174, 124, 111, 45, 24,
]);

// ─── Minimal deterministic CBOR encoder (enough for COSE keys + attestationObject) ──
function cborHead(major: number, n: number): Buffer {
  const m = major << 5;
  if (n < 24) return Buffer.from([m | n]);
  if (n < 0x100) return Buffer.from([m | 24, n]);
  if (n < 0x10000) return Buffer.from([m | 25, n >> 8, n & 0xff]);
  if (n < 0x100000000) {
    const b = Buffer.alloc(5);
    b[0] = m | 26;
    b.writeUInt32BE(n >>> 0, 1);
    return b;
  }
  throw new Error('cbor: integer too large');
}

const cbor = {
  uint: (n: number): Buffer => cborHead(0, n),
  // negative integer: major type 1 encodes (-1 - n)
  nint: (n: number): Buffer => cborHead(1, -1 - n),
  int: (n: number): Buffer => (n < 0 ? cbor.nint(n) : cbor.uint(n)),
  bytes: (buf: Buffer): Buffer => Buffer.concat([cborHead(2, buf.length), buf]),
  text: (str: string): Buffer => {
    const b = Buffer.from(str, 'utf8');
    return Buffer.concat([cborHead(3, b.length), b]);
  },
  // entries: array of [keyBuf, valueBuf]
  map: (entries: Buffer[][]): Buffer =>
    Buffer.concat([cborHead(5, entries.length), ...entries.flat()]),
};

// ─── helpers ──
const b64url = (buf: Buffer): string => Buffer.from(buf).toString('base64url');
const sha256 = (buf: Buffer): Buffer => createHash('sha256').update(buf).digest();

/**
 * Split an uncompressed secp256k1 public key (04 || X(32) || Y(32)) into X, Y.
 * Accepts hex with or without the 0x prefix.
 */
export function xyFromUncompressed(ecPukHex: string): { x: Buffer; y: Buffer } {
  const hex = ecPukHex.startsWith('0x') ? ecPukHex.slice(2) : ecPukHex;
  const buf = Buffer.from(hex, 'hex');
  if (buf.length !== 65 || buf[0] !== 0x04) {
    throw new Error(`expected 65-byte uncompressed EC key (04||X||Y), got ${buf.length} bytes`);
  }
  return { x: buf.subarray(1, 33), y: buf.subarray(33, 65) };
}

/**
 * COSE_Key (CBOR) for an EC2 / ES256K / secp256k1 public key.
 *   1 (kty):  2  (EC2)
 *   3 (alg): -47 (ES256K)
 *  -1 (crv):  8  (secp256k1, per IANA COSE registry)
 *  -2 (x):  bstr
 *  -3 (y):  bstr
 */
export function coseEc2Key(x: Buffer, y: Buffer): Buffer {
  return cbor.map([
    [cbor.uint(1), cbor.uint(2)],
    [cbor.uint(3), cbor.int(-47)],
    [cbor.int(-1), cbor.uint(8)],
    [cbor.int(-2), cbor.bytes(x)],
    [cbor.int(-3), cbor.bytes(y)],
  ]);
}

// Flags byte of authenticatorData.
const FLAG_UP = 0x01; // user present
const FLAG_UV = 0x04; // user verified
const FLAG_AT = 0x40; // attested credential data included

function authenticatorData(o: {
  rpId: string;
  flags: number;
  signCount?: number;
  attestedCredentialData?: Buffer;
}): Buffer {
  const rpIdHash = sha256(Buffer.from(o.rpId, 'utf8'));
  const head = Buffer.alloc(37);
  rpIdHash.copy(head, 0);
  head[32] = o.flags;
  head.writeUInt32BE((o.signCount ?? 0) >>> 0, 33);
  return o.attestedCredentialData ? Buffer.concat([head, o.attestedCredentialData]) : head;
}

function clientDataJSON(type: string, challengeB64url: string, origin: string): Buffer {
  // Field order matches what browsers emit; Casdoor parses by key, not order.
  return Buffer.from(
    JSON.stringify({ type, challenge: challengeB64url, origin, crossOrigin: false }),
    'utf8',
  );
}

/** Format 16 bytes as a lowercase hyphenated UUID (matches google/uuid String()). */
export function uuidFromBytes(buf16: Buffer): string {
  const h = Buffer.from(buf16).toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

export interface Attestation {
  credentialIdB64url: string;
  clientDataJSONB64url: string;
  attestationObjectB64url: string;
}

/**
 * Build a WebAuthn registration (attestation) response with fmt:"none",
 * WIKEY_AAGUID, and the safe's ES256K credential public key.
 */
export function buildAttestation(o: {
  rpId: string;
  origin: string;
  challengeB64url: string;
  credentialId: Buffer;
  x: Buffer;
  y: Buffer;
}): Attestation {
  const coseKey = coseEc2Key(o.x, o.y);
  const credIdLen = Buffer.alloc(2);
  credIdLen.writeUInt16BE(o.credentialId.length, 0);
  const attestedCredentialData = Buffer.concat([WIKEY_AAGUID, credIdLen, o.credentialId, coseKey]);
  const authData = authenticatorData({
    rpId: o.rpId,
    flags: FLAG_UP | FLAG_UV | FLAG_AT,
    attestedCredentialData,
  });
  const attestationObject = cbor.map([
    [cbor.text('fmt'), cbor.text('none')],
    [cbor.text('attStmt'), cbor.map([])],
    [cbor.text('authData'), cbor.bytes(authData)],
  ]);
  return {
    credentialIdB64url: b64url(o.credentialId),
    clientDataJSONB64url: b64url(clientDataJSON('webauthn.create', o.challengeB64url, o.origin)),
    attestationObjectB64url: b64url(attestationObject),
  };
}

export interface Assertion {
  credentialIdB64url: string;
  authenticatorDataB64url: string;
  clientDataJSONB64url: string;
  signedDataHex: string;
  clientDataHashHex: string;
  uuid: string;
}

/**
 * Build a WebAuthn login (assertion) response for POST /api/webauthn/signin/finish.
 *   - signedDataHex: authenticatorData || sha256(clientDataJSON) — the bytes the
 *     authenticator signs (signed with the account key via SSP; not verified by
 *     Casdoor for ES256K but included for faithfulness).
 *   - uuid: the on-chain FIDO object id Casdoor looks up = uuidFromBytes(sha256(cdj)[0:16]).
 *   - clientDataHashHex: sha256(clientDataJSON) hex (for the FIDO object payload).
 */
export function buildAssertion(o: {
  rpId: string;
  origin: string;
  challengeB64url: string;
  credentialId: Buffer;
}): Assertion {
  const cdj = clientDataJSON('webauthn.get', o.challengeB64url, o.origin);
  const authData = authenticatorData({ rpId: o.rpId, flags: FLAG_UP | FLAG_UV });
  const clientDataHash = sha256(cdj);
  const signedData = Buffer.concat([authData, clientDataHash]);
  const uuidBytes = sha256(cdj).subarray(0, 16);
  return {
    credentialIdB64url: b64url(o.credentialId),
    authenticatorDataB64url: b64url(authData),
    clientDataJSONB64url: b64url(cdj),
    signedDataHex: signedData.toString('hex'),
    clientDataHashHex: clientDataHash.toString('hex'),
    uuid: uuidFromBytes(uuidBytes),
  };
}
