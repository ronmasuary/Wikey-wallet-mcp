// Pure synthetic FIDO3 (WebAuthn) authenticator — TS port of the PoC's
// webauthn-authenticator.mjs (ssp-agent-app). No network, no secrets, node:crypto
// only, Buffer throughout → fully unit-testable with fixed vectors.
//
// This is the headless equivalent of the WiKey mobile wallet acting as a
// cross-platform authenticator. It builds the exact attestation (registration)
// and assertion (login) artifacts Casdoor's webauthn.go consumes, using the
// SAFE's EC public key as the credential public key.
//
// Why the safe key and not the account key: Casdoor derives the bound address
// from the credential public key (compress → sha256 → ripemd160 → bech32
// "omnistar"). Registering the safe's ecPuk makes the bound address the SAFE
// address, and the on-chain FIDO object Casdoor checks lives on the safe. Because
// account recovery swaps the account key but keeps the safe, login keeps working
// after recovery.
//
// Casdoor cannot cryptographically verify ES256K (go-webauthn supports only
// ES256/384/512), so the WebAuthn signature is never what authorizes login — the
// on-chain FIDO object is. The signature is present and well-formed but not
// security-relevant; we still fill it with a real account-key signature for
// faithfulness (signed via the signing-server, see casdoorIdentity.ts).

import { createHash } from 'node:crypto';

// WIKEY_AAGUID — must match idp/controllers/webauthn.go exactly.
export const WIKEY_AAGUID = Buffer.from([
  180, 99, 125, 190, 71, 164, 168, 212, 54, 241, 198, 174, 124, 111, 45, 24,
]);

// ─── Minimal deterministic CBOR encoder (enough for COSE keys + attestationObject) ──

const CBOR_MAJOR_BYTES = 2;
const CBOR_MAJOR_TEXT = 3;
const CBOR_MAJOR_MAP = 5;

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
  bytes: (buf: Buffer): Buffer => Buffer.concat([cborHead(CBOR_MAJOR_BYTES, buf.length), buf]),
  text: (s: string): Buffer => {
    const b = Buffer.from(s, 'utf8');
    return Buffer.concat([cborHead(CBOR_MAJOR_TEXT, b.length), b]);
  },
  // entries: array of [keyBuf, valueBuf]
  map: (entries: Buffer[][]): Buffer =>
    Buffer.concat([cborHead(CBOR_MAJOR_MAP, entries.length), ...entries.flat()]),
};

// ─── helpers ───────────────────────────────────────────────────────────────────

const b64url = (buf: Buffer): string => Buffer.from(buf).toString('base64url');
const sha256 = (buf: Buffer): Buffer => createHash('sha256').update(buf).digest();

/**
 * Split an uncompressed secp256k1 public key (04 ‖ X(32) ‖ Y(32)) into X, Y.
 * Accepts hex with or without the 0x prefix.
 */
export function xyFromUncompressed(ecPukHex: string): { x: Buffer; y: Buffer } {
  const hex = ecPukHex.startsWith('0x') ? ecPukHex.slice(2) : ecPukHex;
  const buf = Buffer.from(hex, 'hex');
  if (buf.length !== 65 || buf[0] !== 0x04) {
    throw new Error(`expected 65-byte uncompressed EC key (04‖X‖Y), got ${buf.length} bytes`);
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

export function authenticatorData(opts: {
  rpId: string;
  flags: number;
  signCount?: number;
  attestedCredentialData?: Buffer;
}): Buffer {
  const rpIdHash = sha256(Buffer.from(opts.rpId, 'utf8'));
  const head = Buffer.alloc(37);
  rpIdHash.copy(head, 0);
  head[32] = opts.flags;
  head.writeUInt32BE((opts.signCount ?? 0) >>> 0, 33);
  return opts.attestedCredentialData
    ? Buffer.concat([head, opts.attestedCredentialData])
    : head;
}

export function clientDataJSON(type: string, challengeB64url: string, origin: string): Buffer {
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
export function buildAttestation(opts: {
  rpId: string;
  origin: string;
  challengeB64url: string;
  credentialId: Buffer;
  x: Buffer;
  y: Buffer;
}): Attestation {
  const coseKey = coseEc2Key(opts.x, opts.y);
  const credIdLen = Buffer.alloc(2);
  credIdLen.writeUInt16BE(opts.credentialId.length, 0);
  const attestedCredentialData = Buffer.concat([
    WIKEY_AAGUID,
    credIdLen,
    opts.credentialId,
    coseKey,
  ]);
  const authData = authenticatorData({
    rpId: opts.rpId,
    flags: FLAG_UP | FLAG_UV | FLAG_AT,
    attestedCredentialData,
  });
  const attestationObject = cbor.map([
    [cbor.text('fmt'), cbor.text('none')],
    [cbor.text('attStmt'), cbor.map([])],
    [cbor.text('authData'), cbor.bytes(authData)],
  ]);
  return {
    credentialIdB64url: b64url(opts.credentialId),
    clientDataJSONB64url: b64url(clientDataJSON('webauthn.create', opts.challengeB64url, opts.origin)),
    attestationObjectB64url: b64url(attestationObject),
  };
}

export interface Assertion {
  credentialIdB64url: string;
  authenticatorDataB64url: string;
  clientDataJSONB64url: string;
  /** authenticatorData ‖ sha256(clientDataJSON) — the bytes the authenticator signs. */
  signedDataHex: string;
  /** sha256(clientDataJSON) hex — for the FIDO object payload. */
  clientDataHashHex: string;
  /** The on-chain FIDO object id = uuidFromBytes(sha256(clientDataJSON)[0:16]). */
  uuid: string;
}

/**
 * Build a WebAuthn login (assertion) response. Returns the b64url fields for
 * POST /api/webauthn/signin/finish, plus signedDataHex (the bytes the account
 * key signs via the signing-server), clientDataHashHex, and the on-chain object
 * uuid Casdoor will look up.
 */
export function buildAssertion(opts: {
  rpId: string;
  origin: string;
  challengeB64url: string;
  credentialId: Buffer;
}): Assertion {
  const cdj = clientDataJSON('webauthn.get', opts.challengeB64url, opts.origin);
  const authData = authenticatorData({ rpId: opts.rpId, flags: FLAG_UP | FLAG_UV });
  const clientDataHash = sha256(cdj);
  const signedData = Buffer.concat([authData, clientDataHash]);
  const uuidBytes = clientDataHash.subarray(0, 16);
  return {
    credentialIdB64url: b64url(opts.credentialId),
    authenticatorDataB64url: b64url(authData),
    clientDataJSONB64url: b64url(cdj),
    signedDataHex: signedData.toString('hex'),
    clientDataHashHex: clientDataHash.toString('hex'),
    uuid: uuidFromBytes(uuidBytes),
  };
}
