import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  WIKEY_AAGUID,
  xyFromUncompressed,
  coseEc2Key,
  authenticatorData,
  clientDataJSON,
  uuidFromBytes,
  buildAttestation,
  buildAssertion,
} from '../src/core/webauthn.js';

const sha256 = (b: Buffer) => createHash('sha256').update(b).digest();

// A real uncompressed secp256k1 EC public key (04‖X‖Y) — from the snapshot fixture.
const EC_PUK =
  '04fd6d3b271916ee3833382e4ae016460510636eb4ee2daba196ceae04cfc75cdd73aa7b0f2de6bf4124299b592ecc24ef8fe6bf722f57088aa3c786eed253450b';
const RP_ID = 'localhost';
const ORIGIN = 'http://localhost:8000';
const CHALLENGE = 'Y2hhbGxlbmdlLXZlY3Rvcg'; // arbitrary fixed b64url challenge

test('xyFromUncompressed splits 04‖X‖Y and tolerates 0x prefix', () => {
  const { x, y } = xyFromUncompressed(EC_PUK);
  assert.equal(x.length, 32);
  assert.equal(y.length, 32);
  assert.equal(x.toString('hex'), 'fd6d3b271916ee3833382e4ae016460510636eb4ee2daba196ceae04cfc75cdd');
  assert.equal(y.toString('hex'), '73aa7b0f2de6bf4124299b592ecc24ef8fe6bf722f57088aa3c786eed253450b');
  const pref = xyFromUncompressed('0x' + EC_PUK);
  assert.deepEqual(pref.x, x);
  assert.deepEqual(pref.y, y);
});

test('xyFromUncompressed rejects non-65-byte and non-0x04 input', () => {
  assert.throws(() => xyFromUncompressed('04' + 'aa'.repeat(10)), /65-byte/);
  // 65 bytes but leading byte 0x03 (compressed-form prefix) → rejected.
  assert.throws(() => xyFromUncompressed('03' + 'aa'.repeat(64)), /65-byte/);
});

test('authenticatorData layout: rpIdHash ‖ flags ‖ signCount', () => {
  const ad = authenticatorData({ rpId: RP_ID, flags: 0x05, signCount: 7 });
  assert.equal(ad.length, 37);
  assert.deepEqual(ad.subarray(0, 32), sha256(Buffer.from(RP_ID, 'utf8')));
  assert.equal(ad[32], 0x05);
  assert.equal(ad.readUInt32BE(33), 7);
});

test('coseEc2Key encodes EC2/ES256K/secp256k1 with X and Y embedded', () => {
  const { x, y } = xyFromUncompressed(EC_PUK);
  const cose = coseEc2Key(x, y);
  // CBOR map of 5 entries → 0xa5.
  assert.equal(cose[0], 0xa5);
  assert.ok(cose.includes(x), 'X embedded');
  assert.ok(cose.includes(y), 'Y embedded');
});

test('uuidFromBytes formats 16 bytes as a lowercase hyphenated UUID', () => {
  const u = uuidFromBytes(Buffer.from('0123456789abcdef0123456789abcdef', 'hex'));
  assert.equal(u, '01234567-89ab-cdef-0123-456789abcdef');
});

test('buildAttestation embeds AAGUID, credentialId, COSE key, and correct authData flags', () => {
  const { x, y } = xyFromUncompressed(EC_PUK);
  const credentialId = Buffer.from('credential-id-32-bytes-fixed!!!!', 'utf8');
  const att = buildAttestation({ rpId: RP_ID, origin: ORIGIN, challengeB64url: CHALLENGE, credentialId, x, y });

  // clientDataJSON round-trips to the expected webauthn.create envelope.
  const cdj = JSON.parse(Buffer.from(att.clientDataJSONB64url, 'base64url').toString('utf8'));
  assert.deepEqual(cdj, { type: 'webauthn.create', challenge: CHALLENGE, origin: ORIGIN, crossOrigin: false });

  const attObj = Buffer.from(att.attestationObjectB64url, 'base64url');
  assert.equal(attObj[0], 0xa3, 'attestationObject is a 3-entry CBOR map');
  assert.ok(attObj.includes(WIKEY_AAGUID), 'AAGUID present');
  assert.ok(attObj.includes(credentialId), 'credentialId present');
  assert.ok(attObj.includes(coseEc2Key(x, y)), 'COSE key present');

  // The attested authData carries the rpIdHash and UP|UV|AT (0x45) flags.
  const rpIdHash = sha256(Buffer.from(RP_ID, 'utf8'));
  const at = attObj.indexOf(rpIdHash);
  assert.ok(at > 0, 'rpIdHash present in authData');
  assert.equal(attObj[at + 32], 0x45, 'flags = UP|UV|AT');

  assert.equal(att.credentialIdB64url, credentialId.toString('base64url'));
});

test('buildAssertion: signedData = authData ‖ sha256(cdj); uuid = sha256(cdj)[0:16]', () => {
  const credentialId = Buffer.from('login-cred-id', 'utf8');
  const asr = buildAssertion({ rpId: RP_ID, origin: ORIGIN, challengeB64url: CHALLENGE, credentialId });

  const cdj = clientDataJSON('webauthn.get', CHALLENGE, ORIGIN);
  const cdjHash = sha256(cdj);
  const authData = authenticatorData({ rpId: RP_ID, flags: 0x05 });

  assert.equal(Buffer.from(asr.authenticatorDataB64url, 'base64url').toString('hex'), authData.toString('hex'));
  assert.equal(asr.clientDataHashHex, cdjHash.toString('hex'));
  assert.equal(asr.signedDataHex, Buffer.concat([authData, cdjHash]).toString('hex'));
  assert.equal(asr.uuid, uuidFromBytes(cdjHash.subarray(0, 16)));
  assert.equal(asr.credentialIdB64url, credentialId.toString('base64url'));

  // clientDataJSON is webauthn.get for login.
  const parsed = JSON.parse(Buffer.from(asr.clientDataJSONB64url, 'base64url').toString('utf8'));
  assert.equal(parsed.type, 'webauthn.get');
});
