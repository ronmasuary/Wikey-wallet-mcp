// Passwordless wallet-passkey login against the enrolled gateway (the second
// half of the IDP flow; `register.ts` is the first).
//
// The agent IS the OAuth client (RFC 8252 — no separate callback app). It proves
// possession of the wallet by creating, on-chain, the FIDO-sign object Casdoor's
// ValidateObject looks up — only the safe owner can. Steps:
//
//   1. GET  /api/webauthn/signin/begin?owner&name        -> challenge (+ session)
//   2. build a FIDO3 assertion; uuid = sha256(clientDataJSON)[0:16]
//   3. tx create-fido-object --destination <safe> --id <uuid> --payload …  (signs
//      via SSP), then poll the safe snapshot until the object is valid — THIS is
//      the real proof (Casdoor can't verify ES256K, so it trusts the chain).
//   4. sign the assertion bytes with the account key (faithful; not verified).
//   5. POST /api/webauthn/signin/finish?responseType=code&clientId&…&code_challenge(S256)
//      -> OAuth authorization code
//   6. exchange the code at /api/login/oauth/access_token with the PKCE verifier
//      (public client, NO client secret) -> JWT access token
//   7. GET /api/userinfo with the token to prove it authorizes access
//
// Signing is injected (LoginSigner) so this module stays transport-agnostic and
// never imports the SessionManager — the MCP dispatcher wires the two signing
// verbs to `session.signPrompted`.

import { createHash, randomBytes } from 'node:crypto';
import { loadCfg } from './config.js';
import { loadCredential } from './target.js';
import { resolveWalletIdentity, waitForObjectValid } from './identity.js';
import { buildAssertion } from './webauthn.js';

const sha256hex = (buf: Buffer): string => createHash('sha256').update(buf).digest('hex');

/**
 * The two signing operations login needs, injected by the caller so the core
 * stays free of the signer. Each returns the wallet-cli JSON stdout verbatim.
 */
export interface LoginSigner {
  /** `keys sign-challenge --challenge <hex>` → JSON with data.signature (DER hex). */
  signChallenge(challengeHex: string): Promise<string>;
  /** `tx create-fido-object --destination <safe> --id <uuid> --payload <hex> --broadcast`. */
  createFidoObject(o: { safe: string; uuid: string; payloadHex: string }): Promise<string>;
}

export interface LoginInput {
  /** OAuth scope to request (default: read). */
  scope?: string;
  /** OAuth `state` value (default: random). */
  state?: string;
  /**
   * The wallet account to log in AS — the key whose profile owns the enrolled
   * safe. MUST be the same account the injected `signer` signs with: the
   * on-chain FIDO object is what Casdoor checks, and only the safe's owner can
   * create it. Resolving the identity from one account while signing with
   * another produces a login that fails at the chain rather than at the input.
   *
   * Optional only for back-compat with callers that have not been converted;
   * omitted, `resolveWalletIdentity` falls back to the config pointer. Phase 3
   * removes that fallback.
   */
  account?: string;
}

export interface LoginResult {
  ok: true;
  account: string;
  safe: string;
  organization: string;
  username: string;
  application: string;
  clientId: string;
  /** The on-chain FIDO object id (= the WebAuthn assertion uuid) that gated login. */
  objectId: string;
  objectValid: true;
  txHash: string;
  tokenType: string;
  expiresIn?: number;
  scope: string;
  /** Decoded access-token claims (sub/aud/amr/exp/…) — the proof of amr:["fido"]. */
  claims: Record<string, unknown> | null;
  /** The access token the agent was never given out-of-band (it minted it via the passkey). */
  accessToken: string;
  /** /api/userinfo response (small), trimmed for the tool boundary. */
  userinfo: Record<string, unknown>;
}

function decodeJwt(token: string): Record<string, unknown> | null {
  const parts = String(token).split('.');
  if (parts.length < 2) return null;
  try {
    const json = Buffer.from(parts[1]!.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Build a Cookie header from a response's Set-Cookie(s). */
function cookieHeaderFrom(response: Response): string {
  const setCookies =
    typeof response.headers.getSetCookie === 'function'
      ? response.headers.getSetCookie()
      : [response.headers.get('set-cookie')].filter((v): v is string => Boolean(v));
  return setCookies.map((sc) => sc.split(';')[0]).join('; ');
}

function parseTxHash(stdout: string): string {
  try {
    const j = JSON.parse(stdout) as { data?: { txHash?: string } };
    return j.data?.txHash ?? '?';
  } catch {
    return '?';
  }
}

function parseSignature(stdout: string): string {
  let parsed: { data?: { signature?: string } };
  try {
    parsed = JSON.parse(stdout) as { data?: { signature?: string } };
  } catch {
    throw new Error(`could not parse sign-challenge output: ${stdout.slice(0, 200)}`);
  }
  const sig = parsed.data?.signature;
  if (!sig) throw new Error(`no signature in sign-challenge output: ${stdout.slice(0, 200)}`);
  return sig;
}

/** Run the full passkey OAuth login and return the token + proof of the on-chain gate. */
export async function gatewayLogin(input: LoginInput, signer: LoginSigner): Promise<LoginResult> {
  const cfg = loadCfg();
  const scope = input.scope ?? process.env.CASDOOR_SCOPE ?? 'read';
  const state = input.state ?? process.env.CASDOOR_STATE ?? 'verify' + Math.floor(Math.random() * 1e6);

  const cred = loadCredential();
  if (!cred) {
    throw new Error('no enrolled credential — run wallet_gateway_register first');
  }
  // Guard against stale state: the stored passkey must belong to the active target.
  if (cred.organization !== cfg.organization || cred.username !== cfg.username) {
    throw new Error(
      `enrolled credential is for ${cred.organization}/${cred.username}, but the active target is ` +
        `${cfg.organization}/${cfg.username}. Re-enroll (wallet_gateway_register) or clear state ` +
        `(wallet_gateway_logout) first.`,
    );
  }
  if (!cfg.clientId) {
    throw new Error('target has no clientId — re-run wallet_gateway_register with the invite link');
  }

  // Falls back to the account the passkey was enrolled against: that is a fact
  // recorded at enrollment, not a guess at who we are, and it is exactly the
  // account whose safe this login must prove ownership of.
  const id = await resolveWalletIdentity(cfg, input.account || cred.account);
  if (cred.safe !== id.safe) {
    throw new Error(`enrolled credential safe ${cred.safe} != resolved safe ${id.safe}`);
  }

  const credentialId = Buffer.from(cred.credentialIdB64url, 'base64url');

  // PKCE (RFC 7636, S256): proves possession of the verifier instead of a secret.
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

  // 1. signin/begin → challenge + session cookie
  const beginRes = await fetch(
    `${cfg.host}/api/webauthn/signin/begin?owner=${encodeURIComponent(cfg.organization)}&name=${encodeURIComponent(cfg.username)}`,
  );
  const beginText = await beginRes.text();
  if (!beginRes.ok) throw new Error(`signin/begin HTTP ${beginRes.status}: ${beginText.slice(0, 300)}`);
  const options = JSON.parse(beginText) as {
    publicKey?: { challenge?: string; rpId?: string; rp?: { id?: string } };
    challenge?: string;
    rpId?: string;
    rp?: { id?: string };
  };
  const pk = options.publicKey ?? options;
  const challengeB64url = pk.challenge;
  const rpId = pk.rpId || pk.rp?.id || cfg.rpId;
  if (!challengeB64url) throw new Error(`no challenge in signin/begin: ${beginText.slice(0, 200)}`);
  const authCookie = cookieHeaderFrom(beginRes);

  // 2. build assertion (uuid = sha256(clientDataJSON)[0:16])
  const asr = buildAssertion({ rpId, origin: cfg.origin, challengeB64url, credentialId });

  // 3. create the on-chain FIDO object on the SAFE and wait until valid
  const payloadHex = sha256hex(Buffer.from(asr.signedDataHex, 'hex'));
  const txOut = await signer.createFidoObject({ safe: id.safe, uuid: asr.uuid, payloadHex });
  const txHash = parseTxHash(txOut);
  await waitForObjectValid(cfg, id.safe, asr.uuid);

  // 4. sign the assertion bytes (faithful possession proof; not verified for ES256K)
  const sigOut = await signer.signChallenge(asr.signedDataHex);
  const signatureB64url = Buffer.from(parseSignature(sigOut), 'hex').toString('base64url');

  // 5. signin/finish → OAuth authorization code
  const finishUrl =
    `${cfg.host}/api/webauthn/signin/finish` +
    `?responseType=code&clientId=${encodeURIComponent(cfg.clientId)}` +
    `&redirectUri=${encodeURIComponent(cfg.redirectUri)}` +
    `&scope=${encodeURIComponent(scope)}&state=${encodeURIComponent(state)}` +
    `&code_challenge=${encodeURIComponent(codeChallenge)}&code_challenge_method=S256`;
  const finishRes = await fetch(finishUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: authCookie },
    body: JSON.stringify({
      id: asr.credentialIdB64url,
      rawId: asr.credentialIdB64url,
      type: 'public-key',
      response: {
        authenticatorData: asr.authenticatorDataB64url,
        clientDataJSON: asr.clientDataJSONB64url,
        signature: signatureB64url,
      },
      clientExtensionResults: {},
    }),
  });
  const finishText = await finishRes.text();
  let finish: { status?: string; msg?: string; data?: unknown };
  try {
    finish = JSON.parse(finishText) as { status?: string; msg?: string; data?: unknown };
  } catch {
    throw new Error(`signin/finish non-JSON: ${finishText.slice(0, 300)}`);
  }
  if (finish.status !== 'ok') {
    throw new Error(`signin/finish failed: ${finish.msg || finishText.slice(0, 300)}`);
  }
  if (finish.data && typeof finish.data === 'object' && (finish.data as { required?: unknown }).required) {
    throw new Error('the gateway requires a consent step for this app/scope (disable consent for headless login)');
  }
  const code = finish.data;

  // 6. exchange code → token (PKCE verifier, public client — no client secret)
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code: String(code),
    client_id: cfg.clientId,
    code_verifier: codeVerifier,
    redirect_uri: cfg.redirectUri,
  });
  const tokRes = await fetch(`${cfg.host}/api/login/oauth/access_token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  const tok = (await tokRes.json().catch(() => ({}))) as {
    access_token?: string;
    token_type?: string;
    expires_in?: number;
  };
  if (!tok.access_token) {
    throw new Error(`token exchange failed: ${JSON.stringify(tok).slice(0, 300)}`);
  }
  const claims = decodeJwt(tok.access_token);

  // 7. use the token against a protected resource
  const uiRes = await fetch(`${cfg.host}/api/userinfo`, {
    headers: { authorization: `Bearer ${tok.access_token}` },
  });
  const userinfo = (await uiRes.json().catch(() => ({}))) as Record<string, unknown>;

  return {
    ok: true,
    account: id.account,
    safe: id.safe,
    organization: cfg.organization,
    username: cfg.username,
    application: cfg.application,
    clientId: cfg.clientId,
    objectId: asr.uuid,
    objectValid: true,
    txHash,
    tokenType: tok.token_type ?? 'Bearer',
    ...(tok.expires_in !== undefined ? { expiresIn: tok.expires_in } : {}),
    scope,
    claims,
    accessToken: tok.access_token,
    userinfo,
  };
}
