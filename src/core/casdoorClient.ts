// Casdoor HTTP state machine (P-FIDO). The ONE auditable place all outbound
// Casdoor traffic lives: cookie jar, password bootstrap, passkey register, the
// wallet-passkey login dance (PKCE + on-chain FIDO object + challenge signature
// + token exchange), and the MCP-gateway proxy call. Every URL comes from the
// resolved operator bundle — never the model.
//
// What proves identity is NOT the WebAuthn signature (Casdoor can't verify
// ES256K); it is the on-chain FIDO object created here via the wallet's signing
// session. The signature is still produced faithfully via signRaw.

import { createHash, randomBytes } from 'node:crypto';

import {
  buildAttestation,
  buildAssertion,
} from './webauthn.js';
import {
  resolveWalletIdentity,
  createFidoObjectArgs,
  signChallengeViaSSP,
  waitForObjectValid,
  type QueryFn,
  type StoredCredential,
  type WaitOpts,
} from './casdoorIdentity.js';
import type { IdentityBundle } from './identityRegistry.js';

const sha256hex = (buf: Buffer): string => createHash('sha256').update(buf).digest('hex');

/** Collaborators the login/register flows need (kept minimal for testability). */
export interface GatewayDeps {
  /** The wallet signing session (only the two methods the flow calls). */
  session: {
    signPrompted(args: string[], queue: never[]): Promise<string>;
    signRaw(unsignedDataHex: string, signingPubKey: string): Promise<string>;
  };
  /** wallet-cli read runner (HOME-pinned by the caller). */
  query: QueryFn;
  /** Injectable fetch for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Forwarded to waitForObjectValid (poll cadence) — tests shorten it. */
  waitOpts?: WaitOpts;
}

export interface RegisterResult {
  registered: true;
  safe: string;
  account: string;
  credentialIdB64url: string;
}

export interface LoginResult {
  token: string;
  /** Epoch ms when the token expires (from expires_in, else the JWT exp claim). */
  expiresAt: number;
  account: string;
  safe: string;
}

// ─── cookie jar ────────────────────────────────────────────────────────────────

export interface CookieJar {
  absorb(res: Response): void;
  header(): string;
  readonly size: number;
}

export function makeCookieJar(): CookieJar {
  const jar = new Map<string, string>();
  return {
    absorb(res: Response): void {
      const setCookies =
        typeof res.headers.getSetCookie === 'function'
          ? res.headers.getSetCookie()
          : [res.headers.get('set-cookie')].filter((v): v is string => Boolean(v));
      for (const sc of setCookies) {
        const first = sc.split(';')[0] ?? '';
        const eq = first.indexOf('=');
        if (eq > 0) jar.set(first.slice(0, eq).trim(), first.slice(eq + 1).trim());
      }
    },
    header(): string {
      return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    },
    get size(): number {
      return jar.size;
    },
  };
}

// ─── PKCE + JWT ──────────────────────────────────────────────────────────────

export function pkcePair(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge };
}

export function decodeJwt(token: string): Record<string, unknown> | null {
  const p = String(token).split('.');
  if (p.length < 2) return null;
  try {
    return JSON.parse(Buffer.from(p[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export class CasdoorClient {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly deps: GatewayDeps) {
    this.fetchImpl = deps.fetchImpl ?? fetch;
  }

  /**
   * One-time passkey enrollment. Password-login as the bundle's user, register a
   * FIDO3 attestation whose credential public key is the SAFE's ecPuk (so Casdoor
   * binds the SAFE address), and return the chosen credentialId to persist.
   */
  async register(bundle: IdentityBundle, password: string): Promise<RegisterResult> {
    const jar = await this.passwordLogin(bundle, password);
    const cookie = jar.header();

    const begin = await this.fetchImpl(`${bundle.host}/api/webauthn/signup/begin`, { headers: { cookie } });
    const beginText = await begin.text();
    if (!begin.ok) throw new Error(`signup/begin HTTP ${begin.status}: ${beginText.slice(0, 200)}`);
    const opts = JSON.parse(beginText) as { publicKey?: Record<string, unknown> } & Record<string, unknown>;
    const pk = (opts.publicKey ?? opts) as { challenge?: string; rp?: { id?: string } };
    const challengeB64url = pk.challenge;
    const rpId = pk.rp?.id ?? bundle.rpId;
    if (!challengeB64url) throw new Error(`no challenge in signup/begin: ${beginText.slice(0, 200)}`);

    const id = await resolveWalletIdentity(this.deps.query);
    const credentialId = randomBytes(32);
    const att = buildAttestation({ rpId, origin: bundle.origin, challengeB64url, credentialId, x: id.x, y: id.y });

    const finish = await this.fetchImpl(`${bundle.host}/api/webauthn/signup/finish`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({
        id: att.credentialIdB64url,
        rawId: att.credentialIdB64url,
        type: 'public-key',
        response: {
          attestationObject: att.attestationObjectB64url,
          clientDataJSON: att.clientDataJSONB64url,
        },
        clientExtensionResults: {},
      }),
    });
    const finishText = await finish.text();
    let parsed: { status?: string; msg?: string };
    try {
      parsed = JSON.parse(finishText);
    } catch {
      throw new Error(`signup/finish non-JSON: ${finishText.slice(0, 200)}`);
    }
    if (parsed.status && parsed.status !== 'ok') {
      throw new Error(`signup/finish error: ${parsed.msg ?? finishText.slice(0, 200)}`);
    }
    return { registered: true, safe: id.safe, account: id.account, credentialIdB64url: att.credentialIdB64url };
  }

  /**
   * Full wallet-passkey login → sealed access token. Builds the assertion,
   * creates+awaits the on-chain FIDO object (the real proof), signs the challenge
   * via signRaw, completes signin/finish with PKCE, and exchanges the code with NO
   * client secret. Throws a clear error if Casdoor demands consent (decision #7).
   */
  async login(bundle: IdentityBundle, cred: StoredCredential): Promise<LoginResult> {
    const id = await resolveWalletIdentity(this.deps.query);
    if (cred.safe !== id.safe) {
      throw new Error(`credential safe ${cred.safe} != resolved safe ${id.safe} — re-register this identity`);
    }
    const credentialId = Buffer.from(cred.credentialIdB64url, 'base64url');

    // 1. signin/begin → challenge (+ session cookie).
    const beginUrl =
      `${bundle.host}/api/webauthn/signin/begin` +
      `?owner=${encodeURIComponent(bundle.org)}&name=${encodeURIComponent(bundle.user)}`;
    const begin = await this.fetchImpl(beginUrl);
    const beginText = await begin.text();
    if (!begin.ok) throw new Error(`signin/begin HTTP ${begin.status}: ${beginText.slice(0, 200)}`);
    const opts = JSON.parse(beginText) as { publicKey?: Record<string, unknown> } & Record<string, unknown>;
    const pk = (opts.publicKey ?? opts) as { challenge?: string; rpId?: string; rp?: { id?: string } };
    const challengeB64url = pk.challenge;
    const rpId = pk.rpId ?? pk.rp?.id ?? bundle.rpId;
    if (!challengeB64url) throw new Error(`no challenge in signin/begin: ${beginText.slice(0, 200)}`);
    const cookie = cookieHeaderFrom(begin);

    // 2. assertion.
    const asr = buildAssertion({ rpId, origin: bundle.origin, challengeB64url, credentialId });

    // 3. on-chain FIDO object on the SAFE, then wait until valid (the real proof).
    const payloadHex = sha256hex(Buffer.from(asr.signedDataHex, 'hex'));
    await this.deps.session.signPrompted(createFidoObjectArgs(id.safe, asr.uuid, payloadHex), []);
    await waitForObjectValid(bundle, id.safe, asr.uuid, this.deps.waitOpts ?? {});

    // 4. sign the assertion bytes (faithful; not verified for ES256K).
    const sigHex = await signChallengeViaSSP(this.deps.session, this.deps.query, id.account, asr.signedDataHex);
    const signatureB64url = Buffer.from(sigHex, 'hex').toString('base64url');

    // 5. signin/finish (+ PKCE) → authorization code.
    const { codeVerifier, codeChallenge } = pkcePair();
    const state = 'wmcp' + randomBytes(6).toString('hex');
    const finishUrl =
      `${bundle.host}/api/webauthn/signin/finish` +
      `?responseType=code&clientId=${encodeURIComponent(bundle.clientId)}` +
      `&redirectUri=${encodeURIComponent(bundle.redirectUri)}` +
      `&scope=${encodeURIComponent(bundle.scope)}&state=${encodeURIComponent(state)}` +
      `&code_challenge=${encodeURIComponent(codeChallenge)}&code_challenge_method=S256`;
    const finishRes = await this.fetchImpl(finishUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
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
      finish = JSON.parse(finishText);
    } catch {
      throw new Error(`signin/finish non-JSON: ${finishText.slice(0, 200)}`);
    }
    if (finish.status !== 'ok') {
      throw new Error(`signin/finish failed: ${finish.msg ?? finishText.slice(0, 200)}`);
    }
    if (finish.data && typeof finish.data === 'object' && (finish.data as { required?: unknown }).required) {
      throw new Error(
        'Casdoor returned a consent step (data.required). Disable custom OAuth scopes on the gateway app so headless login does not hit a consent screen (decision #7).',
      );
    }
    const code = String(finish.data);

    // 6. exchange the code for a token — public client, PKCE verifier, NO secret.
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: bundle.clientId,
      code_verifier: codeVerifier,
      redirect_uri: bundle.redirectUri,
    });
    const tokRes = await this.fetchImpl(`${bundle.host}/api/login/oauth/access_token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    const tok = (await tokRes.json().catch(() => ({}))) as {
      access_token?: string;
      expires_in?: number;
      error?: string;
    };
    if (!tok.access_token) {
      throw new Error(`token exchange failed: ${tok.error ?? JSON.stringify(tok).slice(0, 200)}`);
    }

    const expiresAt =
      typeof tok.expires_in === 'number'
        ? Date.now() + tok.expires_in * 1000
        : expFromJwt(tok.access_token);

    return { token: tok.access_token, expiresAt, account: id.account, safe: id.safe };
  }

  /**
   * Proxy a JSON-RPC call through the Casdoor MCP gateway with the sealed bearer.
   * Casdoor verifies the token, checks the per-tool allowlist, injects the
   * upstream secret, and reverse-proxies. Returns the upstream result (the tool
   * layer redacts before it reaches the model).
   */
  async gatewayCall(
    bundle: IdentityBundle,
    token: string,
    ownerName: string,
    method: string,
    params: unknown,
  ): Promise<unknown> {
    if (!ownerName.includes('/')) throw new Error(`owner_name must be "owner/name", got "${ownerName}"`);
    const url = `${bundle.host}/api/server/${ownerName}`;
    const res = await this.fetchImpl(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: params ?? {} }),
    });
    const text = await res.text();
    if (res.status === 401 || res.status === 403) {
      throw new Error(
        `gateway rejected the call (HTTP ${res.status}). Either "${ownerName}" is not registered, ` +
          `or ${bundle.org}/${bundle.user} lacks a Casdoor permission for it.`,
      );
    }
    if (!res.ok) throw new Error(`gateway HTTP ${res.status}: ${text.slice(0, 300)}`);
    try {
      return JSON.parse(text);
    } catch {
      return text; // SSE / non-JSON passthrough
    }
  }

  // ─── internal ─────────────────────────────────────────────────────────────

  private async passwordLogin(bundle: IdentityBundle, password: string): Promise<CookieJar> {
    const jar = makeCookieJar();
    const res = await this.fetchImpl(`${bundle.host}/api/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        type: 'login',
        application: bundle.app,
        organization: bundle.org,
        username: bundle.user,
        password,
        autoSignin: true,
      }),
    });
    const body = (await res.json().catch(() => ({}))) as { status?: string; msg?: string };
    if (body.status !== 'ok') {
      throw new Error(`Casdoor password login failed: ${body.msg ?? JSON.stringify(body).slice(0, 200)}`);
    }
    jar.absorb(res);
    if (jar.size === 0) throw new Error('Casdoor login returned no session cookie');
    return jar;
  }
}

function cookieHeaderFrom(res: Response): string {
  const setCookies =
    typeof res.headers.getSetCookie === 'function'
      ? res.headers.getSetCookie()
      : [res.headers.get('set-cookie')].filter((v): v is string => Boolean(v));
  return setCookies.map((sc) => sc.split(';')[0]).join('; ');
}

/** Token expiry from the JWT exp claim (seconds → ms); falls back to +5min. */
function expFromJwt(token: string): number {
  const claims = decodeJwt(token);
  const exp = claims && typeof claims.exp === 'number' ? claims.exp : null;
  return exp ? exp * 1000 : Date.now() + 5 * 60 * 1000;
}
