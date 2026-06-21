// Call a 3rd-party REST API *through* the enrolled gateway, authorized by the
// wallet passkey — the agent never holds the upstream API key.
//
// The gateway (Casdoor fork) exposes registered `Server` objects at
// `/api/server/{owner}/{name}/{subpath}`. For an API-category server it injects
// the upstream credential (e.g. `Authorization: Bearer sk-or-…`) server-side and
// reverse-proxies the request, after casbin-gating the caller's passkey token.
// So the agent sends ONLY its short-lived passkey JWT; the OpenRouter key stays
// on the gateway.
//
// Auth: pass an `accessToken` (e.g. from a prior wallet_gateway_login) to reuse
// it, or omit it and this performs a fresh passkey login via the injected signer.

import { loadCfg } from './config.js';
import { gatewayLogin, type LoginSigner } from './login.js';

export interface ApiCallInput {
  /** Gateway server to hit: `owner/name` or just `name` (owner defaults to the target org). */
  server: string;
  /** Sub-path appended to the server's base URL, e.g. `v1/chat/completions`. */
  subpath?: string;
  /** HTTP method (default: POST when a body is given, else GET). */
  method?: string;
  /** JSON request body (object) or a pre-serialized string. */
  body?: unknown;
  /** Extra request headers (content-type defaults to application/json for a JSON body). */
  headers?: Record<string, string>;
  /** Reuse an existing passkey access token instead of logging in again. */
  accessToken?: string;
  /** OAuth scope to request when logging in (only used when accessToken is omitted). */
  scope?: string;
}

export interface ApiCallResult {
  ok: boolean;
  status: number;
  /** Resolved gateway URL the request was sent to (no upstream secret in it). */
  url: string;
  server: string;
  method: string;
  /** Whether a fresh passkey login was performed for this call. */
  loggedIn: boolean;
  /** The on-chain object id / txHash, present only when a fresh login happened. */
  objectId?: string;
  txHash?: string;
  /** Parsed JSON response when the upstream returns JSON, else the raw text. */
  data: unknown;
}

const joinUrl = (base: string, sub: string): string =>
  !sub ? base : `${base.replace(/\/$/, '')}/${sub.replace(/^\//, '')}`;

/** Proxy a REST call through the gateway, authorized by the wallet passkey. */
export async function gatewayApiCall(input: ApiCallInput, signer: LoginSigner): Promise<ApiCallResult> {
  const cfg = loadCfg();
  if (!input.server) throw new Error('server is required (e.g. "openrouter_api" or "organization_xyz/openrouter_api")');

  const [ownerOrName, maybeName] = input.server.split('/');
  const owner = maybeName ? ownerOrName! : cfg.organization;
  const name = maybeName ?? ownerOrName!;
  if (!owner) throw new Error('could not resolve server owner — set the active target or pass "owner/name"');

  // Acquire a passkey token (reuse or fresh login).
  let accessToken = input.accessToken;
  let loggedIn = false;
  let objectId: string | undefined;
  let txHash: string | undefined;
  if (!accessToken) {
    const login = await gatewayLogin({ ...(input.scope ? { scope: input.scope } : {}) }, signer);
    accessToken = login.accessToken;
    loggedIn = true;
    objectId = login.objectId;
    txHash = login.txHash;
  }

  const method = (input.method ?? (input.body !== undefined ? 'POST' : 'GET')).toUpperCase();
  const url = joinUrl(`${cfg.host}/api/server/${owner}/${name}`, input.subpath ?? '');

  const headers: Record<string, string> = {
    authorization: `Bearer ${accessToken}`,
    ...(input.headers ?? {}),
  };
  let body: string | undefined;
  if (input.body !== undefined && method !== 'GET' && method !== 'HEAD') {
    body = typeof input.body === 'string' ? input.body : JSON.stringify(input.body);
    if (!Object.keys(headers).some((h) => h.toLowerCase() === 'content-type')) {
      headers['content-type'] = 'application/json';
    }
  }

  const res = await fetch(url, { method, headers, ...(body !== undefined ? { body } : {}) });
  const text = await res.text();
  let data: unknown = text;
  try {
    data = JSON.parse(text);
  } catch {
    /* non-JSON upstream — keep the raw text */
  }

  return {
    ok: res.ok,
    status: res.status,
    url,
    server: `${owner}/${name}`,
    method,
    loggedIn,
    ...(objectId ? { objectId } : {}),
    ...(txHash ? { txHash } : {}),
    data,
  };
}
