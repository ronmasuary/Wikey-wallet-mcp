// Call an MCP server *through* the enrolled gateway's MCP aggregator, authorized
// by the wallet passkey — the agent never holds the upstream MCP credential.
//
// Two gateway surfaces exist, for two Server categories:
//   • API-category  → `/api/server/{owner}/{name}` — a raw REST reverse-proxy
//     (one request in, one response out). That's `apiCall.ts`. It is NOT an MCP
//     client, so pointing it at an MCP server just relays that server's own
//     transport redirects (e.g. Composio answers 307 → /v3/mcp/<id>/mcp) back to
//     the caller, which dead-ends.
//   • MCP-category  → `/api/mcp-gateway` — the aggregator (`wikey-mcp-gateway`),
//     a real streamable-http MCP server that connects to each granted upstream
//     MCP itself: it follows the upstream's redirects, injects the upstream
//     credential (e.g. Composio `x-api-key`) SERVER-SIDE, tokenizes PII, and
//     re-exposes every tool namespaced `<server>__<TOOL>`.
//
// So to reach MCP servers the agent speaks JSON-RPC to the aggregator with ONLY
// its short-lived passkey JWT as `Authorization: Bearer …`; the aggregator
// derives the PII user from the token (no shared service key, unlike LibreChat).
//
// Auth: pass an `accessToken` (e.g. from a prior wallet_gateway_login) to reuse
// it, or omit it and this performs a fresh passkey login via the injected signer.

import { loadCfg } from './config.js';
import { gatewayLogin, type LoginSigner } from './login.js';

/** Default aggregator path on the gateway host. */
const DEFAULT_MCP_PATH = '/api/mcp-gateway';
/** MCP protocol version we advertise in `initialize`. */
const DEFAULT_PROTOCOL_VERSION = '2025-06-18';

export interface McpCallInput {
  /**
   * Federated tool to call, namespaced `<server>__<TOOL>`
   * (e.g. `google-sheets-mcp__GOOGLESHEETS_VALUES_GET`). Omit to list tools.
   */
  tool?: string;
  /** Arguments object for the `tools/call` (ignored when `tool` is omitted). */
  arguments?: Record<string, unknown>;
  /** Advanced: raw JSON-RPC method override (e.g. `resources/list`). Wins over `tool`. */
  method?: string;
  /** Advanced: raw params for `method`. */
  params?: unknown;
  /** Aggregator path (default `/api/mcp-gateway`). */
  path?: string;
  /** Reuse an existing passkey access token instead of logging in again. */
  accessToken?: string;
  /** OAuth scope to request when logging in (only used when accessToken is omitted). */
  scope?: string;
  /** Extra request headers. */
  headers?: Record<string, string>;
  /** MCP protocolVersion to advertise (default `2025-06-18`). */
  protocolVersion?: string;
}

export interface McpCallResult {
  ok: boolean;
  status: number;
  /** Resolved aggregator URL the request was sent to (no upstream secret in it). */
  url: string;
  /** The JSON-RPC method actually sent (`tools/list` | `tools/call` | override). */
  method: string;
  /** Whether a fresh passkey login was performed for this call. */
  loggedIn: boolean;
  /** The on-chain object id / txHash, present only when a fresh login happened. */
  objectId?: string;
  txHash?: string;
  /** The JSON-RPC `result` on success (already unwrapped from the envelope). */
  result?: unknown;
  /** The JSON-RPC `error` when the server returned one. */
  error?: unknown;
}

/**
 * Parse a streamable-http response body: either a single JSON-RPC object
 * (`application/json`) or SSE frames (`text/event-stream`) whose `data:` lines
 * carry the JSON. Returns the frame matching `wantId` when several are present.
 */
function parseJsonRpc(text: string, wantId: number): unknown {
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  const looksSse = /^(event|data|id|:)\s*:/m.test(trimmed) && trimmed.includes('data:');
  if (!looksSse) {
    return JSON.parse(trimmed);
  }
  // Collect every `data:` payload, concatenating multi-line data within a frame.
  const frames: unknown[] = [];
  let buf: string[] = [];
  const flush = () => {
    if (buf.length) {
      try {
        frames.push(JSON.parse(buf.join('\n')));
      } catch {
        /* ignore non-JSON keepalive frames */
      }
      buf = [];
    }
  };
  for (const line of trimmed.split(/\r?\n/)) {
    if (line.startsWith('data:')) buf.push(line.slice(5).replace(/^ /, ''));
    else if (line.trim() === '') flush();
  }
  flush();
  const match = frames.find((f) => (f as { id?: number })?.id === wantId);
  return match ?? frames[frames.length - 1];
}

/** POST one JSON-RPC message to the aggregator; returns {status, body, sessionId}. */
async function rpc(
  url: string,
  headers: Record<string, string>,
  message: { jsonrpc: '2.0'; id: number; method: string; params?: unknown },
): Promise<{ status: number; ok: boolean; body: unknown; sessionId?: string }> {
  const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(message) });
  const text = await res.text();
  const sessionId = res.headers.get('mcp-session-id') ?? undefined;
  return {
    status: res.status,
    ok: res.ok,
    body: parseJsonRpc(text, message.id),
    ...(sessionId ? { sessionId } : {}),
  };
}

/**
 * Speak MCP to the gateway aggregator, authorized by the wallet passkey. Runs the
 * `initialize` handshake, then the requested op (`tools/list` by default, or
 * `tools/call` when `tool` is given, or a raw `method`).
 */
export async function gatewayMcpCall(input: McpCallInput, signer: LoginSigner): Promise<McpCallResult> {
  const cfg = loadCfg();

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

  const rawPath = input.path ?? DEFAULT_MCP_PATH;
  const url = `${cfg.host}${rawPath.startsWith('/') ? rawPath : `/${rawPath}`}`;

  const headers: Record<string, string> = {
    authorization: `Bearer ${accessToken}`,
    accept: 'application/json, text/event-stream',
    'content-type': 'application/json',
    ...(input.headers ?? {}),
  };

  // Resolve the op the caller wants.
  const method = input.method ?? (input.tool ? 'tools/call' : 'tools/list');
  const params =
    input.method !== undefined
      ? input.params
      : input.tool
        ? { name: input.tool, arguments: input.arguments ?? {} }
        : {};

  // 1. initialize — establish the MCP session (the aggregator is stateless today,
  //    but we honour any Mcp-Session-Id it returns so this keeps working if that
  //    changes). A failed handshake is reported rather than silently ignored.
  const init = await rpc(url, headers, {
    jsonrpc: '2.0',
    id: 0,
    method: 'initialize',
    params: {
      protocolVersion: input.protocolVersion ?? DEFAULT_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'wikey-wallet-mcp', version: '1.0.0' },
    },
  });
  if (!init.ok) {
    return {
      ok: false,
      status: init.status,
      url,
      method: 'initialize',
      loggedIn,
      ...(objectId ? { objectId } : {}),
      ...(txHash ? { txHash } : {}),
      error: init.body ?? `initialize failed (HTTP ${init.status})`,
    };
  }
  if (init.sessionId) headers['mcp-session-id'] = init.sessionId;

  // 2. the actual op.
  const res = await rpc(url, headers, { jsonrpc: '2.0', id: 1, method, params });
  const env = (res.body ?? {}) as { result?: unknown; error?: unknown };

  return {
    ok: res.ok && env.error === undefined,
    status: res.status,
    url,
    method,
    loggedIn,
    ...(objectId ? { objectId } : {}),
    ...(txHash ? { txHash } : {}),
    ...(env.result !== undefined ? { result: env.result } : {}),
    ...(env.error !== undefined ? { error: env.error } : {}),
  };
}
