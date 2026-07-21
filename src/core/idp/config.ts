// Shared config resolution for the Casdoor/gateway passkey flow.
//
// Resolution per field (highest first): explicit CASDOOR_* env var > saved
// gateway target (state-root idp/gateway-target.json, set by register) >
// built-in default. The target file is the everyday source of truth; env is an
// override. Recomputed on each call (NOT at module load) because register
// mutates the target mid-process.

import { loadTarget, type Target } from './target.js';

export interface Cfg {
  host: string;
  rpId: string;
  origin: string;
  organization: string;
  username: string;
  application: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  snapshotNode: string;
  env: string;
  snapshotSecure: boolean;
  account?: string;
  /** Wikey proxy base URL for the pre-passkey sponsor-fund call. */
  proxyUrl: string;
}

const env = (k: string): string | undefined =>
  process.env[k] != null && process.env[k] !== '' ? process.env[k] : undefined;

/**
 * Resolve the active config. `overrides` win over everything (used to thread
 * freshly-saved register fields without re-reading the file mid-write).
 */
export function loadCfg(overrides: Target = {}): Cfg {
  const t = { ...(loadTarget() ?? {}), ...overrides } as Target;
  const pick = (envVar: string, key: keyof Target, dflt: string): string =>
    env(envVar) ?? (t[key] != null ? String(t[key]) : dflt);

  return {
    host: pick('CASDOOR_HOST', 'host', 'https://gateway.wikey.io').replace(/\/$/, ''),
    rpId: pick('CASDOOR_RP_ID', 'rpId', 'gateway.wikey.io'),
    origin: pick('CASDOOR_ORIGIN', 'origin', 'https://gateway.wikey.io'),
    organization: pick('CASDOOR_ORG', 'organization', ''),
    username: pick('CASDOOR_USER', 'username', ''),
    application: pick('CASDOOR_APP', 'application', ''),
    clientId: pick('CASDOOR_CLIENT_ID', 'clientId', ''),
    clientSecret: pick('CASDOOR_CLIENT_SECRET', 'clientSecret', ''),
    redirectUri: pick('CASDOOR_REDIRECT_URI', 'redirectUri', 'http://localhost:9000/callback'),
    // omnistar snapshot node — same source Casdoor's ValidateObject reads.
    snapshotNode: env('WIKEY_NODE') ?? 'proxy.omnistar.io:9093',
    env: env('WIKEY_ENV') ?? 'main',
    snapshotSecure: env('WIKEY_SECURE') !== 'false',
    account: env('CASDOOR_ACCOUNT'),
    // Wikey proxy base (funding). Default = mainnet lab; override per environment
    // (e.g. a testnet lab or localhost) with WIKEY_PROXY_URL.
    proxyUrl: pick('WIKEY_PROXY_URL', 'proxyUrl', 'https://reverse-proxy.omnistar.io/mainnet/proxy').replace(/\/$/, ''),
  };
}
