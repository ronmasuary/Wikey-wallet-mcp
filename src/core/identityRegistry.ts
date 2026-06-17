// Operator-controlled identity registry (P-FIDO). The trust boundary for the
// multi-identity gateway: the model picks an identity by ALIAS only; every URL
// (Casdoor host, origin, snapshot node, redirect) comes from here, never from
// the model. resolve() is the single choke point — it must never accept a
// model-supplied host, or SSRF/phishing returns (plan risk #8).
//
// Identities load from two operator-only sources, merged (file wins so the
// operator can override/add at runtime without a restart):
//   1. Environment: WIKEY_CASDOOR_ALIASES="work,team" lists env-defined aliases;
//      each field is WIKEY_CASDOOR_<FIELD>__<ALIAS> (alias upper-cased, non
//      [A-Z0-9] → _). e.g. WIKEY_CASDOOR_HOST__WORK.
//   2. File: <stateRoot>/casdoor-identities.json — a JSON array of bundles,
//      re-read on EVERY resolve()/list() so runtime-added identities appear live.
//
// The per-identity bootstrap password (one-time registration secret) is NOT part
// of the bundle and never returned: WIKEY_CASDOOR_BOOTSTRAP_PASSWORD__<ALIAS>.

import { readFileSync } from 'node:fs';
import path from 'node:path';

import { stateRoot } from './binPaths.js';

/** A named, fully operator-defined Casdoor identity. No secrets here. */
export interface IdentityBundle {
  alias: string;
  /** Casdoor base URL (no trailing slash). */
  host: string;
  rpId: string;
  origin: string;
  org: string;
  user: string;
  app: string;
  clientId: string;
  /** Omnistar snapshot node host:port — MUST be the node Casdoor's wikeyNode reads. */
  snapshotNode: string;
  env: string;
  /** OAuth redirect_uri — must match the value registered on the Casdoor app. */
  redirectUri: string;
  /** OAuth scope. Default 'read'. Custom scopes trigger consent — keep minimal (decision #7). */
  scope: string;
  /** https (true) vs http (false) for the snapshot node. Default true. */
  snapshotSecure: boolean;
}

/** Non-secret summary surfaced to the model via wallet_gateway_list_identities. */
export interface IdentitySummary {
  alias: string;
  host: string;
  org: string;
  user: string;
  app: string;
  env: string;
}

const FIELD_ENV: Record<string, keyof IdentityBundle> = {
  HOST: 'host',
  RP_ID: 'rpId',
  ORIGIN: 'origin',
  ORG: 'org',
  USER: 'user',
  APP: 'app',
  CLIENT_ID: 'clientId',
  SNAPSHOT_NODE: 'snapshotNode',
  ENV: 'env',
  REDIRECT_URI: 'redirectUri',
  SCOPE: 'scope',
  SNAPSHOT_SECURE: 'snapshotSecure',
};

const REQUIRED: (keyof IdentityBundle)[] = [
  'host', 'rpId', 'origin', 'org', 'user', 'app', 'clientId', 'snapshotNode', 'env', 'redirectUri',
];

function aliasEnvKey(alias: string): string {
  return alias.toUpperCase().replace(/[^A-Z0-9]/g, '_');
}

function stripSlash(u: string): string {
  return u.replace(/\/+$/, '');
}

export interface IdentityRegistryOpts {
  /** Override the state root resolver (tests). */
  stateRoot?: () => string;
  /** Override the env source (tests). */
  env?: NodeJS.ProcessEnv;
}

export class IdentityRegistry {
  private readonly stateRootFn: () => string;
  private readonly envSource: NodeJS.ProcessEnv;

  constructor(opts: IdentityRegistryOpts = {}) {
    this.stateRootFn = opts.stateRoot ?? stateRoot;
    this.envSource = opts.env ?? process.env;
  }

  private filePath(): string {
    return path.join(this.stateRootFn(), 'casdoor-identities.json');
  }

  /** Resolve an alias to its full bundle, or throw "unknown identity". */
  resolve(alias: string): IdentityBundle {
    const all = this.loadAll();
    const bundle = all.get(alias);
    if (!bundle) {
      const known = [...all.keys()];
      throw new Error(
        `unknown identity "${alias}". Approved aliases: ${known.length ? known.join(', ') : '(none)'}. ` +
          `The operator adds identities via env (WIKEY_CASDOOR_ALIASES) or ${this.filePath()}.`,
      );
    }
    return bundle;
  }

  /** List approved aliases with non-secret descriptive fields. */
  list(): IdentitySummary[] {
    return [...this.loadAll().values()].map((b) => ({
      alias: b.alias,
      host: b.host,
      org: b.org,
      user: b.user,
      app: b.app,
      env: b.env,
    }));
  }

  /** The one-time bootstrap password for `alias`, or throw if unset (never logged/returned). */
  bootstrapPassword(alias: string): string {
    const key = `WIKEY_CASDOOR_BOOTSTRAP_PASSWORD__${aliasEnvKey(alias)}`;
    const pw = this.envSource[key];
    if (!pw) {
      throw new Error(
        `no bootstrap password for identity "${alias}" — set ${key} (one-time; unset after enrollment).`,
      );
    }
    return pw;
  }

  // ─── loading ──────────────────────────────────────────────────────────────

  private loadAll(): Map<string, IdentityBundle> {
    const map = new Map<string, IdentityBundle>();
    for (const b of this.loadFromEnv()) map.set(b.alias, b);
    for (const b of this.loadFromFile()) map.set(b.alias, b); // file wins (live-editable)
    return map;
  }

  private loadFromEnv(): IdentityBundle[] {
    const list = (this.envSource.WIKEY_CASDOOR_ALIASES ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const out: IdentityBundle[] = [];
    for (const alias of list) {
      const suffix = aliasEnvKey(alias);
      const raw: Record<string, unknown> = { alias };
      for (const [field, prop] of Object.entries(FIELD_ENV)) {
        const v = this.envSource[`WIKEY_CASDOOR_${field}__${suffix}`];
        if (v !== undefined) raw[prop] = v;
      }
      out.push(this.normalize(raw, `env alias "${alias}"`));
    }
    return out;
  }

  private loadFromFile(): IdentityBundle[] {
    let text: string;
    try {
      text = readFileSync(this.filePath(), 'utf8');
    } catch {
      return []; // absent is fine — env-only is a valid configuration
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      throw new Error(`${this.filePath()}: invalid JSON — ${(e as Error).message}`);
    }
    const arr = Array.isArray(parsed) ? parsed : (parsed as { identities?: unknown }).identities;
    if (!Array.isArray(arr)) {
      throw new Error(`${this.filePath()}: expected a JSON array of identity bundles`);
    }
    return arr.map((entry, i) => {
      const o = (entry && typeof entry === 'object' ? entry : {}) as Record<string, unknown>;
      const where = typeof o.alias === 'string' ? `file alias "${o.alias}"` : `file entry #${i}`;
      return this.normalize(o, where);
    });
  }

  /** Validate + apply defaults + normalize URLs. Throws on a missing required field. */
  private normalize(raw: Record<string, unknown>, where: string): IdentityBundle {
    const get = (k: keyof IdentityBundle): string | undefined => {
      const v = raw[k];
      return typeof v === 'string' && v.length > 0 ? v : undefined;
    };
    const alias = get('alias');
    if (!alias) throw new Error(`${where}: missing "alias"`);

    const bundle: IdentityBundle = {
      alias,
      host: stripSlash(get('host') ?? ''),
      rpId: get('rpId') ?? '',
      origin: stripSlash(get('origin') ?? ''),
      org: get('org') ?? '',
      user: get('user') ?? '',
      app: get('app') ?? '',
      clientId: get('clientId') ?? '',
      snapshotNode: get('snapshotNode') ?? '',
      env: get('env') ?? '',
      redirectUri: get('redirectUri') ?? '',
      scope: get('scope') ?? 'read',
      snapshotSecure: parseBool(raw.snapshotSecure, true),
    };

    const missing = REQUIRED.filter((k) => !bundle[k]);
    if (missing.length) {
      throw new Error(`identity ${where}: missing required field(s): ${missing.join(', ')}`);
    }
    return bundle;
  }
}

function parseBool(v: unknown, dflt: boolean): boolean {
  if (v === undefined || v === null || v === '') return dflt;
  if (typeof v === 'boolean') return v;
  const s = String(v).toLowerCase();
  return !(s === 'false' || s === '0' || s === 'no');
}
