// Sealed gateway session (P-FIDO), keyed by identity alias. Enforces decision
// #1: the OAuth token lives like the HMAC key — held inside the server, NEVER
// returned to the model. status() reports auth state per alias with no token;
// the bearer is attached server-side inside call()/listTools(). Many identities
// can be authenticated at once; each has its own token + expiry.

import { CasdoorClient } from './casdoorClient.js';
import { IdentityRegistry } from './identityRegistry.js';
import { loadCredential, saveCredential } from './casdoorIdentity.js';

/** Re-login this many ms BEFORE the real expiry, to avoid mid-call expiry. */
const EXPIRY_SKEW_MS = 30_000;

interface SealedEntry {
  token: string;
  expiresAt: number;
}

export interface AliasStatus {
  alias: string;
  authenticated: boolean;
  registered: boolean;
  expiresInSec: number | null;
}

export interface GatewaySessionOpts {
  /** Override the credential-store root (tests). */
  stateRoot?: () => string;
}

export class GatewaySession {
  private readonly store = new Map<string, SealedEntry>();
  private readonly rootFn: (() => string) | undefined;

  constructor(
    private readonly client: CasdoorClient,
    private readonly registry: IdentityRegistry,
    opts: GatewaySessionOpts = {},
  ) {
    this.rootFn = opts.stateRoot;
  }

  /** Enroll the wallet passkey for `alias` using its operator bootstrap password. */
  async register(alias: string): Promise<{ registered: true; safe: string }> {
    const bundle = this.registry.resolve(alias);
    const password = this.registry.bootstrapPassword(alias);
    const res = await this.client.register(bundle, password);
    saveCredential(
      alias,
      {
        credentialIdB64url: res.credentialIdB64url,
        safe: res.safe,
        account: res.account,
        org: bundle.org,
        user: bundle.user,
        registeredAt: new Date().toISOString(),
      },
      this.rootFn,
    );
    return { registered: true, safe: res.safe };
  }

  /** Ensure a live token for `alias`, re-logging-in if missing/expired. Token stays sealed. */
  private async ensureToken(alias: string): Promise<string> {
    const existing = this.store.get(alias);
    if (existing && existing.expiresAt - EXPIRY_SKEW_MS > Date.now()) {
      return existing.token;
    }
    const bundle = this.registry.resolve(alias);
    const cred = loadCredential(alias, this.rootFn);
    if (!cred) {
      throw new Error(`identity "${alias}" is not registered — call wallet_gateway_register first`);
    }
    const res = await this.client.login(bundle, cred);
    this.store.set(alias, { token: res.token, expiresAt: res.expiresAt });
    return res.token;
  }

  /** Public login entry point (no token returned) — drives ensureToken, reports status. */
  async login(alias: string): Promise<AliasStatus> {
    await this.ensureToken(alias);
    return this.statusFor(alias);
  }

  /** List the upstream tools of a gateway server (redaction happens at the tool layer). */
  async listTools(alias: string, ownerName: string): Promise<unknown> {
    const bundle = this.registry.resolve(alias);
    const token = await this.ensureToken(alias);
    return this.client.gatewayCall(bundle, token, ownerName, 'tools/list', {});
  }

  /** Call an upstream tool through the gateway (auto-login). Bearer attached internally. */
  async call(alias: string, ownerName: string, name: string, args: unknown): Promise<unknown> {
    const bundle = this.registry.resolve(alias);
    const token = await this.ensureToken(alias);
    return this.client.gatewayCall(bundle, token, ownerName, 'tools/call', { name, arguments: args ?? {} });
  }

  /** Per-alias auth state with NO token. Omit `alias` for all approved identities. */
  status(alias?: string): AliasStatus | AliasStatus[] {
    if (alias !== undefined) return this.statusFor(alias);
    return this.registry.list().map((s) => this.statusFor(s.alias));
  }

  private statusFor(alias: string): AliasStatus {
    const entry = this.store.get(alias);
    const authenticated = Boolean(entry && entry.expiresAt - EXPIRY_SKEW_MS > Date.now());
    const registered = loadCredential(alias, this.rootFn) !== null;
    return {
      alias,
      authenticated,
      registered,
      expiresInSec: entry ? Math.max(0, Math.round((entry.expiresAt - Date.now()) / 1000)) : null,
    };
  }

  /** Drop every sealed token. Idempotent. */
  shutdown(): void {
    for (const entry of this.store.values()) entry.token = '';
    this.store.clear();
  }
}
