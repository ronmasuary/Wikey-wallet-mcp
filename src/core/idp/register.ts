// Guided (re-)enrollment of the wallet passkey against a chosen gateway.
//
// The realistic path is an invited employee: they hand the agent an invitation
// link. From the single link the agent derives host/application/organization/
// pinned-username (via /api/get-invitation-info) and the public clientId +
// redirectUri (via /api/get-application), signs up with the invitation code (the
// one-time secret — no password), and binds the wallet passkey to the SAFE.
//
// Enroll does NO wallet signing: it takes the account from the caller, resolves
// that account's safe ecPuk from chain snapshots, and POSTs WebAuthn signup.

import { loadCfg } from './config.js';
import { loadTarget, saveTarget, targetPrevFile, saveCredential, type Target } from './target.js';
import { resolveWalletIdentity, waitForWalletIdentity } from './identity.js';
import { passwordLogin, signupWithInvitation } from './casdoorSession.js';
import { buildAttestation } from './webauthn.js';
import { randomBytes } from 'node:crypto';

export interface RegisterInput {
  invite?: string;
  host?: string;
  organization?: string;
  username?: string;
  application?: string;
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  rpId?: string;
  origin?: string;
  invitationCode?: string;
  password?: string;
  /**
   * The account whose safe the passkey binds to. REQUIRED — there is no default
   * key to infer it from. Sponsor onboarding passes the key it just created the
   * safe on; the MCP dispatcher otherwise settles it with resolveAccount.
   */
  account?: string;
  /**
   * Wait for the account's safe to become queryable instead of failing fast.
   * Needed when enrollment follows create-safe in the same call (~30s validation).
   */
  waitForSafe?: boolean;
}

const TARGET_KEYS: (keyof Target)[] = [
  'host',
  'rpId',
  'origin',
  'organization',
  'username',
  'application',
  'clientId',
  'clientSecret',
  'redirectUri',
];

const stripUndef = (o: Record<string, unknown>): Record<string, string> =>
  Object.fromEntries(
    Object.entries(o).filter(([, v]) => v != null && v !== '').map(([k, v]) => [k, String(v)]),
  );

interface InviteDerived extends Target {
  invitationCode?: string;
  email?: string;
}

/** Derive host/app/org/user/code from an invitation link + /api/get-invitation-info. */
async function resolveInvite(link: string): Promise<InviteDerived> {
  const u = new URL(link);
  const host = u.origin;
  const application = decodeURIComponent(u.pathname.replace(/^\/signup\//, '').replace(/\/$/, ''));
  const invitationCode = u.searchParams.get('invitationCode') || '';
  if (!application || !invitationCode) {
    throw new Error('invite link must look like {host}/signup/{application}?invitationCode=…');
  }
  const appId = application.includes('/') ? application : `admin/${application}`;
  const derived: InviteDerived = { host, application, invitationCode };

  // A self-contained link carries the wallet handle as username@organization
  // (e.g. kehat@wikey). For Casdoor enrollment we need the *local* part as the
  // username and the domain as the org — used only as a fallback, since
  // /api/get-invitation-info (below) is authoritative and overrides these.
  const urlUsername = u.searchParams.get('username') || '';
  if (urlUsername) {
    const at = urlUsername.indexOf('@');
    if (at > 0) {
      derived.username = urlUsername.slice(0, at);
      derived.organization = urlUsername.slice(at + 1);
    } else {
      derived.username = urlUsername;
    }
  }

  // Invitation → organization (owner) + pinned username.
  try {
    const res = await fetch(
      `${host}/api/get-invitation-info?code=${encodeURIComponent(invitationCode)}&applicationId=${encodeURIComponent(appId)}`,
    );
    const body = (await res.json().catch(() => ({}))) as {
      status?: string;
      msg?: string;
      data?: { owner?: string; username?: string; email?: string };
    };
    const inv = body.data;
    if (body.status === 'ok' && inv) {
      if (inv.owner) derived.organization = inv.owner;
      if (inv.username) derived.username = inv.username;
      if (inv.email) derived.email = inv.email;
    }
  } catch {
    /* best-effort; explicit fields can still fill the gaps */
  }

  // Application → clientId + redirectUri (both public; the passkey login is a
  // public PKCE client, so the secret is never needed).
  try {
    const res = await fetch(`${host}/api/get-application?id=${encodeURIComponent(appId)}`);
    const body = (await res.json().catch(() => ({}))) as {
      status?: string;
      data?: { clientId?: string; redirectUris?: string[] };
    };
    const app = body.data;
    if (body.status === 'ok' && app) {
      if (app.clientId) derived.clientId = app.clientId;
      if (Array.isArray(app.redirectUris) && app.redirectUris[0]) derived.redirectUri = app.redirectUris[0];
    }
  } catch {
    /* best-effort */
  }

  return derived;
}

/** Fill rpId/origin from host, and a default loopback redirect, when absent. */
function deriveDefaults(t: Target): Target {
  const d: Target = { ...t };
  if (d.host) {
    try {
      const u = new URL(d.host);
      if (!d.rpId) d.rpId = u.hostname;
      if (!d.origin) d.origin = u.origin;
    } catch {
      /* host not a full URL yet */
    }
  }
  if (!d.redirectUri) d.redirectUri = 'http://localhost:9000/callback';
  return d;
}

export interface RegisterResult {
  registered: true;
  target: Target;
  account: string;
  safe: string;
  organization: string;
  username: string;
  application: string;
  credentialId: string;
  bootstrap: 'invitation-code' | 'password';
  hasOAuthClient: boolean;
}

/** Run the full enroll: resolve target → bootstrap session → bind passkey to safe. */
export async function gatewayRegister(input: RegisterInput): Promise<RegisterResult> {
  const prev = loadTarget() ?? loadTarget(targetPrevFile()) ?? {};

  let inviteDerived: InviteDerived = {};
  let invitationCode = input.invitationCode;
  if (input.invite) {
    inviteDerived = await resolveInvite(input.invite);
    invitationCode = invitationCode || inviteDerived.invitationCode;
    delete inviteDerived.invitationCode; // secret — never persisted to the target file
    delete inviteDerived.email;
  }

  const flagFields = stripUndef({
    host: input.host,
    rpId: input.rpId,
    origin: input.origin,
    organization: input.organization,
    username: input.username,
    application: input.application,
    clientId: input.clientId,
    clientSecret: input.clientSecret,
    redirectUri: input.redirectUri,
  });

  // Precedence: explicit fields > invite-derived > previous target.
  let target = deriveDefaults({ ...prev, ...stripUndef(inviteDerived as Record<string, unknown>), ...flagFields });

  const required: (keyof Target)[] = ['organization', 'username', 'application', 'host'];
  const missing = required.filter((k) => !target[k]);
  if (missing.length) {
    throw new Error(
      `missing required field(s): ${missing.join(', ')} — pass an --invite link or these explicitly`,
    );
  }

  const saved = saveTarget(target);
  target = saved;

  const password = input.password ?? (process.env.CASDOOR_PASSWORD || undefined);
  if (!invitationCode && !password) {
    throw new Error('no bootstrap secret — pass an invite link, invitationCode, or password');
  }

  const cfg = loadCfg(saved);
  if (!input.account) {
    throw new Error(
      'wallet_gateway_register requires the account whose safe the passkey binds to — ' +
        'this wallet has no default key. Pass `account` (wallet_accounts lists them).',
    );
  }
  const id = input.waitForSafe
    ? await waitForWalletIdentity(cfg, input.account)
    : await resolveWalletIdentity(cfg, input.account);

  // 1. bootstrap session (signup-with-code preferred; password for existing users)
  let jar;
  let bootstrap: 'invitation-code' | 'password';
  if (invitationCode) {
    bootstrap = 'invitation-code';
    try {
      jar = await signupWithInvitation({
        host: cfg.host,
        organization: cfg.organization,
        application: cfg.application,
        username: cfg.username,
        password: invitationCode, // throwaway; the passkey supersedes it
        name: cfg.username,
        invitationCode,
      });
    } catch (e) {
      // Idempotent re-runs: if the invite already created the user, log in with
      // the code (which also serves as the password) and re-enroll the passkey.
      if (/exist/i.test((e as Error).message)) {
        jar = await passwordLogin({
          host: cfg.host,
          organization: cfg.organization,
          username: cfg.username,
          password: invitationCode,
          application: cfg.application,
        });
      } else {
        throw e;
      }
    }
  } else {
    bootstrap = 'password';
    jar = await passwordLogin({
      host: cfg.host,
      organization: cfg.organization,
      username: cfg.username,
      password: password as string,
      application: cfg.application,
    });
  }
  const cookie = jar.header();

  // 2. signup/begin → challenge
  const beginRes = await fetch(`${cfg.host}/api/webauthn/signup/begin`, { headers: { cookie } });
  const beginText = await beginRes.text();
  if (!beginRes.ok) throw new Error(`signup/begin HTTP ${beginRes.status}: ${beginText.slice(0, 300)}`);
  const options = JSON.parse(beginText) as {
    publicKey?: { challenge?: string; rp?: { id?: string } };
    challenge?: string;
    rp?: { id?: string };
  };
  const pk = options.publicKey ?? options;
  const challengeB64url = pk.challenge;
  const rpId = pk.rp?.id || cfg.rpId;
  if (!challengeB64url) throw new Error(`no challenge in signup/begin: ${beginText.slice(0, 200)}`);

  // 3. attestation (credential public key = safe ecPuk)
  const credentialId = randomBytes(32);
  const att = buildAttestation({
    rpId,
    origin: cfg.origin,
    challengeB64url,
    credentialId,
    x: id.x,
    y: id.y,
  });

  // 4. signup/finish → Casdoor binds webauthnWikeyAddress = safe address
  const finishRes = await fetch(`${cfg.host}/api/webauthn/signup/finish`, {
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
  const finishText = await finishRes.text();
  let finish: { status?: string; msg?: string };
  try {
    finish = JSON.parse(finishText) as { status?: string; msg?: string };
  } catch {
    throw new Error(`signup/finish non-JSON: ${finishText.slice(0, 300)}`);
  }
  if (finish.status && finish.status !== 'ok') {
    throw new Error(`signup/finish error: ${finish.msg || finishText.slice(0, 300)}`);
  }

  // 5. persist credential
  saveCredential({
    credentialIdB64url: att.credentialIdB64url,
    safe: id.safe,
    account: id.account,
    organization: cfg.organization,
    username: cfg.username,
    registeredAt: new Date().toISOString(),
  });

  return {
    registered: true,
    target: saved,
    account: id.account,
    safe: id.safe,
    organization: cfg.organization,
    username: cfg.username,
    application: cfg.application,
    credentialId: att.credentialIdB64url,
    bootstrap,
    hasOAuthClient: Boolean(saved.clientId),
  };
}
