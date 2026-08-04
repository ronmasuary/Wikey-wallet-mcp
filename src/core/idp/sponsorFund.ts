// Pre-passkey sponsor funding: turn an invitation link into a funded key.
//
// This is the ONE call in the onboarding sequence that goes DIRECT to the Wikey
// proxy (not through the gateway) — it happens before any safe or passkey exists,
// so it is gated only by the one-time invitation code. The proxy verifies the
// code against its `sponsorships` ledger and airdrops gas to the address, once.
//
// No signing and no SSP session: it only reads the default key address through
// the same non-signing `query` runner every read tool uses.

import { loadCfg } from './config.js';
import { parseDefaultAddress } from '../gettingStarted.js';

export interface ParsedInvite {
  host: string;
  application: string;
  invitationCode: string;
  /** The full wallet handle from the link, username@organization (e.g. kehat@wikey). */
  username: string;
  organization: string;
  /**
   * Whether this invite should bind a gateway passkey after the safe is created.
   * The idp appends `&enroll=false` for the fund-and-create-only variant; every
   * other link (and every link issued before that variant existed) omits it, so
   * the default is `true` and existing onboarding is unchanged.
   */
  enroll: boolean;
}

/** Parse the self-contained invite link. Throws if it isn't a signup link with a code. */
export function parseInvite(link: string): ParsedInvite {
  let u: URL;
  try {
    u = new URL(link);
  } catch {
    throw new Error('invalid invite link (not a URL)');
  }
  const host = u.origin;
  const application = decodeURIComponent(u.pathname.replace(/^\/signup\//, '').replace(/\/$/, ''));
  const invitationCode = u.searchParams.get('invitationCode') || '';
  const username = u.searchParams.get('username') || '';
  if (!application || !invitationCode) {
    throw new Error('invite link must look like {host}/signup/{application}?invitationCode=…');
  }
  const at = username.indexOf('@');
  const organization = at > 0 ? username.slice(at + 1) : '';
  // Only the explicit string "false" disables enrollment; anything else (absent,
  // "true", garbage) keeps the default enrol-after-create behavior.
  const enroll = u.searchParams.get('enroll') !== 'false';
  return { host, application, invitationCode, username, organization, enroll };
}

export interface SponsorFundResult {
  funded: boolean;
  address: string;
  /** Full wallet handle for the safe (username@organization). Empty if the link omitted it. */
  username: string;
  organization: string;
  proxyUrl: string;
  /**
   * True ONLY when the grant is committed (`funded:true`) — the invite genuinely
   * onboarded an account, so re-onboarding is a recovery. NOT set for a mere
   * reservation, which is resumable; see `reservedAddress`.
   */
  alreadySpent: boolean;
  /**
   * The address the grant is reserved to, when the proxy refused because someone
   * else holds the reservation (HTTP 409) or reports it committed (403). If this
   * address is in the local keystore, the grant is OURS to resume: the gas is
   * already on that key and only it can finish the onboarding.
   */
  reservedAddress?: string;
  message?: string;
}

/**
 * Ask the proxy to fund `address` (or the default signing key) against the
 * invite's one-time code. Returns `{funded:true}` on success.
 *
 * The two refusal codes are NOT the same thing and must not be collapsed:
 *   - 403 → the grant is committed (or the code is unknown): genuinely spent,
 *     `alreadySpent:true`, the caller should route to recovery.
 *   - 409 → the grant is reserved to another address: value already moved, but
 *     nothing was onboarded. Surfaced with `reservedAddress` so the caller can
 *     resume on that key rather than declaring a false "already used".
 * Neither is thrown, so the orchestrator can branch on them.
 */
export async function sponsorFund(
  invite: string,
  query: (args: string[]) => Promise<string>,
  explicitAddress?: string,
): Promise<SponsorFundResult> {
  const parsed = parseInvite(invite);
  const cfg = loadCfg();

  let address = explicitAddress;
  if (!address) {
    try {
      address = parseDefaultAddress(await query(['config', 'get', 'user.address']));
    } catch {
      /* no default configured */
    }
  }
  if (!address) {
    throw new Error(
      'no default signing key to fund — create one first (wallet_keys_create {setDefault:true})',
    );
  }

  const res = await fetch(`${cfg.proxyUrl}/users/invitations/sponsorFund`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', env: cfg.env },
    body: JSON.stringify({ code: parsed.invitationCode, address }),
  });
  const text = await res.text();
  let body: { funded?: boolean; message?: string; reservedAddress?: string; committed?: boolean } = {};
  try {
    body = JSON.parse(text) as typeof body;
  } catch {
    /* non-JSON error body — keep the raw text below */
  }

  const base = {
    address,
    username: parsed.username,
    organization: parsed.organization,
    proxyUrl: cfg.proxyUrl,
  };

  // 403 = committed/unknown code → genuinely spent. 409 = reserved elsewhere →
  // resumable by the reserving key, NOT spent. `committed` is echoed by newer
  // proxies; fall back to the status code alone against an older one.
  if (res.status === 403 || res.status === 409) {
    return {
      ...base,
      funded: false,
      alreadySpent: body.committed ?? res.status === 403,
      reservedAddress: body.reservedAddress,
      message: body.message || (res.status === 403 ? 'sponsorship already used' : 'sponsorship reserved for another address'),
    };
  }
  if (!res.ok || !body.funded) {
    throw new Error(`sponsorFund failed (HTTP ${res.status}): ${body.message || text.slice(0, 200)}`);
  }

  return { ...base, funded: true, alreadySpent: false };
}

export interface SponsorCommitResult {
  committed: boolean;
  message?: string;
}

/**
 * Phase 2 of sponsor funding: finalize (commit) the grant AFTER create-safe has
 * created the safe, so a failed create-safe never permanently spends the one-time
 * grant. sponsorFund only RESERVES + airdrops; the grant is not marked spent until
 * this call. Idempotent and best-effort: an already-committed or missing-reservation
 * response is not thrown — the safe already exists, which is what matters.
 */
export async function sponsorCommit(
  invite: string,
  address: string,
): Promise<SponsorCommitResult> {
  const parsed = parseInvite(invite);
  const cfg = loadCfg();

  const res = await fetch(`${cfg.proxyUrl}/users/invitations/sponsorCommit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', env: cfg.env },
    body: JSON.stringify({ code: parsed.invitationCode, address }),
  });
  const text = await res.text();
  let body: { committed?: boolean; message?: string } = {};
  try {
    body = JSON.parse(text) as typeof body;
  } catch {
    /* non-JSON error body */
  }

  return { committed: res.ok && Boolean(body.committed), message: body.message };
}
