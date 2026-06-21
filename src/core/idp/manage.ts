// Status + logout for the Casdoor/gateway flow (no network, no signing).

import { loadCfg } from './config.js';
import { readAccountAddress } from './identity.js';
import {
  loadTarget,
  loadCredential,
  clearTarget,
  clearCredential,
  type Target,
} from './target.js';

const maskSecret = (t: Target): Target => {
  const out: Target = { ...t };
  if (out.clientSecret) out.clientSecret = `${out.clientSecret.slice(0, 6)}…`;
  return out;
};

export interface GatewayStatus {
  hasTarget: boolean;
  target: Target | null;
  credential: {
    organization: string;
    username: string;
    safe: string;
    account: string;
    registeredAt: string;
  } | null;
  account: string | null;
  credentialMatchesTarget: boolean;
  hasOAuthClient: boolean;
}

/** Summarize the current gateway target + registered credential (secrets masked). */
export function gatewayStatus(): GatewayStatus {
  const target = loadTarget();
  const cred = loadCredential();
  let account: string | null = null;
  try {
    account = readAccountAddress(loadCfg());
  } catch {
    account = null;
  }
  const credentialMatchesTarget = Boolean(
    cred && target && cred.organization === target.organization && cred.username === target.username,
  );
  return {
    hasTarget: Boolean(target),
    target: target ? maskSecret(target) : null,
    credential: cred
      ? {
          organization: cred.organization,
          username: cred.username,
          safe: cred.safe,
          account: cred.account,
          registeredAt: cred.registeredAt,
        }
      : null,
    account,
    credentialMatchesTarget,
    hasOAuthClient: Boolean(target?.clientId),
  };
}

export interface GatewayLogoutResult {
  clearedTarget: Target | null;
  clearedCredential: boolean;
  note: string;
}

/** Forget local target + credential so the next register starts clean. */
export function gatewayLogout(): GatewayLogoutResult {
  const credExisted = Boolean(loadCredential());
  const clearedTarget = clearTarget({ keepPrev: true });
  const clearedCredential = clearCredential() || credExisted;
  return {
    clearedTarget: clearedTarget ? maskSecret(clearedTarget) : null,
    clearedCredential,
    note: 'Local target + credential forgotten. The passkey still exists on the remote gateway — delete it there too if you want a full reset.',
  };
}
