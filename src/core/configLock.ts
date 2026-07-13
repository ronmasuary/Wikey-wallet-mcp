// Config-key lockdown (H10). A prompt-injected model could use wallet_config_set
// to repoint `signer.url` off-loopback (talk to a hostile signer) or weaken
// at-rest protection by flipping `keystore`/`kek-provider`. We hard-reject
// changes to security-critical keys server-side, where the model can't override.
// Reads of config stay free.
//
// Locked: signer.*, *.url (incl. signer.url, pinned loopback), apiKey, kek*,
// keystore*, user.*.
//
// OPERATOR ESCAPE HATCH: set WIKEY_UNLOCK_CONFIG=1 (operator env, NOT agent-
// controllable — same class as WIKEY_SSP_DIR) to bypass the lock entirely and
// allow the tool boundary to set any config key. This defeats the H10 threat
// model (a prompt-injected model can repoint signing at a hostile signer, weaken
// at-rest protection, etc.); enable it only in a trusted, non-adversarial
// environment. The lock stays ON by default.

/** True when the operator has opted out of the config lock via env. */
export function configLockDisabled(): boolean {
  const v = (process.env.WIKEY_UNLOCK_CONFIG ?? '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

export function lockedConfigCategory(key: string): string | null {
  const lower = key.trim().toLowerCase();
  if (lower === 'signer' || lower.startsWith('signer.')) return 'signer.*';
  if (lower === 'url' || lower.endsWith('.url')) return '*.url';
  if (lower.includes('apikey')) return 'apiKey';
  if (lower.startsWith('kek')) return 'kek*';
  if (lower.startsWith('keystore')) return 'keystore*';
  if (lower === 'user' || lower.startsWith('user.')) return 'user.*';
  return null;
}

export function isLockedConfigKey(key: string): boolean {
  return lockedConfigCategory(key) !== null;
}

/** Throws if the config_set is not allowed. */
export function assertConfigSetAllowed(key: string): void {
  if (configLockDisabled()) return; // operator opted out (WIKEY_UNLOCK_CONFIG)
  const cat = lockedConfigCategory(key);
  if (cat) {
    throw new Error(
      `config key "${key}" is locked (${cat}) by wikey-wallet-mcp and cannot be changed through the tool boundary. ` +
        `signer.url is pinned to loopback; keystore/kek are fixed by the wrapper. Reads (wallet_config_get/show) are allowed.`,
    );
  }
}
