// Config-key lockdown (H10). A prompt-injected model could use wallet_config_set
// to repoint `signer.url` off-loopback (talk to a hostile signer) or weaken
// at-rest protection by flipping `keystore`/`kek-provider`. We hard-reject
// changes to security-critical keys server-side, where the model can't override.
// Reads of config stay free.
//
// Locked: signer.*, *.url (incl. signer.url, pinned loopback), apiKey, kek*,
// keystore*, user.*.

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
  const cat = lockedConfigCategory(key);
  if (cat) {
    throw new Error(
      `config key "${key}" is locked (${cat}) by wikey-wallet-mcp and cannot be changed through the tool boundary. ` +
        `signer.url is pinned to loopback; keystore/kek are fixed by the wrapper. Reads (wallet_config_get/show) are allowed.`,
    );
  }
}
