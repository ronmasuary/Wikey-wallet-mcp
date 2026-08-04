// Recovery deeplink contract.
//
// When a user who lost their key requests recovery, the wallet hands them a link
// they forward to a recovery helper. The helper opens it in the Wikey wallet app,
// or gives it to their own AI agent (this MCP) to approve the recovery.
//
//   https://open.wikey.io/accountRecover?t=recover&pk=<newAddress>&tn=<accountName>
//
//   t  — deeplink type. 'recover' for an approve-recovery request ('setup' is a
//        separate onboarding deeplink handled elsewhere).
//   pk — public key / address of the NEW account the lost account is recovered
//        onto (the key the requester now signs with).
//   tn — trustor name: the account ASKING for help (the username being recovered).
//
// The helper side maps these straight onto `approve-recovery`:
//   --oldaccount = tn   --newaccount = pk

export const RECOVERY_DEEPLINK_BASE = 'https://open.wikey.io/accountRecover';
export const RECOVERY_DEEPLINK_TYPE = 'recover';

export interface RecoveryDeeplinkParts {
  /** Deeplink type (`t`). Always 'recover' for a recovery-approval link. */
  type: string;
  /** `pk` — the new account address the lost account is being recovered onto. */
  newAccount: string;
  /** `tn` — the name/username of the account asking for help (being recovered). */
  accountName: string;
}

/** Build the helper deeplink the recovering user forwards to a recovery helper. */
export function buildRecoveryDeeplink(parts: {
  newAccount: string;
  accountName: string;
  type?: string;
}): string {
  const newAccount = (parts.newAccount ?? '').trim();
  const accountName = (parts.accountName ?? '').trim();
  if (!newAccount) throw new Error('buildRecoveryDeeplink: newAccount (pk) is required');
  if (!accountName) throw new Error('buildRecoveryDeeplink: accountName (tn) is required');
  const q = new URLSearchParams({
    t: parts.type ?? RECOVERY_DEEPLINK_TYPE,
    pk: newAccount,
    tn: accountName,
  });
  return `${RECOVERY_DEEPLINK_BASE}?${q.toString()}`;
}

/**
 * Parse a recovery deeplink a helper received. Lenient about scheme/host casing,
 * strict about the discriminator (`t=recover`) and the required params so an
 * unrelated URL never silently drives a signing call.
 */
export function parseRecoveryDeeplink(link: string): RecoveryDeeplinkParts {
  let url: URL;
  try {
    url = new URL(String(link).trim());
  } catch {
    throw new Error(`Not a valid recovery deeplink URL: ${link}`);
  }

  const t = url.searchParams.get('t') ?? '';
  const pk = url.searchParams.get('pk') ?? '';
  const tn = url.searchParams.get('tn') ?? '';

  if (t !== RECOVERY_DEEPLINK_TYPE) {
    throw new Error(
      `Recovery deeplink type must be t=${RECOVERY_DEEPLINK_TYPE}, got t=${t || '(missing)'}`,
    );
  }
  if (!pk) throw new Error('Recovery deeplink is missing pk (new account address).');
  if (!tn) throw new Error('Recovery deeplink is missing tn (account name being recovered).');

  return { type: t, newAccount: pk, accountName: tn };
}
