// Concept glossary surfaced to the connecting agent — on start (via the MCP
// `instructions` field) and on demand (via the `wallet_concepts` tool). Single
// source of truth so both paths can never disagree.
//
// Provenance: the bodies below are copied VERBATIM from the human-facing skill
// doc `ssp-agent-child` ("Profile vs. Safe", "SIGNATURE vs transfer_id",
// "balance vs balances vs assets"). The doc lives outside this repo, so this is
// a copy, not an import — if the doc wording changes, update here deliberately.

export const CONCEPTS: Record<string, string> = {
  profile:
    'Profile — the on-chain snapshot of the key SSP is managing for you. The profile holds your address, your public key, and a list of safes this key is permitted to operate on. The profile does NOT hold any safe\'s signing material; it only describes what this key is allowed to do and where. When you want to know "what can I do?" — query your profile (wallet_profile).',
  safe:
    'Safe — a separate on-chain account with its own address, asset balances, and policies. You don\'t have the safe\'s keys. Instead, your key submits policy-gated commands referencing a safe (vote, create-transaction, edit-policy, ...). Whether those commands take effect is decided by the safe\'s policies and the votes of its other authorized keys. When you want to know "what does this safe hold / who are its other signers / which policies guard it?" — query the safe by its address.',
  'signature-vs-transferid':
    'SIGNATURE (Omnistar tx hash) vs target-chain transfer_id — when you broadcast any command to the Omnistar chain, the result is an Omnistar tx hash, stored on every on-chain object as its SIGNATURE field (policies, users, transactions, votes). When a later command references an object (tx edit-policy/delete-policy/vote/delete-user --signature SIG), SIG is this Omnistar tx hash read out of the snapshot. Do NOT confuse it with a target-chain transfer id: when a tx create-transaction clears policy and the safe actually moves BTC/ETH/SOL/USDC on the target chain, that transfer has its own hash on THAT chain (a Bitcoin txid, an Ethereum tx hash, a Solana signature). That id is for the target-chain explorer only — it is NOT an Omnistar SIGNATURE and cannot be passed to --signature flags.',
  'balance-vs-balances-vs-assets':
    'balance vs balances vs assets — query balance returns a single denomination for the address (default --denom nost); a thin filter over balances for when you only need OST. query balances returns all denoms held directly by the address (the key); the OST line is included. query assets returns the balances of non-OST assets (BTC, ETH, SOL, ERC20s, ...) held by the safe at the given address — to inspect what a safe under your control holds, pass that safe\'s address. Asset balances are in display units; multiply by the entry\'s smallCoin to get the smallest on-chain unit before transferring.',
};

/**
 * Full glossary as a single titled block — used for the on-start MCP
 * `instructions` field so the agent knows these terms without a tool call.
 */
export function conceptsText(): string {
  const body = Object.values(CONCEPTS)
    .map((v) => `- ${v}`)
    .join('\n\n');
  return `Wikey/Omnistar key concepts the operator may reference. Call wallet_concepts any time to re-fetch one or all of these.\n\n${body}`;
}

/**
 * One concept by key (case-insensitive), or the whole glossary when `concept`
 * is omitted. Unknown keys return an `error` row listing the known keys.
 */
export function lookupConcept(concept?: string): Record<string, string> {
  if (!concept) return CONCEPTS;
  const key = concept.trim().toLowerCase();
  const hit = CONCEPTS[key];
  if (hit !== undefined) return { [key]: hit };
  return { error: `Unknown concept "${concept}". Known: ${Object.keys(CONCEPTS).join(', ')}` };
}
