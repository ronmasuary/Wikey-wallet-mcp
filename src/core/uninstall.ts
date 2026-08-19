// Complete local uninstall — the one irreversible operation in the tool surface.
//
// This deletes signing keys. A deleted key is not recoverable from a backup, a
// passphrase, or Wikey: the private material lives encrypted in the SSP keystore
// under a KEK this machine holds, and nothing off-machine can reconstruct it.
// The only way back into an account whose key is gone is the on-chain recovery
// path — its helpers approving `updateUserAddress` onto a new key — which exists
// only if helpers were configured BEFORE the key was destroyed.
//
// So the AUDIT, not the deletion, is the substance of this module. Three things
// it establishes that a naive implementation gets wrong:
//
//  1. `policyExists: true` does NOT mean recoverable. An account can carry the
//     policy-allow-updateUserAddress policy with an EMPTY allowed_source — the
//     shape a sponsored onboarding leaves behind. Verified live: an account
//     reported `policyExists:true, helpers:[], count:0`. Recoverability is
//     decided by `threshold.requiredCount` against helpers that still exist
//     afterwards, never by the policy's presence.
//
//  2. A HELPER THAT LIVES ON THIS MACHINE DIES WITH IT. Helpers are accounts,
//     and an account's approving key can be another key in this same keystore —
//     the sponsored test accounts are set up exactly that way (one account's two
//     helpers were BOTH local keys). Wiping the machine destroys the helpers and
//     the account they protect in one act, so an account can be nominally
//     recoverable and practically lost. Every helper is classified local vs
//     surviving, and the verdict uses the surviving count.
//
//  3. THE STATE ROOT MAY NOT BE OURS ALONE. `WIKEY_SSP_DIR` defaults to `~/.ssp`,
//     which other Wikey tooling (a standalone wallet-cli, a treasury setup) also
//     uses — a real machine was observed with a foreign `keystore-auto/` beside
//     our `keystore/`. This NEVER removes the root recursively: it removes an
//     explicit list of entries it owns and reports the rest as left behind.
//     Destroying another tool's keys while "uninstalling" this one would be the
//     same unrecoverable mistake, one level up.
//
// Uninstalling does NOT delete anything on-chain. Safes, balances, users and
// policies continue to exist; what is destroyed is this machine's ability to
// authorize anything as them.

import path from 'node:path';

import { listAccounts, type AccountSummary, type QueryRunner } from './accounts.js';

/** Entries under the state root this server owns and may delete. */
export const OWNED_ENTRIES = [
  'keystore', // the signing keys themselves + the hardware-KEK handle
  'dev.kek', // persisted software KEK
  '.wallet-cli', // wallet-cli config (co-located via HOME)
  'bin', // downloaded child binaries
  'idp', // gateway target + enrolled passkey credential + sponsor grants
  'recovery-requests.json', // local recovery breadcrumbs
  'install-child-mode.cjs', // legacy fallback copy of the install script
] as const;

/** Operator env that must be set before anything is deleted. */
export const ALLOW_ENV = 'WIKEY_ALLOW_UNINSTALL';

/** npm package name, used for the global-uninstall step. */
export const PACKAGE_NAME = 'wikey-wallet-mcp';

/** The bin shims npm writes for this package. */
export const BIN_SHIMS = ['wikey-wallet-mcp', 'wikey-wallet-mcp.cmd', 'wikey-wallet-mcp.ps1'] as const;

export type Recoverability = 'recoverable' | 'no-helpers' | 'helpers-are-local' | 'unknown';

/**
 * How this server was installed — decides what "remove the package" means, and
 * what it does NOT mean. A linked install (`npm i -g .`) is a symlink to a
 * working tree: uninstalling removes the link, never the tree, and saying so
 * matters because "it deleted my repo" is the fear that phrasing invites.
 */
export type InstallMode = 'global-real' | 'global-linked' | 'npx' | 'unknown';

export interface HelperRef {
  address: string;
  name?: string;
  /** True when this helper's key is ALSO in this keystore — i.e. dies with it. */
  local: boolean;
}

export interface AccountRisk extends AccountSummary {
  recoverability: Recoverability;
  helpers: HelperRef[];
  /** Approvals the chain requires (decoded from the percentage threshold). */
  requiredApprovals?: number;
  /** Helpers whose keys are NOT on this machine, so they outlive the uninstall. */
  survivingHelpers: number;
  /** Plain-language verdict, safe to relay verbatim. */
  reason: string;
}

/**
 * One thing still on the machine after the tool has done all it can. The point
 * of the whole type: "completely uninstalled" is a claim that has to be
 * itemized, not asserted.
 */
export interface Residual {
  what: string;
  status: 'removed' | 'failed' | 'manual-required' | 'left-behind';
  path?: string;
  /** Exact command the user can run, when there is one. */
  command?: string;
  why?: string;
}

export interface UninstallPlan {
  /**
   * `done` is the ONE terminal success stage. There is deliberately no
   * "done-with-residuals" variant: the client-config entry always needs a human,
   * so residuals are never empty and such a stage would be the only outcome ever
   * seen — a name that reads like partial failure attached to the normal result,
   * while a plain `done` that no caller could ever match. Whether anything went
   * WRONG is a separate question, answered by `residuals[]` entries with
   * `status: 'failed'`.
   */
  stage: 'plan' | 'confirm-mismatch' | 'blocked-not-enabled' | 'refused-unrecoverable' | 'done';
  stateRoot: string;
  installMode: InstallMode;
  keyCount: number;
  accounts: AccountRisk[];
  /** Accounts that will be permanently unreachable afterwards. */
  unrecoverable: AccountRisk[];
  /**
   * Entries this uninstall will delete (present ones only). Names are relative
   * to `stateRoot`, EXCEPT for the nonce file, which is absolute because it does
   * not live under the root — see `nonceFile` on the deps.
   */
  willDelete: string[];
  /** Entries under the root that are NOT ours and will be left alone. */
  willKeep: string[];
  /** The exact string the caller must pass back as `confirm`. */
  confirmPhrase: string;
  /** Everything still on the machine (or that will be), itemized. */
  residuals: Residual[];
  warnings: string[];
  summary: string;
  /** Populated from stage `done`. */
  deleted?: string[];
  npm?: { attempted: boolean; ok: boolean; detail: string };
}

export interface FsOps {
  exists(p: string): boolean;
  readdir(p: string): string[];
  remove(p: string): void;
}

export interface UninstallDeps {
  stateRoot: string;
  listKeys: () => string[];
  query: QueryRunner;
  /** Whether the operator env gate is set. Read from env by the caller. */
  allowUninstall: boolean;
  fs: FsOps;
  /** Tear the signing session down before deleting — see executeUninstall. */
  shutdown: () => void;
  installMode: InstallMode;
  /**
   * Absolute path to the SSP nonce counter, when known.
   *
   * The one file this server writes OUTSIDE the state root: it defaults into
   * `process.cwd()`, so a state-root-scoped cleanup misses it and the user is
   * left with an unexplained `.ssp-nonce` in their working directory — which is
   * exactly how it was found. It is deleted rather than merely reported because
   * it is unambiguously ours (our name, our protocol), inert (a small integer
   * the next session deletes anyway), and holds nothing recoverable. Leaving it
   * would make `residuals[]` a lie, which is the one thing that list cannot be.
   */
  nonceFile?: string;
  /** Directory holding npm's global bin shims, when known. */
  npmBinDir?: string;
  /** Path of the installed package (a symlink target for a linked install). */
  packageDir?: string;
  /**
   * Run `npm uninstall -g`. Injected so tests never touch a real npm, and so a
   * caller can decline the capability entirely by omitting it.
   */
  npmUninstall?: () => Promise<{ ok: boolean; detail: string }>;
  /**
   * Client config files that mention this server. PATHS ONLY — these files hold
   * other servers' credentials, so the tool locates them and never reads their
   * contents back to the model.
   */
  findClientConfigs?: () => string[];
}

// ─── helper audit ───────────────────────────────────────────────────────────

interface HelpersPayload {
  policyExists?: boolean;
  helpers?: { address?: string; name?: string }[];
  threshold?: { requiredCount?: number; totalHelpers?: number; percentage?: number };
}

/**
 * Parse `query helpers --address <addr>`. Returns undefined when the shape is
 * not what we expect — the caller MUST treat that as `unknown` and refuse,
 * never as "no helpers, go ahead". Guessing in the permissive direction costs
 * the user their account.
 */
export function parseHelpers(stdout: string): HelpersPayload | undefined {
  try {
    const data = (JSON.parse(stdout) as { data?: HelpersPayload }).data;
    return data && typeof data === 'object' ? data : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Decide whether ONE account survives this machine being wiped.
 *
 * `localAddresses` is every key in this keystore — the set about to be
 * destroyed. A helper inside that set cannot approve anything afterwards, which
 * is why the verdict counts surviving helpers rather than helpers.
 */
export function classifyRecoverability(
  payload: HelpersPayload | undefined,
  localAddresses: Set<string>,
): Pick<AccountRisk, 'recoverability' | 'helpers' | 'requiredApprovals' | 'survivingHelpers' | 'reason'> {
  if (!payload) {
    return {
      recoverability: 'unknown',
      helpers: [],
      survivingHelpers: 0,
      reason:
        "Could not read this account's recovery helpers — the chain query failed or returned an unexpected " +
        'shape. Treated as NOT recoverable, deliberately: an unreadable answer is not a safe answer when being ' +
        'wrong costs the account. Retry when the network is reachable.',
    };
  }

  const helpers: HelperRef[] = (payload.helpers ?? [])
    .filter((h): h is { address: string; name?: string } => typeof h?.address === 'string')
    .map((h) => ({ address: h.address, ...(h.name ? { name: h.name } : {}), local: localAddresses.has(h.address) }));

  const surviving = helpers.filter((h) => !h.local).length;
  const required = payload.threshold?.requiredCount;

  // No helpers at all — the common and most dangerous case. The policy may still
  // EXIST; an empty allowed_source is what sponsored onboarding leaves behind,
  // and it protects nothing.
  if (helpers.length === 0) {
    return {
      recoverability: 'no-helpers',
      helpers,
      ...(required === undefined ? {} : { requiredApprovals: required }),
      survivingHelpers: 0,
      reason:
        (payload.policyExists
          ? 'This account has a recovery POLICY but NOT ONE HELPER in it — an empty helper list approves nothing. '
          : 'This account has no recovery policy and no helpers. ') +
        'If its key is deleted the account is gone permanently: nobody can approve a move onto a new key. ' +
        'Add helpers with wallet_tx_edit_helpers BEFORE uninstalling.',
    };
  }

  // Helpers exist, but not enough of them outlive this machine.
  if (required !== undefined && surviving < required) {
    const localNames = helpers.filter((h) => h.local).map((h) => h.name ?? h.address).join(', ');
    return {
      recoverability: 'helpers-are-local',
      helpers,
      requiredApprovals: required,
      survivingHelpers: surviving,
      reason:
        `This account needs ${required} approval(s) to recover, but only ${surviving} of its ${helpers.length} ` +
        `helper(s) live outside this machine. The rest (${localNames}) are keys IN THIS KEYSTORE — this uninstall ` +
        `deletes them too, so they could never approve anything afterwards, and the account would be permanently ` +
        `unreachable. Add an off-machine helper with wallet_tx_edit_helpers before uninstalling.`,
    };
  }

  return {
    recoverability: 'recoverable',
    helpers,
    ...(required === undefined ? {} : { requiredApprovals: required }),
    survivingHelpers: surviving,
    reason:
      `Recoverable: ${surviving} helper(s) outside this machine` +
      (required === undefined ? '' : `, ${required} approval(s) needed`) +
      `. After uninstalling, create a key elsewhere and call wallet_tx_request_recovery with this account's NAME — ` +
      `the helpers approve moving it onto the new key.`,
  };
}

// ─── plan ───────────────────────────────────────────────────────────────────

export function confirmPhraseFor(keyCount: number): string {
  return `UNINSTALL WIKEY WALLET AND PERMANENTLY DELETE ${keyCount} KEY${keyCount === 1 ? '' : 'S'}`;
}

/** What removing the npm package will and will not touch, per install mode. */
function npmResidualNote(mode: InstallMode, packageDir?: string): Residual {
  switch (mode) {
    case 'global-linked':
      return {
        what: 'Your local source tree (this is a LINKED install)',
        status: 'left-behind',
        ...(packageDir ? { path: packageDir } : {}),
        why:
          'This server was installed with `npm i -g .`, so the global install is a SYMLINK to a working copy on ' +
          'disk. Uninstalling removes the link and the bin shims — it does not and must not delete your source ' +
          'tree. Delete that folder yourself if you actually want it gone.',
      };
    case 'npx':
      return {
        what: 'npx download cache',
        status: 'manual-required',
        command: 'npm cache clean --force',
        why:
          'This server was run through npx, so nothing was installed globally — there is no global package to ' +
          'remove. A copy may remain in the npx cache until it is cleared.',
      };
    default:
      return {
        what: 'npm global package',
        status: 'manual-required',
        command: `npm uninstall -g ${PACKAGE_NAME}`,
        why: 'Not attempted yet — this is what the confirmed run will do.',
      };
  }
}

/**
 * Read-only survey: what would be destroyed, which accounts would be lost with
 * it, and what would still be left afterwards. Always safe to call — it deletes
 * nothing and needs no gate, because this is also where the user learns the gate
 * exists.
 */
export async function buildUninstallPlan(deps: UninstallDeps): Promise<UninstallPlan> {
  const { stateRoot, listKeys, query, fs } = deps;

  const summaries = await listAccounts(query, listKeys);
  const local = new Set(summaries.map((s) => s.address));

  const accounts: AccountRisk[] = [];
  for (const s of summaries) {
    let payload: HelpersPayload | undefined;
    try {
      payload = parseHelpers(await query(['query', 'helpers', '--address', s.address]));
    } catch {
      payload = undefined; // → 'unknown' → refuse. See classifyRecoverability.
    }
    accounts.push({ ...s, ...classifyRecoverability(payload, local) });
  }

  const unrecoverable = accounts.filter((a) => a.recoverability !== 'recoverable');

  // Split the root into what we own and what we must not touch.
  const willDelete: string[] = OWNED_ENTRIES.filter((e) => fs.exists(path.join(stateRoot, e)));
  // The nonce is appended ABSOLUTE — it is the one thing we delete from outside
  // the state root, so it must not be resolved against it.
  if (deps.nonceFile && fs.exists(deps.nonceFile)) willDelete.push(deps.nonceFile);
  let present: string[] = [];
  try {
    present = fs.readdir(stateRoot);
  } catch {
    present = [];
  }
  const owned = new Set<string>(OWNED_ENTRIES);
  const willKeep = present.filter((e) => !owned.has(e));

  const configs = deps.findClientConfigs?.() ?? [];
  const residuals: Residual[] = [
    npmResidualNote(deps.installMode, deps.packageDir),
    ...(configs.length
      ? configs.map((p): Residual => ({
          what: 'MCP client config entry "wikey-wallet"',
          status: 'manual-required',
          path: p,
          why:
            'Delete the "wikey-wallet" block from this file, then fully restart the client. This tool does not ' +
            'edit client configuration itself: the file belongs to your client, and one malformed write would ' +
            'break every OTHER MCP server listed in it. ' +
            // Observed on a real run: the agent did this edit anyway, correctly.
            // Since it will be done regardless, saying HOW is worth more than
            // pretending it will not happen — an agent reaching for sed on a
            // JSON file its user depends on is the failure mode to prevent.
            'IF YOU PERFORM THIS EDIT ON THE USER\'S BEHALF: copy the file to a timestamped backup first, remove ' +
            'the key by parsing and re-serializing the JSON (never a text or regex substitution), confirm the ' +
            'result still parses and still contains the user\'s other servers, and tell them where the backup is. ' +
            'Delete only the server entry — other keys may legitimately contain the same string.',
        }))
      : [
          {
            what: 'MCP client config entry "wikey-wallet"',
            status: 'manual-required' as const,
            why:
              'No client config naming this server was found in the usual locations, so remove the entry from ' +
              'whichever mcp.json / claude_desktop_config.json you registered it in, then restart the client.',
          },
        ]),
    ...(willKeep.length
      ? [
          {
            what: `Files under the state root that are not this server's (${willKeep.join(', ')})`,
            status: 'left-behind' as const,
            path: stateRoot,
            why:
              'The state root can be SHARED with other Wikey tooling — a standalone wallet-cli or a treasury setup ' +
              'keeps its own keystore here. These are deliberately not removed; deleting them could destroy another ' +
              "tool's keys. Remove them by hand only if you know they are yours.",
          },
        ]
      : []),
  ];

  const warnings: string[] = [
    'Deleting a signing key is IRREVERSIBLE. The private material is encrypted under a key-encryption key held by ' +
      'this machine; it cannot be restored from a backup, a passphrase, or by Wikey — Wikey never held it.',
    'This deletes NOTHING on-chain. Your accounts, safes, balances, users and policies all continue to exist ' +
      "exactly as they are. What is destroyed is this machine's ability to authorize anything as them — including " +
      'moving whatever those safes still hold.',
  ];
  if (!deps.allowUninstall) {
    // Self-contained on purpose: this used to end with "see the enable step
    // below" while the how-to lived only on the execute path, so the plan
    // pointed at instructions that were not in the response.
    warnings.push(
      `The destructive step is currently DISABLED — nothing can be deleted yet. TO ENABLE IT: ` +
        enableInstructions(),
    );
  }

  return {
    stage: 'plan',
    stateRoot,
    installMode: deps.installMode,
    keyCount: summaries.length,
    accounts,
    unrecoverable,
    willDelete: [...willDelete],
    willKeep,
    confirmPhrase: confirmPhraseFor(summaries.length),
    residuals,
    warnings,
    summary: planSummary(summaries.length, accounts, unrecoverable, stateRoot, deps.allowUninstall),
  };
}

function planSummary(
  keyCount: number,
  accounts: AccountRisk[],
  unrecoverable: AccountRisk[],
  stateRoot: string,
  allowed: boolean,
): string {
  const gate = allowed ? '' : ` The destructive step still needs ${ALLOW_ENV}=1 — see warnings and residuals.`;
  if (keyCount === 0) {
    return (
      `NOTHING TO LOSE: this machine holds no signing keys, so uninstalling destroys no account access. It removes ` +
      `this server's state under ${stateRoot} (config, binaries, gateway credential).${gate}`
    );
  }
  const safe = accounts.length - unrecoverable.length;
  const head =
    `THIS IS IRREVERSIBLE. Uninstalling deletes ${keyCount} signing key(s) from ${stateRoot}. The accounts stay ` +
    `on-chain — what goes away forever is this machine's ability to sign as them.`;
  if (unrecoverable.length === 0) {
    return (
      `${head} All ${safe} account(s) DO have recovery helpers who outlive this machine, so each could be ` +
      `recovered onto a new key later. Show the user the per-account detail and get an explicit yes.${gate}`
    );
  }
  const names = unrecoverable.map((a) => a.name ?? a.address).join(', ');
  return (
    `${head} ${unrecoverable.length} of ${accounts.length} account(s) would be LOST PERMANENTLY — ${names} — ` +
    `because no recovery helper of theirs survives this machine. ${safe} account(s) could be recovered. Read each ` +
    `entry's \`reason\` to the user. The fix is wallet_tx_edit_helpers BEFORE uninstalling, not a flag.${gate}`
  );
}

// ─── execute ────────────────────────────────────────────────────────────────

export interface ExecuteOptions {
  confirm?: string;
  acceptPermanentLoss?: boolean;
}

/** How a human turns the gate on. Kept in one place — several stages cite it. */
export function enableInstructions(): string {
  return (
    `Add "${ALLOW_ENV}": "1" to the "env" block of this server's entry in your MCP client config (mcp.json / ` +
    `claude_desktop_config.json), then FULLY QUIT AND REOPEN the client. MCP servers read their environment only ` +
    `at startup, so without the restart the setting has no effect. An agent cannot do this for you — that is ` +
    `exactly the point of the gate: wiping a keystore should require a human at the config file.`
  );
}

/**
 * Delete. Every gate is checked here rather than at the tool boundary so the
 * order is fixed and testable:
 *
 *   1. no `confirm`            → the plan (read-only)
 *   2. `confirm` mismatched    → refuse, hand back the exact phrase
 *   3. operator gate unset     → refuse, explain how the HUMAN sets it
 *   4. losses not accepted     → refuse, list what would be lost
 *   5. delete state → remove the npm package → report residuals
 *
 * The phrase is derived from the live key count, so a plan taken before a key
 * was added or removed no longer matches: a stale confirmation cannot delete a
 * keystore that changed underneath it.
 */
export async function executeUninstall(deps: UninstallDeps, opts: ExecuteOptions = {}): Promise<UninstallPlan> {
  const plan = await buildUninstallPlan(deps);

  if (!opts.confirm) return plan;

  if (opts.confirm.trim() !== plan.confirmPhrase) {
    return {
      ...plan,
      stage: 'confirm-mismatch',
      summary:
        `Nothing was deleted — the confirmation did not match. To proceed, \`confirm\` must equal exactly: ` +
        `"${plan.confirmPhrase}". The phrase names how many keys are on this machine right now, so a confirmation ` +
        `prepared before that changed no longer applies. Show the user the plan and get their agreement first.`,
    };
  }

  if (!deps.allowUninstall) {
    return {
      ...plan,
      stage: 'blocked-not-enabled',
      summary:
        `Nothing was deleted. Uninstalling is disabled until ${ALLOW_ENV}=1 is present in this server's ` +
        `environment, and an agent cannot set that for itself. ${enableInstructions()} Once the client has been ` +
        `restarted, run this tool again.` +
        // Look PAST this gate before sending the user off to edit a config file
        // and restart their client: if the next gate would refuse anyway, they
        // deserve to know now rather than after the round trip. The remedy for
        // that one (adding helpers) is also something they can do FIRST, from
        // the working install they still have.
        (plan.unrecoverable.length > 0
          ? ` HEADS-UP BEFORE YOU DO THAT: enabling the flag will NOT be enough on its own. ` +
            `${plan.unrecoverable.length} of ${plan.accounts.length} account(s) — ` +
            `${plan.unrecoverable.map((a) => a.name ?? a.address).join(', ')} — have no recovery path that ` +
            `survives this machine, so the next attempt is refused too unless the user also accepts losing ` +
            `them permanently. Deal with that FIRST, while the wallet still works: add helpers with ` +
            `wallet_tx_edit_helpers, and move anything those safes hold somewhere the user will still control.`
          : ''),
    };
  }

  if (plan.unrecoverable.length > 0 && !opts.acceptPermanentLoss) {
    const names = plan.unrecoverable.map((a) => `${a.name ?? a.address} (${a.recoverability})`).join('; ');
    return {
      ...plan,
      stage: 'refused-unrecoverable',
      summary:
        `Nothing was deleted. ${plan.unrecoverable.length} account(s) have no recovery path that survives this ` +
        `machine: ${names}. Deleting now loses them for good, along with whatever they hold. Read each reason to ` +
        `the user. Either add helpers first (wallet_tx_edit_helpers — the recoverable outcome), or, if they truly ` +
        `intend to abandon these accounts, re-send with acceptPermanentLoss: true alongside the same confirm ` +
        `phrase. Do NOT set that flag on your own initiative: it must be the user's explicit decision, made after ` +
        `hearing exactly which accounts it abandons.`,
    };
  }

  // Stop the signing child FIRST. It holds the keystore open (on Windows an open
  // handle makes the delete fail outright), and letting it keep running against a
  // half-deleted state root is worse than either outcome.
  deps.shutdown();

  const residuals: Residual[] = [];
  const deleted: string[] = [];
  for (const entry of plan.willDelete) {
    // Entries are root-relative by name; the nonce file arrives absolute because
    // it lives outside the root. Joining an absolute path onto the root would
    // silently target the wrong place — and then report success for it.
    const full = path.isAbsolute(entry) ? entry : path.join(deps.stateRoot, entry);
    try {
      deps.fs.remove(full);
      deleted.push(entry);
    } catch (e) {
      residuals.push({
        what: `State-root entry "${entry}"`,
        status: 'failed',
        path: full,
        why:
          `Could not be removed: ${(e as Error).message}. A still-running signing-server is the usual cause — ` +
          `kill whatever holds 127.0.0.1:8080 and delete this path by hand.`,
      });
    }
  }

  // Remove the root itself ONLY if we emptied it. A shared root still holds
  // another tool's files and must survive.
  const stateFailures = residuals.length;
  if (plan.willKeep.length === 0 && stateFailures === 0) {
    try {
      deps.fs.remove(deps.stateRoot);
    } catch {
      /* an empty leftover directory is harmless */
    }
  }

  // The npm package. Attempted, then VERIFIED on disk, because an exit code is a
  // claim about what npm tried, not about what is now on the filesystem: a
  // wrong prefix, a permission failure, an antivirus hold, or a partially
  // applied removal all exit 0 with files still present.
  //
  // This verification was originally justified by a specific story — that on
  // Windows the `.cmd` shim is held open by the cmd.exe executing it and
  // survives the uninstall. That was ASSUMED, and testing it on Windows 11
  // disproved it: with a server launched through the shim, both the shim and the
  // package directory deleted cleanly while it ran. The check is kept because
  // trusting an exit code about the filesystem is wrong in general, not because
  // of that story. Do not restate the story as fact.
  let npm: UninstallPlan['npm'];
  if (deps.installMode === 'npx') {
    npm = { attempted: false, ok: false, detail: 'Run via npx — nothing was installed globally.' };
    residuals.push(npmResidualNote('npx', deps.packageDir));
  } else if (!deps.npmUninstall) {
    npm = { attempted: false, ok: false, detail: 'No npm runner available in this environment.' };
    residuals.push({
      what: 'npm global package',
      status: 'manual-required',
      command: `npm uninstall -g ${PACKAGE_NAME}`,
      why: 'This server could not run npm itself.',
    });
  } else {
    const r = await deps.npmUninstall();
    const leftovers = deps.npmBinDir
      ? BIN_SHIMS.filter((s) => deps.fs.exists(path.join(deps.npmBinDir!, s)))
      : [];
    const pkgLeft = deps.packageDir && deps.installMode === 'global-real' && deps.fs.exists(deps.packageDir);
    const ok = r.ok && leftovers.length === 0 && !pkgLeft;
    npm = { attempted: true, ok, detail: r.detail };
    if (!ok) {
      residuals.push({
        what: 'npm global package / bin shims',
        status: 'failed',
        command: `npm uninstall -g ${PACKAGE_NAME}`,
        ...(deps.npmBinDir ? { path: deps.npmBinDir } : {}),
        // Report WHAT survived, never a guessed reason why. The cause could be a
        // permission failure, an antivirus hold, a different npm prefix, or a
        // file genuinely in use — and naming the wrong one sends the user to fix
        // something that is not broken.
        why:
          (r.ok
            ? `npm reported success, but ${[...leftovers, ...(pkgLeft ? ['the package directory'] : [])].join(', ')} ` +
              `still exist on disk, so the package is NOT fully removed. `
            : `npm failed: ${r.detail} `) +
          `Fully quit the client, then run the command yourself and check the output — with nothing running out ` +
          `of the package, whatever blocked it is usually visible there.`,
      });
    }
    if (deps.installMode === 'global-linked') residuals.push(npmResidualNote('global-linked', deps.packageDir));
  }

  // Client config is never edited — carry the plan's entries through.
  residuals.push(...plan.residuals.filter((r) => r.what.startsWith('MCP client config')));
  if (plan.willKeep.length) {
    residuals.push(...plan.residuals.filter((r) => r.status === 'left-behind' && r.path === deps.stateRoot));
  }

  const lost = plan.unrecoverable.length;
  // Three different things end up in residuals[], and conflating them is what
  // made every successful run read like a partial failure. Only `failed` means
  // something went wrong; `manual-required` is the expected remainder (the
  // client-config entry ALWAYS needs a human, so residuals are never empty); and
  // `left-behind` is a deliberate refusal to touch someone else's files.
  const failures = residuals.filter((r) => r.status === 'failed');
  const todo = residuals.filter((r) => r.status === 'manual-required');
  const kept = residuals.filter((r) => r.status === 'left-behind');
  const wentWrong = failures.length > 0 || stateFailures > 0;

  return {
    ...plan,
    stage: 'done',
    deleted,
    npm,
    residuals,
    summary:
      `${wentWrong ? 'PARTIALLY DONE' : 'DONE'} — ${deleted.length} state entr(ies) removed and ` +
      `${plan.keyCount} signing key(s) deleted. They cannot be restored.` +
      (lost
        ? ` ${lost} account(s) had no surviving recovery path and are now permanently unreachable, as confirmed.`
        : plan.keyCount
          ? ` Every account had helpers outside this machine: to regain access, create a key elsewhere and call ` +
            `wallet_tx_request_recovery with the account NAME.`
          : '') +
      (failures.length
        ? ` ${failures.length} item(s) could NOT be removed and need fixing — see residuals[] with ` +
          `status:"failed".`
        : '') +
      (todo.length
        ? ` ${todo.length} step(s) remain for the user (residuals[] status:"manual-required") — this is expected, ` +
          `not a failure: removing the entry from the MCP client config always needs a human. Read them out.`
        : '') +
      (kept.length
        ? ` ${kept.length} item(s) were deliberately left alone (status:"left-behind") because they are not this ` +
          `server's to delete.`
        : '') +
      ` The wallet tools stay visible in the client until it is fully restarted, and every one of them will now ` +
      `fail. Note that the on-chain accounts still exist — "uninstalled" means unreachable from here, not deleted.`,
  };
}
