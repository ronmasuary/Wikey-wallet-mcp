# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> The entries for **1.1.0, 1.2.0 and 1.2.1** were backfilled on 2026-08-18, after
> those versions had already shipped. They are reconstructed from the git history
> rather than written at release time, so they summarize what the commits did —
> treat them as a good-faith record, not a contemporaneous one.

## [Unreleased]

### Added

- **Real-filesystem tests for the shared-state-root protection**
  (`tests/uninstallSharedRoot.test.ts`). Every other uninstall test runs on an
  in-memory fake, which proves the logic but not the wiring — `realFs.remove` is
  a recursive `rmSync`, and the only thing between it and a third party's keys is
  the allow-list. Verified on a synthetic `~/.ssp`-style root carrying a foreign
  `keystore-auto/`: our entries deleted, third-party key material intact
  byte-for-byte, root preserved; exclusive-root control fully removed. Also pins
  that a foreign file appearing **between** plan and execute still protects the
  root.

### Changed

- **`wallet_uninstall` now has ONE terminal stage, `done`** — the
  `done-with-residuals` variant is gone. Residuals are never empty (removing the
  MCP client-config entry always needs a human), so that stage was the only
  outcome ever produced: a name reading like partial failure attached to the
  normal, fully-successful result, while a plain `done` sat unreachable along
  with its "Nothing is left on this machine" message. An agent branching on
  `stage === 'done'` never matched and could report a clean uninstall as
  degraded.

  Whether anything went *wrong* is now a separate question from whether work
  remains, and the summary keeps them apart: `failed` residuals lead with
  `PARTIALLY DONE` and "could NOT be removed"; `manual-required` ones are
  described as "expected, not a failure"; `left-behind` ones as deliberately not
  this server's to delete. Callers wanting a failure check use
  `residuals.some(r => r.status === 'failed')`.

  Breaking for anyone matching on `done-with-residuals`, which was only ever
  reachable in `1.3.0-beta` — never on `latest`.

### Fixed

- **`wallet_uninstall` now removes the `.ssp-nonce` counter, which it used to
  leave behind unreported.** The nonce is the only file this server writes
  OUTSIDE the state root — it defaults into `process.cwd()`, not
  `WIKEY_SSP_DIR` — so a root-scoped cleanup never saw it. Found in the wild: a
  user who had run a complete uninstall still had an unexplained `.ssp-nonce` in
  their working directory. Harmless in itself (a small integer that every cold
  start deletes before use), but a file left behind that `residuals[]` did not
  mention, which is the one thing that list cannot do.

  It is deleted rather than merely reported: unambiguously ours, inert, and
  holding nothing recoverable. `willDelete` carries it as an ABSOLUTE path, and
  the executor now resolves absolute entries as-is instead of joining them onto
  the state root — joining would have targeted a nonexistent file, `force: true`
  would have swallowed the miss, and the run would have reported success while
  the real file sat untouched. `SessionManager` exposes `nonceFilePath` so the
  configured path is used rather than a recomputed `cwd`.
- **The npm-removal residual no longer asserts a cause it cannot know.** 1.3.0
  told users a surviving bin shim was "held open by the shell running it" on
  Windows. That explanation was assumed rather than observed, and testing it
  disproved it: on Windows 11, with a server launched through the `.cmd` shim and
  still running, both the shim and the package directory were removed cleanly by
  the same `rmSync` the tool uses. The residual now reports **what** survived and
  points the user at re-running the command after quitting the client, where the
  real reason is visible. The check itself stays — an exit code describes what
  npm attempted, not what the filesystem holds, and a wrong prefix, permission
  failure or antivirus hold all exit 0 with files left behind. Code comments and
  docs corrected to match.
- **The client-config residual now says HOW to edit the file safely.** The tool
  still never writes to client config — but a live run showed the calling agent
  performing that edit itself on the tool's instruction. It did so correctly
  (backup, JSON round-trip, verified re-parse), yet nothing in the guidance
  required any of that, and the next agent may reach for a regex substitution on
  a file that controls every other MCP server the user has. Since the edit will
  happen regardless, the residual now specifies the safe procedure: back up
  first, remove the key by parsing and re-serializing (never text substitution),
  verify the result still parses and still holds the user's other servers, and
  report where the backup is.
- **`wallet_uninstall`'s env-gate refusal now looks one gate ahead.** Refusing
  with `blocked-not-enabled` sent the user off to edit their MCP client config
  and fully restart the client — only for the *next* attempt to be refused again
  because an account had no surviving recovery path. Both facts are known at the
  first call, so both are now reported there: the refusal names the unrecoverable
  accounts and says to add helpers (and move any assets) **first, while the
  wallet still works**. Saves a wasted client-restart round trip, and puts the
  remedy where the user can still act on it. Found by watching the live gate
  sequence on the llm-chat VM.
- **`wallet_uninstall`'s plan no longer points at instructions it does not
  contain.** With the gate unset, the plan warned "…see the enable step below",
  but the how-to-enable text was emitted only on the execute path
  (`blocked-not-enabled`) — so a user reading the plan was referred to a step
  that was not in the response. The warning is now self-contained. Found on the
  llm-chat VM against 1.3.0; covered by a regression test.

### Removed

- **The npm `postinstall` banner (shipped in 1.3.0) is gone.** It never reached
  anyone: **npm 7+ suppresses lifecycle-script output** unless the user passes
  `--foreground-scripts`, so on a normal `npm i -g` the banner was silent —
  confirmed against the published 1.3.0 package on a clean VM and reproduced
  locally. Since delivering the first-install restart message was its only
  purpose, it bought nothing.

  Removing it is also a net security win for a wallet package: a `postinstall`
  hook makes behaviour differ under the common `--ignore-scripts` hardening, and
  it hands anyone who compromises the package a code-execution hook at install
  time. Do not reintroduce it.

  The restart instruction still reaches users through the channels that work:
  `wikey-wallet-mcp doctor` (already the documented post-install step, and it
  ends with the notice), the ⚠️ section in README / INSTALL.md §5, and the
  runtime `restartRequired` block for the upgrade case.

## [1.3.0] - 2026-08-18

### Added

- **`wallet_uninstall` — complete local removal, gated and audited.** Deletes the
  signing keys, this server's state, and the npm package. With no arguments it is
  **read-only** and returns a plan: what would be deleted, a per-account
  recoverability audit, and `residuals[]` itemizing everything that would still
  be left on the machine afterwards.

  The audit is the substance, and it rejects two assumptions that would destroy
  accounts:

  - **`policyExists: true` does not mean recoverable.** An account can hold the
    policy-allow-updateUserAddress policy with an *empty* `allowed_source` — the
    shape sponsored onboarding leaves behind. Verified live against a real
    account returning `policyExists:true, helpers:[], count:0`. The verdict uses
    `threshold.requiredCount` against actual helpers.
  - **A helper on this machine dies with it.** Helpers are accounts, and an
    account's helper can be another key in the same keystore — verified live on
    an account whose two helpers were *both* local keys, i.e. nominally
    recoverable and actually a total loss. Each helper is classified local vs
    surviving and only survivors count. On the development machine this reclassified
    4 of 6 accounts as unrecoverable.

    A helpers query that fails or returns an unexpected shape is `unknown`, which
    blocks the delete — an unreadable answer is not a safe answer.

  Four gates, in a fixed order tested end to end: the `confirm` phrase (which
  embeds the live key count, so a stale plan cannot delete a changed keystore);
  `WIKEY_ALLOW_UNINSTALL=1`, an operator env a **human** must set in the client
  config (an agent cannot set its own environment — this is the only real control
  against a prompt-injected model, and it is documented as such in
  `docs/SECURITY.md`); `acceptPermanentLoss` when any account has no surviving
  recovery path; and `session.shutdown()` before a single file is touched.

  Deletion is **allow-listed**, never recursive: `WIKEY_SSP_DIR` may be shared
  with other Wikey tooling (a machine was observed with a foreign `keystore-auto/`
  beside ours), so unrecognized entries are reported and left alone, and the root
  itself is removed only if it ended up empty. The npm package is removed and then
  **verified on disk** — an exit code of 0 is not proof on Windows, where a bin
  shim held open by the shell that launched the server survives a "successful"
  uninstall. A linked install (`npm i -g .`) reports the source tree as left
  behind rather than implying it was deleted. Client config is located but never
  edited, and its contents are never read back to the model.

  Uninstalling deletes nothing on-chain — that limit is stated in the tool's own
  output rather than left to inference.
- **`doctor` reports install mode and whether uninstall is enabled**, so residuals
  stay checkable from a terminal after the client is gone.

- **First-install "restart your AI client" guidance.** An MCP server has no
  channel to the user until the client has loaded it, and clients load their
  servers only at startup — so the instruction is delivered where the user still
  is: a **postinstall banner** (`scripts/postinstall.cjs`, printed by `npm i`,
  stderr only, silent under `CI`/`WIKEY_QUIET_INSTALL`, and never able to fail an
  install) and a closing note in **`doctor`**. Both carry the host-config
  snippet, the restart rule, and the two first-run options.
- **Stale-build detection** — the half of the restart problem a running server
  *can* see. `npm i -g` overwrites the package in place while the client keeps
  the old process alive, so the user talks to the pre-upgrade build believing
  they upgraded. `wallet_getting_started` now compares the version it booted with
  against the version on disk (`readInstalledVersionFromDisk` deliberately
  bypasses the require cache) and returns `restartRequired: { running, installed,
  message }` plus a `notes[]` entry when they diverge. Never fires on equal or
  unknown versions.
- **`wallet_getting_started` now returns `version`** (the build actually serving
  the call).
- **Prefilled store funding links.** The Wikey store accepts `?address=` and uses
  it to fill its "User address" field, so the address never has to be copied by
  hand — the one step of self-funding that loses real funds when a human
  mistypes it. `storeFundingUrl()` builds the link; `wallet_keys_create` now
  returns `{ result, fundingUrl, next }` with the brand-new address already in
  it, and `wallet_getting_started` uses the same link at stage `unfunded`. The
  address is shape-checked (`omnistar1…`) and URL-encoded before it goes in, so
  a malformed value degrades to the bare store rather than prefilling garbage,
  and a parse failure after key creation degrades the same way instead of
  throwing away a result whose key already exists.

### Changed

- **Stage `no-key` presents the TWO ways to start instead of one.** It used to
  say only "create a signing key"; the individual-vs-sponsored fork appeared one
  stage later, at `unfunded`, which is too late to be a choice. It now leads with
  the question — (1) individual: create a key and fund it with OST from
  <https://store.wikey.io/>; (2) sponsored: redeem an organization invitation
  link, which creates, funds and sets up everything in one `wallet_onboard_sponsor`
  call — and explicitly tells the agent **not** to create a key until the user
  answers. A sponsor invite always provisions a fresh identity and never adopts
  an existing key, so a key minted up front is stranded unfunded and shows up
  beside the real account in `wallet_accounts` forever after.
- Stage `unfunded` names the store URL as the place to buy OST, and warns that
  redeeming an invite at this point will leave the current key behind.
- `SERVER_INSTRUCTIONS` restructured from one linear sequence into the two entry
  points, so the fork is in the model's context before any tool is called.

### Fixed

- **Safe transfers no longer fail before signing on an asset-list timeout.**
  `/api/assets/` prices a list **serially** — ~52 s for 11 assets, with
  MATIC/POL alone taking 17–22 s each — against `wallet-cli`'s hardcoded 10 s
  abort, so every safe transfer died in pre-flight with `API_TIMEOUT` and looked
  like an outage. (A bare `GET` 404s in 0.2 s because the endpoint is POST-only,
  which made the endpoint look healthy when probed by hand.) Fixed MCP-side by
  narrowing to **one request per asset** instead of one request for the list.
- **R6 headroom no longer refuses every OST transfer.** The headroom floor used
  a **USD band** on all chains: $2 converted through the coin price. That is a
  fair proxy where the fee is priced by block-space demand, but Omnistar's fee is
  deterministic — gas limit × gas price, both fixed, worst case
  `400_000 × 11 = 0.0044 OST`. At ~$0.20/OST the band demanded ~10 OST of
  headroom, roughly **2000× the real fee** and more than most test safes hold, so
  every OST transfer came back `at-risk` with `maxSuggested: 0`. Chains with a
  deterministic fee now declare a per-chain `maxFee` that replaces the USD band
  entirely, and the floor becomes that known cost × `FEE_SAFETY` (3). Chains
  whose fees really do float keep the USD band, unchanged.
- **`WIKEY-WALLET-SETUP.md` and the shipped `INSTALL.md`** (kept in sync): §5 now
  spells out why a full client restart is required and why the wallet cannot ask
  for it itself; §7 leads with the individual-vs-sponsored question and the
  prefilled `fundingUrl`; §10.2 replaces the "is `wallet_accounts` in the tool
  list?" heuristic — which only worked for the one release that added it — with
  the `restartRequired` / `version` check the server now performs itself.

## [1.2.1] - 2026-08-17

### Fixed

- Stopped pinning `HOME` on the signing-server child in `session.ts`. Only the
  wallet-cli children need the relocated home; forcing it on the signer as well
  was unnecessary and interfered with KEK resolution on some hosts.

## [1.2.0] - 2026-08-16

### Added

- **Snapshot depth controls.** `wallet_snapshot_object` (one object in full,
  including governance `process`), optional `fields` selection on
  `wallet_snapshot_query` / `wallet_snapshot_page`, a class→field-names map plus
  `siblings` in the snapshot index, and size-aware cache eviction with the
  `WIKEY_SNAPSHOT_MAX_RESULT_BYTES` operator knob. Node/group/safe siblings are
  now preserved at parse time rather than dropped by a fixed projection.
- **`wallet_getting_started`** — the state-classifying onboarding guide.
- **Sponsor onboarding** — `wallet_onboard_sponsor` (invite → key → funding →
  safe → passkey), including the enroll-only invitation variant.
- **Recovery** — request tracking with a local breadcrumb, the `recovery-pending`
  stage, the recovery-helper deeplink, and the `wallet_recovery_helpers` query.
- **Transaction feasibility pre-flight** (`wallet_tx_check`) so a transfer cannot
  drain the balance below its own network fee, plus explicit fee-priority
  handling (`low` / `medium` / `high`, never defaulted silently).
- **Gateway** — target + credential management, MCP calls through the aggregator,
  and session recovery/diagnostics for a wedged signer
  (`wallet_session_recover`).
- `WIKEY_UNLOCK_CONFIG` operator escape hatch for the config lock.

## [1.1.0] - 2026-08-14

### Added

- **Single MCP-owned state root** (`WIKEY_SSP_DIR`), co-locating the keystore and
  wallet-cli's config so key material and the default-key pointer cannot desync.
- **KEK auto-fallback** to a persisted software KEK when no hardware enclave is
  present, so keys survive a restart instead of being lost to an ephemeral key.
- **Per-call signer** (`signingKey`, later renamed `account`) on the signing
  tools.
- `isDevEnv` KEK policy and `installationScriptPath` / `installationScriptUrl`
  install resolution.
- `prepare` script so a git install builds `dist/`.

## [1.0.1] - 2026-06-07

### Fixed

- **`wallet_keys_create` no longer deadlocks.** It was routed through the
  prompt-driven signing engine with an empty queue, but `keys create` signs over
  the signer's HTTP API (no stdin proof) and ends with a `Set as default? (y/n)`
  prompt. With no responder the child never exited; the call rode the timeout and
  surfaced an error even though the key had already been created, so a retry
  produced duplicate keys. It now runs session-gated, answering the y/n (from
  `setDefault`) so wallet-cli prints its JSON result and exits cleanly.

### Changed

- **Install script is owned by the package.** `install-child-mode.cjs` is now
  resolved at the package root (beside `dist/`) — `WIKEY_INSTALL_SCRIPT` override
  → bundled → `~/.ssp` fallback — so a host (e.g. an agent) no longer needs to
  point the server at it. The script carries the GitLab deploy token and stays
  gitignored, shipped with the package rather than committed.

## [1.0.0] - 2026-06-03

### Added

Initial release of `wikey-wallet-mcp` — a self-hosted, zero-custody MCP stdio
server porting the verified core of the Wikey wallet skill into a typed,
enforceable tool boundary that runs in any MCP host.

- **Core (transport-agnostic, ported from the frozen skill):** proof driver with
  SIGTERM→SIGKILL kill ladder, prompt-driven signing runner with dual timeout
  (30s/120s) and stdin-end discipline, query runner, snapshot parser + resolvers
  (create-user / delete-user / delete-policy), and the HMAC rotation driver with
  the exact `ssp-util` exit-code table (retry 6/7 in a 30s grace, fatal 4).
- **Key sealing (net-new):** the HMAC session key is a `Buffer` in the session
  closure — never a module global, never returned, written to `ssp-util` stdin as
  bytes, zeroized on rotation swap and shutdown.
- **Server-owned auto-rotation:** 15-min timer, serialized with signing via an
  async mutex; on a wedge the timer stops and signing is refused. No
  `wallet_hmac_rotate` tool.
- **Lazy, race-guarded session:** reads never spawn SSP; the first signing call
  spawns SSP + mints the key (single spawn under concurrent first-calls). Kills
  only its own child — never `pkill`. Nonce file deleted on fresh spawn, kept
  across rotations.
- **KEK policy:** always `-keystore secure`; hardware-preferred (`-kek-provider
  auto`), persisted env/passphrase KEK fallback on enclave-less VMs. Active
  provider surfaced via `doctor`.
- **MCP wrapper (32 tools):** full skill surface minus `wallet_session_start`
  (lazy) and `wallet_hmac_rotate` (automatic), plus B2 snapshot tools.
- **Config lockdown (H10):** `wallet_config_set` rejects `signer.*`, `*.url`,
  `apiKey`, `kek*`, `keystore*`, `user.*`.
- **Data-integrity boundary (H14):** raw snapshot JSON never crosses the tool
  boundary; `wallet_snapshot` returns a ~300 B index, `wallet_snapshot_query` /
  `wallet_snapshot_page` return byte-budgeted, explicitly-paged rows.
- **Distribution:** no token in this repo; binaries resolved from `~/.ssp/bin` /
  npm global / PATH, with an external install script located via
  `WIKEY_INSTALL_SCRIPT` (→ `~/.ssp` fallback) and auto-run on startup when
  binaries are missing. Installer output to stderr only.
- **`doctor` preflight**, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, CI + npm
  release workflows.
