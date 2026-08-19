# wikey-wallet-mcp

A **self-hosted, zero-custody** MCP stdio server that exposes the Wikey / Omnistar
wallet & signing stack to **your own agent**, on **any MCP host**, through a
**typed, enforceable tool boundary**.

Wikey is a capability vendor: it ships wallet/signing to clients' own agents.
**Wikey never holds your keys.** The wallet **private key** and its **KEK** live
inside the signing-server (SSP) and are never exposed to the model. The only
secret this server process holds is a short-lived **HMAC session key**, which is
**sealed from the model** and **auto-rotated (~15 min)** so a leak is useless
quickly.

> Source of truth: **GitLab** (`gitlab.com/bit2safe/wikey-wallet-mcp`).
> GitHub is a read-only mirror. See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## Why an MCP server

Agent capabilities are often shipped as *instructions* — a markdown file telling
the model how to behave. Instructions are advice. A model that is confused,
jailbroken, or prompt-injected can simply not follow them, and nothing in the
system stops it.

That is not a good enough boundary for a wallet. This ships as an **MCP stdio
server**, so the capability is enforced by the process rather than described in a
document:

- The model can only invoke the **declared tools**, with arguments that satisfy
  their schemas. There is no free-form escape hatch.
- **The model never signs anything itself.** It calls a tool; the server holds the
  sealed HMAC session key and drives the signing stack. A `wallet-cli` run from
  outside this server cannot obtain a valid proof — see the confused-deputy note
  below.
- **Security-critical configuration is locked server-side,** so the model cannot
  talk its way into repointing the signer or the keystore.

The same boundary works on any MCP host — Claude Desktop, IDE extensions, custom
clients — with no Wikey-specific code in the host.

## Threat model (one line)

A prompt-injected or rogue client model trying to (a) make the agent **reveal
the key**, or (b) **sign outside the typed tools**. Defense: key sealing +
auto-rotation + a locked-down config surface + a server-side snapshot store so
the model only ever sees small, complete derived data. Full detail in
[docs/SECURITY.md](./docs/SECURITY.md) and [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md).

---

## Install / host wiring

The server is published to npm as
[`wikey-wallet-mcp`](https://www.npmjs.com/package/wikey-wallet-mcp) and launched
over stdio:

```bash
npm i -g wikey-wallet-mcp
```

Add it to your MCP host config (generic `mcp.json`-style):

```json
{
  "mcpServers": {
    "wikey-wallet": {
      "command": "npx",
      "args": ["-y", "wikey-wallet-mcp"],
      "env": {
        "isDevEnv": "true",
        "installationScriptPath": "/path/to/install-child-mode.cjs",
        "installationScriptUrl": "https://example.com/install-child-mode.cjs"
      }
    }
  }
}
```

Any MCP host works (Claude Desktop, IDE extensions, custom clients) — point its
server config at `npx wikey-wallet-mcp` (or the absolute `dist/mcp-server.js`)
over stdio.

### ⚠️ Then restart your AI client — completely

**MCP hosts load their servers exactly once, at client startup.** Adding the
config above changes nothing in a client that is already running: the wallet
tools will not appear, and the agent has no way to know they exist. **Quit the
application and start it again** — closing the window or opening a new chat is
not enough.

The same applies to **upgrades**: `npm i -g wikey-wallet-mcp@latest` replaces the
files on disk, but the client keeps the already-loaded old process alive, so you
keep talking to the previous build until you restart. The server detects exactly
this and reports it — `wallet_getting_started` returns a `restartRequired` block
(`{ running, installed, message }`) whenever the on-disk version has moved ahead
of the running one.

Because a not-yet-loaded server has no channel to the user, the first-install
instruction is delivered where the user actually is at that moment — the
terminal. Run this straight after installing; it verifies the binaries **and**
ends with the restart rule:

```bash
wikey-wallet-mcp doctor
```

### First run — the two ways to start

Once the client is up, ask the agent to call **`wallet_getting_started`**. On a
brand-new install it reports stage `no-key` and hands back **two options**, as a
question for the user rather than a default:

1. **Individual (self-funded)** — `wallet_keys_create`, then buy OST gas at the
   Wikey store, then `wallet_tx_create_safe` for the account + username.

   `wallet_keys_create` returns a ready-made **`fundingUrl`** alongside the new
   address — the store with `?address=omnistar1…` already applied, which the
   store reads to prefill its *User address* field:

   ```
   https://store.wikey.io/?address=omnistar1wssmy9zpm4jrngxmle0y54l9kr3sx7khw93wyn
   ```

   Relay that link verbatim instead of sending the user to the bare store to
   paste an address by hand — a mistyped bech32 address is the one step of this
   flow that loses real funds. `wallet_getting_started` builds the same link at
   stage `unfunded`, for a key that already exists.
2. **Sponsored** — the user pastes the **invitation link** from their
   organization and `wallet_onboard_sponsor` does all of it in one call: creates
   a key, funds it from the sponsor grant, and creates the account + safe (and
   usually enrolls the gateway passkey).

**The order matters.** An invite always provisions a *fresh* identity and never
adopts an existing key, so a key created "to get started" before the user
answers is stranded — unfunded, safeless, and permanently listed next to the
real account in `wallet_accounts`. That is why the guide asks first and neither
option is the default.

### Uninstalling

**`wallet_uninstall`** removes the wallet from the machine: signing keys, local
state, and the npm package. Called with **no arguments it is read-only** and
returns a plan — what would be deleted, an audit of every account, and what would
still be left over (`residuals[]`). Run that first, always.

Deleting a key is irreversible. The private material is encrypted under a KEK
this machine holds; it cannot be restored from a backup, a passphrase, or by
Wikey. **The only way back into an account is its on-chain recovery helpers**
approving a move onto a new key — and only if they were configured beforehand.

So the audit, not the deletion, is the substance of the tool. Two things it gets
right that a naive check does not:

- **A recovery policy is not a recovery path.** An account can carry the
  policy with an *empty* helper list — the shape sponsored onboarding leaves
  behind. It approves nothing. The verdict uses the approval threshold against
  real helpers, never the policy's presence.
- **A helper that lives on this machine dies with it.** Helpers are accounts, and
  an account's helper can be another key in the same keystore. Wiping the machine
  destroys the account and its rescuers in one act, so each helper is classified
  local vs surviving and the verdict counts only survivors.

The destructive phase is **off by default** and has four gates:

| Gate | Effect |
| ---- | ------ |
| `confirm` phrase | Must match exactly. It embeds the live key count, so a plan taken before the keystore changed no longer applies. |
| `WIKEY_ALLOW_UNINSTALL=1` | Operator env, set by a **human** in the client config and read at startup. An agent cannot set it. Never set it and the capability does not exist. |
| `acceptPermanentLoss` | Required only when an account has no surviving recovery path. |
| Session shutdown | The signer is stopped before any file is touched. |

What it deliberately does **not** do: remove anything outside its own allow-list
under the state root (which may be shared with other Wikey tooling), and edit
your MCP client config (one bad write would break every other server in the
file). Those come back as `residuals[]` with the exact path and command.

**Uninstalling deletes nothing on-chain.** Accounts, safes and balances continue
to exist — they simply become unreachable from this machine.

### Environment flags

All Wikey behavior is driven by the server's own environment (the host's `env`
block above) — **the MCP host stays generic and needs no Wikey-specific
knowledge.**

| Flag | Type | Effect |
| ---- | ---- | ------ |
| `WIKEY_SSP_DIR` | path | **The single persistence knob (operator, not agent).** The one state root holding the SSP keystore, the software KEK (`dev.kek`), the child binaries, and wallet-cli's config. Default `~/.ssp`. Mount **one volume** here and the wallet stack is restart-stable. If the machine already has a `~/.ssp` from another wallet tool or a treasury setup, point this MCP at a separate root (e.g. `~/.ssp-mcp`) so the two keystores cannot collide. |
| `isDevEnv` | `"true"` / `"1"` | **Force software KEK** persisted to `<root>/dev.kek` (generated on first use, reused across restarts). **Unset / false → prod:** hardware-preferred KEK (`-kek-provider auto`); if no hardware enclave is present, the MCP **auto-falls-back once** to the persisted software KEK so keys still survive a restart (logged + shown in `doctor`/`session_status`). The KEK never reaches the model either way. |
| `WIKEY_ALLOW_UNINSTALL` | `"1"` / `"true"` | **Operator opt-in for `wallet_uninstall`'s destructive phase.** Unset (the default) → the tool still returns its read-only plan but refuses to delete anything, and explains that a human must set this. Set by a person in the client config; an agent cannot set its own environment, which is what keeps a keystore wipe out of a rogue model's reach. Leave it unset on any deployment that never needs to uninstall. |
| `installationScriptPath` | path | Explicit local path to `install-child-mode.cjs`. |
| `installationScriptUrl` | URL | Download location for the install script, used only when no local script is found. |

(`WIKEY_IS_DEV_ENV`, `WIKEY_INSTALL_SCRIPT`, `WIKEY_INSTALL_SCRIPT_URL` are
accepted as legacy aliases.)

### Persistence (operator)

In a container, mount **one** volume on the state root — nothing else is needed
and the agent's `mcp.json` stays bare:

```yaml
# docker-compose.yml (the host running the agent)
services:
  agent:
    volumes:
      - ./wikey-state:/root/.ssp   # HOME=/root → ~/.ssp; covers keystore, dev.kek, bin/, .wallet-cli
```

On real hardware (hardware KEK + a real disk at `~/.ssp`) nothing extra is
required. **Note:** a keystore previously encrypted under an *ephemeral* KEK
(e.g. a throwaway KEK on an enclave-less VM before this volume existed) is
**unrecoverable** — mint fresh keys.

### Binaries & auto-install

The server needs three child binaries on the machine:

| Binary           | Resolved from                          |
| ---------------- | -------------------------------------- |
| `signing-server` | `~/.ssp/bin`, then `PATH`              |
| `ssp-util`       | `~/.ssp/bin`, then `PATH`              |
| `wallet-cli`     | npm global bin, then `PATH`            |

On startup the server runs a **preflight**. If any binary is missing it
**auto-runs an external install script**, resolved **local-first, then by URL**:

1. `installationScriptPath`, then
2. the package-bundled script, then
3. `~/.ssp/install-child-mode.cjs`, then
4. download from `installationScriptUrl` (cached to `~/.ssp/install-child-mode.cjs`).

The install script is **not** shipped in this repo (it carries a private
registry token — keeping it out avoids a distribution leak). Provide it via
`installationScriptPath`/`installationScriptUrl`, or place it at
`~/.ssp/install-child-mode.cjs`. If neither a local file nor a URL is available,
the server fails with an actionable message.

The installer's output is streamed to **stderr only** — stdout is the MCP
JSON-RPC channel and is never polluted.

### `doctor` preflight

```bash
npx wikey-wallet-mcp doctor
```

Reports: binaries present + versions, the resolved **KEK provider** (hardware vs
persisted-software fallback), loopback reachability, and whether the install
script was found.

> **Version alignment.** All four components (`signing-server`, `ssp-util`,
> `wallet-cli`, and this MCP) must be **version-aligned per release** — drift
> causes `403` / malformed-proof. `doctor` reports versions. (`wallet-cli` is
> currently frozen at `1.0.0` with no tags — a known upstream gap, out of scope
> here.)

---

## Tool surface (46 tools)

There is **no** `wallet_session_start` (the session starts lazily on the first
signing call) and no `wallet_hmac_rotate` (rotation is automatic). Read-only
`wallet_session_status` is kept and the self-heal `wallet_session_recover` is
added.

- **Orientation:** `wallet_getting_started` (inspects live state and returns the
  exact next action — call this first when the user is unsure),
  `wallet_accounts` (every local key with its on-chain name, funding and safes).
- **Reads** (no SSP, no key): `wallet_chain_info`, `wallet_balance`,
  `wallet_balances`, `wallet_account`, `wallet_profile`, `wallet_assets`,
  `wallet_resolve_name`, `wallet_recovery_helpers`, `wallet_tx_check`.
- **Snapshot store (B2):** `wallet_snapshot` (returns a small **index only** —
  never raw JSON), `wallet_snapshot_query` (byte-budgeted, explicitly paged),
  `wallet_snapshot_page`, `wallet_snapshot_object` (one object in full, with
  `fields` narrowing to recover anything the byte budget dropped).
- **Keys:** `wallet_keys_list`, `wallet_keys_get`, `wallet_keys_create`.
- **Config:** `wallet_config_show`, `wallet_config_get`, `wallet_config_set`
  (security-critical keys **locked**), `wallet_config_init`,
  `wallet_config_reset`, `wallet_config_path`.
- **Session:** `wallet_session_status` (state + wedge diagnostics),
  `wallet_session_recover` (cold-restart a wedged session in place — see below).
- **Signing** (lazily brings up SSP, auto-rotates): `wallet_tx_create_safe`,
  `wallet_tx_send`, `wallet_tx_create_transaction`, `wallet_tx_vote`,
  `wallet_tx_request_recovery`, `wallet_tx_approve_recovery`,
  `wallet_tx_create_policy`, `wallet_tx_edit_policy`, `wallet_tx_delete_policy`,
  `wallet_tx_create_user`, `wallet_tx_delete_user`, `wallet_tx_edit_helpers`,
  `wallet_notification_configure`.
- **Gateway** (passkey-authorized calls to third-party APIs and MCP servers):
  `wallet_gateway_register`, `wallet_gateway_login`, `wallet_gateway_logout`,
  `wallet_gateway_status`, `wallet_gateway_api_call`, `wallet_gateway_mcp_call`.
- **Onboarding:** `wallet_onboard_sponsor` (sponsored invite → funded key → safe
  → optional passkey enrollment, resumable on the same key).

Per-tool operational guidance (smallCoin math, the policy `applyOn` mixing rule,
"a successful broadcast is **not** a completed deletion → re-query `isDeleted`",
token-credential handling) is carried in the tool descriptions.

### There is no default account

Anything that signs must be told **which account** to act as. With exactly one
key on the machine that is inferred; with several, the tool **refuses and returns
the key list** rather than picking for you — the caller passes `account` (address
or on-chain name) explicitly. `wallet_accounts` enumerates the choices.

Earlier versions followed a default-key pointer in the wallet-cli config that
named whichever key was created last, so minting a key could silently redirect
later signing to the wrong account. That pointer is gone; if an older install
left one behind it is blanked once on first start (noted on stderr), and nothing
else in the config is touched.

---

## Security note: the confused-deputy boundary

A raw `wallet-cli tx … --broadcast` run outside this server **cannot obtain a
valid proof** without the sealed HMAC key. SSP returns **403** and the call
fails (or times out with `TIMEOUT` after `wallet-cli`'s ~60s `signTimeout`) —
it never signs. The security claim holds; the mechanism is "403 / no valid
proof," not an indefinite stall.

---

## Recovering a "wedged" session (self-heal)

For security, the session **fails safe**: if the signing-server child dies
unexpectedly, or an automatic HMAC rotation fails, the live key is now useless,
so the session refuses to sign and marks itself **wedged**. Reads still work;
signing tools return an error containing the word `wedged`.

**Recovery does not require restarting the MCP server (or the agent host).** The
MCP server is a long-lived stdio child of the host — reloading the agent does
**not** re-spawn it, which is why "just restart" historically didn't help. Call
**`wallet_session_recover`** instead: it cold-restarts the session *in place*
(zeroize the dead key, kill the dead signer child, fresh nonce + new key + fresh
spawn — exactly what a process restart would do), then returns the
post-recovery status. If the underlying cause persists, it surfaces the real
spawn diagnostic rather than the generic wedge message.

### Guidance for agent clients (please follow)

> When a signing tool fails with a `wedged` error, **do not ask the end user to
> restart the server or the agent.** Instead:
> 1. call `wallet_session_recover` (optionally read `wallet_session_status`
>    first — `wedgedReason` and `lastChildExit` explain *why* it wedged), then
> 2. retry the original operation, and
> 3. tell the user in one line that you recovered and retried.
>
> Recovery is safe and idempotent (equivalent to a restart; no key material
> exposed; a no-op resync when not wedged), so it does not need a separate
> confirmation step beyond the host's normal tool-permission prompt.

### Operator note: skip the prompt

By default an MCP host asks the end user to approve each tool call. To let the
agent self-heal **without a prompt**, allowlist the recover tool in the host's
permission settings — e.g. for Claude Code:

```jsonc
// .claude/settings.json
{ "permissions": { "allow": ["mcp__wikey-wallet__wallet_session_recover"] } }
```

`wallet_session_status` is read-only and safe to allowlist alongside it.

---

## Development

```bash
npm install
npm run build      # → dist/ (incl. dist/mcp-server.js)
npm test           # tsc --noEmit + node:test suites
npm run doctor     # preflight against the local machine
```

- Greenfield ESM TypeScript, Node 22+.
- `src/core/` — pure, transport-agnostic logic (unit-testable, no transport).
- `src/mcp-server.ts` — the MCP stdio wrapper (`bin`).

## License

MIT © 2026 Wikey.
