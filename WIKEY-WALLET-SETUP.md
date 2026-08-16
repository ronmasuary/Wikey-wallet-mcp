# Wikey Wallet MCP — Install Guide

> **This file is written for an AI agent client** (Claude Code, Claude Desktop,
> or any MCP-capable agent). If you are that agent: read this file top to bottom,
> then execute the steps in order. Ask the human only where this file says to.

**Package build: 2026-08-14 · MCP `wikey-wallet-mcp@1.1.0`, installed from the
public npm registry**

Supported on **Linux, macOS and Windows**. Where a command differs by platform,
both forms are given — run the one for your OS.

The Wikey Wallet MCP is a **self-hosted, zero-custody** MCP stdio server. It gives
your agent a typed tool boundary over the Omnistar wallet + signing stack: signing
keys, on-chain safes (accounts), users, governance policies, transactions, and
passkey-authorized calls to third-party APIs/MCPs through the Wikey gateway.

Wikey never holds the keys. Everything below runs on **this machine**.

---

## 0. What is in this package

| File | Purpose |
|---|---|
| `install-child-mode.cjs` | Installs the two native binaries (`signing-server`, `ssp-util`) and the `wallet-cli` Node CLI, all pulled from Wikey's release registry. |
| `INSTALL.md` | This file. |

The MCP server itself is **not** in this package — it is published publicly on npm
as [`wikey-wallet-mcp`](https://www.npmjs.com/package/wikey-wallet-mcp) and installed
with one command in §4.

These two files arrive together as `wikey-wallet-mcp-install.zip`. Extract them
before doing anything else, and keep both together in one folder — the MCP keeps
referring back to `install-child-mode.cjs` at the path you leave it in, so extract
straight into a **permanent** folder rather than Downloads (see §2):

```bash
unzip wikey-wallet-mcp-install.zip -d ~/wikey-wallet
```

```powershell
Expand-Archive wikey-wallet-mcp-install.zip -DestinationPath "$env:USERPROFILE\wikey-wallet" -Force
```

If you extracted to a permanent folder here, §2 is already done — skip to §3.

### Installing fresh, or updating?

If this machine **already has the Wikey Wallet MCP installed** from an earlier copy
of this package, do not work through sections 1–7 again — go straight to
[**§10 Updating an existing install**](#10-updating-an-existing-install), which is a
much shorter path. Sections 1–7 are the first-time install.

Quick way to tell:

```bash
wikey-wallet-mcp doctor
```

If that command is not found, this is a fresh install — continue with §1.

---

## 1. Prerequisites

- **Node.js 22 or newer** (the installer hard-fails below 22) and `npm`.
- Network access to `registry.npmjs.org` (the MCP server is installed from there)
  and to `gitlab.com` (the native binaries are downloaded from there).
- Linux, macOS, or Windows — all three are supported.

```bash
node --version
```

If it prints less than `v22`, install Node 22+ first (`nvm install 22 && nvm use 22`,
or from https://nodejs.org/).

---

## 2. Put the package somewhere permanent

Skip this section if you already extracted the zip into a permanent folder in §0 —
that folder is `<PKG>`, and there is nothing to move.

Otherwise: do **not** run this from a Downloads or temp folder — the MCP server keeps
referring back to `install-child-mode.cjs` at this path.

```bash
mkdir -p ~/wikey-wallet && cp install-child-mode.cjs INSTALL.md ~/wikey-wallet/
```

Windows (PowerShell):

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\wikey-wallet"; Copy-Item install-child-mode.cjs,INSTALL.md "$env:USERPROFILE\wikey-wallet"
```

From here on, `<PKG>` means that folder (e.g. `/home/you/wikey-wallet` or
`C:\Users\you\wikey-wallet`). Use **absolute paths** in every config value below.

---

## 3. Install the signing stack

```bash
node ~/wikey-wallet/install-child-mode.cjs
```

Windows (PowerShell) — `~` is **not** expanded for native commands, so use the
explicit form:

```powershell
node "$env:USERPROFILE\wikey-wallet\install-child-mode.cjs"
```

This installs into `~/.ssp/bin` (`%USERPROFILE%\.ssp\bin` on Windows):

- `signing-server` — the local signing process. It holds key material; it is
  spawned as a child of the MCP and dies with it.
- `ssp-util` — builds the HMAC proofs that authorize each signature.

and installs `wallet-cli` globally via npm. All three come from the same release, so
they are version-aligned with each other by construction.

The script appends `~/.ssp/bin` to your shell profile / user PATH. That is a
convenience only; the MCP resolves the binaries by absolute path, so you do **not**
need to restart your shell for the MCP to work.

> Changing the install location: if you set `SSP_INSTALL_DIR`, you must also set
> `WIKEY_SSP_DIR` to the **same** path in the MCP config in step 5 — otherwise the
> MCP will look for the binaries where they are not.

---

## 4. Install the MCP server

The server is published on the public npm registry, so this is the same single
command on every platform — no file paths involved:

```bash
npm i -g wikey-wallet-mcp
```

Verify the install and the binary resolution in one shot:

```bash
wikey-wallet-mcp doctor
```

`doctor` is read-only and safe to run at any time. You want the last line to read
`READY: all binaries present.` If it says `NOT READY`, re-read the paths it prints —
they tell you exactly which of the three components is missing.

---

## 5. Register the MCP with your agent client

Set **`installationScriptPath`** to the absolute path of `install-child-mode.cjs`.
This is what lets the MCP repair itself: if a binary ever goes missing, the server
re-runs the installer on startup instead of failing.

> **If this machine already has a `~/.ssp` folder** from another wallet tool, a
> standalone `wallet-cli`, or a treasury setup, **do not reuse it** — set
> `WIKEY_SSP_DIR` to a separate root such as `~/.ssp-mcp` in the `env` block below.
> See [§11](#11-state-root-and-environment-flags) for why, and for the full list of
> environment flags.

### Claude Code (CLI)

```bash
claude mcp add wikey-wallet -s user -e installationScriptPath=/absolute/path/to/wikey-wallet/install-child-mode.cjs -- wikey-wallet-mcp
```

### Claude Desktop / generic MCP client

Add this to the client's MCP config file. For Claude Desktop:

| OS | Config file |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

> **Windows path syntax in JSON.** A backslash starts an escape sequence, so
> `"C:\Users\you\wikey-wallet\install-child-mode.cjs"` is invalid JSON and will
> either fail to parse or silently mangle the path. Write **either** doubled
> backslashes `"C:\\Users\\you\\wikey-wallet\\install-child-mode.cjs"` **or**
> forward slashes `"C:/Users/you/wikey-wallet/install-child-mode.cjs"` — both
> work. This applies to every path in this file's JSON blocks.

```json
{
  "mcpServers": {
    "wikey-wallet": {
      "command": "wikey-wallet-mcp",
      "env": {
        "installationScriptPath": "/absolute/path/to/wikey-wallet/install-child-mode.cjs"
      }
    }
  }
}
```

If the client cannot find `wikey-wallet-mcp` on its PATH — common on Windows, where
npm installs a `.cmd` shim, and in GUI apps that do not inherit your shell PATH — use
the fully-explicit form instead. Get the path with `npm prefix -g`:

```json
{
  "mcpServers": {
    "wikey-wallet": {
      "command": "node",
      "args": ["<npm prefix -g>/node_modules/wikey-wallet-mcp/dist/mcp-server.js"],
      "env": {
        "installationScriptPath": "/absolute/path/to/wikey-wallet/install-child-mode.cjs"
      }
    }
  }
}
```

On Linux/macOS the path is `<npm prefix -g>/lib/node_modules/wikey-wallet-mcp/dist/mcp-server.js`.

**Restart the agent client** after editing the config.

---

## 6. Verify the agent can see it

Ask the agent to call **`wallet_getting_started`**. That tool inspects live state and
reports exactly which onboarding step you are on plus the precise next action. If the
tool list came through, you will get a real answer rather than "no such tool".

---

## 7. First run — onboarding order matters

A brand-new user has nothing set up. The sequence is fixed; doing it out of order
fails:

1. **Create a signing key** — `wallet_keys_create`.
2. **Fund that key with OST gas** — send OST to the address the previous step
   returned. Nothing can be broadcast on-chain until this is done. *(A human has to
   do this; the agent cannot conjure gas.)*
3. **Create a safe + claim a username** — `wallet_tx_create_safe`.
4. Then, as needed: add users, set governance policies, send assets, or enroll a
   gateway passkey (`wallet_gateway_register`) to call third-party APIs and MCPs.

If you were given an **invite link** by whoever sent you this package, skip the manual
sequence — call `wallet_onboard_sponsor` with the invite instead. It funds the key,
creates the safe, and enrolls the passkey in one flow.

### There is no default account

This wallet has **no default, current, or remembered account**, by design. Every
tool that signs — and a few that only read — takes an **`account`** parameter
naming the key to act as, either an `omnistar1…` address or an account name like
`alice@acme`.

- With exactly **one** key on the machine, `account` is optional; the tool uses
  that key.
- With **several**, a tool that was not told which account **fails and lists
  them**. That is correct behaviour, not an error to work around. Call
  `wallet_accounts` for the list, **ask the human which one they mean**, and pass
  their answer. Never pick on their behalf — guessing is how a wallet signs with
  the wrong key.

An agent upgrading from an older package should note that `wallet_keys_create` no
longer takes `setDefault`, and no call ever inherits an account from a previous
one.

Whenever you are unsure what to do next, call `wallet_getting_started` again. Reads
are free; the signing process only starts up lazily when something actually needs a
signature.

---

## 8. Troubleshooting

**`NOT READY` from `doctor`, or "binaries still missing after running the install script"**
Run `node <PKG>/install-child-mode.cjs` by hand and read its output — it prints the
exact URL and step that failed. Usual causes: no network to gitlab.com, or Node < 22.

**Every signing operation fails, or the session is reported "wedged"**
A stale `signing-server` from an earlier run is still holding port `127.0.0.1:8080`,
so each new signer child dies on bind. Calling recovery repeatedly will not help until
the orphan is gone:

```bash
lsof -ti :8080 | xargs kill
```

```powershell
Get-NetTCPConnection -LocalPort 8080 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```

Then call `wallet_session_recover`. Use `wallet_session_status` to confirm.

**`403`, "malformed proof", or a wallet-cli command reported as "unknown"**
Version drift. All four components — `signing-server`, `ssp-util`, `wallet-cli`, and
this MCP — must come from the same release. Re-run the installer (it pulls the current
release for all three) and reinstall the MCP with
`npm i -g wikey-wallet-mcp@latest` so it is not an older copy that happens to be on
the machine already.

**`EACCES` / "permission denied" from `npm install -g`**
Common on Linux and macOS when Node was installed system-wide (e.g. via `apt` or
the macOS installer) — the global `node_modules` is root-owned. Do **not** fix this
by re-running the whole install with `sudo`, which leaves root-owned files in your
home directory. Either install Node through a version manager that puts globals in
your home (`nvm`, `fnm`, `volta`), or point npm at a user-writable prefix:

```bash
npm config set prefix ~/.npm-global && export PATH="$HOME/.npm-global/bin:$PATH"
```

Then re-run step 4. Add that `export` line to your shell profile to make it stick.
If you do end up using `sudo` for step 4, run step 3 **without** it — the signing
stack must be installed as the user who will actually run the agent, since it lands
in that user's home directory.

**The agent client shows the server but no tools**
Almost always the config `command` not resolving. Switch to the explicit
`node` + absolute-path form in step 5 and restart the client.

---

## 9. What this software can reach

Worth knowing before you run it:

- The **signing key never leaves this machine**, and never crosses the MCP tool
  boundary — not into a tool result, not into a log, not into a process argument.
- The installer downloads all three components from Wikey's GitLab package registry
  over HTTPS and verifies each against published SHA-256 checksums.
- Security-sensitive configuration (signer URL, keystore location, KEK settings) is
  **locked against the agent** by design. Those are operator decisions, changed via
  environment variables by a human — not something the model can talk itself into.
- Transactions that move value are governed by the policies on your safe, on-chain.
  Installing this MCP does not by itself authorize anything to spend.

---

## 10. Updating an existing install

> Read this section if you were told something like "use the updated Wikey Wallet
> MCP" or "here's the new version" — whether or not you were handed a newer copy of
> this package.

**Knowing a new version exists is not enough.** Your client does not re-check npm.
It executes the copy that `npm` installed globally, and it launched that copy as a
child process when the client itself started. Until you reinstall *and* the client is
restarted, you are still running the old code.

Nothing you own is at risk in an update: signing keys, the keystore, and wallet
config live in the state root (`~/.ssp` by default, or `WIKEY_SSP_DIR`), which the
steps below never touch. You are replacing program code only.

### 10.1 Steps

**1 — Find `<PKG>`, the folder the previous copy was installed from.** If you do not
know it, ask the running server:

```bash
wikey-wallet-mcp doctor
```

The line `install script : <path>` prints the absolute path of
`install-child-mode.cjs`. Its parent folder is `<PKG>`. (If that line says
`(not found)`, use whatever folder the original install used, or pick a new
permanent folder as in §2 and set `installationScriptPath` to match — see step 5.)

**2 — If you were handed a newer copy of this package,** overwrite the old files
with the new ones, both of them, into that same `<PKG>`:

```bash
cp install-child-mode.cjs INSTALL.md <PKG>/
```

```powershell
Copy-Item install-child-mode.cjs,INSTALL.md "<PKG>" -Force
```

Skip this step if you were only told that a new MCP version is on npm — the MCP
server no longer ships in this package, so there may be nothing new to copy.

**3 — Reinstall the MCP server over the old one:**

```bash
npm i -g wikey-wallet-mcp@latest
```

The explicit `@latest` matters: without it, npm sees a `wikey-wallet-mcp` already
installed and may leave it alone. `@latest` always resolves to the newest published
version and replaces what is there, so you do **not** need to `npm uninstall -g`
first. Confirm you actually moved:

```bash
npm ls -g wikey-wallet-mcp
```

**4 — Re-run the binary installer** so all four components stay version-aligned:

```bash
node <PKG>/install-child-mode.cjs
```

This is safe to re-run at any time: it always resolves the current release and
reinstalls over whatever is already there. Skipping it is the usual cause of the
`403` / "malformed proof" symptom in §8 after an upgrade.

**5 — Leave the client config alone.** The registration from §5 refers to the
`wikey-wallet-mcp` command (or the `dist/mcp-server.js` path) and to
`installationScriptPath`. Both still point at the right places after an in-place
update, so there is nothing to edit. Only redo §5 if you moved `<PKG>` to a
different folder.

**6 — Stop the old signing process.** The previous server may have left a
`signing-server` holding `127.0.0.1:8080`; the new one will fail to bind behind it.

```bash
lsof -ti :8080 | xargs kill
```

```powershell
Get-NetTCPConnection -LocalPort 8080 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```

**7 — Restart the agent client.** This step is not optional and cannot be worked
around from inside a chat: an MCP stdio server is spawned once, at client startup,
and the already-running process keeps executing the code it was started with. Ask the
human to fully quit and reopen the client (Claude Desktop: quit the app, not just the
window).

### 10.2 Confirm the update actually landed

```bash
wikey-wallet-mcp doctor
```

Expect `READY: all binaries present.` as the last line before the NOTE.

Then check the live tool list — this is the reliable test, because the package
version number alone does not change on every release:

- The tool **`wallet_accounts`** must be present. It is new in this build; if your
  client does not list it, you are still talking to the **old** server process. Go
  back to step 7 and restart the client properly, then confirm with
  `npm ls -g wikey-wallet-mcp` that the global install resolves where you expect.

A second, stronger check that the new code is actually running: call
`wallet_getting_started`. On a machine with more than one key it must report
`stage: "multiple-accounts"` and give every account its own stage in `accounts[]`.
An older server reports a single top-level stage instead.

Finally, call **`wallet_getting_started`**. It reads live state and will tell you
where the account stands — an update does not move you backwards in onboarding, so
whatever step you were on before is where you still are.

### 10.3 What changed in this build

Relative to the previous package (2026-08-09):

- **The default account is gone.** This is the whole build. There is no default,
  current, or remembered account: every signing tool takes an explicit `account`
  (address or account name), and with several keys on the machine a call that does
  not name one now **fails with the list** instead of silently picking. Previously
  the wallet followed a pointer in its config that named whichever key was created
  last — so creating a key, or completing a sponsored onboarding, could silently
  redirect later signing to the wrong account. See §7.
- **New `wallet_accounts` tool.** Lists every local key with its on-chain name,
  funding and safes. This is what you show the human when a tool asks which account
  to use. Read-only; it never starts the signing session.
- **`wallet_getting_started` classifies each account separately.** With more than
  one key it returns `stage: "multiple-accounts"` and a per-account `accounts[]`,
  each entry carrying its own stage and next steps — so a finished account can no
  longer mask another one's unfinished setup or pending recovery.
- **`wallet_keys_create` no longer takes `setDefault`,** and creating a key no
  longer changes what any later call signs as.
- **One-time cleanup on first start.** If an older install left a default-key
  pointer in the wallet-cli config, it is blanked once, and a line is written to
  stderr saying so. The pointer could not route anything either way; leaving it
  would have made `wallet_config_show` claim a default account that no longer
  exists. Nothing else in the config is touched, and your keys are unaffected.

---

## 11. State root and environment flags

> This section is specific to the repository copy of this guide; it is not in the
> INSTALL.md shipped to end users.

### The state root

The server keeps **all** its state — keystore, software KEK, child binaries, and
wallet-cli config — under **one** root directory, set by `WIKEY_SSP_DIR`. The
default is `~/.ssp` (`C:\Users\<you>\.ssp` on Windows). The folder is created on
first run; you do not need to make it yourself.

**If you already have a `.ssp` folder** — from another wallet tool, a standalone
`wallet-cli`, or a treasury setup — point this MCP at a **separate** root so the two
keystores and their default-key pointers cannot collide:

```
WIKEY_SSP_DIR = C:\Users\<you>\.ssp-mcp
```

Keep that value **fixed** once you have created keys. Keys minted before a
persistent `WIKEY_SSP_DIR` existed were encrypted under an ephemeral KEK and cannot
be recovered if the root moves — see the troubleshooting table below.

### Environment flags

| Flag | Value | Effect |
| ---- | ----- | ------ |
| `WIKEY_SSP_DIR` | path | **The single state root.** Holds keystore, `dev.kek`, child binaries, and wallet-cli config. Default `~/.ssp`. |
| `isDevEnv` | `"true"` | Force the **software KEK** (persisted to `<root>/dev.kek`). Set this on a normal laptop with no hardware enclave. Unset → hardware-preferred KEK with one-time software fallback. |
| `installationScriptPath` | path | Local path to `install-child-mode.cjs` (§5). |
| `installationScriptUrl` | URL | Download location for the install script, used if no local copy is found. |

### How the install script is resolved

On first startup the server runs a preflight for `signing-server`, `ssp-util`, and
`wallet-cli`. If any are missing it auto-runs `install-child-mode.cjs`, resolved in
this order:

1. `installationScriptPath` (explicit local path), then
2. the package-bundled script, then
3. `<WIKEY_SSP_DIR>/install-child-mode.cjs`, then
4. download from `installationScriptUrl` (cached into the state root).

If neither a file nor a URL is available, the server stops with an actionable
message.

### Letting the agent self-heal a wedged session

§8 covers clearing a stale `signing-server` off port 8080. To let the agent call the
recovery tool without a per-call approval prompt, allowlist it — for Claude Code, in
`.claude/settings.json`:

```jsonc
{ "permissions": { "allow": ["mcp__wikey-wallet__wallet_session_recover"] } }
```

`wallet_session_status` is read-only and safe to allowlist alongside it.

### Additional troubleshooting

| Symptom | Likely cause / fix |
| ------- | ------------------ |
| Keys "disappeared" after a restart | The keystore was encrypted under an **ephemeral** KEK before a persistent `WIKEY_SSP_DIR` existed → unrecoverable. Mint fresh keys and keep `WIKEY_SSP_DIR` fixed. |
| Collisions with an existing wallet or treasury setup | You reused `~/.ssp`. Switch this MCP to a separate root such as `.ssp-mcp` (above). |
| `wallet_config_show` names an account that does not exist | An older install's default-key pointer; it is blanked once on first start (§10). Harmless. |

---

## License

MIT © 2026 Wikey.
