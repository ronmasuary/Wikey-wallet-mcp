# Wikey Wallet MCP — End-User Setup

This guide installs the **Wikey Wallet MCP** server on your machine and wires it
into your AI agent client (Claude Desktop, Claude Code, or any MCP host). The
server is a **self-hosted, zero-custody** stdio server: your wallet private key
and its KEK live inside the local signing stack and are **never** exposed to the
model — Wikey never holds your keys.

---

## 1. Prerequisites

| Requirement | Notes |
| ----------- | ----- |
| **Node.js ≥ 22** | Check with `node -v`. Download from <https://nodejs.org>. |
| **git** | npm uses it to fetch the package from the GitHub URL in §2. Check with `git --version`. |
| **An MCP host** | Claude Desktop, Claude Code, an IDE extension, or any custom MCP client. |
| **Wikey install script** | `install-child-mode.cjs` — provided to you separately by Wikey. It carries a private registry token and is **not** in the repo. See §5. |

---

## 2. Install

Source of truth is **GitLab** (private); a **public read-only GitHub mirror** is
used for installs, so you do **not** need any Wikey credentials.

Install the package globally straight from the GitHub mirror branch:

```bash
npm install -g "git+https://github.com/ronmasuary/Wikey-wallet-mcp.git#kehat/idp_gateway_support"
```

npm runs the package's `prepare` script automatically, which builds it for you.
When it finishes you have a `wikey-wallet-mcp` command on your `PATH`:

```bash
wikey-wallet-mcp doctor
```

> Drop `#kehat/idp_gateway_support` once the work lands on the default branch.

---

## 3. ⚠️ State directory — read this before configuring

The server keeps **all** its state (keystore, software KEK, child binaries,
wallet-cli config) under **one** root directory, controlled by the
`WIKEY_SSP_DIR` env var. The default is `~/.ssp` (i.e.
`C:\Users\<you>\.ssp` on Windows).

> **If you already have a `.ssp` folder** (e.g. from another wallet tool, the
> wallet-cli, or a treasury setup), **do not reuse it.** Point this MCP at a
> **separate** root such as `.ssp-mcp` so the two keystores and default-key
> pointers can't collide:
>
> ```
> WIKEY_SSP_DIR = C:\Users\<you>\.ssp-mcp
> ```
>
> The folder is created on first run — you don't need to make it yourself.

---

## 4. Wire it into your MCP host

### Claude Code — one command (no hand-editing)

This writes the config entry for you — no JSON by hand:

```bash
claude mcp add wikey-wallet -e isDevEnv=true -e WIKEY_SSP_DIR=C:\Users\<you>\.ssp-mcp -- wikey-wallet-mcp
```

(Adjust `WIKEY_SSP_DIR` to your chosen state root from §3.)

### Claude Desktop (and any other host) — manual config

In **Claude Desktop**: open **Settings → Developer → Edit Config**. That opens
`claude_desktop_config.json` in your text editor. (Other hosts: `.claude.json` /
`.mcp.json` for Claude Code, or your host's own MCP config file.)

Add a `wikey-wallet` entry:

```jsonc
{
  "mcpServers": {
    "wikey-wallet": {
      "type": "stdio",
      "command": "wikey-wallet-mcp",
      "env": {
        "isDevEnv": "true",
        "WIKEY_SSP_DIR": "C:\\Users\\<you>\\.ssp-mcp"
      }
    }
  }
}
```

- Replace `WIKEY_SSP_DIR` with **your** chosen state root (see §3).
- On Windows JSON, backslashes must be **doubled** (`\\`).
- If your host can't find `wikey-wallet-mcp` on `PATH`, use the absolute path to
  the global bin (run `npm bin -g` to find it) or `npx wikey-wallet-mcp`.

Restart your MCP host after editing. In **Claude Desktop**, fully quit and
reopen the app (closing the window is not enough) so it reloads the config; the
`wikey-wallet` tools then appear under the 🔌 (MCP) menu.

### Environment flags

| Flag | Value | Effect |
| ---- | ----- | ------ |
| `WIKEY_SSP_DIR` | path | **The single state root.** Holds keystore, `dev.kek`, child binaries, and wallet-cli config. Default `~/.ssp`. See §3. |
| `isDevEnv` | `"true"` | Force the **software KEK** (persisted to `<root>/dev.kek`). Leave it set for a normal laptop/dev machine with no hardware enclave. Unset → hardware-preferred KEK with one-time software fallback. |
| `installationScriptPath` | path | Local path to `install-child-mode.cjs` (see §5). |
| `installationScriptUrl` | URL | Download location for the install script, used if no local copy is found. |

---

## 5. Child binaries & the install script

On first startup the server runs a **preflight** and needs three local binaries:
`signing-server`, `ssp-util`, and `wallet-cli`. If any are missing it
**auto-runs** the Wikey install script `install-child-mode.cjs`, resolved in
this order:

1. `installationScriptPath` (explicit local path), then
2. the package-bundled script, then
3. `<WIKEY_SSP_DIR>/install-child-mode.cjs`, then
4. download from `installationScriptUrl` (cached into your state root).

Wikey gives you this script separately (it carries a private registry token).
Either drop it at `<WIKEY_SSP_DIR>\install-child-mode.cjs`, or point
`installationScriptPath` / `installationScriptUrl` at it in your host `env`
block. If neither a file nor a URL is available, the server stops with an
actionable message.

---

## 6. Verify

Run the preflight against your machine:

```bash
wikey-wallet-mcp doctor
```

`doctor` reports: binaries present + versions, the resolved **KEK provider**
(hardware vs persisted-software), loopback reachability, and whether the install
script was found.

> **Version alignment matters.** `signing-server`, `ssp-util`, `wallet-cli`, and
> this MCP must be **version-aligned per release** — drift causes `403` /
> malformed-proof errors. `doctor` shows the versions.

Then, in your agent, ask it to run a read-only tool such as
`wallet_chain_info` or `wallet_balances` — these need no key and confirm the
wiring end-to-end.

---

## 7. If a signing call says the session is "wedged"

For safety the session **fails safe**: if the signing child dies or an automatic
HMAC rotation fails, signing tools return an error containing `wedged` (reads
still work). **You do not need to restart anything.** Ask your agent to call
**`wallet_session_recover`** — it cold-restarts the session in place and retries.
It's safe and idempotent.

To let the agent self-heal without a per-call approval prompt, allowlist the
recover tool. For Claude Code (`.claude/settings.json`):

```jsonc
{ "permissions": { "allow": ["mcp__wikey-wallet__wallet_session_recover"] } }
```

`wallet_session_status` is read-only and safe to allowlist alongside it.

---

## 8. Troubleshooting

| Symptom | Likely cause / fix |
| ------- | ------------------ |
| Server won't start; "install script not found" | Provide `install-child-mode.cjs` — see §5. |
| `403` / malformed-proof on signing | Version drift between the four components — run `doctor`, re-align. |
| Keys "disappeared" after a restart | Your keystore was encrypted under an **ephemeral** KEK before a persistent `WIKEY_SSP_DIR` existed → unrecoverable; mint fresh keys, and keep `WIKEY_SSP_DIR` fixed. |
| Collisions with an existing wallet/treasury | You reused `~/.ssp`. Switch this MCP to a separate root like `.ssp-mcp` (§3). |
| `node -v` shows < 22 | Upgrade Node to ≥ 22. |

---

## License

MIT © 2026 Wikey.
