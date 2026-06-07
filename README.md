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

## Why an MCP server (not a skill)

The previous artifact was a ragent-shaped *skill* that only loaded in ragent
hosts behind an unenforceable `SKILL.md`. This is an **MCP stdio server**: a
typed tool boundary that runs in every MCP host and that the model **cannot**
talk around. The verified core logic is ported from that skill; the MCP wrapper
is the product.

## Threat model (one line)

A prompt-injected or rogue client model trying to (a) make the agent **reveal
the key**, or (b) **sign outside the typed tools**. Defense: key sealing +
auto-rotation + a locked-down config surface + a server-side snapshot store so
the model only ever sees small, complete derived data. Full detail in
[docs/SECURITY.md](./docs/SECURITY.md) and [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md).

---

## Install / host wiring

The server is published to npm as `wikey-wallet-mcp` and launched over stdio.
Add it to your MCP host config (generic `mcp.json`-style):

```json
{
  "mcpServers": {
    "wikey-wallet": {
      "command": "npx",
      "args": ["-y", "wikey-wallet-mcp"],
      "env": {
        "WIKEY_INSTALL_SCRIPT": "/path/to/install-child-mode.cjs"
      }
    }
  }
}
```

Any MCP host works (Claude Desktop, IDE extensions, custom clients) — point its
server config at `npx wikey-wallet-mcp` (or the absolute `dist/mcp-server.js`)
over stdio.

### Binaries & auto-install

The server needs three child binaries on the machine:

| Binary           | Resolved from                          |
| ---------------- | -------------------------------------- |
| `signing-server` | `~/.ssp/bin`, then `PATH`              |
| `ssp-util`       | `~/.ssp/bin`, then `PATH`              |
| `wallet-cli`     | npm global bin, then `PATH`            |

On startup the server runs a **preflight**. If any binary is missing it
**auto-runs an external install script**, located via:

1. `WIKEY_INSTALL_SCRIPT` env var, then
2. `~/.ssp/install-child-mode.cjs` (fallback).

The install script is **not** shipped in this repo (it carries a private
registry token — keeping it out avoids a distribution leak). Place it on the
machine, or point `WIKEY_INSTALL_SCRIPT` at it. If it's absent, the server fails
with an actionable message. *(A public download link for the script is planned;
v1 uses the env var + local fallback.)*

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

## Tool surface (32 tools)

Skill-compatible: the full skill surface **minus** `wallet_session_start` (the
session now starts lazily on the first signing call) and `wallet_hmac_rotate`
(rotation is automatic). Read-only `wallet_session_status` is kept, and three B2
snapshot tools are added.

- **Reads** (no SSP, no key): `wallet_chain_info`, `wallet_balance`,
  `wallet_balances`, `wallet_account`, `wallet_profile`, `wallet_assets`.
- **Snapshot store (B2):** `wallet_snapshot` (returns a small **index only** —
  never raw JSON), `wallet_snapshot_query` (byte-budgeted, explicitly paged),
  `wallet_snapshot_page`.
- **Keys:** `wallet_keys_list`, `wallet_keys_get`, `wallet_keys_create`.
- **Config:** `wallet_config_show`, `wallet_config_get`, `wallet_config_set`
  (security-critical keys **locked**), `wallet_config_init`,
  `wallet_config_reset`, `wallet_config_path`.
- **Session:** `wallet_session_status`.
- **Signing** (lazily brings up SSP, auto-rotates): `wallet_tx_create_safe`,
  `wallet_tx_send`, `wallet_tx_create_transaction`, `wallet_tx_vote`,
  `wallet_tx_request_recovery`, `wallet_tx_approve_recovery`,
  `wallet_tx_create_policy`, `wallet_tx_edit_policy`, `wallet_tx_delete_policy`,
  `wallet_tx_create_user`, `wallet_tx_delete_user`, `wallet_tx_edit_helpers`,
  `wallet_notification_configure`.

Per-tool operational guidance (smallCoin math, the policy `applyOn` mixing rule,
"a successful broadcast is **not** a completed deletion → re-query `isDeleted`",
token-credential handling) is carried in the tool descriptions.

---

## Security note: the confused-deputy boundary

A raw `wallet-cli tx … --broadcast` run outside this server **cannot obtain a
valid proof** without the sealed HMAC key. SSP returns **403** and the call
fails (or times out with `TIMEOUT` after `wallet-cli`'s ~60s `signTimeout`) —
it never signs. The security claim holds; the mechanism is "403 / no valid
proof," not an indefinite stall.

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
