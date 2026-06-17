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

### Environment flags

All Wikey behavior is driven by the server's own environment (the host's `env`
block above) — **the MCP host stays generic and needs no Wikey-specific
knowledge.**

| Flag | Type | Effect |
| ---- | ---- | ------ |
| `WIKEY_SSP_DIR` | path | **The single persistence knob (operator, not agent).** The one state root holding the SSP keystore, the software KEK (`dev.kek`), the child binaries, and wallet-cli's config (the default-key pointer). Default `~/.ssp`. Mount **one volume** here and the wallet stack is restart-stable; the keystore and the "which key is default" pointer co-locate and cannot desync. |
| `isDevEnv` | `"true"` / `"1"` | **Force software KEK** persisted to `<root>/dev.kek` (generated on first use, reused across restarts). **Unset / false → prod:** hardware-preferred KEK (`-kek-provider auto`); if no hardware enclave is present, the MCP **auto-falls-back once** to the persisted software KEK so keys still survive a restart (logged + shown in `doctor`/`session_status`). The KEK never reaches the model either way. |
| `installationScriptPath` | path | Explicit local path to `install-child-mode.cjs`. |
| `installationScriptUrl` | URL | Download location for the install script, used only when no local script is found. |

(`WIKEY_IS_DEV_ENV`, `WIKEY_INSTALL_SCRIPT`, `WIKEY_INSTALL_SCRIPT_URL` are
accepted as legacy aliases.)

The Casdoor gateway is **off by default**: with no `WIKEY_CASDOOR_*` set, the
`wallet_gateway_*` tools simply error on use and nothing else changes. To enable
it, define identities (next section).

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

## Tool surface (39 tools)

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
- **Casdoor MCP gateway** (passkey login; token sealed): `wallet_gateway_list_identities`,
  `wallet_gateway_register`, `wallet_gateway_login`, `wallet_gateway_list_tools`,
  `wallet_gateway_call`, `wallet_gateway_status`. Every per-identity tool takes an
  `identity` **alias** (never a URL). See "Casdoor MCP gateway" below.

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

## Casdoor MCP gateway (passkey login)

The wallet can log into a **Casdoor** identity server **as a FIDO passkey** and
then call **third-party MCP servers through Casdoor's MCP gateway** — Casdoor
injects the upstream secret, so the agent never holds it. The OAuth token is
**sealed server-side and never returned to the model** (it lives like the HMAC
key). Full design in [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) §8 and
[docs/SECURITY.md](./docs/SECURITY.md).

**New outbound hosts** (this is the server's first network egress beyond the
installer): the **Casdoor host**, the **snapshot node**, and the **loopback
signer** (`/v1/sign`). The operator should restrict egress accordingly.

### Multi-identity model (operator defines, model picks by alias)

The operator defines a set of named identities. The model selects one by its
**alias only** for every gateway tool — it can never supply a host/URL (that
would be an SSRF/phishing hole). Identities load from **two operator-only
sources, merged (file wins, re-read live so additions need no restart):**

1. **Environment.** List aliases in `WIKEY_CASDOOR_ALIASES` (comma-separated);
   each field is `WIKEY_CASDOOR_<FIELD>__<ALIAS>` (alias upper-cased, non
   `[A-Z0-9]`→`_`):

   ```
   WIKEY_CASDOOR_ALIASES=work
   WIKEY_CASDOOR_HOST__WORK=http://localhost:8000
   WIKEY_CASDOOR_RP_ID__WORK=localhost
   WIKEY_CASDOOR_ORIGIN__WORK=http://localhost:8000
   WIKEY_CASDOOR_ORG__WORK=organization_kehat
   WIKEY_CASDOOR_USER__WORK=kehat_user
   WIKEY_CASDOOR_APP__WORK=application_kehat
   WIKEY_CASDOOR_CLIENT_ID__WORK=9d6472debe42f68f5f97
   WIKEY_CASDOOR_SNAPSHOT_NODE__WORK=proxy.omnistar.io:9093
   WIKEY_CASDOOR_ENV__WORK=main
   WIKEY_CASDOOR_REDIRECT_URI__WORK=http://localhost:9000/callback
   # optional: WIKEY_CASDOOR_SCOPE__WORK (default "read"), WIKEY_CASDOOR_SNAPSHOT_SECURE__WORK (default true)
   # one-time enrollment secret (unset after register; never seen by the model):
   WIKEY_CASDOOR_BOOTSTRAP_PASSWORD__WORK=...
   ```

2. **File.** A JSON array at `<root>/casdoor-identities.json` (operator-editable,
   re-read on every resolve — add identities at runtime, no restart):

   ```json
   [
     { "alias": "team", "host": "https://id.team.example", "rpId": "team.example",
       "origin": "https://id.team.example", "org": "org_team", "user": "team_user",
       "app": "app_team", "clientId": "cid_team", "snapshotNode": "node.team:9093",
       "env": "main", "redirectUri": "https://id.team.example/callback",
       "scope": "read", "snapshotSecure": true }
   ]
   ```

> **Operator requirements:** (1) configure the Casdoor gateway app with **no
> custom OAuth scopes** (custom scopes force a human consent screen that headless
> login cannot pass — login throws a clear error if it sees one); (2) point
> `SNAPSHOT_NODE` at the **same** node Casdoor's `wikeyNode` reads, or the
> on-chain object validity poll watches a different chain view.

### Flow

`wallet_gateway_register {identity}` (one-time, uses the bootstrap password) →
`wallet_gateway_login {identity}` (creates an on-chain FIDO proof object, signs
the challenge, exchanges an OAuth code; returns auth status, **no token**) →
`wallet_gateway_list_tools {identity, owner_name}` → `wallet_gateway_call
{identity, owner_name, name, arguments}` (auto-logs-in; result redacted). The
registered credential id (public, not a secret) persists per identity at
`<root>/casdoor-credentials/<alias>.json`.

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
