# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
