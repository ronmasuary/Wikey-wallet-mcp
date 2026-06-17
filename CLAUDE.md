# wikey-wallet-mcp

MCP stdio server exposing the Wikey/Omnistar wallet & signing stack to a
client's own agent. Zero key custody by Wikey. See `docs/ARCHITECTURE.md` and
`docs/SECURITY.md` for the trust model.

## Layout

- `src/core/` — pure, transport-agnostic logic (unit-testable, no transport).
  - `session.ts` — SessionManager: sealed HMAC key Buffer, lazy/race-guarded
    `ensureSession`, own-child tracking, nonce lifecycle, auto-rotation timer,
    wedged flag, shutdown.
  - `proof.ts` / `signing.ts` / `query.ts` / `rotation.ts` — ported skill core.
  - `snapshot.ts` — ported parser/resolvers. `snapshotCache.ts` — B2 store.
  - `binPaths.ts` / `installer.ts` — binary resolution + KEK policy
    (hardware→software fallback) + single state root + auto-install.
  - `mutex.ts` / `redact.ts` / `configLock.ts` — supporting primitives.
  - Casdoor MCP-gateway (FIDO passkey login): `webauthn.ts` (pure FIDO3),
    `identityRegistry.ts` (operator alias→bundle), `casdoorIdentity.ts`
    (wallet↔Casdoor bridge), `casdoorClient.ts` (Casdoor HTTP), `gatewaySession.ts`
    (sealed token). `session.signRaw` signs caller bytes via `/v1/sign`.
- `src/mcp-server.ts` — MCP stdio entry (`bin`), tool registry, config lockdown,
  `doctor` subcommand, gateway wiring, signal/stdin-EOF → shutdown.
- `tests/` — `node:test` + `tsx`. Spawn-based suites use `tests/fixtures/*.mjs`
  stub binaries.

## Invariants (do not break)

- The HMAC key never crosses the tool boundary, a log, `session_status`, or
  child argv. Only egress: `ssp-util` stdin and `SSP_HMAC_KEY` child env.
- Raw snapshot JSON never returned to the model — only byte-budgeted derived
  rows (`maxResultBytes`, default 4 KB).
- Kill only our own SSP child — never `pkill`.
- Security-critical config keys are locked (`signer.*`, `*.url`, `apiKey`,
  `kek*`, `keystore*`, `user.*`).
- Single state root: `WIKEY_SSP_DIR` (default `~/.ssp`) is the ONE persistence
  knob (operator, not agent). Keystore (`-keystore-dir <root>/keystore`) +
  wallet-cli config (via `HOME=<root>`) co-locate so key material and the
  default-key pointer never desync. Co-location uses `HOME`, never
  `config set user.*` — the config lock stays intact.
- Casdoor gateway: the OAuth token is sealed like the HMAC key — held in
  `GatewaySession`, never returned to the model, never in `status()`, dropped on
  shutdown. The model passes an identity **alias only**; all URLs come from the
  operator registry (env + `<root>/casdoor-identities.json`) — never accept a
  model-supplied host. The gateway app must have **no custom OAuth scopes**.

## Git flow

Feature branches base off `origin/beta`. Merge target is `origin/beta`. `main`
is updated separately via a beta → main merge.

```bash
git checkout -b <type>/<short-desc> origin/beta
git add <files>
git commit -m "<type>(<scope>): <subject>

<body>"
git push -u origin <type>/<short-desc>
git fetch origin && git rebase origin/beta
git checkout beta && git pull origin beta && git merge --no-ff <type>/<short-desc> && git push origin beta
```

Branch naming follows conventional-commit prefixes: `fix/`, `feat/`, `chore/`.

## Build / test

```bash
npm install
npm run build   # tsc -p tsconfig.build.json → dist/
npm test        # tsc --noEmit + node --test --import tsx "tests/**/*.test.ts"
```
