# Security

## Threat actors

1. **External / network attacker** — mitigated by stdio-only transport (no HTTP
   exposed) and SSP binding loopback only; keys never egress on the network.
2. **Other local processes on the VM** — mitigated by killing only our own SSP
   child (never `pkill`) and by the short-lived, rotated HMAC key. (UDS +
   `SO_PEERCRED` is a documented future hardening; SSP's bind is fixed this round.)
3. **Prompt-injected / rogue client model** — the primary fear. It can only call
   the typed tools over stdio; it cannot reach the HMAC key, the wallet private
   key, the KEK, or raw signing.

## Defenses shipped in v1

### Key sealing (H11)

The HMAC session key is a `Buffer` held in the SessionManager closure — never a
module global, `globalThis`, an export, or a return value. Its only egress is:

- `ssp-util proof` / `rotate` **stdin** (written as bytes + `\n`), and
- the single `SSP_HMAC_KEY` **child env** at spawn (SSP `os.Unsetenv`s it
  immediately).

It is `.fill(0)`-zeroized on every rotation swap and on shutdown. No tool result,
error string, log line, `session_status` field, or child argv ever contains it
(`sealing.test.ts` asserts this, including `ps` argv). Residual heap/swap risk
(Node can't `mlock` its own Buffer) is bounded by rotation.

### Auto-rotation (server-owned)

A 15-min `setInterval` rotates the key via `ssp-util rotate`, serialized with
signing through an async mutex, sharing the monotonic nonce file. The exact
`ssp-util` exit-code policy is enforced: retry on `6`/`7` with 500 ms backoff
inside a 30 s grace (matching SSP's `rotateGracePeriod`), `4` is fatal ("SSP
unreachable"), grace-elapsed or any other code wedges the session — which stops
the timer and refuses further signing. There is no model-callable rotate tool.

### Lazy session, own-child only, nonce ownership

Reads never spawn SSP. The first signing call (including `wallet_keys_create`)
spawns SSP and mints the key, race-guarded so concurrent first-calls spawn
exactly one server. We hold the `ChildProcess` handle and kill only it. The
nonce file is deleted on a fresh spawn (client file and SSP's in-memory counter
both restart at 0) and kept across rotations (monotonic).

### Keys-at-rest KEK (H4)

Always `-keystore secure`. The MCP tries **hardware first** (`-kek-provider auto`
picks Keychain/TPM/DPAPI/Secure-Enclave). If SSP reports *no usable KEK provider*
at boot (enclave-less container, `SSP_KEK` unset), the MCP **falls back once** to
a persisted software KEK (`env` provider + a `dev.kek` 32-byte base64 key under
the state root) so the at-rest signing key survives a restart instead of being
lost. The downgrade is **fail-closed-then-warn**: it is logged to stderr and
surfaced via `session_status` (`kekProvider`/`kekFallback`) and `doctor`, so an
operator on real-prod hardware notices a transiently-missing enclave rather than
silently losing at-rest protection. `isDevEnv` remains an explicit *force-
software* override. A non-KEK boot failure is surfaced as-is and never triggers
the fallback. The KEK never reaches the model regardless of provider.

**Pre-existing keystores under an ephemeral KEK are unrecoverable** — those keys
were encrypted under a throwaway KEK that no longer exists; the fallback fixes
the problem going forward but cannot decrypt them. Mint fresh keys.

### Single state root (P2 — no default-key desync)

All persistent wallet state lives under **one root** (`WIKEY_SSP_DIR`, default
`~/.ssp`): the SSP keystore (`-keystore-dir <root>/keystore`), `dev.kek`, the
child binaries, and — crucially — wallet-cli's config (`<root>/.wallet-cli`,
reached by pinning `HOME=<root>` on every wallet-cli child). The **key material**
and the **"which key is default" pointer** (`user.address`/`user.pubkey`) thus
co-locate on one volume and survive a restart together, so they can never desync
into "pubkey does not match signer address". The config is seeded on first run
only (`signer.url` pinned to `http://127.0.0.1:8080`); an existing pointer is
never clobbered. This internal co-location uses `HOME`, never `config set user.*`,
so the tool-boundary config lock is preserved. An operator makes the stack
restart-stable with **one volume** on the root; the agent's `mcp.json` stays
bare (`{ "command": "wikey-wallet-mcp" }`).

### Transport enforcement & config lockdown (H10)

Stdio-only, private OS pipe; HTTP is never exposed. Reads are free; signing is
gated. `wallet_config_set` hard-rejects security-critical keys server-side:
`signer.*` (so `signer.url` stays pinned to loopback), `*.url`, `apiKey`, `kek*`,
`keystore*`, `user.*`. A prompt-injected model therefore cannot repoint the
signer off-loopback or weaken at-rest protection. Reads of config remain free.

**Operator escape hatch (`WIKEY_UNLOCK_CONFIG`).** An operator may set the
`WIKEY_UNLOCK_CONFIG` env var (`1`/`true`/`yes`/`on`) to bypass the lock entirely,
allowing the tool boundary to set *any* config key. This is an **operator** knob
(same class as `WIKEY_SSP_DIR`) — it is not agent-controllable, and the lock stays
**on by default**. Enabling it **defeats the H10 protection**: a prompt-injected
model can then repoint `signer.url` off-loopback (talk to a hostile signer),
weaken at-rest protection (`kek*`/`keystore*`), or move the default-key pointer.
Turn it on only in a trusted, non-adversarial environment where the agent is not
exposed to untrusted input.

### Lifecycle (H9)

`stdin` EOF, `SIGTERM`, `SIGINT`, and `SIGHUP` all trigger `session.shutdown()`
(zeroize key + kill own child + clear timer), so a dead host can't leave SSP
running with a live key.

### Data-integrity boundary (H14)

Raw safe/profile snapshot JSON is parsed and cached **server-side** and is
**never** returned to the model. The boundary is **size-bounded, not
shape-bounded**: every field of every object stays *reachable* (summary rows by
default, payload keys via `fields`, one complete object via
`wallet_snapshot_object`), but each response is byte-budgeted under
`maxResultBytes` (default 4 KB, below the smallest known host tool-result
limit; operators can raise it via `WIKEY_SNAPSHOT_MAX_RESULT_BYTES`). Any cut
is explicit — dropped rows report `{truncated, total, returned, nextOffset}`,
dropped fields are named in `omittedFields:[{key,bytes}]` — never silent. A
host that silently truncates a large tool result can therefore never feed the
model a corrupted snapshot (wrong SIGNATURE / parentGroup / isDeleted).

> Posture note: earlier versions also bounded the *shape* (a fixed 8-field
> projection with everything else silently dropped). That was a bug, not a
> defense — the model could not distinguish "absent" from "removed". Object
> payload values (policy conditions, user public_key, …) now cross the boundary
> on request; SIGNATURE values always did.

## Confused-deputy caveat (H12)

A raw `wallet-cli tx … --broadcast` run outside this server cannot obtain a valid
proof without the sealed HMAC key. SSP returns **403** (`exitAEADReject`), and
the call fails — or times out with `TIMEOUT` after `wallet-cli`'s ~60 s
`signTimeout` — rather than signing. The mechanism is "403 / no valid proof," not
an indefinite stall.

## Documented follow-ups (not in v1)

Intent verification (decode/simulate the unsigned `Sign Request` bytes and
assert they match the typed tool args), server-side spend caps + destination
allowlist, a tamper-evident hash-chained audit log, two-phase destructive ops,
binary checksum/signature pinning + SLSA provenance, and the asymmetric +
hardware-backed signing end-state (which would make rotation near-unnecessary).
The last requires SSP changes and is out of scope this round.

## Responsible disclosure

Report security issues privately via GitLab to the Wikey team
(`gitlab.com/bit2safe/wikey-wallet-mcp`). Do not open public issues for
vulnerabilities.
