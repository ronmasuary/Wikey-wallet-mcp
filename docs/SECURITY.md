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

Always `-keystore secure`. Hardware-preferred (`-kek-provider auto` picks
Keychain/TPM/DPAPI/Secure-Enclave). On enclave-less VMs a persisted
env/passphrase KEK is an allowed fallback so the at-rest signing key survives an
agent restart. The KEK never reaches the model regardless of provider; `doctor`
surfaces which provider is active.

### Transport enforcement & config lockdown (H10)

Stdio-only, private OS pipe; HTTP is never exposed. Reads are free; signing is
gated. `wallet_config_set` hard-rejects security-critical keys server-side:
`signer.*` (so `signer.url` stays pinned to loopback), `*.url`, `apiKey`, `kek*`,
`keystore*`, `user.*`. A prompt-injected model therefore cannot repoint the
signer off-loopback or weaken at-rest protection. Reads of config remain free.

### Lifecycle (H9)

`stdin` EOF, `SIGTERM`, `SIGINT`, and `SIGHUP` all trigger `session.shutdown()`
(zeroize key + kill own child + clear timer), so a dead host can't leave SSP
running with a live key.

### Data-integrity boundary (H14)

Raw safe/profile snapshot JSON is parsed and cached **server-side** and is
**never** returned to the model. `wallet_snapshot` returns a ~300 B index;
`wallet_snapshot_query` / `wallet_snapshot_page` return byte-budgeted results
under `maxResultBytes` (default 4 KB, below the smallest known host tool-result
limit) with explicit `{truncated, total, returned, nextOffset}`. A host that
silently truncates a large tool result can therefore never feed the model a
corrupted snapshot (wrong SIGNATURE / parentGroup / isDeleted).

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
