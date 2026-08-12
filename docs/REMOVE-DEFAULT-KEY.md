# Removing the "default key" (plan — MCP-only)

**Status:** COMPLETE — all four phases done 2026-08-10 (uncommitted; needs an
MCP restart to take effect, and has NOT yet run against the live chain). One
smaller question noted at the bottom.
The env-over-file precedence this design rests on is **VERIFIED** against real
wallet-cli, and now covered by an automated test.
**Scope:** `Wikey-wallet-mcp` only. **wallet-cli is not modified.** Written
2026-08-06, revised 2026-08-09 to the MCP-only approach.

## Goal

Stop the MCP from ever choosing a signing key implicitly. When a task needs a
signer and the caller did not name one, the tool either uses **the only key that
exists** or **fails with the list of accounts and tells the agent to ask the
user** — it never falls back to an ambient pointer.

The problem this solves: `keys create` currently mutates global signing identity
as a side effect. Every path that creates or recovers a key therefore silently
re-points every *other* command, which is exactly why key creation and recovery
are the two flows that keep breaking.

## What "default key" actually is today

Four separate mechanisms, layered.

### 1. The config pointer (wallet-cli)

`keys create` writes `user.address` + `user.pubkey` into
`<stateRoot>/.wallet-cli/config.json` —
[`keys.ts:45-56`](../../wallet-cli/src/cli/commands/keys.ts). Every tx command
then falls back to it:

| What | Fallback | Where |
| ---- | -------- | ----- |
| creator | `(opts.creator) \|\| config.user.address` | `registry.ts:128`, `broadcast.ts:174`, `tx.ts:286`, `tx.ts:326`, + 12 command definitions |
| pubkey | `(opts.pubkey) \|\| config.user.pubkey` | `broadcast.ts:175` |
| pubkey **again** | `config.signingPubKeyHex ?? base64ToHex(walletConfig.user.pubkey)` | `http-signer.ts:85` |

The third one is the dangerous one — it is *silent*. If creator and pubkey
disagree you broadcast a tx whose authInfo advertises key A but is signed by key
B. The MCP already found this and patches around it (`broadcast.ts:61-70`).

### 2. Reads default to it too

`query snapshot` / `profile` / `helpers` fall back to `config.user.address`
(`query.ts:144,177,216`). `query assets` has **no `--address` option at all** —
it goes `getAssetInfo()` → `getUserAssets()` →
`snapshot/client?publickey=${config.user.address}` (`api-client.ts:164`).

### 3. The MCP's per-call override

`resolveSignerArgs` ([`signing.ts:211`](../src/core/signing.ts)) turns a
`signingKey` address into `--creator/--pubkey`. It is wired into 10 signing tools
but is **optional on all of them** — omit it and you silently get the pointer.

### 4. The MCP reads the pointer as *identity*

This is the part that hurts most:

- `readAccountAddress` ([`idp/identity.ts:39`](../src/core/idp/identity.ts)) —
  gateway register/login/status bind the passkey to whatever the pointer says.
- `onboardSponsor` learns the address of the key it just created **by re-reading
  the pointer** ([`onboardSponsor.ts:150-158, 241-250`](../src/core/onboardSponsor.ts)).
- `wallet_getting_started` has a whole `no-default` stage
  ([`gettingStarted.ts:129`](../src/core/gettingStarted.ts)).
- `wallet_tx_request_recovery` derives the deeplink's `pk` from the pointer
  (`mcp-server.ts:1012-1021`); `wallet_tx_edit_helpers` derives `creator` from it
  (`mcp-server.ts:1179`) and its `notification configure --inbox` step cannot be
  routed with CLI flags at all.

Sponsor onboarding already documents fighting this ("the key minted this run is
unused but is now the wallet's default"), and recovery is precisely the case
where two keys legitimately coexist.

## The mechanism: per-process env injection

**wallet-cli already supports a per-process key override**, so none of the above
requires changing it.

`loadConfig()` layers **env over the config file**
([`loader.ts:99-108`](../../wallet-cli/src/config/loader.ts)), and two of the env
vars are exactly the pointer:

```
ADDRESS: 'WALLET_ADDRESS',
PUBKEY:  'WALLET_PUBKEY',
```
— [`types/config.ts:126-132`](../../wallet-cli/src/types/config.ts)

`loadConfigFromEnv` builds `config.user` from them (`loader.ts:67-76`), and
`mergeConfig` only filters `undefined`, **not** `''` (`types/config.ts:146`) — so
when both are set, env fully replaces whatever is in the file. A stale pointer
cannot shadow it.

**Verified against real wallet-cli** (2026-08-10), by running `config show` with
a deliberately wrong pointer in the config file — a pure local read, no network:

| Case | `user.address` seen by wallet-cli |
| ---- | --------------------------------- |
| file only, no env | `omnistar1FILEPOINTER` (the file) |
| both env vars set | `omnistar1ENVWINS` (env, both fields) |
| `WALLET_ADDRESS` only | `omnistar1ONLYADDR`, **pubkey `""`** |

The third row is why `walletCliEnv` sets both or neither.

The MCP already spawns every wallet-cli child through `walletCliEnv()`
([`binPaths.ts:108`](../src/core/binPaths.ts)). Teaching that function to take the
resolved account and add the two vars routes the signing key **per child
process** — no shared-file mutation, no cross-call race.

### Why this beats `--creator/--pubkey`

Three commands have no flags to route them, and all three read `loadConfig()`, so
env reaches them where flags cannot:

| Path | `--creator/--pubkey` | `WALLET_ADDRESS/PUBKEY` |
| --- | --- | --- |
| dynamic `tx *` | yes | yes |
| `tx send` | pubkey only | yes |
| `keys sign-challenge` | **no flag** | yes — `http-signer.ts:85` calls `loadConfig()` itself |
| `notification configure` | **no flag** | yes |
| `query assets` | **no flag** | yes |

`resolveSignerArgs` was **deleted** (Phase 2). It did its own `keys get`, so a
signing call would have made two independent lookups — one for the flags, one for
the env — which could in principle name different keys. It is replaced by the pure
`signerArgsFor(account)`, fed by the same single resolution as the env.

### Resolution rule

| Keystore | `account` given | Result |
| -------- | --------------- | ------ |
| 0 keys | — | onboarding error (create a key first) |
| 1 key | omitted | use it, silently |
| 1 key | given | validate it is that key |
| N keys | omitted | **throw** with `accounts[]` + "ask the user which account" |
| N keys | given | validate it is in the keystore |

**Explicitly not doing:** a server-side "current account" that persists across
calls. That is the default key with a new name. The agent remembers the user's
choice within a conversation and passes it.

## Bug found while surveying

`wallet_assets` pushes `--address` (`mcp-server.ts:799-803`) at a command that
does not define it, and there is no `allowUnknownOption` anywhere in wallet-cli —
so **`wallet_assets {address}` fails outright today**. It only ever works with no
argument, i.e. against the default key. Phase 1.4 fixes it by dropping the flag
and targeting the account through the env instead.

## Plan

### Phase 1 — account resolution + env routing ✅ DONE

1. ✅ `walletCliEnv(account?)` injects `WALLET_ADDRESS` + `WALLET_PUBKEY`. Sets
   **both** — setting only one blanks the other (`loader.ts:70-76`) — and
   **deletes inherited values** so the operator's environment cannot become an
   ambient default key by another name.
2. ✅ New `core/accounts.ts`: `listAccounts`, `resolveAccountAddress`
   (signing-free) and `resolveAccount` (adds the pubkey), implementing the
   resolution rule above. Errors are an `AccountResolutionError` carrying
   `accounts[]`, with the list also rendered into `.message` — the MCP tool
   boundary passes only the message. `requested` accepts an account NAME as well
   as an address, since the name is what the user actually says.
   `fetchPubkey` was extracted from `resolveSignerArgs` (signing.ts) so flag
   routing and env routing report an unknown key identically.
3. ✅ New read-only tool **`wallet_accounts`**.
4. ✅ `wallet_assets`: dropped the `--address` flag it pushed (commander rejected
   it — the tool only ever worked against the default key) and routes the
   account through the env instead. **Schema change:** its parameter is now
   `account` (a key/profile address or account name), not `address`; the old
   name implied a safe address, which it never was.

### Phase 2 — route every key-consuming path ✅ DONE

5. ✅ Every signing tool resolves an account (`acct()` in the dispatcher) and
   passes it into the child env. `signingKey` stays optional in the schema; all
   descriptions rewritten to *"omit ONLY when this machine has exactly one key;
   if it has several, ASK THE USER"*. The parameter now also accepts an account
   NAME. `resolveSignerArgs` was **replaced** by `signerArgsFor(account)` — a
   pure function fed by the same single resolution as the env, so the flags and
   the env can never name different keys (previously they were two independent
   `keys get` lookups).
6. ✅ **The guard is the type signature.** `session.signPrompted(account, …)`
   takes the account as a REQUIRED first parameter, so a signing path that
   forgets to route one does not compile — stronger than the planned runtime
   check, and it is what proved all 16 call sites were converted. A runtime
   check remains for the case types cannot catch: an account carrying an address
   but no pubkey (a read-only account) is refused before any spawn.
   `runWithSession` keeps the account OPTIONAL — `keys create` mints the first
   key and must run with an empty keystore.
7. ✅ The three flag-less paths route through the env: `notification configure`
   (including the `--inbox` step inside `wallet_tx_edit_helpers`),
   `keys sign-challenge` and `tx create-fido-object`, via a shared
   `gatewaySigner(session, account)` helper. `account` is threaded into
   `gatewayLogin` → `resolveWalletIdentity(cfg, account)` and forwarded by
   `gatewayApiCall` / `gatewayMcpCall`, so login resolves the safe of the SAME
   account it signs as — otherwise the on-chain FIDO object is created by a key
   that does not own the safe and Casdoor's check fails at the chain.

Also removed in passing: `wallet_tx_request_recovery` built its helper deeplink's
`pk` by reading the config pointer back, and `wallet_tx_edit_helpers` derived its
`creator` the same way. Both now use the resolved account — the key that actually
signed.

### Phase 3 — stop writing and stop reading the pointer ✅ DONE

8. ✅ `wallet_keys_create` ALWAYS answers `n` to the `Set as default?` prompt, so
   the config pointer is never written. `setDefault` removed from the schema —
   it is no longer a choice, because accepting would re-create the ambient
   default. The `n` answer is still required: it is what makes wallet-cli print
   its JSON and exit.
9. ✅ `onboardSponsor` learns the new address by **parsing `keys create` stdout**
   (`parseCreatedKey` → `data.id` + `data.pubkeyBase64`). Deleted
   `currentDefaultAddress`, the "expected a new default key" check, the entire
   `switched` variable and every "displaced default" warning. Its dep is now
   `createKey()` returning `{address, pubkey}` rather than `createDefaultKey()`
   returning stdout. Single biggest simplification in the change.
10. ✅ `readAccountAddress` **deleted** — it was the last reader of the pointer
    for identity. `resolveWalletIdentity(cfg, account)` takes `account` as
    required; `gatewayRegister` requires it. `gatewayLogin` falls back to the
    ENROLLED credential's account — a fact recorded at enrollment, not a guess —
    and `gatewayStatus.account` now reports the same, instead of the pointer
    (which could name an account with no passkey at all). `CASDOOR_ACCOUNT`
    survives as an operator fallback but is resolved like any other request, so
    an address outside the keystore is an error, not a silent mis-binding.
11. ✅ `gettingStarted.ts` rewritten per-account. Stages are `no-key → unfunded →
    no-safe → recovery-pending → ready`; `no-default` is gone. The report carries
    `accounts[]`, each with its own stage AND its own next steps (which name the
    key, so following one cannot act on a different account). Top-level `stage`
    is that account's stage when there is exactly one key, and
    `multiple-accounts` otherwise — deliberately NOT a collapsed "best" stage,
    which would let a ready account mask another's unfinished recovery. The
    parsers `extractAddresses`/`parseFunded` moved to accounts.ts, because the
    guide is now built on `listAccounts` and leaving them there would make the
    two modules import each other. `parseDefaultAddress` deleted.
12. ✅ `sponsorFund(invite, address)` takes the address explicitly (it no longer
    needs the `query` runner at all). `wallet_tx_request_recovery` builds its
    deeplink `pk` from the resolved account.
13. ✅ `SERVER_INSTRUCTIONS` drops `setDefault` and states the rule: there is no
    default account, one key is automatic, several means ask the user.

### Phase 4 — migration + tests ✅ DONE

14. ✅ One-shot migration (`core/migrateDefaultKey.ts`, run from `main()`): blanks
    `user.address`/`user.pubkey` in the co-located config and logs what it
    cleared. Not needed for correctness — the injected env wins over the file —
    but a pointer sitting in a config `wallet_config_show` reads claims a default
    account that does not exist, and it names whichever key happened to be
    created last. Deliberately conservative: only those two fields, blanked (not
    deleted) to match wallet-cli's own default shape, every failure swallowed, so
    a wallet that cannot complete it still starts and is still correct.
    Verified end-to-end through a real server startup: pointer cleared,
    `signer.url` untouched, and silent on the second start.
15. ✅ **Precedence regression test** (`tests/envPrecedence.test.ts`) — runs REAL
    wallet-cli `config show` (a pure local read: no network, no signer, no chain)
    against a temp state root holding a deliberately wrong pointer, and asserts
    the injected account wins. Also pins the partial-injection behaviour
    (address alone blanks the pubkey). Skips rather than fails when wallet-cli is
    not installed. This is the one assumption no stub-based test could catch: a
    wallet-cli release that reordered `loadConfig`'s layers would silently send
    every signing call back to the file.
16. ✅ Guard covered (`signPrompted refuses an account with no pubkey`); the
    compile-time half needs no test.
17. ✅ `gettingStarted.test.ts` rewritten around `classifyAccount` + per-account
    reports (including the case where a ready account must not mask another's
    pending recovery); `onboardSponsor.test.ts` converted to the `createKey` dep;
    `accounts.test.ts` covers the resolution matrix; `signer.test.ts` re-pointed
    at `fetchPubkey` + `signerArgsFor`.

### Test status

181 tests: 160 pass, 21 fail. All 21 failures are `spawn EFTYPE` in the
spawn-based fixture suites — pre-existing Windows noise, identical to the set
before this work, unrelated to the default key.

### Not yet done

**No live-chain run.** The tests cover resolution logic, the guard, the migration
and env precedence; none of them proves a routed `tx create-safe` broadcasts from
the intended key. The first live exercise should be a two-key machine performing
one signing operation on the NON-obvious account.

## Residuals of the MCP-only approach

Accepted consequences of not touching wallet-cli:

- **wallet-cli keeps its default key for humans.** Anyone running it directly
  still gets the old behavior. Out of scope, but it means the two repos now have
  different safety models — worth stating in wallet-cli's README eventually.
- **Error quality on an MCP bug.** If a future signing path forgets to pass the
  account, wallet-cli produces a confusing failure (empty `signingPubKey`
  reaching the signer) rather than a clean *"no signing key"*. Item 6 is what
  keeps that unreachable; item 16 is what keeps item 6 honest.
- **`keys create`'s prompt and config write still exist** in wallet-cli. The MCP
  simply never opts in. A human running wallet-cli directly against the same
  `WIKEY_SSP_DIR` could still set a pointer — harmless, since env overrides it on
  every MCP call.

## Decisions

**RESOLVED — `wallet_getting_started` with multiple keys:** report per-account,
with a `multiple-accounts` top-level stage rather than a collapsed one.
Implemented in Phase 3.11.

*(The earlier decision about `keys create`'s prompt is moot in the MCP-only
approach: the prompt stays in wallet-cli, and the MCP answers `n`.)*

## Follow-up done: `signingKey` → `account`

The parameter was renamed across the whole surface on 2026-08-10, so one concept
has one name. 16 tools now take `account`; no schema advertises `signingKey`.
`SIGNING_KEY_PROP` and `GATEWAY_ACCOUNT_PROP` collapsed into a single
`ACCOUNT_PROP`, and `wallet_getting_started` emits `account` in its suggested
args (it teaches the name, so it had to move too).

Why the old name had to go: it accepted an account NAME as well as a key, and on
the three flag-less paths (`notification configure`, `keys sign-challenge`,
`query assets`) nothing key-shaped is passed at all — the account is injected as
identity. It also disagreed with everything around it: the resolver error says
"ask the user which account", the lister is `wallet_accounts`, the report field
is `accounts[]`.

**Compatibility:** the dispatcher reads `input.account ?? input.signingKey`
(`accountOf`), so a caller with the old name hardcoded keeps working. It is
deliberately UNDECLARED — the model sees one parameter, old callers still
function. Safe to delete in a later release: an ignored `signingKey` can never
produce a wrong-key signature, because with one key the outcome is identical and
with several the resolver refuses to guess either way. There is a test for that
property.

Not renamed: `address` on the query tools (`wallet_balance`, `wallet_profile`,
`wallet_snapshot`, `wallet_recovery_helpers`, …). Those take any on-chain
address, including one this machine does not hold — a read target, not account
selection. Keeping the word distinct is information.

### Bug found while doing it

`wallet_notification_configure`'s dispatcher read `input.signingKey` but its
schema never declared the parameter, so on a multi-key machine it could only ever
fail — no advertised way to name the account, and the resolver correctly refusing
to guess. Introduced in Phase 2, fixed here. It slipped through because that tool
sits between the two vocabularies (an `address` for the request URL, an account
for the signer), so an audit keyed on `SIGNING_KEY_PROP` missed it.
