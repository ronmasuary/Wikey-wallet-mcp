# Smoke test: no-default-key on this machine

Test plan for the change in `REMOVE-DEFAULT-KEY.md`, written 2026-08-10 against
the live state of **this** machine (`WIKEY_SSP_DIR=C:\Users\kehat\.ssp-mcp`).
Read it after restarting the MCP — the session that wrote the code is gone by then.

## How to run it

Hand this file to the agent and ask it to run **Phase A**. Phase A is read-only
and it can do the whole thing unattended via the `wikey-wallet` MCP tools.

**Phase B moves real value on mainnet — the agent must stop and ask before it.**
Confirm B1 explicitly when you want it run.

Two things the agent cannot do for you:

- **The backup is a PRE-restart step.** The migration fires on the MCP's first
  startup, so it is too late once a new session is reading this. (Already done
  2026-08-10: `~/.ssp-mcp/.wallet-cli/config.json.bak`, holding
  `user.address = omnistar170g0375r707j3q75dasrez07mtzglat6hez6al` = sponsorTest2.)
- **It cannot see the MCP host's stderr**, so A1's log line is yours to eyeball.
  The agent verifies A1 from the config file instead, which is the part that
  matters.

## Two things to know before you start

**1. No reinstall needed.** The global package is a SYMLINK to this repo:

```
wikey-wallet-mcp@1.1.0 -> ...\projects\Wikey-wallet-mcp
```

so the `dist/` you just built is already what the MCP host loads. **Restart only** —
do not `npm i -g .`, and do not delete this tree.

**2. This machine holds FIVE keys**, so it is the multi-account case from the
first call onward. Every signing tool will now refuse to pick and will ask you
which account. That is the change working, not a failure.

| Address | Account | Safes |
| --- | --- | --- |
| `omnistar1553jw0…` | sponsorTest7@organization_xyz | 1 |
| `omnistar170g03…` | sponsorTest2@organization_xyz | 1 |
| `omnistar1e2eq2…` | sponsorTest4@organization_xyz | 1 |
| `omnistar1m756…` | **wikeyMCP** (the real one) | 2 |
| `omnistar1rccp2…` | sponsorTest6@organization_xyz | 1 |

## The drift is already on this machine

Right now `~/.ssp-mcp/.wallet-cli/config.json` says:

```json
"user": { "address": "omnistar170g0375r707j3q75dasrez07mtzglat6hez6al" }
```

That is **sponsorTest2**, not wikeyMCP. A sponsor-onboarding run moved the
pointer and never moved it back, so under the OLD code any signing call that
omitted `signingKey` signed as sponsorTest2 — silently, including on the wikeyMCP
safe. This is the bug the change removes, sitting in your own state.

**Back the file up before the first restart** — the migration blanks
`user.address`/`user.pubkey`, and that pointer value is not recorded anywhere
else:

```bash
cp ~/.ssp-mcp/.wallet-cli/config.json ~/.ssp-mcp/.wallet-cli/config.json.bak
```

## Phase A — read-only (no gas, no signing, no risk)

Run these first. None of them broadcasts anything or wakes the signer.

**A1. The migration fired.** After the first restart, check the MCP's stderr for:

```
[wikey-wallet-mcp] cleared the legacy default-key pointer …
```

then confirm the file:

```bash
node -e "console.log(JSON.stringify(require(process.env.USERPROFILE+'/.ssp-mcp/.wallet-cli/config.json').user))"
```

Expect `address` and `pubkey` empty, `signer.url` untouched. Restarting again
must NOT print the line a second time.

**A2. `wallet_accounts`** — expect the five rows in the table above, each with
`name`, `funded: true`, and its safes. This is the tool you point the user at
whenever another tool asks "which account?".

**A3. `wallet_getting_started`** — expect `stage: "multiple-accounts"`,
`keyCount: 5`, and an `accounts[]` where every entry has its own `stage`
(all `ready` here). The first `next` step should be `wallet_accounts`. Under the
old code this reported a single stage for whatever the pointer named.

**A4. `wallet_assets` with NO argument — expect a FAILURE.** The error should
list the five accounts and say to ask the user. This is the refusal working.

**A5. `wallet_assets { account: "wikeyMCP" }`** — expect the wikeyMCP safe's
portfolio. This is the highest-value read in the whole plan: `query assets` has
no `--address` flag, so it can ONLY be aimed by the injected environment. If A5
returns wikeyMCP's assets while A4 refused, the env routing works end to end.
(Note it takes the account NAME — addresses work too.)

**A6. Old-name compatibility** — `wallet_assets { signingKey: "wikeyMCP" }`
should behave exactly like A5. The parameter is no longer advertised but is
still read.

⚠️ **A6 may be untestable through an MCP client.** The fallback is deliberately
undeclared, so a client that validates arguments against the schema will strip
`signingKey` before the call ever reaches the server — and the result is then
indistinguishable from the parameter being ignored. If A6 comes back as the A4
refusal, that is **inconclusive, not a failure**: it means the client dropped the
argument. The fallback is covered by a unit test either way; verify it directly
with a raw JSON-RPC call only if you specifically care.

## Phase B — one signing operation (costs gas)

Only after Phase A passes. **Expect the port-8080 wedge on the first signing
call** — a stale `signing-server.exe` orphan holds the pinned port. Kill that PID,
then `wallet_session_recover`, then retry. Repeated `recover` alone will not help.

**B1. `wallet_tx_send`** — send a trivial amount (e.g. `1000nost`) between two
keys you own, e.g. from sponsorTest6 to sponsorTest7. This proves the full path:
account resolution validating that `from` is a local key, env routing, the
`--pubkey`-only flags, the SSP proof, and the broadcast. Cost is gas only, and it
touches no safe and no governance.

**B2 (optional). `wallet_gateway_login { account: "wikeyMCP" }`** — the deeper
proof: it signs an on-chain FIDO object and must resolve the safe of the SAME
account it signs as. Under the old code this pair came from two different places.
Costs gas.

## Do NOT test with

- **`wallet_tx_create_safe`** — creates a second, separate account. Never as a smoke test.
- **`wallet_onboard_sponsor`** — mints a key and spends a real invitation grant.
- **Anything on a safe you care about** (`create_user`, `edit_policy`, `edit_helpers`)
  until Phase A and B1 pass. Those are vote-governed and awkward to undo.

## What "it works" looks like

1. The pointer is cleared once and stays cleared.
2. A call that does not name an account either uses the only key (not the case
   here — there are five) or **refuses with the list**. It never picks.
3. A call that names an account acts on exactly that account, including on
   `query assets`, which has no flag to force it.
4. Naming an account this machine does not hold is an error, not a fallback.
