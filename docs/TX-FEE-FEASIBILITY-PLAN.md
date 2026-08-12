# Transaction feasibility pre-flight (fee-aware sends)

Status: **proposed, not implemented**. Two open questions at the bottom.

## The problem

A user asks their agent to "transfer all my BTC". The agent reads the balance
from `wallet_assets`, passes it verbatim as `amount` to
`wallet_tx_create_transaction`, and the transaction fails on-chain — the network
fee is paid out of the same asset, so a request for exactly the balance can
never settle.

Nothing in the MCP tool surface tells the model a fee exists.
`wallet_tx_create_transaction` ([src/mcp-server.ts:434](../src/mcp-server.ts))
documents smallest-units conversion and says nothing about fees at all.

## Why we can't just subtract the real fee

`wallet_tx_create_transaction` → wallet-cli `tx create-transaction` →
`context.api.getFeeRates(asset, destination)`
(`wallet-cli/src/commands/definitions/create-transaction.ts:194`) → proxy
`GET /api/transaction/estimated-fee`. That value is stored on the transaction as
`fee_rate`, and the name is literal — the proxy's values are masked and
normalized, and per chain they are not even the same kind of quantity:

| Chain | What `qty` actually is |
|---|---|
| BTC | `sat_per_vbyte` — a rate (`proxy/src/actions/blockchain/others/BTC.ts:37`) |
| ETH / Base / Polygon | the priority index `0\|1\|2`; `calcGasFeePrice` returns `qty: fee` where `fee` is the argument index (`proxy/src/actions/blockchain/rpc/ethereum/index.ts:132`) |
| XRP | a real total in drops (`proxy/src/actions/blockchain/rpc/xrp/index.ts:139`) |

The ETH source says it outright: `// NOTE: today we are calculating fee in the
safe!!!!!!!`. The real fee is computed by the signing engine, downstream of
anything the agent can observe.

Computing it independently from the network is possible per chain — trivial for
ETH-family and XRP, coupled to the signer's coin-selection for BTC — but that
puts a **second** fee implementation in the MCP, producing a number the signer
never sees, against a signer that computes its own. When they disagree (different
block, different UTXO set, different gas price) the agent reports one number and
the chain charges another. Rejected.

## The approach

Don't estimate the fee. Classify the *shape* of the request.

Most real failures are structural and provable without knowing any fee at all.
Only one band is a judgement call, and that one is reported as a probability
rather than a number.

## Rule ladder

New pure module `src/core/txFeasibility.ts` (transport-agnostic, per the layout
rule in `CLAUDE.md`). Rules evaluated in order, first match wins:

| # | Condition | Verdict | Needs a fee number? |
|---|---|---|---|
| R1 | Asset not held in that safe | `will-fail` | no |
| R2 | `amount > balance` | `will-fail` | no |
| R3 | `amount == balance` — full drain | `will-fail` | no |
| R4 | ERC-20 send, but the safe holds no native gas coin for that chain | `will-fail` | no |
| R5 | Reserve chain (XRP) left below the account reserve | `will-fail` | no |
| R6 | `balance − amount` under the headroom floor | `at-risk` | heuristic only |
| R7 | otherwise | `likely-pass` | — |

### R3 is the reported bug

And it is certain, not probabilistic: the fee comes out of the same asset, so a
request for exactly the balance cannot settle. No fee value is needed to know
that.

### R4 is not in the original report but belongs here

A USDC transfer pays gas in ETH, not USDC. A safe holding plenty of USDC and zero
ETH fails every time, and the failure looks like an amount problem — so it gets
"fixed" by lowering the amount, forever. Pure structural check, zero fee math.

### R6 is the only heuristic, and should be honest about it

Floor = `max(per-asset absolute minimum, USD-denominated headroom ÷ priceValue)`.

A flat percentage is wrong at both ends — 0.5% of a dust balance is nothing,
0.5% of 10 BTC is absurd — whereas fees are roughly USD-denominated in reality,
and `priceValue` is already in the assets response. One table, one file,
documented as deliberately conservative.

## Data source — already available, free

`query assets` returns, per safe: `symbol`, `value` (balance), `smallCoin`,
`priceValue`, and `layer2data { contractAddress, chain }` for tokens
(`wallet-cli/src/commands/types.ts:124`). The MCP already reaches it at
[src/mcp-server.ts:934](../src/mcp-server.ts) via `resolveAccountAddress` +
`queryAs(['query','assets'])`.

No new endpoint, no new credentials, no session bring-up — the check stays a free
read, consistent with the "reads are free" contract.

## Output shape

```jsonc
{
  "verdict": "will-fail" | "at-risk" | "likely-pass",
  "reason": "…human-readable, names the rule that fired…",
  "asset": "BTC",
  "safe": "omnistar1…",
  "balance": 123456,        // smallest units
  "requested": 123456,
  "remaining": 0,
  "maxSuggested": 121000,   // deliberately conservative, NOT a real fee
  "checkedAt": "2026-08-12T…Z"
}
```

`maxSuggested` is what the agent uses for "send everything". It is explicitly a
safe under-estimate. A transfer that lands slightly short beats one that fails.

## Enforcement — refuse, don't advise

Two surfaces:

1. **`wallet_tx_check`** — new read-only tool. Free, never signs, never brings up
   the session. Same class as `wallet_getting_started` / `wallet_recovery_helpers`.
2. **A precondition inside `wallet_tx_create_transaction`**
   ([src/mcp-server.ts:1119](../src/mcp-server.ts)) that runs the same core and
   **refuses** on `will-fail`, returning the structured verdict so the model can
   retry with a corrected amount.

The precondition is the part that matters. The current description already tells
the model about smallest-units and it still drained the balance — advisory text
loses to a user saying "send everything". The codebase already has the right
precedent: the no-default-account path refuses and hands back the account list
rather than guessing. Same shape here.

`at-risk` is overridable with an explicit `acknowledgeRisk: true`. R1–R3 are not
overridable — no legitimate call sends more than the balance.

## Files to touch

- `src/core/txFeasibility.ts` — **new**. Pure rule ladder + headroom table. Takes
  parsed assets as input, so it is unit-testable with no spawn fixtures.
- [src/mcp-server.ts](../src/mcp-server.ts):
  - `wallet_tx_check` entry in the `tools` array (next to
    `wallet_tx_create_transaction`, ~line 431) + dispatcher case.
  - precondition in the `wallet_tx_create_transaction` case (~line 1119).
  - fee language in the `wallet_tx_create_transaction` description (~line 434):
    the fee is deducted from the same asset; the full balance is never sendable.
  - `wallet_tx_send` (~line 1106) has the identical bug for OST — same core
    applies.
- `tests/txFeasibility.test.ts` — **new**. `node:test` over the rule table.
- `src/core/gettingStarted.ts` — `CAPABILITIES` (~line 90) should mention the
  check alongside "Send assets out of a safe".

## What this does not do

- It cannot catch a fee spike between check and broadcast. `likely-pass` is a
  probability, not a guarantee, and the output should say so rather than imply
  certainty.
- R6's floor is a judgement call that will need tuning against real failures.
  Everything above it (R1–R5) is structural and exact.
- It does not surface governance holds — a transaction that trips an amount or
  symbols policy will broadcast but wait on votes. That is a different kind of
  "it didn't go through" and is out of scope here.

## Open questions

1. **Chain scope for R4/R5** — the gas-asset and reserve rules are per-chain.
   Which chains ship in the first cut (BTC, ETH + ERC-20 incl. Base/Polygon,
   XRP, OST)?
2. **`at-risk` behaviour** — refuse-with-override, or annotate the result and let
   the call through?
