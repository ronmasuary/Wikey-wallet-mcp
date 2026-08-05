# Snapshot field fidelity — handoff

**Status:** implemented and verified live; **round 2 is uncommitted**
**Branch:** `truncate_fix` (21 commits ahead of `origin/beta`)
**Component:** `wikey-wallet-mcp` — snapshot read path
**Tools:** `wallet_snapshot`, `wallet_snapshot_query`, `wallet_snapshot_page`, `wallet_snapshot_object`
**Last verified:** 2026-08-05, live against mainnet
**Supersedes:** `SNAPSHOT-FIELD-FIDELITY-PLAN.md` (2026-08-04, "proposed, not started")

---

## 1. Where things stand

| | |
| --- | --- |
| Round 1 (phases 0–5) | **Committed** — `3856810..b96c772`, 7 commits |
| Round 2 (`fields` narrowing, `siblings`) | **UNCOMMITTED** — working tree only |
| Tests | Snapshot suites 46/46 (`snapshotCache` 24 + `snapshotResolver` 22) |
| Live verification | All steps green, 2026-08-05 |

**The most important thing to know:** the code that makes this work end-to-end is sitting
uncommitted in the working tree:

```
 docs/ARCHITECTURE.md        |  11 ++
 src/core/snapshotCache.ts   | 108 ++++++++++++++++---
 src/mcp-server.ts           |  22 ++--
 tests/snapshotCache.test.ts | 135 +++++++++++++++++++++++-
```

Do not clean the tree without committing these.

---

## 2. The problem this solved

> The design intent was to bound response **size**. The implementation bounded response
> **shape**. Those are not the same thing, and the gap was the bug.

An agent reading a snapshot received a fixed 8-field subset of each object with **no signal
anything was missing** — indistinguishable from "the field is genuinely empty."

Lost across three layers:

| Layer | Site | What it did |
| --- | --- | --- |
| **1. Parser** | `snapshot.ts` — `asNestedObject`/`asGroup`/`asSafe` | Rebuilt nodes from a whitelist. Dropped `name`, `isValid`, **`process`** — and `process.currentPhase` *is* the governance state (approved vs. pending votes). |
| **2. Row projection** | `snapshotCache.ts` — `allRows` + `page` | **Primary culprit.** Took the fully-preserved `node.object` and emitted 8 fields. Discarded before budgeting was even considered. |
| **3. Byte budget** | `budget()` | **Not a cause.** Drops whole rows, always reports `truncated`. Field loss was unconditional — it happened on single-row results too. |

Layer 2 made `policy.conditions`/`applyOn`, `user.public_key`, `transaction.amount` and
`vote.votes` unreachable through *any* tool.

### Design principles (still binding)

1. Size is the constraint, **not a whitelist** — every field stays reachable.
2. **Never silent** — field-level omission is reported like row truncation already was.
3. **Discoverable before requestable** — the model learns a field exists without guessing.
4. **Backwards compatible** — default responses keep the historical shape.
5. **H14 holds** — raw snapshot JSON never crosses the tool boundary.

---

## 3. Round 1 — what shipped (committed)

| Commit | Phase | Change |
| --- | --- | --- |
| `3856810` | 0 | Test blocker: an assertion banned the *string* `/SIGNATURE/` from the index, which putting field *names* there trips. Narrowed to a **value** check — deliberately not deleted. |
| `c0c5bbe` | 1 | Parser preserves siblings: `name`, `isValid`, `process` on nodes; `isValid`/`object`/`process` on groups; `isMain`/`balance`/`assets`/`lastActive` on safes. `nestedPolicies`/`nestedUsers` verified as strict duplicates — still dropped. |
| `2fd75d3` | 2 | `fields: Record<class, string[]>` map in the index. |
| `fb6cc77` | 3 | New `wallet_snapshot_object` — one object complete, with `omittedFields:[{key,bytes}]`. |
| `4cc4bf1` | 4 | `fields?: string[] \| '*'` on query/page; the two copy-pasted projection sites merged into one `projectRow`. |
| `79348cb` | — | Size-aware cache eviction + `WIKEY_SNAPSHOT_MAX_RESULT_BYTES`. |
| `b96c772` | 5 | Tool descriptions and H14 wording match reality. |

### Deliberate divergences from the original plan

- **`fields` is top-level on the index, not per-safe.** The plan put it inside
  `SafeIndexEntry`. The map is near-identical per safe; per-safe would only bloat the index.
- **Safe-level extras are parsed but not surfaced in the index.** `SafeIndexEntry` stays
  `{address, name, counts}`. The plan listed surfacing them as optional; declined.
- **`object()` signature changed** from the planned `opts?:{maxBytes?}` to
  `opts?:{safe?, fields?}` — see round 2.

---

## 4. Round 2 — the gap round 1 created (UNCOMMITTED)

Round 1 made every field *reachable*. Testing on a large profile
(`omnistar16tnradtv953565jgv3qctzyxx8n9d6lgjrq7xk`, 9.28 MB, 4 safes, 1416 objects) showed
that wasn't sufficient.

**The failure:** the 4096 B default budget sits almost exactly on that profile's p90
complete-response size (median 2582 B, p90 4262 B, max 23963 B), so ~250 objects didn't
fit. The trimmer drops largest-first, and `process` (median 1542 B) is usually the biggest
thing on a transaction — so **governance state was the first field sacrificed, on 253/1414
objects.**

It was named in `omittedFields`, so the invariant held — but it was **unrecoverable**.
`wallet_snapshot_object` was the terminal call and took only `{snapshotId, id, safe}`, so
retrying returned the identical trim. And `fields` on query/page couldn't reach `process`
at all: it is a **sibling** of `object`, not a payload key, so even `'*'` missed it.

**The insight:** a budget that only ever removes data is a dead end. There must be a rung
*above* the biggest read, because **the way to get a dropped field is to ask for LESS, not
more** — the whole object doesn't fit, but one field almost always does.

### What was added

- **`opts.fields` on `object()`** — narrows the read to named payload keys and/or siblings.
  This is the recovery path for anything the budget dropped.
- **A shared `selectFields()`** so query/page reach siblings too.
- **`unknownFields`** — a bogus key returns an explicit list, never a silent `{}`.
- **`siblings: ["process","name","isValid"]`** as a **top-level index key** (added
  2026-08-05). Costs **+40 bytes**, versus +155 to merge the three names into all six class
  arrays.

**Result on the real capture: 272/278 dropped fields recoverable; `process` 253/253.**

### Why `siblings` is a separate namespace — do not "simplify" this

`index.fields` is built from object *payload* keys only, so it could never list
`process`/`name`/`isValid`. They needed advertising somewhere. They are kept separate, not
merged into the per-class arrays, because **payload wins a name clash**: `policy` carries
its own `name` payload key, so `fields:['name']` on a policy returns the payload value and
the node-level sibling is unreachable (and is *not* reported in `unknownFields`). **A merged
per-class list could not express that difference.**

**Proving this needs PLACEMENT, not value.** On real data a policy's payload `name` and its
node sibling hold the *identical string* (confirmed on two separate profiles), so comparing
values proves nothing. The observable difference is where the key lands:

```
fields:['name'] on a policy      → object:{name:"Genesis Profile Policy"}   (payload wins)
fields:['name'] on a transaction → top-level name:"undefined"               (sibling served)
```

Note: the sibling `name` is frequently the literal string `"undefined"`. That is faithful
passthrough of what the chain sends — verified against raw JSON. Not a parser bug.

---

## 5. Live verification — 2026-08-05

Run through the real MCP tools against mainnet, after rebuild + MCP restart.

| Step | Check | Result |
| --- | --- | --- |
| 1 | Index carries `siblings` | ✅ |
| 2a | `siblings == ["process","name","isValid"]` | ✅ |
| 2b | No class array contains `process`/`isValid` | ✅ all 6 classes clean |
| 2c | `name` present in `fields.policy` | ✅ (and in no other class) |
| 2d | Index size | 1954 B with / 1914 B without → **+40 B** as predicted |
| 3 | Sibling requestable from index alone | ✅ `currentPhase.name:"Failed"`, `object {}`, no `omittedFields` |
| 4 | Payload shadows sibling | ✅ nested under `object`, no `unknownFields` |
| 5 | Regression: full read | ✅ `omittedFields:[{key:"process",bytes:2316}]` |
| 5 | Regression: `fields:['process']` | ✅ `currentPhase.name === "Executed"`, `object {}`, clean |

Profile drift: object count is now **1416**, not the 1414 recorded on 2026-08-04 — live data
grew by 2. Both the live index and an independent capture agree.

---

## 6. Open items

### 6.1 `API_TIMEOUT` on large profiles — NEEDS A CONVERSATION, DO NOT PATCH UNILATERALLY

Fetching the large test profile fails intermittently with `API_TIMEOUT`. **This is not
flakiness.** `wallet-cli/src/core/api-client.ts:9` hardcodes `DEFAULT_TIMEOUT = 10000`, and
`createApiClient()` (same file, ~line 363) never passes an override — there is no config or
env knob. The upstream reverse-proxy fetch for this profile measures **9.5–12.7 s**
(`curl -w time_total`), straddling the cap, so the call succeeds or fails essentially at
random. It took 4 attempts on 2026-08-05.

As the profile grows this becomes a permanent failure.

**The 10 s value is assumed deliberate** — it is a different repo with a different author,
and a short cap on a wallet CLI is a plausible design choice (bounding how long an agent
blocks, or matching a signer-side deadline). **Do not change it without talking to the
wallet-cli author first.** If it does get raised, a per-call override scoped to the snapshot
read path is likely a better ask than moving the global default, since it is that one path
that has outgrown the cap.

Workaround in the meantime: retry, or replay offline (§7.2).

### 6.2 Six residual oversized fields

Six fields are single values larger than the whole 4 KB budget (`params` 17.9 KB, `message`
5.3 KB, …). No narrowing can fix those — they need
`WIKEY_SNAPSHOT_MAX_RESULT_BYTES`. Measured: 8192 → 2 still stuck; 16384 → 1; 32768 → 0.

### 6.3 Round 2 is uncommitted

See §1. Also worth deciding whether `truncate_fix` (21 commits ahead, and carrying an
unrelated `deeplink` commit `414894e`) should be split before merging to `beta`.

### Resolved since the plan

- ~~"The 4 KB default is not currently configurable"~~ → `WIKEY_SNAPSHOT_MAX_RESULT_BYTES`.

---

## 7. How to work on this

### 7.1 Build and reload

```bash
npm run build
```

The MCP host is a **symlink** to this repo (`npm root -g` →
`wikey-wallet-mcp -> ../../../projects/Wikey-wallet-mcp`), so a rebuild needs no reinstall.
**But the stdio server holds `dist` in memory from session start** — a restart is required
before changes take effect, and a *resumed* session keeps its stale tool registry, so new
tools only appear in a NEW conversation. First check on any verification run should be
"does the index carry the field I just added?"

### 7.2 Offline replay (no signer, no keys, works on profiles you don't own)

Snapshot reads are public. This bypasses the wallet-cli timeout entirely:

```bash
curl -s "https://reverse-proxy.omnistar.io/mainnet/node/snapshot/client?env=main&publickey=<addr>" -o big.json
```

Then ingest through the built `dist`:

```js
import { SnapshotCache } from 'file:///C:/Users/kehat/projects/Wikey-wallet-mcp/dist/core/snapshotCache.js';
const idx = new SnapshotCache().ingest(readFileSync('big.json', 'utf8'));
```

On Windows the import **must** be a `file:///` URL or Node rejects the drive letter as an
unsupported ESM scheme.

Size note: raw wire size is 4.55 MB but `index.bytes` reports 9.28 MB — wallet-cli
pretty-prints its stdout, so the two numbers measure different things. Neither is wrong.

### 7.3 Tests

```bash
npm test
```

Snapshot suites should be **46/46**. There are **21 pre-existing `spawn EFTYPE` failures**
on Windows (session/rotation/kek/signer/sealing/signing/stateRoot — spawning
`tests/fixtures/*.mjs`). They are unrelated to this work and were failing before it.

### 7.4 Gotchas

- **Pass `safe` on multi-safe profiles.** Ids like `policy-genesis` and `safe_profile` exist
  in several safes with **different payloads** (10 ambiguous ids in the large test profile).
  Without it you silently get the first match.
- **Pin `WIKEY_SSP_DIR=~/.ssp-mcp`** when running wallet-cli by hand, or it seeds config
  into treasury-voter's `~/.ssp`.
- The snapshot cache holds the **last 3** snapshots for **15 minutes**.

---

## 8. Deliberately out of scope

- **Filtering on object fields** (e.g. `filter:{applyOn:'transaction'}`). Selection first;
  revisit only if it proves necessary.
- **`wallet_recovery_helpers` stays as-is.** Once `wallet_snapshot_object` landed it is
  redundant, but it is load-bearing in live runbooks. Leave it — **and add no further
  per-field escape hatches.** That tool was itself a hand-patch of this same bug; the whole
  point of this work is that the general mechanism now exists.
- **`fields:'*'` on a broad match** collapses row counts hard. Mitigated by explicit
  truncation; tool descriptions steer callers to `wallet_snapshot_object` for depth and
  `wallet_snapshot_query` for enumeration.
