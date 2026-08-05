# Sponsor onboarding (funded accounts via an invitation link)

Lets an **invited user come online without funding their own key** — a "sponsor"
grant (created with a Casdoor invitation) authorizes a one-time gas airdrop to the
invitee's new key, then the safe is created under the invite's handle. Generic:
"sponsor" is anyone who issues an invitation (an org admin, or one user inviting
another), not just corporate.

One invitation code, **two independent ledgers**:

| Ledger | Owner | Store | Governs | Spent |
| ------ | ----- | ----- | ------- | ----- |
| Funding | proxy | Mongo `sponsorships` | one-time gas airdrop | two-phase: `reservedAddress` → `funded:true` |
| Enrollment | Casdoor idp | SQL `Invitation` | passkey binding | `UsedCount` / `Quota`, reusable |

They share a human-facing code but are tracked separately, so enrollment can never
re-arm funding. The existing `invitations` collection is **unchanged**.

## Onboarding sequence

1. `wallet_keys_create {setDefault:true}` — local key, zero custody
2. **sponsor-fund** — proxy verifies the code against `sponsorships`, airdrops gas, **reserves** the grant to the key
3. `wallet_tx_create-safe --username kehat@wikey --allow-org-username`
4. **sponsor-commit** — marks `funded:true`, only now is the grant spent
5. `wallet_gateway_register --invite …` — passkey binds to the safe

**Fund-and-create-only variant.** An invitation may carry **`&enroll=false`**, in
which case steps 1–4 run and step 5 (passkey enrollment) is intentionally
skipped — the invitee gets a funded, created account and nothing else. The result
stage is `funded-created`. Enrollment is deferred, not lost: the Casdoor
enrollment ledger (`UsedCount`/`Quota`) is untouched, so `wallet_gateway_register`
with the same link binds a passkey later on demand. Links **without** the param
behave exactly as before (`enroll` defaults to true). The idp appends the param
from a per-invitation "skip enrollment" flag; the proxy and wallet-cli are
unchanged (funding and create-safe are identical for both variants).

`wallet_onboard_sponsor {invite}` runs **all five** in one call — redeeming an
invitation link is a single tool call for the agent. Steps 3→5 are separated by
the time the safe needs to become queryable on-chain; the tool polls for it
(enrollment needs the safe's `ecPuk` as the credential public key).

> **How long 3→5 really takes.** An earlier version of this doc said ~30s. That
> was wrong, and it made healthy onboardings report as `created-enroll-failed`.
> The profile's `safes[]` is written by a **separate, later `addSafe` tx** than
> the create-safe tx, so the wait is the sum of both. A mainnet run on
> 2026-07-21 took **~2 minutes** (create-safe `D747BD3D…`, then `addSafe`
> `CB68DB80…`). `waitForWalletIdentity` now budgets **≈4 min**
> (`initialDelayMs 30s + 43×5s`). Timing out is not fatal — the on-chain work is
> kept and only enrollment is retried — so the budget is deliberately ~2× the
> observed worst case.

### Two-phase spend, and why re-running is safe

Funding moves real value before the safe exists, so the grant is spent in two
steps: `/sponsorFund` **reserves + airdrops**, `/sponsorCommit` **commits**. A
create-safe failure between them therefore never burns the invite.

Re-running `wallet_onboard_sponsor` with the same link **resumes** rather than
starting a second identity — it never mints a second key for a grant this machine
already funded. Two signals find the funded key again:

- **local breadcrumb** — `<state-root>/idp/sponsor-grants.json`, keyed by
  SHA-256 of the code (the code itself, a bearer secret, is never persisted).
  Checked *before* any key is minted.
- **proxy `reservedAddress`** — returned with the 409, used when the breadcrumb
  is gone. If we hold that key locally we adopt it; the key minted this run is
  then unused (and is the default) so the result carries a warning.

Work already done is skipped against the **chain**, not the breadcrumb:
create-safe is re-broadcast only if the address has no profile+safe.

Only a **committed** grant (proxy 403) means the invite genuinely onboarded
someone → `recovery-required`. A 409 for a key we don't hold means onboarding was
started on another machine and only that key can finish it — also
`recovery-required`, but with a different message; it is *not* "already used".

The breadcrumb's **terminal stage depends on the variant**: an enrol invite is
finished at `enrolled`, a no-enroll invite at `committed`. The record persists an
`enroll` flag so a re-run reads a completed no-enroll grant (`committed` +
`enroll:false`) as *done* → `already-onboarded`, rather than mistaking it for an
enrol grant stuck at `committed` and resuming into the already-spent proxy grant
(which would wrongly report `recovery-required`).

### Result stages

| Stage | Meaning | What to do |
| ----- | ------- | ---------- |
| `funded-created-enrolled` | fully done | nothing |
| `funded-created` | no-enroll invite (`enroll=false`): account ready on-chain, enrollment skipped by design | nothing; optionally `wallet_gateway_register` later to bind a passkey |
| `created-enroll-failed` | on-chain work done + grant committed, passkey didn't bind | retry `wallet_gateway_register` with the same link |
| `recovery-required` | the invite already onboarded an account | `wallet_tx_request_recovery` |

A thrown error means create-safe did not land: the grant is **reserved, not
spent**, and re-running the tool with the same link resumes on the funded key.
`warnings[]` carries non-fatal issues (uncommitted ledger entry, stray default key).

> **Funding = airdrop, not fee-grant.** The diagram originally showed a cosmos
> fee-grant, but wallet-cli never sets a tx fee-granter, so a fee-grant-only
> (zero-balance) key can't broadcast create-safe. The proxy therefore **airdrops
> real gas** to the key (`isFaucet=true`). Switching to a controlled fee-grant
> later means adding `--fee-granter` to wallet-cli (proxy would also return the
> granter address).

## What changed, per repo

- **idp** (`gitlab.com/bit2safe/idp`)
  - `object/invitation.go` `GetInvitationLink` → appends `&username={Username}@{Owner}`,
    and `&enroll=false` when the new `Invitation.SkipEnrollment` bool is set
    (fund-and-create-only variant). The field syncs as a new column on rebuild
    (bool, no xorm tag — same as `IsRegexp`); `UpdateInvitation` uses `AllCols()`.
  - `web/src/InvitationEditPage.js` → a "Skip enrollment" Switch (mirrors the OST
    amount row). `web/src/InvitationListPage.js` → `skipEnrollment:false` default
    on a new invitation.
  - `object/mongo_sponsorship.go` (new) + `object/mongodb.go` → `sponsorships` collection, write-once `SaveSponsorship`, `SeedSponsorshipForInvitation`.
  - `object/invitation.go` `AddInvitation` → seeds the funding grant (best-effort).
  - `conf/app.conf` → `mongoSponsorshipsCollection="sponsorships"`.
- **proxy** (`bit2safe`)
  - `services/database.service.ts` → `sponsorships` collection + unique index on `code`.
  - `routes/users/invitations.ts` → `POST /users/invitations/sponsorFund {code,address}`
    (code-gated airdrop, reserve-once) + `POST /users/invitations/sponsorCommit {code,address}`
    (finalize after create-safe; idempotent). Both refusals carry `reservedAddress`
    and `committed` so the caller can tell a resumable reservation (409) from a
    genuinely spent grant (403).
- **wallet-cli**
  - `utils/validation.ts` `validateUsername(u,{allowEmail})` → permits a single `@`.
  - `commands/definitions/create-safe.ts` → `--allow-org-username` flag.
  - `cli/commands/keys.ts` → `keys sign-challenge --challenge <hex>` (2026-07-21).
    Signs raw bytes via `POST /v1/sign`, no broadcast; needed by gateway *login*,
    not by onboarding. It **must** write the sign request to stderr as
    `Sign Request:` + JSON *before* awaiting the proof — the MCP watches stderr
    for that marker to compute the HMAC proof, and without it the command hangs
    on stdin instead of failing.
- **MCP** (this repo)
  - `core/idp/register.ts` `resolveInvite` → reads `username` from the URL (fallback for Casdoor login);
    `RegisterInput.account` (bind the passkey to an explicit address, not the config default)
    + `waitForSafe` (poll instead of failing while the safe validates).
  - `core/idp/identity.ts` → `resolveWalletIdentity(cfg, explicitAccount?)` + `waitForWalletIdentity`.
  - `core/idp/config.ts` + `core/idp/target.ts` → `proxyUrl` (env `WIKEY_PROXY_URL`).
  - `core/idp/sponsorFund.ts` (new) → `parseInvite` + `sponsorFund` + `sponsorCommit`.
  - `core/idp/sponsorGrants.ts` (new) → hashed-code breadcrumb of funded grants (resume).
  - `core/onboardSponsor.ts` (new) + tool `wallet_onboard_sponsor`. Reads
    `parsed.enroll`; when false, returns at stage `funded-created` without
    enrolling, and persists `enroll:false` on the grant so the terminal
    `committed` stage is recognized as done on a re-run.
  - `core/idp/sponsorFund.ts` `parseInvite` → parses `&enroll=false` into
    `ParsedInvite.enroll` (default true). `core/idp/sponsorGrants.ts`
    `SponsorGrantRecord` → optional `enroll` flag.
  - `tests/onboardSponsor.test.ts` (new) → happy path, both resume routes, partial-enroll,
    403-vs-409, and the "code is never persisted" guard.
  - `core/idp/identity.ts` `waitForWalletIdentity` → poll budget 110s → ≈240s
    (`attempts 43, intervalMs 5000, initialDelayMs 30_000`), see the timing note above.
  - `core/session.ts` → `toSpawnFailure()` normalizer. Unknown rejections were cast
    `as SpawnFailure`, so a plain Error (no `output`) made `spawnFailureToError`
    itself throw `Cannot read properties of undefined (reading 'trim')`, replacing
    every spawn diagnostic with a bogus TypeError.

## Test setup

1. **idp** — point at the shared Mongo (same cluster as the proxy's `DB_CONN_STRING`) so
   `AddInvitation` seeds `sponsorships`:
   ```ini
   # conf/app.conf
   mongodbconnectionstring = "mongodb+srv://…"   # same cluster as the proxy
   mongoDbDatabase = "bit2safe"                  # MUST equal the proxy's DB_NAME
   ```
   `mongoDbDatabase` must match the proxy's `DB_NAME` (currently `bit2safe`) or the
   idp writes the grant to a different database and `sponsorFund` always 403s.
   Rebuild/restart Casdoor.
2. **proxy** — ensure `FAUCET_MNEMONIC` is set and it runs against the target lab; the
   new `sponsorFund` route is live after a rebuild.
3. **wallet-cli** — rebuild + reinstall so the `create-safe` on PATH accepts
   `--allow-org-username`:
   ```bash
   cd wallet-cli && npm run build && npm i -g .
   ```
   Also confirm the passkey-login command exists — onboarding does not need it,
   but the account is useless without it (see the note below):
   ```bash
   wallet-cli keys sign-challenge --help   # must not say "unknown command"
   ```
4. **MCP** — build, reinstall globally, and set the proxy base + env in the MCP
   host's `env` block (building `dist/` alone doesn't update the installed binary):
   ```bash
   cd Wikey-wallet-mcp && npm run build && npm i -g .
   ```
   ```jsonc
   // MCP host env
   "WIKEY_PROXY_URL": "https://reverse-proxy.omnistar.io/<lab>/proxy",  // or http://localhost:<port>/…/proxy
   "WIKEY_ENV": "test"        // 'main' for mainnet
   ```
   Restart the MCP host so it re-spawns the server with the new env.

### Enrolling never signs; using the account always does

Worth being precise, because it is easy to get backwards:

| Step | Signs on-chain? | Needs `keys sign-challenge`? |
| ---- | --------------- | ---------------------------- |
| `wallet_gateway_register` — invite **or** username/password | no | **no** |
| `wallet_gateway_login` | yes | **yes** |
| `wallet_gateway_api_call` / `_mcp_call` | yes | **yes** |

`register.ts` does no wallet signing on either bootstrap path: it reads the
account from config, resolves the safe's `ecPuk` from chain snapshots, and POSTs
the WebAuthn signup. The two bootstraps differ only in how the Casdoor *session*
is opened (`signupWithInvitation` vs `passwordLogin`).

The consequence for an invited end user: a missing `sign-challenge` does **not**
break onboarding — they enrol cleanly and then fail on their first gateway call.
That failure mode surfaced on 2026-07-21 because the command had been lost (it
lived only as an uncommitted working-tree edit and was in no commit on any
branch); it is now implemented in `src/cli/commands/keys.ts`. Note that
`tests/idpLogin.test.ts` injects a stub `LoginSigner`, so **a green MCP suite
does not prove the real CLI path works** — only a live `wallet_gateway_login`
does.

### Troubleshooting a run

- **`SSP session is wedged`** — the usual cause is a stale `signing-server.exe`
  orphan still holding `127.0.0.1:8080`, so every fresh signer child dies on
  bind. Kill that PID, then `wallet_session_recover`; repeated recover alone will
  not help. A second, unrelated wedge (`rotation failed: ssp-util rotate exit 1`)
  is cleared by `wallet_session_recover` on its own. Both hit the same run on
  2026-07-21.
- **`created-enroll-failed` on a healthy run** — see the timing note above; retry
  `wallet_gateway_register` with the same link, the on-chain work is not redone.
- **Verifying the funding ledger** needs the proxy's `DB_CONN_STRING`; there is
  no `.env` in the local proxy checkout, so `sponsorships.funded:true` cannot be
  checked from a dev machine without it. The local breadcrumb reaching
  `stage: "committed"` is good indirect evidence.
- **`npm test` in this repo is ~97/21 on Windows** — pre-existing and unrelated:
  the spawn fixtures are `.mjs` files exec'd via a `#!/usr/bin/env node` shebang,
  which Windows ignores (`spawn EFTYPE`). Not a signal about your change.

### Creating the invitation (the only manual step)

In Casdoor, create the invitation as usual and **fill the `Username` field** (e.g.
`kehat`) — that is the invitee's handle. `Owner` (the organization the invitation
belongs to, e.g. `wikey`) is automatic. The link then carries
`&username=kehat@wikey`. **If `Username` is left empty the link omits it and
`wallet_onboard_sponsor` errors** (`invite link has no &username=`).

## Test — phase 1 (redeem the link end to end)

Give the agent the invitation link and ask it to redeem it. Expected: one
`wallet_onboard_sponsor` call → `stage: "funded-created-enrolled"`, a funded key,
safe `kehat@wikey`, `sponsorships` shows `funded:true`, and the Casdoor user has a
bound passkey (`webauthnWikeyAddress` = the safe). Allow a couple of minutes: most
of it is the on-chain safe validation the tool polls through.

**Verified on mainnet 2026-07-21** with `sponsorTest2@organization_xyz` → key
`omnistar1vtqrrlm…`, safe `omnistar14nv3gvs…`, passkey bound, and a subsequent
`wallet_gateway_login` returning a real token (`amr:["fido"]`, `objectValid`).
The run also exercised the resume path for free: it died mid-flow on a wedged
session, and the re-run came back `keyCreated:false, resumed:true` on the same
address with exactly one key in the keystore — the two-phase spend behaved as
designed.

Interrupt-and-resume check: kill the agent between the airdrop and create-safe,
then re-run with the same link. Expected: **no second key** (the address is
unchanged), and it finishes to `funded-created-enrolled`. Deleting
`<state-root>/idp/sponsor-grants.json` first exercises the other resume route —
the proxy's 409 `reservedAddress` — which does mint a stray key and returns a
`warnings[]` entry saying so.

## Test — phase 2 (recovery on reuse)  — *detection only so far*

Reuse a **committed** link (one that completed phase 1). The proxy returns 403 →
`alreadySpent`, and `wallet_onboard_sponsor` returns `stage: "recovery-required"`.
Full recovery orchestration (request-recovery onto the new key, and how the new key
gets gas when the sponsorship is spent) is the remaining phase-2 work.

Note the distinction introduced with the two-phase spend: a *reserved but
uncommitted* grant is **not** this case — it resumes silently (above) and never
reaches recovery.
