#!/usr/bin/env node
// Wikey Wallet MCP — stdio server (THE product).
//
// Registers the typed tool surface over StdioServerTransport and maps each tool
// to the transport-agnostic core. The model reaches ONLY these typed tools over
// a private OS pipe; the HMAC key, the wallet private key, and the KEK are all
// unreachable. Reads are free; signing is gated and lazily brings up SSP.
//
// Security wiring here:
//   - config-key lockdown (H10): wallet_config_set rejects security-critical keys.
//   - raw snapshot JSON never returned (H14): wallet_snapshot returns an index;
//     wallet_snapshot_query / _page return byte-budgeted rows.
//   - stdin-EOF / SIGTERM / SIGINT / SIGHUP → session.shutdown() (H9).
//   - error strings are scrubbed (H11) before crossing the boundary.

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import {
  SessionManager,
  SnapshotCache,
  ensureBinaries,
  resolveBins,
  resolveKekPolicy,
  isDevEnv,
  locateInstallScript,
  runQuery,
  walletCliEnv,
  walletHome,
  stateRoot,
  keystoreDir,
  listKeystoreAddresses,
  parseSnapshot,
  findSafe,
  extractGroupsFromSafe,
  resolveCreateUserTarget,
  resolveUserDeletion,
  resolvePolicyDeletion,
  extractUsernameFromProfile,
  listAccounts,
  parseCreatedKey,
  resolveAccount,
  resolveAccountAddress,
  AccountResolutionError,
  isChainAddress,
  signerArgsFor,
  buildPolicyQueue,
  buildEditHelpersQueue,
  resolveNameViaEditHelpers,
  assertConfigSetAllowed,
  clearDefaultKeyPointer,
  buildGettingStarted,
  storeFundingUrl,
  WIKEY_STORE_URL,
  executeUninstall,
  ALLOW_ENV,
  detectInstall,
  realFs,
  npmUninstall,
  findClientConfigs,
  onboardSponsor,
  buildRecoveryDeeplink,
  parseRecoveryDeeplink,
  checkFeasibility,
  buildFeeChoice,
  normalizeFeePriority,
  feePriorityRefusal,
  feePriorityInvalid,
  checkBankSend,
  fetchSafeAssets,
  fetchPortfolio,
  fetchRecipientSafes,
  pickRecipientSafe,
  pickReceiveAddress,
  checkAddressFamily,
  checkSelfSend,
  addressFamily,
  suggestAccountNames,
  unknownNameRefusal,
  parseDenomAmount,
  parseBalanceAmount,
  toSmallest,
  saveRecoveryRequest,
  loadRecoveryRequest,
  clearRecoveryRequest,
  redact,
  type AccountEnv,
  type RecipientSafe,
  type SafeChoice,
  type NameCandidate,
  type ResolvedAccount,
  type FieldSelector,
  type PolicyCondition,
  type QueryFilter,
  type WalletCliLauncher,
} from './core/index.js';
import {
  gatewayRegister,
  gatewayStatus,
  gatewayLogout,
  gatewayLogin,
  gatewayApiCall,
  gatewayMcpCall,
  loadCfg,
  resolveWalletIdentity,
  waitForWalletIdentity,
  type RegisterInput,
  type LoginInput,
  type LoginSigner,
  type ApiCallInput,
  type McpCallInput,
} from './core/idp/index.js';
import { createConnection } from 'node:net';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { createRequireResolveVersion, readInstalledVersionFromDisk } from './version.js';
import { FIRST_INSTALL_RESTART_NOTICE } from './core/restartNotice.js';

const SERVER_NAME = 'wikey-wallet-mcp';
const SERVER_VERSION = createRequireResolveVersion();

// ─── Orientation (Layer A) ────────────────────────────────────────────────────
// Sent to the client in the `initialize` result and injected into the model's
// context at connect time. Its job is to teach the ONBOARDING SEQUENCE and point
// at the one tool that answers "what can I do next?" — NOT to re-list the tools
// (the client already shows those). Keep it short; specifics live in each tool's
// own description and in wallet_getting_started's live output.
const SERVER_INSTRUCTIONS = `Wikey Wallet — a self-custody wallet + signing stack on the Omnistar chain. It
manages signing keys, on-chain "safes" (accounts), users, governance policies,
transactions, and passkey-authorized calls to 3rd-party APIs/MCPs via the gateway.
Wikey never holds the keys.

FIRST-RUN ONBOARDING HAS TWO ENTRY POINTS — a brand-new user has nothing set up, and
which path they are on decides the very first call. ASK THEM, never assume:

  A. INDIVIDUAL (self-funded) — three steps, in order:
       1. Create a signing key       → wallet_keys_create
       2. Fund it with OST gas       → buy OST at https://store.wikey.io/ and send it to
                                       that key's address (required to broadcast anything)
       3. Create a safe + username   → wallet_tx_create_safe

  B. SPONSORED (an invitation link from their organization) — ONE call:
       wallet_onboard_sponsor does all three: it creates a key, funds it from the
       sponsor (the user never buys gas), and creates their account + safe.

  Do NOT create a key "to get started" before knowing which one applies: an invite
  always provisions a FRESH key, so a key made up front is left stranded, unfunded.
  After either path: add users, set policies, send assets, or enroll a gateway passkey.

THERE IS NO DEFAULT ACCOUNT. Anything that signs must be told which account to act
as. With exactly one key that is automatic; with several, the tool REFUSES and you
must ASK THE USER which account they mean — never pick for them. wallet_accounts
lists the choices. Their answer goes in the "account" parameter on each call.

FEE PRIORITY IS THE USER'S CHOICE TOO. A transfer is bid low, medium or high; if the
user did not say (and set no standing default), wallet_tx_create_transaction REFUSES
and hands back the three options with their target confirmation times — ask them,
never default to medium. wallet_tx_check returns the same menu up front. It quotes no
cost on purpose: the real fee is only known once the signer builds the transaction.

WHENEVER the user asks "what can I do?", "what's next?", "help", "how do I start?",
or seems unsure — call wallet_getting_started FIRST. It inspects live state, reports
exactly which of the steps above they're on, and returns the precise next action.
Prefer it over guessing. Reads are free; signing lazily brings up the secure session.`;

// ─── Tool surface ───────────────────────────────────────────────────────────
// Full skill surface (32 tools) MINUS wallet_session_start (lazy) and
// wallet_hmac_rotate (automatic); KEEP read-only wallet_session_status; ADD B2's
// wallet_snapshot (index-only), wallet_snapshot_query, wallet_snapshot_page.
// wallet_snapshot is redefined: it returns the small index, NEVER raw JSON.

// Which account this call acts as — the ONE name for that idea across the whole
// tool surface (signing tools, gateway tools, wallet_assets).
//
// There is NO default key: omitting this is only valid when the machine holds
// exactly one key. With several, the call fails with the account list rather
// than guessing — picking for the user is what used to sign the wrong key after
// a key creation or recovery.
//
// It was called `signingKey` until 2026-08-10. Two names for one concept made
// the model choose between them, and the word was wrong twice over: the value
// may be an account NAME rather than a key, and on the paths with no
// --creator/--pubkey flags (notification configure, keys sign-challenge, query
// assets) nothing key-shaped is passed at all — the account is injected as
// identity. The dispatcher still accepts `signingKey` as an undeclared fallback;
// see the note there.
const ACCOUNT_PROP = {
  type: 'string',
  description:
    'The account to act as — an omnistar1… key address or an account name (e.g. alice@acme). Omit ONLY when this machine has exactly one key; if it has several, the call fails and you must ASK THE USER which account they mean, then pass their choice. There is no default or remembered account. Call wallet_accounts to list them.',
} as const;

const tools = [
  // ── Orientation (Layer B) ──
  {
    name: 'wallet_getting_started',
    description:
      "START HERE. Read-only onboarding guide that answers \"what can I do next?\" / \"help\" / \"how do I start?\". Inspects live state (every local key, its funding and safes) and classifies EACH ACCOUNT separately — stages are no-key → unfunded → no-safe → recovery-pending → ready. Returns { stage, summary, keyCount, accounts[], next[], capabilities?[], version?, restartRequired? }, where each accounts[] entry carries its own stage and next steps. At stage no-key it returns the TWO ways to start — self-funded (create a key, buy OST at https://store.wikey.io/) or sponsored (redeem an invitation link, which does everything in one call) — as a question to put to the user, NOT a default to pick: the sponsored path mints its own key, so creating one first strands it. If `restartRequired` is set, relay it before anything else — the package was upgraded while the client stayed up, so this process is serving the OLD build until the user fully restarts their AI client. The top-level `stage` is that account's stage when there is exactly one key, and `multiple-accounts` when there are several: with no default key there is no single answer, and a ready account must not mask another one's unfinished recovery — read accounts[] in that case. Call this before guiding a new or unsure user. Never signs, never brings up the secure session.",
    inputSchema: { type: 'object', properties: {} },
  },
  // ── Query tools ──
  {
    name: 'wallet_chain_info',
    description: 'Get Omnistar chain ID and latest block height.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'wallet_balance',
    description:
      'Get the OST balance held DIRECTLY by one address — the gas/funding check. Takes an omnistar1… address or an account name (a name is resolved to its account address, which is the key address gas is paid from). This is not a portfolio read: it reports one address\'s own OST, so a safe holding cross-chain assets can answer 0 here. For everything an account\'s safes hold, use wallet_assets.',
    inputSchema: {
      type: 'object',
      properties: {
        address: {
          type: 'string',
          description: 'omnistar1… address, OR an account name (e.g. alice@acme) to resolve.',
        },
      },
      required: ['address'],
    },
  },
  {
    name: 'wallet_balances',
    description:
      'Get every coin balance for one address (wallet_balance returns only OST). Takes an omnistar1… address or an account name to resolve.',
    inputSchema: {
      type: 'object',
      properties: {
        address: {
          type: 'string',
          description: 'omnistar1… address, OR an account name (e.g. alice@acme) to resolve.',
        },
      },
      required: ['address'],
    },
  },
  {
    name: 'wallet_account',
    description:
      'Get account number and sequence for an address. Takes an omnistar1… address or an account name to resolve.',
    inputSchema: {
      type: 'object',
      properties: {
        address: {
          type: 'string',
          description: 'omnistar1… address, OR an account name (e.g. alice@acme) to resolve.',
        },
      },
      required: ['address'],
    },
  },
  {
    name: 'wallet_snapshot',
    description:
      "Take a snapshot of the profile's safes and return a SMALL INDEX only: { snapshotId, address, bytes, ts, safes:[{address,name,counts}], fields:{class:[key...]}, siblings:[key...] }. The fields map lists which object payload keys each class carries (e.g. policy: conditions, applyOn) — use it to know what you can request, without guessing. `siblings` lists the node-level keys (process, name, isValid) requestable via `fields` IN ADDITION to the payload keys — `process` carries the governance state and is not in the fields map. On a name clash the payload key wins (a policy's own `name` shadows the sibling). The raw snapshot JSON is NEVER returned (it can exceed a host's tool-result limit and be silently truncated). Use the returned snapshotId with wallet_snapshot_query (enumerate/filter rows), wallet_snapshot_object (ONE object in full — governance state, conditions), or wallet_snapshot_page. Resolves SIGNATURE + parentGroup for delete-user / delete-policy. When address is omitted, uses the configured profile.",
    inputSchema: {
      type: 'object',
      properties: {
        address: {
          type: 'string',
          description:
            'omnistar1... profile address (optional, uses config default). NOT a safe address — find the target safe inside the returned safes[] list.',
        },
      },
    },
  },
  {
    name: 'wallet_snapshot_query',
    description:
      "Query rows from a cached snapshot (by snapshotId from wallet_snapshot). By DEFAULT each row is a summary projection (safe, group, groupName, class, id, isDeleted, parentGroup, SIGNATURE) — NOT the full object. Request payload keys with fields:[...] or fields:'*' (returned nested under object:, dropped keys named in omittedFields), or use wallet_snapshot_object for one object in full. Byte-budgeted: a broad match returns the rows that fit PLUS {truncated:true,total,returned,nextOffset} so you page explicitly — never a silent cut. A point lookup ({id}) returns all matching rows (complete in row count) and is the path for delete-user/delete-policy resolution. Rule of thumb: _query to enumerate, _object for depth.",
    inputSchema: {
      type: 'object',
      properties: {
        snapshotId: { type: 'string', description: 'snapshotId from wallet_snapshot' },
        filter: {
          type: 'object',
          properties: {
            safe: { type: 'string', description: 'Safe address (omnistar1...)' },
            class: {
              type: 'string',
              description: "Object class: user, policy, group, transaction, vote, profile, execution",
            },
            id: { type: 'string', description: 'Exact object id (point lookup — all matching rows returned)' },
            isDeleted: { type: 'boolean', description: 'Filter by soft-deleted flag' },
            parentGroup: { type: 'string', description: 'Parent group id (e.g. Primary)' },
          },
        },
        fields: {
          description:
            "Optional object payload keys to include per row (nested under object:), or '*' for all. See the fields map in the wallet_snapshot index for what each class carries. Wide rows shrink the row count per response.",
          oneOf: [{ type: 'array', items: { type: 'string' } }, { type: 'string', enum: ['*'] }],
        },
      },
      required: ['snapshotId'],
    },
  },
  {
    name: 'wallet_snapshot_page',
    description:
      "Explicit pagination over a (safe, class) in a cached snapshot. Returns { rows, offset, limit, returned, total, truncated }. Supports fields:[...]|'*' like wallet_snapshot_query; byte-budgeted, so with wide rows `returned` may be fewer than limit — continue from offset+returned. Use after wallet_snapshot_query reports truncated:true for a large class.",
    inputSchema: {
      type: 'object',
      properties: {
        snapshotId: { type: 'string', description: 'snapshotId from wallet_snapshot' },
        safe: { type: 'string', description: 'Safe address (omnistar1...)' },
        class: { type: 'string', description: 'Object class to page through' },
        offset: { type: 'number', description: 'Row offset (0-based)' },
        limit: { type: 'number', description: 'Max rows to return' },
        fields: {
          description:
            "Optional object payload keys to include per row (nested under object:), or '*' for all. Byte-budgeted: returned may be fewer rows than limit.",
          oneOf: [{ type: 'array', items: { type: 'string' } }, { type: 'string', enum: ['*'] }],
        },
      },
      required: ['snapshotId', 'safe', 'class', 'offset', 'limit'],
    },
  },
  {
    name: 'wallet_snapshot_object',
    description:
      "Read ONE object from a cached snapshot COMPLETELY: the full object payload (e.g. policy conditions/applyOn, user public_key, transaction amount) plus name, isValid and process (process.currentPhase = governance state: approved vs pending votes). Use the index fields map from wallet_snapshot to discover which fields a class carries. Byte-budgeted: if the object is too large, the largest fields are dropped and NAMED in omittedFields:[{key,bytes}] — never a silent cut. IF A FIELD YOU NEED IS IN omittedFields, CALL AGAIN WITH fields:['<key>'] — a whole object may not fit the budget but one field almost always does; asking for less is how you get it. Repeating the same full read returns the same trimmed result. On a multi-safe profile pass `safe`: ids like policy-genesis exist in several safes with DIFFERENT payloads, and without it you get the first match.",
    inputSchema: {
      type: 'object',
      properties: {
        snapshotId: { type: 'string', description: 'snapshotId from wallet_snapshot' },
        id: { type: 'string', description: 'Exact object id (from wallet_snapshot_query rows)' },
        safe: { type: 'string', description: 'Optional safe address (omnistar1...) to narrow the lookup' },
        fields: {
          description:
            "Narrow the read to these keys — payload keys and/or the siblings process/name/isValid. Omit for the whole object; use this to recover a field listed in omittedFields (e.g. fields:['process']). '*' means the whole payload but NOT the siblings, which must be named.",
          oneOf: [
            { type: 'array', items: { type: 'string' } },
            { type: 'string', enum: ['*'] },
          ],
        },
      },
      required: ['snapshotId', 'id'],
    },
  },
  {
    name: 'wallet_profile',
    description: 'Get on-chain profile (pubkey, policies, linked safes). Uses config address when omitted.',
    inputSchema: {
      type: 'object',
      properties: { address: { type: 'string', description: 'omnistar1... address (optional, uses config default)' } },
    },
  },
  {
    name: 'wallet_assets',
    description:
      "Get the full asset portfolio of an account's safes (OST + cross-chain assets with smallCoin). smallCoin is the divisor for converting display amounts to smallest units for wallet_tx_create_transaction. `account` is the KEY/profile address (or account name) that owns the safes — NOT a safe address; the response lists each safe separately. Omit it only when this machine holds exactly one key; with several, ask the user which account and pass it (wallet_accounts lists them).",
    inputSchema: {
      type: 'object',
      properties: {
        account: {
          type: 'string',
          description:
            'omnistar1... key address OR account name (e.g. alice@acme) whose safes to read. Optional when there is exactly one key.',
        },
      },
    },
  },
  // ── Account tools ──
  {
    name: 'wallet_accounts',
    description:
      "List every signing key on this machine with what the chain says about it: { address, name?, funded?, safes[] }. This is the answer to \"which account should I use?\" — call it whenever a tool reports that several keys exist and none was named, then ASK THE USER which one and pass their choice. `name` is the on-chain account name (e.g. alice@acme) and is absent for a key that has no account yet; `safes` is empty until create-safe lands. There is no default or 'current' account — the choice is made per call. Read-only: counts keys from the keystore directory, never brings up the secure session.",
    inputSchema: { type: 'object', properties: {} },
  },
  // ── Key tools ──
  {
    name: 'wallet_keys_list',
    description: 'List all key IDs in the signing-server.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'wallet_keys_get',
    description: 'Get details for a specific key ID.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string', description: 'Key ID' } },
      required: ['id'],
    },
  },
  {
    name: 'wallet_keys_create',
    description:
      'Generate a new keypair in the signing-server. Returns { result, fundingUrl, next }: `result` carries the new omnistar1... address, which is what you pass as `account` to act as it, and `fundingUrl` is the Wikey store link with that address ALREADY prefilled — RELAY IT TO THE USER VERBATIM rather than telling them to visit the store and paste the address, which is the one step of self-funding a human can get unrecoverably wrong. A new key holds no gas and can broadcast nothing until it is funded. Creating a key changes NOTHING about existing accounts — there is no default to displace — but it does mean the machine now holds more than one key, so subsequent signing calls will ask which account to use. Do NOT call this first when the user has a sponsor invitation link: wallet_onboard_sponsor mints its own key and the one made here would be stranded, unfunded. This is a signing operation: it lazily brings up the secure SSP session on first use.',
    inputSchema: { type: 'object', properties: {} },
  },
  // ── Config tools ──
  {
    name: 'wallet_config_show',
    description: 'Show the full wallet-cli configuration (read-only).',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'wallet_config_get',
    description: 'Get a single config value by dot-path key (read-only, e.g. user.address).',
    inputSchema: {
      type: 'object',
      properties: { key: { type: 'string', description: 'Config key (e.g. user.address, apiKey)' } },
      required: ['key'],
    },
  },
  {
    name: 'wallet_config_set',
    description:
      'Set a config value by dot-path key. Security-critical keys are LOCKED and rejected by default: signer.* (signer.url is pinned to loopback), *.url, apiKey, kek*, keystore*, user.*. Reads (wallet_config_get/show) are always allowed. The operator can bypass the lock by setting the WIKEY_UNLOCK_CONFIG=1 environment variable (not agent-controllable), allowing any key to be set.',
    inputSchema: {
      type: 'object',
      properties: {
        key: { type: 'string', description: 'Config key (locked keys are rejected)' },
        value: { type: 'string', description: 'Value to set' },
      },
      required: ['key', 'value'],
    },
  },
  {
    name: 'wallet_config_init',
    description: 'Initialize wallet-cli configuration with defaults.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'wallet_config_reset',
    description: 'Reset wallet-cli configuration to defaults.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'wallet_config_path',
    description: 'Show the path to the wallet-cli config file.',
    inputSchema: { type: 'object', properties: {} },
  },
  // ── Session tools ──
  {
    name: 'wallet_session_status',
    description:
      'Check the secure SSP session state. Returns { active, pid, wedged, lastRotation, state, kekProvider, kekFallback, wedgedReason, lastChildExit } — never any key material. kekProvider is the keys-at-rest provider the live signer came up with (auto=hardware, env=software); kekFallback is true when software was reached because no hardware enclave was found. When wedged, wedgedReason gives a short redacted cause; lastChildExit ({code, signal, ts, output}) holds the diagnostics from the last unexpected signing-server exit (redacted tail) — read these to explain WHY it wedged. The session starts automatically on the first signing call and the HMAC key auto-rotates; there is no manual start or rotate. If wedged, call wallet_session_recover.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'wallet_session_recover',
    description:
      'Recover a wedged SSP session in place — call this when wallet_session_status reports wedged:true (or a signing tool fails with "session is wedged"). It cold-restarts the session inside the running server (zeroize old key, kill the dead signer child, fresh nonce + new key + fresh spawn) WITHOUT restarting the MCP server itself. Returns the post-recovery session status; if the underlying cause persists, it throws the real spawn diagnostic instead. Safe to call when not wedged (no-op resync). Never exposes key material.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  // ── Signing tools ──
  {
    name: 'wallet_tx_create_safe',
    description: 'Create a safe + profile on-chain with a username. Takes ~30s to validate after broadcast.',
    inputSchema: {
      type: 'object',
      properties: {
        username: {
          type: 'string',
          description: 'Safe username (letters, numbers, dots only; no leading/trailing/consecutive dots)',
        },
        account: ACCOUNT_PROP,
      },
      required: ['username'],
    },
  },
  {
    name: 'wallet_onboard_sponsor',
    description:
      'Redeem an invitation link — the COMPLETE sponsored onboarding in one call. Use this whenever a user hands you an invitation/signup link and asks to redeem or use it, EXCEPT when the link carries enroll=only: that is an enroll-only invitation for someone who already has a wallet account, and it needs wallet_gateway_register instead (this tool refuses it without side effects). It (1) creates a signing key, (2) funds it from the sponsor grant behind the invite code (the invitee never funds anything), (3) creates their account + safe under the invite\'s username@organization handle, and (4) enrolls the wallet passkey to the gateway with the same code. Takes a few minutes for EITHER variant: the safe needs time to become queryable on-chain, and this tool waits for that before returning so its answer agrees with wallet_getting_started. Some invitations carry enroll=false — the fund-and-create-only variant: steps 1-3 run and step 4 is intentionally skipped (a passkey can be bound later with wallet_gateway_register). Stage "funded-created-enrolled" = fully done; "funded-created" = no-enroll invite, account ready on-chain, enrollment skipped by design; if either success stage comes back with a warning that the safe is not queryable yet, onboarding still SUCCEEDED — never call wallet_tx_create_safe to "fix" it (that would create a second safe on the funded key), just re-check in a few minutes; "created-enroll-failed" = on-chain work done, retry only wallet_gateway_register; "recovery-required" = the invite already onboarded an account. Safe to re-run with the same link: it RESUMES an interrupted onboarding on the already-funded key instead of creating a second identity.',
    inputSchema: {
      type: 'object',
      properties: {
        invite: {
          type: 'string',
          description:
            'The full invitation link, e.g. https://gateway.wikey.io/signup/{app}?invitationCode=…&username=kehat@wikey',
        },
      },
      required: ['invite'],
    },
  },
  {
    name: 'wallet_tx_send',
    description:
      "Send OST directly between key addresses (not safe funds). Use for gas funding. The gas for this transaction is paid in the OST being sent, so the sender's full balance is never sendable — this tool refuses a send that would drain the address.",
    inputSchema: {
      type: 'object',
      properties: {
        from: { type: 'string', description: 'Sender omnistar1... address' },
        to: { type: 'string', description: 'Recipient omnistar1... address' },
        amount: { type: 'string', description: 'Amount with denom (e.g. 1000nost). Never the sender\'s whole balance — gas comes out of it.' },
        acknowledgeRisk: {
          type: 'boolean',
          description: "Force a send flagged 'at-risk' (too little left for gas). Does not override a drain, which cannot settle.",
        },
      },
      required: ['from', 'to', 'amount'],
    },
  },
  {
    name: 'wallet_tx_check',
    description:
      "Will this transfer succeed? Read-only pre-flight for wallet_tx_create_transaction — call it BEFORE sending, and ALWAYS when the user says \"all\", \"everything\", \"the whole balance\", or \"max\". Returns { verdict, reason, balance, requested, remaining, maxSuggested, feeChoice }. feeChoice is the low/medium/high menu for this chain with a target confirmation time for each — PUT IT TO THE USER and pass their answer as feePriority; it quotes no cost on purpose (the real fee is only known when the signer builds the transaction, so any number here would be invented). verdict is 'will-fail' (structural — proven from balances, e.g. the amount exceeds the balance, it drains a fee-bearing asset to zero, or a token has no native gas coin to pay with), 'at-risk' (too little left over to cover a fee), or 'likely-pass'. USE maxSuggested AS THE AMOUNT for a send-everything request: the network fee is deducted from the same balance, so the full balance is never sendable and maxSuggested is the largest amount that clears. It is deliberately conservative, not an exact fee — the real fee is computed by the signing engine and is not visible here. Never signs, never brings up the secure session.",
    inputSchema: {
      type: 'object',
      properties: {
        destination: {
          type: 'string',
          description:
            "The safe the assets leave FROM — an omnistar1… address or a safe NAME (e.g. wikeyMCP_safe). Omit it and, if the account holds exactly one safe, that one is used; with several the call reports a menu to put to the user. Passing an address costs no extra lookup.",
        },
        asset: { type: 'string', description: 'Asset symbol (e.g. BTC, USDC, OST)' },
        amount: {
          type: ['number', 'string'],
          description:
            'Amount in SMALLEST units (display value × smallCoin). Pass a STRING for large values — wei-scale amounts lose precision as a JSON number. Omit to just ask for maxSuggested.',
        },
        toName: {
          type: 'string',
          description:
            "Recipient ACCOUNT NAME (e.g. op20). Pass the SAME toName/toSafe/to you will pass to wallet_tx_create_transaction, so the check and the send run off one recipient. Adds `recipient` to the result.",
        },
        toSafe: { type: 'string', description: "Which of the recipient's safes (address or safe name), when they have several." },
        to: { type: 'string', description: 'A LITERAL recipient address, instead of toName — checked for chain-family mismatch too.' },
        tokenAddress: { type: 'string', description: 'ERC20 contract address (0x + 40 hex) — with `chain`, for an ERC20' },
        chain: { type: 'string', enum: ['ethereum', 'polygon', 'base'], description: 'ERC20 chain — with `tokenAddress`' },
        account: ACCOUNT_PROP,
      },
      required: ['asset'],
    },
  },
  {
    name: 'wallet_tx_create_transaction',
    description:
      "Move assets out of a safe. Use this (not wallet_tx_send) when the safe holds the funds. amount must be in SMALLEST units (display value × smallCoin from wallet_assets). THE NETWORK FEE IS DEDUCTED FROM THE SAME BALANCE, so the full balance is NEVER sendable — a request to send \"all\" or \"everything\" must use maxSuggested from wallet_tx_check, not the raw balance from wallet_assets. This tool runs that check itself and REFUSES a transfer it can prove will fail; a borderline one is refused too and can be forced with acknowledgeRisk. It also refuses when feePriority is missing and the user has no saved default — fee priority is the user's call, and the refusal carries the options to ask them with.",
    inputSchema: {
      type: 'object',
      properties: {
        destination: {
          type: 'string',
          description:
            "The safe the funds leave FROM — an omnistar1… address or a safe NAME (e.g. wikeyMCP_safe). Omit it and, with exactly one safe, that one is used; with several the call REFUSES with a menu to put to the user, because a wrong source is only caught when the wrong safe happens not to hold the asset. Passing an address costs no extra lookup.",
        },
        toName: {
          type: 'string',
          description:
            "The recipient's ACCOUNT NAME (e.g. op20) — the preferred way to address a Wikey recipient. Pass it EXACTLY as the user said it: never expand, complete or correct a partial name yourself. A handle is name@organization, the bare \"alice\" does NOT resolve to \"alice@acme\", and the call REFUSES with candidate names to put to the user — completing it silently sends real funds to an account they never named. The server resolves the name to the right chain-native address for this asset, and also REFUSES if the recipient has several safes and `toSafe` did not say which. Mutually exclusive with `to`.",
        },
        toSafe: {
          type: 'string',
          description:
            "Which of the recipient's safes to pay, as an address or a safe name. Pass the USER's answer when a call refused with a safe menu — never pick for them.",
        },
        to: {
          type: 'string',
          description:
            "A LITERAL recipient address, for a recipient OUTSIDE Wikey (an exchange deposit address, say). Mutually exclusive with `toName`. This must be the CHAIN-NATIVE address for the asset — an omnistar1… safe address is only correct for OST, and sending anything else there loses the funds.",
        },
        amount: { type: 'number', description: 'Amount in smallest units (display value × smallCoin). Never the full balance of a fee-bearing asset — see wallet_tx_check.' },
        asset: { type: 'string', description: 'Asset symbol (e.g. BTC, USDC, OST)' },
        feePriority: {
          type: 'string',
          enum: ['low', 'medium', 'high'],
          description:
            "The USER's choice of fee priority, not yours. Omit it unless they said which they want (or implied it — \"urgent\", \"cheap\", \"no rush\"); the call then REFUSES and hands back the three options with their target confirmation times, which you put to the user. Never default it to medium to avoid asking. wallet_tx_check returns the same menu in `feeChoice` before you get here.",
        },
        tokenAddress: { type: 'string', description: 'ERC20 contract address (0x + 40 hex) — required for ERC20 assets' },
        chain: { type: 'string', enum: ['ethereum', 'polygon', 'base'], description: 'ERC20 chain — required for ERC20 assets' },
        smallCoin: { type: 'number', description: 'ERC20 token divisor — required for ERC20 assets' },
        acknowledgeRisk: {
          type: 'boolean',
          description:
            "Force a transfer wallet_tx_check rated 'at-risk' (too little left over to cover the fee). Only set this after telling the user it may fail and getting their go-ahead. It does NOT override a 'will-fail' verdict — those are structural and cannot settle at any fee.",
        },
        account: ACCOUNT_PROP,
      },
      // feePriority is deliberately NOT required: a required parameter does not
      // produce a question, it produces a guess. The handler refuses instead and
      // returns the menu — see core/feeChoice.ts.
      // Neither `to` nor `destination` is required. A schema cannot express
      // "exactly one of to/toName", and a required `destination` does not
      // produce a question — it produces a guess at which safe pays. The
      // handler refuses with the menu instead. Same reasoning as feePriority.
      required: ['amount', 'asset'],
    },
  },
  {
    name: 'wallet_tx_vote',
    description:
      'Vote on an on-chain object. signature is the Omnistar tx hash (the SIGNATURE field from wallet_snapshot_query / wallet_profile).',
    inputSchema: {
      type: 'object',
      properties: {
        destination: { type: 'string', description: 'Safe address (omnistar1...)' },
        vote: { type: 'string', enum: ['YES', 'NO'] },
        signature: { type: 'string', description: 'Omnistar tx hash of the object being voted on' },
        account: ACCOUNT_PROP,
      },
      required: ['destination', 'vote', 'signature'],
    },
  },
  {
    name: 'wallet_tx_request_recovery',
    description:
      'Request account recovery for an existing username (for a user who lost their key). Signs with the NEW key and references the original account by username (wallet-cli requires --username). Pass `username` directly, or pass `oldAddress` and the server resolves the username via query profile. Exactly one of the two is required. Returns { tx, recoveryDeeplink, shareWithHelpers }: forward `recoveryDeeplink` (https://open.wikey.io/accountRecover?t=recover&pk=<newAddress>&tn=<accountName>) to a recovery helper — they open it in the Wikey wallet app, or hand it to their own agent which passes it to wallet_tx_approve_recovery.',
    inputSchema: {
      type: 'object',
      properties: {
        username: { type: 'string', description: 'Original account username being recovered' },
        oldAddress: {
          type: 'string',
          description: 'omnistar1... address of the account being recovered; the server resolves the username via query profile',
        },
        account: ACCOUNT_PROP,
      },
      required: [],
    },
  },
  {
    name: 'wallet_tx_approve_recovery',
    description:
      "Approve a recovery request as a helper. If a friend sent you a recovery deeplink (https://open.wikey.io/accountRecover?t=recover&pk=<newAddress>&tn=<accountName>), just pass it as `deeplink` — it maps to oldaccount=tn (the account being recovered) and newaccount=pk (their new address). Otherwise pass `oldaccount` and `newaccount` explicitly. Explicit values win over the deeplink.",
    inputSchema: {
      type: 'object',
      properties: {
        deeplink: {
          type: 'string',
          description:
            'Recovery deeplink the requester forwarded (https://open.wikey.io/accountRecover?t=recover&pk=<newAddress>&tn=<accountName>). Supplies oldaccount/newaccount when they are not passed explicitly.',
        },
        oldaccount: { type: 'string', description: 'Original account username being recovered (tn). Optional if `deeplink` is given.' },
        newaccount: { type: 'string', description: 'New omnistar1... address replacing the old one (pk). Optional if `deeplink` is given.' },
        account: ACCOUNT_PROP,
      },
      required: [],
    },
  },
  {
    name: 'wallet_tx_create_policy',
    description:
      'Create a policy on a safe. Valid applyOn values: group, user, transaction, policy, profile (comma-separated for multiple). MIXING RULE: amount and symbols conditions ONLY available when applyOn is exactly "transaction" (single value) — any other value or mix → voting only. Never pass name/description as CLI flags — always supply via the name/description fields. Name/description prompts always appear (empty string allowed).',
    inputSchema: {
      type: 'object',
      properties: {
        destination: { type: 'string', description: 'Safe address (omnistar1...)' },
        applyOn: {
          type: 'string',
          description: 'Comma-separated apply-on classes. Valid: group, user, transaction, policy, profile. Mix rule: amount/symbols only when value is exactly "transaction" alone.',
        },
        conditions: {
          type: 'array',
          description: 'Policy conditions to enable',
          items: {
            type: 'object',
            properties: {
              type: { type: 'string', enum: ['voting', 'amount', 'symbols'] },
              votingQty: { type: 'number', description: 'Voting threshold percentage (0-100), for type=voting' },
              minAmount: { type: 'number', description: 'Minimum amount, for type=amount. Only when applyOn is exactly "transaction".' },
              maxAmount: { type: 'number', description: 'Maximum amount, for type=amount. Only when applyOn is exactly "transaction".' },
              symbols: { type: 'array', items: { type: 'string' }, description: 'Allowed symbols, for type=symbols. Only when applyOn is exactly "transaction".' },
            },
            required: ['type'],
          },
        },
        name: { type: 'string', description: 'Policy name (optional)' },
        description: { type: 'string', description: 'Policy description (optional)' },
        account: ACCOUNT_PROP,
      },
      required: ['destination', 'applyOn', 'conditions'],
    },
  },
  {
    name: 'wallet_tx_edit_policy',
    description:
      'Edit an existing policy on a safe. Same applyOn and conditions rules as wallet_tx_create_policy. MIXING RULE: amount and symbols only when applyOn is exactly "transaction". policyId and signature come from wallet_profile / wallet_snapshot_query output (find policy by id, read its SIGNATURE field).',
    inputSchema: {
      type: 'object',
      properties: {
        destination: { type: 'string', description: 'Safe address (omnistar1...)' },
        policyId: { type: 'string', description: 'Policy ID (from wallet_profile / wallet_snapshot_query output)' },
        signature: { type: 'string', description: 'On-chain SIGNATURE of the policy' },
        applyOn: { type: 'string', description: 'Comma-separated apply-on classes. Valid: group, user, transaction, policy, profile.' },
        conditions: {
          type: 'array',
          description: 'Policy conditions to enable',
          items: {
            type: 'object',
            properties: {
              type: { type: 'string', enum: ['voting', 'amount', 'symbols'] },
              votingQty: { type: 'number', description: 'Voting threshold percentage (0-100), for type=voting' },
              minAmount: { type: 'number', description: 'Minimum amount, for type=amount. Only when applyOn is exactly "transaction".' },
              maxAmount: { type: 'number', description: 'Maximum amount, for type=amount. Only when applyOn is exactly "transaction".' },
              symbols: { type: 'array', items: { type: 'string' }, description: 'Allowed symbols, for type=symbols. Only when applyOn is exactly "transaction".' },
            },
            required: ['type'],
          },
        },
        name: { type: 'string', description: 'Policy name (optional, for non-transaction-only applyOn)' },
        description: { type: 'string', description: 'Policy description (optional, for non-transaction-only applyOn)' },
        account: ACCOUNT_PROP,
      },
      required: ['destination', 'policyId', 'signature', 'applyOn', 'conditions'],
    },
  },
  {
    name: 'wallet_tx_delete_policy',
    description:
      "Soft-delete a policy from a safe. Data remains on-chain. policyId is the policy-object id from wallet_snapshot_query (filter {class:'policy'}). The server resolves --signature and --parent-group from the snapshot. SUCCESSFUL BROADCAST IS NOT A COMPLETED DELETION — it is vote-governed; re-query wallet_snapshot_query and check the target's isDeleted flag.",
    inputSchema: {
      type: 'object',
      properties: {
        destination: { type: 'string', description: 'Safe address (omnistar1...)' },
        policyId: { type: 'string', description: "Policy-object id from wallet_snapshot_query (class === 'policy')." },
        account: ACCOUNT_PROP,
      },
      required: ['destination', 'policyId'],
    },
  },
  {
    name: 'wallet_tx_create_user',
    description:
      'Add a user to a SAFE\'s group. `destination` MUST be a safe address — users are added to a safe\'s groups, NEVER to a profile\'s groups. `user` MUST be an `omnistar1…` address — usernames are not accepted. `group` is OPTIONAL and MUST be a group ID (literal `Primary` or a UUID), NEVER a group name. If omitted and the safe has exactly one group, the server uses it; if ambiguous, it errors with the valid id (name) pairs.',
    inputSchema: {
      type: 'object',
      properties: {
        destination: { type: 'string', description: "SAFE address (omnistar1...). NEVER the agent's own profile address." },
        user: { type: 'string', description: 'omnistar1... address of the new user (not a username).' },
        group: { type: 'string', description: 'Group ID — literal `Primary` or a UUID. NEVER a group name. Required only if safe has >1 group.' },
        account: ACCOUNT_PROP,
      },
      required: ['destination', 'user'],
    },
  },
  {
    name: 'wallet_tx_delete_user',
    description:
      "Remove a user from a SAFE's group. `destination` MUST be a safe address. `userId` is the user-object id from wallet_snapshot_query (filter {class:'user'}) — NOT an address. The server resolves --signature and --parent-group from the snapshot. SUCCESSFUL BROADCAST IS NOT A COMPLETED DELETION — it is vote-governed; re-query and check isDeleted.",
    inputSchema: {
      type: 'object',
      properties: {
        destination: { type: 'string', description: 'SAFE address (omnistar1...). Users live in safe groups, not profile groups.' },
        userId: { type: 'string', description: "User-object id from wallet_snapshot_query (class === 'user'). Not an address." },
        account: ACCOUNT_PROP,
      },
      required: ['destination', 'userId'],
    },
  },
  {
    name: 'wallet_recovery_helpers',
    description:
      "AUTHORITATIVE list of the account's recovery helpers — call this to answer \"who are the helpers / who can approve a recovery?\" instead of reading it off wallet_profile yourself. Helpers are exactly the `allowed_source` of the policy-allow-updateUserAddress policy, and EVERY entry counts (including any address Wikey added as a default recovery path). Returns { helpers:[{address,name}], count, threshold:{percentage, requiredCount, totalHelpers} }. The on-chain threshold is a PERCENTAGE of the total helper count, so `requiredCount` is the decoded number of approvals needed. Read-only; call it BEFORE wallet_tx_edit_helpers so you know the current helpers and how adding/removing rescales the threshold. `address` accepts an account NAME (e.g. alice@acme) as well as an omnistar1… address — use the name when recovering a LOST key, where the account's address is exactly what the user no longer has. An unknown name/address is an ERROR, never an empty helper list.",
    inputSchema: {
      type: 'object',
      properties: {
        address: {
          type: 'string',
          description:
            'omnistar1... address OR account name (e.g. alice@acme, or a bare handle like createTest1). Optional; uses config default. Pass the NAME when the account\'s key was lost.',
        },
        account: ACCOUNT_PROP,
      },
    },
  },
  {
    name: 'wallet_resolve_name',
    description:
      "Resolve an on-chain account NAME (alice@acme, or a bare handle like createTest1) to its omnistar1… address, and thereby confirm the account EXISTS. READ-ONLY and signing-free: it drives wallet-cli's own username resolver and aborts before any transaction is built — nothing is signed, nothing is broadcast, the secure session is never woken. Use it BEFORE naming an account as a recovery helper, and to turn a name into the address that wallet_profile / wallet_balance / wallet_snapshot require (those accept an ADDRESS ONLY). An unknown name is an ERROR, never an empty answer. An address passed in comes back unchanged. `account` picks which local account to act as; it must have an on-chain profile.",
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Account name to resolve (e.g. alice@acme or createTest1).',
        },
        account: ACCOUNT_PROP,
      },
      required: ['name'],
    },
  },
  {
    name: 'wallet_resolve_recipient',
    description:
      "Where do I SEND to, for an account NAME? Turns \"transfer 2 BTC to op20\" into the chain-native address `wallet_tx_create_transaction` needs, by walking name → account → safe → that safe's receive address for the asset. READ-ONLY and signing-free: nothing is built, signed or broadcast, and the secure session is never woken. USE THIS, NOT wallet_resolve_name, when the goal is to PAY someone: wallet_resolve_name stops at the account's omnistar1… address, and passing THAT as `to` sends the funds to a wrong-chain address that cannot be recovered — it only happens to work for OST, whose receive address genuinely is the safe's own address. Returns { name, accountAddress, safe:{address,name,nameMatchesAccount}, asset, to, symbolUsed, addressFamily, safeCount, echo } when the answer is unambiguous — relay `echo` to the user before sending. When the account is in SEVERAL safes it returns needsChoice:true with `message` (a ready-to-relay menu) and `safes[]`: ASK THE USER which safe and pass their answer as `safe` — do not pick for them. A safe list is the safes an account PARTICIPATES in, not the ones it owns; the only signal is that <name>_safe is the account's own, which the menu labels. Omit `asset` to see every safe with everything it can receive. For an ERC20, pass `tokenAddress` + `chain`: a token has no receive row of its own and lands at the chain's native-coin address.",
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description:
            'The recipient ACCOUNT name (e.g. op20, or alice@acme), EXACTLY as the user gave it — never a completed or corrected version of it. A handle is name@organization and the bare "alice" does NOT resolve to "alice@acme"; when it misses, the call returns candidate names for you to ASK the user about, and picking one yourself pays an account they never named. An omnistar1… account address is also accepted, but then the <name>_safe convention cannot be checked, so the menu can say less. NOT a safe name — the safe of account X is X_safe; name the owner.',
        },
        asset: {
          type: 'string',
          description: 'Asset symbol being sent (e.g. BTC, OST, USDC). Omit to list every safe with everything it can receive.',
        },
        safe: {
          type: 'string',
          description: "Which of the recipient's safes, as an address or a safe name. Pass the USER's answer to a needsChoice menu here.",
        },
        tokenAddress: { type: 'string', description: 'ERC20 contract address (0x + 40 hex) — for an ERC20, with `chain`' },
        chain: { type: 'string', enum: ['ethereum', 'polygon', 'base'], description: 'ERC20 chain — for an ERC20, with `tokenAddress`' },
        account: ACCOUNT_PROP,
      },
      required: ['name'],
    },
  },
  {
    name: 'wallet_tx_edit_helpers',
    description:
      'Add/remove recovery helpers and set threshold. Helpers have no safe permissions — recovery only. Helpers are the `allowed_source` of policy-allow-updateUserAddress; call wallet_recovery_helpers FIRST to see the CURRENT helpers (existing/Wikey-added entries already count) before choosing a threshold. `threshold` is passed as an integer COUNT of helpers required, but is stored on-chain as a PERCENTAGE of the total, so adding/removing helpers rescales it (e.g. 1 of 2 helpers = 50%). `addHelpers` takes an account NAME as readily as an address — wallet-cli resolves it server-side, so do NOT hunt for the address first. An unresolvable name aborts the command BEFORE anything is built, signed or broadcast, so a failed add costs nothing on-chain; use wallet_resolve_name first only when you want to confirm the account exists without running a tx at all.',
    inputSchema: {
      type: 'object',
      properties: {
        addHelpers: { type: 'array', items: { type: 'string' }, description: 'Helper addresses/usernames to add' },
        removeHelpers: { type: 'array', items: { type: 'string' }, description: 'Helper addresses to remove (server resolves the numbered index)' },
        threshold: { type: 'number', description: 'Number of helpers required for recovery (integer count; stored on-chain as a percentage of total helpers)' },
        account: ACCOUNT_PROP,
      },
      required: ['threshold'],
    },
  },
  {
    name: 'wallet_notification_configure',
    description:
      'Configure notifications. Returns a token credential — display to the user ONCE with an explanation, then drop it. At least one channel field required.',
    inputSchema: {
      type: 'object',
      properties: {
        email: { type: 'string', description: 'Comma-separated email addresses' },
        sms: { type: 'string', description: 'Comma-separated phone numbers' },
        webhook: { type: 'string', description: 'Comma-separated webhook URLs' },
        telegram: { type: 'string', description: 'Comma-separated Telegram handles/chat IDs' },
        push: { type: 'string', description: 'Comma-separated push tokens' },
        address: { type: 'string', description: 'Address to register the channels for (defaults to the signing account)' },
        account: ACCOUNT_PROP,
        url: { type: 'string', description: 'Override config wikeyAuthUrl' },
      },
      required: [],
    },
  },

  // ── Casdoor / gateway IDP (wallet-passkey login) ──
  {
    name: 'wallet_gateway_register',
    description:
      "Enroll this wallet's passkey with a Casdoor/gateway IdP, binding it to the wallet's SAFE (recovery-proof). The realistic path is an invited employee: pass `invite` (the invitation link) and nothing else — the agent derives host/application/organization/pinned-username and the public clientId/redirectUri from the link, signs up with the invitation code (the one-time secret), and binds the passkey. This is ALSO the whole job for an enroll=only invitation link: call this tool alone (NOT wallet_onboard_sponsor) — it funds nothing, creates no key and no safe, and signs no on-chain tx, it only binds a passkey to the account you already have. Existing users without an invite: pass explicit fields + `password`. Binds to `account`'s safe, which must have an EC public key (assets.ecPuk) — if you have no account with a safe yet, you need sponsored onboarding first, not this tool. Persists the target + credential under the state root.",
    inputSchema: {
      type: 'object',
      properties: {
        invite: {
          type: 'string',
          description:
            'Invitation link, e.g. https://gateway.wikey.io/signup/application_x?invitationCode=ABC123 — the agent derives everything else from it.',
        },
        host: { type: 'string', description: 'Gateway host (https://…). Derived from the invite when omitted.' },
        organization: { type: 'string', description: 'Casdoor organization (owner). Derived from the invite when omitted.' },
        username: { type: 'string', description: 'Pinned username to enroll. Derived from the invite when omitted.' },
        application: { type: 'string', description: 'Casdoor application. Derived from the invite when omitted.' },
        clientId: { type: 'string', description: 'OAuth client id for the later token login (public). Derived from the invite when omitted.' },
        clientSecret: { type: 'string', description: 'OAuth client secret (optional; passkey login is a public PKCE client and does not need it).' },
        redirectUri: { type: 'string', description: 'OAuth redirect URI (defaults to the agent loopback).' },
        rpId: { type: 'string', description: 'WebAuthn rpId (defaults to the host domain).' },
        origin: { type: 'string', description: 'WebAuthn origin (defaults to https://host).' },
        invitationCode: { type: 'string', description: 'Bootstrap invitation code, if not embedded in `invite`.' },
        password: { type: 'string', description: 'Bootstrap password for an existing user (alternative to an invitation code).' },
        account: ACCOUNT_PROP,
      },
    },
  },
  {
    name: 'wallet_gateway_login',
    description:
      "Log in to the enrolled gateway with the wallet passkey and obtain an OAuth access token (the passwordless second half of register). The agent IS the OAuth client (RFC 8252, PKCE public client — no client secret): it builds a WebAuthn assertion, SIGNS the on-chain FIDO-sign object on the SAFE (only the safe owner can — this is the real Level-3 proof Casdoor's ValidateObject checks), then exchanges the authorization code for a JWT. Returns the token + decoded claims (expect amr:[\"fido\"], aud=clientId) plus the on-chain object id/txHash that gated it. Requires a prior wallet_gateway_register. Signs on-chain (brings up SSP lazily).",
    inputSchema: {
      type: 'object',
      properties: {
        scope: { type: 'string', description: 'OAuth scope to request (default: read).' },
        state: { type: 'string', description: 'OAuth state value (default: random).' },
        account: ACCOUNT_PROP,
      },
    },
  },
  {
    name: 'wallet_gateway_api_call',
    description:
      "Call a 3rd-party REST API THROUGH the enrolled gateway, authorized by the wallet passkey — the agent never holds the upstream API key. The gateway injects the upstream credential (e.g. OpenRouter `Authorization: Bearer sk-or-…`) server-side and reverse-proxies after casbin-gating the passkey token. Pass the gateway `server` (e.g. `openrouter_api` or `organization_xyz/openrouter_api`), a `subpath` (e.g. `v1/chat/completions`), and an optional JSON `body`. Omit `accessToken` to perform a fresh passkey login (signs on-chain); pass one from a prior wallet_gateway_login to reuse it. Requires a prior wallet_gateway_register.",
    inputSchema: {
      type: 'object',
      properties: {
        server: {
          type: 'string',
          description: 'Gateway server: `owner/name` or just `name` (owner defaults to the active target org). E.g. `openrouter_api`.',
        },
        subpath: { type: 'string', description: 'Path appended to the server base URL, e.g. `v1/chat/completions`.' },
        method: { type: 'string', description: 'HTTP method (default: POST when a body is given, else GET).' },
        body: { type: 'object', description: 'JSON request body forwarded verbatim to the upstream API.' },
        headers: { type: 'object', description: 'Optional extra request headers.' },
        accessToken: { type: 'string', description: 'Reuse a passkey token from wallet_gateway_login instead of logging in again.' },
        scope: { type: 'string', description: 'OAuth scope to request when logging in (only used when accessToken is omitted).' },
        account: ACCOUNT_PROP,
      },
      required: ['server'],
    },
  },
  {
    name: 'wallet_gateway_mcp_call',
    description:
      "Call an MCP server THROUGH the enrolled gateway's MCP aggregator (`/api/mcp-gateway`), authorized by the wallet passkey — the agent never holds the upstream MCP credential. Unlike wallet_gateway_api_call (a REST reverse-proxy for API-category servers), this speaks MCP streamable-http: the aggregator connects to each granted upstream MCP itself (follows its transport redirects, injects the upstream credential e.g. Composio `x-api-key` server-side, tokenizes PII) and re-exposes every tool namespaced `<server>__<TOOL>`. Omit `tool` to list the federated tools; pass `tool` (e.g. `google-sheets-mcp__GOOGLESHEETS_VALUES_GET`) + `arguments` to call one. Omit `accessToken` to perform a fresh passkey login (signs on-chain); pass one from a prior wallet_gateway_login to reuse it. Requires a prior wallet_gateway_register.",
    inputSchema: {
      type: 'object',
      properties: {
        tool: {
          type: 'string',
          description: 'Federated tool to call, namespaced `<server>__<TOOL>` (e.g. `google-sheets-mcp__GOOGLESHEETS_VALUES_GET`). Omit to list all tools.',
        },
        arguments: { type: 'object', description: 'Arguments object for the tools/call (ignored when `tool` is omitted).' },
        method: { type: 'string', description: 'Advanced: raw JSON-RPC method override (e.g. `resources/list`). Wins over `tool`.' },
        params: { type: 'object', description: 'Advanced: raw params for `method`.' },
        path: { type: 'string', description: 'Aggregator path (default `/api/mcp-gateway`).' },
        accessToken: { type: 'string', description: 'Reuse a passkey token from wallet_gateway_login instead of logging in again.' },
        scope: { type: 'string', description: 'OAuth scope to request when logging in (only used when accessToken is omitted).' },
        account: ACCOUNT_PROP,
        headers: { type: 'object', description: 'Optional extra request headers.' },
      },
    },
  },
  {
    name: 'wallet_gateway_status',
    description:
      'Show the current gateway target and the enrolled passkey credential (client secret masked). Reports the resolved default-key account and whether the stored credential matches the active target. No network, no signing.',
    inputSchema: { type: 'object', properties: {} },
  },
  // ── Uninstall (irreversible) ──
  {
    name: 'wallet_uninstall',
    description:
      'Remove Wikey Wallet from this machine — signing keys, local state, and the npm package. THIS DESTROYS KEYS IRREVERSIBLY: a deleted key cannot be restored from any backup, passphrase, or by Wikey, and the ONLY way back into an account is its on-chain recovery helpers approving a move onto a new key. Called with NO arguments it is READ-ONLY and returns a plan: what would be deleted, an audit of every account\'s recoverability, and what would still be left over afterwards (residuals[]). ALWAYS run the plan first and read it to the user — especially each account\'s `reason` — before asking whether to proceed; never call the destructive form on your own initiative. To delete, pass `confirm` equal to the plan\'s exact `confirmPhrase`. Four gates apply in order: the confirm phrase (which names the current key count, so a stale plan cannot delete a changed keystore); the operator env WIKEY_ALLOW_UNINSTALL=1, which a HUMAN must set in the client config — an agent cannot set it, and if it is missing the tool explains how; and `acceptPermanentLoss: true`, required only when some account has no recovery helper that survives this machine (set it ONLY on the user\'s explicit say-so after telling them which accounts it abandons). Deleting nothing on-chain: accounts, safes and balances continue to exist and simply become unreachable from here.',
    inputSchema: {
      type: 'object',
      properties: {
        confirm: {
          type: 'string',
          description:
            "Exact `confirmPhrase` from the plan. Omit to get the read-only plan. Must come from the user's explicit agreement, not from you echoing the plan back.",
        },
        acceptPermanentLoss: {
          type: 'boolean',
          description:
            'Proceed even though some accounts have no surviving recovery path and will be lost forever. Only ever the user\'s decision, made after hearing which accounts it abandons.',
        },
      },
    },
  },
  {
    name: 'wallet_gateway_logout',
    description:
      'Forget the local gateway target + enrolled credential so the next register starts clean. Does not delete the passkey on the remote gateway. No signing.',
    inputSchema: { type: 'object', properties: {} },
  },
];

// ─── Prompts (Layer C) ────────────────────────────────────────────────────────
// User-initiated entry points the client surfaces in its UI (Claude Desktop's
// "+"/attachment menu, etc.) — the discoverable "help" affordance for a user who
// doesn't know what to type. Each prompt just steers the model to the live guide.

const PROMPTS = [
  {
    name: 'getting-started',
    title: 'Getting started with Wikey Wallet',
    description: "Orient yourself: what this wallet does and your exact next step, based on your current setup.",
  },
  {
    name: 'help',
    title: 'What can I do with Wikey Wallet?',
    description: 'List everything you can do with the wallet right now, given where you are in setup.',
  },
];

function promptMessages(name: string): { role: 'user'; content: { type: 'text'; text: string } }[] {
  const text =
    name === 'help'
      ? 'Using the Wikey Wallet MCP, call wallet_getting_started and then tell me, in plain language, everything I can do right now and what (if anything) I need to set up first. Present the next step(s) as a short numbered list.'
      : 'I am new to the Wikey Wallet MCP and not sure how to begin. Call wallet_getting_started to check my current state, then explain what this wallet does and walk me through my single next step. Keep it short and concrete.';
  return [{ role: 'user', content: { type: 'text', text } }];
}

// ─── Dispatcher ───────────────────────────────────────────────────────────────

interface Deps {
  session: SessionManager;
  cache: SnapshotCache;
  walletCli: WalletCliLauncher;
}

/**
 * Recipient safe lists, memoized briefly.
 *
 * "Send 2 BTC to op20" is three calls about ONE recipient —
 * wallet_resolve_recipient (or wallet_tx_check) to get the menu, then
 * create-transaction with the answer — and each would otherwise re-read a
 * response that is 4.6 MB for a heavy account.
 *
 * 60s covers that conversation and deliberately nothing more: safes are not
 * created often, but a safe created DURING the window must not stay invisible
 * for longer than it takes to put one question to a user.
 *
 * Module-scoped because `dispatch` runs per request. Kept SEPARATE from the B2
 * snapshot cache on purpose: ingesting a third party's snapshot there would
 * evict the user's own index (see wallet_snapshot).
 */
const RECIPIENT_TTL_MS = 60_000;
const recipientMemo = new Map<string, { at: number; safes: RecipientSafe[] }>();

/** Everything a recipient answer carries, refused or not (see resolveRecipient). */
interface RecipientBase {
  name: string;
  accountAddress: string;
  safeCount: number;
}
interface RecipientRefused extends RecipientBase {
  ok: false;
  kind: string;
  message: string;
  /** The menu, when the refusal is a choice. */
  safes?: SafeChoice[] | undefined;
  /** The chosen safe, when the refusal happened after choosing one. */
  safe?: SafeChoice | undefined;
  canReceive?: string[] | undefined;
  /** Near-miss local account names, when the name itself did not resolve. */
  candidates?: NameCandidate[] | undefined;
}
interface RecipientResolved extends RecipientBase {
  ok: true;
  safe: SafeChoice;
  echo: string;
  warning?: string | undefined;
  /** Absent when no asset was named — then this is an inventory answer. */
  asset?: string | undefined;
  to?: string | undefined;
  symbolUsed?: string | undefined;
  addressFamily?: string | undefined;
}
type RecipientAnswer = RecipientResolved | RecipientRefused;

/**
 * The two signing verbs the gateway passkey flow needs, bound to one account.
 * Shared by login / api_call / mcp_call so all three sign as the same key they
 * resolve the safe from — see the note at wallet_gateway_login.
 */
function gatewaySigner(session: SessionManager, account: ResolvedAccount): LoginSigner {
  return {
    signChallenge: (challengeHex: string) =>
      session.signPrompted(account, ['keys', 'sign-challenge', '--challenge', challengeHex], []),
    createFidoObject: ({ safe, uuid, payloadHex }) =>
      session.signPrompted(
        account,
        ['tx', 'create-fido-object', '--destination', safe, '--id', uuid, '--payload', payloadHex, '--broadcast', ...signerArgsFor(account)],
        [],
      ),
  };
}

// Loose coercion of the optional `fields` tool arg ('*' | string[]).
function parseFields(v: unknown): FieldSelector | undefined {
  if (v === '*') return '*';
  if (Array.isArray(v)) return v.map(String);
  return undefined;
}

// Says what a partial portfolio means, so the agent reports it instead of
// telling the user those assets are gone or empty.
const UNAVAILABLE_NOTE =
  'These assets could not be priced in time and are MISSING from the list above — ' +
  'that is not the same as a zero balance. Every other asset is accurate. ' +
  'Retrying usually resolves it; a transfer of an unlisted asset will still pre-flight correctly.';

async function dispatch(deps: Deps, name: string, input: Record<string, unknown>): Promise<unknown> {
  const { session, cache, walletCli } = deps;
  // Every wallet-cli read runs with HOME pinned to the state root so it reads the
  // SAME co-located config (default-key pointer) the signing paths write (P2).
  const query = (args: string[]) => runQuery({ walletCli, args, env: walletCliEnv() });
  // (There was a `queryAs` here that injected WALLET_ADDRESS into the child env
  // to target commands wallet-cli gives no --address flag. Its only caller was
  // `query assets`, which now reads the pricing endpoint directly — see
  // core/assetInfo.ts. walletCliEnv(account) still does the env injection for
  // the paths that need it, e.g. resolveName below.)
  //
  // Settle WHO a call acts as. There is no default key: this returns the only
  // key when there is one, the named one when the caller chose, and otherwise
  // throws with the account list so the agent can ask the user.
  //
  // One resolution feeds BOTH routings — the child env (WALLET_ADDRESS/
  // WALLET_PUBKEY, which reaches commands that have no flags) and the
  // --creator/--pubkey flags via signerArgsFor — so they can never disagree.
  //
  // Bound here (not called bare) so the `keys get` pubkey lookup runs with the
  // session guaranteed up: it talks to the signing-server over HTTP, and would
  // otherwise fail on a cold session with a bare `fetch failed`.
  const acct = (requested: unknown) =>
    resolveAccount(query, listKeystoreAddresses, requested, {
      ensureSession: () => session.ensureSession(),
    });

  // The account parameter, with back-compat. `signingKey` was this parameter's
  // name until 2026-08-10; it is no longer advertised in any schema, but a
  // caller with the old name hardcoded still works for one release. Safe to
  // drop later: ignoring it can never sign the wrong key — with one key the
  // result is identical, and with several the resolver refuses either way.
  const accountOf = (i: Record<string, unknown>): unknown => i.account ?? i.signingKey;

  // Account NAME → address, through the ONE resolver wallet-cli ships
  // (ApiClient.resolveUsername). It has no CLI surface of its own, so we reach it
  // the only way a spawning caller can: `tx edit-helpers` resolves what is typed
  // at its username prompt, and the probe aborts before anything is built or
  // signed (see resolveNameViaEditHelpers). Signing-free — the account is settled
  // with resolveAccountAddress, which never wakes SSP.
  const resolveName = async (asked: string, requested: unknown) => {
    const creator = await resolveAccountAddress(query, listKeystoreAddresses, requested);
    return resolveNameViaEditHelpers({
      walletCli,
      creator,
      name: asked,
      env: walletCliEnv({ address: creator }),
    });
  };

  // Name → address, cheapest route first. A LOCAL account's own name is answered
  // from the keystore listing — free, and the common case — before falling back
  // to the probe, which is what covers an account this machine holds no key for
  // (the lost-key user, or any third-party recipient).
  //
  // Shared by every by-name path so they cannot disagree about what a name
  // means; each caller wraps the failure in its own wording, because "could not
  // resolve" needs to say something different about a helper than about a
  // payee. Note wallet_resolve_name does NOT come through here — it is the
  // deliberate probe, and answering it from the keystore would report an
  // account exists on-chain without having checked.
  //
  // ASSUMPTION, and exactly where it stops holding. The two routes answer to
  // different authorities: the local shortcut reads the name off the CHAIN
  // profile of a key this machine holds, while the probe asks the directory,
  // which is the one place a name maps to a single current address. RECOVERY is
  // what pulls those apart — it mints a NEW address and leaves the NAME alone,
  // so the chain ends up carrying one name on two or more accounts while the
  // directory carries only the active one.
  //
  // In the flows that actually occur the two agree. The machine that performed
  // the recovery holds only the new key — recovery is refused for an account
  // already in the list, so the retired key is never sitting beside it to
  // compete — and a machine holding no key for that name falls through to the
  // probe. They diverge on a machine still holding the SUPERSEDED key after a
  // recovery done elsewhere: that key's chain profile still carries the name, so
  // the local match wins and this returns the retired address without ever
  // asking the directory.
  //
  // Left as-is deliberately (2026-08-20). The probe is a wallet-cli spawn with
  // 30s/60s timeouts; paying that on every by-name read to cover a cross-machine
  // case is the worse trade, and on the signing paths it would not even help —
  // a machine that holds only the old key cannot sign as the new address
  // whatever we resolve to. The read tools echo the address they resolved to, so
  // the choice is inspectable in the response even though it is made silently.
  //
  // Second, narrower gap, unrelated to recovery: with several local accounts
  // sharing one name, `.find` takes the first in keystore order, arbitrarily.
  const localOrChainAddress = async (asked: string, requested: unknown): Promise<string> => {
    const local = (await listAccounts(query, listKeystoreAddresses)).find(
      (a) => a.name && a.name.toLowerCase() === asked.toLowerCase(),
    );
    if (local) return local.address;
    return (await resolveName(asked, requested)).address;
  };

  // The address whose helpers to read, from a name.
  const resolveHelperTarget = async (asked: string, requested: unknown): Promise<string> => {
    try {
      return await localOrChainAddress(asked, requested);
    } catch (e) {
      throw new Error(
        `"${asked}" could not be resolved to an account address, so its recovery helpers cannot be ` +
          `read. This is reported as an error on purpose: wallet-cli's \`query helpers\` accepts an ` +
          `ADDRESS only, and would answer a name with an empty helper list that reads as "this ` +
          `account has no helpers". Underlying error: ${(e as Error).message}`,
      );
    }
  };

  // The subject of a plain chain read (`query balance|balances|account`),
  // settled to an address from either spelling of the parameter.
  //
  // Two distinct mistakes were reachable here and NEITHER said what was wrong.
  // Every other tool on this server names this parameter `account` and accepts a
  // NAME in it, so a caller following the house convention passes `account` to
  // these three — `input.address` is then undefined, and `String(undefined)`
  // forwards the literal text "undefined" as --address. An account NAME passed
  // as `address` is forwarded just as literally. Both arrive at cosmjs as a
  // non-bech32 string and come back as "decoding bech32 failed: invalid
  // separator index -1", which names neither the tool, the parameter, nor the
  // value — the failure is indistinguishable from a chain problem.
  //
  // So: accept both spellings, resolve a name the way wallet_recovery_helpers
  // does, and never stringify undefined into an argument. `account` stays
  // undeclared in the schemas, the same way `signingKey` does above — the
  // advertised name is `address`, and the fallback only rescues a caller who
  // reached for the convention the other tools taught them.
  const queryTarget = async (i: Record<string, unknown>, tool: string): Promise<string> => {
    const viaAddress = i.address == null ? '' : String(i.address).trim();
    const asked = viaAddress || (i.account == null ? '' : String(i.account).trim());
    if (!asked) {
      throw new Error(
        `${tool} requires \`address\` — an omnistar1… address or an account name (e.g. alice@acme). ` +
          `Call wallet_accounts to list this machine's accounts.`,
      );
    }
    if (isChainAddress(asked)) return asked;

    // A NAME. When `account` is what supplied it, that name is the SUBJECT of
    // the read, not the actor performing it — forwarding it as the actor would
    // fail a third party's name with "not a signing key on this machine". The
    // on-chain probe runs as this machine's own key in that case.
    //
    // It resolves to an ACCOUNT address — the key address gas is paid from —
    // never a safe. For an account that has been RECOVERED, see the assumption
    // documented on localOrChainAddress: the name survives recovery unchanged
    // while the address moves, and on a machine still holding the retired key
    // the local shortcut can answer with that address. wallet-cli echoes
    // whichever address was queried, so a caller checking gas can see which one
    // it got; pass the address outright when it has to be a specific one.
    try {
      return await localOrChainAddress(asked, viaAddress ? accountOf(i) : undefined);
    } catch (e) {
      // TWO different failures, and they must not wear the same message. "Which
      // of your keys should probe this name?" is not "that name does not exist"
      // — the first is answerable by passing `account`, the second is not. The
      // resolver already asks the right question in the right words, so it
      // passes through untouched rather than being buried under a wrapper that
      // blames the name.
      if (e instanceof AccountResolutionError) throw e;
      throw new Error(
        `"${asked}" could not be resolved to an account address, so ${tool} has nothing to query. ` +
          `Pass an omnistar1… address, or an account name that exists on-chain. ` +
          `Underlying error: ${(e as Error).message}`,
      );
    }
  };

  // Will a transfer settle? Reads the same priced asset rows wallet_assets
  // returns — no credentials beyond the config's own api-key, no session
  // bring-up, so the check stays a free read and can be a precondition on the
  // signing path without making signing slower to reach.
  //
  // NARROWED to the asset being sent. It does NOT shell out to `query assets`:
  // that command asks the pricing endpoint for the safe's ENTIRE asset list in
  // one request, the endpoint prices serially, and wallet-cli aborts at a
  // hardcoded 10s — so on a safe holding a slow asset (MATIC/POL took 17-22s
  // each on 2026-08-17) EVERY transfer failed with API_TIMEOUT before it could
  // reach the signer, whatever was being sent. Pricing just the sent asset
  // (plus its gas coin, for a token) is a sub-second read. See core/assetInfo.ts.
  //
  // It never estimates a fee: the fee that settles a transfer is computed by the
  // signing engine, and the one number reachable from here (`fee_rate`) is masked
  // and means a different thing on every chain. See core/txFeasibility.ts.
  const feasibility = async (i: Record<string, unknown>, amount: bigint) => {
    const address = await resolveAccountAddress(query, listKeystoreAddresses, accountOf(i));
    const asset = String(i.asset ?? '');
    return checkFeasibility({
      safes: await fetchSafeAssets(await assetDeps(), address, [asset]),
      safe: String(i.destination ?? ''),
      asset,
      amount,
    });
  };

  /**
   * WHICH SAFE THE MONEY LEAVES FROM (`--destination`).
   *
   * Not merely a convenience. `destination` is required today and the agent
   * typically infers it from wallet_assets; a wrong guess is caught ONLY when
   * the wrong safe happens not to hold the asset (R1). When two safes both hold
   * BTC, nothing catches it and the transfer succeeds from the wrong source —
   * quietly debiting, say, an organization's safe instead of the user's own.
   *
   * FAST PATH FIRST: an omnistar address is passed straight through, with no
   * read at all. Only a safe NAME, or an omitted destination, pays for the safe
   * list — so this cannot slow down a call that works today.
   */
  const resolveSourceSafe = async (i: {
    destination?: unknown;
    asset?: string | undefined;
    account?: unknown;
  }): Promise<
    { ok: true; address: string } | { ok: false; kind: string; message: string; safes?: SafeChoice[] }
  > => {
    const asked = String(i.destination ?? '').trim();
    if (asked && isChainAddress(asked)) return { ok: true, address: asked };

    const accountAddress = await resolveAccountAddress(query, listKeystoreAddresses, i.account);
    const accountName =
      (await listAccounts(query, listKeystoreAddresses)).find((a) => a.address === accountAddress)?.name ?? '';
    const picked = pickRecipientSafe({
      safes: await readRecipientSafes(accountAddress),
      accountName,
      requested: asked || undefined,
      asset: i.asset,
      role: 'source',
    });
    if (!picked.ok) return { ok: false, kind: picked.kind, message: picked.message, safes: picked.safes };
    return { ok: true, address: picked.safe.address };
  };

  /**
   * The `--to` a transfer will ACTUALLY use, from either a literal address or a
   * recipient NAME.
   *
   * Shared by wallet_tx_check and wallet_tx_create_transaction on purpose: if
   * the pre-flight resolved a name differently from the broadcast, the agent
   * would check one recipient and pay another. One function, one answer.
   *
   * Runs before anything signs or wakes SSP, so an unknown name, an ambiguous
   * safe or a wrong-chain address fails while the call is still free.
   */
  const resolveSendTarget = async (i: {
    to?: unknown;
    toName?: unknown;
    toSafe?: unknown;
    asset: string;
    destination: string;
    chain?: string | undefined;
    tokenAddress?: string | undefined;
    account?: unknown;
  }): Promise<
    | { ok: true; to: string; resolvedFrom?: Record<string, unknown> }
    | { ok: false; kind: string; message: string; safes?: SafeChoice[]; candidates?: NameCandidate[] }
  > => {
    const literal = String(i.to ?? '').trim();
    const named = String(i.toName ?? '').trim();

    if (literal && named) {
      return {
        ok: false,
        kind: 'to-and-toName',
        message:
          `Pass EITHER \`to\` (a literal recipient address) OR \`toName\` (an account name), not both — ` +
          `they can disagree, and only one of them can be right. Got to="${literal}" and toName="${named}".`,
      };
    }
    if (!literal && !named) {
      return {
        ok: false,
        kind: 'no-recipient',
        message:
          `No recipient: pass \`toName\` with the recipient's account name (recommended — it resolves ` +
          `to the right chain-native address for ${i.asset.toUpperCase()}), or \`to\` with a literal ` +
          `address if the recipient is outside Wikey.`,
      };
    }

    let to = literal;
    let resolvedFrom: Record<string, unknown> | undefined;
    let resolvedSafe: SafeChoice | undefined;

    if (named) {
      const r = await resolveRecipient({
        name: named,
        asset: i.asset,
        safe: i.toSafe === undefined ? undefined : String(i.toSafe),
        chain: i.chain,
        tokenAddress: i.tokenAddress,
        account: i.account,
      });
      if (!r.ok)
        return {
          ok: false,
          kind: r.kind,
          message: r.message,
          safes: r.safes,
          ...(r.candidates ? { candidates: r.candidates } : {}),
        };
      // `to` is set whenever an asset was named, and a transfer always names
      // one — so this cannot fire. It is here because the alternative to a
      // guard is `String(undefined)`, which would put the literal text
      // "undefined" on a broadcast.
      if (!r.to) {
        return {
          ok: false,
          kind: 'no-receive-address',
          message:
            `Resolved "${named}" to safe ${r.safe.name || r.safe.address}, but no receive address for ` +
            `${i.asset.toUpperCase()} came back with it. Do not retry blindly — report this.`,
        };
      }
      to = r.to;
      resolvedSafe = r.safe;
      resolvedFrom = {
        name: r.name,
        accountAddress: r.accountAddress,
        safe: { address: r.safe.address, name: r.safe.name, nameMatchesAccount: r.safe.nameMatchesAccount },
        to,
        echo: r.echo,
        ...(r.warning ? { warning: r.warning } : {}),
      };
    }

    // G1 applies to a LITERAL `to` as well, not just a resolved one — a hand-
    // typed omnistar address is exactly the mistake this guard exists for.
    // Open-world: it only fires when both families are known and disagree, so
    // it can never refuse a send that works today. No override.
    const family = checkAddressFamily(i.asset, to, { chain: i.chain, tokenAddress: i.tokenAddress });
    if (!family.ok) return { ok: false, kind: family.kind, message: family.message };

    // G3, with what is free. A resolved safe that IS the source safe is a
    // self-send whatever the asset; for a literal address we can only compare
    // against the source safe's own address, which catches the OST case (where
    // the receive address IS the safe address) but not a hand-typed BTC address
    // belonging to the same safe. Confirming that would cost a snapshot read on
    // every send, and the stake here is a wasted fee, not lost funds.
    if (resolvedSafe && resolvedSafe.address.toLowerCase() === i.destination.trim().toLowerCase()) {
      return {
        ok: false,
        kind: 'self-send',
        message:
          `Refusing: "${named}" resolves to ${resolvedSafe.name || resolvedSafe.address}, which IS the ` +
          `safe the funds would leave from. The transfer would pay a fee to move ${i.asset.toUpperCase()} ` +
          `nowhere. Check whether the source safe (destination) or the recipient is wrong.`,
      };
    }
    const self = checkSelfSend({
      to,
      sourceSafe: { address: i.destination.trim(), name: '', assets: [] },
      asset: i.asset,
    });
    if (!self.ok) return { ok: false, kind: self.kind, message: self.message };

    return { ok: true, to, ...(resolvedFrom ? { resolvedFrom } : {}) };
  };

  // Read a config value via the wallet-cli read runner (reads are never locked).
  // A missing key, a wedged read or junk JSON all answer '' — every caller here
  // treats "no value" as "fall through to the explicit path", never as an error.
  const cfgGet = async (key: string): Promise<string> => {
    try {
      const j = JSON.parse(await query(['config', 'get', key])) as { data?: { value?: string } };
      return j?.data?.value ?? '';
    } catch {
      return '';
    }
  };

  // Endpoints + credential for the direct asset reads, straight from the SAME
  // wallet-cli config every other path uses — so a re-pointed environment (a
  // testnet proxy, a rotated api-key) moves these reads with it and there is no
  // second place to keep in sync. Read-only: `config get` is never locked.
  //
  // Missing values are an error, not a default. A hardcoded fallback URL would
  // silently price a testnet safe against mainnet.
  const assetDeps = async () => {
    const [snapshotUrl, apiServerUrl, apiKey] = await Promise.all([
      cfgGet('snapshotUrl'),
      cfgGet('apiServerUrl'),
      cfgGet('apiKey'),
    ]);
    const missing = [
      ['snapshotUrl', snapshotUrl],
      ['apiServerUrl', apiServerUrl],
      ['apiKey', apiKey],
    ]
      .filter(([, v]) => !v)
      .map(([k]) => k);
    if (missing.length) {
      throw new Error(
        `Cannot read asset prices: wallet-cli config is missing ${missing.join(', ')}. ` +
          `Run wallet_config_show to inspect it.`,
      );
    }
    return { snapshotUrl, apiServerUrl, apiKey };
  };

  // Narrower than assetDeps on purpose. A recipient read prices NOTHING, so
  // demanding apiServerUrl/apiKey would fail a call that never uses them — and
  // no credential of ours should leave the process for a public read.
  const snapshotDeps = async () => {
    const snapshotUrl = await cfgGet('snapshotUrl');
    if (!snapshotUrl) {
      throw new Error(
        `Cannot read safes: wallet-cli config is missing snapshotUrl. ` +
          `Run wallet_config_show to inspect it.`,
      );
    }
    return { snapshotUrl };
  };

  const readRecipientSafes = async (accountAddress: string): Promise<RecipientSafe[]> => {
    const hit = recipientMemo.get(accountAddress);
    if (hit && Date.now() - hit.at < RECIPIENT_TTL_MS) return hit.safes;
    const safes = await fetchRecipientSafes(await snapshotDeps(), accountAddress);
    recipientMemo.set(accountAddress, { at: Date.now(), safes });
    return safes;
  };

  /**
   * "op20" → the chain-native address to put in `--to`.
   *
   * Three links: name → account address (wallet-cli's resolver, or the keystore
   * when it is a local account), account → its safes, safe → the receive address
   * for this asset. Read-only and signing-free the whole way: nothing here wakes
   * SSP, so an unknown name or an ambiguous safe fails while the call is free.
   *
   * Returns a refusal rather than throwing, because the two callers need
   * opposite things from it — wallet_resolve_recipient RETURNS the menu (an
   * agent exploring on the user's behalf should not have to catch an error to
   * see a list), while the signing path turns it into one.
   */
  const resolveRecipient = async (i: {
    name: string;
    asset?: string | undefined;
    safe?: string | undefined;
    chain?: string | undefined;
    tokenAddress?: string | undefined;
    account?: unknown;
  }): Promise<RecipientAnswer> => {
    const asked = String(i.name ?? '').trim();
    if (!asked) throw new Error('wallet_resolve_recipient requires `name` — the recipient account name.');

    // An address passed where a name was expected is accepted and used as-is,
    // the way wallet_resolve_name does. The naming convention cannot be applied
    // then (we never learn the account's name), so the menu says so instead of
    // implying that none of the safes are theirs.
    const isAddress = isChainAddress(asked);
    let accountAddress: string;
    try {
      accountAddress = isAddress ? asked : await localOrChainAddress(asked, i.account);
    } catch (e) {
      // TWO different failures, and they must not wear the same message. "Which
      // of your keys is asking?" is not "your recipient does not exist" — on
      // that path the name was never looked up at all, because wallet-cli's
      // resolver runs AS an account and there were several to choose from.
      // Reporting it as an unknown recipient sends the user hunting for a typo
      // in a name that is very probably correct.
      if (e instanceof AccountResolutionError) {
        throw new Error(
          `Cannot look up "${asked}" yet: resolving a name runs as one of YOUR accounts, and the ` +
            `call did not say which to use. This says nothing about whether "${asked}" exists — ` +
            `pass \`account\` and try again.\n${(e as Error).message}`,
        );
      }
      // G8. A name that did not resolve is a REFUSAL WITH CANDIDATES, not a bare
      // error — because a bare error is what makes an agent complete the handle
      // itself. Users say `sponsorTest2`; the account is
      // `sponsorTest2@organization_xyz`; the resolver rejects the short form. On
      // 2026-08-20 an agent bridged that gap on its own and moved real funds,
      // telling the user only afterwards. The candidates are offered so the
      // question can be asked, and the refusal stands so it MUST be.
      const refusal = unknownNameRefusal({
        asked,
        candidates: suggestAccountNames(asked, await listAccounts(query, listKeystoreAddresses)),
        underlying: (e as Error).message,
      });
      return { ...refusal, name: asked, accountAddress: '', safeCount: 0 };
    }

    const safes = await readRecipientSafes(accountAddress);
    const accountName = isAddress ? '' : asked;
    const picked = pickRecipientSafe({
      safes,
      accountName,
      requested: i.safe,
      asset: i.asset,
    });

    const base = { name: asked, accountAddress, safeCount: safes.length };
    if (!picked.ok) {
      return { ok: false as const, ...base, kind: picked.kind, message: picked.message, safes: picked.safes };
    }

    const safe = picked.choice;
    const echoTail = (to?: string) =>
      `${asked} → account ${accountAddress} → safe ${safe.name || safe.address} (${safe.address})` +
      (to ? ` → ${String(i.asset).toUpperCase()} ${to}` : '');

    // Decision 1: a lone safe is used without asking, and the ECHO carries the
    // warning — a single safe is not automatically THEIR safe, it may be a
    // shared one, and that is the only thing the data can actually prove.
    const warning =
      safes.length === 1 && !safe.nameMatchesAccount && !isAddress
        ? `${asked}'s only safe is "${safe.name}", which is NOT ${asked}_safe — so it is probably a ` +
          `SHARED safe that ${asked} is merely a member of, not their own. Say so before sending.`
        : undefined;

    if (!i.asset) {
      return {
        ok: true as const,
        ...base,
        safe,
        echo: echoTail(),
        ...(warning ? { warning } : {}),
      };
    }

    const address = pickReceiveAddress({
      safe: picked.safe,
      asset: i.asset,
      chain: i.chain,
      tokenAddress: i.tokenAddress,
    });
    if (!address.ok) {
      return { ok: false as const, ...base, kind: address.kind, message: address.message, safe, canReceive: address.canReceive };
    }

    // G1 against an address we derived ourselves. It should never fire — and
    // that is exactly why it runs: if it ever does, the receive table and the
    // family table disagree, which is worth failing over rather than sending.
    const family = checkAddressFamily(i.asset, address.to, {
      chain: i.chain,
      tokenAddress: i.tokenAddress,
    });
    if (!family.ok) {
      return { ok: false as const, ...base, kind: family.kind, message: family.message, safe };
    }

    return {
      ok: true as const,
      ...base,
      safe,
      asset: i.asset.toUpperCase(),
      to: address.to,
      symbolUsed: address.symbolUsed,
      addressFamily: addressFamily(address.to),
      echo: echoTail(address.to),
      ...(warning ? { warning } : {}),
    };
  };

  // Tool-arg amount → smallest units. Accepts a string so wei-scale values
  // survive: as a JSON number anything past 2^53 has already lost digits by the
  // time it reaches us, and a silently-rounded amount is money.
  const amountArg = (v: unknown): bigint => {
    if (typeof v === 'bigint') return v;
    if (typeof v === 'string') {
      const parsed = toSmallest(v.trim(), '1');
      if (parsed === null) throw new Error(`amount "${v}" is not a number`);
      return parsed;
    }
    const n = Number(v);
    if (!Number.isFinite(n)) throw new Error(`amount "${String(v)}" is not a number`);
    if (!Number.isInteger(n)) {
      throw new Error(
        `amount ${n} is not a whole number. Amounts are in SMALLEST units (display value × smallCoin from wallet_assets), which are always integers.`,
      );
    }
    if (!Number.isSafeInteger(n)) {
      throw new Error(
        `amount ${n} exceeds JSON number precision and has already lost digits. Pass it as a STRING instead.`,
      );
    }
    return BigInt(n);
  };

  switch (name) {
    // ── orientation ──
    case 'wallet_getting_started':
      // Keys are counted from the keystore directory (listKeystoreAddresses),
      // never via the signer — so an idle SSP session is never misread as no-key.
      // The recovery breadcrumb keeps a key that is mid-recovery from being told
      // to create a safe — the account already exists and is waiting on helpers.
      // The build pair (running vs on-disk) makes this tool the one place a
      // "restart your client" notice can still reach the user: an in-place
      // upgrade under a live client leaves THIS process serving the old code.
      return buildGettingStarted(
        query,
        SERVER_NAME,
        listKeystoreAddresses,
        { load: loadRecoveryRequest, clear: clearRecoveryRequest },
        { running: SERVER_VERSION, installed: readInstalledVersionFromDisk() },
      );

    // ── reads ──
    case 'wallet_chain_info':
      return query(['query', 'chain-info']);
    // All three settle their target through queryTarget: `--address` takes an
    // address only, and a missing or name-shaped value used to be stringified
    // straight into the flag. See the helper for what that produced.
    case 'wallet_balance':
      return query(['query', 'balance', '--address', await queryTarget(input, 'wallet_balance')]);
    case 'wallet_balances':
      return query(['query', 'balances', '--address', await queryTarget(input, 'wallet_balances')]);
    case 'wallet_account':
      return query(['query', 'account', '--address', await queryTarget(input, 'wallet_account')]);
    case 'wallet_profile': {
      const args = ['query', 'profile'];
      if (input.address) args.push('--address', String(input.address));
      return query(args);
    }
    case 'wallet_assets': {
      // Reads the pricing endpoint directly rather than via `query assets`.
      // Same envelope, same rows — but ONE REQUEST PER ASSET (throttled)
      // instead of the CLI's single all-assets request, which the endpoint
      // prices serially: 52s on an 11-asset safe, against wallet-cli's
      // hardcoded 10s abort. See core/assetInfo.ts for the measurements.
      //
      // `unavailable` rides along when an asset could not be priced. It is
      // reported rather than thrown BECAUSE this is a display read — one slow
      // asset must not cost the user the other ten — and reported rather than
      // omitted so a missing row is never mistaken for a zero balance.
      const address = await resolveAccountAddress(query, listKeystoreAddresses, accountOf(input));
      const { safes, unavailable } = await fetchPortfolio(await assetDeps(), address);
      return {
        success: true,
        data: {
          assets: safes,
          ...(unavailable.length ? { unavailable, note: UNAVAILABLE_NOTE } : {}),
        },
      };
    }
    case 'wallet_accounts':
      return listAccounts(query, listKeystoreAddresses);

    // ── B2 snapshot store (H14) ──
    case 'wallet_snapshot': {
      const args = ['query', 'snapshot'];
      if (input.address) args.push('--address', String(input.address));
      const raw = await query(args);
      return cache.ingest(raw); // returns the small index ONLY — never raw JSON
    }
    case 'wallet_snapshot_query': {
      const snapshotId = String(input.snapshotId);
      const filter = (input.filter ?? {}) as QueryFilter;
      return cache.query(snapshotId, filter, parseFields(input.fields));
    }
    case 'wallet_snapshot_page': {
      return cache.page(
        String(input.snapshotId),
        String(input.safe),
        String(input.class),
        Number(input.offset),
        Number(input.limit),
        parseFields(input.fields),
      );
    }
    case 'wallet_snapshot_object': {
      const fields = parseFields(input.fields);
      return cache.object(String(input.snapshotId), String(input.id), {
        ...(input.safe ? { safe: String(input.safe) } : {}),
        ...(fields !== undefined ? { fields } : {}),
      });
    }

    // ── keys ──
    case 'wallet_keys_list':
      return query(['keys', 'list']);
    case 'wallet_keys_get':
      return query(['keys', 'get', '--id', String(input.id)]);
    case 'wallet_keys_create': {
      // keys create signs over the signer's HTTP API (no stdin proof) and ends
      // with a `Set as default? (y/n)` prompt. ALWAYS answer 'n': wallet-cli
      // still offers to write user.address/user.pubkey, and accepting would
      // re-introduce the ambient default key this wallet no longer has (and
      // would silently re-point every unrouted command at the new key). The
      // answer is still required — it is what makes wallet-cli print its JSON
      // and exit. Run it session-gated, NOT via the prompt engine, which would
      // deadlock on that y/n and time out even though the key was created.
      //
      // No account is routed: this is the one signing command that must work
      // with an empty keystore.
      const created = await session.runWithSession(['keys', 'create'], { input: 'n\n' });

      // Hand back the store link with the new address ALREADY in it. This is the
      // exact moment the user needs it — the key exists and is worth nothing
      // until it has gas — and it removes the only unrecoverable manual step in
      // the individual path: retyping a bech32 address into a payment form.
      //
      // Best-effort by construction. The key is created and persisted before we
      // ever look at the output, so a parse failure must degrade to the bare
      // store URL and NEVER throw: losing the result here would leave the user
      // with a key they cannot see the address of.
      let fundingUrl = WIKEY_STORE_URL;
      try {
        fundingUrl = storeFundingUrl(parseCreatedKey(String(created)).address);
      } catch {
        /* unparseable output — the raw result still carries the address */
      }
      return {
        result: created,
        fundingUrl,
        next:
          `Give the user this link to buy OST gas for the new key: ${fundingUrl} — pass it VERBATIM. ` +
          `It prefills the store's "User address" field, so nobody has to copy the address by hand. ` +
          `The key cannot broadcast anything on-chain until it holds OST. Once funded, call ` +
          `wallet_getting_started again for the next step (creating the account + safe).`,
      };
    }

    // ── uninstall (irreversible) ──
    case 'wallet_uninstall': {
      // Every gate lives in executeUninstall so their ORDER is one reviewable
      // thing rather than split across the boundary. With no `confirm` this is
      // a read-only plan, which is why the env gate is not checked here: the
      // plan is exactly where a user learns the gate exists and how to set it.
      const install = await detectInstall();
      return executeUninstall(
        {
          stateRoot: stateRoot(),
          listKeys: listKeystoreAddresses,
          query,
          allowUninstall: ['1', 'true'].includes((process.env[ALLOW_ENV] ?? '').toLowerCase()),
          fs: realFs,
          shutdown: () => session.shutdown(),
          // Taken from the session rather than recomputed from cwd, so a custom
          // nonceFile is honoured and we never delete a path we do not use.
          nonceFile: session.nonceFilePath,
          installMode: install.mode,
          ...(install.binDir ? { npmBinDir: install.binDir } : {}),
          packageDir: install.mode === 'global-linked' ? install.packageDir : install.globalEntry,
          npmUninstall,
          findClientConfigs,
        },
        {
          ...(input.confirm == null ? {} : { confirm: String(input.confirm) }),
          ...(input.acceptPermanentLoss === true ? { acceptPermanentLoss: true } : {}),
        },
      );
    }

    // ── config ──
    case 'wallet_config_show':
      return query(['config', 'show']);
    case 'wallet_config_get':
      return query(['config', 'get', String(input.key)]);
    case 'wallet_config_set': {
      const key = String(input.key);
      assertConfigSetAllowed(key); // H10 — reject locked keys
      return query(['config', 'set', key, String(input.value)]);
    }
    case 'wallet_config_init':
      return query(['config', 'init']);
    case 'wallet_config_reset':
      return query(['config', 'reset']);
    case 'wallet_config_path':
      return query(['config', 'path']);

    // ── session ──
    case 'wallet_session_status':
      return session.status();
    case 'wallet_session_recover': {
      // Clear the wedge + init latch, then cold-start so the agent gets immediate
      // proof it's healthy (active:true) — or the real spawn error if it isn't.
      session.recover();
      await session.ensureSession();
      return session.status();
    }

    // ── signing ──
    case 'wallet_tx_create_safe': {
      const a = await acct(accountOf(input));
      return session.signPrompted(
        a,
        ['tx', 'create-safe', '--username', String(input.username), '--broadcast', ...signerArgsFor(a)],
        [],
      );
    }
    case 'wallet_onboard_sponsor': {
      const result = await onboardSponsor(String(input.invite), {
        query,
        // keys create signs over the signer HTTP API and ends with a y/n default
        // prompt — answer 'n' (same as wallet_keys_create: no default key) and
        // read the new key's identity out of the command's own JSON, so
        // onboarding never depends on a config pointer it just moved.
        createKey: async () => parseCreatedKey(await session.runWithSession(['keys', 'create'], { input: 'n\n' })),
        // Sign as the onboarded address EXPLICITLY: a resumed run adopts the
        // previously funded key, which is not the key this run may have minted.
        createSafe: async (username, allowOrg, address) => {
          const a = await acct(address);
          const args = ['tx', 'create-safe', '--username', username, '--broadcast', ...signerArgsFor(a)];
          if (allowOrg) args.push('--allow-org-username');
          return session.signPrompted(a, args, []);
        },
        listKeys: listKeystoreAddresses,
        // Pre-flight "is this handle already ours?": compare the invite's handle
        // against the on-chain profile name of every key in the keystore. Uses the
        // non-signing query runner, so it never wakes the SSP session. A key with
        // no profile (fresh, unfunded, or never create-safe'd) throws here — that
        // is a non-match, not an error, so each lookup is swallowed individually
        // rather than failing the whole scan.
        findLocalAccount: async (username) => {
          for (const addr of listKeystoreAddresses()) {
            try {
              if (extractUsernameFromProfile(await query(['query', 'profile', '--address', addr])) === username) {
                return addr;
              }
            } catch {
              /* no profile on this key — not a match */
            }
          }
          return undefined;
        },
        // Chain-truth check for a resumed run: does this key already have a
        // profile+safe? Reads the snapshot node directly by address (no default-key
        // dependency, no SSP session). Any failure means "not yet" — the caller
        // only uses this to SKIP work, so failing closed just redoes create-safe.
        safeExists: async (address) => {
          try {
            await resolveWalletIdentity(loadCfg(), address);
            return true;
          } catch {
            return false;
          }
        },
        // Same poll enrollment uses (waitForSafe), exposed for the no-enroll
        // variant, which has no enrollment step to absorb the wait. On a resumed
        // run safeExists already proved the safe is queryable, so answer from a
        // single immediate attempt instead of paying the initial delay. A timeout
        // (or any failure) is reported as "not visible yet", never as an error:
        // the caller degrades it to a warning on an otherwise-complete onboarding.
        awaitSafe: async (address, { safeIsNew }) => {
          try {
            const id = await waitForWalletIdentity(
              loadCfg(),
              address,
              safeIsNew ? {} : { initialDelayMs: 0, attempts: 1 },
            );
            return id.safe;
          } catch {
            return undefined;
          }
        },
        // Wait for on-chain validation only when create-safe just broadcast; a
        // resumed run already confirmed the safe is queryable via safeExists.
        enroll: async (invite, address, { safeIsNew }) => {
          const reg = await gatewayRegister({ invite, account: address, waitForSafe: safeIsNew });
          return { safe: reg.safe, username: reg.username, organization: reg.organization };
        },
      });
      return JSON.stringify(result, null, 2);
    }
    case 'wallet_tx_send': {
      // The signer for a bank send IS the --from key (you can only spend your own
      // funds), so the account is not a free choice here — it is --from, and
      // resolving it also validates that this machine actually holds that key.
      // `send` has no --creator option (it derives creator from --from), so the
      // flags are pubkey-only.
      const a = await acct(input.from);

      // Same drain guard as create-transaction, against `query balance` — a bank
      // send's gas is the OST it is sending, so an exact-balance send cannot pay
      // for itself. Skipped silently when the amount is not `<digits><denom>`:
      // wallet-cli validates that itself, and a parse we do not understand must
      // not become a refusal.
      const parsedAmount = parseDenomAmount(String(input.amount));
      if (parsedAmount) {
        const balanceRaw = await query(['query', 'balance', '--address', a.address, '--denom', parsedAmount.denom]);
        const balance = parseBalanceAmount(balanceRaw);
        if (balance !== null) {
          const verdict = checkBankSend({ address: a.address, balance, ...parsedAmount });
          if (verdict.verdict === 'will-fail' || (verdict.verdict === 'at-risk' && input.acknowledgeRisk !== true)) {
            throw new Error(
              `Refusing to broadcast — ${verdict.verdict} (${verdict.rule}).\n${verdict.reason}\n` +
                `Full check: ${JSON.stringify(verdict)}`,
            );
          }
        }
      }

      return session.signPrompted(
        a,
        ['tx', 'send', '--from', a.address, '--to', String(input.to), '--amount', String(input.amount), '--broadcast', ...signerArgsFor(a, { pubkeyOnly: true })],
        [],
      );
    }
    case 'wallet_tx_check': {
      // Amount is optional here: with none, report the ceiling for a
      // send-everything request (asking 0 exercises the same ladder and leaves
      // maxSuggested as the answer).
      const amount = input.amount === undefined ? BigInt(0) : amountArg(input.amount);

      // The SOURCE half. Settled before the balance read, because the balance
      // read is *about* this safe — checking the wrong one answers the wrong
      // question. Reported as data, like the recipient: this tool never throws
      // a choice at the caller.
      const source = await resolveSourceSafe({
        destination: input.destination,
        asset: String(input.asset ?? ''),
        account: accountOf(input),
      });
      if (!source.ok) {
        return { source, feeChoice: buildFeeChoice(String(input.asset ?? ''), undefined) };
      }
      const verdict = await feasibility({ ...input, destination: source.address }, amount);

      // The RECIPIENT half of the pre-flight, when the caller named one. This is
      // the free place to find a wrong-chain address, an ambiguous safe or a
      // self-send — the alternative is finding them at broadcast, with money
      // already committed. Reported as data rather than thrown: a menu is an
      // answer here, not an error, and the balance verdict is still worth
      // seeing alongside it.
      const wantsRecipient = input.to !== undefined || input.toName !== undefined;
      const recipient = wantsRecipient
        ? await resolveSendTarget({
            to: input.to,
            toName: input.toName,
            toSafe: input.toSafe,
            asset: String(input.asset ?? ''),
            destination: source.address,
            chain: input.chain === undefined ? undefined : String(input.chain),
            tokenAddress: input.tokenAddress === undefined ? undefined : String(input.tokenAddress),
            account: accountOf(input),
          })
        : undefined;

      // The fee menu rides along with the pre-flight the agent already has to
      // call: same read, no extra round-trip, and it arrives at exactly the
      // moment the choice has to be put to the user. Priced by the coin that
      // actually pays — for a token that is its chain's gas coin, not the token.
      return {
        ...verdict,
        feeChoice: buildFeeChoice(verdict.asset, verdict.gasAsset?.symbol),
        ...(recipient ? { recipient } : {}),
        ...(String(input.destination ?? '').trim() === source.address ? {} : { source }),
      };
    }
    case 'wallet_tx_create_transaction': {
      const { amount, asset, feePriority, tokenAddress, chain, smallCoin } = input as {
        amount: number; asset: string; feePriority?: unknown;
        tokenAddress?: string; chain?: string; smallCoin?: number;
      };

      // WHICH SAFE PAYS. First, because both the self-send guard and the balance
      // read are about this safe — and because a wrong source is not caught
      // downstream when the wrong safe also holds the asset.
      const source = await resolveSourceSafe({
        destination: input.destination,
        asset: String(asset ?? ''),
        account: accountOf(input),
      });
      if (!source.ok) {
        throw new Error(
          source.kind === 'needs-choice' ? source.message : `Refusing to broadcast — ${source.kind}.\n${source.message}`,
        );
      }
      const destination = source.address;

      // Then WHO IS PAID. Still before the feasibility read and long before
      // anything signs, so an unknown name, an ambiguous safe or a wrong-chain
      // address costs nothing. Unlike wallet_tx_check, this path REFUSES rather
      // than reporting — past here money moves.
      const target = await resolveSendTarget({
        to: input.to,
        toName: input.toName,
        toSafe: input.toSafe,
        asset: String(asset ?? ''),
        destination,
        chain,
        tokenAddress,
        account: accountOf(input),
      });
      if (!target.ok) {
        throw new Error(
          target.kind === 'needs-choice'
            ? target.message
            : `Refusing to broadcast — ${target.kind}.\n${target.message}`,
        );
      }
      const to = target.to;

      // PRECONDITION, not advice. The description already told the model the
      // amount is in smallest units and it still passed the whole balance — a
      // user saying "send everything" beats advisory text every time. So the
      // check runs here and REFUSES, in the same shape as the no-default-account
      // refusal: hand back the numbers needed to retry rather than guessing an
      // amount on the user's behalf.
      const verdict = await feasibility({ ...input, destination }, amountArg(amount));
      if (verdict.verdict === 'will-fail' || (verdict.verdict === 'at-risk' && input.acknowledgeRisk !== true)) {
        const how =
          verdict.verdict === 'at-risk'
            ? `Retry with amount ${verdict.maxSuggested}, or pass acknowledgeRisk:true to send it anyway after telling the user it may fail.`
            : verdict.maxSuggested && verdict.maxSuggested !== '0'
              ? `Retry with amount ${verdict.maxSuggested}.`
              : 'No amount of this asset can settle from this safe right now.';
        throw new Error(
          `Refusing to broadcast — wallet_tx_check says ${verdict.verdict} (${verdict.rule}).\n` +
            `${verdict.reason}\n${how}\n` +
            `Full check: ${JSON.stringify(verdict)}`,
        );
      }

      // SECOND precondition, same shape as the amount one and for the same
      // reason. feePriority used to be `required` in the schema, which bought
      // nothing: nothing validates the schema at this boundary, so a missing
      // value reached spawn() as `undefined` and died on ERR_INVALID_ARG_TYPE —
      // and a model that must fill a field simply writes "medium", spending the
      // user's money on a tier they were never shown. So: the user's explicit
      // answer wins, a standing default they set themselves is honoured, and
      // otherwise we refuse WITH the menu instead of picking. See core/feeChoice.ts.
      const said = feePriority === undefined || feePriority === null || String(feePriority).trim() === ''
        ? null
        : feePriority;
      const given = said === null ? null : normalizeFeePriority(said);
      // Something WAS passed and it is not one of the three: name it rather than
      // falling through to a default, which would send at a tier nobody chose.
      if (said !== null && given === null) throw new Error(feePriorityInvalid(said));
      // Only read config when the call did not say — one wallet-cli read, and
      // only on the path that needs it.
      const priority = given ?? normalizeFeePriority(await cfgGet('feePriority'));
      if (!priority) {
        throw new Error(
          feePriorityRefusal(buildFeeChoice(verdict.asset || asset, verdict.gasAsset?.symbol), verdict.asset || asset),
        );
      }

      const args = [
        'tx', 'create-transaction',
        '--destination', destination,
        '--to', to,
        '--amount', amount.toString(),
        '--asset', asset,
        '--fee-priority', priority,
      ];
      if (tokenAddress) args.push('--token-address', tokenAddress);
      if (chain) args.push('--chain', chain);
      if (smallCoin !== undefined) args.push('--small-coin', smallCoin.toString());
      args.push('--broadcast');
      const a = await acct(accountOf(input));
      args.push(...signerArgsFor(a));
      const broadcast = await session.signPrompted(a, args, []);

      // G7. When a NAME was resolved, hand back the whole chain — name →
      // account → safe → address — so the agent can state where the money
      // actually went. A literal `to` keeps the bare wallet-cli output it has
      // always returned.
      const named = target.resolvedFrom !== undefined;
      const sourceResolved = String(input.destination ?? '').trim() !== destination;
      return named || sourceResolved
        ? {
            broadcast,
            ...(target.resolvedFrom ? { resolvedFrom: target.resolvedFrom } : {}),
            ...(sourceResolved ? { sentFrom: destination } : {}),
          }
        : broadcast;
    }
    case 'wallet_tx_vote': {
      const a = await acct(accountOf(input));
      return session.signPrompted(
        a,
        ['tx', 'vote', '--destination', String(input.destination), '--vote', String(input.vote), '--signature', String(input.signature), '--broadcast', ...signerArgsFor(a)],
        [{ match: 'Add another vote entry?', respond: () => 'n\n' }],
      );
    }
    case 'wallet_tx_request_recovery': {
      const { username, oldAddress } = input as { username?: string; oldAddress?: string };
      let resolved = username;
      if (!resolved) {
        if (!oldAddress) throw new Error('wallet_tx_request_recovery requires either `username` or `oldAddress`');
        const profileRaw = await query(['query', 'profile', '--address', oldAddress]);
        resolved = extractUsernameFromProfile(profileRaw);
      }
      const a = await acct(accountOf(input));
      const args = ['tx', 'request-recovery', '--username', resolved, '--broadcast', ...signerArgsFor(a)];
      // Sponsor/org accounts carry a username@organization handle; recovery must
      // opt into the same @-tolerant validation create-safe uses, or wallet-cli
      // rejects the '@' before signing.
      if (resolved.includes('@')) args.push('--allow-org-username');
      const tx = await session.signPrompted(a, args, []);

      // Hand the requester a deeplink to forward to a recovery helper. pk = the
      // NEW key the account is being recovered onto — which is exactly the key
      // that just signed, so it is the resolved account and needs no separate
      // lookup (it used to be read back from the config default-key pointer,
      // which could name a different key entirely).
      const newAccount = a.address;
      const txResult: unknown = (() => {
        try {
          return JSON.parse(tx);
        } catch {
          return tx;
        }
      })();
      const recoveryDeeplink = newAccount
        ? buildRecoveryDeeplink({ newAccount, accountName: resolved })
        : undefined;

      // Record the outstanding recovery so wallet_getting_started reports
      // "waiting on helpers" instead of "create a safe" for however long the
      // helpers take. Best-effort: a write failure must not fail a broadcast
      // that already succeeded.
      if (newAccount) saveRecoveryRequest({ newAddress: newAccount, username: resolved });

      return JSON.stringify(
        {
          tx: txResult,
          recoveryDeeplink,
          shareWithHelpers: recoveryDeeplink
            ? `Send this link to a recovery helper. They can open it in the Wikey wallet app, or hand it to their own AI agent (wikey-wallet MCP) to approve recovering "${resolved}" onto your new key.`
            : `Recovery requested for "${resolved}", but the new account address could not be resolved to build a helper deeplink.`,
          // The request broadcasting cleanly says nothing about completion — the
          // helpers have not acted yet, and the safe settles after they do.
          note:
            `Recovery requested — this is NOT the recovery finishing. It completes only once enough helpers ` +
            `approve, and each approves on their own schedule. After the final approval the account's safe ` +
            `usually appears under the new key within about a minute — occasionally several minutes longer. ` +
            `Do not tell the user the recovery is complete, and do not attempt anything involving the ` +
            `account's safe, until wallet_getting_started reports stage "ready" with the safe listed.`,
        },
        null,
        2,
      );
    }
    case 'wallet_tx_approve_recovery': {
      const { oldaccount, newaccount, deeplink } = input as {
        oldaccount?: string;
        newaccount?: string;
        deeplink?: string;
      };
      // A helper can paste the recovery deeplink their friend sent instead of
      // spelling out oldaccount/newaccount. Explicit params win; the deeplink
      // fills in whatever is missing (tn → oldaccount, pk → newaccount).
      let oldAccount = oldaccount ? String(oldaccount) : '';
      let newAccount = newaccount ? String(newaccount) : '';
      if (deeplink) {
        const parts = parseRecoveryDeeplink(String(deeplink));
        if (!oldAccount) oldAccount = parts.accountName;
        if (!newAccount) newAccount = parts.newAccount;
      }
      if (!oldAccount || !newAccount) {
        throw new Error(
          'wallet_tx_approve_recovery requires `deeplink`, or both `oldaccount` and `newaccount`.',
        );
      }
      const a = await acct(accountOf(input));
      const tx = await session.signPrompted(
        a,
        ['tx', 'approve-recovery', '--oldaccount', oldAccount, '--newaccount', newAccount, '--broadcast', ...signerArgsFor(a)],
        [],
      );
      const txResult: unknown = (() => {
        try {
          return JSON.parse(tx);
        } catch {
          return tx;
        }
      })();
      // A clean broadcast records THIS helper's approval — it is NOT the recovery
      // finishing, and a bare `code: 0` reads as "done" to any agent. Two things
      // can still be outstanding: other helpers, and the safe resolving under the
      // new key afterwards. Both are named here so the caller cannot infer
      // completion from a successful tx.
      return JSON.stringify(
        {
          tx: txResult,
          status: 'approval-recorded',
          note:
            `Approval recorded for "${oldAccount}" → ${newAccount}. This is NOT the recovery finishing. ` +
            `Other helpers may still need to approve, and once the last one does the account's safe usually ` +
            `appears under the new key within about a minute — occasionally several minutes longer. ` +
            `Do not tell the user the recovery is complete, and do not attempt anything involving the ` +
            `account's safe, until wallet_getting_started reports stage "ready" with the safe listed.`,
        },
        null,
        2,
      );
    }
    case 'wallet_tx_create_policy': {
      const typed = input as { destination: string; applyOn: string; conditions: PolicyCondition[]; name?: string; description?: string };
      const a = await acct(accountOf(input));
      return session.signPrompted(
        a,
        ['tx', 'create-policy', '--destination', typed.destination, '--apply-on', typed.applyOn, '--broadcast', ...signerArgsFor(a)],
        buildPolicyQueue(typed),
      );
    }
    case 'wallet_tx_edit_policy': {
      const typed = input as { destination: string; policyId: string; signature: string; applyOn: string; conditions: PolicyCondition[]; name?: string; description?: string };
      const a = await acct(accountOf(input));
      return session.signPrompted(
        a,
        ['tx', 'edit-policy', '--destination', typed.destination, '--policy-id', typed.policyId, '--signature', typed.signature, '--apply-on', typed.applyOn, '--broadcast', ...signerArgsFor(a)],
        buildPolicyQueue(typed),
      );
    }
    case 'wallet_tx_delete_policy': {
      const { destination, policyId } = input as { destination: string; policyId: string };
      const snapshot = parseSnapshot(await query(['query', 'snapshot']));
      const safe = findSafe(snapshot, destination);
      const { signature, parentGroup } = resolvePolicyDeletion({ destination, policyId, safe });
      const a = await acct(accountOf(input));
      return session.signPrompted(
        a,
        ['tx', 'delete-policy', '--destination', destination, '--policy-id', policyId, '--signature', signature, '--parent-group', parentGroup, '--broadcast', ...signerArgsFor(a)],
        [],
      );
    }
    case 'wallet_tx_create_user': {
      const { destination, user, group } = input as { destination: string; user: string; group?: string };
      if (!user.startsWith('omnistar1')) throw new Error('user must be an omnistar1… address');
      const snapshot = parseSnapshot(await query(['query', 'snapshot']));
      const safe = findSafe(snapshot, destination);
      const parentGroup = resolveCreateUserTarget({ destination, group, groups: extractGroupsFromSafe(safe) });
      const a = await acct(accountOf(input));
      return session.signPrompted(
        a,
        ['tx', 'create-user', '--destination', destination, '--public-key', user, '--parent-group', parentGroup, '--broadcast', ...signerArgsFor(a)],
        [],
      );
    }
    case 'wallet_tx_delete_user': {
      const { destination, userId } = input as { destination: string; userId: string };
      const snapshot = parseSnapshot(await query(['query', 'snapshot']));
      const safe = findSafe(snapshot, destination);
      const { signature, parentGroup } = resolveUserDeletion({ destination, userId, safe });
      const a = await acct(accountOf(input));
      return session.signPrompted(
        a,
        ['tx', 'delete-user', '--destination', destination, '--user-id', userId, '--signature', signature, '--parent-group', parentGroup, '--broadcast', ...signerArgsFor(a)],
        [],
      );
    }
    case 'wallet_recovery_helpers': {
      const asked = input.address == null ? '' : String(input.address).trim();
      if (!asked) return query(['query', 'helpers']);
      if (isChainAddress(asked)) return query(['query', 'helpers', '--address', asked]);
      // A NAME. `query helpers --address` takes an ADDRESS only: handed a name
      // it answers success:true, policyExists:false, helpers:[] — a silent false
      // negative indistinguishable from a real account with no helpers. So the
      // name is NEVER forwarded; it is resolved to an address first, and a name
      // that cannot be resolved is an error rather than an empty helper list.
      const address = await resolveHelperTarget(asked, accountOf(input));
      return query(['query', 'helpers', '--address', address]);
    }
    case 'wallet_resolve_recipient': {
      // Refusals come back as DATA here, never as an error: enumerating the
      // safes IS this tool's job, and an agent should not have to catch an
      // exception to see a list. The signing paths convert the same value into
      // a refusal — see wallet_tx_create_transaction.
      const r = await resolveRecipient({
        name: String(input.name ?? ''),
        asset: input.asset === undefined ? undefined : String(input.asset),
        safe: input.safe === undefined ? undefined : String(input.safe),
        chain: input.chain === undefined ? undefined : String(input.chain),
        tokenAddress: input.tokenAddress === undefined ? undefined : String(input.tokenAddress),
        account: accountOf(input),
      });
      if (r.ok) return { ...r, needsChoice: false };
      // `unknown-name` sets it too: an agent that already branches on
      // needsChoice to put a question to the user must take that branch here,
      // which is the whole point of returning candidates instead of guessing.
      return { ...r, needsChoice: r.kind === 'needs-choice' || r.kind === 'unknown-name' };
    }
    case 'wallet_resolve_name': {
      const asked = String(input.name ?? '').trim();
      if (!asked) throw new Error('name is required');
      // An address is already the answer — no reason to spawn anything.
      if (isChainAddress(asked)) return { name: asked, address: asked, resolved: false };
      return { ...(await resolveName(asked, accountOf(input))), resolved: true };
    }
    case 'wallet_tx_edit_helpers': {
      const { addHelpers = [], removeHelpers = [], threshold } = input as { addHelpers?: string[]; removeHelpers?: string[]; threshold: number };
      const a = await acct(accountOf(input));

      // The account whose helpers we're editing IS the signer.
      const creator = a.address;

      // ── Isolate the two signings ────────────────────────────────────────────
      // edit-helpers no longer registers the inbox channel inline: the prompt
      // runner signs exactly once per wallet-cli process (it ends stdin after the
      // first proof), so an inline inbox signing + the tx signing cannot coexist.
      // Instead, if the account has no inbox channel yet, register it as its OWN
      // isolated signing FIRST — and if that fails, do NOT add the recovery helper.
      let hasInbox = false;
      const apiServerUrl = await cfgGet('apiServerUrl');
      if (apiServerUrl && creator) {
        try {
          const statusUrl =
            `${apiServerUrl.replace(/\/$/, '')}/api/notification/inbox/status` +
            `?address=${encodeURIComponent(creator)}`;
          const resp = await fetch(statusUrl);
          if (resp.ok) {
            const body = (await resp.json()) as { inbox?: unknown };
            hasInbox = body?.inbox === true;
          }
        } catch {
          // Inconclusive (endpoint unreachable/undeployed) → fall through and
          // register the inbox; registration is idempotent and fail-fast.
          hasInbox = false;
        }
      }

      if (!hasInbox) {
        // Isolated signing #1 — inbox registration. A throw here aborts the whole
        // tool call, so we never add a helper without a working inbox channel.
        // `notification configure` has no --creator/--pubkey flags, so the env
        // routing is the ONLY way to aim it at `a` rather than a config pointer.
        await session.signPrompted(a, ['notification', 'configure', '--inbox', creator], []);
      }

      // Isolated signing #2 — the helper tx.
      return session.signPrompted(a, ['tx', 'edit-helpers', '--broadcast', ...signerArgsFor(a)], buildEditHelpersQueue(addHelpers, removeHelpers, threshold));
    }
    case 'wallet_notification_configure': {
      const { email, sms, webhook, telegram, push, address, url } = input as Record<string, string | undefined>;
      // No --creator/--pubkey on this command: the signing key comes from the
      // child env alone. `--address` only sets the address in the request URL.
      const a = await acct(accountOf(input));
      const args = ['notification', 'configure'];
      if (email) args.push('--email', email);
      if (sms) args.push('--sms', sms);
      if (webhook) args.push('--webhook', webhook);
      if (telegram) args.push('--telegram', telegram);
      if (push) args.push('--push', push);
      if (address) args.push('--address', address);
      if (url) args.push('--url', url);
      args.push('--sign');
      return session.signPrompted(a, args, []);
    }

    // ── Casdoor / gateway IDP ──
    case 'wallet_gateway_register': {
      // The passkey binds to THIS account's safe. CASDOOR_ACCOUNT (operator env,
      // not agent-controllable) still names a fallback when the caller passes
      // none — but it is resolved like any other request, so an address that is
      // not in this keystore is an error rather than a silent mis-binding.
      const a = await acct((input as RegisterInput).account ?? process.env.CASDOOR_ACCOUNT);
      return gatewayRegister({ ...(input as RegisterInput), account: a.address });
    }
    case 'wallet_gateway_login': {
      // Inject the two signing verbs the login needs, both bound to the SAME
      // account whose identity gatewayLogin resolves — the on-chain FIDO object
      // is the real proof, and only the safe's owner can create it, so signing
      // as one account while resolving the safe of another fails at the chain.
      // `keys sign-challenge` has no --creator/--pubkey flags: the env routing
      // is the only thing aiming it at this account.
      //
      // Both ride the standard prompt/proof flow through SSP (empty queue), so
      // the HMAC key + private key stay sealed — only signed artifacts cross back.
      const a = await acct(accountOf(input) ?? process.env.CASDOOR_ACCOUNT);
      return gatewayLogin({ ...(input as LoginInput), account: a.address }, gatewaySigner(session, a));
    }
    case 'wallet_gateway_api_call': {
      // Same injected signer: a fresh login (when no accessToken is passed) needs
      // to sign the on-chain FIDO object + the assertion via the sealed session.
      const a = await acct(accountOf(input) ?? process.env.CASDOOR_ACCOUNT);
      return gatewayApiCall(
        { ...(input as unknown as ApiCallInput), account: a.address },
        gatewaySigner(session, a),
      );
    }
    case 'wallet_gateway_mcp_call': {
      // Same injected signer as api_call: a fresh login (when no accessToken is
      // passed) signs the on-chain FIDO object + assertion via the sealed session.
      // The passkey JWT is the ONLY credential sent — the aggregator injects the
      // upstream MCP credential server-side.
      const a = await acct(accountOf(input) ?? process.env.CASDOOR_ACCOUNT);
      return gatewayMcpCall(
        { ...(input as unknown as McpCallInput), account: a.address },
        gatewaySigner(session, a),
      );
    }
    case 'wallet_gateway_status':
      return gatewayStatus();
    case 'wallet_gateway_logout':
      return gatewayLogout();

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ─── doctor preflight ─────────────────────────────────────────────────────────

async function doctor(): Promise<number> {
  const out = (s: string) => process.stdout.write(s + '\n');
  out(`${SERVER_NAME} doctor`);
  out(`version        : ${SERVER_VERSION}`);
  out('─'.repeat(40));

  const bins = resolveBins();
  out(`signing-server : ${bins.signingServer ?? '(MISSING)'}`);
  out(`ssp-util       : ${bins.sspUtil ?? '(MISSING)'}`);
  out(`wallet-cli     : ${bins.walletCli?.display ?? '(MISSING)'}`);

  const versions: Record<string, string> = {};
  if (bins.walletCli)
    versions['wallet-cli'] = await tryVersion(bins.walletCli.command, [
      ...bins.walletCli.prefixArgs,
      '--version',
    ]);
  if (bins.sspUtil) versions['ssp-util'] = await tryVersion(bins.sspUtil, ['--version']);
  if (bins.signingServer) versions['signing-server'] = await tryVersion(bins.signingServer, ['--version']);
  for (const [k, v] of Object.entries(versions)) out(`  ${k} version: ${v}`);

  const kek = resolveKekPolicy();
  out(`dev env        : ${isDevEnv() ? 'true (isDevEnv set)' : 'false'}`);
  if (kek.provider === 'env') {
    out('KEK provider   : env (persisted software KEK — forced via isDevEnv)');
  } else {
    // doctor runs without spawning SSP, so it can only predict; the actual
    // provider is settled at first session bring-up (see session_status).
    out('KEK provider   : auto (hardware-preferred)');
    out('               : will fall back to persisted software KEK if no hardware enclave is present');
  }

  const cfgPath = path.join(walletHome(), '.wallet-cli', 'config.json');
  out(`state root     : ${stateRoot()}`);
  out(`  keystore dir : ${keystoreDir()}`);
  out(`  wallet config: ${cfgPath}${existsSync(cfgPath) ? '' : ' (absent — seeded on first start)'}`);

  const loopback = await tcpReachable('127.0.0.1', 8080, 1500);
  out(`loopback 8080  : ${loopback ? 'reachable (SSP appears up)' : 'not reachable (normal when idle — SSP is lazy)'}`);

  const install = await detectInstall();
  const allowed = ['1', 'true'].includes((process.env[ALLOW_ENV] ?? '').toLowerCase());
  out(`install mode   : ${install.mode}${install.mode === 'global-linked' ? ` (symlink → ${install.packageDir})` : ''}`);
  out(`uninstall      : ${allowed ? `ENABLED (${ALLOW_ENV} set) — wallet_uninstall can delete keys` : `disabled (set ${ALLOW_ENV}=1 to enable)`}`);

  const script = locateInstallScript();
  const url = process.env.installationScriptUrl ?? process.env.WIKEY_INSTALL_SCRIPT_URL;
  out(`install script : ${script ?? (url ? `(none local — will download from ${url})` : '(not found — set installationScriptPath or installationScriptUrl)')}`);

  const ready = Boolean(bins.signingServer && bins.sspUtil && bins.walletCli);
  out('─'.repeat(40));
  out(ready ? 'READY: all binaries present.' : 'NOT READY: missing binaries (the server will try the install script on startup).');
  out('NOTE: all 4 components (signing-server, ssp-util, wallet-cli, this MCP) must be version-aligned per release; drift causes 403 / malformed-proof.');
  // doctor runs in the user's own terminal, which is the ONLY channel that
  // exists before a client has loaded the server (an npm postinstall banner
  // cannot do it — npm hides lifecycle output by default; see restartNotice.ts).
  // So the first-install restart rule is repeated here verbatim.
  out('');
  out(`${FIRST_INSTALL_RESTART_NOTICE}`);
  out('Once the client is up, ask your agent to call wallet_getting_started — it reports your exact next step.');
  return ready ? 0 : 1;
}

async function tryVersion(bin: string, args: string[]): Promise<string> {
  try {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const run = promisify(execFile);
    const { stdout, stderr } = await run(bin, args, { timeout: 5000 });
    return (stdout || stderr).trim().split('\n')[0] ?? '(unknown)';
  } catch {
    return '(unknown)';
  }
}

function tcpReachable(host: string, port: number, timeoutMs: number): Promise<boolean> {
  
  return new Promise((resolve) => {
    const s = createConnection({ host, port });
    const done = (v: boolean) => {
      s.destroy();
      resolve(v);
    };
    s.setTimeout(timeoutMs);
    s.on('connect', () => done(true));
    s.on('timeout', () => done(false));
    s.on('error', () => done(false));
  });
}

// ─── state-root config seeding ────────────────────────────────────────────────

/**
 * Seed wallet-cli's co-located config on first run only. The config lives under
 * the state root via the pinned HOME, alongside the SSP keystore, so both
 * survive a restart together (P2). If the config already exists we do not
 * re-seed it. signer.url is pinned to IPv4 loopback (SSP binds 127.0.0.1;
 * `localhost` may resolve to ::1 in a dual-stack container and refuse). This
 * internal call intentionally bypasses the tool-boundary config lock — the model
 * never reaches it.
 *
 * The config no longer holds a default-key pointer: which account a command acts
 * as is injected per child process (walletCliEnv). See clearDefaultKeyPointer
 * for what happens to the pointer an older install left behind.
 */
async function ensureWalletConfig(walletCli: WalletCliLauncher): Promise<void> {
  const cfgPath = path.join(walletHome(), '.wallet-cli', 'config.json');
  if (existsSync(cfgPath)) return; // already seeded — never clobber
  try {
    await runQuery({ walletCli, args: ['config', 'init'], env: walletCliEnv() });
    await runQuery({
      walletCli,
      args: ['config', 'set', 'signer.url', 'http://127.0.0.1:8080'],
      env: walletCliEnv(),
    });
    process.stderr.write(
      `[${SERVER_NAME}] seeded wallet-cli config under ${stateRoot()} (signer.url=http://127.0.0.1:8080).\n`,
    );
  } catch (e) {
    process.stderr.write(
      `[${SERVER_NAME}] warning: could not seed wallet-cli config: ${(e as Error).message}\n`,
    );
  }
}

// ─── main ───────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  if (process.argv[2] === 'doctor') {
    process.exit(await doctor());
  }

  const bins = await ensureBinaries(); // auto-install on startup if missing (logs to stderr)
  await ensureWalletConfig(bins.walletCli!); // co-locate wallet-cli's config (P2)

  // One-shot: blank a default-key pointer left by an older install. It cannot
  // route anything (the injected env wins over the file), but leaving it makes
  // wallet_config_show claim a default account that does not exist.
  const cleared = clearDefaultKeyPointer();
  if (cleared) {
    process.stderr.write(
      `[${SERVER_NAME}] cleared the legacy default-key pointer from wallet-cli config ` +
        `(user.address=${cleared.address ?? '""'}). This wallet has no default account: ` +
        `each call names the account it acts as.\n`,
    );
  }
  const session = new SessionManager({
    bins: {
      signingServer: bins.signingServer!,
      sspUtil: bins.sspUtil!,
      walletCli: bins.walletCli!,
    },
  });
  // WIKEY_SNAPSHOT_MAX_RESULT_BYTES: operator env (not agent-controllable) —
  // raises the per-response byte budget on hosts with larger tool-result
  // limits. The 4096 default stays below the smallest known host limit.
  const maxResultBytes = Number.parseInt(process.env.WIKEY_SNAPSHOT_MAX_RESULT_BYTES ?? '', 10);
  const cache = new SnapshotCache(
    Number.isFinite(maxResultBytes) && maxResultBytes > 0 ? { maxResultBytes } : {},
  );
  const deps: Deps = { session, cache, walletCli: bins.walletCli! };

  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {}, prompts: {} }, instructions: SERVER_INSTRUCTIONS },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

  // Prompts (Layer C): discoverable, user-initiated orientation entry points.
  server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: PROMPTS }));
  server.setRequestHandler(GetPromptRequestSchema, async (req) => {
    const { name } = req.params;
    if (!PROMPTS.some((p) => p.name === name)) throw new Error(`Unknown prompt: ${name}`);
    return { messages: promptMessages(name) };
  });

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args } = req.params;
    try {
      const result = await dispatch(deps, name, (args ?? {}) as Record<string, unknown>);
      const text = typeof result === 'string' ? result : JSON.stringify(result);
      return { content: [{ type: 'text', text }] };
    } catch (e) {
      // Scrub any secret before it crosses the boundary (H11). The HMAC key never
      // legitimately appears here; this is defensive against an unexpected echo.
      const msg = redact((e as Error).message ?? String(e));
      return { content: [{ type: 'text', text: msg }], isError: true };
    }
  });

  // Lifecycle: stdin-EOF / signals → shutdown (H9).
  const shutdown = () => {
    session.shutdown();
    process.exit(0);
  };
  process.stdin.on('end', shutdown);
  process.stdin.on('close', shutdown);
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  process.on('SIGHUP', shutdown);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`[${SERVER_NAME}] ready (stdio). ${tools.length} tools.\n`);
}

main().catch((e) => {
  process.stderr.write(`[${SERVER_NAME}] fatal: ${(e as Error).message}\n`);
  process.exit(1);
});
