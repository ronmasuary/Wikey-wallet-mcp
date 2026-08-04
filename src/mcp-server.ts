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
  resolveSignerArgs,
  buildPolicyQueue,
  buildEditHelpersQueue,
  assertConfigSetAllowed,
  buildGettingStarted,
  onboardSponsor,
  buildRecoveryDeeplink,
  parseRecoveryDeeplink,
  redact,
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
import { createRequireResolveVersion } from './version.js';

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

FIRST-RUN ONBOARDING IS A SEQUENCE — a brand-new user has nothing set up. Do it in order:
  1. Create a signing key            → wallet_keys_create { setDefault: true }
  2. Fund that key with OST gas       → the user sends OST to the key's address (required to broadcast anything)
  3. Create a safe + username         → wallet_tx_create_safe
  4. Then: add users, set policies, send assets, or enroll a gateway passkey.

WHENEVER the user asks "what can I do?", "what's next?", "help", "how do I start?",
or seems unsure — call wallet_getting_started FIRST. It inspects live state, reports
exactly which of the steps above they're on, and returns the precise next action.
Prefer it over guessing. Reads are free; signing lazily brings up the secure session.`;

// ─── Tool surface ───────────────────────────────────────────────────────────
// Full skill surface (32 tools) MINUS wallet_session_start (lazy) and
// wallet_hmac_rotate (automatic); KEEP read-only wallet_session_status; ADD B2's
// wallet_snapshot (index-only), wallet_snapshot_query, wallet_snapshot_page.
// wallet_snapshot is redefined: it returns the small index, NEVER raw JSON.

// Optional per-call signer override, shared by every signing tool that maps to a
// dynamic wallet-cli `tx` subcommand (all of them except `tx send`, which uses
// --from). Resolves to `--creator <addr> --pubkey <b64>`; omitted → config default.
const SIGNING_KEY_PROP = {
  type: 'string',
  description:
    'Optional omnistar1… key address to sign with. Omit to use the configured default key. Use to sign with a specific funded key when the default has drifted.',
} as const;

const tools = [
  // ── Orientation (Layer B) ──
  {
    name: 'wallet_getting_started',
    description:
      'START HERE. Read-only onboarding guide that answers "what can I do next?" / "help" / "how do I start?". Inspects live state (keys, default key, funding, safes), classifies the exact onboarding stage (no-key → no-default → unfunded → no-safe → ready), and returns { stage, summary, next[], capabilities?[] } where next[] names the precise tool to call for the next step. Call this before guiding a new or unsure user. Never signs, never brings up the secure session.',
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
    description: 'Get OST balance directly held by an address (use for gas/funding checks).',
    inputSchema: {
      type: 'object',
      properties: { address: { type: 'string', description: 'omnistar1... address' } },
      required: ['address'],
    },
  },
  {
    name: 'wallet_balances',
    description: 'Get all OST balances for an address.',
    inputSchema: {
      type: 'object',
      properties: { address: { type: 'string', description: 'omnistar1... address' } },
      required: ['address'],
    },
  },
  {
    name: 'wallet_account',
    description: 'Get account number and sequence for an address.',
    inputSchema: {
      type: 'object',
      properties: { address: { type: 'string', description: 'omnistar1... address' } },
      required: ['address'],
    },
  },
  {
    name: 'wallet_snapshot',
    description:
      "Take a snapshot of the profile's safes and return a SMALL INDEX only: { snapshotId, address, bytes, ts, safes:[{address,name,counts}], fields:{class:[key...]} }. The fields map lists which object payload keys each class carries (e.g. policy: conditions, applyOn) — use it to know what you can request, without guessing. The raw snapshot JSON is NEVER returned (it can exceed a host's tool-result limit and be silently truncated). Use the returned snapshotId with wallet_snapshot_query (enumerate/filter rows), wallet_snapshot_object (ONE object in full — governance state, conditions), or wallet_snapshot_page. Resolves SIGNATURE + parentGroup for delete-user / delete-policy. When address is omitted, uses the configured profile.",
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
      'Read ONE object from a cached snapshot COMPLETELY: the full object payload (e.g. policy conditions/applyOn, user public_key, transaction amount) plus name, isValid and process (process.currentPhase = governance state: approved vs pending votes). Use the index fields map from wallet_snapshot to discover which fields a class carries. Byte-budgeted: if the object is too large, the largest fields are dropped and NAMED in omittedFields:[{key,bytes}] — never a silent cut. Use this for depth on a single object; use wallet_snapshot_query to enumerate.',
    inputSchema: {
      type: 'object',
      properties: {
        snapshotId: { type: 'string', description: 'snapshotId from wallet_snapshot' },
        id: { type: 'string', description: 'Exact object id (from wallet_snapshot_query rows)' },
        safe: { type: 'string', description: 'Optional safe address (omnistar1...) to narrow the lookup' },
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
      'Get full asset portfolio of the safe (OST + cross-chain assets with smallCoin). Defaults to configured safe. smallCoin is the divisor for converting display amounts to smallest units for wallet_tx_create_transaction.',
    inputSchema: {
      type: 'object',
      properties: { address: { type: 'string', description: 'omnistar1... safe address (optional)' } },
    },
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
      'Generate a new keypair in the signing-server. Returns the new omnistar1... address. This is a signing operation — it lazily brings up the secure SSP session on first use.',
    inputSchema: {
      type: 'object',
      properties: { setDefault: { type: 'boolean', description: 'Set this key as the default' } },
    },
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
        signingKey: SIGNING_KEY_PROP,
      },
      required: ['username'],
    },
  },
  {
    name: 'wallet_onboard_sponsor',
    description:
      'Redeem an invitation link — the COMPLETE sponsored onboarding in one call. Use this whenever a user hands you an invitation/signup link and asks to redeem or use it. It (1) creates a signing key, (2) funds it from the sponsor grant behind the invite code (the invitee never funds anything), (3) creates their account + safe under the invite\'s username@organization handle, and (4) enrolls the wallet passkey to the gateway with the same code. Takes a few minutes for EITHER variant: the safe needs time to become queryable on-chain, and this tool waits for that before returning so its answer agrees with wallet_getting_started. Some invitations carry enroll=false — the fund-and-create-only variant: steps 1-3 run and step 4 is intentionally skipped (a passkey can be bound later with wallet_gateway_register). Stage "funded-created-enrolled" = fully done; "funded-created" = no-enroll invite, account ready on-chain, enrollment skipped by design; if either success stage comes back with a warning that the safe is not queryable yet, onboarding still SUCCEEDED — never call wallet_tx_create_safe to "fix" it (that would create a second safe on the funded key), just re-check in a few minutes; "created-enroll-failed" = on-chain work done, retry only wallet_gateway_register; "recovery-required" = the invite already onboarded an account. Safe to re-run with the same link: it RESUMES an interrupted onboarding on the already-funded key instead of creating a second identity.',
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
    description: 'Send OST directly between key addresses (not safe funds). Use for gas funding.',
    inputSchema: {
      type: 'object',
      properties: {
        from: { type: 'string', description: 'Sender omnistar1... address' },
        to: { type: 'string', description: 'Recipient omnistar1... address' },
        amount: { type: 'string', description: 'Amount with denom (e.g. 1000nost)' },
      },
      required: ['from', 'to', 'amount'],
    },
  },
  {
    name: 'wallet_tx_create_transaction',
    description:
      'Move assets out of a safe. Use this (not wallet_tx_send) when the safe holds the funds. amount must be in SMALLEST units (display value × smallCoin from wallet_assets).',
    inputSchema: {
      type: 'object',
      properties: {
        destination: { type: 'string', description: 'Safe address (omnistar1...)' },
        to: { type: 'string', description: 'Recipient address' },
        amount: { type: 'number', description: 'Amount in smallest units (display value × smallCoin)' },
        asset: { type: 'string', description: 'Asset symbol (e.g. BTC, USDC, OST)' },
        feePriority: { type: 'string', enum: ['low', 'medium', 'high'], description: 'Transaction fee priority' },
        tokenAddress: { type: 'string', description: 'ERC20 contract address (0x + 40 hex) — required for ERC20 assets' },
        chain: { type: 'string', enum: ['ethereum', 'polygon', 'base'], description: 'ERC20 chain — required for ERC20 assets' },
        smallCoin: { type: 'number', description: 'ERC20 token divisor — required for ERC20 assets' },
        signingKey: SIGNING_KEY_PROP,
      },
      required: ['destination', 'to', 'amount', 'asset', 'feePriority'],
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
        signingKey: SIGNING_KEY_PROP,
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
        signingKey: SIGNING_KEY_PROP,
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
        signingKey: SIGNING_KEY_PROP,
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
        signingKey: SIGNING_KEY_PROP,
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
        signingKey: SIGNING_KEY_PROP,
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
        signingKey: SIGNING_KEY_PROP,
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
        signingKey: SIGNING_KEY_PROP,
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
        signingKey: SIGNING_KEY_PROP,
      },
      required: ['destination', 'userId'],
    },
  },
  {
    name: 'wallet_recovery_helpers',
    description:
      "AUTHORITATIVE list of the account's recovery helpers — call this to answer \"who are the helpers / who can approve a recovery?\" instead of reading it off wallet_profile yourself. Helpers are exactly the `allowed_source` of the policy-allow-updateUserAddress policy, and EVERY entry counts (including any address Wikey added as a default recovery path). Returns { helpers:[{address,name}], count, threshold:{percentage, requiredCount, totalHelpers} }. The on-chain threshold is a PERCENTAGE of the total helper count, so `requiredCount` is the decoded number of approvals needed. Read-only; call it BEFORE wallet_tx_edit_helpers so you know the current helpers and how adding/removing rescales the threshold.",
    inputSchema: {
      type: 'object',
      properties: {
        address: { type: 'string', description: 'omnistar1... address (optional, uses config default)' },
      },
    },
  },
  {
    name: 'wallet_tx_edit_helpers',
    description:
      'Add/remove recovery helpers and set threshold. Helpers have no safe permissions — recovery only. Helpers are the `allowed_source` of policy-allow-updateUserAddress; call wallet_recovery_helpers FIRST to see the CURRENT helpers (existing/Wikey-added entries already count) before choosing a threshold. `threshold` is passed as an integer COUNT of helpers required, but is stored on-chain as a PERCENTAGE of the total, so adding/removing helpers rescales it (e.g. 1 of 2 helpers = 50%).',
    inputSchema: {
      type: 'object',
      properties: {
        addHelpers: { type: 'array', items: { type: 'string' }, description: 'Helper addresses/usernames to add' },
        removeHelpers: { type: 'array', items: { type: 'string' }, description: 'Helper addresses to remove (server resolves the numbered index)' },
        threshold: { type: 'number', description: 'Number of helpers required for recovery (integer count; stored on-chain as a percentage of total helpers)' },
        signingKey: SIGNING_KEY_PROP,
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
        address: { type: 'string', description: 'Override config user.address' },
        url: { type: 'string', description: 'Override config wikeyAuthUrl' },
      },
      required: [],
    },
  },

  // ── Casdoor / gateway IDP (wallet-passkey login) ──
  {
    name: 'wallet_gateway_register',
    description:
      "Enroll this wallet's passkey with a Casdoor/gateway IdP, binding it to the wallet's SAFE (recovery-proof). The realistic path is an invited employee: pass `invite` (the invitation link) and nothing else — the agent derives host/application/organization/pinned-username and the public clientId/redirectUri from the link, signs up with the invitation code (the one-time secret), and binds the passkey. Existing users without an invite: pass explicit fields + `password`. Requires a default key whose profile has a safe with an EC public key (assets.ecPuk). Persists the target + credential under the state root. Does NOT sign any on-chain tx.",
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

// Loose coercion of the optional `fields` tool arg ('*' | string[]).
function parseFields(v: unknown): FieldSelector | undefined {
  if (v === '*') return '*';
  if (Array.isArray(v)) return v.map(String);
  return undefined;
}

async function dispatch(deps: Deps, name: string, input: Record<string, unknown>): Promise<unknown> {
  const { session, cache, walletCli } = deps;
  // Every wallet-cli read runs with HOME pinned to the state root so it reads the
  // SAME co-located config (default-key pointer) the signing paths write (P2).
  const query = (args: string[]) => runQuery({ walletCli, args, env: walletCliEnv() });

  switch (name) {
    // ── orientation ──
    case 'wallet_getting_started':
      // Keys are counted from the keystore directory (listKeystoreAddresses),
      // never via the signer — so an idle SSP session is never misread as no-key.
      return buildGettingStarted(query, SERVER_NAME, listKeystoreAddresses);

    // ── reads ──
    case 'wallet_chain_info':
      return query(['query', 'chain-info']);
    case 'wallet_balance':
      return query(['query', 'balance', '--address', String(input.address)]);
    case 'wallet_balances':
      return query(['query', 'balances', '--address', String(input.address)]);
    case 'wallet_account':
      return query(['query', 'account', '--address', String(input.address)]);
    case 'wallet_profile': {
      const args = ['query', 'profile'];
      if (input.address) args.push('--address', String(input.address));
      return query(args);
    }
    case 'wallet_assets': {
      const args = ['query', 'assets'];
      if (input.address) args.push('--address', String(input.address));
      return query(args);
    }

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
      return cache.object(
        String(input.snapshotId),
        String(input.id),
        input.safe ? { safe: String(input.safe) } : {},
      );
    }

    // ── keys ──
    case 'wallet_keys_list':
      return query(['keys', 'list']);
    case 'wallet_keys_get':
      return query(['keys', 'get', '--id', String(input.id)]);
    case 'wallet_keys_create': {
      // keys create signs over the signer's HTTP API (no stdin proof) and ends
      // with a `Set as default? (y/n)` prompt. Answer it (y/n from setDefault)
      // so wallet-cli prints its JSON result and exits. Run it session-gated —
      // NOT via the prompt engine, which would deadlock on that y/n and time out
      // even though the key was already created.
      return session.runWithSession(['keys', 'create'], { input: input.setDefault ? 'y\n' : 'n\n' });
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
      const signer = await resolveSignerArgs(query, input.signingKey);
      return session.signPrompted(['tx', 'create-safe', '--username', String(input.username), '--broadcast', ...signer], []);
    }
    case 'wallet_onboard_sponsor': {
      const result = await onboardSponsor(String(input.invite), {
        query,
        // keys create signs over the signer HTTP API and ends with a y/n default
        // prompt — answer 'y' via runWithSession (same as wallet_keys_create).
        createDefaultKey: () => session.runWithSession(['keys', 'create'], { input: 'y\n' }),
        // Sign with the onboarded address EXPLICITLY (--creator/--pubkey) rather
        // than the ambient default: a resumed run adopts the previously funded
        // key, which is not necessarily what user.address points at.
        createSafe: async (username, allowOrg, address) => {
          const signer = await resolveSignerArgs(query, address);
          const args = ['tx', 'create-safe', '--username', username, '--broadcast', ...signer];
          if (allowOrg) args.push('--allow-org-username');
          return session.signPrompted(args, []);
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
      // The signer for a bank send is the --from key (you can only spend your own
      // funds), so resolve --from's pubkey and pass --pubkey. Without it wallet-cli
      // signs with the config default key regardless of --from. `send` has no
      // --creator option (it derives creator from --from), so pubkey-only here.
      const signer = await resolveSignerArgs(query, input.from, { pubkeyOnly: true });
      return session.signPrompted(
        ['tx', 'send', '--from', String(input.from), '--to', String(input.to), '--amount', String(input.amount), '--broadcast', ...signer],
        [],
      );
    }
    case 'wallet_tx_create_transaction': {
      const { destination, to, amount, asset, feePriority, tokenAddress, chain, smallCoin } = input as {
        destination: string; to: string; amount: number; asset: string; feePriority: string;
        tokenAddress?: string; chain?: string; smallCoin?: number;
      };
      const args = [
        'tx', 'create-transaction',
        '--destination', destination,
        '--to', to,
        '--amount', amount.toString(),
        '--asset', asset,
        '--fee-priority', feePriority,
      ];
      if (tokenAddress) args.push('--token-address', tokenAddress);
      if (chain) args.push('--chain', chain);
      if (smallCoin !== undefined) args.push('--small-coin', smallCoin.toString());
      args.push('--broadcast');
      args.push(...(await resolveSignerArgs(query, input.signingKey)));
      return session.signPrompted(args, []);
    }
    case 'wallet_tx_vote': {
      const signer = await resolveSignerArgs(query, input.signingKey);
      return session.signPrompted(
        ['tx', 'vote', '--destination', String(input.destination), '--vote', String(input.vote), '--signature', String(input.signature), '--broadcast', ...signer],
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
      const signer = await resolveSignerArgs(query, input.signingKey);
      const args = ['tx', 'request-recovery', '--username', resolved, '--broadcast', ...signer];
      // Sponsor/org accounts carry a username@organization handle; recovery must
      // opt into the same @-tolerant validation create-safe uses, or wallet-cli
      // rejects the '@' before signing.
      if (resolved.includes('@')) args.push('--allow-org-username');
      const tx = await session.signPrompted(args, []);

      // Hand the requester a deeplink to forward to a recovery helper. pk = the
      // NEW key the account is being recovered onto (the signer); tn = the
      // account asking for help (the username being recovered).
      let newAccount = input.signingKey ? String(input.signingKey) : '';
      if (!newAccount) {
        try {
          newAccount =
            (JSON.parse(await query(['config', 'get', 'user.address'])) as { data?: { value?: string } })
              ?.data?.value ?? '';
        } catch {
          /* address unresolved — deeplink omitted below */
        }
      }
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
      return JSON.stringify(
        {
          tx: txResult,
          recoveryDeeplink,
          shareWithHelpers: recoveryDeeplink
            ? `Send this link to a recovery helper. They can open it in the Wikey wallet app, or hand it to their own AI agent (wikey-wallet MCP) to approve recovering "${resolved}" onto your new key.`
            : `Recovery requested for "${resolved}", but the new account address could not be resolved to build a helper deeplink.`,
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
      const signer = await resolveSignerArgs(query, input.signingKey);
      return session.signPrompted(
        ['tx', 'approve-recovery', '--oldaccount', oldAccount, '--newaccount', newAccount, '--broadcast', ...signer],
        [],
      );
    }
    case 'wallet_tx_create_policy': {
      const typed = input as { destination: string; applyOn: string; conditions: PolicyCondition[]; name?: string; description?: string };
      const signer = await resolveSignerArgs(query, input.signingKey);
      return session.signPrompted(
        ['tx', 'create-policy', '--destination', typed.destination, '--apply-on', typed.applyOn, '--broadcast', ...signer],
        buildPolicyQueue(typed),
      );
    }
    case 'wallet_tx_edit_policy': {
      const typed = input as { destination: string; policyId: string; signature: string; applyOn: string; conditions: PolicyCondition[]; name?: string; description?: string };
      const signer = await resolveSignerArgs(query, input.signingKey);
      return session.signPrompted(
        ['tx', 'edit-policy', '--destination', typed.destination, '--policy-id', typed.policyId, '--signature', typed.signature, '--apply-on', typed.applyOn, '--broadcast', ...signer],
        buildPolicyQueue(typed),
      );
    }
    case 'wallet_tx_delete_policy': {
      const { destination, policyId } = input as { destination: string; policyId: string };
      const snapshot = parseSnapshot(await query(['query', 'snapshot']));
      const safe = findSafe(snapshot, destination);
      const { signature, parentGroup } = resolvePolicyDeletion({ destination, policyId, safe });
      const signer = await resolveSignerArgs(query, input.signingKey);
      return session.signPrompted(
        ['tx', 'delete-policy', '--destination', destination, '--policy-id', policyId, '--signature', signature, '--parent-group', parentGroup, '--broadcast', ...signer],
        [],
      );
    }
    case 'wallet_tx_create_user': {
      const { destination, user, group } = input as { destination: string; user: string; group?: string };
      if (!user.startsWith('omnistar1')) throw new Error('user must be an omnistar1… address');
      const snapshot = parseSnapshot(await query(['query', 'snapshot']));
      const safe = findSafe(snapshot, destination);
      const parentGroup = resolveCreateUserTarget({ destination, group, groups: extractGroupsFromSafe(safe) });
      const signer = await resolveSignerArgs(query, input.signingKey);
      return session.signPrompted(
        ['tx', 'create-user', '--destination', destination, '--public-key', user, '--parent-group', parentGroup, '--broadcast', ...signer],
        [],
      );
    }
    case 'wallet_tx_delete_user': {
      const { destination, userId } = input as { destination: string; userId: string };
      const snapshot = parseSnapshot(await query(['query', 'snapshot']));
      const safe = findSafe(snapshot, destination);
      const { signature, parentGroup } = resolveUserDeletion({ destination, userId, safe });
      const signer = await resolveSignerArgs(query, input.signingKey);
      return session.signPrompted(
        ['tx', 'delete-user', '--destination', destination, '--user-id', userId, '--signature', signature, '--parent-group', parentGroup, '--broadcast', ...signer],
        [],
      );
    }
    case 'wallet_recovery_helpers':
      return query(['query', 'helpers', ...(input.address ? ['--address', String(input.address)] : [])]);
    case 'wallet_tx_edit_helpers': {
      const { addHelpers = [], removeHelpers = [], threshold } = input as { addHelpers?: string[]; removeHelpers?: string[]; threshold: number };
      const signer = await resolveSignerArgs(query, input.signingKey);

      // Read a config value via the wallet-cli read runner (reads are never locked).
      const cfgGet = async (key: string): Promise<string> => {
        try {
          const j = JSON.parse(await query(['config', 'get', key])) as { data?: { value?: string } };
          return j?.data?.value ?? '';
        } catch {
          return '';
        }
      };
      // The account whose helpers we're editing = the signer. Default key unless a
      // per-call signingKey routes elsewhere.
      const creator = input.signingKey ? String(input.signingKey) : await cfgGet('user.address');

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
        // (`notification configure` always signs with the default key.)
        await session.signPrompted(['notification', 'configure', '--inbox', creator], []);
      }

      // Isolated signing #2 — the helper tx.
      return session.signPrompted(['tx', 'edit-helpers', '--broadcast', ...signer], buildEditHelpersQueue(addHelpers, removeHelpers, threshold));
    }
    case 'wallet_notification_configure': {
      const { email, sms, webhook, telegram, push, address, url } = input as Record<string, string | undefined>;
      const args = ['notification', 'configure'];
      if (email) args.push('--email', email);
      if (sms) args.push('--sms', sms);
      if (webhook) args.push('--webhook', webhook);
      if (telegram) args.push('--telegram', telegram);
      if (push) args.push('--push', push);
      if (address) args.push('--address', address);
      if (url) args.push('--url', url);
      args.push('--sign');
      return session.signPrompted(args, []);
    }

    // ── Casdoor / gateway IDP ──
    case 'wallet_gateway_register':
      return gatewayRegister(input as RegisterInput);
    case 'wallet_gateway_login': {
      // Inject the two signing verbs the login needs. Both ride the standard
      // prompt/proof flow through SSP (empty queue), so the HMAC key + private key
      // stay sealed in the session — only the signed artifacts cross back here.
      const signer: LoginSigner = {
        signChallenge: (challengeHex: string) =>
          session.signPrompted(['keys', 'sign-challenge', '--challenge', challengeHex], []),
        createFidoObject: ({ safe, uuid, payloadHex }) =>
          session.signPrompted(
            ['tx', 'create-fido-object', '--destination', safe, '--id', uuid, '--payload', payloadHex, '--broadcast'],
            [],
          ),
      };
      return gatewayLogin(input as LoginInput, signer);
    }
    case 'wallet_gateway_api_call': {
      // Same injected signer: a fresh login (when no accessToken is passed) needs
      // to sign the on-chain FIDO object + the assertion via the sealed session.
      const signer: LoginSigner = {
        signChallenge: (challengeHex: string) =>
          session.signPrompted(['keys', 'sign-challenge', '--challenge', challengeHex], []),
        createFidoObject: ({ safe, uuid, payloadHex }) =>
          session.signPrompted(
            ['tx', 'create-fido-object', '--destination', safe, '--id', uuid, '--payload', payloadHex, '--broadcast'],
            [],
          ),
      };
      return gatewayApiCall(input as unknown as ApiCallInput, signer);
    }
    case 'wallet_gateway_mcp_call': {
      // Same injected signer as api_call: a fresh login (when no accessToken is
      // passed) signs the on-chain FIDO object + assertion via the sealed session.
      // The passkey JWT is the ONLY credential sent — the aggregator injects the
      // upstream MCP credential server-side.
      const signer: LoginSigner = {
        signChallenge: (challengeHex: string) =>
          session.signPrompted(['keys', 'sign-challenge', '--challenge', challengeHex], []),
        createFidoObject: ({ safe, uuid, payloadHex }) =>
          session.signPrompted(
            ['tx', 'create-fido-object', '--destination', safe, '--id', uuid, '--payload', payloadHex, '--broadcast'],
            [],
          ),
      };
      return gatewayMcpCall(input as unknown as McpCallInput, signer);
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

  const script = locateInstallScript();
  const url = process.env.installationScriptUrl ?? process.env.WIKEY_INSTALL_SCRIPT_URL;
  out(`install script : ${script ?? (url ? `(none local — will download from ${url})` : '(not found — set installationScriptPath or installationScriptUrl)')}`);

  const ready = Boolean(bins.signingServer && bins.sspUtil && bins.walletCli);
  out('─'.repeat(40));
  out(ready ? 'READY: all binaries present.' : 'NOT READY: missing binaries (the server will try the install script on startup).');
  out('NOTE: all 4 components (signing-server, ssp-util, wallet-cli, this MCP) must be version-aligned per release; drift causes 403 / malformed-proof.');
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
 * Seed wallet-cli's co-located config on first run only. The config (the
 * default-key pointer, user.address/pubkey) lives under the state root via the
 * pinned HOME, alongside the SSP keystore — so they survive a restart together
 * and cannot desync (P2). If the config already exists we NEVER touch it, which
 * preserves the default-key pointer across restarts. signer.url is pinned to
 * IPv4 loopback (SSP binds 127.0.0.1; `localhost` may resolve to ::1 in a
 * dual-stack container and refuse). This internal call intentionally bypasses
 * the tool-boundary config lock — the model never reaches it.
 */
async function ensureWalletConfig(walletCli: WalletCliLauncher): Promise<void> {
  const cfgPath = path.join(walletHome(), '.wallet-cli', 'config.json');
  if (existsSync(cfgPath)) return; // existing pointer — never clobber
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
  await ensureWalletConfig(bins.walletCli!); // co-locate the default-key pointer (P2)
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
