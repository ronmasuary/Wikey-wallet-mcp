// Prompt-driven signing runner + prompt-queue builders (H1). Ported from the
// skill (index.ts:163-387). The dual timeout (per-prompt 30s + overall 120s),
// the ANSI-strip + sliding stderr window prompt matching, and the stdin-end
// discipline (end() ONLY after the proof; ordinary prompts write without end())
// are all load-bearing — getting stdin-end wrong reproduces the original
// 60s-hang bug.
//
// Change vs. the skill: the HMAC key is a sealed Buffer passed straight through
// to computeProof (never a JS string in this module).

import { spawn } from 'node:child_process';

import type { WalletCliLauncher } from './binPaths.js';
import { computeProof, parseSignRequest } from './proof.js';

const ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]/g;

export type PromptStep = { match: string; respond: () => string };

export interface PromptedOpts {
  perPromptMs?: number;
  overallMs?: number;
}

export interface RunSigningOpts {
  walletCli: WalletCliLauncher;
  sspUtil: string;
  nonceFile: string;
  /** Sealed HMAC key bytes. Forwarded to computeProof; never stringified here. */
  key: Buffer;
  args: string[];
  queue: PromptStep[] | ((all: string) => PromptStep[]);
  opts?: PromptedOpts;
  proofTimeoutMs?: number;
  /** Child env (e.g. HOME pinned to the state root to co-locate config). */
  env?: NodeJS.ProcessEnv;
}

export async function runSigningPrompted(o: RunSigningOpts): Promise<string> {
  const perPromptMs = o.opts?.perPromptMs ?? 30_000;
  const overallMs = o.opts?.overallMs ?? 120_000;
  const isFn = typeof o.queue === 'function';

  return new Promise<string>((resolve, reject) => {
    const child = spawn(o.walletCli.command, [...o.walletCli.prefixArgs, ...o.args], {
      stdio: ['pipe', 'pipe', 'pipe'],
      ...(o.env ? { env: o.env } : {}),
    });

    let stderrWindow = '';
    let allStderr = '';
    let stdout = '';
    let proofSent = false;
    let queueIdx = 0;
    let settled = false;
    let promptTimer: ReturnType<typeof setTimeout> | null = null;

    function settle(fn: () => void) {
      if (settled) return;
      settled = true;
      clearTimeout(overallTimer);
      if (promptTimer) clearTimeout(promptTimer);
      fn();
    }

    function fail(err: Error) {
      try {
        child.kill('SIGTERM');
      } catch {
        /* ignore */
      }
      settle(() => reject(err));
    }

    function getStep(): PromptStep | null {
      const steps = isFn
        ? (o.queue as (all: string) => PromptStep[])(allStderr)
        : (o.queue as PromptStep[]);
      return steps[queueIdx] ?? null;
    }

    function armPromptTimer() {
      if (promptTimer) clearTimeout(promptTimer);
      const step = getStep();
      if (!step) {
        promptTimer = null;
        return;
      }
      promptTimer = setTimeout(() => {
        fail(
          new Error(
            `runSigningPrompted stuck waiting: "${step.match}". Last stderr:\n${allStderr.slice(-400)}`,
          ),
        );
      }, perPromptMs);
    }

    function respond(step: PromptStep) {
      let payload: string;
      try {
        payload = step.respond();
      } catch (e) {
        fail(e as Error);
        return;
      }
      stderrWindow = '';
      child.stdin.write(payload);
      queueIdx++;
      armPromptTimer();
    }

    const overallTimer = setTimeout(() => {
      fail(
        new Error(
          `runSigningPrompted overall timeout after ${overallMs / 1000}s. Last stderr:\n${allStderr.slice(-400)}`,
        ),
      );
    }, overallMs);

    armPromptTimer();

    child.stderr.on('data', async (chunk: Buffer) => {
      const s = chunk.toString().replace(ANSI_RE, '');
      stderrWindow += s;
      allStderr += s;
      if (settled) return;

      if (!proofSent) {
        const req = parseSignRequest(allStderr);
        if (req) {
          proofSent = true;
          if (promptTimer) {
            clearTimeout(promptTimer);
            promptTimer = null;
          }
          try {
            const proof = await computeProof({
              sspUtil: o.sspUtil,
              nonceFile: o.nonceFile,
              key: o.key,
              unsignedData: req.unsignedData,
              signingPubKey: req.signingPubKey,
              timeoutMs: o.proofTimeoutMs,
            });
            // stdin-end discipline: end() ONLY after the proof.
            child.stdin.write(proof + '\n');
            child.stdin.end();
          } catch (e) {
            fail(e as Error);
          }
          return;
        }
      }

      while (!settled) {
        const step = getStep();
        if (!step) break;
        if (!stderrWindow.includes(step.match)) break;
        respond(step);
      }
    });

    child.stdout.on('data', (c: Buffer) => {
      stdout += c.toString();
    });

    child.on('close', (code: number | null) => {
      if (settled) return;
      if (code === 0) {
        settle(() => resolve(stdout.trim()));
        return;
      }
      let detail = allStderr.slice(-500);
      try {
        const j = JSON.parse(stdout.trim()) as Record<string, unknown>;
        const e = j?.error as Record<string, unknown> | undefined;
        detail = (e?.message as string) ?? (j?.message as string) ?? detail;
      } catch {
        /* use allStderr tail */
      }
      settle(() => reject(new Error(`wallet-cli exit ${code}: ${detail}`)));
    });

    child.on('error', (e: Error) => fail(e));
  });
}

// ─── Signer key lookup ───────────────────────────────────────────────────────────

/**
 * The base64 public key of a keystore address, via `keys get` over the signer's
 * HTTP API. The keystore filename carries a key's ADDRESS but not its pubkey, so
 * this is the only way to obtain one — and it needs the SSP session up (callers
 * that may run cold must `ensureSession()` first). Without that, a cold session
 * fails here with a bare `fetch failed` naming neither the session nor the key.
 *
 * Used by `resolveAccount` (accounts.ts), which feeds both routings: the child
 * env (`WALLET_ADDRESS`/`WALLET_PUBKEY`) and the `--creator/--pubkey` flags.
 */
export async function fetchPubkey(
  query: (args: string[]) => Promise<string>,
  address: string,
): Promise<string> {
  const raw = await query(['keys', 'get', '--id', address]);
  let pubkey: string | undefined;
  try {
    const j = JSON.parse(raw) as { success?: boolean; data?: { pubkeyBase64?: string } };
    pubkey = j?.data?.pubkeyBase64;
  } catch {
    throw new Error(`signingKey ${address}: could not parse keys-get output to resolve its pubkey`);
  }
  if (!pubkey) throw new Error(`signingKey ${address}: no pubkey found (is the key present in the signer?)`);
  return pubkey;
}

// ─── Profile helper ─────────────────────────────────────────────────────────────

export function extractUsernameFromProfile(raw: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`failed to parse profile JSON. Raw tail: ${raw.slice(-200)}`);
  }
  const root = parsed as { data?: { profile?: { name?: unknown } }; profile?: { name?: unknown } };
  const name = root?.data?.profile?.name ?? root?.profile?.name;
  if (typeof name !== 'string' || name.length === 0) {
    throw new Error('profile.name not found in query profile response');
  }
  return name;
}

// ─── Policy types + prompt queue ─────────────────────────────────────────────────

export interface PolicyCondition {
  type: string;
  votingQty?: number;
  minAmount?: number;
  maxAmount?: number;
  symbols?: string[];
}

export function buildPolicyQueue(opts: {
  applyOn: string;
  conditions: PolicyCondition[];
  name?: string;
  description?: string;
}): PromptStep[] {
  const classes = opts.applyOn.split(',').map((s) => s.trim().toLowerCase());
  const onlyTx = classes.length === 1 && classes[0] === 'transaction';

  const menuMap: Record<string, number> = { voting: 1 };
  if (onlyTx) {
    menuMap['amount'] = 2;
    menuMap['symbols'] = 3;
  }

  const selected = opts.conditions
    .map((c) => ({ c, idx: menuMap[c.type.toLowerCase()] }))
    .filter((x): x is { c: PolicyCondition; idx: number } => x.idx !== undefined)
    .sort((a, b) => a.idx - b.idx);

  const steps: PromptStep[] = [
    { match: 'Your selection', respond: () => selected.map((x) => x.idx).join(',') + '\n' },
  ];

  for (const { c } of selected) {
    const t = c.type.toLowerCase();
    if (t === 'voting') {
      steps.push({ match: 'Enter voting quantity', respond: () => (c.votingQty ?? 0).toString() + '\n' });
    } else if (t === 'amount') {
      steps.push({ match: 'Enter minimum amount', respond: () => (c.minAmount ?? 0).toString() + '\n' });
      steps.push({ match: 'Enter maximum amount', respond: () => (c.maxAmount ?? 0).toString() + '\n' });
    } else if (t === 'symbols') {
      steps.push({
        match: 'Enter symbols (comma-separated',
        respond: () => (c.symbols ?? []).join(',') + '\n',
      });
    }
  }

  steps.push({ match: 'Enter policy name (optional', respond: () => (opts.name ?? '') + '\n' });
  steps.push({
    match: 'Enter policy description (optional',
    respond: () => (opts.description ?? '') + '\n',
  });
  return steps;
}

export function buildEditHelpersQueue(
  addHelpers: string[],
  removeHelpers: string[],
  threshold: number,
): (all: string) => PromptStep[] {
  return (all: string): PromptStep[] => {
    const steps: PromptStep[] = [];

    if (addHelpers.length === 0) {
      steps.push({ match: 'Would you like to add a helper?', respond: () => 'n\n' });
    } else {
      steps.push({ match: 'Would you like to add a helper?', respond: () => 'y\n' });
      for (let i = 0; i < addHelpers.length; i++) {
        const addr = addHelpers[i]!;
        steps.push({ match: 'Enter helper address or username', respond: () => addr + '\n' });
        const isLast = i === addHelpers.length - 1;
        steps.push({
          match: 'Would you like to add another helper?',
          respond: () => (isLast ? 'n\n' : 'y\n'),
        });
      }
    }

    if (removeHelpers.length === 0) {
      steps.push({ match: 'Would you like to remove a helper?', respond: () => 'n\n' });
    } else {
      steps.push({ match: 'Would you like to remove a helper?', respond: () => 'y\n' });
      for (let i = 0; i < removeHelpers.length; i++) {
        const target = removeHelpers[i]!;
        steps.push({
          match: 'Enter the number of the helper to remove',
          respond: () => {
            const matches = [...all.matchAll(/^\s*(\d+)[.)]\s*(.+)$/gm)];
            const list = matches.map((m) => m[2]!.trim());
            const idx = list.findIndex((h) => h.toLowerCase().includes(target.toLowerCase()));
            if (idx === -1) {
              throw new Error(`helper not found in list: "${target}". Available: ${list.join(', ')}`);
            }
            return (idx + 1).toString() + '\n';
          },
        });
        const isLast = i === removeHelpers.length - 1;
        steps.push({
          match: 'Would you like to remove another helper?',
          respond: () => (isLast ? 'n\n' : 'y\n'),
        });
      }
    }

    steps.push({
      match: 'Enter threshold (number of helpers required,',
      respond: () => threshold.toString() + '\n',
    });

    return steps;
  };
}

// ─── name → address, via the SHIPPED edit-helpers resolver ───────────────────
//
// wallet-cli owns exactly one resolver, `ApiClient.resolveUsername`
// (GET /users/accounts/getAccountByName). It is a library method, not a CLI
// surface — no subcommand exposes it, and the package entry point is the
// commander program itself, so a spawning caller cannot import it. `tx
// edit-helpers` is the one shipped command that reaches it from stdin: it
// resolves whatever is typed at its "Enter helper address or username" prompt.
// So we drive that command as far as the resolution and stop.
//
// WHY THIS IS A READ DESPITE LIVING ON A `tx` COMMAND. The tx pipeline runs the
// command's `resolve` hook — where the prompts and the lookup happen — BEFORE it
// fetches signer info, resolves a fee, or builds any message (wallet-cli
// src/cli/commands/tx.ts: executeMultiMessage precedes getSignerInfo). We spawn
// with neither --sign nor --broadcast, answer only the prompts up to the
// resolution, and SIGTERM the child before the threshold prompt. Nothing is
// built, signed or broadcast. The "add" exists in that child's memory for a few
// hundred milliseconds and dies with it.
//
// It is a PLAIN spawn, not runSigningPrompted: no HMAC key, no nonce, no SSP.
// The session is never woken, which is what keeps this a free read.

/** `  1. alice@acme (omnistar1…)` — one row of wallet-cli's displayHelpers(). */
const HELPER_LINE_RE = /^\s*\d+[.)]\s*(.+?)\s*\(\s*(omnistar1[0-9a-z]+)\s*\)\s*$/gm;

/** Printed instead of a new row when the name resolves to an EXISTING helper. */
const ALREADY_RE = /Helper\s+(omnistar1[0-9a-z]+)\s+is already in the list/i;

const ADD_PROMPT = 'Would you like to add a helper?';
const NAME_PROMPT = 'Enter helper address or username';
const ANOTHER_PROMPT = 'Would you like to add another helper?';

export interface ProbedHelper {
  name: string;
  address: string;
}

/** Every `N. name (address)` row anywhere in a chunk of wallet-cli stderr. */
export function parseHelperLines(text: string): ProbedHelper[] {
  return Array.from(text.matchAll(HELPER_LINE_RE)).map((m) => ({
    name: m[1]!.trim(),
    address: m[2]!,
  }));
}

/**
 * The address wallet-cli resolved `asked` to, read off the before/after stderr.
 *
 * Three independent signals, because the display degrades in ways that each
 * defeat one of them on its own:
 *
 *  1. "Helper <addr> is already in the list" — the name resolved to an address
 *     that is ALREADY a helper, so no new row is printed. The message itself
 *     carries the answer.
 *  2. Set difference: the row present after our input and absent before it.
 *     Survives the case where the helper's own profile lookup fails and the CLI
 *     falls back to printing the ADDRESS as the name.
 *  3. Name match, last resort.
 *
 * Returns null when nothing resolved — the caller reports that as an error, not
 * as an empty answer.
 */
export function pickResolvedAddress(
  beforeText: string,
  afterText: string,
  asked: string,
): string | null {
  const already = ALREADY_RE.exec(afterText);
  if (already) return already[1]!;

  const before = new Set(parseHelperLines(beforeText).map((h) => h.address));
  const added = parseHelperLines(afterText).find((h) => !before.has(h.address));
  if (added) return added.address;

  const byName = parseHelperLines(afterText).find(
    (h) => h.name.toLowerCase() === asked.trim().toLowerCase(),
  );
  return byName ? byName.address : null;
}

export interface ResolveNameOpts {
  walletCli: WalletCliLauncher;
  /** Local account to act as — wallet-cli reads ITS profile before prompting. */
  creator: string;
  /** The account name to resolve. */
  name: string;
  env?: NodeJS.ProcessEnv;
  opts?: PromptedOpts;
}

export interface ResolvedName {
  name: string;
  address: string;
}

/**
 * Resolve an account NAME to its address through the shipped `tx edit-helpers`
 * resolver. Read-only — see the block comment above for why a `tx` command is
 * safe here.
 *
 * A name that does not exist surfaces wallet-cli's own UsernameNotFoundError
 * (the command aborts inside the resolve hook, before anything is built). It is
 * never degraded into an empty or absent answer.
 */
export async function resolveNameViaEditHelpers(o: ResolveNameOpts): Promise<ResolvedName> {
  const perPromptMs = o.opts?.perPromptMs ?? 30_000;
  const overallMs = o.opts?.overallMs ?? 60_000;
  const asked = o.name.trim();

  return new Promise<ResolvedName>((resolve, reject) => {
    const child = spawn(
      o.walletCli.command,
      [...o.walletCli.prefixArgs, 'tx', 'edit-helpers', '--creator', o.creator],
      { stdio: ['pipe', 'pipe', 'pipe'], ...(o.env ? { env: o.env } : {}) },
    );

    let all = '';
    let stdout = '';
    let beforeText = '';
    let stage: 0 | 1 | 2 | 3 = 0;
    let settled = false;
    let stageTimer: ReturnType<typeof setTimeout> | null = null;

    function settle(fn: () => void): void {
      if (settled) return;
      settled = true;
      clearTimeout(overallTimer);
      if (stageTimer) clearTimeout(stageTimer);
      fn();
    }

    /** Abort the child. Nothing was built or signed — see the block comment. */
    function stop(): void {
      try {
        child.kill('SIGTERM');
      } catch {
        /* already gone */
      }
    }

    function fail(err: Error): void {
      stop();
      settle(() => reject(err));
    }

    function armStageTimer(): void {
      if (stageTimer) clearTimeout(stageTimer);
      if (stage > 2) {
        stageTimer = null;
        return;
      }
      const label = stage === 0 ? ADD_PROMPT : stage === 1 ? NAME_PROMPT : ANOTHER_PROMPT;
      stageTimer = setTimeout(() => {
        fail(
          new Error(`name resolution stuck waiting: "${label}". Last stderr:\n${all.slice(-400)}`),
        );
      }, perPromptMs);
    }

    const overallTimer = setTimeout(() => {
      fail(new Error(`name resolution overall timeout after ${overallMs / 1000}s`));
    }, overallMs);
    armStageTimer();

    child.stdin.on('error', () => {
      /* the child may exit first — ignore EPIPE */
    });
    child.on('error', (e) => fail(e));

    child.stderr.on('data', (chunk: Buffer) => {
      all += chunk.toString().replace(ANSI_RE, '');
      if (settled) return;

      if (stage === 0 && all.includes(ADD_PROMPT)) {
        // Snapshot the helper rows as they stand BEFORE our input adds one.
        beforeText = all;
        stage = 1;
        child.stdin.write('y\n');
        armStageTimer();
        return;
      }

      if (stage === 1 && all.includes(NAME_PROMPT)) {
        stage = 2;
        child.stdin.write(asked + '\n');
        armStageTimer();
        return;
      }

      if (stage === 2 && (all.includes(ANOTHER_PROMPT) || ALREADY_RE.test(all))) {
        // The refreshed list is out; everything we came for is on stderr. Stop
        // HERE — before the threshold prompt, before the transaction is built.
        stage = 3;
        const address = pickResolvedAddress(beforeText, all, asked);
        stop();
        if (!address) {
          settle(() =>
            reject(
              new Error(
                `wallet-cli accepted "${asked}" but printed no address for it. Last stderr:\n${all.slice(-400)}`,
              ),
            ),
          );
          return;
        }
        settle(() => resolve({ name: asked, address }));
      }
    });

    child.stdout.on('data', (c: Buffer) => {
      stdout += c.toString();
    });

    child.on('close', (code: number | null) => {
      if (settled) return;
      // Exiting before we have an answer means the command aborted — usually
      // wallet-cli's UsernameNotFoundError for a name that does not exist.
      // Surface ITS message; never turn this into an empty answer.
      let detail = all.slice(-500);
      try {
        const j = JSON.parse(stdout.trim()) as Record<string, unknown>;
        const e = j?.error as Record<string, unknown> | undefined;
        detail = (e?.message as string) ?? (j?.message as string) ?? detail;
      } catch {
        /* fall back to the stderr tail */
      }
      settle(() =>
        reject(
          new Error(
            `could not resolve "${asked}" to an account address (wallet-cli exit ${code}): ${detail}`,
          ),
        ),
      );
    });
  });
}
