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

// ─── Per-call signer resolution (P3) ─────────────────────────────────────────────

/**
 * Resolve an optional per-call signer. Given a key address, fetch its pubkey via
 * `keys get` and return `--creator <addr> --pubkey <b64>` for the dynamic
 * wallet-cli tx builder (tx.ts honors these over the config default). Omitted →
 * `[]` (default key, back-compat). A bad/unknown key throws before any signing is
 * attempted. `query` is the caller's wallet-cli read runner (env-pinned).
 *
 * `pubkeyOnly` emits just `--pubkey <b64>` (no `--creator`) for commands like
 * `tx send`, whose signer is fixed by `--from` and which reject an unknown
 * `--creator` option. Passing the matching pubkey is what actually routes the
 * SSP proof/signature to `--from` instead of the config default key.
 *
 * `ensureSession` brings the SSP session up before the `keys get` lookup, which
 * talks to the signing-server over HTTP. Without it a cold session fails here
 * with a bare `fetch failed` naming neither the session nor the key — and, worse,
 * passing `signingKey` silently opts the call out of lazy bring-up, since the
 * same call WITHOUT it reaches ensureSession via signPrompted and works fine.
 * Injected rather than imported so core/ stays transport-agnostic. It is awaited
 * only AFTER the no-key early return, so omitting `signingKey` still never wakes
 * the session (reads stay free).
 */
export async function resolveSignerArgs(
  query: (args: string[]) => Promise<string>,
  signingKey: unknown,
  opts: { pubkeyOnly?: boolean; ensureSession?: () => Promise<void> } = {},
): Promise<string[]> {
  if (signingKey === undefined || signingKey === null || signingKey === '') return [];
  const addr = String(signingKey);
  if (opts.ensureSession) await opts.ensureSession();
  const raw = await query(['keys', 'get', '--id', addr]);
  let pubkey: string | undefined;
  try {
    const j = JSON.parse(raw) as { success?: boolean; data?: { pubkeyBase64?: string } };
    pubkey = j?.data?.pubkeyBase64;
  } catch {
    throw new Error(`signingKey ${addr}: could not parse keys-get output to resolve its pubkey`);
  }
  if (!pubkey) throw new Error(`signingKey ${addr}: no pubkey found (is the key present in the signer?)`);
  return opts.pubkeyOnly ? ['--pubkey', pubkey] : ['--creator', addr, '--pubkey', pubkey];
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
