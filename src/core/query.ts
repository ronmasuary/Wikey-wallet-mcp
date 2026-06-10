// Non-signing query runner (H1). Ported from the skill's `runQuery`
// (index.ts:101-110): execFile wallet-cli with a 30s timeout. Reads never spawn
// SSP and never touch the HMAC key.

import { execFile as execFileCb, spawn } from 'node:child_process';
import { promisify } from 'node:util';

const execFile = promisify(execFileCb);

export interface RunQueryOpts {
  walletCli: string;
  args: string[];
  timeoutMs?: number;
  /** A single line written to the child's stdin, then stdin is ended (EOF). */
  input?: string;
  /** Child env (e.g. HOME pinned to the state root to co-locate config). */
  env?: NodeJS.ProcessEnv;
}

export async function runQuery(opts: RunQueryOpts): Promise<string> {
  try {
    const { stdout } = await execFile(opts.walletCli, opts.args, {
      timeout: opts.timeoutMs ?? 30_000,
      maxBuffer: 64 * 1024 * 1024, // snapshots can be hundreds of KB
      ...(opts.env ? { env: opts.env } : {}),
    });
    return stdout.trim();
  } catch (e: unknown) {
    const err = e as { stderr?: string; stdout?: string; code?: number | string };
    const detail = err.stdout?.trim() || err.stderr?.trim() || String(e);
    throw new Error(`wallet-cli exit ${err.code ?? '?'}: ${detail}`);
  }
}

/**
 * Run a session-gated wallet-cli command whose signing happens over the running
 * signer's HTTP API (NOT via the stdin prompt/proof flow) — e.g. `keys create`.
 *
 * Such commands emit a single fixed confirmation (e.g.
 * `Set this key as the default? (y/n):`). We answer it with `opts.input`
 * (e.g. "y\n"/"n\n"), then end stdin — wallet-cli proceeds and prints its JSON
 * result to stdout. (Routing these through the prompt engine instead deadlocks:
 * its empty queue never answers the y/n, so the child never exits and the call
 * rides the timeout even though the operation already succeeded.)
 */
export function runWalletCliWithInput(opts: RunQueryOpts): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const child = spawn(opts.walletCli, opts.args, {
      // Pipe stdin so we can answer the one confirmation prompt, then EOF.
      stdio: ['pipe', 'pipe', 'pipe'],
      ...(opts.env ? { env: opts.env } : {}),
    });
    child.stdin.on('error', () => {
      /* child may exit before we finish writing — ignore EPIPE */
    });
    child.stdin.end(opts.input ?? '');
    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
      finish(() => reject(new Error(`wallet-cli timed out after ${(opts.timeoutMs ?? 30_000) / 1000}s`)));
    }, opts.timeoutMs ?? 30_000);
    timer.unref?.();
    child.stdout.on('data', (c: Buffer) => {
      stdout += c;
    });
    child.stderr.on('data', (c: Buffer) => {
      stderr += c;
    });
    child.on('error', (e) => finish(() => reject(e)));
    child.on('close', (code) => {
      finish(() => {
        if (code === 0) resolve(stdout.trim());
        else reject(new Error(`wallet-cli exit ${code}: ${stdout.trim() || stderr.trim()}`));
      });
    });
  });
}
