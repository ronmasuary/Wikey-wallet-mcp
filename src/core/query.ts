// Non-signing query runner (H1). Ported from the skill's `runQuery`
// (index.ts:101-110): execFile wallet-cli with a 30s timeout. Reads never spawn
// SSP and never touch the HMAC key.

import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';

const execFile = promisify(execFileCb);

export interface RunQueryOpts {
  walletCli: string;
  args: string[];
  timeoutMs?: number;
}

export async function runQuery(opts: RunQueryOpts): Promise<string> {
  try {
    const { stdout } = await execFile(opts.walletCli, opts.args, {
      timeout: opts.timeoutMs ?? 30_000,
      maxBuffer: 64 * 1024 * 1024, // snapshots can be hundreds of KB
    });
    return stdout.trim();
  } catch (e: unknown) {
    const err = e as { stderr?: string; stdout?: string; code?: number | string };
    const detail = err.stdout?.trim() || err.stderr?.trim() || String(e);
    throw new Error(`wallet-cli exit ${err.code ?? '?'}: ${detail}`);
  }
}
