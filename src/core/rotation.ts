// HMAC rotation driver (H2). Ported from the skill's `runHmacRotation`
// (index.ts:131-151) with the EXACT ssp-util exit-code table verified against
// secure_signing_process/cmd/ssp-util/rotate.go:24-34:
//
//   0 OK · 1 usage · 2 stdin format · 3 nonce-file · 4 HTTP transport (SSP
//   unreachable) · 5 HTTP non-200 · 6 AEAD/nonce-replay reject · 7 ack mismatch
//   · 8 internal crypto.
//
// Policy: retry on 6/7 with 500ms backoff inside a 30s deadline (matches SSP's
// rotateGracePeriod), 10s per-attempt kill-timeout; exit 4 = fatal "SSP
// unreachable"; deadline-exceeded ⇒ wedged; any other code fatal. The HMAC key
// never crosses as a string — old and new keys are written as Buffers to stdin.

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';

function withKillTimeout<T>(
  ms: number,
  label: string,
  child: ReturnType<typeof spawn>,
  promise: Promise<T>,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      try {
        child.kill('SIGTERM');
      } catch {
        /* ignore */
      }
      reject(new Error(`${label} timed out after ${ms / 1000}s`));
    }, ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

/** Mint a fresh 64-hex HMAC key as a Buffer (the 64-hex contract SSP requires). */
export function mintKey(): Buffer {
  return Buffer.from(crypto.randomBytes(32).toString('hex'), 'utf8');
}

export interface RotateOpts {
  sspUtil: string;
  nonceFile: string;
  /** Current sealed HMAC key bytes. */
  currentKey: Buffer;
  deadlineMs?: number;
  perAttemptMs?: number;
  backoffMs?: number;
}

/**
 * Rotate the HMAC key. Resolves with the new key Buffer on exit 0. Throws on a
 * fatal exit code or when the grace deadline elapses (caller treats the throw as
 * "wedged" and stops the timer + refuses signing).
 */
export async function runHmacRotation(opts: RotateOpts): Promise<{ newKey: Buffer }> {
  const deadline = Date.now() + (opts.deadlineMs ?? 30_000);
  const perAttemptMs = opts.perAttemptMs ?? 10_000;
  const backoffMs = opts.backoffMs ?? 500;

  for (;;) {
    const newKey = mintKey();
    const p = spawn(opts.sspUtil, ['rotate', '--nonce-file', opts.nonceFile]);
    const inner = new Promise<number | null>((resolve, reject) => {
      p.on('error', reject);
      p.on('close', resolve);
      // old key, newline, new key, newline — both as Buffers.
      p.stdin.write(opts.currentKey);
      p.stdin.write('\n');
      p.stdin.write(newKey);
      p.stdin.end('\n');
    });

    let code: number | null;
    try {
      code = await withKillTimeout(perAttemptMs, 'ssp-util rotate', p, inner);
    } catch (e) {
      // per-attempt timeout / spawn error
      newKey.fill(0);
      if (Date.now() >= deadline) {
        throw new Error('HMAC rotation failed: session wedged after grace deadline');
      }
      throw e;
    }

    if (code === 0) return { newKey };

    // Not adopting newKey on a non-zero exit — zeroize it.
    newKey.fill(0);

    if ((code === 6 || code === 7) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, backoffMs));
      continue;
    }
    if (code === 4) throw new Error('SSP unreachable (ssp-util rotate exit 4)');
    if (Date.now() >= deadline) {
      throw new Error('HMAC rotation failed: session wedged after grace deadline');
    }
    throw new Error(`ssp-util rotate exit ${code}`);
  }
}
