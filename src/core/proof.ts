// Proof driver (H1). Ported from the skill's `computeProof` / `parseSignRequest`
// (index.ts:47-97). We never compute the HMAC ourselves — `ssp-util proof` does
// (message = BE64(nonce) ‖ unsignedData ‖ signingPubKey). Core only drives it.
//
// Two corrections vs. the skill:
//   1. The HMAC key crosses to ssp-util as a Buffer written to stdin (+'\n'),
//      not a JS string, so the sealed key never materializes as an unwipeable
//      string in this process (H11).
//   2. ssp-util is a compiled binary that may ignore SIGTERM, so we escalate
//      SIGTERM → SIGKILL at +2s on the 20s overall timeout (kill ladder).

import { spawn } from 'node:child_process';

export interface SignRequest {
  unsignedData: string;
  signingPubKey: string;
}

/** Extract the first balanced JSON object after a "Sign Request:" marker. */
export function parseSignRequest(buf: string): SignRequest | null {
  const i = buf.indexOf('Sign Request:');
  if (i === -1) return null;
  const tail = buf.slice(i + 'Sign Request:'.length);
  const start = tail.indexOf('{');
  if (start === -1) return null;
  let depth = 0;
  let end = -1;
  for (let k = start; k < tail.length; k++) {
    if (tail[k] === '{') depth++;
    else if (tail[k] === '}' && --depth === 0) {
      end = k;
      break;
    }
  }
  if (end === -1) return null;
  try {
    const obj = JSON.parse(tail.slice(start, end + 1)) as Record<string, unknown>;
    if (typeof obj.unsignedData === 'string' && typeof obj.signingPubKey === 'string') {
      return { unsignedData: obj.unsignedData, signingPubKey: obj.signingPubKey };
    }
  } catch {
    /* ignore — partial/garbled object */
  }
  return null;
}

export interface ComputeProofOpts {
  sspUtil: string;
  nonceFile: string;
  /** Sealed HMAC key as raw bytes (64-hex utf8). Written to ssp-util stdin. */
  key: Buffer;
  unsignedData: string;
  signingPubKey: string;
  timeoutMs?: number;
}

export function computeProof(opts: ComputeProofOpts): Promise<string> {
  const timeoutMs = opts.timeoutMs ?? 20_000;
  const p = spawn(opts.sspUtil, [
    'proof',
    '--unsigned-data',
    opts.unsignedData,
    '--signing-pub-key',
    opts.signingPubKey,
    '--nonce-file',
    opts.nonceFile,
  ]);

  const inner = new Promise<string>((resolve, reject) => {
    let out = '';
    let err = '';
    p.stdout.on('data', (c: Buffer) => {
      out += c.toString();
    });
    p.stderr.on('data', (c: Buffer) => {
      err += c.toString();
    });
    p.on('close', (code: number | null) => {
      if (code === 0) resolve(out.trim());
      else reject(new Error(`ssp-util proof exit ${code}: ${err.trim()}`));
    });
    p.on('error', (e: Error) => {
      try {
        p.kill('SIGTERM');
      } catch {
        /* ignore */
      }
      reject(e);
    });
    // Egress: key bytes on stdin, then newline, then EOF.
    p.stdin.write(opts.key);
    p.stdin.end('\n');
  });

  return new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => {
      try {
        p.kill('SIGTERM');
      } catch {
        /* ignore */
      }
      setTimeout(() => {
        try {
          p.kill('SIGKILL');
        } catch {
          /* ignore */
        }
      }, 2_000);
      reject(new Error(`computeProof timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);
    inner.then(
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
