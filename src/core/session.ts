// SessionManager — the heart of the security model.
//
// Owns: the sealed HMAC key (a Buffer in this closure, never a module global,
// never exported, never returned), the OWN signing-server child process, the
// monotonic nonce file lifecycle (H6), the auto-rotation timer (H2), the wedged
// flag, and shutdown (zeroize + kill OWN child only + clear timer).
//
//   - Lazy: reads never spawn SSP. ensureSession() spawns SSP + mints the key on
//     the FIRST signing call, race-guarded by a single init-once promise (H8).
//   - Own-child only: we hold the ChildProcess handle and kill only it — never
//     `pkill` (H5).
//   - Nonce: deleted on a fresh spawn (client file + SSP's in-memory counter both
//     start at 0), kept across rotations (monotonic) (H6).
//   - Serialization: ensureSession (init-once) + signing + rotation are
//     serialized so we never drive two ssp-util proof/rotate calls at once.

import { spawn, type ChildProcess } from 'node:child_process';
import { createConnection } from 'node:net';
import { unlink } from 'node:fs/promises';
import path from 'node:path';

import { Mutex } from './mutex.js';
import { resolveKekPolicy } from './binPaths.js';
import { mintKey, runHmacRotation } from './rotation.js';
import { runSigningPrompted, type PromptStep, type PromptedOpts } from './signing.js';

export interface SessionBins {
  signingServer: string;
  sspUtil: string;
  walletCli: string;
}

export interface SessionConfig {
  bins: SessionBins;
  nonceFile?: string;
  rotationMs?: number;
  port?: number;
  host?: string;
  probeTimeoutMs?: number;
  /** Hook for logging to stderr (never stdout). Defaults to process.stderr. */
  log?: (msg: string) => void;
}

export interface SessionStatus {
  active: boolean;
  pid: number | null;
  wedged: boolean;
  lastRotation: number | null;
  state: 'no-session' | 'active' | 'wedged';
}

export class SessionManager {
  private readonly bins: SessionBins;
  private readonly nonceFile: string;
  private readonly rotationMs: number;
  private readonly port: number;
  private readonly host: string;
  private readonly probeTimeoutMs: number;
  private readonly log: (msg: string) => void;
  private readonly mutex = new Mutex();

  private key: Buffer | null = null;
  private child: ChildProcess | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private initPromise: Promise<void> | null = null;
  private wedged = false;
  private shuttingDown = false;
  private lastRotation: number | null = null;

  constructor(cfg: SessionConfig) {
    this.bins = cfg.bins;
    this.nonceFile = cfg.nonceFile ?? path.join(process.cwd(), '.ssp-nonce');
    this.rotationMs = cfg.rotationMs ?? 15 * 60 * 1000;
    this.port = cfg.port ?? 8080;
    this.host = cfg.host ?? '127.0.0.1';
    this.probeTimeoutMs = cfg.probeTimeoutMs ?? 10_000;
    this.log = cfg.log ?? ((m) => process.stderr.write(m + '\n'));
  }

  // ─── lazy session bring-up (race-guarded, init-once) ────────────────────────

  async ensureSession(): Promise<void> {
    if (this.wedged) throw new Error('SSP session is wedged — restart the MCP server to recover.');
    if (this.key && this.child) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = this.doInit().catch((e) => {
      // allow a later signing call to retry a cold start
      this.initPromise = null;
      throw e;
    });
    return this.initPromise;
  }

  private async doInit(): Promise<void> {
    // Fresh spawn: drop the nonce file so client + SSP's in-memory counter both
    // restart at 0 (kept across rotations, deleted only here).
    try {
      await unlink(this.nonceFile);
    } catch {
      /* may not exist */
    }

    const key = mintKey();
    const kek = resolveKekPolicy();

    const proc = spawn(
      this.bins.signingServer,
      ['-spawned-by-agent', ...kek.flags, '-keystore', 'secure'],
      {
        env: {
          ...process.env,
          SSP_HMAC_KEY: key.toString('utf8'), // env values must be strings; SSP os.Unsetenv's it
          ...kek.env,
        },
        detached: false,
        stdio: 'ignore',
      },
    );

    proc.on('error', () => {
      this.child = null;
      if (this.key) {
        this.key.fill(0);
        this.key = null;
      }
    });
    proc.on('exit', () => this.handleChildExit(proc));

    try {
      await this.probePort();
    } catch (e) {
      try {
        proc.kill('SIGTERM');
      } catch {
        /* ignore */
      }
      key.fill(0);
      throw e;
    }

    this.child = proc;
    this.key = key;
    this.startRotationTimer();
    this.log(`[wikey-wallet-mcp] SSP session started (pid ${proc.pid}, kek=${kek.provider}).`);
  }

  private probePort(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const deadline = Date.now() + this.probeTimeoutMs;
      const probe = () => {
        const s = createConnection({ port: this.port, host: this.host });
        s.on('connect', () => {
          s.destroy();
          resolve();
        });
        s.on('error', () => {
          s.destroy();
          if (Date.now() >= deadline) {
            reject(new Error(`SSP did not start within ${this.probeTimeoutMs / 1000}s`));
            return;
          }
          setTimeout(probe, 200);
        });
      };
      probe();
    });
  }

  private handleChildExit(proc: ChildProcess): void {
    if (this.shuttingDown) return;
    if (proc !== this.child) return; // a stale handle
    // SSP died unexpectedly — the key is now useless. Per design, the session is
    // over: zeroize, stop the timer, and wedge (no auto-restart; restart the MCP).
    this.log('[wikey-wallet-mcp] signing-server exited unexpectedly — session wedged.');
    this.stopRotationTimer();
    if (this.key) {
      this.key.fill(0);
      this.key = null;
    }
    this.child = null;
    this.wedged = true;
  }

  // ─── signing / reads ────────────────────────────────────────────────────────

  /** Run a prompt-driven signing op. Lazily brings up SSP, serialized w/ rotation. */
  async signPrompted(
    args: string[],
    queue: PromptStep[] | ((all: string) => PromptStep[]),
    opts?: PromptedOpts,
  ): Promise<string> {
    await this.ensureSession();
    return this.mutex.runExclusive(() => {
      if (!this.key) throw new Error('no active HMAC key');
      return runSigningPrompted({
        walletCli: this.bins.walletCli,
        sspUtil: this.bins.sspUtil,
        nonceFile: this.nonceFile,
        key: this.key,
        args,
        queue,
        ...(opts ? { opts } : {}),
      });
    });
  }

  // ─── rotation ─────────────────────────────────────────────────────────────────

  private startRotationTimer(): void {
    this.stopRotationTimer();
    this.timer = setInterval(() => {
      void this.rotateNow().catch((e) => {
        this.log(`[wikey-wallet-mcp] rotation failed: ${(e as Error).message}`);
      });
    }, this.rotationMs);
    // Don't keep the event loop alive solely for rotation.
    this.timer.unref?.();
  }

  private stopRotationTimer(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /** Rotate now (also used by the timer). Serialized with signing via the mutex. */
  async rotateNow(): Promise<void> {
    return this.mutex.runExclusive(async () => {
      if (!this.key || !this.child || this.wedged) return;
      try {
        const { newKey } = await runHmacRotation({
          sspUtil: this.bins.sspUtil,
          nonceFile: this.nonceFile,
          currentKey: this.key,
        });
        const old = this.key;
        this.key = newKey;
        old.fill(0); // zeroize the previous key
        this.lastRotation = Date.now();
        this.log('[wikey-wallet-mcp] HMAC key rotated.');
      } catch (e) {
        // Wedged: stop the timer, refuse further signing, surface the error.
        this.wedged = true;
        this.stopRotationTimer();
        throw e;
      }
    });
  }

  // ─── status / shutdown ──────────────────────────────────────────────────────

  status(): SessionStatus {
    const active = this.key !== null && this.child !== null;
    return {
      active,
      pid: this.child?.pid ?? null,
      wedged: this.wedged,
      lastRotation: this.lastRotation,
      state: this.wedged ? 'wedged' : active ? 'active' : 'no-session',
    };
  }

  /** Zeroize the key, kill OUR child only, clear the timer. Idempotent. */
  shutdown(): void {
    if (this.shuttingDown) return;
    this.shuttingDown = true;
    this.stopRotationTimer();
    if (this.key) {
      this.key.fill(0);
      this.key = null;
    }
    if (this.child) {
      try {
        this.child.kill('SIGTERM');
      } catch {
        /* ignore */
      }
      this.child = null;
    }
  }
}
