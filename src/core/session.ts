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
import { mkdirSync } from 'node:fs';
import path from 'node:path';

import { Mutex } from './mutex.js';
import {
  resolveKekPolicy,
  softwareKekPolicy,
  isDevEnv,
  SSP_NO_KEK_MARKER,
  keystoreDir,
  walletHome,
  walletCliEnv,
  type KekPolicy,
} from './binPaths.js';
import { mintKey, runHmacRotation } from './rotation.js';
import { runSigningPrompted, type PromptStep, type PromptedOpts } from './signing.js';
import { runWalletCliWithInput } from './query.js';

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
  /** The KEK provider the live SSP child actually came up with (never the key). */
  kekProvider: 'auto' | 'env' | null;
  /** True when software KEK was reached via runtime fallback (no hardware). */
  kekFallback: boolean;
}

/** Internal: why a spawn attempt failed, for the fallback decision. */
interface SpawnFailure {
  /** The child exited before the port became reachable (vs. a probe timeout). */
  earlyExit: boolean;
  /** Bounded tail of the child's stdout+stderr (marker-bearing on a KEK fail). */
  output: string;
  exitCode?: number | null;
  cause?: Error;
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
  private effectiveKekProvider: 'auto' | 'env' | null = null;
  private kekFellBack = false;

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
    let kek = resolveKekPolicy();
    let fellBack = false;

    let proc: ChildProcess;
    try {
      proc = await this.attemptSpawn(kek, key);
    } catch (e) {
      const f = e as SpawnFailure;
      // Fall back to the persisted software KEK once, but ONLY when the primary
      // was hardware AND SSP reported no usable KEK at boot. SSP logs that marker
      // to its STDOUT via slog-JSON (main.go:40) — attemptSpawn scans both
      // streams. A non-KEK early failure (no marker) is surfaced as-is, never
      // masked by a fallback.
      if (kek.provider === 'auto' && f.earlyExit && f.output.includes(SSP_NO_KEK_MARKER)) {
        this.log(
          '[wikey-wallet-mcp] no hardware KEK; falling back to persisted software KEK (dev.kek).',
        );
        kek = softwareKekPolicy();
        fellBack = !isDevEnv();
        try {
          proc = await this.attemptSpawn(kek, key);
        } catch (e2) {
          key.fill(0);
          throw this.spawnFailureToError(e2 as SpawnFailure);
        }
      } else {
        key.fill(0);
        throw this.spawnFailureToError(f);
      }
    }

    // Live: attach lifecycle handlers and drain the pipes (discard) so SSP's
    // ongoing JSON logging can never fill the pipe buffer and block the child.
    proc.on('error', () => {
      this.child = null;
      if (this.key) {
        this.key.fill(0);
        this.key = null;
      }
    });
    proc.on('exit', () => this.handleChildExit(proc));
    proc.stdout?.resume();
    proc.stderr?.resume();

    this.child = proc;
    this.key = key;
    this.effectiveKekProvider = kek.provider;
    this.kekFellBack = fellBack;
    this.startRotationTimer();
    this.log(
      `[wikey-wallet-mcp] SSP session started (pid ${proc.pid}, kek=${kek.provider}` +
        `${fellBack ? ', software fallback — no hardware enclave' : ''}).`,
    );
  }

  /**
   * Spawn signing-server with the given KEK policy and resolve once the port is
   * reachable. Captures a bounded tail of the child's stdout+stderr; rejects with
   * a SpawnFailure that flags whether the child exited early (vs. a probe
   * timeout) and carries the captured output for marker scanning + diagnostics.
   * On resolve, the capture/diagnostic listeners are removed and ownership of the
   * live pipes passes to doInit (which drains them).
   */
  private attemptSpawn(kek: KekPolicy, key: Buffer): Promise<ChildProcess> {
    const ksDir = keystoreDir();
    try {
      mkdirSync(ksDir, { recursive: true });
    } catch {
      /* best effort; SSP will error if it truly can't write and we surface it */
    }
    return new Promise<ChildProcess>((resolve, reject) => {
      const proc = spawn(
        this.bins.signingServer,
        ['-spawned-by-agent', ...kek.flags, '-keystore', 'secure', '-keystore-dir', ksDir],
        {
          env: {
            ...process.env,
            HOME: walletHome(), // symmetry with wallet-cli; keeps any HOME-derived paths under the root
            SSP_HMAC_KEY: key.toString('utf8'), // env values must be strings; SSP os.Unsetenv's it
            ...kek.env,
          },
          detached: false,
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );

      let output = '';
      const capture = (c: Buffer) => {
        output = (output + c.toString()).slice(-2048); // bounded ring (~2 KB)
      };
      proc.stdout?.on('data', capture);
      proc.stderr?.on('data', capture);

      let settled = false;
      const removeBringupListeners = () => {
        proc.stdout?.removeListener('data', capture);
        proc.stderr?.removeListener('data', capture);
        proc.removeListener('error', onError);
        proc.removeListener('exit', onExit);
      };
      const onError = (err: Error) => {
        if (settled) return;
        settled = true;
        removeBringupListeners();
        reject({ earlyExit: false, output, cause: err } as SpawnFailure);
      };
      const onExit = (code: number | null) => {
        if (settled) return;
        settled = true;
        removeBringupListeners();
        reject({ earlyExit: true, output, exitCode: code } as SpawnFailure);
      };
      proc.on('error', onError);
      proc.on('exit', onExit);

      this.probePort()
        .then(() => {
          if (settled) return;
          settled = true;
          removeBringupListeners();
          resolve(proc);
        })
        .catch((probeErr: Error) => {
          if (settled) return;
          settled = true;
          removeBringupListeners();
          try {
            proc.kill('SIGTERM'); // probe timed out with no exit — reap it
          } catch {
            /* ignore */
          }
          reject({ earlyExit: false, output, cause: probeErr } as SpawnFailure);
        });
    });
  }

  private spawnFailureToError(f: SpawnFailure): Error {
    const base = f.cause?.message ?? `signing-server exited (code ${f.exitCode ?? '?'})`;
    const tail = f.output.trim();
    return new Error(tail ? `${base}\n${tail.slice(-500)}` : base);
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
        env: walletCliEnv(), // co-locate wallet-cli config under the state root
        ...(opts ? { opts } : {}),
      });
    });
  }

  /**
   * Run a session-gated wallet-cli command that signs over the signer's HTTP
   * API rather than the stdin proof flow (e.g. `keys create`). Brings up SSP,
   * then runs it answering its single y/n confirmation via `input` so wallet-cli
   * emits its JSON result and exits — see runWalletCliWithInput. Serialized with
   * signing/rotation via the same mutex.
   */
  async runWithSession(args: string[], opts: { input?: string; timeoutMs?: number } = {}): Promise<string> {
    await this.ensureSession();
    return this.mutex.runExclusive(() => {
      if (!this.key) throw new Error('no active HMAC key');
      return runWalletCliWithInput({
        walletCli: this.bins.walletCli,
        args,
        env: walletCliEnv(), // co-locate wallet-cli config under the state root
        ...(opts.input !== undefined ? { input: opts.input } : {}),
        ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
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
      kekProvider: active ? this.effectiveKekProvider : null,
      kekFallback: active ? this.kekFellBack : false,
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
