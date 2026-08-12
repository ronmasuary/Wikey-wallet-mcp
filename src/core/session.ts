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
  type AccountEnv,
  type KekPolicy,
  type WalletCliLauncher,
} from './binPaths.js';
import { mintKey, runHmacRotation } from './rotation.js';
import { runSigningPrompted, type PromptStep, type PromptedOpts } from './signing.js';
import { runWalletCliWithInput } from './query.js';
import { redact } from './redact.js';

export interface SessionBins {
  signingServer: string;
  sspUtil: string;
  walletCli: WalletCliLauncher;
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
  /**
   * Why the session is wedged, if it is — a short, secret-redacted label
   * (e.g. "signing-server exited (code=3, signal=null)" or "rotation failed: …").
   * null when not wedged. Lets an agent/operator see WHY without reading logs.
   */
  wedgedReason: string | null;
  /**
   * Diagnostics from the most recent UNEXPECTED signing-server exit: the exit
   * code/signal, a timestamp, and a redacted tail (~2 KB) of the child's last
   * stdout+stderr. Retained across a recover() so the cause is still inspectable
   * after self-heal; null until the child has died unexpectedly at least once.
   * Never contains key material (redacted, and SSP never logs the key).
   */
  lastChildExit: { code: number | null; signal: string | null; ts: number; output: string } | null;
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

/**
 * Coerce an unknown rejection into a SpawnFailure.
 *
 * `attemptSpawn` rejects with a real SpawnFailure on the paths it controls, but
 * a throw from anywhere else (binary resolution, a synchronous spawn error)
 * arrives as a plain Error with no `output`. Casting that to SpawnFailure made
 * the error HANDLER itself crash on `output.trim()` — replacing the real spawn
 * diagnostic with "Cannot read properties of undefined". Normalizing here keeps
 * the true cause intact, which is the whole point of this error path.
 */
function toSpawnFailure(e: unknown): SpawnFailure {
  if (typeof e === 'object' && e !== null && typeof (e as SpawnFailure).output === 'string') {
    return e as SpawnFailure;
  }
  return {
    earlyExit: false,
    output: '',
    cause: e instanceof Error ? e : new Error(String(e)),
  };
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
  /** Bounded ring (~2 KB) of the LIVE child's recent stdout+stderr, for the exit tail. */
  private liveTail = '';
  /** Diagnostics captured the last time the child died unexpectedly. */
  private lastChildExit: { code: number | null; signal: string | null; ts: number; output: string } | null = null;
  /** Short redacted label of why we wedged; cleared on recover/cold-start. */
  private wedgedReason: string | null = null;

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
    if (this.wedged)
      throw new Error(
        'SSP session is wedged (signing-server died or rotation failed). ' +
          'Call wallet_session_recover to cold-restart the session in place — ' +
          'no MCP-server restart needed.',
      );
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
      const f = toSpawnFailure(e);
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
          throw this.spawnFailureToError(toSpawnFailure(e2));
        }
      } else {
        key.fill(0);
        throw this.spawnFailureToError(f);
      }
    }

    // Live: attach lifecycle handlers and drain the pipes so SSP's ongoing JSON
    // logging can never fill the pipe buffer and block the child. We KEEP a
    // bounded tail (instead of discarding) so an unexpected exit can report the
    // child's dying words — that's how we learn WHY it wedged. Attaching a 'data'
    // listener also flips the stream into flowing mode (no resume() needed).
    this.liveTail = ''; // fresh child → fresh ring
    const captureLive = (c: Buffer) => {
      this.liveTail = (this.liveTail + c.toString()).slice(-2048);
    };
    proc.on('error', () => {
      this.child = null;
      if (this.key) {
        this.key.fill(0);
        this.key = null;
      }
    });
    proc.on('exit', (code, signal) => this.handleChildExit(proc, code, signal));
    proc.stdout?.on('data', captureLive);
    proc.stderr?.on('data', captureLive);

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
    // Defensive: this is the last stop before the user sees an error, so it must
    // never be the thing that throws.
    const tail = (f.output ?? '').trim();
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

  private handleChildExit(proc: ChildProcess, code: number | null, signal: NodeJS.Signals | null): void {
    if (this.shuttingDown) return;
    if (proc !== this.child) return; // a stale handle
    // SSP died unexpectedly — the key is now useless. Per design the session is
    // over: zeroize, stop the timer, and wedge. Recovery is wallet_session_recover
    // (cold-start in place), no longer a full MCP restart. Capture the exit
    // code/signal + a redacted tail of the child's last output so the cause is
    // inspectable via wallet_session_status instead of lost.
    const output = redact(this.liveTail).trim().slice(-2048);
    this.lastChildExit = { code, signal, ts: Date.now(), output };
    this.wedgedReason = `signing-server exited (code=${code ?? 'null'}, signal=${signal ?? 'null'})`;
    this.log(
      `[wikey-wallet-mcp] signing-server exited unexpectedly (code=${code ?? 'null'}, ` +
        `signal=${signal ?? 'null'}) — session wedged.` +
        (output ? ` last output: ${output.slice(-500)}` : ''),
    );
    this.stopRotationTimer();
    if (this.key) {
      this.key.fill(0);
      this.key = null;
    }
    this.child = null;
    this.wedged = true;
  }

  // ─── signing / reads ────────────────────────────────────────────────────────

  /**
   * Run a prompt-driven signing op AS `account`. Lazily brings up SSP,
   * serialized w/ rotation.
   *
   * The account is REQUIRED, and that is the point: there is no default key, so
   * every signing path must state who it acts as. Making it a parameter rather
   * than a runtime lookup means the compiler — not a code review — is what
   * catches a new signing call that forgot to route one. The address and pubkey
   * are injected into the child env (see walletCliEnv), which is what reaches
   * the commands wallet-cli gives no `--creator/--pubkey` flags.
   *
   * Callers resolve the account with `resolveAccount` (accounts.ts). Use
   * `runWithSession` for the one signing command that legitimately has no
   * account — `keys create`, which may run with an empty keystore.
   */
  async signPrompted(
    account: AccountEnv,
    args: string[],
    queue: PromptStep[] | ((all: string) => PromptStep[]),
    opts?: PromptedOpts,
  ): Promise<string> {
    // Defence in depth against a pubkey-less (read-only) account reaching a
    // signing path: wallet-cli would blank config.user.pubkey and fail somewhere
    // deep in the broadcast. Name the real problem here instead.
    if (!account?.address || !account.pubkey) {
      throw new Error(
        'signing requires an explicit account (address + pubkey) — this wallet has no default key. ' +
          'Resolve one with resolveAccount() first; if several keys exist, ask the user which to use.',
      );
    }
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
        // HOME pins the config under the state root; WALLET_ADDRESS/WALLET_PUBKEY
        // route this child at `account` (env beats the config file).
        env: walletCliEnv(account),
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
   *
   * `account` is OPTIONAL here, unlike signPrompted: this path exists for
   * `keys create`, which mints the wallet's FIRST key and therefore must run
   * with an empty keystore and no account to act as.
   */
  async runWithSession(
    args: string[],
    opts: { input?: string; timeoutMs?: number; account?: AccountEnv } = {},
  ): Promise<string> {
    await this.ensureSession();
    return this.mutex.runExclusive(() => {
      if (!this.key) throw new Error('no active HMAC key');
      return runWalletCliWithInput({
        walletCli: this.bins.walletCli,
        args,
        env: walletCliEnv(opts.account), // config under the state root; account routed when given
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
        this.wedgedReason = `rotation failed: ${redact((e as Error).message ?? String(e))}`;
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
      wedgedReason: this.wedged ? this.wedgedReason : null,
      lastChildExit: this.lastChildExit,
    };
  }

  /**
   * Recover a wedged session in place — the in-process equivalent of an MCP
   * restart. Mirrors shutdown's teardown (zeroize key, kill OUR child only, stop
   * the timer) but instead of marking the manager dead it clears the wedged flag
   * and the init-once latch so the NEXT signing call cold-starts via doInit
   * (fresh nonce + new key + fresh spawn — exactly what a process restart does).
   *
   * Safe because recovery is a deliberate, agent-invoked action, never an
   * automatic respawn loop: if the underlying cause persists, the cold start
   * fails with the real diagnostic, not the generic wedge message. No-op once
   * shutdown() has been called (the process is going away).
   */
  recover(): void {
    if (this.shuttingDown) return;
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
    this.initPromise = null;
    this.lastRotation = null;
    this.effectiveKekProvider = null;
    this.kekFellBack = false;
    this.wedged = false;
    this.wedgedReason = null; // no longer wedged; keep lastChildExit as history
    this.log('[wikey-wallet-mcp] session recovered — will cold-start on next signing call.');
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
