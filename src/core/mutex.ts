// Async mutex — serializes ensureSession + signing + rotation so we never
// drive two `ssp-util` proof/rotate calls against the shared monotonic nonce
// file at once (H6), and never spawn two signing-servers from a cold session
// (H8). `ssp-util`'s own flock(LOCK_EX) is the cross-process backstop; this is
// the in-process guarantee.

export class Mutex {
  private tail: Promise<void> = Promise.resolve();

  /** Run `fn` with exclusive access. Calls are serialized in arrival order. */
  runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.tail.then(fn, fn);
    // Keep the chain alive regardless of whether `fn` resolved or rejected.
    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}
