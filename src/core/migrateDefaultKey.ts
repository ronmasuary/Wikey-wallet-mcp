// One-shot migration: clear the legacy default-key pointer.
//
// This wallet no longer has a default key — every command states the account it
// acts as, injected per child process (see walletCliEnv). But installs created
// before that change still carry `user.address` / `user.pubkey` in the
// co-located wallet-cli config, written by an old `keys create`.
//
// Those leftovers cannot actually route anything: the env we inject wins over
// the config file (verified against wallet-cli — see docs/REMOVE-DEFAULT-KEY.md),
// so a stale pointer is inert. Clearing it is about TRUTHFULNESS, not behavior:
// `wallet_config_show` reads that file, and a pointer sitting in it says the
// wallet has a default account when it does not. Anyone — user or agent — who
// reads it and reasons from it reasons wrongly, and the pointer names whichever
// key happened to be created last, which is exactly the association this work
// removed.
//
// Deliberately conservative: it only ever blanks those two fields, never
// rewrites or reformats anything else, and any failure is swallowed. A wallet
// that cannot complete this migration is still CORRECT — just untidy — so it
// must never be a reason not to start.

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { walletHome } from './binPaths.js';

export interface ClearedPointer {
  address?: string;
  pubkey?: string;
}

/** Path of the co-located wallet-cli config (HOME is pinned to the state root). */
export function walletConfigPath(): string {
  return path.join(walletHome(), '.wallet-cli', 'config.json');
}

/**
 * Blank `user.address` / `user.pubkey` in the co-located config if either is
 * set. Returns what was cleared, or null when there was nothing to do (which is
 * the case on every run after the first, and on a fresh install).
 *
 * Fields are set to `''` rather than deleted: that is the shape wallet-cli's own
 * DEFAULT_CONFIG uses, so the file stays something wallet-cli would have written.
 */
export function clearDefaultKeyPointer(file = walletConfigPath()): ClearedPointer | null {
  if (!existsSync(file)) return null;

  let cfg: { user?: { address?: unknown; pubkey?: unknown } };
  try {
    cfg = JSON.parse(readFileSync(file, 'utf-8')) as typeof cfg;
  } catch {
    return null; // unreadable/corrupt — not this migration's problem
  }

  const address = typeof cfg.user?.address === 'string' ? cfg.user.address : '';
  const pubkey = typeof cfg.user?.pubkey === 'string' ? cfg.user.pubkey : '';
  if (!address && !pubkey) return null;

  cfg.user = { ...cfg.user, address: '', pubkey: '' };
  try {
    writeFileSync(file, JSON.stringify(cfg, null, 2), 'utf-8');
  } catch {
    return null; // read-only volume, permissions — leave it, it is inert anyway
  }

  return {
    ...(address ? { address } : {}),
    ...(pubkey ? { pubkey } : {}),
  };
}
