// The load-bearing assumption: WALLET_ADDRESS/WALLET_PUBKEY beat the config file.
//
// Removing the default key did NOT change wallet-cli. Instead every child is
// spawned with the chosen account in its environment, relying on wallet-cli's
// config loader layering env OVER the config file. If a wallet-cli release ever
// reorders those layers, nothing here would fail to compile and no unit test
// built on stubs would notice — every signing call would silently fall back to
// whatever pointer the file holds. That is precisely the failure this whole
// change exists to prevent, so it is worth one test against the REAL binary.
//
// `config show` is the right probe: a pure local read of the resolved config —
// no network, no signer, no chain, nothing to broadcast.
//
// Skips (does not fail) when wallet-cli is not installed, so a checkout without
// the child binaries still gets a green suite.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { resolveBins, walletCliEnv } from '../src/core/binPaths.js';
import { runQuery } from '../src/core/query.js';

const FILE_ADDR = 'omnistar1filepointer0000000';
const FILE_PUBKEY = 'RklMRVBVQktFWQ==';
const ENV_ADDR = 'omnistar1envwins0000000000';
const ENV_PUBKEY = 'RU5WUFVCS0VZ';

const walletCli = resolveBins().walletCli;
const skip = walletCli ? false : 'wallet-cli is not installed';

/** Run `config show` against a temp state root holding a deliberately wrong pointer. */
async function showUser(account?: { address: string; pubkey?: string }) {
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-prec-'));
  const prev = process.env.WIKEY_SSP_DIR;
  try {
    process.env.WIKEY_SSP_DIR = dir; // walletCliEnv pins HOME/USERPROFILE here
    mkdirSync(path.join(dir, '.wallet-cli'), { recursive: true });
    writeFileSync(
      path.join(dir, '.wallet-cli', 'config.json'),
      JSON.stringify({ user: { address: FILE_ADDR, pubkey: FILE_PUBKEY, name: 'file' } }, null, 2),
      'utf-8',
    );
    const raw = await runQuery({ walletCli: walletCli!, args: ['config', 'show'], env: walletCliEnv(account) });
    return (JSON.parse(raw) as { data: { user: { address: string; pubkey: string } } }).data.user;
  } finally {
    if (prev === undefined) delete process.env.WIKEY_SSP_DIR;
    else process.env.WIKEY_SSP_DIR = prev;
    rmSync(dir, { recursive: true, force: true });
  }
}

test('without an injected account, wallet-cli reads the config file', { skip }, async () => {
  const user = await showUser();
  assert.equal(user.address, FILE_ADDR, 'baseline: the file is what it would otherwise use');
});

test('an injected account OVERRIDES the config file — the whole design rests on this', { skip }, async () => {
  const user = await showUser({ address: ENV_ADDR, pubkey: ENV_PUBKEY });
  assert.equal(user.address, ENV_ADDR, 'WALLET_ADDRESS must beat user.address in the file');
  assert.equal(user.pubkey, ENV_PUBKEY, 'WALLET_PUBKEY must beat user.pubkey in the file');
});

test('injecting an address alone BLANKS the pubkey (why walletCliEnv sets both)', { skip }, async () => {
  const user = await showUser({ address: ENV_ADDR });
  assert.equal(user.address, ENV_ADDR);
  // wallet-cli builds config.user from whichever var is present and fills the
  // other with ''. A signing command routed this way therefore fails loudly
  // instead of quietly signing with the file's key — see signPrompted's guard.
  assert.equal(user.pubkey, '', 'the file pubkey must NOT survive a partial injection');
});
