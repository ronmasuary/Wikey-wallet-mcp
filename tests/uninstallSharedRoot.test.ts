// Shared-state-root protection, against the REAL filesystem.
//
// Every other uninstall test runs on an in-memory fake, which proves the logic
// but not the wiring: `realFs.remove` is a recursive `rmSync`, and the thing
// standing between it and a THIRD PARTY's keys is only the allow-list. That is
// the one branch where a mistake destroys data belonging to someone who never
// installed this server, so it gets exercised for real.
//
// `WIKEY_SSP_DIR` defaults to `~/.ssp`, which a standalone wallet-cli or a
// treasury setup also uses — a real machine was observed carrying a foreign
// `keystore-auto/` beside ours. The fixture reproduces that layout.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync, existsSync, readFileSync, rmSync, readdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { buildUninstallPlan, executeUninstall, confirmPhraseFor, type UninstallDeps } from '../src/core/uninstall.js';
import { realFs } from '../src/core/uninstallEnv.js';

const KEY = 'omnistar1testkey000000000000000000000000';

function ourState(root: string) {
  mkdirSync(path.join(root, 'keystore'), { recursive: true });
  writeFileSync(path.join(root, 'keystore', `${KEY}.enc`), 'OUR-KEY');
  writeFileSync(path.join(root, 'dev.kek'), 'OUR-KEK');
  mkdirSync(path.join(root, '.wallet-cli'), { recursive: true });
  writeFileSync(path.join(root, '.wallet-cli', 'config.json'), '{}');
  mkdirSync(path.join(root, 'bin'), { recursive: true });
  writeFileSync(path.join(root, 'bin', 'signing-server'), 'BIN');
  mkdirSync(path.join(root, 'idp'), { recursive: true });
  writeFileSync(path.join(root, 'idp', 'casdoor-credential.json'), '{}');
  writeFileSync(path.join(root, 'recovery-requests.json'), '{}');
}

/** Another Wikey tool's state, sharing the root. */
function foreignState(root: string) {
  mkdirSync(path.join(root, 'keystore-auto'), { recursive: true });
  writeFileSync(path.join(root, 'keystore-auto', 'omnistar1someoneelse.enc'), 'THIRD-PARTY-KEY');
  writeFileSync(path.join(root, 'keystore-auto', 'kek.dpapi'), 'THIRD-PARTY-KEK');
  mkdirSync(path.join(root, 'treasury'), { recursive: true });
  writeFileSync(path.join(root, 'treasury', 'voter.json'), 'THIRD-PARTY-CONFIG');
  writeFileSync(path.join(root, 'ssp-test.log'), 'someone elses log');
}

// One local key with an OFF-machine helper, so the audit passes and the run
// reaches the deletion rather than stopping at the unrecoverable gate.
const query = async (args: string[]): Promise<string> => {
  if (args[1] === 'profile') return JSON.stringify({ data: { profile: { name: 'shared@test' } } });
  if (args[1] === 'balance') return JSON.stringify({ data: { balances: [{ denom: 'nost', amount: '5000' }] } });
  if (args[1] === 'snapshot')
    return JSON.stringify({ data: { snapshot: [{ address: 'omnistar1safe', name: 'shared@test_safe', groups: [] }] } });
  if (args[1] === 'helpers')
    return JSON.stringify({
      data: {
        policyExists: true,
        helpers: [{ address: 'omnistar1offmachine', name: 'rescuer@elsewhere' }],
        count: 1,
        threshold: { percentage: 100, requiredCount: 1, totalHelpers: 1 },
      },
    });
  return '';
};

function deps(root: string): UninstallDeps {
  return {
    stateRoot: root,
    listKeys: () => [KEY],
    query,
    allowUninstall: true,
    fs: realFs, // the real recursive remove
    shutdown: () => {},
    installMode: 'global-real',
    // Pointed at paths that do not exist so the npm verification passes without
    // a real npm ever being invoked — uninstalling the developer's own global
    // package from a test would be an unpleasant surprise.
    npmBinDir: path.join(root, '__no_shims__'),
    packageDir: path.join(root, '__no_package__'),
    npmUninstall: async () => ({ ok: true, detail: 'stubbed' }),
    findClientConfigs: () => [],
  };
}

function tmpRoot(): string {
  return mkdtempSync(path.join(os.tmpdir(), 'wikey-uninstall-'));
}

test('SHARED root: our entries go, a third party\'s keys survive byte-for-byte, root remains', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  ourState(root);
  foreignState(root);

  const plan = await buildUninstallPlan(deps(root));
  assert.deepEqual(plan.willKeep.sort(), ['keystore-auto', 'ssp-test.log', 'treasury']);
  assert.ok(!plan.willDelete.includes('keystore-auto'));

  await executeUninstall(deps(root), { confirm: confirmPhraseFor(1) });

  // Ours: gone.
  for (const e of ['keystore', 'dev.kek', '.wallet-cli', 'bin', 'idp', 'recovery-requests.json']) {
    assert.equal(existsSync(path.join(root, e)), false, `${e} should have been deleted`);
  }
  // Theirs: untouched, contents included — not merely "the directory still exists".
  assert.equal(readFileSync(path.join(root, 'keystore-auto', 'omnistar1someoneelse.enc'), 'utf8'), 'THIRD-PARTY-KEY');
  assert.equal(readFileSync(path.join(root, 'keystore-auto', 'kek.dpapi'), 'utf8'), 'THIRD-PARTY-KEK');
  assert.equal(readFileSync(path.join(root, 'treasury', 'voter.json'), 'utf8'), 'THIRD-PARTY-CONFIG');
  assert.equal(readFileSync(path.join(root, 'ssp-test.log'), 'utf8'), 'someone elses log');
  // And the root itself must survive, or their files go with it.
  assert.ok(existsSync(root), 'a shared root must never be removed');
  assert.deepEqual(readdirSync(root).sort(), ['keystore-auto', 'ssp-test.log', 'treasury']);
});

test('the nonce file is really deleted from OUTSIDE the root, at its own path', async (t) => {
  // The nonce is appended to willDelete as an absolute path. Joining it onto the
  // state root would point at a file that does not exist, `force: true` would
  // swallow the miss, and the run would report success while the real file sat
  // untouched — the exact bug this exercises against a real filesystem.
  const root = tmpRoot();
  const elsewhere = tmpRoot();
  t.after(() => {
    rmSync(root, { recursive: true, force: true });
    rmSync(elsewhere, { recursive: true, force: true });
  });
  ourState(root);
  const nonce = path.join(elsewhere, '.ssp-nonce');
  writeFileSync(nonce, '4');

  const d = { ...deps(root), nonceFile: nonce };
  const plan = await buildUninstallPlan(d);
  assert.ok(plan.willDelete.includes(nonce));

  await executeUninstall(d, { confirm: confirmPhraseFor(1) });
  assert.equal(existsSync(nonce), false, 'the nonce must be gone from its real location');
  assert.ok(existsSync(elsewhere), 'only the file — never its directory');
});

test('EXCLUSIVE root: nothing foreign, so the root itself is removed too', async (t) => {
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  ourState(root);

  const plan = await buildUninstallPlan(deps(root));
  assert.deepEqual(plan.willKeep, []);

  await executeUninstall(deps(root), { confirm: confirmPhraseFor(1) });
  assert.equal(existsSync(root), false, 'an exclusively-ours root should be fully removed');
});

test('a foreign file added AFTER the plan still protects the root at execute time', async (t) => {
  // The plan and the deletion are two separate calls; the second re-reads the
  // root. A file that appeared in between must not be deleted, and must still
  // stop the root from being removed.
  const root = tmpRoot();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  ourState(root);

  const plan = await buildUninstallPlan(deps(root));
  assert.deepEqual(plan.willKeep, []); // clean at plan time

  writeFileSync(path.join(root, 'someone-elses-new-file'), 'ARRIVED LATE');
  await executeUninstall(deps(root), { confirm: confirmPhraseFor(1) });

  assert.ok(existsSync(root), 'the root must survive a file that appeared after planning');
  assert.equal(readFileSync(path.join(root, 'someone-elses-new-file'), 'utf8'), 'ARRIVED LATE');
});
