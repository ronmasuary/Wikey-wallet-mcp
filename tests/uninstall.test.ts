import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';

import {
  buildUninstallPlan,
  executeUninstall,
  classifyRecoverability,
  parseHelpers,
  confirmPhraseFor,
  OWNED_ENTRIES,
  ALLOW_ENV,
  type FsOps,
  type UninstallDeps,
} from '../src/core/uninstall.js';

const ROOT = path.join('/tmp', 'ssp-root');
const A1 = 'omnistar1aaaaaaaaaaaaaaaaaaa';
const A2 = 'omnistar1bbbbbbbbbbbbbbbbbbb';
const OUTSIDER = 'omnistar1outsider00000000000';
const SAFE = 'omnistar1safe0000000000000';

// ── fakes ─────────────────────────────────────────────────────────────────────

interface KeyState {
  name?: string;
  funded?: boolean;
  safe?: string;
  /** undefined → the helpers query throws (the `unknown` path). */
  helpers?: { address: string; name?: string }[] | 'error';
  policyExists?: boolean;
  requiredCount?: number;
}

function queryFor(state: Record<string, KeyState>) {
  return async (args: string[]): Promise<string> => {
    const addr = args[args.indexOf('--address') + 1] ?? '';
    const s = state[addr];
    if (!s) throw new Error('unknown account');
    if (args[1] === 'profile') {
      if (!s.name) throw new Error('no profile on-chain yet');
      return JSON.stringify({ data: { profile: { name: s.name } } });
    }
    if (args[1] === 'balance') {
      return JSON.stringify({ data: { balances: [{ denom: 'nost', amount: s.funded ? '5000' : '0' }] } });
    }
    if (args[1] === 'snapshot') {
      if (!s.safe) throw new Error('no profile on-chain yet');
      return JSON.stringify({ data: { snapshot: [{ address: s.safe, name: s.name ?? '', groups: [] }] } });
    }
    if (args[1] === 'helpers') {
      if (s.helpers === 'error') throw new Error('chain unreachable');
      const helpers = s.helpers ?? [];
      return JSON.stringify({
        data: {
          address: addr,
          policyExists: s.policyExists ?? true,
          helpers,
          count: helpers.length,
          threshold: { percentage: 100, requiredCount: s.requiredCount ?? helpers.length, totalHelpers: helpers.length },
        },
      });
    }
    return '';
  };
}

/** In-memory filesystem keyed by absolute path. */
function fakeFs(entries: string[]): FsOps & { removed: string[]; present: Set<string> } {
  const present = new Set(entries);
  const removed: string[] = [];
  return {
    present,
    removed,
    exists: (p) => present.has(p),
    readdir: (p) => {
      if (p !== ROOT) throw new Error('ENOENT');
      return [...present]
        .filter((e) => e.startsWith(ROOT + path.sep))
        .map((e) => e.slice(ROOT.length + 1).split(path.sep)[0]!)
        .filter((v, i, a) => a.indexOf(v) === i);
    },
    remove: (p) => {
      removed.push(p);
      for (const e of [...present]) if (e === p || e.startsWith(p + path.sep)) present.delete(e);
    },
  };
}

function deps(over: Partial<UninstallDeps> = {}): UninstallDeps & { fs: ReturnType<typeof fakeFs> } {
  const fs = (over.fs as ReturnType<typeof fakeFs>) ?? fakeFs(OWNED_ENTRIES.map((e) => path.join(ROOT, e)));
  return {
    stateRoot: ROOT,
    listKeys: () => [A1],
    query: queryFor({ [A1]: { name: 'alice', funded: true, safe: SAFE, helpers: [{ address: OUTSIDER }] } }),
    allowUninstall: true,
    shutdown: () => {},
    installMode: 'global-real',
    npmUninstall: async () => ({ ok: true, detail: 'removed' }),
    findClientConfigs: () => ['/home/u/.claude.json'],
    ...over,
    fs,
  };
}

// ── the recoverability classifier ─────────────────────────────────────────────

test('parseHelpers returns undefined for anything unparseable', () => {
  assert.equal(parseHelpers('not json'), undefined);
  assert.equal(parseHelpers('{"nope":1}'), undefined);
  assert.deepEqual(parseHelpers('{"data":{"policyExists":true}}'), { policyExists: true });
});

test('an EXISTING policy with zero helpers is NOT recoverable', () => {
  // Verified live: sponsored onboarding leaves policyExists:true, helpers:[].
  // Reading the policy's presence as safety is the trap this guards.
  const r = classifyRecoverability({ policyExists: true, helpers: [], threshold: { requiredCount: 0 } }, new Set());
  assert.equal(r.recoverability, 'no-helpers');
  assert.match(r.reason, /NOT ONE HELPER/);
});

test('helpers that are all LOCAL keys do not survive the uninstall', () => {
  // The account needs 2 approvals; both helpers are keys in this same keystore,
  // so the wipe destroys the account and its rescuers together.
  const r = classifyRecoverability(
    { policyExists: true, helpers: [{ address: A1 }, { address: A2 }], threshold: { requiredCount: 2 } },
    new Set([A1, A2]),
  );
  assert.equal(r.recoverability, 'helpers-are-local');
  assert.equal(r.survivingHelpers, 0);
  assert.match(r.reason, /IN THIS KEYSTORE/);
});

test('a mix still fails when survivors cannot meet the threshold', () => {
  const r = classifyRecoverability(
    { helpers: [{ address: A1 }, { address: OUTSIDER }], threshold: { requiredCount: 2 } },
    new Set([A1]),
  );
  assert.equal(r.recoverability, 'helpers-are-local');
  assert.equal(r.survivingHelpers, 1);
});

test('enough surviving helpers = recoverable', () => {
  const r = classifyRecoverability(
    { helpers: [{ address: A1 }, { address: OUTSIDER }], threshold: { requiredCount: 1 } },
    new Set([A1]),
  );
  assert.equal(r.recoverability, 'recoverable');
  assert.equal(r.survivingHelpers, 1);
});

test('an unreadable helpers answer is treated as UNRECOVERABLE, never as safe', () => {
  const r = classifyRecoverability(undefined, new Set());
  assert.equal(r.recoverability, 'unknown');
  assert.match(r.reason, /not a safe answer/);
});

// ── the plan ──────────────────────────────────────────────────────────────────

test('plan is read-only and never deletes, even with the gate open', async () => {
  const d = deps();
  const plan = await buildUninstallPlan(d);
  assert.equal(plan.stage, 'plan');
  assert.deepEqual(d.fs.removed, []);
  assert.equal(plan.keyCount, 1);
  assert.equal(plan.confirmPhrase, confirmPhraseFor(1));
});

test('plan never proposes deleting foreign files in a SHARED state root', async () => {
  // A real machine had a foreign keystore-auto/ beside ours. Removing the root
  // recursively would destroy another tool's keys.
  const fs = fakeFs([
    ...OWNED_ENTRIES.map((e) => path.join(ROOT, e)),
    path.join(ROOT, 'keystore-auto'),
    path.join(ROOT, 'ssp-test.log'),
  ]);
  const plan = await buildUninstallPlan(deps({ fs }));
  assert.ok(!plan.willDelete.includes('keystore-auto'));
  assert.deepEqual(plan.willKeep.sort(), ['keystore-auto', 'ssp-test.log']);
  assert.ok(plan.residuals.some((r) => r.status === 'left-behind' && /not this server's/.test(r.what)));
});

// ── the nonce file, which lives OUTSIDE the state root ────────────────────────

test('the nonce file is planned and deleted even though it is outside the state root', async () => {
  // Found in the wild: after a full uninstall a `.ssp-nonce` was still sitting in
  // the user's working directory, unreported. It is the only file this server
  // writes outside the root, so a root-scoped cleanup misses it.
  const nonce = path.join('/home/u/project', '.ssp-nonce');
  const fs = fakeFs([...OWNED_ENTRIES.map((e) => path.join(ROOT, e)), nonce]);
  const d = deps({ fs, nonceFile: nonce });

  const plan = await buildUninstallPlan(d);
  assert.ok(plan.willDelete.includes(nonce), 'the nonce must be listed by absolute path');

  await executeUninstall(d, { confirm: confirmPhraseFor(1) });
  // Removed at its REAL path — not joined onto the state root, which would have
  // silently targeted the wrong file and then reported success.
  assert.ok(d.fs.removed.includes(nonce));
  assert.ok(!d.fs.removed.some((p) => p === path.join(ROOT, nonce)));
  assert.equal(d.fs.present.has(nonce), false);
});

test('an absent nonce file is not planned, and no nonceFile dep is harmless', async () => {
  const withPathButNoFile = deps({ nonceFile: '/home/u/project/.ssp-nonce' });
  const p1 = await buildUninstallPlan(withPathButNoFile);
  assert.ok(!p1.willDelete.some((e) => e.includes('.ssp-nonce')));

  const p2 = await buildUninstallPlan(deps()); // no nonceFile at all
  assert.ok(!p2.willDelete.some((e) => e.includes('.ssp-nonce')));
});

test('a nonce outside the root does not stop the root itself being removed', async () => {
  // The nonce is not IN the root, so it must not count toward willKeep.
  const nonce = path.join('/home/u/project', '.ssp-nonce');
  const fs = fakeFs([...OWNED_ENTRIES.map((e) => path.join(ROOT, e)), nonce]);
  const d = deps({ fs, nonceFile: nonce });
  const plan = await buildUninstallPlan(d);
  assert.deepEqual(plan.willKeep, []);
  await executeUninstall(d, { confirm: confirmPhraseFor(1) });
  assert.ok(d.fs.removed.includes(ROOT), 'an otherwise-empty root should still be removed');
});

test('plan warns that nothing on-chain is deleted', async () => {
  const plan = await buildUninstallPlan(deps());
  assert.ok(plan.warnings.some((w) => /NOTHING on-chain/.test(w)));
});

test('a disabled gate carries the enable instructions IN the plan, not a dangling pointer', async () => {
  // Regression (found on the llm-chat VM, 1.3.0): the warning ended with "see
  // the enable step below" while the how-to lived only on the execute path, so
  // the plan referred the reader to instructions that were not in the response.
  const plan = await buildUninstallPlan(deps({ allowUninstall: false }));
  const w = plan.warnings.find((x) => x.includes(ALLOW_ENV));
  assert.ok(w, 'a disabled gate must be called out');
  assert.doesNotMatch(w!, /see the enable step below/);
  // The actual steps: where to put it, and that a restart is required.
  assert.match(w!, /env.*block|client config/i);
  assert.match(w!, /QUIT AND REOPEN/i);
  assert.match(w!, /agent cannot do this for you/i);
});

test('an enabled gate produces no enable warning at all', async () => {
  const plan = await buildUninstallPlan(deps({ allowUninstall: true }));
  assert.ok(!plan.warnings.some((x) => x.includes(ALLOW_ENV)));
});

// ── the gates, in order ───────────────────────────────────────────────────────

test('a wrong confirm phrase deletes nothing', async () => {
  const d = deps();
  const r = await executeUninstall(d, { confirm: 'yes do it' });
  assert.equal(r.stage, 'confirm-mismatch');
  assert.deepEqual(d.fs.removed, []);
});

test('a STALE phrase (key count changed) no longer matches', async () => {
  const d = deps();
  const r = await executeUninstall(d, { confirm: confirmPhraseFor(2) }); // machine has 1
  assert.equal(r.stage, 'confirm-mismatch');
  assert.deepEqual(d.fs.removed, []);
});

test('without the operator env var nothing is deleted, and the human is told how to set it', async () => {
  const d = deps({ allowUninstall: false });
  const r = await executeUninstall(d, { confirm: confirmPhraseFor(1) });
  assert.equal(r.stage, 'blocked-not-enabled');
  assert.deepEqual(d.fs.removed, []);
  assert.match(r.summary, new RegExp(ALLOW_ENV));
  assert.match(r.summary, /QUIT AND REOPEN/i);
  assert.match(r.summary, /agent cannot set that for itself/);
});

test('the env-gate refusal warns that unrecoverable accounts will block the NEXT attempt too', async () => {
  // Otherwise the user edits mcp.json, fully restarts their client, re-runs —
  // and only then learns the account was unrecoverable all along. Both facts are
  // known now, so both get reported now.
  const d = deps({
    allowUninstall: false,
    query: queryFor({ [A1]: { name: 'alice', funded: true, safe: SAFE, helpers: [] } }),
  });
  const r = await executeUninstall(d, { confirm: confirmPhraseFor(1) });
  assert.equal(r.stage, 'blocked-not-enabled');
  assert.deepEqual(d.fs.removed, []);
  assert.match(r.summary, /will NOT be enough on its own/);
  assert.match(r.summary, /alice/);
  assert.match(r.summary, /wallet_tx_edit_helpers/);
});

test('the env-gate refusal stays short when every account IS recoverable', async () => {
  const d = deps({ allowUninstall: false }); // default fake: one surviving helper
  const r = await executeUninstall(d, { confirm: confirmPhraseFor(1) });
  assert.equal(r.stage, 'blocked-not-enabled');
  assert.doesNotMatch(r.summary, /will NOT be enough/);
});

test('unrecoverable accounts block the delete until loss is explicitly accepted', async () => {
  const d = deps({
    listKeys: () => [A1],
    query: queryFor({ [A1]: { name: 'alice', funded: true, safe: SAFE, helpers: [], policyExists: true } }),
  });
  const r = await executeUninstall(d, { confirm: confirmPhraseFor(1) });
  assert.equal(r.stage, 'refused-unrecoverable');
  assert.deepEqual(d.fs.removed, []);
  assert.equal(r.unrecoverable.length, 1);
  assert.match(r.summary, /wallet_tx_edit_helpers/);
  assert.match(r.summary, /NOT set that flag on your own initiative/);
});

test('acceptPermanentLoss lets a confirmed, gated delete through', async () => {
  const d = deps({
    query: queryFor({ [A1]: { name: 'alice', funded: true, safe: SAFE, helpers: [] } }),
  });
  const r = await executeUninstall(d, { confirm: confirmPhraseFor(1), acceptPermanentLoss: true });
  assert.equal(r.stage, 'done');
  assert.ok(r.deleted!.includes('keystore'));
});

test('a failed helpers query blocks the delete (unknown is not permission)', async () => {
  const d = deps({ query: queryFor({ [A1]: { name: 'alice', funded: true, safe: SAFE, helpers: 'error' } }) });
  const r = await executeUninstall(d, { confirm: confirmPhraseFor(1) });
  assert.equal(r.stage, 'refused-unrecoverable');
  assert.deepEqual(d.fs.removed, []);
});

// ── execution ─────────────────────────────────────────────────────────────────

test('a full delete kills the session FIRST, then removes only owned entries', async () => {
  const order: string[] = [];
  const fs = fakeFs([...OWNED_ENTRIES.map((e) => path.join(ROOT, e)), path.join(ROOT, 'keystore-auto')]);
  const wrapped: FsOps = { ...fs, remove: (p) => { order.push(`rm:${p}`); fs.remove(p); } };
  const d = deps({ fs: wrapped as never, shutdown: () => order.push('shutdown') });

  const r = await executeUninstall(d, { confirm: confirmPhraseFor(1) });
  assert.equal(order[0], 'shutdown', 'signer must be stopped before files go');
  assert.ok(!order.some((o) => o === `rm:${ROOT}`), 'a shared root must survive');
  assert.ok(!order.some((o) => o.endsWith('keystore-auto')), "another tool's keystore must survive");
  assert.equal(r.stage, 'done');
});

test('an empty root IS removed once nothing foreign is left in it', async () => {
  const fs = fakeFs(OWNED_ENTRIES.map((e) => path.join(ROOT, e)));
  const d = deps({ fs });
  await executeUninstall(d, { confirm: confirmPhraseFor(1) });
  assert.ok(d.fs.removed.includes(ROOT));
});

test('npm success is VERIFIED on disk, not taken from the exit code', async () => {
  // npm exits 0 but a bin shim survives. The cause is deliberately unspecified —
  // the originally-assumed one (Windows holding the .cmd open) was tested and
  // disproven; a wrong prefix, a permission failure or an antivirus hold produce
  // the same shape, which is exactly why the check looks at disk, not exit codes.
  const binDir = '/npm/bin';
  const fs = fakeFs([
    ...OWNED_ENTRIES.map((e) => path.join(ROOT, e)),
    path.join(binDir, 'wikey-wallet-mcp.cmd'),
  ]);
  const d = deps({ fs, npmBinDir: binDir, npmUninstall: async () => ({ ok: true, detail: 'removed 1 package' }) });
  const r = await executeUninstall(d, { confirm: confirmPhraseFor(1) });
  assert.equal(r.npm?.ok, false, 'a surviving shim means the package is not gone');
  const failed = r.residuals.find((x) => x.status === 'failed' && /npm/i.test(x.what));
  assert.ok(failed, 'a surviving shim must be reported');
  assert.match(failed!.why!, /still exist on disk/);
  // It must say WHAT survived, never guess WHY — naming the wrong cause sends
  // the user to fix something that is not broken.
  assert.doesNotMatch(failed!.why!, /held open|Windows/i);
  // A real failure is reported in the PROSE, not by a distinct stage.
  assert.equal(r.stage, 'done');
  assert.match(r.summary, /PARTIALLY DONE/);
  assert.match(r.summary, /could NOT be removed/);
});

test('a linked install reports the source tree as left behind, never deleted', async () => {
  const d = deps({ installMode: 'global-linked', packageDir: '/home/u/projects/Wikey-wallet-mcp' });
  const r = await executeUninstall(d, { confirm: confirmPhraseFor(1) });
  const tree = r.residuals.find((x) => /source tree/i.test(x.what));
  assert.ok(tree, 'the working copy must be reported');
  assert.equal(tree!.status, 'left-behind');
  assert.ok(!d.fs.removed.includes('/home/u/projects/Wikey-wallet-mcp'));
});

test('the client config entry is always a residual and its contents are never read back', async () => {
  const d = deps({ findClientConfigs: () => ['/home/u/.claude.json'] });
  const r = await executeUninstall(d, { confirm: confirmPhraseFor(1) });
  const cfg = r.residuals.find((x) => x.what.startsWith('MCP client config'));
  assert.equal(cfg?.status, 'manual-required');
  assert.equal(cfg?.path, '/home/u/.claude.json');
  // The path is reported; nothing from inside the file ever is.
  assert.ok(!JSON.stringify(r).includes('mcpServers'));
});

test('the config residual tells an agent HOW to edit safely, since it will anyway', async () => {
  // Observed live: the agent performed this edit despite "this tool never edits
  // client config". It did so correctly, but the next one might reach for sed on
  // a file controlling every other MCP server the user has.
  const r = await executeUninstall(deps(), { confirm: confirmPhraseFor(1) });
  const cfg = r.residuals.find((x) => x.what.startsWith('MCP client config'))!;
  assert.match(cfg.why!, /backup/i);
  assert.match(cfg.why!, /never a text or regex substitution/i);
  assert.match(cfg.why!, /still parses/i);
});

test('the done summary states that on-chain accounts still exist', async () => {
  const r = await executeUninstall(deps(), { confirm: confirmPhraseFor(1) });
  assert.match(r.summary, /on-chain accounts still exist/);
  assert.match(r.summary, /cannot be restored/);
});

test('`done` is the ONLY terminal stage, and a clean run does not read as a failure', async () => {
  // There is no `done-with-residuals`: the client-config entry always needs a
  // human, so residuals are never empty and such a stage would be the only
  // outcome ever seen — a partial-failure name on the normal result.
  const r = await executeUninstall(deps(), { confirm: confirmPhraseFor(1) });
  assert.equal(r.stage, 'done');
  assert.ok(r.residuals.length > 0, 'residuals are never empty in practice');
  assert.match(r.summary, /^DONE/);
  assert.doesNotMatch(r.summary, /PARTIALLY DONE/);
  assert.doesNotMatch(r.summary, /NOT FULLY REMOVED/);
  // Remaining manual work is named as expected, not as breakage.
  assert.match(r.summary, /this is expected, not a failure/);
});

test('a state-entry deletion failure downgrades the wording but not the stage', async () => {
  const fs = fakeFs(OWNED_ENTRIES.map((e) => path.join(ROOT, e)));
  const wrapped: FsOps = {
    ...fs,
    remove: (p) => {
      if (p.endsWith('keystore')) throw new Error('EBUSY: signer still holding it');
      fs.remove(p);
    },
  };
  const r = await executeUninstall(deps({ fs: wrapped as never }), { confirm: confirmPhraseFor(1) });
  assert.equal(r.stage, 'done');
  assert.match(r.summary, /PARTIALLY DONE/);
  const failed = r.residuals.find((x) => x.status === 'failed');
  assert.match(failed!.why!, /EBUSY/);
  assert.match(failed!.why!, /8080/); // points at the usual cause
});
