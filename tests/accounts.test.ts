import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  listAccounts,
  resolveAccount,
  resolveAccountAddress,
  signerArgsFor,
  AccountResolutionError,
} from '../src/core/accounts.js';

const A = 'omnistar1aaaaaaaaaaaaaaaaaa';
const B = 'omnistar1bbbbbbbbbbbbbbbbbb';
const SAFE_A = 'omnistar1safeaaaaaaaaaaaaaa';

// A `query` fake that answers per subcommand, keyed by the --address it is given.
// Anything unmapped throws, which is what a key with no profile really does.
function fakeQuery(state: Record<string, { name?: string; funded?: boolean; safe?: string }>) {
  const seen: string[][] = [];
  const q = async (args: string[]): Promise<string> => {
    seen.push(args);
    const addr = args[args.indexOf('--address') + 1] ?? '';
    const s = state[addr];
    const [verb, sub] = args;
    if (verb === 'keys' && sub === 'get') {
      const id = args[args.indexOf('--id') + 1] ?? '';
      return JSON.stringify({ success: true, data: { id, pubkeyBase64: `PUB(${id})` } });
    }
    if (!s) throw new Error(`no such account ${addr}`);
    if (sub === 'profile') {
      if (!s.name) throw new Error('no profile');
      return JSON.stringify({ data: { profile: { name: s.name } } });
    }
    if (sub === 'balance') {
      return JSON.stringify({ data: { balances: [{ denom: 'nost', amount: s.funded ? '1000' : '0' }] } });
    }
    if (sub === 'snapshot') {
      const safes = s.safe ? [{ address: s.safe, name: s.name ?? '', groups: [] }] : [];
      return JSON.stringify({ success: true, data: { address: addr, snapshot: safes } });
    }
    throw new Error(`unexpected query ${args.join(' ')}`);
  };
  return { q, seen };
}

test('listAccounts annotates each key and degrades per-probe, not per-list', async () => {
  const { q } = fakeQuery({
    [A]: { name: 'alice@acme', funded: true, safe: SAFE_A },
    [B]: { funded: false }, // fresh key: no profile, no safe
  });
  const out = await listAccounts(q, () => [A, B]);

  assert.deepEqual(out[0], {
    address: A,
    name: 'alice@acme',
    funded: true,
    safes: [{ address: SAFE_A, name: 'alice@acme' }],
  });
  // B's profile lookup throws; that is a normal state, so the row still appears.
  assert.deepEqual(out[1], { address: B, funded: false, safes: [] });
});

test('zero keys → onboarding error, never a silent pick', async () => {
  const { q } = fakeQuery({});
  await assert.rejects(resolveAccountAddress(q, () => []), (e: Error) => {
    assert.ok(e instanceof AccountResolutionError);
    assert.match(e.message, /No signing key exists/);
    assert.match(e.message, /wallet_keys_create/);
    return true;
  });
});

test('exactly one key → used silently, with no network probing', async () => {
  const { q, seen } = fakeQuery({ [A]: { name: 'alice@acme', funded: true } });
  assert.equal(await resolveAccountAddress(q, () => [A]), A);
  assert.deepEqual(seen, [], 'the unambiguous path costs no query');
});

test('several keys and none named → throws, lists them, and does NOT choose', async () => {
  const { q } = fakeQuery({
    [A]: { name: 'alice@acme', funded: true, safe: SAFE_A },
    [B]: { funded: false },
  });
  await assert.rejects(resolveAccountAddress(q, () => [A, B]), (e: Error) => {
    assert.ok(e instanceof AccountResolutionError);
    assert.match(e.message, /ASK THE USER/);
    assert.match(e.message, /alice@acme/);
    assert.match(e.message, /no account yet/); // B, described honestly
    assert.equal((e as AccountResolutionError).accounts.length, 2);
    return true;
  });
});

test('a named address is validated against the keystore, not trusted', async () => {
  const { q } = fakeQuery({ [A]: { name: 'alice@acme' }, [B]: {} });
  assert.equal(await resolveAccountAddress(q, () => [A, B], B), B);

  await assert.rejects(
    resolveAccountAddress(q, () => [A, B], 'omnistar1elsewhere000000000'),
    /is not a signing key on this machine/,
  );
});

test('an account NAME resolves to its key — what the user actually says', async () => {
  const { q } = fakeQuery({
    [A]: { name: 'alice@acme', funded: true, safe: SAFE_A },
    [B]: { name: 'bob@acme', funded: true },
  });
  assert.equal(await resolveAccountAddress(q, () => [A, B], 'bob@acme'), B);
  assert.equal(await resolveAccountAddress(q, () => [A, B], 'ALICE@acme'), A, 'case-insensitive');
});

test('signerArgsFor and the env are fed by ONE resolution, so they cannot disagree', async () => {
  const { q, seen } = fakeQuery({ [A]: { name: 'alice@acme' } });
  const account = await resolveAccount(q, () => [A]);
  const lookups = seen.filter((args) => args[0] === 'keys' && args[1] === 'get');

  assert.equal(lookups.length, 1, 'one keys-get serves both routings');
  assert.deepEqual(signerArgsFor(account), ['--creator', A, `--pubkey`, `PUB(${A})`]);
  // The same pair is what walletCliEnv injects — see stateRoot.test.ts.
  assert.equal(account.address, A);
  assert.equal(account.pubkey, `PUB(${A})`);
});

test('resolveAccount adds the pubkey, and wakes the session only once settled', async () => {
  const { q } = fakeQuery({ [A]: { name: 'alice@acme' }, [B]: {} });
  let woken = 0;
  const ensureSession = async () => {
    woken++;
  };

  assert.deepEqual(await resolveAccount(q, () => [A], undefined, { ensureSession }), {
    address: A,
    pubkey: `PUB(${A})`,
  });
  assert.equal(woken, 1);

  // Ambiguity is settled BEFORE the signer is needed, so a failing call leaves
  // SSP asleep — reads stay free.
  await assert.rejects(resolveAccount(q, () => [A, B], undefined, { ensureSession }));
  assert.equal(woken, 1, 'ambiguous call never woke the session');
});

// ── the `signingKey` → `account` rename (2026-08-10) ─────────────────────────

test('the old signingKey name is ignored safely: never a wrong-key signature', async () => {
  const { q } = fakeQuery({ [A]: { name: 'alice@acme' }, [B]: { name: 'bob@acme' } });

  // One key: an ignored parameter cannot change the outcome — there is only one
  // possible answer, which is exactly what the caller meant.
  assert.equal(await resolveAccountAddress(q, () => [A], undefined), A);

  // Several keys: an ignored parameter degrades to the ambiguity error, never to
  // a guess. This is why dropping the compat fallback later is safe.
  await assert.rejects(resolveAccountAddress(q, () => [A, B], undefined), AccountResolutionError);
});
