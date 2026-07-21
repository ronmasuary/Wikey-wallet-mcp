import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { onboardSponsor, type OnboardSponsorDeps } from '../src/core/onboardSponsor.js';
import { saveGrant, loadGrant } from '../src/core/idp/sponsorGrants.js';

const CODE = 'invite-code-123';
const INVITE = `https://gateway.test/signup/app_x?invitationCode=${CODE}&username=kehat@wikey`;
const NEW_KEY = 'omnistar1newkey000000000000';
const OLD_KEY = 'omnistar1oldkey000000000000';
const PRIOR = 'omnistar1priordefault000000';
const SAFE = 'omnistar1safe00000000000000';

// The orchestrator resolves the proxy base + env through loadCfg (state root +
// env). Pin the state root to a temp dir so the grant breadcrumb never touches a
// developer's real ~/.ssp, and clear the knobs that would leak in from a shell.
const ENV_KEYS = ['WIKEY_SSP_DIR', 'WIKEY_PROXY_URL', 'WIKEY_ENV', 'CASDOOR_HOST', 'CASDOOR_ACCOUNT'];

async function withFixture(fn: () => Promise<void>): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  const savedFetch = globalThis.fetch;
  const dir = mkdtempSync(path.join(tmpdir(), 'wmcp-sponsor-'));
  process.env.WIKEY_SSP_DIR = dir;
  process.env.WIKEY_PROXY_URL = 'https://proxy.test/proxy';
  try {
    await fn();
  } finally {
    globalThis.fetch = savedFetch;
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    rmSync(dir, { recursive: true, force: true });
  }
}

const json = (obj: unknown, status = 200): Response =>
  new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json' } });

/** Fake proxy: `fund` decides the /sponsorFund reply, commit always succeeds. */
function stubProxy(fund: (address: string) => Response): string[] {
  const calls: string[] = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    const body = JSON.parse(String(init?.body ?? '{}')) as { address?: string };
    calls.push(`${u.split('/').pop()}:${body.address}`);
    if (u.endsWith('/sponsorFund')) return fund(body.address ?? '');
    if (u.endsWith('/sponsorCommit')) return json({ committed: true, address: body.address });
    throw new Error(`unexpected fetch ${u}`);
  }) as typeof fetch;
  return calls;
}

/** Deps with a happy-path default; every field is overridable per test. */
function deps(over: Partial<OnboardSponsorDeps> = {}): OnboardSponsorDeps {
  let defaultKey = PRIOR;
  return {
    query: async (args) => (args.join(' ') === 'config get user.address' ? defaultKey : ''),
    createDefaultKey: async () => {
      defaultKey = NEW_KEY;
      return 'created';
    },
    createSafe: async () => 'broadcast ok',
    listKeys: () => [PRIOR, NEW_KEY],
    safeExists: async () => false,
    enroll: async () => ({ safe: SAFE, username: 'kehat', organization: 'wikey' }),
    ...over,
  };
}

test('happy path funds, creates, commits and enrolls in one call', async () => {
  await withFixture(async () => {
    stubProxy(() => json({ funded: true }));
    const enrolled: string[] = [];
    const res = await onboardSponsor(INVITE, deps({
      enroll: async (_invite, address) => {
        enrolled.push(address);
        return { safe: SAFE, username: 'kehat', organization: 'wikey' };
      },
    }));

    assert.equal(res.stage, 'funded-created-enrolled');
    assert.equal(res.enrolled, true);
    assert.equal(res.address, NEW_KEY);
    assert.equal(res.safe, SAFE);
    assert.equal(res.username, 'kehat@wikey');
    assert.equal(res.resumed, false);
    assert.equal(res.warnings, undefined);
    // Enrollment must bind the key we onboarded, not the ambient default.
    assert.deepEqual(enrolled, [NEW_KEY]);
    assert.equal(loadGrant(CODE)?.stage, 'enrolled');
  });
});

test('create-safe succeeds but enrollment fails → partial success, not a throw', async () => {
  await withFixture(async () => {
    stubProxy(() => json({ funded: true }));
    const res = await onboardSponsor(INVITE, deps({
      enroll: async () => { throw new Error('casdoor down'); },
    }));

    assert.equal(res.stage, 'created-enroll-failed');
    assert.equal(res.enrolled, false);
    assert.equal(res.funded, true);
    assert.match(res.next ?? '', /wallet_gateway_register/);
    // The on-chain work is done and committed — it must not be repeated.
    assert.equal(loadGrant(CODE)?.stage, 'committed');
  });
});

test('breadcrumb resumes the funded key instead of minting a second identity', async () => {
  await withFixture(async () => {
    saveGrant(CODE, { address: OLD_KEY, username: 'kehat@wikey', stage: 'funded' });
    const calls = stubProxy(() => json({ funded: true }));
    let minted = false;
    const signedBy: string[] = [];

    const res = await onboardSponsor(INVITE, deps({
      listKeys: () => [PRIOR, OLD_KEY],
      createDefaultKey: async () => { minted = true; return 'created'; },
      createSafe: async (_u, _o, address) => { signedBy.push(address); return 'ok'; },
    }));

    assert.equal(minted, false, 'must not mint a key when the invite is already funded locally');
    assert.equal(res.address, OLD_KEY);
    assert.equal(res.resumed, true);
    assert.equal(res.keyCreated, false);
    assert.deepEqual(signedBy, [OLD_KEY], 'create-safe must be signed by the funded key');
    assert.deepEqual(calls, [`sponsorFund:${OLD_KEY}`, `sponsorCommit:${OLD_KEY}`]);
  });
});

test('resume skips create-safe when the safe already exists on chain', async () => {
  await withFixture(async () => {
    saveGrant(CODE, { address: OLD_KEY, username: 'kehat@wikey', stage: 'funded' });
    stubProxy(() => json({ funded: true }));
    let createCalls = 0;
    const waited: boolean[] = [];

    const res = await onboardSponsor(INVITE, deps({
      listKeys: () => [OLD_KEY],
      safeExists: async () => true,
      createSafe: async () => { createCalls++; return 'ok'; },
      enroll: async (_i, _a, { safeIsNew }) => {
        waited.push(safeIsNew);
        return { safe: SAFE, username: 'kehat', organization: 'wikey' };
      },
    }));

    assert.equal(createCalls, 0, 'chain says the safe exists — do not re-broadcast');
    assert.equal(res.stage, 'funded-created-enrolled');
    assert.equal(res.resumed, true);
    // The safe was already confirmed queryable — enrolling must not sit through
    // the ~30s validation wait a fresh create-safe needs.
    assert.deepEqual(waited, [false]);
  });
});

test('a freshly created safe enrolls with the validation wait enabled', async () => {
  await withFixture(async () => {
    stubProxy(() => json({ funded: true }));
    const waited: boolean[] = [];

    await onboardSponsor(INVITE, deps({
      enroll: async (_i, _a, { safeIsNew }) => {
        waited.push(safeIsNew);
        return { safe: SAFE, username: 'kehat', organization: 'wikey' };
      },
    }));

    assert.deepEqual(waited, [true]);
  });
});

test('proxy 409 for a locally-held key is adopted, not reported as already-used', async () => {
  await withFixture(async () => {
    // No breadcrumb (lost), so a fresh key is minted and refused; the proxy tells
    // us which address holds the reservation and we own it → resume there.
    const calls = stubProxy((address) =>
      address === OLD_KEY
        ? json({ funded: true })
        : json({ error: true, message: 'reserved', reservedAddress: OLD_KEY, committed: false }, 409),
    );

    const res = await onboardSponsor(INVITE, deps({ listKeys: () => [PRIOR, NEW_KEY, OLD_KEY] }));

    assert.equal(res.stage, 'funded-created-enrolled');
    assert.equal(res.address, OLD_KEY);
    assert.equal(res.resumed, true);
    assert.deepEqual(calls, [`sponsorFund:${NEW_KEY}`, `sponsorFund:${OLD_KEY}`, `sponsorCommit:${OLD_KEY}`]);
    // The stray minted key is now the default — that must be surfaced.
    assert.match(res.warnings?.join(' ') ?? '', /unused but is now the wallet's default/);
  });
});

test('proxy 409 for a key we do NOT hold is not a recovery-by-us claim', async () => {
  await withFixture(async () => {
    stubProxy(() => json({ error: true, message: 'reserved', reservedAddress: OLD_KEY, committed: false }, 409));

    const res = await onboardSponsor(INVITE, deps({ listKeys: () => [PRIOR, NEW_KEY] }));

    assert.equal(res.stage, 'recovery-required');
    assert.equal(res.funded, false);
    assert.match(res.message, /not a key on this machine/);
    // It must NOT claim the invite already onboarded an account — it did not.
    assert.doesNotMatch(res.message, /already used to onboard/);
  });
});

test('committed grant (403) is the only genuine already-used path', async () => {
  await withFixture(async () => {
    stubProxy(() => json({ error: true, message: 'spent', committed: true }, 403));

    const res = await onboardSponsor(INVITE, deps());

    assert.equal(res.stage, 'recovery-required');
    assert.match(res.message, /already used to onboard/);
    assert.match(res.next ?? '', /wallet_tx_request_recovery/);
  });
});

test('transient create-safe failure reports the grant as reserved and resumable', async () => {
  await withFixture(async () => {
    stubProxy(() => json({ funded: true }));

    await assert.rejects(
      onboardSponsor(INVITE, deps({ createSafe: async () => { throw new Error('node timeout'); } })),
      (e: Error) => {
        assert.match(e.message, /RESERVED \(not spent\)/);
        assert.match(e.message, /re-run wallet_onboard_sponsor/);
        assert.doesNotMatch(e.message, /consumed/);
        return true;
      },
    );
    // The breadcrumb must survive so the re-run finds the funded key.
    assert.equal(loadGrant(CODE)?.address, NEW_KEY);
    assert.equal(loadGrant(CODE)?.stage, 'funded');
  });
});

test('a failed commit warns instead of failing the onboarding', async () => {
  await withFixture(async () => {
    globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
      const u = String(url);
      const body = JSON.parse(String(init?.body ?? '{}')) as { address?: string };
      if (u.endsWith('/sponsorFund')) return json({ funded: true, address: body.address });
      return json({ error: true, message: 'no matching reservation' }, 409);
    }) as typeof fetch;

    const res = await onboardSponsor(INVITE, deps());

    assert.equal(res.stage, 'funded-created-enrolled');
    assert.match(res.warnings?.join(' ') ?? '', /ledger still shows this invite as unspent/);
  });
});

test('an invite without &username= is rejected before anything is minted', async () => {
  await withFixture(async () => {
    let minted = false;
    await assert.rejects(
      onboardSponsor(`https://gateway.test/signup/app_x?invitationCode=${CODE}`, deps({
        createDefaultKey: async () => { minted = true; return ''; },
      })),
      /no &username=/,
    );
    assert.equal(minted, false);
  });
});

test('the invitation code is never written to the grant store', async () => {
  await withFixture(async () => {
    stubProxy(() => json({ funded: true }));
    await onboardSponsor(INVITE, deps());
    const raw = JSON.stringify(loadGrant(CODE));
    assert.doesNotMatch(raw, new RegExp(CODE), 'the bearer code must not be persisted');
  });
});
