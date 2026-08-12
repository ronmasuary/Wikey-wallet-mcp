import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { onboardSponsor, type OnboardSponsorDeps } from '../src/core/onboardSponsor.js';
import { saveGrant, loadGrant } from '../src/core/idp/sponsorGrants.js';

const CODE = 'invite-code-123';
const INVITE = `https://gateway.test/signup/app_x?invitationCode=${CODE}&username=kehat@wikey`;
const INVITE_NO_ENROLL = `${INVITE}&enroll=false`;
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
  return {
    // No `config get user.address` probe any more: the minted key reports its
    // own address, so onboarding never reads (or moves) a default pointer.
    query: async () => '',
    createKey: async () => ({ address: NEW_KEY, pubkey: 'TkVXS0VZ' }),
    createSafe: async () => 'broadcast ok',
    listKeys: () => [PRIOR, NEW_KEY],
    findLocalAccount: async () => undefined,
    safeExists: async () => false,
    awaitSafe: async () => SAFE,
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

test('enroll=false funds and creates the safe but never enrolls', async () => {
  await withFixture(async () => {
    stubProxy(() => json({ funded: true }));
    let enrollCalled = false;
    const awaited: { address: string; safeIsNew: boolean }[] = [];
    const res = await onboardSponsor(INVITE_NO_ENROLL, deps({
      awaitSafe: async (address, { safeIsNew }) => {
        awaited.push({ address, safeIsNew });
        return SAFE;
      },
      enroll: async () => { enrollCalled = true; return { safe: SAFE, username: 'kehat', organization: 'wikey' }; },
    }));

    assert.equal(enrollCalled, false, 'a no-enroll invite must not bind a passkey');
    assert.equal(res.stage, 'funded-created');
    assert.equal(res.enrolled, false);
    assert.equal(res.funded, true);
    assert.equal(res.address, NEW_KEY);
    assert.match(res.next ?? '', /wallet_gateway_register/);
    // Terminal breadcrumb for a no-enroll grant is 'committed' + enroll:false.
    assert.equal(loadGrant(CODE)?.stage, 'committed');
    assert.equal(loadGrant(CODE)?.enroll, false);
    // With no enrollment step to absorb it, this branch must do the safe wait
    // itself — otherwise it returns success while getting_started still reads
    // stage `no-safe` and tells the user to create a safe they already have.
    assert.deepEqual(awaited, [{ address: NEW_KEY, safeIsNew: true }]);
    assert.equal(res.safe, SAFE, 'the resolved safe is reported, not left undefined');
    assert.equal(res.warnings, undefined);
  });
});

test('enroll=false reports a visible-yet timeout as a warning, not a failure', async () => {
  await withFixture(async () => {
    stubProxy(() => json({ funded: true }));
    const res = await onboardSponsor(INVITE_NO_ENROLL, deps({
      awaitSafe: async () => undefined, // never became queryable in the budget
    }));

    // Funding, create-safe and the commit all succeeded; a slow chain must not
    // downgrade the stage or re-run anything.
    assert.equal(res.stage, 'funded-created');
    assert.equal(res.funded, true);
    assert.equal(res.safe, undefined);
    assert.equal(loadGrant(CODE)?.stage, 'committed');
    // The warning has to steer the agent AWAY from the destructive "fix".
    assert.equal(res.warnings?.length, 1);
    assert.match(res.warnings?.[0] ?? '', /COMPLETE/);
    assert.match(res.warnings?.[0] ?? '', /wallet_tx_create_safe/);
  });
});

test('a completed no-enroll grant short-circuits on re-run, not driven to recovery', async () => {
  await withFixture(async () => {
    // Prior no-enroll run finished at 'committed' with enroll:false. A re-run must
    // read that as done (already-onboarded), NOT resume into the spent proxy grant.
    saveGrant(CODE, { address: OLD_KEY, username: 'kehat@wikey', stage: 'committed', enroll: false });
    globalThis.fetch = (async () => {
      throw new Error('a finished no-enroll onboarding must not re-contact the proxy');
    }) as typeof fetch;

    const res = await onboardSponsor(INVITE_NO_ENROLL, deps({
      listKeys: () => [OLD_KEY],
      findLocalAccount: async () => OLD_KEY,
    }));

    assert.equal(res.stage, 'already-onboarded');
    assert.equal(res.address, OLD_KEY);
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
      createKey: async () => { minted = true; return { address: NEW_KEY, pubkey: 'TkVXS0VZ' }; },
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
    // The stray minted key is still surfaced — but it no longer displaces
    // anything, which is the whole point: adopting the funded key used to leave
    // the wallet pointed at an unfunded one.
    assert.match(res.warnings?.join(' ') ?? '', /unused and unfunded/);
    assert.doesNotMatch(res.warnings?.join(' ') ?? '', /is now the wallet's default/);
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

test('a handle we already own short-circuits before minting or calling the proxy', async () => {
  await withFixture(async () => {
    // Any proxy call at all is a failure here: the answer is knowable locally.
    globalThis.fetch = (async () => {
      throw new Error('the proxy must not be contacted when the account is already ours');
    }) as typeof fetch;
    let minted = false;

    const res = await onboardSponsor(INVITE, deps({
      createKey: async () => { minted = true; return { address: NEW_KEY, pubkey: 'TkVXS0VZ' }; },
      findLocalAccount: async (username) => (username === 'kehat@wikey' ? OLD_KEY : undefined),
    }));

    assert.equal(res.stage, 'already-onboarded');
    assert.equal(res.address, OLD_KEY);
    assert.equal(minted, false, 'no key may be burned to learn what the keystore already knows');
    assert.equal(res.funded, false);
    assert.equal(res.keyCreated, false);
    assert.match(res.message, /already exists on this machine/);
    // It is not a recovery — the account is already ours.
    assert.doesNotMatch(res.next ?? '', /wallet_tx_request_recovery/);
  });
});

test('the pre-flight only matches the invite handle, not any local account', async () => {
  await withFixture(async () => {
    stubProxy(() => json({ funded: true }));
    // A keystore full of other people's accounts must not block a fresh invite.
    const res = await onboardSponsor(INVITE, deps({
      findLocalAccount: async (username) => (username === 'someone.else@wikey' ? OLD_KEY : undefined),
    }));

    assert.equal(res.stage, 'funded-created-enrolled');
    assert.equal(res.address, NEW_KEY);
  });
});

test('an interrupted grant still resumes even though the handle exists locally', async () => {
  await withFixture(async () => {
    // create-safe landed, then the run died: the account exists AND the grant is
    // uncommitted with no passkey. Short-circuiting here would strand both.
    saveGrant(CODE, { address: OLD_KEY, username: 'kehat@wikey', stage: 'created' });
    stubProxy(() => json({ funded: true }));

    const res = await onboardSponsor(INVITE, deps({
      listKeys: () => [OLD_KEY],
      safeExists: async () => true,
      findLocalAccount: async () => OLD_KEY,
    }));

    assert.equal(res.stage, 'funded-created-enrolled', 'an in-flight grant must finish, not report already-onboarded');
    assert.equal(res.resumed, true);
    assert.equal(res.address, OLD_KEY);
    assert.equal(loadGrant(CODE)?.stage, 'enrolled');
  });
});

test('a fully enrolled grant does short-circuit on a re-run', async () => {
  await withFixture(async () => {
    saveGrant(CODE, { address: OLD_KEY, username: 'kehat@wikey', stage: 'enrolled' });
    globalThis.fetch = (async () => {
      throw new Error('a finished onboarding must not re-contact the proxy');
    }) as typeof fetch;

    const res = await onboardSponsor(INVITE, deps({
      listKeys: () => [OLD_KEY],
      findLocalAccount: async () => OLD_KEY,
    }));

    assert.equal(res.stage, 'already-onboarded');
    assert.equal(res.address, OLD_KEY);
  });
});

test('an invite without &username= is rejected before anything is minted', async () => {
  await withFixture(async () => {
    let minted = false;
    await assert.rejects(
      onboardSponsor(`https://gateway.test/signup/app_x?invitationCode=${CODE}`, deps({
        createKey: async () => { minted = true; return { address: NEW_KEY, pubkey: 'TkVXS0VZ' }; },
      })),
      /no &username=/,
    );
    assert.equal(minted, false);
  });
});

test('an enroll=only invite is refused before anything is minted or funded', async () => {
  await withFixture(async () => {
    let minted = false;
    const calls = stubProxy(() => json({ funded: true }));
    await assert.rejects(
      onboardSponsor(`${INVITE}&enroll=only`, deps({
        createKey: async () => { minted = true; return { address: NEW_KEY, pubkey: 'TkVXS0VZ' }; },
      })),
      /ENROLL-ONLY.*wallet_gateway_register/s,
    );
    // The wrong-tool check must land before any side effect: no key minted, and
    // above all no call to the funding proxy.
    assert.equal(minted, false);
    assert.deepEqual(calls, []);
  });
});

test('a code with no grant at all is reported as such, never as a recovery', async () => {
  await withFixture(async () => {
    // What the proxy returns for an enroll-only marker: refused, nothing spent,
    // nothing reserved. The status code alone is identical to a spent grant.
    stubProxy(() =>
      json(
        { error: true, message: 'this invitation carries no funding grant (enroll-only)', committed: false, sponsored: false },
        403,
      ),
    );
    await assert.rejects(
      onboardSponsor(INVITE, deps()),
      (e: Error) => {
        assert.match(e.message, /ENROLL-ONLY invite/);
        assert.match(e.message, /wallet_gateway_register/);
        // The old behaviour was a `recovery-required` result sending the user to
        // find recovery helpers for an account nobody ever created.
        assert.doesNotMatch(e.message, /wallet_recovery_helpers|wallet_tx_request_recovery/);
        // The key was already minted by the time the proxy answered — say so.
        assert.match(e.message, new RegExp(NEW_KEY));
        return true;
      },
    );
  });
});

test('an unarmed grant (no enroll-only marker) is also not a recovery', async () => {
  await withFixture(async () => {
    // An older proxy, or a genuinely removed grant: same 403, no `sponsored` field.
    stubProxy(() => json({ error: true, message: 'no valid unspent sponsorship for this code', committed: false }, 403));
    await assert.rejects(
      onboardSponsor(INVITE, deps()),
      (e: Error) => {
        assert.match(e.message, /no funding grant for this invitation code/);
        assert.doesNotMatch(e.message, /wallet_recovery_helpers|wallet_tx_request_recovery/);
        return true;
      },
    );
  });
});

test('a genuinely spent grant still routes to recovery', async () => {
  await withFixture(async () => {
    // The regression guard for the two tests above: committed:true must keep its
    // existing meaning — this invite really did onboard someone.
    stubProxy(() => json({ error: true, message: 'sponsorship already spent for this code', committed: true }, 403));
    const res = await onboardSponsor(INVITE, deps());
    assert.equal(res.stage, 'recovery-required');
    assert.equal(res.funded, false);
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
