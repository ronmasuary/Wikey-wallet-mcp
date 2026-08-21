import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  pickRecipientSafe,
  pickReceiveAddress,
  checkAddressFamily,
  checkSelfSend,
  addressFamily,
  assetFamily,
  nameMatchesAccount,
  lastActiveDate,
  suggestAccountNames,
  unknownNameRefusal,
} from '../src/core/recipient.js';
import type { RecipientSafe } from '../src/core/assetInfo.js';

// The same raw /snapshot/client fixture the fetch-level tests use, mapped the
// way fetchRecipientSafes maps it — so these tests run against the exact shape
// the real read produces, without duplicating the parser.
interface RawSafe {
  name: string;
  address: string;
  lastActive?: string;
  assets: { assets: Array<{ symbol: string; address: string }> };
}

const SAFES: RecipientSafe[] = (
  JSON.parse(
    readFileSync(new URL('./fixtures/recipient-snapshot.json', import.meta.url), 'utf8'),
  ) as RawSafe[]
).map((s) => ({
  address: s.address,
  name: s.name,
  ...(s.lastActive ? { lastActive: s.lastActive } : {}),
  assets: s.assets.assets.map((a) => ({ symbol: a.symbol, address: a.address })),
}));

/** Assert a refusal and hand back the narrowed value — assert.equal does not narrow. */
function refused<T extends { ok: boolean }>(r: T): Extract<T, { ok: false }> {
  assert.equal(r.ok, false, `expected a refusal, got ${JSON.stringify(r)}`);
  return r as Extract<T, { ok: false }>;
}

/** The same, for the accepted branch. */
function accepted<T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> {
  assert.equal(r.ok, true, `expected success, got ${JSON.stringify(r)}`);
  return r as Extract<T, { ok: true }>;
}

const OP20 = SAFES[0]!; // op20_safe — the name-matching one
const TREASURY = SAFES[1]!; // treasury_safe — shared; BTC/ETH/POL/OST
const EXECUTOR = SAFES[3]!; // trExecutor_safe — OST only
const OP20_BTC = 'bc1qg7f4k2m9x3vd8w0s5jn6h2ce4mua7lqp9tnpga';

const only = (safe: RecipientSafe): RecipientSafe[] => [safe];

// ─── the choice ─────────────────────────────────────────────────────────────

test('2+ safes REFUSE with a menu — the name match does not decide it', async () => {
  // Decision 3 (2026-08-19): safe names are unique and system-derived, which
  // makes op20_safe a reliable identification — and auto-selecting on it was
  // still rejected. The user sees the destination before the money moves.
  const r = refused(pickRecipientSafe({ safes: SAFES, accountName: 'op20', asset: 'BTC' }));

  assert.equal(r.kind, 'needs-choice');
  assert.equal(r.safes!.length, 5);
  assert.match(r.message, /ASK THE USER which safe/);
  assert.match(r.message, /do not pick one for them/);
});

test('the menu ranks the account-named safe first, then by recency', async () => {
  const r = refused(pickRecipientSafe({ safes: SAFES, accountName: 'op20', asset: 'BTC' }));

  assert.deepEqual(
    r.safes!.map((s) => s.name),
    [
      'op20_safe', // matches the account name
      'treasuryAcc_safe', // 2026-06-11
      'treasury_safe', // 2026-05-29
      'trExecutor_safe', // 2026-05-25
      'createTest3_safe', // 2026-03-31
    ],
    'own safe first, the rest most-recently-active first',
  );
  assert.match(r.message, /last active 2026-06-11/, 'a DATE, not the raw epoch stamp');
  assert.equal(r.safes![0]!.nameMatchesAccount, true);
  assert.ok(r.safes!.slice(1).every((s) => !s.nameMatchesAccount));
});

test("the menu says which entry is the account's own, and what the others are", async () => {
  // A user shown five near-identical addresses with no context can plausibly
  // pick a shared treasury by mistake. This is the one distinction the data
  // actually proves, so it is the only one stated.
  const r = refused(pickRecipientSafe({ safes: SAFES, accountName: 'op20', asset: 'BTC' }));

  assert.match(r.message, /\[matches the account name\]/);
  assert.match(r.message, /Only #1 is named after op20; the others are safes op20 is a member of/);
});

test("the menu carries each safe's receive address for the asset, not the safe address", async () => {
  const r = refused(pickRecipientSafe({ safes: SAFES, accountName: 'op20', asset: 'BTC' }));

  assert.equal(r.safes![0]!.to, OP20_BTC);
  assert.match(r.message, /BTC → bc1qg7f4k2m9x3…9tnpga/, 'head and tail, so two safes stay distinguishable');
  // trExecutor_safe holds OST only — shown, and shown as unusable.
  const exec = r.safes!.find((s) => s.name === 'trExecutor_safe')!;
  assert.equal(exec.to, undefined);
  assert.match(r.message, /CANNOT receive BTC/);
});

test('a menu with no name match says so without claiming none of them is theirs', async () => {
  // A safe created before the naming convention existed can be the account's
  // own under an unrelated name — rare and legacy, but "none can be confirmed"
  // costs nothing to say and "none is theirs" would sometimes be false.
  const r = refused(pickRecipientSafe({ safes: SAFES, accountName: 'someoneElse', asset: 'OST' }));

  assert.match(r.message, /None of these is named someoneElse_safe/);
  assert.match(r.message, /none can be confirmed as someoneElse's own/);
  assert.ok(r.safes!.every((s) => !s.nameMatchesAccount));
});

test('identified by ADDRESS, the menu does not claim the convention was checked', async () => {
  // Live regression (levisch, 2026-08-19): passing an address printed "None of
  // these is named after that account, so all of them are safes that account
  // merely participates in" — while levisch_safe sat at position 1. The name
  // was never known, so no claim about it can be made.
  const r = refused(pickRecipientSafe({ safes: SAFES, accountName: '', asset: 'BTC' }));

  assert.match(r.message, /convention could NOT be checked/);
  assert.match(r.message, /Pass the account NAME instead/);
  assert.doesNotMatch(r.message, /merely participates|None of these is named/);
});

test('two safes matching the convention is reported as broken, not ranked', async () => {
  // Names are system-derived and unique; two matches means the invariant is
  // broken, and a menu is not the right response to that.
  const twins = [OP20, { ...TREASURY, name: 'op20_safe' }];
  const r = refused(pickRecipientSafe({ safes: twins, accountName: 'op20', asset: 'BTC' }));

  assert.match(r.message, /WARNING: 2 safes are named op20_safe/);
  assert.match(r.message, /should not happen/);
});

test('a single safe is used without asking, and reports whether it is really theirs', async () => {
  // Decision 1: asking about a one-item list is noise and the answer could only
  // be "yes" — but a lone SHARED safe is exactly what the echo has to flag.
  const own = accepted(pickRecipientSafe({ safes: only(OP20), accountName: 'op20', asset: 'BTC' }));
  assert.equal(own.choice.nameMatchesAccount, true);
  assert.equal(own.choice.to, OP20_BTC);

  const shared = accepted(
    pickRecipientSafe({ safes: only(TREASURY), accountName: 'op20', asset: 'BTC' }),
  );
  assert.equal(
    shared.choice.nameMatchesAccount,
    false,
    "the echo can warn this is not op20's own safe",
  );
});

test('a requested safe resolves by address or by name', async () => {
  const byAddress = accepted(
    pickRecipientSafe({ safes: SAFES, accountName: 'op20', requested: TREASURY.address, asset: 'BTC' }),
  );
  assert.equal(byAddress.safe.name, 'treasury_safe');

  const byName = accepted(
    pickRecipientSafe({ safes: SAFES, accountName: 'op20', requested: 'TREASURY_SAFE', asset: 'BTC' }),
  );
  assert.equal(byName.safe.address, TREASURY.address);
});

test('an unknown toSafe lists the real ones instead of dead-ending', async () => {
  const r = refused(
    pickRecipientSafe({ safes: SAFES, accountName: 'op20', requested: 'op20_wallet', asset: 'BTC' }),
  );

  assert.equal(r.kind, 'unknown-safe');
  assert.match(r.message, /is not one of op20's safes/);
  assert.equal(r.safes!.length, 5);
});

test('G4: an account that resolved but has no safe gets its own error', async () => {
  // Never "unknown account": the name RESOLVED, so a typo hunt is the wrong
  // next step, and a just-created safe is not queryable for minutes.
  const r = refused(pickRecipientSafe({ safes: [], accountName: 'op20', asset: 'BTC' }));

  assert.equal(r.kind, 'no-safes');
  assert.match(r.message, /exists on-chain but has no safe/);
  assert.match(r.message, /2-8 minutes/);
  assert.doesNotMatch(r.message, /unknown|not found/i);
});

test('no safe able to receive the asset is refused as such, not as a choice', async () => {
  // Asking "which safe?" would be a question with no useful answer.
  const r = refused(
    pickRecipientSafe({
      safes: [EXECUTOR, { ...EXECUTOR, name: 'other_safe' }],
      accountName: 'op20',
      asset: 'ADA',
    }),
  );

  assert.equal(r.kind, 'cannot-receive');
  assert.match(r.message, /None of op20's 2 safe\(s\) can receive ADA/);
  assert.deepEqual(r.canReceive, ['OST']);
});

// ─── the SOURCE side (same mechanics, opposite question) ────────────────────

test('role:source asks which safe the money leaves FROM, via `destination`', async () => {
  // The mechanics are identical to the recipient side; the wording cannot be.
  // Asking "which safe do you want to send to?" when the ambiguity is in the
  // user's OWN wallet points them at the wrong end of the transfer.
  const r = refused(pickRecipientSafe({ safes: SAFES, accountName: 'op20', asset: 'BTC', role: 'source' }));

  assert.equal(r.kind, 'needs-choice');
  assert.match(r.message, /op20 holds 5 safes and the call did not say which to send FROM/);
  assert.match(r.message, /which safe the funds should leave from/);
  assert.match(r.message, /pass it as `destination`/);
  assert.doesNotMatch(r.message, /toSafe|send to\b/);
  // These are the user's OWN safes; pointing at the recipient tool would send
  // the agent to look up the wrong party.
  assert.match(r.message, /Call wallet_accounts for the same list/);
  assert.doesNotMatch(r.message, /wallet_resolve_recipient/);
});

test('role:source keeps the ranking, the labels and the receive addresses', async () => {
  const r = refused(pickRecipientSafe({ safes: SAFES, accountName: 'op20', asset: 'BTC', role: 'source' }));

  assert.equal(r.safes![0]!.name, 'op20_safe', 'own safe still first');
  assert.match(r.message, /\[matches the account name\]/);
  assert.match(r.message, /Only #1 is named after op20/);
});

test('role:source names the right parameter when the safe is unknown', async () => {
  const r = refused(
    pickRecipientSafe({ safes: SAFES, accountName: 'op20', requested: 'nope_safe', asset: 'BTC', role: 'source' }),
  );

  assert.equal(r.kind, 'unknown-safe');
  assert.match(r.message, /or drop destination to be shown the choice/);
});

test('role:source tells an account with no safe to create one, not to wait to be paid', async () => {
  const r = refused(pickRecipientSafe({ safes: [], accountName: 'op20', asset: 'BTC', role: 'source' }));

  assert.equal(r.kind, 'no-safes');
  assert.match(r.message, /nothing to send FROM/);
  assert.match(r.message, /wallet_tx_create_safe/);
  assert.doesNotMatch(r.message, /before they can be paid/);
});

test('one safe is used silently on the source side too', async () => {
  const r = accepted(pickRecipientSafe({ safes: only(OP20), accountName: 'op20', asset: 'BTC', role: 'source' }));
  assert.equal(r.safe.address, OP20.address);
});

// ─── the receive address ────────────────────────────────────────────────────

test('the receive address is the chain-native one — and OST is the trap', async () => {
  const btc = accepted(pickReceiveAddress({ safe: OP20, asset: 'BTC' }));
  assert.equal(btc.to, OP20_BTC);
  assert.notEqual(btc.to, OP20.address, 'never the safe address');

  // OST genuinely IS received at the safe address — which is why passing the
  // safe address as --to passes an OST test and loses money on BTC.
  const ost = accepted(pickReceiveAddress({ safe: OP20, asset: 'OST' }));
  assert.equal(ost.to, OP20.address);
});

test('G5: MATIC resolves against a safe that reports POL, and vice versa', async () => {
  // Must agree with the feasibility ladder: it resolves the alias through the
  // same findAsset, and addressing the transfer differently than the balance
  // was checked would send to a chain nobody verified.
  const polOnly: RecipientSafe = {
    address: TREASURY.address,
    name: 'pol_safe',
    assets: TREASURY.assets.filter((a) => a.symbol === 'POL'),
  };
  assert.equal(accepted(pickReceiveAddress({ safe: polOnly, asset: 'MATIC' })).symbolUsed, 'POL');

  const maticOnly: RecipientSafe = {
    address: OP20.address,
    name: 'matic_safe',
    assets: OP20.assets.filter((a) => a.symbol === 'MATIC'),
  };
  assert.equal(accepted(pickReceiveAddress({ safe: maticOnly, asset: 'POL' })).symbolUsed, 'MATIC');
});

test("G6: an ERC20 is addressed to its CHAIN's coin, not to a row of its own", async () => {
  // The safe carries chain coins; USDC has no receive row anywhere.
  const usdc = accepted(
    pickReceiveAddress({ safe: OP20, asset: 'USDC', chain: 'polygon', tokenAddress: '0xabc' }),
  );
  assert.equal(usdc.symbolUsed, 'POL', 'a Polygon token lands at the POL address');
  assert.equal(usdc.to, OP20.assets.find((a) => a.symbol === 'POL')!.address);

  // Base is the one that surprises people: its gas and its coin are ETH.
  const onBase = accepted(
    pickReceiveAddress({ safe: OP20, asset: 'USDC', chain: 'base', tokenAddress: '0xabc' }),
  );
  assert.equal(onBase.symbolUsed, 'ETH');
});

test('a token with no usable chain is refused rather than addressed by its symbol', async () => {
  const r = refused(pickReceiveAddress({ safe: OP20, asset: 'USDC', tokenAddress: '0xabc' }));
  assert.equal(r.kind, 'unknown-chain');
  assert.match(r.message, /ethereum, polygon, base/);
});

test('G2: a safe without a receive row for the asset lists what it can take', async () => {
  // A missing row is not a zero balance and must not be worded like one.
  const r = refused(pickReceiveAddress({ safe: EXECUTOR, asset: 'BTC' }));

  assert.equal(r.kind, 'cannot-receive');
  assert.match(r.message, /cannot receive BTC/);
  assert.match(r.message, /receive addresses for: OST/);
  assert.deepEqual(r.canReceive, ['OST']);
});

// ─── G1 — address family ────────────────────────────────────────────────────

test('G1 refuses the loss case: a safe address passed as --to for BTC', async () => {
  const r = refused(checkAddressFamily('BTC', OP20.address));

  assert.equal(r.kind, 'wrong-address-family');
  assert.match(r.message, /that address is omnistar/);
  assert.match(r.message, /Only OST is received there/);
  assert.match(r.message, /cannot be forced/);
});

test('G1 passes every asset addressed to its own family', async () => {
  for (const { symbol, address } of OP20.assets) {
    assert.equal(
      checkAddressFamily(symbol, address).ok,
      true,
      `${symbol} at its own receive address must pass`,
    );
  }
});

test('G1 is OPEN-WORLD: an unknown asset or unclassifiable address passes', async () => {
  // The guard is being added to `to`, which already works. A closed-world rule
  // would retroactively refuse sends that succeed today, for assets missing
  // from a table that lives in this repo rather than on the chain.
  assert.equal(checkAddressFamily('NEWCOIN', OP20.address).ok, true, 'unknown asset → no opinion');
  assert.equal(checkAddressFamily('BTC', 'nseh38fjJJ2').ok, true, 'unclassifiable address → no opinion');
  assert.equal(checkAddressFamily('SOL', OP20.address).ok, true, 'SOL is deliberately unclassified');
});

test('G1 catches cross-family mistakes in both directions', async () => {
  assert.equal(checkAddressFamily('OST', OP20_BTC).ok, false, 'OST to a bitcoin address');
  assert.equal(checkAddressFamily('ETH', OP20_BTC).ok, false, 'ETH to a bitcoin address');
  assert.equal(checkAddressFamily('BTC', '0x7f4c2a9e3d8b0f5a6c2e4d1b7a9c3e5f8d0b2a46').ok, false);
});

test('G1 CANNOT tell one EVM chain from another — and must not pretend to', async () => {
  // Ethereum, Base, Polygon and Avalanche share one address format. This is a
  // shape check, not a wrong-network guarantee, and the tool text must say so.
  const evm = '0x7f4c2a9e3d8b0f5a6c2e4d1b7a9c3e5f8d0b2a46';
  for (const symbol of ['ETH', 'POL', 'MATIC', 'BASE', 'AVAX']) {
    assert.equal(checkAddressFamily(symbol, evm).ok, true, `${symbol} passes — indistinguishable`);
  }
});

test('G1 applies to a token through its chain', async () => {
  const opts = { chain: 'polygon', tokenAddress: '0xabc' };
  assert.equal(checkAddressFamily('USDC', OP20.address, opts).ok, false, 'a token to an omnistar address');
  assert.equal(
    checkAddressFamily('USDC', '0x7f4c2a9e3d8b0f5a6c2e4d1b7a9c3e5f8d0b2a46', opts).ok,
    true,
  );
});

test('address classification does not mistake a long base58 key for a short one', async () => {
  // The reason Solana is unclassified: any rule wide enough to catch a bare
  // base58 key also swallows Dogecoin and Ripple addresses.
  const sol = OP20.assets.find((a) => a.symbol === 'SOL')!.address;
  assert.equal(addressFamily(sol), undefined, '43-char base58 stays unknown');
  assert.equal(addressFamily(OP20.assets.find((a) => a.symbol === 'DOGE')!.address), 'dogecoin');
  assert.equal(addressFamily(OP20.assets.find((a) => a.symbol === 'XRP')!.address), 'ripple');
  assert.equal(addressFamily(OP20.assets.find((a) => a.symbol === 'ADA')!.address), 'cardano');
  assert.equal(assetFamily('SOL'), undefined);
});

// ─── G3 — self-send ─────────────────────────────────────────────────────────

test('G3 refuses a send to any address the SOURCE safe owns', async () => {
  const toSafeAddress = refused(checkSelfSend({ to: OP20.address, sourceSafe: OP20, asset: 'OST' }));
  assert.equal(toSafeAddress.kind, 'self-send');
  assert.match(toSafeAddress.message, /belongs to the source safe itself/);

  const toOwnBtc = checkSelfSend({ to: OP20_BTC, sourceSafe: OP20, asset: 'BTC' });
  assert.equal(toOwnBtc.ok, false, 'the per-asset receive address counts too');
});

test('G3 is case-insensitive, because EIP-55 casing is optional', async () => {
  const evm = OP20.assets.find((a) => a.symbol === 'ETH')!.address;
  const r = checkSelfSend({ to: evm.toUpperCase().replace('0X', '0x'), sourceSafe: OP20, asset: 'ETH' });
  assert.equal(r.ok, false, 'the same address in checksum casing is still the same address');
});

test('G3 allows a genuine transfer, and is a no-op with no source safe', async () => {
  assert.equal(checkSelfSend({ to: OP20_BTC, sourceSafe: TREASURY, asset: 'BTC' }).ok, true);
  assert.equal(checkSelfSend({ to: OP20_BTC, sourceSafe: undefined, asset: 'BTC' }).ok, true);
});

// ─── the convention ─────────────────────────────────────────────────────────

test('the name convention matches case-insensitively and nothing else', async () => {
  assert.equal(nameMatchesAccount('op20_safe', 'op20'), true);
  assert.equal(nameMatchesAccount('OP20_SAFE', 'op20'), true);
  assert.equal(nameMatchesAccount('op20_safe2', 'op20'), false);
  assert.equal(nameMatchesAccount('op20', 'op20'), false, 'the safe is <name>_safe, not <name>');
  assert.equal(nameMatchesAccount('op20_safe', ''), false, 'no account name, no match');
});

test('lastActive is epoch MILLIS in a string — rendered as a date, sorted as a number', async () => {
  // Found live, 2026-08-19: the snapshot reports "1786370716000", not an ISO
  // date. The first cut sliced the first 10 characters off it and printed
  // "last active 1784454721" — a number no user can read. Lexicographic sorting
  // also only worked while every stamp had the same digit count.
  assert.equal(lastActiveDate('1769591640000'), '2026-01-28');
  assert.equal(lastActiveDate('1769591640'), '2026-01-28', 'seconds tolerated too');
  assert.equal(lastActiveDate('2026-01-28T09:14:00.000Z'), '2026-01-28', 'ISO degrades gracefully');
  assert.equal(lastActiveDate('not a time'), undefined, 'garbage is shown as nothing, not as itself');
  assert.equal(lastActiveDate(undefined), undefined);

  // Ordering must be numeric: a 13-digit stamp is later than a 10-digit one,
  // which string comparison gets backwards.
  const safes: RecipientSafe[] = [
    { address: 'omnistar1a', name: 'older_safe', lastActive: '1769591640', assets: OP20.assets },
    { address: 'omnistar1b', name: 'newer_safe', lastActive: '1786370716000', assets: OP20.assets },
  ];
  const r = refused(pickRecipientSafe({ safes, accountName: 'nobody', asset: 'BTC' }));
  assert.deepEqual(r.safes!.map((s) => s.name), ['newer_safe', 'older_safe']);
});

test('the convention holds for an org handle, which is the sponsored-user shape', async () => {
  // A sponsored account is `username@organization`, and its safe is that whole
  // handle plus _safe — the '@' and the underscores in the org name are part of
  // the name, not separators.
  const handle = 'sponsorTest1@organization_xyz';
  assert.equal(nameMatchesAccount(`${handle}_safe`, handle), true);

  const safes: RecipientSafe[] = [
    { address: OP20.address, name: `${handle}_safe`, assets: OP20.assets },
    { address: TREASURY.address, name: 'treasury_safe', assets: TREASURY.assets },
  ];
  const r = refused(pickRecipientSafe({ safes, accountName: handle, asset: 'BTC' }));
  assert.equal(r.safes![0]!.name, `${handle}_safe`, 'still ranked first');
  assert.equal(r.safes![0]!.nameMatchesAccount, true);
});

// ─── G8 — an unresolved name must ASK, never guess ──────────────────────────

/** The operator's real keystore shape on 2026-08-20, which is where this bug bit. */
const LOCAL = [
  { name: 'sponsorTest7@organization_xyz', address: 'omnistar1553jw0etc7azajqar6nyt8wgtftvx7htxxdj9e' },
  { name: 'sponsorTest2@organization_xyz', address: 'omnistar170g0375r707j3q75dasrez07mtzglat6hez6al' },
  { name: 'sponsorTest4@organization_xyz', address: 'omnistar1e2eq2l8wesg6n6vx9a4fnr52w09l6hedgnjwvh' },
  { name: 'wikeyMCP', address: 'omnistar1m756hagxk040tqvgazldxgg0nua66pqmj03uy4' },
  { name: undefined, address: 'omnistar1nokeyname000000000000000000000000000000' },
];

test('G8: a bare handle offers the account as a CANDIDATE, never as an answer', async () => {
  // The live case: the user said "sponsorTest2", the account is
  // "sponsorTest2@organization_xyz", the resolver rejected the short form, and
  // the agent completed it and sent real funds.
  const c = suggestAccountNames('sponsorTest2', LOCAL);
  assert.equal(c.length, 1);
  assert.equal(c[0]!.name, 'sponsorTest2@organization_xyz');
  assert.equal(c[0]!.why, 'handle', 'matched on the part before the "@"');

  const r = unknownNameRefusal({ asked: 'sponsorTest2', candidates: c });
  assert.equal(r.ok, false);
  assert.equal(r.kind, 'unknown-name');
  assert.equal(r.candidates!.length, 1);
  // One near-certain candidate is still a question. This is the whole fix: a
  // single match is exactly the case an agent talks itself into resolving.
  assert.match(r.message, /DO NOT PICK ONE OF THESE FOR THE USER\. ASK which they meant/);
  assert.match(r.message, /sponsorTest2@organization_xyz/);
});

test('G8: the imperative precedes the list, so it is read before a number is picked', async () => {
  const r = unknownNameRefusal({ asked: 'sponsorTest2', candidates: suggestAccountNames('sponsorTest2', LOCAL) });
  assert.ok(
    r.message.indexOf('DO NOT PICK') < r.message.indexOf('1. sponsorTest2@organization_xyz'),
    'an instruction printed under a numbered menu is read after the choice is made',
  );
});

test('G8: a shared prefix ranks below an exact handle and is labelled as weaker', async () => {
  const c = suggestAccountNames('sponsorTest', LOCAL);
  assert.deepEqual(
    c.map((x) => x.name),
    ['sponsorTest2@organization_xyz', 'sponsorTest4@organization_xyz', 'sponsorTest7@organization_xyz'],
    'all prefix matches, ordered by name for a stable menu',
  );
  assert.ok(c.every((x) => x.why === 'prefix'));

  // With one exact-handle match present, it must come first regardless of name order.
  const mixed = suggestAccountNames('sponsorTest7', LOCAL);
  assert.equal(mixed[0]!.why, 'handle');
  assert.equal(mixed[0]!.name, 'sponsorTest7@organization_xyz');
});

test('G8: no candidates still refuses, and does not imply the name is wrong', async () => {
  const c = suggestAccountNames('someoneElseEntirely', LOCAL);
  assert.deepEqual(c, []);

  const r = unknownNameRefusal({ asked: 'someoneElseEntirely', candidates: c, underlying: 'exit 1' });
  assert.equal(r.kind, 'unknown-name');
  assert.match(r.message, /is not a registered account name/);
  assert.match(r.message, /Underlying error: exit 1/, 'a transport failure must stay visible');
  // No menu, so no "do not pick" — but also no claim that the account is absent
  // everywhere, since only local names could ever have been listed.
  assert.doesNotMatch(r.message, /DO NOT PICK/);
});

test('G8: keys with no on-chain name are skipped, not offered as blanks', async () => {
  // A funded key with no account yet has name: undefined. Offering it would put
  // an unnamed row in a menu the user is being asked to choose a payee from.
  assert.deepEqual(suggestAccountNames('', LOCAL), [], 'an empty ask matches nothing');
  assert.ok(suggestAccountNames('omni', LOCAL).every((c) => c.name.trim() !== ''));
});

test('G8: matching is case-insensitive but the candidate keeps its real casing', async () => {
  const c = suggestAccountNames('SPONSORTEST2', LOCAL);
  assert.equal(c.length, 1);
  assert.equal(c[0]!.name, 'sponsorTest2@organization_xyz', 'the name to pass back is the stored one');
});
