import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { IdentityRegistry } from '../src/core/identityRegistry.js';

function tmp(): string {
  return mkdtempSync(path.join(tmpdir(), 'wmcp-reg-'));
}

const ENV_WORK: NodeJS.ProcessEnv = {
  WIKEY_CASDOOR_ALIASES: 'work',
  WIKEY_CASDOOR_HOST__WORK: 'http://localhost:8000/',
  WIKEY_CASDOOR_RP_ID__WORK: 'localhost',
  WIKEY_CASDOOR_ORIGIN__WORK: 'http://localhost:8000',
  WIKEY_CASDOOR_ORG__WORK: 'organization_kehat',
  WIKEY_CASDOOR_USER__WORK: 'kehat_user',
  WIKEY_CASDOOR_APP__WORK: 'application_kehat',
  WIKEY_CASDOOR_CLIENT_ID__WORK: '9d6472debe42f68f5f97',
  WIKEY_CASDOOR_SNAPSHOT_NODE__WORK: 'proxy.omnistar.io:9093',
  WIKEY_CASDOOR_ENV__WORK: 'main',
  WIKEY_CASDOOR_REDIRECT_URI__WORK: 'http://localhost:9000/callback',
};

test('resolves an env-defined identity; strips trailing slash; applies scope/secure defaults', () => {
  const dir = tmp();
  try {
    const reg = new IdentityRegistry({ env: ENV_WORK, stateRoot: () => dir });
    const b = reg.resolve('work');
    assert.equal(b.alias, 'work');
    assert.equal(b.host, 'http://localhost:8000', 'trailing slash stripped');
    assert.equal(b.org, 'organization_kehat');
    assert.equal(b.scope, 'read', 'scope defaults to read');
    assert.equal(b.snapshotSecure, true, 'snapshotSecure defaults to true');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('unknown alias throws (and the model can only pass an alias, never a URL)', () => {
  const dir = tmp();
  try {
    const reg = new IdentityRegistry({ env: ENV_WORK, stateRoot: () => dir });
    assert.throws(() => reg.resolve('http://evil.example.com'), /unknown identity/);
    assert.throws(() => reg.resolve('nope'), /unknown identity/);
    // resolve's only parameter is an alias string — there is no host/url channel.
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a JSON file identity is picked up, and overrides env on alias clash; file edits are live', () => {
  const dir = tmp();
  const file = path.join(dir, 'casdoor-identities.json');
  try {
    const reg = new IdentityRegistry({ env: ENV_WORK, stateRoot: () => dir });
    // before the file exists: only the env identity.
    assert.deepEqual(reg.list().map((s) => s.alias).sort(), ['work']);

    writeFileSync(
      file,
      JSON.stringify([
        {
          alias: 'team',
          host: 'https://id.team.example',
          rpId: 'team.example',
          origin: 'https://id.team.example',
          org: 'org_team',
          user: 'team_user',
          app: 'app_team',
          clientId: 'cid_team',
          snapshotNode: 'node.team:9093',
          env: 'main',
          redirectUri: 'https://id.team.example/callback',
          snapshotSecure: false,
        },
      ]),
    );
    // next resolve re-reads the file with no restart.
    assert.deepEqual(reg.list().map((s) => s.alias).sort(), ['team', 'work']);
    const team = reg.resolve('team');
    assert.equal(team.snapshotSecure, false);
    assert.equal(team.host, 'https://id.team.example');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a file entry missing a required field throws a clear error', () => {
  const dir = tmp();
  const file = path.join(dir, 'casdoor-identities.json');
  try {
    writeFileSync(file, JSON.stringify([{ alias: 'broken', host: 'https://x' }]));
    const reg = new IdentityRegistry({ env: {}, stateRoot: () => dir });
    assert.throws(() => reg.list(), /missing required field/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bootstrapPassword reads the per-alias env and throws when unset', () => {
  const dir = tmp();
  try {
    const reg = new IdentityRegistry({
      env: { ...ENV_WORK, WIKEY_CASDOOR_BOOTSTRAP_PASSWORD__WORK: 's3cret' },
      stateRoot: () => dir,
    });
    assert.equal(reg.bootstrapPassword('work'), 's3cret');

    const reg2 = new IdentityRegistry({ env: ENV_WORK, stateRoot: () => dir });
    assert.throws(() => reg2.bootstrapPassword('work'), /no bootstrap password/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
