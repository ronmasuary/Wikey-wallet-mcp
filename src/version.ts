// Resolve the package version at runtime (single source of truth = package.json).
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

export function createRequireResolveVersion(): string {
  try {
    const require = createRequire(import.meta.url);
    // dist/version.js → ../package.json ; src/version.ts → ../package.json
    const pkg = require('../package.json') as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/**
 * Re-read the version straight off disk, bypassing the require cache.
 *
 * `createRequireResolveVersion` is called once at startup and then frozen in the
 * module cache — which is exactly right for "what am I running", and exactly
 * wrong for "what is installed". `npm i -g` overwrites the package in place
 * while the client keeps the old process alive, so only a fresh read sees the
 * upgrade. The difference between the two is what tells a user their client is
 * still serving the pre-upgrade build (see core/restartNotice.ts).
 */
export function readInstalledVersionFromDisk(): string | undefined {
  try {
    const require = createRequire(import.meta.url);
    const pkgPath = require.resolve('../package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version?: string };
    return pkg.version;
  } catch {
    return undefined;
  }
}
