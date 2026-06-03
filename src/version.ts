// Resolve the package version at runtime (single source of truth = package.json).
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
