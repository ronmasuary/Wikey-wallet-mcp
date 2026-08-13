// Public barrel for the transport-agnostic core. The MCP wrapper
// (src/mcp-server.ts) is the product; this is the unit-testable library.

export * from './snapshot.js';
export * from './snapshotCache.js';
export * from './signing.js';
export * from './accounts.js';
export * from './proof.js';
export * from './query.js';
export * from './gettingStarted.js';
export * from './onboardSponsor.js';
export * from './recoveryDeeplink.js';
export * from './txFeasibility.js';
export * from './recoveryRequests.js';
export * from './rotation.js';
export * from './session.js';
export * from './binPaths.js';
export * from './installer.js';
export * from './configLock.js';
export * from './migrateDefaultKey.js';
export * from './redact.js';
export { Mutex } from './mutex.js';
