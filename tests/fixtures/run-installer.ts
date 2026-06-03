// Test runner: invoke runInstallScript on a given script path. Used to verify
// (in a child process) that the installer's output goes to stderr only and the
// MCP stdout channel stays clean.
import { runInstallScript } from '../../src/core/installer.js';

const script = process.argv[2]!;
runInstallScript(script).then(
  () => process.exit(0),
  (e: unknown) => {
    process.stderr.write('ERR ' + (e as Error).message + '\n');
    process.exit(1);
  },
);
