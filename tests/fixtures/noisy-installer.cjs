// A stub install script that writes to BOTH stdout and stderr, to prove the MCP
// process redirects installer stdout to its own stderr (keeping the JSON-RPC
// stdout channel clean).
console.log('INSTALLER_STDOUT_LINE');
console.error('INSTALLER_STDERR_LINE');
process.exit(0);
