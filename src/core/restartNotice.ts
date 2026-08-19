// "Restart your AI client" — the one piece of onboarding an MCP server cannot
// deliver by itself.
//
// An MCP server has NO channel to the user until the client has loaded it, and a
// client loads its servers exactly once, at startup. So the first-install advice
// ("you must restart your client before the wallet tools appear") is by
// definition too late coming from a tool result: if a tool ran, the restart
// already happened. That message belongs to `doctor` and the install docs, which
// reach the user in the terminal they are actually looking at.
//
// It was briefly delivered by an npm `postinstall` banner too (shipped in 1.3.0,
// removed after). That does NOT work: npm 7+ suppresses lifecycle-script output
// unless the user passes --foreground-scripts, so the banner was invisible on a
// normal install — verified against the published package. Do not reintroduce
// it: besides buying nothing, a postinstall hook in a wallet package means
// behaviour differs under the common `--ignore-scripts` hardening, and it hands
// anyone who compromises the package a code-execution hook on install.
//
// What this module covers is the half that IS detectable from inside a running
// server: an UPGRADE performed while the client stayed up. `npm i -g` replaces
// the files on disk in place, but the client keeps the already-loaded process
// alive, so the user is talking to the OLD build while believing they upgraded.
// Comparing the version this process was started with against the version now on
// disk detects exactly that, and the notice rides out on wallet_getting_started
// (the tool an unsure user is steered to anyway) plus doctor.
//
// Deliberately NOT a hard failure: the old build still works. It is a note.

export interface RestartNotice {
  /** Version of the code serving this call. */
  running: string;
  /** Version currently installed on disk (what a restart would load). */
  installed: string;
  /** Ready to relay verbatim. */
  message: string;
}

/**
 * Compare the running build against what is installed on disk.
 *
 * Returns undefined when they agree, when either is unknown, or when the on-disk
 * copy is OLDER (a downgrade is someone's deliberate act, and a version string
 * we cannot parse must never manufacture a scary note). String inequality is the
 * signal — no semver ordering is attempted beyond the unknown-value guards,
 * because any difference at all means the process predates the package.
 */
export function detectStaleBuild(running: string | undefined, installed: string | undefined): RestartNotice | undefined {
  if (!running || !installed) return undefined;
  if (running === '0.0.0' || installed === '0.0.0') return undefined; // version lookup failed
  if (running === installed) return undefined;
  return {
    running,
    installed,
    message:
      `This MCP server process is running v${running}, but v${installed} is what is installed on disk. ` +
      `The upgrade happened while your AI client was already up, and a client loads its MCP servers only ` +
      `at startup — so everything you get from the wallet until then comes from the OLD build. ` +
      `RESTART YOUR AI CLIENT COMPLETELY (quit the application, not just this conversation or window) to ` +
      `load v${installed}. Nothing is broken in the meantime and no key material is affected; the old ` +
      `build simply keeps answering until it is replaced.`,
  };
}

/**
 * The first-install instruction, kept here as the single source of truth so the
 * `doctor` output and the docs cannot drift apart. It is never
 * returned from a tool — by the time a tool can answer, it is already moot.
 */
export const FIRST_INSTALL_RESTART_NOTICE =
  'RESTART YOUR AI CLIENT COMPLETELY after registering this server — quit the application, ' +
  'do not just close the window or open a new chat. MCP servers are loaded only when the client ' +
  'starts, so until you restart, the wallet tools will not appear and your agent cannot see them.';
