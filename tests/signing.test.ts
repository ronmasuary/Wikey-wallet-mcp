import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { runSigningPrompted } from '../src/core/signing.js';
import { mintKey } from '../src/core/rotation.js';

const WC = fileURLToPath(new URL('./fixtures/fake-wallet-cli.mjs', import.meta.url));
const SSP = fileURLToPath(new URL('./fixtures/fake-ssp-util.mjs', import.meta.url));
const NONCE = fileURLToPath(new URL('./fixtures/.nonce-signing', import.meta.url));

function withWC(scenario: object, fn: () => Promise<void>): Promise<void> {
  const prev = process.env.STUB_WC;
  process.env.STUB_WC = JSON.stringify(scenario);
  return fn().finally(() => {
    if (prev === undefined) delete process.env.STUB_WC;
    else process.env.STUB_WC = prev;
  });
}

test('happy path: prompt-before-proof, proof, end() discipline, exit 0', async () => {
  await withWC(
    {
      prompts: ['Your selection:'],
      sign: { unsignedData: 'AABBCC', signingPubKey: 'PUBKEY' },
      requireStdinEnd: true, // stub fails (98) if stdin not ended after proof
      stdout: '{"ok":true,"txhash":"DEAD"}',
      exit: 0,
    },
    async () => {
      const out = await runSigningPrompted({
        walletCli: WC,
        sspUtil: SSP,
        nonceFile: NONCE,
        key: mintKey(),
        args: [],
        queue: [{ match: 'Your selection', respond: () => '1\n' }],
      });
      assert.equal(out, '{"ok":true,"txhash":"DEAD"}');
    },
  );
});

test('per-prompt timeout fires when the expected prompt never appears', async () => {
  await withWC({ prompts: ['UNEXPECTED PROMPT:'] }, async () => {
    await assert.rejects(
      runSigningPrompted({
        walletCli: WC,
        sspUtil: SSP,
        nonceFile: NONCE,
        key: mintKey(),
        args: [],
        queue: [{ match: 'WANTED', respond: () => 'x\n' }],
        opts: { perPromptMs: 150, overallMs: 5000 },
      }),
      /stuck waiting: "WANTED"/,
    );
  });
});

test('overall timeout fires when the CLI hangs after a prompt', async () => {
  await withWC({ prompts: ['Go:'], hang: true }, async () => {
    await assert.rejects(
      runSigningPrompted({
        walletCli: WC,
        sspUtil: SSP,
        nonceFile: NONCE,
        key: mintKey(),
        args: [],
        queue: [{ match: 'Go', respond: () => 'x\n' }],
        opts: { perPromptMs: 5000, overallMs: 200 },
      }),
      /overall timeout/,
    );
  });
});

test('error-detail extraction: parses error.message from stdout JSON on non-zero exit', async () => {
  await withWC(
    {
      sign: { unsignedData: 'AA', signingPubKey: 'PK' },
      requireStdinEnd: true,
      stdout: '{"error":{"message":"boom detail from cli"}}',
      exit: 1,
    },
    async () => {
      await assert.rejects(
        runSigningPrompted({ walletCli: WC, sspUtil: SSP, nonceFile: NONCE, key: mintKey(), args: [], queue: [] }),
        /boom detail from cli/,
      );
    },
  );
});
