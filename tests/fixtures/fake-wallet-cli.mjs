#!/usr/bin/env node
// Stub for `wallet-cli` signing flows. Driven by STUB_WC (JSON):
//   { prompts: string[],            // emitted on stderr in order; waits for a stdin line each
//     hang: bool,                   // after prompts, hang forever (overall-timeout test)
//     sign: {unsignedData,signingPubKey} | null,  // emit "Sign Request:" then wait for proof
//     requireStdinEnd: bool,        // after proof, require stdin 'end' before finishing (end() discipline)
//     stdout: string, exit: number }
import readline from 'node:readline';

const sc = JSON.parse(process.env.STUB_WC || '{}');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let stdinEnded = false;
process.stdin.on('end', () => {
  stdinEnded = true;
});

const pending = [];
let waiter = null;
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (l) => {
  if (waiter) {
    const w = waiter;
    waiter = null;
    w(l);
  } else pending.push(l);
});
const nextLine = () =>
  new Promise((res) => {
    if (pending.length) res(pending.shift());
    else waiter = res;
  });

async function main() {
  for (const p of sc.prompts ?? []) {
    process.stderr.write(p + '\n');
    await nextLine();
  }
  if (sc.hang) {
    await sleep(60_000);
    return;
  }
  if (sc.sign) {
    process.stderr.write('Sign Request: ' + JSON.stringify(sc.sign) + '\n');
    await nextLine(); // proof line
    if (sc.requireStdinEnd) {
      const deadline = Date.now() + 5000;
      while (!stdinEnded && Date.now() < deadline) await sleep(10);
      if (!stdinEnded) {
        process.stderr.write('STUB: stdin not ended after proof — end() discipline violated\n');
        process.exit(98);
      }
    }
  }
  if (sc.stdout) process.stdout.write(sc.stdout);
  process.exit(sc.exit ?? 0);
}
main();
