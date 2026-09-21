// Check that the wasm being served actually works.
//
// call() is copied straight from `crates/oag-node/assets/wallet.js`, so it takes
// the same path the browser does. **Even with a matching fingerprint, broken
// contents fail here.**
//
//   node tools/wallet-wasm-smoke.mjs [path to the wasm]
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";

const path = process.argv[2] || "crates/oag-node/assets/wallet.wasm";
const module = readFileSync(path);
const { instance } = await WebAssembly.instantiate(module, {});
const wasm = instance.exports;
const bytesOf = (ptr, len) => new Uint8Array(wasm.memory.buffer, ptr, len);
const hex = (a) => Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");

function call(request) {
  const body = new TextEncoder().encode(JSON.stringify(request));
  const input = wasm.oag_alloc(body.length);
  bytesOf(input, body.length).set(body);
  const output = wasm.oag_call(input, body.length);
  wasm.oag_free(input, body.length);
  const length = new DataView(wasm.memory.buffer).getUint32(output, true);
  const answer = new TextDecoder().decode(bytesOf(output, length + 4).slice(4));
  wasm.oag_free(output, length + 4);
  const parsed = JSON.parse(answer);
  if (parsed.error) throw new Error(parsed.error);
  return parsed.ok;
}

// Hand it the seed the same way startup does.
const seed = new Uint8Array(32);
webcrypto.getRandomValues(seed);
call({ cmd: "seed", bytes: hex(seed) });

const t0 = Date.now();
const made = call({ cmd: "create", network: "regtest", pass: "passphrase", words: 24 });
const argonMs = Date.now() - t0;
console.log(`create (one Argon2 pass): ${argonMs} ms`);
console.log(`words: ${made.phrase.split(" ").length}`);
console.log(`address: ${made.addresses[0]}`);

const record = JSON.parse(made.record);
console.log(`record: version ${record.version} / ${record.kdf.algorithm} ` +
  `m=${record.kdf.m_cost / 1024}MiB t=${record.kdf.t_cost}`);

// Reopen it.
call({ cmd: "lock" });
const t1 = Date.now();
const opened = call({ cmd: "open", network: "regtest", pass: "passphrase", record: made.record });
console.log(`unlock: ${Date.now() - t1} ms`);
if (opened.addresses[0] !== made.addresses[0]) throw new Error("the address changed");

// Go all the way through signing.
const mine = made.addresses[0];
const signed = call({
  cmd: "pay", network: "regtest", to: mine, amount: "1",
  fee_rate: "50000000000", next_height: 500,
  coins: [{ txid: "11".repeat(32), index: 0, amount: "100000000000000000",
            height: 10, coinbase: true, address: mine }],
});
console.log(`sign: ${signed.size} bytes / fee ${signed.fee} OAG`);
console.log(`txid: ${signed.txid}`);
if (!/^[0-9a-f]+$/.test(signed.hex)) throw new Error("not hexadecimal");

// Push something large through, to see it still reads after memory grows.
const many = [];
for (let i = 0; i < 400; i++) {
  many.push({ txid: i.toString(16).padStart(64, "0"), index: 0,
              amount: "100000000000000000", height: 10, coinbase: true, address: mine });
}
// Timed: signing 400 inputs is where the per-input sighash work shows up.
const t2 = Date.now();
const swept = call({
  cmd: "sweep", network: "regtest", fee_rate: "50000000000",
  next_height: 500, coins: many,
});
const sweepMs = Date.now() - t2;
console.log(`consolidate: ${swept.inputs} inputs / ${swept.size} bytes / fee ${swept.fee} OAG`);
console.log(`             ${sweepMs} ms`);

console.log("\neverything passed");
