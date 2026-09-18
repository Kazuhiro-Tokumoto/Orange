// 配ってある wasm が本当に動くことを確かめる。
//
// `crates/oag-node/assets/wallet.js` の call() をそのまま写してあるので、
// ブラウザが通るのと同じ道筋を通る。**指紋が合っていても中身が壊れて
// いれば、ここで落ちる。**
//
//   node tools/wallet-wasm-smoke.mjs [wasm への経路]
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

// 起動時と同じ手順で種を渡す。
const seed = new Uint8Array(32);
webcrypto.getRandomValues(seed);
call({ cmd: "seed", bytes: hex(seed) });

const t0 = Date.now();
const made = call({ cmd: "create", network: "regtest", pass: "passphrase", words: 24 });
const argonMs = Date.now() - t0;
console.log(`作成 (Argon2 を 1 回): ${argonMs} ms`);
console.log(`語: ${made.phrase.split(" ").length} 語`);
console.log(`住所: ${made.addresses[0]}`);

const record = JSON.parse(made.record);
console.log(`記録: 版数 ${record.version} / ${record.kdf.algorithm} ` +
  `m=${record.kdf.m_cost / 1024}MiB t=${record.kdf.t_cost}`);

// 開き直す。
call({ cmd: "lock" });
const t1 = Date.now();
const opened = call({ cmd: "open", network: "regtest", pass: "passphrase", record: made.record });
console.log(`解錠: ${Date.now() - t1} ms`);
if (opened.addresses[0] !== made.addresses[0]) throw new Error("住所が変わった");

// 署名まで通す。
const mine = made.addresses[0];
const signed = call({
  cmd: "pay", network: "regtest", to: mine, amount: "1",
  fee_rate: "50000000000", next_height: 500,
  coins: [{ txid: "11".repeat(32), index: 0, amount: "100000000000000000",
            height: 10, coinbase: true, address: mine }],
});
console.log(`署名: ${signed.size} バイト / 手数料 ${signed.fee} OAG`);
console.log(`txid: ${signed.txid}`);
if (!/^[0-9a-f]+$/.test(signed.hex)) throw new Error("16 進ではない");

// 大きいものを通して、memory が伸びた後も読めるか見る。
const many = [];
for (let i = 0; i < 400; i++) {
  many.push({ txid: i.toString(16).padStart(64, "0"), index: 0,
              amount: "100000000000000000", height: 10, coinbase: true, address: mine });
}
const swept = call({
  cmd: "sweep", network: "regtest", fee_rate: "50000000000",
  next_height: 500, coins: many,
});
console.log(`まとめ: 入力 ${swept.inputs} 個 / ${swept.size} バイト / 手数料 ${swept.fee} OAG`);

console.log("\n全部通った");
