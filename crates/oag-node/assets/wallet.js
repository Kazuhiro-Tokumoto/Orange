// The Orange (OAG) wallet.
//
// This file **never touches keys**. Only the wasm does. All this does is
//
//   - moving things on and off the screen
//   - querying the node
//   - putting the encrypted record in localStorage
//
// The passphrase passes through once on its way to the wasm, but
// neither the seed nor any private key ever comes back to this side.
"use strict";

const RECORD_KEY = "oag.wallet.record";
// How many indices are queried at a time when restoring from a phrase.
const WINDOW = 200;
// The cap on how many windows the search looks at. **Never build an endless loop.**
// Anyone who handed out this many addresses is better off bringing the record along.
const WINDOWS = 25;

let wasm = null;
let chain = null;
let state = { addresses: [], coins: [], total: "0", truncated: false, count: 0 };

// ======== wasm ========

function bytes(ptr, len) {
  return new Uint8Array(wasm.memory.buffer, ptr, len);
}

function hex(array) {
  return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
}

// One JSON in, one JSON out. The reply is [length, 4 bytes LE][contents].
function call(request) {
  const body = new TextEncoder().encode(JSON.stringify(request));
  const input = wasm.oag_alloc(body.length);
  bytes(input, body.length).set(body);

  const output = wasm.oag_call(input, body.length);
  wasm.oag_free(input, body.length);

  // Memory can grow on every allocation. **Re-read it every time.**
  const length = new DataView(wasm.memory.buffer).getUint32(output, true);
  const answer = new TextDecoder().decode(bytes(output, length + 4).slice(4));
  wasm.oag_free(output, length + 4);

  const parsed = JSON.parse(answer);
  if (parsed.error) throw new Error(parsed.error);
  return parsed.ok;
}

// ======== the node ========

async function ask(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  const answer = await response.json();
  if (answer.error) throw new Error(answer.error);
  return answer;
}

// ======== screen helpers ========

const $ = (id) => document.getElementById(id);

function show(id, visible) {
  $(id).classList.toggle("hidden", !visible);
}

function say(id, message, bad) {
  const node = $(id);
  node.textContent = message;
  node.className = bad ? "bad" : "note";
}

function tabs(group, chosen) {
  for (const [tab, pane] of group) {
    const on = tab === chosen;
    $(tab).setAttribute("aria-selected", String(on));
    show(pane, on);
  }
}

// Let the page paint once before heavy work, so it does not freeze.
// Argon2 takes seconds. With no feedback on the press it looks broken.
function breathe() {
  return new Promise((resolve) => setTimeout(resolve, 30));
}

async function working(button, label, task) {
  const was = button.textContent;
  button.disabled = true;
  button.textContent = label;
  await breathe();
  try {
    return await task();
  } finally {
    button.disabled = false;
    button.textContent = was;
  }
}

// ======== the record ========

// Some browsers cannot use storage (private windows, storage disabled).
// **Funds are not lost when it cannot be stored.** The recovery phrase brings
// them back. But the user must be told that it will not reopen.
const STORAGE_FAILED =
  "No record could be stored on this machine. Close it and it will not reopen. " +
  "Be sure to write down the recovery phrase.";

function keepRecord(record) {
  try {
    localStorage.setItem(RECORD_KEY, record);
    return true;
  } catch (e) {
    return false;
  }
}

function storedRecord() {
  try {
    return localStorage.getItem(RECORD_KEY);
  } catch (e) {
    return null;
  }
}

// ======== the lock ========

const GATE = [
  ["tab-open", "pane-open"],
  ["tab-new", "pane-new"],
  ["tab-restore", "pane-restore"],
  ["tab-verify", "pane-verify"],
];

function gateReady() {
  const record = storedRecord();
  show("no-record", !record);
  show("have-record", !!record);
  tabs(GATE, record ? "tab-open" : "tab-new");
}

async function doOpen() {
  const record = storedRecord();
  if (!record) return say("gate-msg", "there is no record on this machine", true);
  const pass = $("open-pass").value;
  await working($("do-open"), "unlocking…", async () => {
    try {
      const opened = call({
        cmd: "open",
        network: chain.network,
        pass,
        record,
      });
      $("open-pass").value = "";
      await enterWallet(opened.addresses);
    } catch (e) {
      say("gate-msg", e.message, true);
    }
  });
}

async function doCreate() {
  const pass = $("new-pass").value;
  if (pass !== $("new-pass2").value) {
    return say("gate-msg", "the two passphrases do not match", true);
  }
  await working($("do-new"), "creating…", async () => {
    try {
      const made = call({
        cmd: "create",
        network: chain.network,
        pass,
        words: Number($("new-words").value),
      });
      $("new-pass").value = $("new-pass2").value = "";
      const kept = keepRecord(made.record);
      showBackup(made.phrase, made.addresses, made.record, kept);
    } catch (e) {
      say("gate-msg", e.message, true);
    }
  });
}

async function doRestore() {
  const phrase = $("res-phrase").value.trim().replace(/\s+/g, " ");
  const pass = $("res-pass").value;
  await working($("do-restore"), "restoring…", async () => {
    try {
      const back = call({ cmd: "restore", network: chain.network, pass, phrase });
      $("res-phrase").value = "";
      $("res-pass").value = "";
      const kept = keepRecord(back.record);
      if (!kept) say("gate-msg", STORAGE_FAILED, true);
      const found = await discover();
      await enterWallet(found);
    } catch (e) {
      say("gate-msg", e.message, true);
    }
  });
}

// Restoring from the phrase alone, nothing records how far it was used.
//
// **Do not decide from unspent outputs alone.** An address that received
// and then spent everything has no unspent outputs, so stopping there
// misses the funds beyond it. Evidence of use is found in the history.
async function discover() {
  say("gate-msg", "querying the chain…", false);
  let highest = -1;
  for (let window = 0; window < WINDOWS; window += 1) {
    const from = window * WINDOW;
    const looked = call({ cmd: "derive", from, count: WINDOW });
    let used = [];
    if (chain.indexed) {
      // We only need to know whether it was used. **The contents do not matter.**
      used = (await ask("/api/history", { addresses: looked.addresses, max: 1 })).used;
    } else {
      // Without an index there is no history. **Search on remaining outputs alone.**
      // Say on screen that this can miss things.
      const scanned = await ask("/api/scan", { addresses: looked.addresses });
      used = scanned.utxos.map((u) => ({ address: u.address }));
    }
    for (const entry of used) {
      const at = looked.addresses.indexOf(entry.address);
      if (at >= 0) highest = Math.max(highest, from + at);
    }
    // No trace in this window is taken to mean none beyond it either.
    if (used.length === 0) break;
  }
  const grown = call({ cmd: "grow", accounts: Math.max(highest + 1, 1) });
  keepRecord(grown.record);
  return grown.addresses;
}

// When `kept` is false the record is not on this machine. **There is nothing to reopen.**
//
// `record` is used for the download. **Do not re-read it from storage.** Re-reading
// after a failed store yields an empty file exactly when the backup matters most.
function showBackup(phrase, addresses, record, kept) {
  show("no-storage", kept === false);
  const words = phrase.split(" ");
  const box = $("phrase-words");
  box.textContent = "";
  words.forEach((word, n) => {
    const span = document.createElement("span");
    const number = document.createElement("b");
    number.textContent = String(n + 1);
    span.append(number, document.createTextNode(word));
    box.append(span);
  });

  $("do-download").onclick = () => {
    const blob = new Blob([record], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "oag-wallet.json";
    link.click();
    URL.revokeObjectURL(link.href);
  };
  $("do-backed").onclick = () => {
    box.textContent = "";
    enterWallet(addresses);
  };

  show("gate", false);
  show("backup", true);
}

// ======== the wallet itself ========

const PANES = [
  ["tab-recv", "pane-recv"],
  ["tab-send", "pane-send"],
  ["tab-coins", "pane-coins"],
  ["tab-sign", "pane-sign"],
];

async function enterWallet(addresses) {
  state.addresses = addresses;
  show("gate", false);
  show("backup", false);
  show("wallet", true);
  tabs(PANES, "tab-recv");
  $("recv-addr").textContent = addresses[addresses.length - 1];
  fillSignAddresses();
  await refresh();
}

async function refresh() {
  const scanned = await ask("/api/scan", { addresses: state.addresses });
  state.coins = scanned.utxos;
  state.total = scanned.totaloag;
  state.count = scanned.count;
  state.truncated = scanned.truncated;
  chain = await ask("/api/info", {});
  draw();
}

function mature(coin) {
  return !coin.coinbase || chain.height + 1 >= coin.height + chain.maturity;
}

function draw() {
  const usable = state.coins.filter(mature);
  const waiting = state.coins.length - usable.length;

  $("bal").textContent = state.total;
  const parts = [`${state.count} unspent outputs`];
  if (waiting > 0) parts.push(`${waiting} of them waiting to mature`);
  if (state.truncated) parts.push("the scan hit its limit, so this is not all of them");
  $("bal-sub").textContent = parts.join(" · ");

  const list = $("coins");
  list.textContent = "";
  for (const coin of state.coins.slice(0, 200)) {
    const row = document.createElement("div");
    row.className = "utxo";
    const who = document.createElement("div");
    who.className = "who mono";
    who.textContent = `${coin.txid.slice(0, 12)}…:${coin.index}`;
    if (!mature(coin)) {
      const pill = document.createElement("span");
      pill.className = "pill";
      pill.textContent = "maturing";
      who.append(pill);
    }
    const much = document.createElement("div");
    much.textContent = `${coin.amountoag} OAG`;
    row.append(who, much);
    list.append(row);
  }
  $("coins-head").textContent =
    state.coins.length > 200
      ? `showing 200 of ${state.count}`
      : `${state.count}`;
  show("do-sweep", usable.length >= 2);
}

function usableCoins() {
  return state.coins.filter((c) => c.address);
}

async function doSend() {
  const to = $("send-to").value.trim();
  const amount = $("send-amount").value.trim();
  say("send-msg", "", false);
  await working($("do-send"), "signing…", async () => {
    try {
      const signed = call({
        cmd: "pay",
        network: chain.network,
        to,
        amount,
        fee_rate: chain.feerate,
        next_height: chain.height + 1,
        coins: usableCoins(),
      });
      const sent = await ask("/api/send", { hex: signed.hex });
      $("send-to").value = $("send-amount").value = "";
      say("send-msg", `sent. ${sent.txid} (fee ${signed.fee} OAG)`, false);
      await refresh();
    } catch (e) {
      say("send-msg", e.message, true);
    }
  });
}

async function doSweep() {
  say("sweep-msg", "", false);
  await working($("do-sweep"), "consolidating…", async () => {
    try {
      const signed = call({
        cmd: "sweep",
        network: chain.network,
        fee_rate: chain.feerate,
        next_height: chain.height + 1,
        coins: usableCoins(),
      });
      const sent = await ask("/api/send", { hex: signed.hex });
      say(
        "sweep-msg",
        `folded ${signed.inputs} into one. ${sent.txid} ` +
          `(${signed.size} bytes, fee ${signed.fee} OAG)`,
        false,
      );
      await refresh();
    } catch (e) {
      say("sweep-msg", e.message, true);
    }
  });
}

async function doNewAddress() {
  await working($("do-newaddr"), "creating…", async () => {
    try {
      const grown = call({ cmd: "grow", accounts: state.addresses.length + 1 });
      keepRecord(grown.record);
      state.addresses = grown.addresses;
      $("recv-addr").textContent = grown.addresses[grown.addresses.length - 1];
      fillSignAddresses();
      await refresh();
    } catch (e) {
      say("bal-sub", e.message, true);
    }
  });
}

function doLock() {
  call({ cmd: "lock" });
  state = { addresses: [], coins: [], total: "0", truncated: false, count: 0 };
  show("wallet", false);
  show("gate", true);
  say("gate-msg", "", false);
  gateReady();
}

// ======== startup ========

async function boot() {
  // A page delivered in plaintext gives no sign that it was swapped out.
  // **Warn unless it was opened locally.**
  const local = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(location.hostname);
  show("insecure", location.protocol !== "https:" && !local);

  const module = await fetch("/wallet.wasm").then((r) => r.arrayBuffer());
  wasm = (await WebAssembly.instantiate(module, {})).instance.exports;

  // The wasm has no source of randomness. **We hand it a seed.**
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  call({ cmd: "seed", bytes: hex(seed) });
  seed.fill(0);

  chain = await ask("/api/info", {});
  $("chain").textContent = `${chain.network} · height ${chain.height}`;

  show("boot", false);
  gateReady();
}

// ======== signing a message ========

// Every address of this wallet can sign. The first one is chosen at the
// start, as the CLI's `sign` does without `--address`; a choice already made
// is kept when the list grows.
function fillSignAddresses() {
  const box = $("sign-addr");
  const chosen = box.value;
  box.replaceChildren(
    ...state.addresses.map((address) => {
      const option = document.createElement("option");
      option.value = address;
      option.textContent = address;
      return option;
    }),
  );
  if (state.addresses.includes(chosen)) box.value = chosen;
}

// The message is signed as the UTF-8 bytes of exactly what is in the box.
// **Nothing is trimmed and no newline is added**, so that the CLI's
// `--message` and this agree byte for byte.
function doSign() {
  const message = $("sign-msg").value;
  const address = $("sign-addr").value;
  show("sign-copy-row", false);
  $("sign-sig").textContent = "";
  if (!message) return say("sign-out", "there is nothing to sign", true);

  // One look before it happens. The signature cannot move coins, but it can
  // be shown to others as proof, so it should not leave without being read.
  const shown = message.length > 300 ? `${message.slice(0, 300)}…` : message;
  if (!confirm(`Sign this with ${address}?\n\n${shown}\n\nAnyone can then show that this address signed it.`)) return;

  try {
    const out = call({ cmd: "sign_message", message, address });
    say("sign-out", `${out.address} signed ${out.bytes} bytes`);
    $("sign-sig").textContent = out.signature;
    show("sign-copy-row", true);
  } catch (e) {
    say("sign-out", e.message, true);
  }
}

// Verification needs no wallet, so this runs whether or not one is open.
function doVerify() {
  const address = $("ver-addr").value.trim();
  const signature = $("ver-sig").value.trim();
  const message = $("ver-msg").value;
  try {
    const out = call({ cmd: "verify_message", address, signature, message });
    say("ver-msg-out", `ok — ${out.address} signed these ${out.bytes} bytes on ${out.network}`);
    $("ver-msg-out").className = "ok";
  } catch (e) {
    // The usual reason is that the message changed on its way here.
    // **It is not repaired and retried** — what was signed is what is here.
    let hint = "";
    if (message.includes("\r\n")) hint = " (the message has CRLF line endings; a copy through Windows or a chat client may have rewritten them)";
    else if (message.endsWith("\n")) hint = " (the message ends with a newline; check whether it should)";
    say("ver-msg-out", e.message + hint, true);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  for (const [tab] of GATE) $(tab).onclick = () => tabs(GATE, tab);
  for (const [tab] of PANES) $(tab).onclick = () => tabs(PANES, tab);

  $("do-open").onclick = doOpen;
  $("do-new").onclick = doCreate;
  $("do-restore").onclick = doRestore;
  $("do-send").onclick = doSend;
  $("do-sweep").onclick = doSweep;
  $("do-sign").onclick = doSign;
  $("do-verify").onclick = doVerify;
  $("do-copysig").onclick = () => navigator.clipboard.writeText($("sign-sig").textContent);
  $("do-refresh").onclick = () => refresh();
  $("do-newaddr").onclick = doNewAddress;
  $("do-lock").onclick = doLock;
  $("do-copy").onclick = () => navigator.clipboard.writeText($("recv-addr").textContent);
  $("do-phrase").onclick = () => {
    const seen = call({ cmd: "phrase" });
    showBackup(seen.phrase, state.addresses, storedRecord() || "", true);
  };
  $("do-forget").onclick = () => {
    if (!confirm("This deletes the record from this machine. Without the recovery phrase it cannot be restored.")) return;
    try {
      localStorage.removeItem(RECORD_KEY);
    } catch (e) {
      /* carry on even if it cannot be deleted */
    }
    gateReady();
  };

  boot().catch((e) => {
    $("boot").textContent = `cannot start: ${e.message}`;
    $("boot").className = "bad";
  });
});
