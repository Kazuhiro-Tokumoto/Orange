// Orange (OAG) のウォレット。
//
// ここは**鍵に触らない**。触るのは wasm の中だけで、こちらは
//
//   - 画面の出し入れ
//   - ノードへの問い合わせ
//   - 暗号化された記録を localStorage に置くこと
//
// しかやらない。パスフレーズは wasm へ渡すために一度だけ通るが、
// 種と秘密鍵がこちら側へ返ることは無い。
"use strict";

const RECORD_KEY = "oag.wallet.record";
// 語から戻したときに、一度に問い合わせる番号の幅。
const WINDOW = 200;
// 探索で見る窓の数の上限。**終わらない輪を作らない。**
// ここに当たるほど配った人は、記録を持ち込んで開く方が速い。
const WINDOWS = 25;

let wasm = null;
let chain = null;
let state = { addresses: [], coins: [], total: "0", truncated: false, count: 0 };

// ━━━━━━━━ wasm ━━━━━━━━

function bytes(ptr, len) {
  return new Uint8Array(wasm.memory.buffer, ptr, len);
}

function hex(array) {
  return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
}

// JSON を 1 本渡して 1 本返る。返りは [長さ 4 バイト LE][中身]。
function call(request) {
  const body = new TextEncoder().encode(JSON.stringify(request));
  const input = wasm.oag_alloc(body.length);
  bytes(input, body.length).set(body);

  const output = wasm.oag_call(input, body.length);
  wasm.oag_free(input, body.length);

  // 確保のたびに memory が伸びうる。**毎回見直す。**
  const length = new DataView(wasm.memory.buffer).getUint32(output, true);
  const answer = new TextDecoder().decode(bytes(output, length + 4).slice(4));
  wasm.oag_free(output, length + 4);

  const parsed = JSON.parse(answer);
  if (parsed.error) throw new Error(parsed.error);
  return parsed.ok;
}

// ━━━━━━━━ ノード ━━━━━━━━

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

// ━━━━━━━━ 画面の道具 ━━━━━━━━

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

// 画面を止めずに、重い処理の前に一度描かせる。
// Argon2 は数秒かかる。押した手応えが無いと壊れたように見える。
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

// ━━━━━━━━ 記録 ━━━━━━━━

// 置き場を使えない browser がある (私的な窓、保存を止めてある設定)。
// **置けなくても資金は消えない。** 控えの語さえあれば戻せる。だが
// 「次に開けない」ことは伝わっていなければならない。
const STORAGE_FAILED =
  "この機械に記録を置けませんでした。閉じると開き直せません。" +
  "控えの語を必ず書き留めてください。";

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

// ━━━━━━━━ 錠 ━━━━━━━━

const GATE = [
  ["tab-open", "pane-open"],
  ["tab-new", "pane-new"],
  ["tab-restore", "pane-restore"],
];

function gateReady() {
  const record = storedRecord();
  show("no-record", !record);
  show("have-record", !!record);
  tabs(GATE, record ? "tab-open" : "tab-new");
}

async function doOpen() {
  const record = storedRecord();
  if (!record) return say("gate-msg", "この機械には記録がありません", true);
  const pass = $("open-pass").value;
  await working($("do-open"), "解いています…", async () => {
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
    return say("gate-msg", "二度入れたパスフレーズが違います", true);
  }
  await working($("do-new"), "作っています…", async () => {
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
  await working($("do-restore"), "戻しています…", async () => {
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

// 控えの語だけから戻したとき、どこまで使われていたかは記録に無い。
//
// **未使用出力だけを見て決めない。** 受け取って全部使ったアドレスは
// 未使用出力を持たないので、そこで探索を止めると、その先の資金を
// 見落とす。使われた形跡は履歴で見る。
async function discover() {
  say("gate-msg", "鎖に問い合わせています…", false);
  let highest = -1;
  for (let window = 0; window < WINDOWS; window += 1) {
    const from = window * WINDOW;
    const looked = call({ cmd: "derive", from, count: WINDOW });
    let used = [];
    if (chain.indexed) {
      // 使われたかどうかだけ分かればいい。**中身は要らない。**
      used = (await ask("/api/history", { addresses: looked.addresses, max: 1 })).used;
    } else {
      // 索引が無ければ履歴を引けない。**残っている出力だけで探す。**
      // 見落としうることは画面に出す。
      const scanned = await ask("/api/scan", { addresses: looked.addresses });
      used = scanned.utxos.map((u) => ({ address: u.address }));
    }
    for (const entry of used) {
      const at = looked.addresses.indexOf(entry.address);
      if (at >= 0) highest = Math.max(highest, from + at);
    }
    // この窓に形跡が無ければ、その先にも無いとみなす。
    if (used.length === 0) break;
  }
  const grown = call({ cmd: "grow", accounts: Math.max(highest + 1, 1) });
  keepRecord(grown.record);
  return grown.addresses;
}

// `kept` が偽なら、記録をこの機械に置けていない。**次に開くものが無い。**
//
// `record` は書き出しに使う。**置き場から読み直さない。** 置けなかった
// ときに読み直すと空が落ちてきて、一番要る場面で控えが取れない。
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

// ━━━━━━━━ 本体 ━━━━━━━━

const PANES = [
  ["tab-recv", "pane-recv"],
  ["tab-send", "pane-send"],
  ["tab-coins", "pane-coins"],
];

async function enterWallet(addresses) {
  state.addresses = addresses;
  show("gate", false);
  show("backup", false);
  show("wallet", true);
  tabs(PANES, "tab-recv");
  $("recv-addr").textContent = addresses[addresses.length - 1];
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
  const parts = [`未使用の出力 ${state.count} 個`];
  if (waiting > 0) parts.push(`うち ${waiting} 個は成熟待ち`);
  if (state.truncated) parts.push("上限に達したため、これで全部ではありません");
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
      pill.textContent = "成熟待ち";
      who.append(pill);
    }
    const much = document.createElement("div");
    much.textContent = `${coin.amountoag} OAG`;
    row.append(who, much);
    list.append(row);
  }
  $("coins-head").textContent =
    state.coins.length > 200
      ? `${state.count} 個のうち 200 個を表示しています`
      : `${state.count} 個`;
  show("do-sweep", usable.length >= 2);
}

function usableCoins() {
  return state.coins.filter((c) => c.address);
}

async function doSend() {
  const to = $("send-to").value.trim();
  const amount = $("send-amount").value.trim();
  say("send-msg", "", false);
  await working($("do-send"), "署名しています…", async () => {
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
      say("send-msg", `送りました。${sent.txid} (手数料 ${signed.fee} OAG)`, false);
      await refresh();
    } catch (e) {
      say("send-msg", e.message, true);
    }
  });
}

async function doSweep() {
  say("sweep-msg", "", false);
  await working($("do-sweep"), "まとめています…", async () => {
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
        `${signed.inputs} 個を 1 個にまとめました。${sent.txid} ` +
          `(${signed.size} バイト、手数料 ${signed.fee} OAG)`,
        false,
      );
      await refresh();
    } catch (e) {
      say("sweep-msg", e.message, true);
    }
  });
}

async function doNewAddress() {
  await working($("do-newaddr"), "作っています…", async () => {
    try {
      const grown = call({ cmd: "grow", accounts: state.addresses.length + 1 });
      keepRecord(grown.record);
      state.addresses = grown.addresses;
      $("recv-addr").textContent = grown.addresses[grown.addresses.length - 1];
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

// ━━━━━━━━ 起動 ━━━━━━━━

async function boot() {
  // 平文で届いた頁は、差し替えられていても見分けが付かない。
  // **手元から開いた場合を除いて警告する。**
  const local = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(location.hostname);
  show("insecure", location.protocol !== "https:" && !local);

  const module = await fetch("/wallet.wasm").then((r) => r.arrayBuffer());
  wasm = (await WebAssembly.instantiate(module, {})).instance.exports;

  // wasm には乱数源が無い。**こちらから種を渡す。**
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  call({ cmd: "seed", bytes: hex(seed) });
  seed.fill(0);

  chain = await ask("/api/info", {});
  $("chain").textContent = `${chain.network} · 高さ ${chain.height}`;

  show("boot", false);
  gateReady();
}

document.addEventListener("DOMContentLoaded", () => {
  for (const [tab] of GATE) $(tab).onclick = () => tabs(GATE, tab);
  for (const [tab] of PANES) $(tab).onclick = () => tabs(PANES, tab);

  $("do-open").onclick = doOpen;
  $("do-new").onclick = doCreate;
  $("do-restore").onclick = doRestore;
  $("do-send").onclick = doSend;
  $("do-sweep").onclick = doSweep;
  $("do-refresh").onclick = () => refresh();
  $("do-newaddr").onclick = doNewAddress;
  $("do-lock").onclick = doLock;
  $("do-copy").onclick = () => navigator.clipboard.writeText($("recv-addr").textContent);
  $("do-phrase").onclick = () => {
    const seen = call({ cmd: "phrase" });
    showBackup(seen.phrase, state.addresses, storedRecord() || "", true);
  };
  $("do-forget").onclick = () => {
    if (!confirm("この機械から記録を消します。控えの語が無いと戻せません。")) return;
    try {
      localStorage.removeItem(RECORD_KEY);
    } catch (e) {
      /* 消せなくても進む */
    }
    gateReady();
  };

  boot().catch((e) => {
    $("boot").textContent = `起動できません: ${e.message}`;
    $("boot").className = "bad";
  });
});
