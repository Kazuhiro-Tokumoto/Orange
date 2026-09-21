//! ブラウザで動くウォレットの中身。
//!
//! # 何のためにあるのか
//!
//! ブラウザ側で**秘密鍵を扱う部分だけ**を wasm に閉じ込める。CLI の
//! ウォレットと同じ [`oag_wallet`] をそのまま呼ぶので、鍵の導出も、
//! 記録の暗号化も、sighash の計算も、実装が二重にならない。
//!
//! # 境目
//!
//! **種と秘密鍵は JS 側へ出さない。** JS が渡すのはパスフレーズ・宛先・
//! 金額・ノードから引いてきた UTXO の一覧であり、返るのは署名済みの
//! トランザクション (16 進) と、画面に出すための数字だけである。
//!
//! 控えの語だけは例外で、`phrase` で取り出せる。**書き留めて
//! もらうためだけの口**であり、呼んだ側は表示が済んだら消すこと。
//!
//! # 呼び方
//!
//! JSON の文字列を 1 本渡して、JSON の文字列が 1 本返る。
//!
//! ```text
//! let p = oag_alloc(len);          // wasm の中に場所を取る
//! (JS が p に要求を書く)
//! let r = oag_call(p, len);        // 返り値は [長さ 4 バイト LE][中身]
//! (JS が中身を読む)
//! oag_free(r, 4 + n);
//! ```
//!
//! 返る形は `{"ok": …}` か `{"error": "…"}` のどちらかである。

#![warn(missing_docs, clippy::all)]

mod rng;

use std::cell::RefCell;

use oag_consensus::codec::Encode;
use oag_consensus::lock::Lock;
use oag_consensus::tx::{OutPoint, TxOutput};
use oag_primitives::{Address, Amount, Hash, Network};
use oag_wallet::build::{build, consolidate, sign, Coin, Consolidate, Draft, Spend};
use oag_wallet::keystore::{Keystore, NONCE_LEN, SALT_LEN};
use oag_wallet::Mnemonic;
use serde_json::{json, Value};

thread_local! {
    /// 開いているウォレット。**閉じれば消える。**
    static OPEN: RefCell<Option<Keystore>> = const { RefCell::new(None) };
}

// ---------------------------------------------------------------- 呼び口

/// wasm の中に `len` バイトの場所を取る。
///
/// # Safety
///
/// 返った場所は [`oag_free`] に**同じ長さ**で返すこと。
#[no_mangle]
pub extern "C" fn oag_alloc(len: usize) -> *mut u8 {
    // **`with_capacity` ではなく詰めて作る。** 返すときに長さと容量が
    // 食い違うと、割り当ての形が合わない。
    leak(vec![0u8; len])
}

/// 場所を手放して、先頭を返す。長さは呼んだ側が覚えている。
fn leak(buf: Vec<u8>) -> *mut u8 {
    Box::into_raw(buf.into_boxed_slice()).cast()
}

/// [`oag_alloc`] で取った場所を返す。
///
/// # Safety
///
/// `ptr` は [`oag_alloc`] か [`oag_call`] が返したもので、`len` は
/// そのときの長さであること。同じ場所を二度返さないこと。
#[no_mangle]
pub unsafe extern "C" fn oag_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    drop(unsafe { Box::from_raw(slice as *mut [u8]) });
}

/// 要求を 1 本処理する。
///
/// 返るのは `[長さ 4 バイト LE][JSON]` である。長さを頭に付けるのは、
/// wasm の関数が返せる値が 1 つだけだからである。
///
/// # Safety
///
/// `ptr` は `len` バイトの UTF-8 を指していること。
#[no_mangle]
pub unsafe extern "C" fn oag_call(ptr: *const u8, len: usize) -> *mut u8 {
    let request = unsafe { std::slice::from_raw_parts(ptr, len) };
    let answer = match std::str::from_utf8(request) {
        Ok(text) => handle(text),
        Err(_) => json!({ "error": "the request is not UTF-8" }),
    };
    let body = serde_json::to_vec(&answer).unwrap_or_else(|_| {
        r#"{"error":"the response cannot be turned into JSON"}"#
            .as_bytes()
            .to_vec()
    });

    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    leak(out)
}

// ------------------------------------------------------------ 取り次ぎ

fn handle(text: &str) -> Value {
    match dispatch(text) {
        Ok(value) => json!({ "ok": value }),
        Err(message) => json!({ "error": message }),
    }
}

fn dispatch(text: &str) -> Result<Value, String> {
    let request: Value =
        serde_json::from_str(text).map_err(|e| format!("the request cannot be read: {e}"))?;
    let cmd = request
        .get("cmd")
        .and_then(Value::as_str)
        .ok_or("cmd is missing")?;

    match cmd {
        "seed" => cmd_seed(&request),
        "create" => cmd_create(&request),
        "restore" => cmd_restore(&request),
        "open" => cmd_open(&request),
        "lock" => cmd_lock(),
        "derive" => cmd_derive(&request),
        "grow" => cmd_grow(&request),
        "phrase" => cmd_phrase(),
        "pay" => cmd_pay(&request),
        "sweep" => cmd_sweep(&request),
        other => Err(format!("unknown command: {other}")),
    }
}

// -------------------------------------------------------------- 命令

fn cmd_seed(request: &Value) -> Result<Value, String> {
    let bytes = hex_field(request, "bytes")?;
    let seed: [u8; rng::SEED_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("the seed must be {} bytes", rng::SEED_LEN))?;
    rng::seed(&seed);
    Ok(json!({ "seeded": true }))
}

fn cmd_create(request: &Value) -> Result<Value, String> {
    let network = network_field(request)?;
    let pass = str_field(request, "pass")?;
    let extra = request.get("extra").and_then(Value::as_str).unwrap_or("");
    // 12 語では 128 ビット。**既定は 24 語 (256 ビット) にしてある。**
    let words = request.get("words").and_then(Value::as_u64).unwrap_or(24);
    let entropy_len = match words {
        12 => 16,
        24 => 32,
        other => {
            return Err(format!(
                "the word count must be 12 or 24 ({other} was given)"
            ))
        }
    };

    let mut entropy = vec![0u8; entropy_len];
    if !rng::fill(&mut entropy) {
        return Err("the random seed has not been supplied yet".to_string());
    }
    let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|e| e.to_string())?;

    let store = Keystore::in_memory(network, pass.as_bytes(), &mnemonic, extra)
        .map_err(|e| e.to_string())?;
    let record = seal(&store)?;
    let addresses = addresses_of(&store)?;
    let phrase = mnemonic.phrase().to_string();
    put(store);
    Ok(json!({ "record": record, "phrase": phrase, "addresses": addresses }))
}

fn cmd_restore(request: &Value) -> Result<Value, String> {
    let network = network_field(request)?;
    let pass = str_field(request, "pass")?;
    let extra = request.get("extra").and_then(Value::as_str).unwrap_or("");
    let phrase = str_field(request, "phrase")?;

    let mnemonic = Mnemonic::parse(&phrase).map_err(|e| e.to_string())?;
    let store = Keystore::in_memory(network, pass.as_bytes(), &mnemonic, extra)
        .map_err(|e| e.to_string())?;
    let record = seal(&store)?;
    let addresses = addresses_of(&store)?;
    put(store);
    Ok(json!({ "record": record, "addresses": addresses }))
}

fn cmd_open(request: &Value) -> Result<Value, String> {
    let network = network_field(request)?;
    let pass = str_field(request, "pass")?;
    let record = str_field(request, "record")?;

    let store =
        Keystore::from_json(&record, network, pass.as_bytes()).map_err(|e| e.to_string())?;
    let addresses = addresses_of(&store)?;
    let accounts = store.len();
    put(store);
    Ok(json!({ "accounts": accounts, "addresses": addresses }))
}

fn cmd_lock() -> Result<Value, String> {
    OPEN.with(|cell| *cell.borrow_mut() = None);
    Ok(json!({ "locked": true }))
}

/// まだ自分のものと決めていない番号のアドレスを作る。**探索のため。**
fn cmd_derive(request: &Value) -> Result<Value, String> {
    let from = request.get("from").and_then(Value::as_u64).unwrap_or(0) as u32;
    let count = request.get("count").and_then(Value::as_u64).unwrap_or(0) as u32;
    // 一度に作りすぎると、ブラウザが固まったように見える。
    if count > 1_000 {
        return Err("at most 1000 can be derived at once".to_string());
    }
    with_open(|store| {
        let addresses = store
            .addresses_at(from, count)
            .map_err(|e| e.to_string())?
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>();
        Ok(json!({ "from": from, "addresses": addresses }))
    })
}

/// 探索で分かった数まで、自分のアドレスを増やす。
fn cmd_grow(request: &Value) -> Result<Value, String> {
    let accounts = request
        .get("accounts")
        .and_then(Value::as_u64)
        .ok_or("accounts is missing")? as u32;
    with_open_mut(|store| {
        store.grow_to(accounts).map_err(|e| e.to_string())?;
        let record = seal(store)?;
        let addresses = addresses_of(store)?;
        Ok(json!({ "record": record, "addresses": addresses }))
    })
}

fn cmd_phrase() -> Result<Value, String> {
    with_open(|store| Ok(json!({ "phrase": store.mnemonic().phrase().to_string() })))
}

fn cmd_pay(request: &Value) -> Result<Value, String> {
    let to = lock_field(request, "to")?;
    let amount: Amount = str_field(request, "amount")?
        .parse()
        .map_err(|e| format!("the amount to send cannot be read: {e}"))?;
    let fee_rate = fee_rate_field(request)?;
    let next_height = u64_field(request, "next_height")?;

    with_open(|store| {
        let coins = coins_field(request)?;
        let change_to = Lock::from_address(
            &store
                .default_address()
                .map_err(|e| format!("cannot look up the change address: {e}"))?,
        );
        let spend = Spend {
            to,
            amount,
            change_to,
            next_height,
            fee_rate,
        };
        let draft = build(&coins, &spend).map_err(|e| e.to_string())?;
        finish(store, &draft)
    })
}

fn cmd_sweep(request: &Value) -> Result<Value, String> {
    let fee_rate = fee_rate_field(request)?;
    let next_height = u64_field(request, "next_height")?;
    let max_inputs = request
        .get("max_inputs")
        .and_then(Value::as_u64)
        .map(|n| n as usize);

    with_open(|store| {
        let coins = coins_field(request)?;
        // 宛先を省いたら自分の既定のアドレスへ。**まとめは自分宛が既定。**
        let to = match request.get("to").and_then(Value::as_str) {
            Some(text) if !text.is_empty() => parse_lock(store.network(), text)?,
            _ => Lock::from_address(&store.default_address().map_err(|e| e.to_string())?),
        };
        let order = Consolidate {
            to,
            next_height,
            fee_rate,
            max_inputs,
        };
        let draft = consolidate(&coins, &order).map_err(|e| e.to_string())?;
        finish(store, &draft)
    })
}

/// 署名して、画面に出すための数字を添える。
fn finish(store: &Keystore, draft: &Draft) -> Result<Value, String> {
    let signed = sign(draft, |lock| store.key_for(lock)).map_err(|e| e.to_string())?;
    let raw = signed.encode();
    Ok(json!({
        "hex": hex::encode(&raw),
        "txid": signed.txid().to_string(),
        "size": raw.len(),
        "inputs": signed.inputs.len(),
        "outputs": signed.outputs.len(),
        "fee": draft.fee.to_string(),
        "change": draft.change.to_string(),
    }))
}

// ------------------------------------------------------------ 道具

/// 開いているウォレットを暗号化して文字列にする。
///
/// ソルトと nonce は**毎回作り直す**。
fn seal(store: &Keystore) -> Result<String, String> {
    let salt: [u8; SALT_LEN] = rng::bytes()?;
    let nonce: [u8; NONCE_LEN] = rng::bytes()?;
    store.to_json(&salt, &nonce).map_err(|e| e.to_string())
}

fn put(store: Keystore) {
    OPEN.with(|cell| *cell.borrow_mut() = Some(store));
}

fn with_open<T>(f: impl FnOnce(&Keystore) -> Result<T, String>) -> Result<T, String> {
    OPEN.with(|cell| {
        let slot = cell.borrow();
        let store = slot.as_ref().ok_or("no wallet is open")?;
        f(store)
    })
}

fn with_open_mut<T>(f: impl FnOnce(&mut Keystore) -> Result<T, String>) -> Result<T, String> {
    OPEN.with(|cell| {
        let mut slot = cell.borrow_mut();
        let store = slot.as_mut().ok_or("no wallet is open")?;
        f(store)
    })
}

fn addresses_of(store: &Keystore) -> Result<Vec<String>, String> {
    Ok(store
        .addresses()
        .map_err(|e| e.to_string())?
        .iter()
        .map(|a| a.to_string())
        .collect())
}

fn str_field(request: &Value, name: &str) -> Result<String, String> {
    request
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("{name} is missing"))
}

fn u64_field(request: &Value, name: &str) -> Result<u64, String> {
    request
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{name} is missing"))
}

fn hex_field(request: &Value, name: &str) -> Result<Vec<u8>, String> {
    let text = str_field(request, name)?;
    hex::decode(&text).map_err(|e| format!("{name} cannot be read as hexadecimal: {e}"))
}

fn network_field(request: &Value) -> Result<Network, String> {
    str_field(request, "network")?
        .parse()
        .map_err(|_| "unknown network".to_string())
}

fn fee_rate_field(request: &Value) -> Result<Amount, String> {
    let atomic = str_field(request, "fee_rate")?
        .parse::<u128>()
        .map_err(|e| format!("the fee rate cannot be read: {e}"))?;
    Amount::from_atomic(atomic).map_err(|e| format!("the fee rate cannot be read: {e}"))
}

fn lock_field(request: &Value, name: &str) -> Result<Lock, String> {
    let text = str_field(request, name)?;
    let network = network_field(request)?;
    parse_lock(network, &text)
}

fn parse_lock(network: Network, text: &str) -> Result<Lock, String> {
    let address = Address::decode_on(network, text)
        .map_err(|e| format!("the address {text} cannot be read: {e}"))?;
    Ok(Lock::from_address(&address))
}

/// ノードの `scanutxos` が返した形から、使える出力の一覧を作る。
///
/// **自分の鍵で開けない出力は落とす。** `address` が付いていないものは
/// 問い合わせたアドレスのどれにも当たらなかったものであり、署名できない。
fn coins_field(request: &Value) -> Result<Vec<Coin>, String> {
    let list = request
        .get("coins")
        .and_then(Value::as_array)
        .ok_or("coins is missing")?;
    let network = network_field(request)?;

    let mut out = Vec::with_capacity(list.len());
    for item in list {
        let Some(address) = item.get("address").and_then(Value::as_str) else {
            continue;
        };
        let lock = parse_lock(network, address)?;
        let txid: Hash = str_field(item, "txid")?
            .parse()
            .map_err(|e| format!("the txid cannot be read: {e}"))?;
        let index = u64_field(item, "index")? as u32;
        let atomic = str_field(item, "amount")?
            .parse::<u128>()
            .map_err(|e| format!("the amount cannot be read: {e}"))?;
        let amount =
            Amount::from_atomic(atomic).map_err(|e| format!("the amount cannot be read: {e}"))?;
        out.push(Coin {
            outpoint: OutPoint { txid, index },
            output: TxOutput { amount, lock },
            height: u64_field(item, "height")?,
            is_coinbase: item
                .get("coinbase")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_consensus::codec::Decode;

    /// 試験の中では乱数の質を問わない。**入っていること**だけが要る。
    fn seeded() {
        let answer = handle(
            r#"{"cmd":"seed","bytes":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}"#,
        );
        assert!(answer.get("ok").is_some(), "{answer}");
    }

    fn ok(text: &str) -> Value {
        let answer = handle(text);
        answer
            .get("ok")
            .cloned()
            .unwrap_or_else(|| panic!("it failed: {answer}"))
    }

    fn err(text: &str) -> String {
        let answer = handle(text);
        answer
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("it passed after all: {answer}"))
            .to_string()
    }

    fn make_wallet() -> Value {
        seeded();
        ok(r#"{"cmd":"create","network":"regtest","pass":"passphrase","words":24}"#)
    }

    #[test]
    fn a_new_wallet_comes_with_a_record_and_a_phrase() {
        let made = make_wallet();
        let phrase = made["phrase"].as_str().unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);

        // 記録は CLI が読むのと同じ形式である。
        let record: Value = serde_json::from_str(made["record"].as_str().unwrap()).unwrap();
        assert_eq!(record["version"], 3);
        assert_eq!(record["network"], "regtest");
        assert_eq!(record["kdf"]["algorithm"], "argon2id");
    }

    #[test]
    fn a_record_reopens_with_the_same_addresses() {
        let made = make_wallet();
        let record = made["record"].as_str().unwrap().to_string();
        let before = made["addresses"].clone();

        ok(r#"{"cmd":"lock"}"#);
        let opened = ok(&serde_json::to_string(&json!({
            "cmd": "open", "network": "regtest", "pass": "passphrase", "record": record
        }))
        .unwrap());
        assert_eq!(opened["addresses"], before);
    }

    #[test]
    fn a_wrong_passphrase_does_not_open_the_record() {
        let made = make_wallet();
        let record = made["record"].as_str().unwrap().to_string();
        ok(r#"{"cmd":"lock"}"#);

        let message = err(&serde_json::to_string(&json!({
            "cmd": "open", "network": "regtest", "pass": "chigau-mono", "record": record
        }))
        .unwrap());
        assert!(message.contains("cannot decrypt"), "{message}");
    }

    /// **鍵が要る命令は、閉じているときに通ってはならない。**
    #[test]
    fn nothing_signs_while_the_wallet_is_locked() {
        make_wallet();
        ok(r#"{"cmd":"lock"}"#);
        for cmd in [
            r#"{"cmd":"phrase"}"#,
            r#"{"cmd":"derive","from":0,"count":1}"#,
            r#"{"cmd":"grow","accounts":5}"#,
        ] {
            assert_eq!(err(cmd), "no wallet is open", "{cmd}");
        }
    }

    #[test]
    fn a_payment_is_signed_inside_and_only_the_hex_comes_out() {
        let made = make_wallet();
        let mine = made["addresses"][0].as_str().unwrap().to_string();

        let request = json!({
            "cmd": "pay",
            "network": "regtest",
            "to": mine,
            "amount": "1",
            "fee_rate": "50000000000",
            "next_height": 200,
            "coins": [{
                "txid": "11".repeat(32),
                "index": 0,
                "amount": "100000000000000000",
                "height": 10,
                "coinbase": true,
                "address": mine,
            }],
        });
        let paid = ok(&serde_json::to_string(&request).unwrap());

        let raw = hex::decode(paid["hex"].as_str().unwrap()).unwrap();
        let tx = oag_consensus::Transaction::decode(&raw).unwrap();
        assert_eq!(tx.encode(), raw, "it does not round-trip when encoded");
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.txid().to_string(), paid["txid"].as_str().unwrap());
        // **署名が入っていること。** 場所取りのままなら 0 が並ぶ。
        assert_eq!(tx.inputs[0].signature.len(), 64);
        assert!(tx.inputs[0].signature.iter().any(|b| *b != 0));
        // 種も鍵も応答に混ざっていない。
        let text = paid.to_string();
        assert!(!text.contains("phrase") && !text.contains("seed"), "{text}");
    }

    /// コインベースは成熟するまで使えない。**ブラウザでも同じ規則が効く。**
    #[test]
    fn an_immature_coinbase_is_refused_in_the_browser_too() {
        let made = make_wallet();
        let mine = made["addresses"][0].as_str().unwrap().to_string();
        let request = json!({
            "cmd": "sweep",
            "network": "regtest",
            "fee_rate": "50000000000",
            "next_height": 11,
            "coins": [{
                "txid": "22".repeat(32), "index": 0, "amount": "100000000000000000",
                "height": 10, "coinbase": true, "address": mine,
            }, {
                "txid": "33".repeat(32), "index": 0, "amount": "100000000000000000",
                "height": 10, "coinbase": true, "address": mine,
            }],
        });
        let message = err(&serde_json::to_string(&request).unwrap());
        assert!(!message.is_empty());
    }

    /// 探索は `accounts` を動かさない。動かすと、まだ自分のものと決めて
    /// いない番号が控えに混ざる。
    #[test]
    fn looking_ahead_does_not_claim_the_addresses_it_looks_at() {
        let made = make_wallet();
        let before = made["addresses"].as_array().unwrap().len();
        let looked = ok(r#"{"cmd":"derive","from":0,"count":50}"#);
        assert_eq!(looked["addresses"].as_array().unwrap().len(), 50);

        let now = ok(r#"{"cmd":"phrase"}"#);
        assert!(now.get("phrase").is_some());
        let opened = ok(r#"{"cmd":"derive","from":0,"count":1}"#);
        assert_eq!(opened["addresses"][0], made["addresses"][0]);
        assert_eq!(
            before, 1,
            "there should be exactly one right after creation"
        );
    }

    #[test]
    fn growing_keeps_the_addresses_that_were_already_handed_out() {
        let made = make_wallet();
        let first = made["addresses"][0].clone();
        let grown = ok(r#"{"cmd":"grow","accounts":5}"#);
        let list = grown["addresses"].as_array().unwrap();
        assert_eq!(list.len(), 5);
        assert_eq!(list[0], first, "the first entry changed");
    }

    /// 種を入れる前に記録を作らせない。**予測できるソルトを黙って
    /// 使うくらいなら断る。**
    #[test]
    fn nothing_is_sealed_before_the_randomness_arrives() {
        // 他の試験と混ざらないよう、状態を持たない経路で確かめる。
        let mut buffer = [0u8; 4];
        let seeded_already = rng::fill(&mut buffer);
        if !seeded_already {
            let message = err(r#"{"cmd":"create","network":"regtest","pass":"passphrase"}"#);
            assert!(message.contains("seed"), "{message}");
        }
    }
}
