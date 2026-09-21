//! ウォレットからノードへ、実際に送金が通ることを確かめる。
//!
//! 鍵の保管・UTXO の走査・組み立て・署名・JSON-RPC・mempool・採掘・
//! UTXO セットの更新まで、**全部を通す**。部品ごとの試験がすべて通って
//! いても、繋いだときに通るとは限らない。
//!
//! # なぜ 130 ブロック掘るのか
//!
//! コインベースは 120 ブロック経つまで使えない。使える残高を作るには、
//! それを超えて掘るしかない。regtest は難易度調整をしないため、これが
//! 現実的な時間で終わる。**調整を止めていなければ、速く掘るほど難易度が
//! 上がり、この試験は終わらない。**

use oag_consensus::codec::Encode;
use oag_consensus::lock::Lock;
use oag_consensus::params;
use oag_consensus::TxOutput;
use oag_node::service::{MiningMode, NodeEvent, NodeHandle, NodeService};
use oag_node::start_rpc;
use oag_primitives::{Address, Amount, Network};
use oag_rpc::auth::read_cookie;
use oag_rpc::client::Client;
use oag_wallet::build::{build, sign, Coin, Spend};
use oag_wallet::keystore::Keystore;
use oag_wallet::pst::Pst;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const NETWORK: Network = Network::Regtest;

/// 試験で用いるパスフレーズ。
const PASS: &[u8] = b"correct horse battery staple";

/// 使える残高を作るのに要る高さ。コインベースの成熟に 120 ブロック。
const MINE_TO: u64 = params::COINBASE_MATURITY + 10;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("oag-pay-{tag}-{}-{n}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 掘り終わるまで待つ。
async fn mine(handle: &NodeHandle, payout: &Address, blocks: u64) {
    let mut events = handle.subscribe();
    handle
        .start_mining(
            Lock::from_address(payout),
            Some(blocks),
            MiningMode::light(),
        )
        .await
        .unwrap();

    let wait = async {
        loop {
            match events.recv().await {
                Ok(NodeEvent::MiningStopped) => return,
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(300), wait)
        .await
        .expect("mining does not finish");
}

/// ウォレットの手持ちを RPC で数える。ウォレットの CLI と同じ道を通る。
async fn coins(client: &Client, store: &Keystore) -> Vec<Coin> {
    let addresses: Vec<String> = store
        .addresses()
        .unwrap()
        .iter()
        .map(|a| a.to_string())
        .collect();
    let result = client.call("scanutxos", json!([addresses])).await.unwrap();
    assert_eq!(
        result.get("truncated").and_then(Value::as_bool),
        Some(false),
        "the scan was truncated"
    );

    let known: Vec<(String, Lock)> = store
        .addresses()
        .unwrap()
        .iter()
        .map(|a| (a.to_string(), Lock::from_address(a)))
        .collect();

    result
        .get("utxos")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|utxo| {
            let address = utxo["address"].as_str().unwrap().to_string();
            let (_, lock) = known.iter().find(|(t, _)| *t == address).unwrap();
            let atomic: u128 = utxo["amount"].as_str().unwrap().parse().unwrap();
            Coin {
                outpoint: oag_consensus::tx::OutPoint {
                    txid: utxo["txid"].as_str().unwrap().parse().unwrap(),
                    index: utxo["index"].as_u64().unwrap() as u32,
                },
                output: TxOutput::new(Amount::from_atomic(atomic).unwrap(), lock.clone()),
                height: utxo["height"].as_u64().unwrap(),
                is_coinbase: utxo["coinbase"].as_bool().unwrap(),
            }
        })
        .collect()
}

fn spendable(coins: &[Coin], next_height: u64) -> Amount {
    Amount::sum(
        coins
            .iter()
            .filter(|c| c.is_spendable_at(next_height))
            .map(|c| c.output.amount),
    )
    .unwrap()
}

async fn block_count(client: &Client) -> u64 {
    client
        .call("getblockcount", json!([]))
        .await
        .unwrap()
        .as_u64()
        .unwrap()
}

/// RPC を起こし、呼び出し口を返す。
async fn rpc(handle: &NodeHandle, data_dir: &Path) -> Client {
    // ポート 0 で空いているところを取る。試験を並行して走らせても衝突しない。
    let addr = start_rpc(handle.clone(), "127.0.0.1:0".parse().unwrap(), data_dir)
        .await
        .expect("RPC can be started");
    Client::new(addr, read_cookie(data_dir).expect("the cookie can be read"))
}

/// 掘った報酬を、ウォレットから別のウォレットへ送れること。
#[test]
fn a_mined_coin_can_be_spent_to_another_wallet() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let dir = TempDir::new("send");
    let service = NodeService::start(NETWORK, &dir.0).expect("a node can be started");
    let handle = service.handle();

    let (alice, _) = Keystore::create(&dir.0.join("alice.json"), NETWORK, PASS, "").unwrap();
    let (bob, _) = Keystore::create(&dir.0.join("bob.json"), NETWORK, PASS, "").unwrap();

    runtime.block_on(async {
        let client = rpc(&handle, &dir.0).await;
        mine(&handle, &alice.default_address().unwrap(), MINE_TO).await;

        let height = block_count(&client).await;
        assert_eq!(height, MINE_TO);

        let alice_coins = coins(&client, &alice).await;
        let available = spendable(&alice_coins, height + 1);
        assert!(
            available >= "20".parse::<Amount>().unwrap(),
            "the spendable balance is insufficient: {available}"
        );
        assert!(
            coins(&client, &bob).await.is_empty(),
            "bob should hold nothing yet"
        );

        // ── 組み立てて署名する。秘密鍵はノードに渡らない ──
        let amount = "12.5".parse::<Amount>().unwrap();
        let spend = Spend {
            to: Lock::from_address(&bob.default_address().unwrap()),
            amount,
            change_to: Lock::from_address(&alice.default_address().unwrap()),
            next_height: height + 1,
            fee_rate: params::MIN_RELAY_FEE_RATE_PER_BYTE,
        };
        let draft = build(&alice_coins, &spend).expect("it can be built");
        let signed = sign(&draft, |lock| alice.key_for(lock)).expect("it can be signed");

        // 入力の合計 = 出力の合計 + 手数料。
        let inputs = Amount::sum(draft.spent.iter().map(|o| o.amount)).unwrap();
        let outputs = Amount::sum(signed.outputs.iter().map(|o| o.amount)).unwrap();
        assert_eq!(inputs, outputs.checked_add(draft.fee).unwrap());

        // ── ノードに投げる ──
        let hex: String = signed.encode().iter().map(|b| format!("{b:02x}")).collect();
        let txid = client
            .call("sendrawtransaction", json!([hex]))
            .await
            .expect("the mempool accepts it");
        assert_eq!(txid.as_str().unwrap(), signed.txid().to_string());

        let mempool = client.call("getmempool", json!([])).await.unwrap();
        assert_eq!(
            mempool.as_array().unwrap().len(),
            1,
            "it is not in the mempool"
        );

        // 確定するまでは bob の残高は増えない。
        assert!(
            coins(&client, &bob).await.is_empty(),
            "bob received it although it is unconfirmed"
        );

        // ── ブロックに取り込ませる ──
        mine(&handle, &alice.default_address().unwrap(), 1).await;
        assert_eq!(block_count(&client).await, MINE_TO + 1);
        assert!(
            client
                .call("getmempool", json!([]))
                .await
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty(),
            "still in the mempool although it was included"
        );

        // ── bob が受け取っている ──
        let bob_coins = coins(&client, &bob).await;
        assert_eq!(bob_coins.len(), 1, "bob does not have exactly one UTXO");
        assert_eq!(bob_coins[0].output.amount, amount);
        assert!(!bob_coins[0].is_coinbase, "treated as a coinbase");

        // ── alice はおつりを受け取り、使った分は消えている ──
        let after = coins(&client, &alice).await;
        assert!(
            after.iter().any(|c| c.output.amount == draft.change),
            "the change is nowhere to be found"
        );
        for spent in &draft.tx.inputs {
            assert!(
                !after.iter().any(|c| c.outpoint == spent.prev_out),
                "a UTXO that should have been spent is still there: {:?}",
                spent.prev_out
            );
        }
    });
}

/// PST を経由しても送金が通ること。
///
/// **署名する側はノードに触れない。** 署名に要るもの (使う出力の金額と
/// 支払い条件) は PST が運ぶ。16 進のテキストに直して読み戻すところまで
/// 通し、別の機械へ持ち出す経路を実際に辿る。
#[test]
fn a_payment_can_go_through_a_partially_signed_transaction() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let dir = TempDir::new("pst");
    let service = NodeService::start(NETWORK, &dir.0).expect("a node can be started");
    let handle = service.handle();

    let (alice, _) = Keystore::create(&dir.0.join("alice.json"), NETWORK, PASS, "").unwrap();
    let (bob, _) = Keystore::create(&dir.0.join("bob.json"), NETWORK, PASS, "").unwrap();

    runtime.block_on(async {
        let client = rpc(&handle, &dir.0).await;
        mine(&handle, &alice.default_address().unwrap(), MINE_TO).await;
        let height = block_count(&client).await;

        let amount = "7.25".parse::<Amount>().unwrap();
        let spend = Spend {
            to: Lock::from_address(&bob.default_address().unwrap()),
            amount,
            change_to: Lock::from_address(&alice.default_address().unwrap()),
            next_height: height + 1,
            fee_rate: params::MIN_RELAY_FEE_RATE_PER_BYTE,
        };
        let draft = build(&coins(&client, &alice).await, &spend).expect("it can be built");

        // ── ここまでがノードに繋がる側。以降は鍵を持つ側 ──
        let carried = Pst::from_draft(&draft).encode();
        let mut offline = Pst::decode(&carried).expect("it reads as a PST");
        assert!(
            !offline.is_complete(),
            "a signature is present right after creation"
        );
        assert_eq!(offline.fee().unwrap(), draft.fee, "the fee is not visible");

        let added = offline
            .sign_with(|lock| alice.key_for(lock))
            .expect("it can be signed");
        assert_eq!(
            added,
            draft.spent.len(),
            "the signature count does not match the input count"
        );
        assert!(offline.is_complete());

        // ── 署名済みの PST を持ち帰る ──
        let returned = Pst::decode(&offline.encode()).expect("it reads even once signed");
        let signed = returned.finalize().expect("it can be finalized");

        // 直に署名したものと、署名以外は同じであること。
        //
        // **署名そのものは一致しない。** BIP340 のノンス生成は補助乱数を
        // 混ぜるので、同じ鍵で同じ対象に署名しても毎回違うバイト列になる。
        // 本チェーンの txid は署名を含むため、txid も変わる (SPEC §5.3)。
        // 第三者が書き換えられないことは変わらない。
        let direct = sign(&draft, |lock| alice.key_for(lock)).unwrap();
        let bare = |tx: &oag_consensus::Transaction| {
            let mut tx = tx.clone();
            for input in &mut tx.inputs {
                input.signature.clear();
            }
            tx
        };
        assert_eq!(
            bare(&signed),
            bare(&direct),
            "the result through a PST differs from signing directly"
        );
        assert_eq!(signed.inputs[0].signature.len(), 64);
        assert_ne!(
            signed.inputs[0].signature, direct.inputs[0].signature,
            "the auxiliary randomness is not in effect"
        );

        let hex: String = signed.encode().iter().map(|b| format!("{b:02x}")).collect();
        let txid = client
            .call("sendrawtransaction", json!([hex]))
            .await
            .expect("the mempool accepts it");
        assert_eq!(txid.as_str().unwrap(), signed.txid().to_string());

        mine(&handle, &alice.default_address().unwrap(), 1).await;
        let bob_coins = coins(&client, &bob).await;
        assert_eq!(bob_coins.len(), 1, "bob does not have exactly one UTXO");
        assert_eq!(bob_coins[0].output.amount, amount);
    });
}

/// 他人の資金は動かせないこと。
///
/// **署名が要ることの確認である。** ここが通ってしまうなら、誰でも
/// 誰の資金でも動かせる。
#[test]
fn a_transaction_signed_by_the_wrong_key_is_refused() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let dir = TempDir::new("forge");
    let service = NodeService::start(NETWORK, &dir.0).expect("a node can be started");
    let handle = service.handle();

    let (alice, _) = Keystore::create(&dir.0.join("alice.json"), NETWORK, PASS, "").unwrap();
    let (mallory, _) = Keystore::create(&dir.0.join("mallory.json"), NETWORK, PASS, "").unwrap();

    runtime.block_on(async {
        let client = rpc(&handle, &dir.0).await;
        mine(&handle, &alice.default_address().unwrap(), MINE_TO).await;

        let height = block_count(&client).await;
        let alice_coins = coins(&client, &alice).await;

        // mallory が alice の UTXO を自分宛てに使おうとする。
        let spend = Spend {
            to: Lock::from_address(&mallory.default_address().unwrap()),
            amount: "10".parse::<Amount>().unwrap(),
            change_to: Lock::from_address(&mallory.default_address().unwrap()),
            next_height: height + 1,
            fee_rate: params::MIN_RELAY_FEE_RATE_PER_BYTE,
        };
        let draft = build(&alice_coins, &spend).expect("building does succeed");

        // 自分の鍵で署名する。alice の鍵は持っていない。
        let forged =
            sign(&draft, |_| Some(mallory_key(&mallory))).expect("signing itself does work");
        let hex: String = forged.encode().iter().map(|b| format!("{b:02x}")).collect();

        let result = client.call("sendrawtransaction", json!([hex])).await;
        assert!(
            result.is_err(),
            "someone else's funds could be moved: {result:?}"
        );

        assert!(
            client
                .call("getmempool", json!([]))
                .await
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty(),
            "it refused yet the entry is in the mempool"
        );
    });
}

/// 鍵を 1 個だけ持つウォレットから、その鍵を取り出す。
fn mallory_key(store: &Keystore) -> oag_primitives::SecretKey {
    store
        .key_for(&Lock::from_address(&store.default_address().unwrap()))
        .expect("our own key can be looked up")
}
