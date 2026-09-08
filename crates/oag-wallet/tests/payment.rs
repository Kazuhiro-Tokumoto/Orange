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
use oag_node::service::{NodeEvent, NodeHandle, NodeService};
use oag_node::start_rpc;
use oag_primitives::{Address, Amount, Network};
use oag_rpc::auth::read_cookie;
use oag_rpc::client::Client;
use oag_wallet::build::{build, sign, Coin, Spend};
use oag_wallet::keystore::Keystore;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const NETWORK: Network = Network::Regtest;

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
        .start_mining(Lock::from_address(payout), Some(blocks))
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
        .expect("採掘が終わらない");
}

/// ウォレットの手持ちを RPC で数える。ウォレットの CLI と同じ道を通る。
async fn coins(client: &Client, store: &Keystore) -> Vec<Coin> {
    let addresses: Vec<String> = store.addresses().iter().map(|a| a.to_string()).collect();
    let result = client.call("scanutxos", json!([addresses])).await.unwrap();
    assert_eq!(
        result.get("truncated").and_then(Value::as_bool),
        Some(false),
        "走査が打ち切られた"
    );

    let known: Vec<(String, Lock)> = store
        .addresses()
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
        .expect("RPC を起こせる");
    Client::new(addr, read_cookie(data_dir).expect("合言葉を読める"))
}

/// 掘った報酬を、ウォレットから別のウォレットへ送れること。
#[test]
fn a_mined_coin_can_be_spent_to_another_wallet() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let dir = TempDir::new("send");
    let service = NodeService::start(NETWORK, &dir.0).expect("ノードを起こせる");
    let handle = service.handle();

    let alice = Keystore::create(&dir.0.join("alice.json"), NETWORK).unwrap();
    let bob = Keystore::create(&dir.0.join("bob.json"), NETWORK).unwrap();

    runtime.block_on(async {
        let client = rpc(&handle, &dir.0).await;
        mine(&handle, &alice.default_address(), MINE_TO).await;

        let height = block_count(&client).await;
        assert_eq!(height, MINE_TO);

        let alice_coins = coins(&client, &alice).await;
        let available = spendable(&alice_coins, height + 1);
        assert!(
            available >= "20".parse::<Amount>().unwrap(),
            "使える残高が足りない: {available}"
        );
        assert!(
            coins(&client, &bob).await.is_empty(),
            "bob はまだ何も持っていないはず"
        );

        // ── 組み立てて署名する。秘密鍵はノードに渡らない ──
        let amount = "12.5".parse::<Amount>().unwrap();
        let spend = Spend {
            to: Lock::from_address(&bob.default_address()),
            amount,
            change_to: Lock::from_address(&alice.default_address()),
            next_height: height + 1,
            fee_rate: params::MIN_RELAY_FEE_RATE_PER_BYTE,
        };
        let draft = build(&alice_coins, &spend).expect("組み立てられる");
        let signed = sign(&draft, |lock| alice.key_for(lock)).expect("署名できる");

        // 入力の合計 = 出力の合計 + 手数料。
        let inputs = Amount::sum(draft.spent.iter().map(|o| o.amount)).unwrap();
        let outputs = Amount::sum(signed.outputs.iter().map(|o| o.amount)).unwrap();
        assert_eq!(inputs, outputs.checked_add(draft.fee).unwrap());

        // ── ノードに投げる ──
        let hex: String = signed.encode().iter().map(|b| format!("{b:02x}")).collect();
        let txid = client
            .call("sendrawtransaction", json!([hex]))
            .await
            .expect("mempool が受け付ける");
        assert_eq!(txid.as_str().unwrap(), signed.txid().to_string());

        let mempool = client.call("getmempool", json!([])).await.unwrap();
        assert_eq!(
            mempool.as_array().unwrap().len(),
            1,
            "mempool に入っていない"
        );

        // 確定するまでは bob の残高は増えない。
        assert!(
            coins(&client, &bob).await.is_empty(),
            "未確定なのに bob が受け取っている"
        );

        // ── ブロックに取り込ませる ──
        mine(&handle, &alice.default_address(), 1).await;
        assert_eq!(block_count(&client).await, MINE_TO + 1);
        assert!(
            client
                .call("getmempool", json!([]))
                .await
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty(),
            "取り込まれたのに mempool に残っている"
        );

        // ── bob が受け取っている ──
        let bob_coins = coins(&client, &bob).await;
        assert_eq!(bob_coins.len(), 1, "bob の UTXO が 1 件でない");
        assert_eq!(bob_coins[0].output.amount, amount);
        assert!(!bob_coins[0].is_coinbase, "コインベース扱いになっている");

        // ── alice はおつりを受け取り、使った分は消えている ──
        let after = coins(&client, &alice).await;
        assert!(
            after.iter().any(|c| c.output.amount == draft.change),
            "おつりが見当たらない"
        );
        for spent in &draft.tx.inputs {
            assert!(
                !after.iter().any(|c| c.outpoint == spent.prev_out),
                "使ったはずの UTXO が残っている: {:?}",
                spent.prev_out
            );
        }
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
    let service = NodeService::start(NETWORK, &dir.0).expect("ノードを起こせる");
    let handle = service.handle();

    let alice = Keystore::create(&dir.0.join("alice.json"), NETWORK).unwrap();
    let mallory = Keystore::create(&dir.0.join("mallory.json"), NETWORK).unwrap();

    runtime.block_on(async {
        let client = rpc(&handle, &dir.0).await;
        mine(&handle, &alice.default_address(), MINE_TO).await;

        let height = block_count(&client).await;
        let alice_coins = coins(&client, &alice).await;

        // mallory が alice の UTXO を自分宛てに使おうとする。
        let spend = Spend {
            to: Lock::from_address(&mallory.default_address()),
            amount: "10".parse::<Amount>().unwrap(),
            change_to: Lock::from_address(&mallory.default_address()),
            next_height: height + 1,
            fee_rate: params::MIN_RELAY_FEE_RATE_PER_BYTE,
        };
        let draft = build(&alice_coins, &spend).expect("組み立てはできてしまう");

        // 自分の鍵で署名する。alice の鍵は持っていない。
        let forged = sign(&draft, |_| Some(mallory_key(&mallory))).expect("署名自体はできる");
        let hex: String = forged.encode().iter().map(|b| format!("{b:02x}")).collect();

        let result = client.call("sendrawtransaction", json!([hex])).await;
        assert!(result.is_err(), "他人の資金を動かせてしまった: {result:?}");

        assert!(
            client
                .call("getmempool", json!([]))
                .await
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty(),
            "断ったのに mempool に入っている"
        );
    });
}

/// 鍵を 1 個だけ持つウォレットから、その鍵を取り出す。
fn mallory_key(store: &Keystore) -> oag_primitives::SecretKey {
    store
        .key_for(&Lock::from_address(&store.default_address()))
        .expect("自分の鍵は引ける")
}
