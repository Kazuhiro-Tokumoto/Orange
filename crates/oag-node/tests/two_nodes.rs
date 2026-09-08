//! 2 台のノードを実際に TCP で繋ぎ、同期することを確かめる。
//!
//! 単体試験はそれぞれの部品が仕様どおりに動くことしか示さない。
//! **繋いだときに実際にブロックが渡るか**は、繋いでみないと分からない。
//!
//! regtest を用いる。難易度 1 なので RandomX の計算はすぐ終わる。
//! それでも検証器の初期化に 256 MB の確保が伴うため、この試験は
//! 他の試験より重い。

use oag_consensus::lock::Lock;
use oag_net::magic::magic_for;
use oag_net::transport::Listener;
use oag_node::service::{NodeHandle, NodeService};
use oag_node::{accept_loop, dial};
use oag_primitives::{Address, Network, SecretKey};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const NETWORK: Network = Network::Regtest;

/// 同期を待つ上限。RandomX の検証を含むため短くしすぎない。
const SYNC_TIMEOUT: Duration = Duration::from_secs(60);

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// 試験ごとに独立した一時ディレクトリ。作りっぱなしにせず片付ける。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("oag-p2p-{tag}-{}-{n}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn payout() -> Lock {
    let secret = SecretKey::generate();
    Lock::from_address(&Address::from_pubkey(NETWORK, &secret.public_key()))
}

/// ノードを 1 台起こす。
fn start(tag: &str, mine_limit: Option<u64>) -> (TempDir, NodeService) {
    let dir = TempDir::new(tag);
    let service = NodeService::start(NETWORK, &dir.0, mine_limit).expect("ノードを起こせる");
    (dir, service)
}

/// 待ち受けを始め、受け入れ作業を走らせる。実際に開いた住所を返す。
async fn listen(handle: NodeHandle) -> SocketAddr {
    // ポート 0 を指定すると空いているポートが選ばれる。試験を並行して
    // 走らせても衝突しない。
    let listener = Listener::bind(magic_for(NETWORK), "127.0.0.1:0".parse().unwrap())
        .await
        .expect("待ち受けられる");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(accept_loop(handle, listener));
    addr
}

/// 高さがその値になるまで待つ。
async fn wait_for_height(handle: &NodeHandle, wanted: u64, what: &str) {
    let deadline = Instant::now() + SYNC_TIMEOUT;
    let mut last = 0;
    while Instant::now() < deadline {
        let status = handle.status().await.expect("状態を引ける");
        last = status.height;
        if status.height >= wanted {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{what}: 高さ {wanted} に届かなかった (今は {last})");
}

/// 掘り終えるまで待つ。
async fn wait_for_mining(handle: &NodeHandle, wanted: u64) {
    wait_for_height(handle, wanted, "採掘").await;
}

/// 追いついたノードが、追いつかれた側と同じ先端を持つこと。
async fn assert_same_tip(a: &NodeHandle, b: &NodeHandle) {
    let sa = a.status().await.unwrap();
    let sb = b.status().await.unwrap();
    assert_eq!(sa.tip, sb.tip, "先端が食い違っている");
    assert_eq!(sa.height, sb.height, "高さが食い違っている");
    assert_eq!(sa.utxo_count, sb.utxo_count, "UTXO の数が食い違っている");
    assert_eq!(
        sa.cumulative_work, sb.cumulative_work,
        "累積作業量が食い違っている"
    );
}

/// 先に積まれたチェーンに、後から繋いだノードが追いつくこと。
#[test]
fn a_new_node_catches_up_with_an_existing_chain() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (_dir_a, service_a) = start("a-src", Some(5));
    let (_dir_b, service_b) = start("a-dst", None);
    let a = service_a.handle();
    let b = service_b.handle();

    runtime.block_on(async {
        // A に 5 ブロック積む。この時点で B は繋がっていない。
        a.start_mining(payout()).await.unwrap();
        wait_for_mining(&a, 5).await;
        assert_eq!(b.status().await.unwrap().height, 0, "B はまだ空のはず");

        // B を A に繋ぐ。
        let addr = listen(a.clone()).await;
        tokio::spawn(dial(b.clone(), addr));

        wait_for_height(&b, 5, "追いつき").await;
        assert_same_tip(&a, &b).await;
    });
}

/// 繋がっている間に掘られたブロックが、相手に伝わること。
///
/// 追いつきとは別の道である。追いつきは `getheaders` から始まるが、
/// こちらは掘った側が `inv` で知らせるところから始まる。
#[test]
fn a_block_mined_while_connected_reaches_the_peer() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (_dir_a, service_a) = start("b-src", Some(3));
    let (_dir_b, service_b) = start("b-dst", None);
    let a = service_a.handle();
    let b = service_b.handle();

    runtime.block_on(async {
        // 先に繋いでから掘る。
        let addr = listen(a.clone()).await;
        tokio::spawn(dial(b.clone(), addr));

        // ハンドシェイクが済むのを待つ。両方とも高さ 0 のままである。
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(a.status().await.unwrap().height, 0);
        assert_eq!(b.status().await.unwrap().height, 0);

        a.start_mining(payout()).await.unwrap();
        wait_for_mining(&a, 3).await;

        wait_for_height(&b, 3, "中継").await;
        assert_same_tip(&a, &b).await;
    });
}

/// 同期しても、相手の言い分をそのまま信じてはいないこと。
///
/// 受け取ったブロックは自分で検証している。検証を通ったのだから、
/// **UTXO セットは自分で組み立てた結果**である。同じ高さで同じ
/// UTXO 件数になることがその証拠になる。
#[test]
fn a_synced_node_rebuilds_the_utxo_set_itself() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (_dir_a, service_a) = start("c-src", Some(4));
    let (_dir_b, service_b) = start("c-dst", None);
    let a = service_a.handle();
    let b = service_b.handle();

    runtime.block_on(async {
        a.start_mining(payout()).await.unwrap();
        wait_for_mining(&a, 4).await;

        let addr = listen(a.clone()).await;
        tokio::spawn(dial(b.clone(), addr));
        wait_for_height(&b, 4, "追いつき").await;

        let sb = b.status().await.unwrap();
        // ジェネシスは報酬を受け取らないため、高さ 4 なら UTXO は 4 件。
        assert_eq!(sb.utxo_count, 4, "コインベース 4 件が UTXO になる");
        assert_eq!(sb.indexed_blocks, 5, "ジェネシスを含めて 5 個");
        assert_same_tip(&a, &b).await;
    });
}
