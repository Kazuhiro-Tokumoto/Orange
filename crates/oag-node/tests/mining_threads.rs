//! 複数スレッドで実際に掘れることを確かめる。
//!
//! `oag-miner` の単体試験は偽のハッシュで探索の筋道だけを見ている。
//! **RandomX を積んだ本物の採掘器で、ノードを通して掘れるか**は、
//! 通してみないと分からない。採掘器はスレッドごとに建てるので、
//! 「建てられるか」「同じノンスを 2 人で試していないか」「掘れた
//! ブロックが自分のチェーンに入るか」がここで初めて繋がる。
//!
//! regtest を用いる。難易度 1 なので RandomX の計算はすぐ終わる。
//! それでも**採掘器 1 本につき 256 MB を確保する**ため、この試験は重い。
//! 本数を増やすとそのぶん memory を食うので、2 本に留めてある。

use oag_consensus::lock::Lock;
use oag_node::service::{MiningMode, NodeHandle, NodeService};
use oag_primitives::{Address, Network, SecretKey};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const NETWORK: Network = Network::Regtest;

/// 掘り終えるのを待つ上限。採掘器の初期化を含むため短くしすぎない。
const MINING_TIMEOUT: Duration = Duration::from_secs(120);

/// この試験で起こす採掘スレッドの数。
const THREADS: usize = 2;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "oag-threads-{tag}-{}-{n}-{nanos}",
            std::process::id()
        ));
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

fn start(tag: &str) -> (TempDir, NodeService) {
    let dir = TempDir::new(tag);
    let service = NodeService::start(NETWORK, &dir.0).expect("a node can be started");
    (dir, service)
}

async fn wait_for_height(handle: &NodeHandle, wanted: u64) {
    let deadline = Instant::now() + MINING_TIMEOUT;
    let mut last = 0;
    while Instant::now() < deadline {
        let status = handle.status().await.expect("the state can be read");
        last = status.height;
        if status.height >= wanted {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("did not reach height {wanted} (now {last})");
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// 複数スレッドで掘ったブロックが、ちゃんと自分のチェーンに積まれること。
///
/// 1 本でも掘れるので、**枚数ではなく本数が問題である**。2 本に増やして
/// 同じように積めるなら、スレッドごとの採掘器が建ち、担当するノンスが
/// 散らばり、当たりが 1 か所に集まる道筋が通っている。
#[test]
fn several_threads_mine_a_chain() {
    let runtime = runtime();
    let (_dir, service) = start("many");
    let handle = service.handle();

    runtime.block_on(async {
        let mode = MiningMode::light().with_threads(THREADS);
        handle.start_mining(payout(), Some(3), mode).await.unwrap();
        wait_for_height(&handle, 3).await;

        let status = handle.status().await.unwrap();
        assert_eq!(status.height, 3);
        // 分岐していないこと。**同じ高さを 2 本が別々に掘って、両方
        // 積もうとしていたらここで増える。**
        assert_eq!(
            status.indexed_blocks, 4,
            "there should be genesis plus 3 but there are {}",
            status.indexed_blocks
        );
    });
}

/// 掘っている途中で止められること。
///
/// 止める合図は**作業スレッドが走っている間に**届く。受け取ったあと
/// 畳み切れずに残ると、次に掘り始めたときスレッドが二重になる。
#[test]
fn mining_stops_while_the_threads_are_running() {
    let runtime = runtime();
    let (_dir, service) = start("stop");
    let handle = service.handle();

    runtime.block_on(async {
        let mode = MiningMode::light().with_threads(THREADS);
        // 止まる数を指定しないので、止めるまで掘り続ける。
        handle.start_mining(payout(), None, mode).await.unwrap();
        wait_for_height(&handle, 1).await;

        handle.stop_mining().await.unwrap();
        let settled = handle.status().await.unwrap().height;

        // 止めたあとに増えないこと。畳み残しがあれば増える。
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            handle.status().await.unwrap().height,
            settled,
            "still mining after being stopped"
        );

        // もう一度始められること。
        handle.start_mining(payout(), Some(1), mode).await.unwrap();
        wait_for_height(&handle, settled + 1).await;
    });
}
