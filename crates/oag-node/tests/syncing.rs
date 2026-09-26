//! 同期の最中は繋がれても応えず、追いついたら応えること。
//!
//! 同期の最中とは、知っているヘッダより繋いだ本体が
//! [`SYNC_BEHIND`](oag_node::service::SYNC_BEHIND) を超えて遅れている
//! ことである。ここではヘッダだけを先に渡してその状態を作る。

use oag_consensus::lock::Lock;
use oag_net::magic::magic_for;
use oag_net::message::{VersionMessage, PROTOCOL_VERSION, SERVICE_NONE};
use oag_net::transport::{Connection, Listener};
use oag_node::accept_loop;
use oag_node::service::{MiningMode, NodeHandle, NodeService, SYNC_BEHIND};
use oag_primitives::{Address, Hash, Network, SecretKey};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const NETWORK: Network = Network::Regtest;

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
            "oag-syncing-{tag}-{}-{n}-{nanos}",
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

fn start(tag: &str) -> (TempDir, NodeService) {
    let dir = TempDir::new(tag);
    let service = NodeService::start(NETWORK, &dir.0).expect("a node can be started");
    (dir, service)
}

async fn listen(handle: NodeHandle) -> SocketAddr {
    let listener = Listener::bind(magic_for(NETWORK), "127.0.0.1:0".parse().unwrap())
        .await
        .expect("it can listen");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(accept_loop(handle, listener));
    addr
}

/// 繋いで名乗り合えるか。
async fn handshake_succeeds(addr: SocketAddr) -> bool {
    let Ok(mut conn) = Connection::connect(magic_for(NETWORK), addr).await else {
        return false;
    };
    let version = VersionMessage {
        protocol_version: PROTOCOL_VERSION,
        services: SERVICE_NONE,
        timestamp: 1_800_000_000,
        nonce: 0x5eed,
        user_agent: "/syncing-test/".to_owned(),
        start_height: 0,
        relay: false,
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(10), conn.handshake(version)).await,
        Ok(Ok(_))
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_syncing_node_refuses_connections_until_it_catches_up() {
    let blocks = SYNC_BEHIND + 4;

    // A を掘らせて、B が追いかけるチェーンを作る。
    let (_a_dir, a) = start("a");
    let a = a.handle();
    let payout = Lock::from_address(&Address::from_pubkey(
        NETWORK,
        &SecretKey::generate().public_key(),
    ));
    a.start_mining(payout, Some(blocks), MiningMode::light())
        .await
        .expect("mining starts");
    let deadline = Instant::now() + Duration::from_secs(120);
    while a.status().await.unwrap().height < blocks {
        assert!(Instant::now() < deadline, "A did not mine {blocks} blocks");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (_b_dir, b) = start("b");
    let b = b.handle();
    let b_addr = listen(b.clone()).await;

    // 何も知らないうちは同期中ではない。繋がれれば応える。
    assert!(!b.is_syncing().await.unwrap());
    assert!(handshake_succeeds(b_addr).await, "a fresh node refused");

    // ヘッダだけを渡す。先を知ったのに本体が無いので、同期の最中になる。
    let headers = a
        .headers_after(b.locator().await.unwrap(), Hash::ZERO)
        .await
        .unwrap();
    assert_eq!(headers.len() as u64, blocks);
    b.accept_headers(headers.clone()).await.unwrap();
    assert!(b.is_syncing().await.unwrap());
    assert!(
        !handshake_succeeds(b_addr).await,
        "a syncing node accepted a connection"
    );

    // 本体を渡して追いつかせる。追いついたら応える。
    for header in &headers {
        let block = a.block(header.hash()).await.unwrap().expect("A has it");
        b.accept_block(block).await.unwrap();
    }
    assert_eq!(b.status().await.unwrap().height, blocks);
    assert!(!b.is_syncing().await.unwrap());
    assert!(
        handshake_succeeds(b_addr).await,
        "a caught-up node refused a connection"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn being_a_little_behind_is_not_syncing() {
    // 差が SYNC_BEHIND 以内なら同期中ではない。先端の 1 個のヘッダが
    // 本体より先に届くのは普段のことである。
    let blocks = SYNC_BEHIND;

    let (_a_dir, a) = start("a2");
    let a = a.handle();
    let payout = Lock::from_address(&Address::from_pubkey(
        NETWORK,
        &SecretKey::generate().public_key(),
    ));
    a.start_mining(payout, Some(blocks), MiningMode::light())
        .await
        .expect("mining starts");
    let deadline = Instant::now() + Duration::from_secs(120);
    while a.status().await.unwrap().height < blocks {
        assert!(Instant::now() < deadline, "A did not mine {blocks} blocks");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (_b_dir, b) = start("b2");
    let b = b.handle();
    let headers = a
        .headers_after(b.locator().await.unwrap(), Hash::ZERO)
        .await
        .unwrap();
    b.accept_headers(headers).await.unwrap();
    assert!(!b.is_syncing().await.unwrap());
}
