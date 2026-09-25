//! 生存確認 (`ping` / `pong`) を実際の接続で確かめる。
//!
//! ノードは 60 秒ごとに `ping` を送る。この試験は最初の 1 回を待つので、
//! 1 分ほどかかる。返事が無いときに切るのは 5 分後で、試験で待つには
//! 長すぎる。そちらは `peer` の単体試験で時計を渡して確かめている。

use oag_net::magic::magic_for;
use oag_net::message::{Message, VersionMessage, PROTOCOL_VERSION, SERVICE_NONE};
use oag_net::transport::{Connection, Listener};
use oag_node::accept_loop;
use oag_node::service::NodeService;
use oag_primitives::Network;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const NETWORK: Network = Network::Regtest;

/// 最初の `ping` を待つ上限。間隔 (60 秒) に余裕を足したもの。
const PING_WAIT: Duration = Duration::from_secs(90);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("oag-keepalive-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_node_pings_and_answers_pings() {
    let dir = TempDir::new();
    let service = NodeService::start(NETWORK, &dir.0).expect("a node can be started");
    let handle = service.handle();

    let listener = Listener::bind(magic_for(NETWORK), "127.0.0.1:0".parse().unwrap())
        .await
        .expect("it can listen");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(accept_loop(handle, listener));

    let mut conn = Connection::connect(magic_for(NETWORK), addr)
        .await
        .expect("it can connect");
    conn.handshake(VersionMessage {
        protocol_version: PROTOCOL_VERSION,
        services: SERVICE_NONE,
        timestamp: 1_800_000_000,
        nonce: 0x5eed,
        user_agent: "/keepalive-test/".to_owned(),
        start_height: 0,
        relay: false,
    })
    .await
    .expect("the handshake completes");

    // こちらの ping には pong が返る (0.1.0 からの振る舞い)。
    conn.send(&Message::Ping(99)).await.unwrap();

    let started = Instant::now();
    let mut answered = false;
    let theirs = loop {
        let left = PING_WAIT
            .checked_sub(started.elapsed())
            .expect("the node sent no ping within the interval");
        let message = tokio::time::timeout(left, conn.recv())
            .await
            .expect("the node sent no ping within the interval")
            .expect("the connection is still open");
        match message {
            Message::Pong(99) => answered = true,
            Message::Ping(nonce) => break nonce,
            _ => {}
        }
    };
    assert!(answered, "the node did not answer our ping");

    // 返事をすれば切られない。次の ping もこの接続に来る。
    conn.send(&Message::Pong(theirs)).await.unwrap();
    let next = loop {
        let message = tokio::time::timeout(PING_WAIT, conn.recv())
            .await
            .expect("the node sent no second ping")
            .expect("the node dropped a peer that answered its ping");
        if let Message::Ping(nonce) = message {
            break nonce;
        }
    };
    assert_ne!(next, theirs, "the same nonce was used twice");
}
