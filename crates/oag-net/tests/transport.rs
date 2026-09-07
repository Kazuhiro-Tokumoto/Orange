//! 実際に TCP ソケットを開いて行う試験。
//!
//! ここまでの試験は決定的だったが、ここからは本物のソケットを使う。
//! すべての待ちに制限時間を設けてあるので、詰まっても CI は止まらない。

#![cfg(feature = "tokio")]

use oag_consensus::lock::Lock;
use oag_consensus::tx::{
    encode_coinbase_signature, OutPoint, TxInput, TxOutput, CURRENT_TX_VERSION,
};
use oag_consensus::{Block, BlockHeader, Transaction};
use oag_net::frame::{self, COMMAND_LEN, MAX_PAYLOAD};
use oag_net::magic::{MAGIC_LEN, MAGIC_MAINNET, MAGIC_TESTNET};
use oag_net::message::{InvItem, Message, VersionMessage, PROTOCOL_VERSION, SERVICE_FULL_NODE};
use oag_net::transport::{Connection, Listener, TransportError};
use oag_primitives::{hash, merkle, Amount, Hash, SecretKey};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const MAGIC: [u8; MAGIC_LEN] = MAGIC_MAINNET;
const LIMIT: Duration = Duration::from_secs(10);

/// 待ちに制限時間を付ける。詰まったら試験を落とす。
macro_rules! within {
    ($what:expr) => {
        tokio::time::timeout(LIMIT, $what)
            .await
            .expect("制限時間を超えた")
    };
}

fn version(nonce: u64, height: u64) -> VersionMessage {
    VersionMessage {
        protocol_version: PROTOCOL_VERSION,
        services: SERVICE_FULL_NODE,
        timestamp: 1_800_000_000,
        nonce,
        user_agent: "/oag:0.1.0/".to_owned(),
        start_height: height,
        relay: true,
    }
}

fn payment(seed: u64) -> Transaction {
    let mut input = TxInput::new(OutPoint::new(hash::txid(&seed.to_le_bytes()), 0));
    input.signature = vec![0xab; 64];
    Transaction {
        version: CURRENT_TX_VERSION,
        inputs: vec![input],
        outputs: vec![TxOutput::new(
            Amount::from_oag(1).unwrap(),
            Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
        )],
        locktime: 0,
    }
}

/// 実運用に近い大きさのブロック。
fn big_block(count: u64) -> Block {
    let mut coinbase_input = TxInput::new(OutPoint::null());
    coinbase_input.signature = encode_coinbase_signature(100, b"orange");
    let coinbase = Transaction {
        version: CURRENT_TX_VERSION,
        inputs: vec![coinbase_input],
        outputs: vec![TxOutput::new(
            oag_consensus::params::BLOCK_REWARD,
            Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
        )],
        locktime: 0,
    };
    let mut transactions = vec![coinbase];
    transactions.extend((0..count).map(payment));
    let txids: Vec<Hash> = transactions.iter().map(|t| t.txid()).collect();
    Block {
        header: BlockHeader {
            version: 0,
            prev_hash: hash::block_hash(b"parent"),
            merkle_root: merkle::merkle_root(&txids).unwrap(),
            timestamp: 1_800_000_000,
            difficulty: 1_000,
            height: 100,
            nonce: 7,
        },
        transactions,
    }
}

/// 待ち受けを 1 つ立て、その住所を返す。
async fn listener(magic: [u8; MAGIC_LEN]) -> (Listener, SocketAddr) {
    let listener = Listener::bind(magic, "127.0.0.1:0".parse().unwrap())
        .await
        .expect("待ち受けられる");
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

#[tokio::test]
async fn two_peers_complete_a_handshake() {
    let (listener, addr) = listener(MAGIC).await;

    let server = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        conn.handshake(version(200, 50)).await
    });

    let mut client = within!(Connection::connect(MAGIC, addr)).unwrap();
    let server_version = within!(client.handshake(version(100, 10))).unwrap();
    let client_version = within!(server).unwrap().unwrap();

    assert_eq!(server_version.nonce, 200);
    assert_eq!(server_version.start_height, 50);
    assert_eq!(client_version.nonce, 100);
    assert_eq!(client_version.start_height, 10);
}

#[tokio::test]
async fn messages_travel_in_both_directions() {
    let (listener, addr) = listener(MAGIC).await;

    let server = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        conn.handshake(version(2, 0)).await.unwrap();
        // ping が来たら pong を返す。
        let Message::Ping(nonce) = conn.recv().await.unwrap() else {
            panic!("ping を期待した");
        };
        conn.send(&Message::Pong(nonce)).await.unwrap();
        conn.recv().await
    });

    let mut client = within!(Connection::connect(MAGIC, addr)).unwrap();
    within!(client.handshake(version(1, 0))).unwrap();

    within!(client.send(&Message::Ping(0xCAFE))).unwrap();
    assert_eq!(within!(client.recv()).unwrap(), Message::Pong(0xCAFE));

    let inv = Message::Inv(vec![InvItem::block(hash::block_hash(b"x"))]);
    within!(client.send(&inv)).unwrap();
    assert_eq!(within!(server).unwrap().unwrap(), inv);
}

#[tokio::test]
async fn a_large_block_survives_fragmentation() {
    // 15 万バイト級のブロックは 1 回の読み取りでは絶対に収まらない。
    // 溜めながら組み立てられることを確かめる。
    let block = big_block(1_000);
    let encoded_len = frame::encode(MAGIC, &Message::Block(Box::new(block.clone()))).len();
    assert!(encoded_len > 100_000, "実際には {encoded_len} バイト");

    let (listener, addr) = listener(MAGIC).await;
    let sent = block.clone();
    let server = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        conn.handshake(version(2, 0)).await.unwrap();
        conn.send(&Message::Block(Box::new(sent))).await
    });

    let mut client = within!(Connection::connect(MAGIC, addr)).unwrap();
    within!(client.handshake(version(1, 0))).unwrap();
    let received = within!(client.recv()).unwrap();
    within!(server).unwrap().unwrap();

    assert_eq!(received, Message::Block(Box::new(block)));
}

#[tokio::test]
async fn several_messages_sent_at_once_are_read_one_by_one() {
    // TCP は境界を保たない。まとめて送っても 1 個ずつ取り出せること。
    let (listener, addr) = listener(MAGIC).await;
    let server = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        conn.handshake(version(2, 0)).await.unwrap();
        for i in 0..50u64 {
            conn.send(&Message::Ping(i)).await.unwrap();
        }
    });

    let mut client = within!(Connection::connect(MAGIC, addr)).unwrap();
    within!(client.handshake(version(1, 0))).unwrap();
    for i in 0..50u64 {
        assert_eq!(
            within!(client.recv()).unwrap(),
            Message::Ping(i),
            "{i} 個目"
        );
    }
    within!(server).unwrap();
}

#[tokio::test]
async fn closing_the_connection_is_detected() {
    let (listener, addr) = listener(MAGIC).await;
    let server = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        conn.handshake(version(2, 0)).await.unwrap();
        // 何も言わずに切る。
    });

    let mut client = within!(Connection::connect(MAGIC, addr)).unwrap();
    within!(client.handshake(version(1, 0))).unwrap();
    within!(server).unwrap();

    assert!(
        matches!(within!(client.recv()), Err(TransportError::Closed)),
        "接続が閉じられたことを検出できていない"
    );
}

#[tokio::test]
async fn a_peer_on_another_network_is_rejected() {
    // testnet のノードが mainnet の待ち受けに繋いできた状況。
    let (listener, addr) = listener(MAGIC_MAINNET).await;
    let server = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        conn.handshake(version(2, 0)).await
    });

    let mut client = within!(Connection::connect(MAGIC_TESTNET, addr)).unwrap();
    let _ = within!(client.send(&Message::Version(version(1, 0))));

    let result = within!(server).unwrap();
    assert!(
        matches!(result, Err(TransportError::Frame(_))),
        "別のネットワークの相手が受け入れられている: {result:?}"
    );
}

#[tokio::test]
async fn an_absurd_declared_length_is_rejected() {
    // 前置きだけを送り、巨大な長さを宣言して黙る。
    // ペイロードを待ち続けるとメモリを枯渇させられる。
    let (listener, addr) = listener(MAGIC).await;
    let server = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        conn.recv().await
    });

    let mut raw = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut header = Vec::new();
    header.extend_from_slice(&MAGIC);
    let mut command = [0u8; COMMAND_LEN];
    command[..5].copy_from_slice(b"block");
    header.extend_from_slice(&command);
    header.extend_from_slice(&u32::MAX.to_le_bytes());
    header.extend_from_slice(&[0u8; 4]);
    within!(raw.write_all(&header)).unwrap();
    within!(raw.flush()).unwrap();

    let result = within!(server).unwrap();
    assert!(
        matches!(
            result,
            Err(TransportError::Frame(oag_net::FrameError::PayloadTooLarge { max, .. })) if max == MAX_PAYLOAD
        ),
        "巨大な長さの宣言が拒否されていない: {result:?}"
    );
}

#[tokio::test]
async fn a_message_before_the_handshake_is_rejected() {
    let (listener, addr) = listener(MAGIC).await;
    let server = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        conn.handshake(version(2, 0)).await
    });

    let mut client = within!(Connection::connect(MAGIC, addr)).unwrap();
    // 名乗らずにいきなり本題を送る。
    within!(client.send(&Message::GetAddr)).unwrap();

    let result = within!(server).unwrap();
    assert!(
        matches!(result, Err(TransportError::Handshake(_))),
        "名乗る前の要求が受け入れられている: {result:?}"
    );
}

#[tokio::test]
async fn connecting_to_oneself_is_detected_over_the_wire() {
    // 同じ乱数を使う 2 つの端が繋がると、自己接続として弾かれる。
    let (listener, addr) = listener(MAGIC).await;
    let server = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        conn.handshake(version(777, 0)).await
    });

    let mut client = within!(Connection::connect(MAGIC, addr)).unwrap();
    let client_result = within!(client.handshake(version(777, 0)));
    let server_result = within!(server).unwrap();

    assert!(
        client_result.is_err() || server_result.is_err(),
        "自己接続が検出されていない"
    );
}

#[tokio::test]
async fn many_connections_can_be_served() {
    let (listener, addr) = listener(MAGIC).await;
    let server = tokio::spawn(async move {
        for i in 0..8u64 {
            let mut conn = listener.accept().await.unwrap();
            conn.handshake(version(1_000 + i, 0)).await.unwrap();
            conn.send(&Message::Pong(i)).await.unwrap();
        }
    });

    for i in 0..8u64 {
        let mut client = within!(Connection::connect(MAGIC, addr)).unwrap();
        let peer = within!(client.handshake(version(i, 0))).unwrap();
        assert_eq!(peer.nonce, 1_000 + i);
        assert_eq!(within!(client.recv()).unwrap(), Message::Pong(i));
    }
    within!(server).unwrap();
}
