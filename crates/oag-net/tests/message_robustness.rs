//! 壊れたメッセージを復号器に浴びせる。
//!
//! oag-consensus の `decode_robustness` と同じ手をネットワーク層に
//! 当てたものである。**こちらが最も外側**であり、
//! 相手が自由に決めたバイト列がそのまま入る唯一の場所である。
//!
//! 主張は 2 つ。
//!
//! 1. どんな命令名とどんなバイト列の組み合わせでも `panic` しない
//! 2. 復号できたなら、符号化し直すと元のバイト列に戻る
//!
//! 2 番目が破れると、同じメッセージを表すバイト列が 2 通りあることに
//! なる。メッセージ自体に ID は無いが、**中に入っているブロックや
//! トランザクションには ID がある**。復号して詰め直したものが元と
//! 違うなら、中継の途中で別物になりうる。

use oag_consensus::lock::Lock;
use oag_consensus::params::BLOCK_REWARD;
use oag_consensus::tx::{
    encode_coinbase_signature, OutPoint, Transaction, TxInput, TxOutput, CURRENT_TX_VERSION,
};
use oag_consensus::{Block, BlockHeader};
use oag_net::message::{GetHeaders, InvItem, Message, NetAddress, SendCompact, VersionMessage};
use oag_primitives::{merkle, Hash, SecretKey};

/// xorshift64*。種を固定できて、並びが版に依らない。
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        (self.next() % 256) as u8
    }
}

fn hash(n: u64) -> Hash {
    oag_primitives::hash::block_hash(&n.to_le_bytes())
}

fn block() -> Block {
    let mut input = TxInput::new(OutPoint::null());
    input.signature = encode_coinbase_signature(9, b"orange");
    let coinbase = Transaction {
        version: CURRENT_TX_VERSION,
        inputs: vec![input],
        outputs: vec![TxOutput::new(
            BLOCK_REWARD,
            Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
        )],
        locktime: 0,
    };
    let txids = vec![coinbase.txid()];
    Block {
        header: BlockHeader {
            version: 0,
            prev_hash: hash(1),
            merkle_root: merkle::merkle_root(&txids).unwrap(),
            timestamp: 1_774_000_000,
            difficulty: 100_000,
            height: 9,
            nonce: 42,
        },
        transactions: vec![coinbase],
    }
}

/// 見本となる、正しいメッセージの一式。
fn samples() -> Vec<Message> {
    let b = block();
    vec![
        Message::Version(VersionMessage {
            protocol_version: 1,
            services: 1,
            timestamp: 1_774_000_000,
            nonce: 0x1234_5678,
            user_agent: "/oag:0.1.0/".to_string(),
            start_height: 9,
            relay: true,
        }),
        Message::Verack,
        Message::Ping(7),
        Message::Pong(7),
        Message::GetAddr,
        Message::Addr(vec![
            NetAddress::from_socket("127.0.0.1:19444".parse().unwrap(), 1, 1_774_000_000),
            NetAddress::from_socket("[::1]:19444".parse().unwrap(), 1, 1_774_000_001),
        ]),
        Message::Inv(vec![InvItem::block(hash(2)), InvItem::tx(hash(3))]),
        Message::GetData(vec![InvItem::block(hash(4))]),
        Message::NotFound(vec![InvItem::tx(hash(5))]),
        Message::GetHeaders(GetHeaders {
            protocol_version: 1,
            locator: vec![hash(6), hash(7), hash(8)],
            stop: Hash::ZERO,
        }),
        Message::Headers(vec![b.header]),
        Message::Block(Box::new(b.clone())),
        Message::Tx(Box::new(b.transactions[0].clone())),
        Message::Mempool,
        Message::SendCompact(SendCompact {
            high_bandwidth: true,
            version: 1,
        }),
    ]
}

fn corrupt(rng: &mut Rng, original: &[u8]) -> Vec<u8> {
    let mut bytes = original.to_vec();
    match rng.next() % 6 {
        0 => {
            if !bytes.is_empty() {
                let at = rng.below(bytes.len());
                bytes[at] ^= 1 << (rng.next() % 8);
            }
        }
        1 => {
            if !bytes.is_empty() {
                let at = rng.below(bytes.len());
                bytes[at] = rng.byte();
            }
        }
        2 => {
            let keep = rng.below(bytes.len() + 1);
            bytes.truncate(keep);
        }
        3 => {
            for _ in 0..rng.below(40) {
                let b = rng.byte();
                bytes.push(b);
            }
        }
        4 => {
            let at = rng.below(bytes.len() + 1);
            let b = rng.byte();
            bytes.insert(at, b);
        }
        _ => {
            let len = rng.below(200);
            bytes = (0..len).map(|_| rng.byte()).collect();
        }
    }
    bytes
}

fn round_trips(command: &str, payload: &[u8]) {
    if let Ok(message) = Message::decode_payload(command, payload) {
        let again = message.encode_payload();
        assert_eq!(
            again, payload,
            "{command}: 復号できたのに符号化し直すと別のバイト列になる"
        );
    }
}

#[test]
fn a_corrupted_payload_never_panics_and_never_decodes_two_ways() {
    let mut rng = Rng::new(0x0A6E_1001);
    for message in samples() {
        let command = message.command();
        let original = message.encode_payload();
        for _ in 0..4_000 {
            let bytes = corrupt(&mut rng, &original);
            round_trips(command, &bytes);
        }
    }
}

#[test]
fn any_payload_under_any_command_never_panics() {
    // 命令名と中身の組み合わせを総当たりに近い形で崩す。block の中身を
    // tx として読ませる、といった食い違いをここで踏む。
    let commands: Vec<&'static str> = samples().iter().map(|m| m.command()).collect();
    let payloads: Vec<Vec<u8>> = samples().iter().map(|m| m.encode_payload()).collect();

    let mut rng = Rng::new(0x0A6E_1002);
    for command in &commands {
        for payload in &payloads {
            round_trips(command, payload);
            for _ in 0..200 {
                let bytes = corrupt(&mut rng, payload);
                round_trips(command, &bytes);
            }
        }
    }
}

#[test]
fn pure_noise_under_every_command_never_panics() {
    let commands: Vec<&'static str> = samples().iter().map(|m| m.command()).collect();
    let mut rng = Rng::new(0x0A6E_1003);
    for command in &commands {
        for _ in 0..2_000 {
            let len = rng.below(300);
            let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            round_trips(command, &bytes);
        }
    }
}

#[test]
fn an_unknown_command_is_refused_rather_than_guessed() {
    let payload = samples()[0].encode_payload();
    assert!(Message::decode_payload("nonsense", &payload).is_err());
    assert!(Message::decode_payload("", &[]).is_err());
}
