//! メッセージの枠組み。
//!
//! ```text
//! magic     [4]   ネットワーク識別子
//! command  [12]   コマンド名。ASCII、余りは NUL 埋め
//! length    [4]   ペイロード長 (u32 LE)
//! checksum  [4]   BLAKE3(payload)[0..4]
//! payload  [長さ]
//! ```
//!
//! 合計 24 バイトの前置きが付く。
//!
//! # 上限の意味
//!
//! [`MAX_PAYLOAD`] を超える長さを宣言されたら、**読み込む前に**拒否する。
//! 長さだけを大きく偽って接続を保つことで、相手のメモリを枯渇させられる
//! ためである。ブロックの上限は 200,000 バイトなので、1 MiB あれば
//! すべての正当なメッセージが収まる。

use crate::magic::MAGIC_LEN;
use crate::message::{Message, MessageError};

/// コマンド名の領域。
pub const COMMAND_LEN: usize = 12;

/// 前置きの大きさ。
pub const HEADER_LEN: usize = MAGIC_LEN + COMMAND_LEN + 4 + 4;

/// ペイロードの最大長。
///
/// 最大のブロック (200,000 バイト) と、上限まで詰めた `inv`
/// (5,000 項目 × 33 バイト = 165,000 バイト) の双方が余裕をもって収まる。
pub const MAX_PAYLOAD: usize = 1024 * 1024;

/// チェックサムの長さ。
pub const CHECKSUM_LEN: usize = 4;

/// 枠組みの誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// ネットワーク識別子が違う。別のネットワークか、雑音である。
    #[error("ネットワーク識別子が一致しない: {actual:02x?}")]
    BadMagic {
        /// 受け取った値。
        actual: [u8; MAGIC_LEN],
    },
    /// コマンド名が ASCII として解釈できない、または NUL 埋めが不正。
    #[error("コマンド名が不正")]
    BadCommand,
    /// 宣言された長さが上限を超えている。
    #[error("ペイロード長 {actual} が上限 {max} を超えている")]
    PayloadTooLarge {
        /// 宣言された長さ。
        actual: usize,
        /// 上限。
        max: usize,
    },
    /// チェックサムが合わない。
    #[error("チェックサムが一致しない")]
    BadChecksum,
    /// メッセージの中身が解釈できない。
    #[error(transparent)]
    Message(#[from] MessageError),
}

/// ペイロードのチェックサム。
pub fn checksum(payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = blake3::hash(payload);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest.as_bytes()[..CHECKSUM_LEN]);
    out
}

/// メッセージを 1 個分のバイト列に符号化する。
pub fn encode(magic: [u8; MAGIC_LEN], message: &Message) -> Vec<u8> {
    let payload = message.encode_payload();
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&magic);

    let command = message.command().as_bytes();
    debug_assert!(command.len() <= COMMAND_LEN);
    let mut field = [0u8; COMMAND_LEN];
    field[..command.len()].copy_from_slice(command);
    out.extend_from_slice(&field);

    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&checksum(&payload));
    out.extend_from_slice(&payload);
    out
}

/// バイト列の先頭から 1 個のメッセージを取り出す。
///
/// - `Ok(None)` — まだ足りない。もっと読んでから呼び直す
/// - `Ok(Some((message, 消費バイト数)))` — 1 個取り出せた
/// - `Err(_)` — 壊れている。接続を切るべき
pub fn decode(magic: [u8; MAGIC_LEN], buf: &[u8]) -> Result<Option<(Message, usize)>, FrameError> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }

    let mut actual_magic = [0u8; MAGIC_LEN];
    actual_magic.copy_from_slice(&buf[..MAGIC_LEN]);
    if actual_magic != magic {
        return Err(FrameError::BadMagic {
            actual: actual_magic,
        });
    }

    let command_field = &buf[MAGIC_LEN..MAGIC_LEN + COMMAND_LEN];
    let command = parse_command(command_field)?;

    let mut length_bytes = [0u8; 4];
    length_bytes.copy_from_slice(&buf[MAGIC_LEN + COMMAND_LEN..MAGIC_LEN + COMMAND_LEN + 4]);
    let length = u32::from_le_bytes(length_bytes) as usize;

    // 長さの検査は読み込む前に行う。
    if length > MAX_PAYLOAD {
        return Err(FrameError::PayloadTooLarge {
            actual: length,
            max: MAX_PAYLOAD,
        });
    }

    let mut expected = [0u8; CHECKSUM_LEN];
    expected.copy_from_slice(&buf[MAGIC_LEN + COMMAND_LEN + 4..HEADER_LEN]);

    let total = HEADER_LEN + length;
    if buf.len() < total {
        return Ok(None);
    }
    let payload = &buf[HEADER_LEN..total];

    if checksum(payload) != expected {
        return Err(FrameError::BadChecksum);
    }

    let message = Message::decode_payload(&command, payload)?;
    Ok(Some((message, total)))
}

fn parse_command(field: &[u8]) -> Result<String, FrameError> {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    // NUL より後ろはすべて NUL でなければならない。
    if field[end..].iter().any(|b| *b != 0) {
        return Err(FrameError::BadCommand);
    }
    let name = &field[..end];
    if name.is_empty() || !name.iter().all(|b| b.is_ascii_lowercase()) {
        return Err(FrameError::BadCommand);
    }
    Ok(String::from_utf8_lossy(name).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::magic::{magic_for, MAGIC_MAINNET, MAGIC_TESTNET};
    use crate::message::{GetHeaders, InvItem, NetAddress, VersionMessage, PROTOCOL_VERSION};
    use oag_consensus::lock::Lock;
    use oag_consensus::tx::{OutPoint, TxInput, TxOutput, CURRENT_TX_VERSION};
    use oag_consensus::{Block, BlockHeader, Transaction};
    use oag_primitives::{hash, merkle, Amount, Hash, Network, SecretKey};

    const MAGIC: [u8; MAGIC_LEN] = MAGIC_MAINNET;

    fn version() -> VersionMessage {
        VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            services: crate::message::SERVICE_FULL_NODE,
            timestamp: 1_800_000_000,
            nonce: 0x0123_4567_89AB_CDEF,
            user_agent: "/oag:0.1.0/".to_owned(),
            start_height: 12_345,
            relay: true,
        }
    }

    fn transaction() -> Transaction {
        let mut input = TxInput::new(OutPoint::new(hash::txid(b"prev"), 0));
        input.signature = vec![0xab; 64];
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: vec![TxOutput::new(
                Amount::from_oag(9).unwrap(),
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            )],
            locktime: 0,
        }
    }

    fn header(height: u64) -> BlockHeader {
        BlockHeader {
            version: 0,
            prev_hash: hash::block_hash(b"parent"),
            merkle_root: hash::txid(b"merkle"),
            timestamp: 1_800_000_000 + height as i64 * 60,
            difficulty: 1_000,
            height,
            nonce: height,
        }
    }

    fn block() -> Block {
        let tx = transaction();
        let mut header = header(7);
        header.merkle_root = merkle::merkle_root(&[tx.txid()]).unwrap();
        Block {
            header,
            transactions: vec![tx],
        }
    }

    fn every_message() -> Vec<Message> {
        vec![
            Message::Version(version()),
            Message::Verack,
            Message::Ping(42),
            Message::Pong(42),
            Message::GetAddr,
            Message::Mempool,
            Message::Addr(vec![NetAddress::from_socket(
                "203.0.113.5:9444".parse().unwrap(),
                1,
                1_800_000_000,
            )]),
            Message::Inv(vec![
                InvItem::tx(hash::txid(b"a")),
                InvItem::block(hash::block_hash(b"b")),
            ]),
            Message::GetData(vec![InvItem::block(hash::block_hash(b"c"))]),
            Message::NotFound(vec![InvItem::tx(hash::txid(b"d"))]),
            Message::GetHeaders(GetHeaders {
                protocol_version: PROTOCOL_VERSION,
                locator: vec![hash::block_hash(b"tip"), hash::block_hash(b"older")],
                stop: Hash::ZERO,
            }),
            Message::Headers(vec![header(1), header(2), header(3)]),
            Message::Block(Box::new(block())),
            Message::Tx(Box::new(transaction())),
        ]
    }

    #[test]
    fn every_message_round_trips() {
        for message in every_message() {
            let bytes = encode(MAGIC, &message);
            let (decoded, consumed) = decode(MAGIC, &bytes)
                .unwrap_or_else(|e| panic!("{} の復号に失敗: {e}", message.command()))
                .unwrap_or_else(|| panic!("{} が不完全と判定された", message.command()));
            assert_eq!(decoded, message, "{} が往復しない", message.command());
            assert_eq!(consumed, bytes.len());
        }
    }

    #[test]
    fn the_header_is_24_bytes() {
        assert_eq!(HEADER_LEN, 24);
        let bytes = encode(MAGIC, &Message::Verack);
        assert_eq!(bytes.len(), HEADER_LEN, "verack はペイロードを持たない");
    }

    #[test]
    fn a_partial_message_is_not_an_error() {
        let bytes = encode(MAGIC, &Message::Block(Box::new(block())));
        for cut in 0..bytes.len() {
            assert_eq!(
                decode(MAGIC, &bytes[..cut]),
                Ok(None),
                "{cut} バイトで誤りと判定された"
            );
        }
        assert!(decode(MAGIC, &bytes).unwrap().is_some());
    }

    #[test]
    fn several_messages_can_share_a_buffer() {
        let messages = vec![Message::Ping(1), Message::Verack, Message::Pong(2)];
        let mut buf = Vec::new();
        for m in &messages {
            buf.extend_from_slice(&encode(MAGIC, m));
        }

        let mut offset = 0;
        let mut got = Vec::new();
        while let Some((message, consumed)) = decode(MAGIC, &buf[offset..]).unwrap() {
            offset += consumed;
            got.push(message);
        }
        assert_eq!(got, messages);
        assert_eq!(offset, buf.len());
    }

    #[test]
    fn a_foreign_network_is_rejected() {
        let bytes = encode(MAGIC_TESTNET, &Message::Verack);
        assert_eq!(
            decode(MAGIC_MAINNET, &bytes),
            Err(FrameError::BadMagic {
                actual: MAGIC_TESTNET
            })
        );
        // それぞれのネットワークで自分のものは通る。
        for network in Network::ALL {
            let magic = magic_for(network);
            assert!(decode(magic, &encode(magic, &Message::Verack))
                .unwrap()
                .is_some());
        }
    }

    #[test]
    fn a_corrupted_payload_is_caught() {
        let mut bytes = encode(MAGIC, &Message::Ping(7));
        *bytes.last_mut().unwrap() ^= 0xff;
        assert_eq!(decode(MAGIC, &bytes), Err(FrameError::BadChecksum));
    }

    #[test]
    fn an_oversized_length_is_rejected_before_reading_the_payload() {
        // 前置きだけを渡し、巨大な長さを宣言する。ペイロードは 1 バイトも無い。
        // これを Ok(None) として待ち続けると、相手にメモリを枯渇させられる。
        let mut header_bytes = Vec::new();
        header_bytes.extend_from_slice(&MAGIC);
        let mut command = [0u8; COMMAND_LEN];
        command[..5].copy_from_slice(b"block");
        header_bytes.extend_from_slice(&command);
        header_bytes.extend_from_slice(&(u32::MAX).to_le_bytes());
        header_bytes.extend_from_slice(&[0u8; CHECKSUM_LEN]);
        assert_eq!(header_bytes.len(), HEADER_LEN);

        assert_eq!(
            decode(MAGIC, &header_bytes),
            Err(FrameError::PayloadTooLarge {
                actual: u32::MAX as usize,
                max: MAX_PAYLOAD
            })
        );
    }

    #[test]
    fn the_largest_valid_message_fits_within_the_limit() {
        // 上限まで詰めた inv。
        let items: Vec<InvItem> = (0..crate::message::MAX_INV_ITEMS as u64)
            .map(|i| InvItem::tx(hash::txid(&i.to_le_bytes())))
            .collect();
        let bytes = encode(MAGIC, &Message::Inv(items));
        assert!(
            bytes.len() - HEADER_LEN <= MAX_PAYLOAD,
            "上限まで詰めた inv が {} バイトになる",
            bytes.len()
        );
        assert!(decode(MAGIC, &bytes).unwrap().is_some());

        // 最大のブロックも収まること。
        const { assert!(oag_consensus::params::MAX_BLOCK_SIZE < MAX_PAYLOAD) };
    }

    #[test]
    fn a_malformed_command_is_rejected() {
        let make = |command: [u8; COMMAND_LEN]| {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&MAGIC);
            bytes.extend_from_slice(&command);
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&checksum(&[]));
            bytes
        };

        // NUL の後ろにごみが入っている。
        let mut command = [0u8; COMMAND_LEN];
        command[..6].copy_from_slice(b"verack");
        command[10] = b'x';
        assert_eq!(decode(MAGIC, &make(command)), Err(FrameError::BadCommand));

        // 大文字を含む。
        let mut command = [0u8; COMMAND_LEN];
        command[..6].copy_from_slice(b"VERACK");
        assert_eq!(decode(MAGIC, &make(command)), Err(FrameError::BadCommand));

        // 空。
        assert_eq!(
            decode(MAGIC, &make([0u8; COMMAND_LEN])),
            Err(FrameError::BadCommand)
        );
    }

    #[test]
    fn an_unknown_command_is_reported_as_such() {
        let mut command = [0u8; COMMAND_LEN];
        command[..7].copy_from_slice(b"unknown");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&command);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&checksum(&[]));
        assert!(matches!(
            decode(MAGIC, &bytes),
            Err(FrameError::Message(MessageError::UnknownCommand(_)))
        ));
    }

    #[test]
    fn item_count_caps_are_enforced() {
        use oag_consensus::codec::{write_varint, Encode};
        // 上限を 1 個超える inv を手で組み立てる。
        let mut payload = Vec::new();
        write_varint(crate::message::MAX_INV_ITEMS as u128 + 1, &mut payload);
        for i in 0..=crate::message::MAX_INV_ITEMS as u64 {
            InvItem::tx(hash::txid(&i.to_le_bytes())).encode_into(&mut payload);
        }
        assert!(matches!(
            Message::decode_payload("inv", &payload),
            Err(MessageError::TooManyItems { max, .. }) if max == crate::message::MAX_INV_ITEMS
        ));
    }

    #[test]
    fn empty_messages_reject_a_payload() {
        assert!(matches!(
            Message::decode_payload("verack", &[0x00]),
            Err(MessageError::Codec(_))
        ));
    }

    #[test]
    fn addresses_round_trip_through_sockets() {
        for text in ["203.0.113.5:9444", "[2001:db8::1]:19444"] {
            let socket: std::net::SocketAddr = text.parse().unwrap();
            let addr = NetAddress::from_socket(socket, 1, 1_800_000_000);
            assert_eq!(addr.to_socket(), socket, "{text}");
        }
    }

    #[test]
    fn unroutable_addresses_are_recognised() {
        let check = |text: &str| NetAddress::from_socket(text.parse().unwrap(), 1, 0).is_routable();
        // 広めてよい住所。
        assert!(check("1.1.1.1:9444"));
        assert!(check("8.8.8.8:9444"));
        assert!(check("[2001:db8::1]:9444"), "IPv6 のグローバル住所");

        // 広めてはいけない住所。
        assert!(!check("127.0.0.1:9444"), "ループバック");
        assert!(!check("[::1]:9444"), "IPv6 のループバック");
        assert!(!check("10.0.0.1:9444"), "私設網");
        assert!(!check("192.168.1.1:9444"), "私設網");
        assert!(!check("172.16.0.1:9444"), "私設網");
        assert!(!check("169.254.1.1:9444"), "リンクローカル");
        assert!(!check("0.0.0.0:9444"), "未指定");
        // 203.0.113.0/24 と 198.51.100.0/24 は文書用に予約された範囲であり、
        // 実在のホストを指さない。広めても意味がない。
        assert!(!check("203.0.113.5:9444"), "文書用の予約範囲");
        assert!(!check("198.51.100.7:9444"), "文書用の予約範囲");
    }
}
