//! P2P メッセージ。
//!
//! 参照: `docs/SPEC.md` §14.4

use oag_consensus::codec::{write_var_bytes, write_varint, CodecError, Decode, Encode, Reader};
use oag_consensus::{Block, BlockHeader, Transaction};
use oag_primitives::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// 現在のプロトコル版数。
pub const PROTOCOL_VERSION: u32 = 1;

/// 受け入れる最小のプロトコル版数。
pub const MIN_PROTOCOL_VERSION: u32 = 1;

/// `inv` / `getdata` / `notfound` に載せられる項目数の上限。
pub const MAX_INV_ITEMS: usize = 5_000;

/// `headers` に載せられるヘッダ数の上限。
pub const MAX_HEADERS: usize = 2_000;

/// `addr` に載せられるアドレス数の上限。
pub const MAX_ADDRESSES: usize = 1_000;

/// `getblocktxn` / `blocktxn` に載せられる件数の上限。
pub const MAX_BLOCK_TXN: usize = crate::compact::MAX_BLOCK_TRANSACTIONS;

/// `getheaders` のロケータに載せられるハッシュ数の上限。
pub const MAX_LOCATOR: usize = 64;

/// ユーザエージェント文字列の最大バイト数。
pub const MAX_USER_AGENT: usize = 64;

/// 提供する機能を表すビット。現在は定義していない。
pub const SERVICE_NONE: u64 = 0;
/// フルノードであること (ブロックを提供できる)。
pub const SERVICE_FULL_NODE: u64 = 1;

/// メッセージの誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    /// 符号化・復号の誤り。
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// 知らないコマンド。
    #[error("知らないコマンド: {0}")]
    UnknownCommand(String),
    /// 項目数が上限を超えている。
    #[error("{field} の項目数 {actual} が上限 {max} を超えている")]
    TooManyItems {
        /// フィールド名。
        field: &'static str,
        /// 実際の数。
        actual: usize,
        /// 上限。
        max: usize,
    },
    /// 知らない inv の種別。
    #[error("知らない inv の種別: {0}")]
    UnknownInvKind(u8),
    /// ユーザエージェントが不正。
    #[error("ユーザエージェントが不正")]
    BadUserAgent,
}

/// `inv` が指すものの種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum InvKind {
    /// トランザクション。
    Tx = 1,
    /// ブロック。
    Block = 2,
}

impl InvKind {
    fn from_byte(byte: u8) -> Result<InvKind, MessageError> {
        match byte {
            1 => Ok(InvKind::Tx),
            2 => Ok(InvKind::Block),
            other => Err(MessageError::UnknownInvKind(other)),
        }
    }
}

/// 在庫の 1 項目。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InvItem {
    /// 種別。
    pub kind: InvKind,
    /// 対象のハッシュ。
    pub hash: Hash,
}

impl InvItem {
    /// トランザクションを指す項目。
    pub fn tx(hash: Hash) -> InvItem {
        InvItem {
            kind: InvKind::Tx,
            hash,
        }
    }

    /// ブロックを指す項目。
    pub fn block(hash: Hash) -> InvItem {
        InvItem {
            kind: InvKind::Block,
            hash,
        }
    }
}

impl Encode for InvItem {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.kind as u8);
        out.extend_from_slice(self.hash.as_bytes());
    }

    fn encoded_len(&self) -> usize {
        33
    }
}

impl Decode for InvItem {
    fn read_from(reader: &mut Reader<'_>) -> Result<InvItem, CodecError> {
        let kind = reader.read_u8()?;
        let hash = reader.read_hash()?;
        let kind = InvKind::from_byte(kind).map_err(|_| CodecError::ValueOutOfRange {
            field: "inv.kind",
            value: u128::from(kind),
        })?;
        Ok(InvItem { kind, hash })
    }
}

/// ピアのアドレス。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetAddress {
    /// 提供する機能。
    pub services: u64,
    /// IPv6 で表した住所。IPv4 は IPv4 射影アドレスとして格納する。
    pub ip: [u8; 16],
    /// ポート番号。
    pub port: u16,
    /// 最後に見かけた時刻 (Unix 秒)。
    pub last_seen: i64,
}

impl NetAddress {
    /// ソケットアドレスから作る。
    pub fn from_socket(addr: SocketAddr, services: u64, last_seen: i64) -> NetAddress {
        let ip = match addr.ip() {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };
        NetAddress {
            services,
            ip,
            port: addr.port(),
            last_seen,
        }
    }

    /// ソケットアドレスに戻す。IPv4 射影アドレスは IPv4 に戻す。
    pub fn to_socket(self) -> SocketAddr {
        let v6 = Ipv6Addr::from(self.ip);
        let ip = match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        };
        SocketAddr::new(ip, self.port)
    }

    /// 外部に広めてよい住所か。
    ///
    /// ループバック・未指定・私設網の住所は広めない。
    pub fn is_routable(self) -> bool {
        match self.to_socket().ip() {
            IpAddr::V4(v4) => {
                !(v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    || v4 == Ipv4Addr::UNSPECIFIED)
            }
            IpAddr::V6(v6) => !(v6.is_loopback() || v6 == Ipv6Addr::UNSPECIFIED),
        }
    }
}

impl Encode for NetAddress {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.services.to_le_bytes());
        out.extend_from_slice(&self.ip);
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&self.last_seen.to_le_bytes());
    }

    fn encoded_len(&self) -> usize {
        34
    }
}

impl Decode for NetAddress {
    fn read_from(reader: &mut Reader<'_>) -> Result<NetAddress, CodecError> {
        Ok(NetAddress {
            services: reader.read_u64()?,
            ip: reader.read_array()?,
            port: u16::from_be_bytes(reader.read_array()?),
            last_seen: reader.read_i64()?,
        })
    }
}

/// `version` の中身。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMessage {
    /// プロトコル版数。
    pub protocol_version: u32,
    /// 提供する機能。
    pub services: u64,
    /// 送信時刻 (Unix 秒)。
    pub timestamp: i64,
    /// 自己接続を検出するための乱数。
    pub nonce: u64,
    /// 実装の名乗り。
    pub user_agent: String,
    /// 先端の高さ。
    pub start_height: u64,
    /// トランザクションの中継を望むか。
    pub relay: bool,
}

impl Encode for VersionMessage {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        out.extend_from_slice(&self.services.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        write_var_bytes(self.user_agent.as_bytes(), out);
        write_varint(u128::from(self.start_height), out);
        out.push(u8::from(self.relay));
    }
}

impl Decode for VersionMessage {
    fn read_from(reader: &mut Reader<'_>) -> Result<VersionMessage, CodecError> {
        let protocol_version = reader.read_u32()?;
        let services = reader.read_u64()?;
        let timestamp = reader.read_i64()?;
        let nonce = reader.read_u64()?;
        let agent = reader.read_var_bytes("version.user_agent", MAX_USER_AGENT)?;
        let user_agent =
            String::from_utf8(agent.to_vec()).map_err(|_| CodecError::LengthTooLarge {
                field: "version.user_agent",
                actual: agent.len() as u128,
                max: MAX_USER_AGENT,
            })?;
        let start_height = reader.read_varint_u64("version.start_height")?;
        let relay = reader.read_u8()? != 0;
        Ok(VersionMessage {
            protocol_version,
            services,
            timestamp,
            nonce,
            user_agent,
            start_height,
            relay,
        })
    }
}

/// `getblocktxn` の中身。ブロックの一部の取引を番号で求める。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlockTxn {
    /// 対象のブロック。
    pub block_hash: Hash,
    /// 欲しい取引の番号。ブロック内の位置である。
    pub indices: Vec<u32>,
}

impl Encode for GetBlockTxn {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.block_hash.as_bytes());
        write_varint(self.indices.len() as u128, out);
        // 番号は昇順に並ぶので差分で書く。
        let mut previous: i64 = -1;
        for index in &self.indices {
            let diff = i64::from(*index) - previous - 1;
            write_varint(diff.max(0) as u128, out);
            previous = i64::from(*index);
        }
    }
}

impl Decode for GetBlockTxn {
    fn read_from(reader: &mut Reader<'_>) -> Result<GetBlockTxn, CodecError> {
        let block_hash = reader.read_hash()?;
        let count = reader.read_count("getblocktxn.indices")?;
        if count > MAX_BLOCK_TXN {
            return Err(CodecError::LengthTooLarge {
                field: "getblocktxn.indices",
                actual: count as u128,
                max: MAX_BLOCK_TXN,
            });
        }
        let mut indices = Vec::with_capacity(count);
        let mut previous: i64 = -1;
        for _ in 0..count {
            let diff = reader.read_varint_u32("getblocktxn.index")?;
            let index = previous
                .checked_add(i64::from(diff))
                .and_then(|v| v.checked_add(1))
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(CodecError::ValueOutOfRange {
                    field: "getblocktxn.index",
                    value: u128::from(diff),
                })?;
            previous = i64::from(index);
            indices.push(index);
        }
        Ok(GetBlockTxn {
            block_hash,
            indices,
        })
    }
}

/// `blocktxn` の中身。求められた取引を返す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTxn {
    /// 対象のブロック。
    pub block_hash: Hash,
    /// 求められた順に並べた取引。
    pub transactions: Vec<Transaction>,
}

impl Encode for BlockTxn {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.block_hash.as_bytes());
        write_varint(self.transactions.len() as u128, out);
        for tx in &self.transactions {
            tx.encode_into(out);
        }
    }
}

impl Decode for BlockTxn {
    fn read_from(reader: &mut Reader<'_>) -> Result<BlockTxn, CodecError> {
        let block_hash = reader.read_hash()?;
        let count = reader.read_count("blocktxn.transactions")?;
        if count > MAX_BLOCK_TXN {
            return Err(CodecError::LengthTooLarge {
                field: "blocktxn.transactions",
                actual: count as u128,
                max: MAX_BLOCK_TXN,
            });
        }
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            transactions.push(Transaction::read_from(reader)?);
        }
        Ok(BlockTxn {
            block_hash,
            transactions,
        })
    }
}

/// `sendcmpct` の中身。圧縮したブロックで知らせてほしいかを伝える。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendCompact {
    /// 真なら、こちらから先に `cmpctblock` を送ってよい。
    /// 偽なら、`inv` で知らせてから求められたら送る。
    pub high_bandwidth: bool,
    /// Compact Blocks の版数。
    pub version: u64,
}

impl Encode for SendCompact {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(u8::from(self.high_bandwidth));
        out.extend_from_slice(&self.version.to_le_bytes());
    }
}

impl Decode for SendCompact {
    fn read_from(reader: &mut Reader<'_>) -> Result<SendCompact, CodecError> {
        Ok(SendCompact {
            high_bandwidth: reader.read_u8()? != 0,
            version: reader.read_u64()?,
        })
    }
}

/// `getheaders` の中身。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetHeaders {
    /// プロトコル版数。
    pub protocol_version: u32,
    /// ブロックロケータ。新しい順に、間隔を指数的に広げて並べる。
    pub locator: Vec<Hash>,
    /// ここまで欲しい、という目印。0 なら上限まで。
    pub stop: Hash,
}

impl Encode for GetHeaders {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        write_varint(self.locator.len() as u128, out);
        for hash in &self.locator {
            out.extend_from_slice(hash.as_bytes());
        }
        out.extend_from_slice(self.stop.as_bytes());
    }
}

impl Decode for GetHeaders {
    fn read_from(reader: &mut Reader<'_>) -> Result<GetHeaders, CodecError> {
        let protocol_version = reader.read_u32()?;
        let count = reader.read_count("getheaders.locator")?;
        if count > MAX_LOCATOR {
            return Err(CodecError::LengthTooLarge {
                field: "getheaders.locator",
                actual: count as u128,
                max: MAX_LOCATOR,
            });
        }
        let mut locator = Vec::with_capacity(count);
        for _ in 0..count {
            locator.push(reader.read_hash()?);
        }
        let stop = reader.read_hash()?;
        Ok(GetHeaders {
            protocol_version,
            locator,
            stop,
        })
    }
}

/// P2P メッセージ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// 接続開始の名乗り。
    Version(VersionMessage),
    /// `version` の受領確認。
    Verack,
    /// 生存確認。
    Ping(u64),
    /// 生存確認への応答。
    Pong(u64),
    /// 知っているピアの住所を求める。
    GetAddr,
    /// 知っているピアの住所。
    Addr(Vec<NetAddress>),
    /// 持っているものの通知。
    Inv(Vec<InvItem>),
    /// 実体の要求。
    GetData(Vec<InvItem>),
    /// 要求されたものを持っていない。
    NotFound(Vec<InvItem>),
    /// ヘッダの要求。
    GetHeaders(GetHeaders),
    /// ヘッダの列。
    Headers(Vec<BlockHeader>),
    /// ブロック本体。
    Block(Box<Block>),
    /// トランザクション。
    Tx(Box<Transaction>),
    /// mempool の中身を通知してほしい。
    Mempool,
    /// 圧縮したブロックで知らせてほしいかを伝える。
    SendCompact(SendCompact),
    /// 圧縮したブロック。
    CompactBlock(Box<crate::compact::CompactBlock>),
    /// ブロックの一部の取引を求める。
    GetBlockTxn(GetBlockTxn),
    /// 求められた取引。
    BlockTxn(Box<BlockTxn>),
}

impl Message {
    /// このメッセージのコマンド名。
    pub fn command(&self) -> &'static str {
        match self {
            Message::Version(_) => "version",
            Message::Verack => "verack",
            Message::Ping(_) => "ping",
            Message::Pong(_) => "pong",
            Message::GetAddr => "getaddr",
            Message::Addr(_) => "addr",
            Message::Inv(_) => "inv",
            Message::GetData(_) => "getdata",
            Message::NotFound(_) => "notfound",
            Message::GetHeaders(_) => "getheaders",
            Message::Headers(_) => "headers",
            Message::Block(_) => "block",
            Message::Tx(_) => "tx",
            Message::Mempool => "mempool",
            Message::SendCompact(_) => "sendcmpct",
            Message::CompactBlock(_) => "cmpctblock",
            Message::GetBlockTxn(_) => "getblocktxn",
            Message::BlockTxn(_) => "blocktxn",
        }
    }

    /// ハンドシェイクの一部であるか。
    pub fn is_handshake(&self) -> bool {
        matches!(self, Message::Version(_) | Message::Verack)
    }

    /// ペイロードを符号化する。
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Message::Verack | Message::GetAddr | Message::Mempool => {}
            Message::Version(v) => v.encode_into(&mut out),
            Message::Ping(nonce) | Message::Pong(nonce) => {
                out.extend_from_slice(&nonce.to_le_bytes());
            }
            Message::Addr(items) => encode_list(items, &mut out),
            Message::Inv(items) | Message::GetData(items) | Message::NotFound(items) => {
                encode_list(items, &mut out);
            }
            Message::GetHeaders(g) => g.encode_into(&mut out),
            Message::Headers(headers) => encode_list(headers, &mut out),
            Message::Block(block) => block.encode_into(&mut out),
            Message::Tx(tx) => tx.encode_into(&mut out),
            Message::SendCompact(s) => s.encode_into(&mut out),
            Message::CompactBlock(c) => c.encode_into(&mut out),
            Message::GetBlockTxn(g) => g.encode_into(&mut out),
            Message::BlockTxn(b) => b.encode_into(&mut out),
        }
        out
    }

    /// コマンド名とペイロードからメッセージを復元する。
    pub fn decode_payload(command: &str, payload: &[u8]) -> Result<Message, MessageError> {
        let msg = match command {
            "version" => Message::Version(VersionMessage::decode(payload)?),
            "verack" => {
                expect_empty(payload)?;
                Message::Verack
            }
            "getaddr" => {
                expect_empty(payload)?;
                Message::GetAddr
            }
            "mempool" => {
                expect_empty(payload)?;
                Message::Mempool
            }
            "ping" => Message::Ping(read_nonce(payload)?),
            "pong" => Message::Pong(read_nonce(payload)?),
            "addr" => Message::Addr(decode_list(payload, "addr", MAX_ADDRESSES)?),
            "inv" => Message::Inv(decode_list(payload, "inv", MAX_INV_ITEMS)?),
            "getdata" => Message::GetData(decode_list(payload, "getdata", MAX_INV_ITEMS)?),
            "notfound" => Message::NotFound(decode_list(payload, "notfound", MAX_INV_ITEMS)?),
            "getheaders" => Message::GetHeaders(GetHeaders::decode(payload)?),
            "headers" => Message::Headers(decode_list(payload, "headers", MAX_HEADERS)?),
            "block" => Message::Block(Box::new(Block::decode(payload)?)),
            "tx" => Message::Tx(Box::new(Transaction::decode(payload)?)),
            "sendcmpct" => Message::SendCompact(SendCompact::decode(payload)?),
            "cmpctblock" => {
                Message::CompactBlock(Box::new(crate::compact::CompactBlock::decode(payload)?))
            }
            "getblocktxn" => Message::GetBlockTxn(GetBlockTxn::decode(payload)?),
            "blocktxn" => Message::BlockTxn(Box::new(BlockTxn::decode(payload)?)),
            other => return Err(MessageError::UnknownCommand(other.to_owned())),
        };
        Ok(msg)
    }
}

fn encode_list<T: Encode>(items: &[T], out: &mut Vec<u8>) {
    write_varint(items.len() as u128, out);
    for item in items {
        item.encode_into(out);
    }
}

fn decode_list<T: Decode>(
    payload: &[u8],
    field: &'static str,
    max: usize,
) -> Result<Vec<T>, MessageError> {
    let mut reader = Reader::new(payload);
    let count = reader.read_count(field)?;
    if count > max {
        return Err(MessageError::TooManyItems {
            field,
            actual: count,
            max,
        });
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(T::read_from(&mut reader)?);
    }
    reader.finish()?;
    Ok(items)
}

fn expect_empty(payload: &[u8]) -> Result<(), MessageError> {
    if payload.is_empty() {
        Ok(())
    } else {
        Err(MessageError::Codec(CodecError::TrailingBytes(
            payload.len(),
        )))
    }
}

fn read_nonce(payload: &[u8]) -> Result<u64, MessageError> {
    let mut reader = Reader::new(payload);
    let nonce = reader.read_u64()?;
    reader.finish()?;
    Ok(nonce)
}
