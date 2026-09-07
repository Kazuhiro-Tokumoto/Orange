//! Orange (OAG) の P2P プロトコル。
//!
//! - [`magic`] — ネットワーク識別子
//! - [`message`] — メッセージの型
//! - [`frame`] — メッセージの枠組み
//! - [`handshake`] — ハンドシェイクの状態機械
//!
//! 本クレートは **入出力を行わない**。バイト列とメッセージの相互変換と、
//! 状態遷移の規則だけを扱う。実際の通信は上位の層が担う。この分離により、
//! プロトコルの規則をネットワークなしで試験できる。
//!
//! rust-libp2p は採用していない。PoW チェーンの P2P 要件は
//! 「ブロックとトランザクションを撒く」ことに尽き、libp2p の DHT や
//! 多様なトランスポートはオーバースペックであると判断した (SPEC §14.4)。

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod frame;
pub mod handshake;
pub mod magic;
pub mod message;

pub use frame::FrameError;
pub use handshake::{Handshake, HandshakeError};
pub use magic::magic_for;
pub use message::{InvItem, InvKind, Message, MessageError, NetAddress, VersionMessage};
