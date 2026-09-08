//! Orange (OAG) の基本型。
//!
//! 本クレートは、上位のコンセンサス・ネットワーク・ウォレット層が共有する
//! 最小限の型を提供する。
//!
//! - [`amount`] — `u128` の金額型。検査付き演算のみを公開する
//! - [`hash`] — BLAKE3 とドメイン分離
//! - [`merkle`] — RFC 6962 方式のマークルツリー
//! - [`varint`] — LEB128 可変長整数 (最短形以外を拒否する)
//! - [`keys`] — secp256k1 と BIP340 Schnorr 署名
//! - [`address`] — bech32m アドレス
//! - [`network`] — ネットワーク種別と既定値
//!
//! すべての定数と規則は `docs/SPEC.md` に対応する。仕様書が正典であり、
//! 本実装との差異は仕様書側を優先して解消する。

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod address;
pub mod amount;
pub mod hash;
pub mod keys;
pub mod merkle;
pub mod network;
pub mod varint;

pub use address::Address;
pub use amount::Amount;
pub use hash::Hash;
pub use keys::{fill_random, PublicKey, SecretKey, Signature};
pub use network::Network;
