//! Orange (OAG) のウォレット。
//!
//! - [`mod@build`] — 支払いの組み立てと署名
//! - [`keystore`] — 鍵の保管 (パスフレーズで暗号化)
//! - [`pst`] — 部分署名トランザクション (PSBT 相当)
//! - [`seed`] — 種と、そこからの鍵の導出
//!
//! **ノードとは JSON-RPC でしか話さない。** チェーンの状態を持たず、
//! 秘密鍵はノードに渡らない。署名はここで済ませ、出来上がったものだけを
//! `sendrawtransaction` で投げる。

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod bip32;
pub mod bip39;
pub mod build;
pub mod keystore;
pub mod pst;
pub mod scan;
pub mod seed;

pub use bip39::{Bip39Error, Mnemonic};
pub use build::{build, consolidate, sign, BuildError, Coin, Consolidate, Draft, Spend};
pub use keystore::{Keystore, KeystoreError};
pub use pst::{Pst, PstError};
pub use scan::{BlockChanges, CoinTracker, OwnedCoin, Rollback};
pub use seed::{Seed, SeedError};
