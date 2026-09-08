//! Orange (OAG) のウォレット。
//!
//! - [`mod@build`] — 支払いの組み立てと署名
//! - [`keystore`] — 鍵の保管
//!
//! **ノードとは JSON-RPC でしか話さない。** チェーンの状態を持たず、
//! 秘密鍵はノードに渡らない。署名はここで済ませ、出来上がったものだけを
//! `sendrawtransaction` で投げる。

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod build;
pub mod keystore;

pub use build::{build, sign, BuildError, Coin, Draft, Spend};
pub use keystore::{Keystore, KeystoreError};
