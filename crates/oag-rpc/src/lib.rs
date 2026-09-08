//! Orange (OAG) の JSON-RPC。
//!
//! - [`jsonrpc`] — JSON-RPC 2.0 の要求と応答
//! - [`http`] — それを運ぶための必要最小限の HTTP/1.1
//! - [`auth`] — 使い捨ての合言葉
//! - [`client`] — 呼び出し側 (ウォレットの CLI が使う)
//!
//! **手続きの中身はここには無い。** ここが担うのは運び方だけであり、
//! どんな手続きがあるかはノード側が決める。チェーンの型に依存しないため、
//! この層だけを差し替えたり試験したりできる。
//!
//! # 締め出しの既定値
//!
//! 待ち受けは**ループバックのみ**を既定とし、合言葉による認証を必須と
//! する (SPEC §14.1)。RPC を外部公開した結果として資金を喪失する事故は
//! 複数のプロジェクトで起きている。

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod auth;
pub mod client;
pub mod http;
pub mod jsonrpc;

pub use auth::{AuthError, Credential};
pub use client::{Client, ClientError};
pub use http::{Handler, Server};
pub use jsonrpc::{Id, Request, Response, RpcError};
