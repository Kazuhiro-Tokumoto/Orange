//! Orange (OAG) のチェーン状態。
//!
//! - [`index`] — ブロックインデックス
//! - [`chain`] — 最良チェーンの選択とリオーグ
//! - [`genesis`] — ジェネシスブロックの構築
//! - [`store`] — 記憶域の抽象とメモリ実装
//! - [`scenarios`] — 記憶域によらず走らせる試験手順
//!
//! チェーンの状態の実体は [`store::ChainStore`] が持つ。メモリ実装と
//! 永続化実装 (`oag-store` クレート) を同じコードで扱える。

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod chain;
pub mod genesis;
pub mod index;
pub mod scenarios;
pub mod store;

pub use chain::{AcceptOutcome, Chain, ChainError, Reorg};
pub use genesis::GenesisSpec;
pub use index::{BlockIndex, BlockIndexEntry, BlockStatus};
pub use store::{ChainStore, MemoryStore};
