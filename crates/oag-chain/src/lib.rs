//! Orange (OAG) のチェーン状態。
//!
//! - [`index`] — ブロックインデックス
//! - [`chain`] — 最良チェーンの選択とリオーグ
//! - [`genesis`] — ジェネシスブロックの構築
//!
//! 本クレートの実装はすべてメモリ上に保持する。永続化は後のフェーズで行う。

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod chain;
pub mod genesis;
pub mod index;

pub use chain::{AcceptOutcome, Chain, ChainError, Reorg};
pub use genesis::GenesisSpec;
pub use index::{BlockIndexEntry, BlockStatus};
