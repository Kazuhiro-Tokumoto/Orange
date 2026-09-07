//! Orange (OAG) の mempool と中継ポリシー。
//!
//! - [`policy`] — 中継ポリシーの設定
//! - [`pool`] — mempool 本体
//!
//! **ここで扱うのはコンセンサスルールではない。** mempool に入れるかどうかは
//! 各ノードの判断であり、変更にハードフォークを必要としない。ここで拒否した
//! トランザクションがブロックに入っていても、そのブロックは有効でありうる。
//!
//! 参照: `docs/SPEC.md` §13

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod policy;
pub mod pool;

pub use policy::Policy;
pub use pool::{Mempool, MempoolEntry, Reject};
