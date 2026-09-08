//! Orange (OAG) の採掘。
//!
//! - [`template`] — ブロックテンプレートの組み立て
//! - [`mod@mine`] — `nonce` の探索
//!
//! ハッシュの計算は [`mine::PowHasher`] として抽象化してある。実際の採掘では
//! RandomX を渡し、試験では速い偽物を渡す。

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod mine;
pub mod template;

pub use mine::{mine, MineError, MiningOutcome, NeverStop, PowHasher, StopSignal};
pub use template::{build_template, BlockTemplate, TemplateError, TemplateRequest};
