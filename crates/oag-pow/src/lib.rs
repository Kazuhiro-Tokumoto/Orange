//! Orange (OAG) の Proof of Work。
//!
//! - [`target`] — 難易度とターゲットの変換、PoW 判定
//! - [`lwma`] — LWMA-1 による難易度調整
//! - [`seed`] — RandomX のシードエポック
//! - `randomx` — RandomX への FFI (feature `randomx` が必要)
//!
//! # feature `randomx`
//!
//! RandomX の実装は C++ ([tevador/RandomX](https://github.com/tevador/RandomX))
//! であり、ビルドに cmake と C++ コンパイラを要する。そのため既定では無効に
//! してある。実際の採掘とブロック検証にはこの feature が必須である。
//!
//! ```sh
//! cargo test -p oag-pow --features randomx
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod lwma;
pub mod seed;
pub mod target;

#[cfg(feature = "randomx")]
pub mod randomx;

pub use lwma::next_difficulty;
pub use seed::seed_height;
pub use target::{meets_difficulty, meets_target, target_from_difficulty};
