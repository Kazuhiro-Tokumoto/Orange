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

// **この crate だけ `forbid` ではなく `deny` である。** 他の crate は全部
// `forbid(unsafe_code)` のままである。
//
// fast モードのデータセット (2 GB) を採掘スレッドの間で共有するのに、
// `unsafe impl Send / Sync` が 2 行だけ要る。`randomx-rs` の
// `RandomXDataset` が生ポインタを持つため、コンパイラには共有してよいか
// 分からないからである。`forbid` は内側の `allow` で解けないので、ここを
// `deny` に下げ、その 2 行にだけ `allow` を付けている。
// 何を引き受けているかは `randomx::SharedDataset` に書いてある。
#![deny(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod lwma;
pub mod seed;
pub mod target;

#[cfg(feature = "randomx")]
pub mod randomx;

pub use lwma::next_difficulty;
pub use seed::seed_height;
pub use target::{meets_difficulty, meets_target, target_from_difficulty};
