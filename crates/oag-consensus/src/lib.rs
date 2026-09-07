//! Orange (OAG) のコンセンサス定義。
//!
//! - [`codec`] — 正準シリアライズ。曖昧な符号化を拒否する
//! - [`params`] — コンセンサスパラメータと手数料ポリシー
//! - [`lock`] — 出力の支払い条件
//! - [`tx`] — トランザクション
//! - [`mod@sighash`] — BIP341 方式の署名対象
//! - [`block`] — ブロックとブロックヘッダ
//!
//! すべての定数と規則は `docs/SPEC.md` に対応する。仕様書が正典であり、
//! 本実装との差異は仕様書側を優先して解消する。

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod block;
pub mod codec;
pub mod lock;
pub mod params;
pub mod sighash;
pub mod tx;

pub use block::{Block, BlockHeader};
pub use codec::{CodecError, Decode, Encode};
pub use lock::Lock;
pub use sighash::{sighash, SighashBase, SighashType};
pub use tx::{OutPoint, Transaction, TxInput, TxOutput};
