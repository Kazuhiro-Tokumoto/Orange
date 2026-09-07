//! ブロックインデックス。
//!
//! 受け取ったすべてのブロック (アクティブチェーン上にないものを含む) の
//! 位置づけを記録する。最良チェーンの選択はこの記録に基づいて行う。

use oag_consensus::BlockHeader;
use oag_primitives::Hash;

/// ブロックの検証状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStatus {
    /// ヘッダと PoW は検証済み。本体はまだ検証していない。
    ///
    /// 本体の検証には、そのブロックの位置における UTXO の状態が必要である。
    /// サイドチェーンのブロックは繋がるまでこの状態にとどまる。
    HeaderValid,
    /// 本体まで検証し、実際にアクティブチェーンへ接続したことがある。
    FullyValid,
    /// 検証に失敗した。子孫もすべて無効である。
    Invalid,
}

/// インデックスの 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIndexEntry {
    /// ブロックハッシュ。
    pub hash: Hash,
    /// ヘッダ。
    pub header: BlockHeader,
    /// ジェネシスからこのブロックまでの難易度の総和。
    ///
    /// 最良チェーンはこの値で選ぶ。ブロック数ではない。
    pub cumulative_work: u128,
    /// 検証状態。
    pub status: BlockStatus,
}

impl BlockIndexEntry {
    /// 高さ。
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// 親ブロックのハッシュ。
    pub fn prev_hash(&self) -> Hash {
        self.header.prev_hash
    }

    /// このブロックを候補として検討してよいか。
    pub fn is_candidate(&self) -> bool {
        !matches!(self.status, BlockStatus::Invalid)
    }
}
