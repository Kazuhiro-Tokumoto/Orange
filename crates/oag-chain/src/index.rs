//! ブロックインデックス。
//!
//! 受け取ったすべてのブロック (アクティブチェーン上にないものを含む) の
//! 位置づけを記録する。最良チェーンの選択はこの記録に基づいて行う。

use oag_consensus::codec::{CodecError, Decode, Encode, Reader};
use oag_consensus::BlockHeader;
use oag_primitives::Hash;

/// ブロックの検証状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStatus {
    /// ヘッダと PoW は検証済み。**本体をまだ持っていない。**
    ///
    /// headers-first 同期で、ヘッダだけ先に受け取った状態である。本体が
    /// 無いのだから接続できない。チェーン選択の候補にもならない。
    HeaderOnly,
    /// ヘッダと PoW は検証済み。本体は持っているが、まだ検証していない。
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

    /// 本体を持っているか。
    pub fn has_body(&self) -> bool {
        matches!(
            self.status,
            BlockStatus::HeaderValid | BlockStatus::FullyValid
        )
    }

    /// ヘッダとして有効か (無効と判定されていないか)。
    ///
    /// 本体の有無は問わない。ロケータの構築や、次に本体を取り寄せるべき
    /// ブロックの選定に用いる。
    pub fn is_valid_header(&self) -> bool {
        !matches!(self.status, BlockStatus::Invalid)
    }

    /// このブロックをアクティブチェーンの先端の候補として検討してよいか。
    ///
    /// **本体を持っていることを要求する。** 本体が無ければ接続できず、
    /// 候補に含めても失敗するだけだからである。祖先まで本体がそろって
    /// いるかは、この 1 件だけでは分からない。
    /// [`Chain::accept_block`](crate::chain::Chain::accept_block) が
    /// 経路全体を確かめる。
    pub fn is_candidate(&self) -> bool {
        self.has_body()
    }
}

// ━━━━━━━━ 永続化のためのシリアライズ ━━━━━━━━

impl BlockStatus {
    fn to_byte(self) -> u8 {
        match self {
            BlockStatus::HeaderValid => 0,
            BlockStatus::FullyValid => 1,
            BlockStatus::Invalid => 2,
            BlockStatus::HeaderOnly => 3,
        }
    }

    fn from_byte(byte: u8) -> Option<BlockStatus> {
        match byte {
            0 => Some(BlockStatus::HeaderValid),
            1 => Some(BlockStatus::FullyValid),
            2 => Some(BlockStatus::Invalid),
            3 => Some(BlockStatus::HeaderOnly),
            _ => None,
        }
    }
}

impl Encode for BlockIndexEntry {
    /// `hash` は書き出さない。ヘッダから再計算できるため、保存すると
    /// 食い違いが起きうる余地を作るだけである。
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.header.encode_into(out);
        out.extend_from_slice(&self.cumulative_work.to_le_bytes());
        out.push(self.status.to_byte());
    }

    fn encoded_len(&self) -> usize {
        oag_consensus::block::BLOCK_HEADER_LEN + 16 + 1
    }
}

impl Decode for BlockIndexEntry {
    fn read_from(reader: &mut Reader<'_>) -> Result<BlockIndexEntry, CodecError> {
        let header = BlockHeader::read_from(reader)?;
        let cumulative_work = u128::from_le_bytes(reader.read_array()?);
        let raw = reader.read_u8()?;
        let status = BlockStatus::from_byte(raw).ok_or(CodecError::ValueOutOfRange {
            field: "index.status",
            value: u128::from(raw),
        })?;
        Ok(BlockIndexEntry {
            hash: header.hash(),
            header,
            cumulative_work,
            status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_primitives::hash;

    fn sample(status: BlockStatus) -> BlockIndexEntry {
        let header = BlockHeader {
            version: 0,
            prev_hash: hash::block_hash(b"parent"),
            merkle_root: hash::txid(b"merkle"),
            timestamp: 1_800_000_000,
            difficulty: 12_345,
            height: 678,
            nonce: 90,
        };
        BlockIndexEntry {
            hash: header.hash(),
            header,
            cumulative_work: u128::MAX / 3,
            status,
        }
    }

    #[test]
    fn round_trip() {
        for status in [
            BlockStatus::HeaderOnly,
            BlockStatus::HeaderValid,
            BlockStatus::FullyValid,
            BlockStatus::Invalid,
        ] {
            let entry = sample(status);
            let bytes = entry.encode();
            assert_eq!(bytes.len(), entry.encoded_len());
            assert_eq!(BlockIndexEntry::decode(&bytes).unwrap(), entry);
        }
    }

    #[test]
    fn the_hash_is_recomputed_not_stored() {
        // 保存しないので、ヘッダと食い違ったハッシュが記録されることはない。
        let entry = sample(BlockStatus::FullyValid);
        assert_eq!(entry.encoded_len(), 100 + 16 + 1);
        assert_eq!(
            BlockIndexEntry::decode(&entry.encode()).unwrap().hash,
            entry.header.hash()
        );
    }

    #[test]
    fn only_entries_with_a_body_are_candidates() {
        assert!(!sample(BlockStatus::HeaderOnly).is_candidate());
        assert!(sample(BlockStatus::HeaderValid).is_candidate());
        assert!(sample(BlockStatus::FullyValid).is_candidate());
        assert!(!sample(BlockStatus::Invalid).is_candidate());
    }

    #[test]
    fn a_header_only_entry_is_still_a_valid_header() {
        // 本体が無くても、ヘッダの連なりとしては有効である。
        assert!(sample(BlockStatus::HeaderOnly).is_valid_header());
        assert!(!sample(BlockStatus::HeaderOnly).has_body());
        assert!(!sample(BlockStatus::Invalid).is_valid_header());
    }

    #[test]
    fn an_unknown_status_byte_is_rejected() {
        let mut bytes = sample(BlockStatus::FullyValid).encode();
        *bytes.last_mut().unwrap() = 9;
        assert!(matches!(
            BlockIndexEntry::decode(&bytes),
            Err(CodecError::ValueOutOfRange { .. })
        ));
    }
}
