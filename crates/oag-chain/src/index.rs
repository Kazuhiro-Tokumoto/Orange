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

// ━━━━━━━━ インデックス全体 ━━━━━━━━

/// 作業量による並び順の鍵。
///
/// 作業量の多いものを「大きい」とする。同点のときは**ハッシュの小さい
/// ほうを大きい**とする。同点の扱いを決めておかないと、同じ作業量の
/// チェーンが 2 本届いたときにノードごとに違う先端を選び、合意が割れる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkKey {
    work: u128,
    hash: Hash,
}

impl Ord for WorkKey {
    fn cmp(&self, other: &WorkKey) -> std::cmp::Ordering {
        self.work
            .cmp(&other.work)
            // ハッシュだけ逆順にする。こうすると集合の末尾が常に「最良」に
            // なり、`next_back()` 1 回で先端が引ける。
            .then_with(|| other.hash.cmp(&self.hash))
    }
}

impl PartialOrd for WorkKey {
    fn partial_cmp(&self, other: &WorkKey) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// ブロックインデックス。
///
/// # なぜ派生した索引を持つのか
///
/// ブロックを 1 個受け取るたびに知りたいことは 3 つある。
///
/// 1. 先端の候補 — 本体を持ち、現先端より作業量の多いもの
/// 2. 最良ヘッダ — 本体の有無を問わず、最も作業量の多いもの
/// 3. あるブロックの子 — 無効の印を子孫へ広げるため
///
/// どれも全件を走査すれば求まる。**しかしブロック 1 個あたり O(n) は、
/// 初期同期の全体では O(n²) になる。** 10 万ブロックで 10^10 回の比較
/// であり、公開できる速さではない。
///
/// そこで、登録・状態変更のたびに索引を張り替えて持つ。1 と 2 は作業量
/// 順の集合の末尾を見るだけ (O(log n))、3 は親から子への写像を引くだけ
/// になる。Bitcoin の `setBlockIndexCandidates` と `pindexBestHeader` に
/// 相当する。
///
/// **索引の整合はこの型の中だけで保たれる。** 登録も状態変更もここを
/// 通す。外から `entries` を書き換える口は開けていない。
#[derive(Debug, Default)]
pub struct BlockIndex {
    entries: std::collections::HashMap<Hash, BlockIndexEntry>,
    /// 本体を持つもの。先端の候補になりうる。
    with_body: std::collections::BTreeSet<WorkKey>,
    /// 無効と判定されていないもの。本体の有無は問わない。
    valid_headers: std::collections::BTreeSet<WorkKey>,
    /// 親 → 子。ジェネシスは親を持たないので登録しない。
    children: std::collections::HashMap<Hash, Vec<Hash>>,
}

impl BlockIndex {
    /// 空のインデックス。
    pub fn new() -> BlockIndex {
        BlockIndex::default()
    }

    /// 登録されている件数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 1 件も登録されていないか。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 1 件を引く。
    pub fn get(&self, hash: &Hash) -> Option<&BlockIndexEntry> {
        self.entries.get(hash)
    }

    /// 知っているか。
    pub fn contains(&self, hash: &Hash) -> bool {
        self.entries.contains_key(hash)
    }

    /// 1 件を登録する。同じハッシュがあれば置き換える。
    ///
    /// 置き換えでは親子関係を張り直さない。**同じハッシュなら同じヘッダで
    /// あり、親も変わらない**ためである。
    pub fn insert(&mut self, entry: BlockIndexEntry) {
        let hash = entry.hash;
        let key = WorkKey {
            work: entry.cumulative_work,
            hash,
        };
        let height = entry.height();
        let prev = entry.prev_hash();
        let has_body = entry.has_body();
        let valid_header = entry.is_valid_header();

        match self.entries.insert(hash, entry) {
            Some(old) => {
                // 作業量が変わっていれば古い鍵が残る。両方外してから入れ直す。
                let stale = WorkKey {
                    work: old.cumulative_work,
                    hash,
                };
                self.with_body.remove(&stale);
                self.valid_headers.remove(&stale);
            }
            None if height != 0 => {
                self.children.entry(prev).or_default().push(hash);
            }
            None => {}
        }

        if has_body {
            self.with_body.insert(key);
        } else {
            self.with_body.remove(&key);
        }
        if valid_header {
            self.valid_headers.insert(key);
        } else {
            self.valid_headers.remove(&key);
        }
    }

    /// 状態だけを書き換える。書き換えた結果を返す。
    ///
    /// 知らないハッシュなら何もせず `None` を返す。
    pub fn set_status(&mut self, hash: &Hash, status: BlockStatus) -> Option<&BlockIndexEntry> {
        let entry = self.entries.get_mut(hash)?;
        entry.status = status;
        let key = WorkKey {
            work: entry.cumulative_work,
            hash: *hash,
        };
        let (has_body, valid_header) = (entry.has_body(), entry.is_valid_header());

        if has_body {
            self.with_body.insert(key);
        } else {
            self.with_body.remove(&key);
        }
        if valid_header {
            self.valid_headers.insert(key);
        } else {
            self.valid_headers.remove(&key);
        }
        self.entries.get(hash)
    }

    /// `hash` を親とするブロック。
    pub fn children_of(&self, hash: &Hash) -> &[Hash] {
        self.children.get(hash).map_or(&[], Vec::as_slice)
    }

    /// 本体を持ち、作業量が `work` を超えるものを**多い順に**返す。
    ///
    /// 先端の候補である。走るのは条件を満たす件数だけであり、全件では
    /// ない。先端を 1 個伸ばしただけなら 1 件で止まる。
    pub fn candidates_above(&self, work: u128) -> impl Iterator<Item = &BlockIndexEntry> {
        self.with_body
            .iter()
            .rev()
            .take_while(move |key| key.work > work)
            .filter_map(move |key| self.entries.get(&key.hash))
    }

    /// 最も作業量の多い、無効でないヘッダ。
    pub fn best_header(&self) -> Option<&BlockIndexEntry> {
        self.valid_headers
            .iter()
            .next_back()
            .and_then(|key| self.entries.get(&key.hash))
    }
}

impl std::ops::Index<&Hash> for BlockIndex {
    type Output = BlockIndexEntry;

    fn index(&self, hash: &Hash) -> &BlockIndexEntry {
        self.entries
            .get(hash)
            .unwrap_or_else(|| panic!("インデックスに {hash} が無い"))
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

    // ━━━━━━━━ インデックス全体 ━━━━━━━━

    fn entry_at(
        prev: Hash,
        height: u64,
        nonce: u64,
        work: u128,
        status: BlockStatus,
    ) -> BlockIndexEntry {
        let header = BlockHeader {
            version: 0,
            prev_hash: prev,
            merkle_root: hash::txid(b"merkle"),
            timestamp: 1_800_000_000,
            difficulty: 1,
            height,
            nonce,
        };
        BlockIndexEntry {
            hash: header.hash(),
            header,
            cumulative_work: work,
            status,
        }
    }

    /// ジェネシスと、その上に伸びる 1 本の鎖。
    fn a_chain(len: u64) -> (BlockIndex, Vec<BlockIndexEntry>) {
        let mut index = BlockIndex::new();
        let genesis = entry_at(Hash::ZERO, 0, 0, 1, BlockStatus::FullyValid);
        index.insert(genesis.clone());
        let mut chain = vec![genesis];
        for height in 1..=len {
            let prev = chain.last().unwrap();
            let entry = entry_at(
                prev.hash,
                height,
                height,
                prev.cumulative_work + 1,
                BlockStatus::FullyValid,
            );
            index.insert(entry.clone());
            chain.push(entry);
        }
        (index, chain)
    }

    #[test]
    fn the_best_header_is_the_one_with_the_most_work() {
        let (index, chain) = a_chain(20);
        assert_eq!(
            index.best_header().unwrap().hash,
            chain.last().unwrap().hash
        );
        assert_eq!(index.len(), 21);
    }

    #[test]
    fn only_candidates_above_the_given_work_are_visited() {
        // **これが O(n²) を避ける根拠である。** 先端を 1 個伸ばしただけ
        // なら、走るのは 1 件でなければならない。全件を舐めていたら、
        // ここが 100 件になる。
        let (index, chain) = a_chain(100);
        let tip_work = chain[chain.len() - 2].cumulative_work;
        let visited: Vec<_> = index.candidates_above(tip_work).collect();
        assert_eq!(visited.len(), 1, "先端 1 件を超えて走査している");
        assert_eq!(visited[0].hash, chain.last().unwrap().hash);

        // 先端に並んだら 1 件も返らない。
        let tip_work = chain.last().unwrap().cumulative_work;
        assert_eq!(index.candidates_above(tip_work).count(), 0);
    }

    #[test]
    fn candidates_come_back_most_work_first() {
        let (mut index, chain) = a_chain(3);
        // 同じ親から 2 本、作業量を変えて伸ばす。
        let parent = &chain[2];
        let heavy = entry_at(
            parent.hash,
            3,
            900,
            parent.cumulative_work + 5,
            BlockStatus::HeaderValid,
        );
        let light = entry_at(
            parent.hash,
            3,
            901,
            parent.cumulative_work + 2,
            BlockStatus::HeaderValid,
        );
        index.insert(heavy.clone());
        index.insert(light.clone());

        let order: Vec<Hash> = index
            .candidates_above(parent.cumulative_work)
            .map(|e| e.hash)
            .collect();
        assert_eq!(order[0], heavy.hash, "作業量の多いほうが先に来ていない");
        assert!(order.contains(&light.hash));
    }

    #[test]
    fn equal_work_is_broken_by_the_smaller_hash() {
        // 同点の順序が揺らぐと、同じ作業量のチェーンが 2 本届いたときに
        // ノードごとに違う先端を選ぶ。
        let (mut index, chain) = a_chain(2);
        let parent = &chain[1];
        let work = parent.cumulative_work + 7;
        let a = entry_at(parent.hash, 2, 500, work, BlockStatus::HeaderValid);
        let b = entry_at(parent.hash, 2, 501, work, BlockStatus::HeaderValid);
        index.insert(a.clone());
        index.insert(b.clone());

        let first = index
            .candidates_above(parent.cumulative_work)
            .next()
            .unwrap()
            .hash;
        let expected = if a.hash < b.hash { a.hash } else { b.hash };
        assert_eq!(first, expected, "同点でハッシュの小さいほうを選んでいない");
        assert_eq!(index.best_header().unwrap().hash, expected);
    }

    #[test]
    fn a_header_only_entry_is_a_header_but_not_a_candidate() {
        let (mut index, chain) = a_chain(2);
        let parent = chain.last().unwrap();
        let pending = entry_at(
            parent.hash,
            2,
            77,
            parent.cumulative_work + 1,
            BlockStatus::HeaderOnly,
        );
        index.insert(pending.clone());

        assert_eq!(
            index.best_header().unwrap().hash,
            pending.hash,
            "本体が無くても最良ヘッダにはなる"
        );
        assert_eq!(
            index.candidates_above(parent.cumulative_work).count(),
            0,
            "本体が無いのに先端の候補になっている"
        );
    }

    #[test]
    fn a_body_arriving_later_turns_a_header_into_a_candidate() {
        let (mut index, chain) = a_chain(2);
        let parent = chain.last().unwrap();
        let mut entry = entry_at(
            parent.hash,
            2,
            77,
            parent.cumulative_work + 1,
            BlockStatus::HeaderOnly,
        );
        index.insert(entry.clone());
        assert_eq!(index.candidates_above(parent.cumulative_work).count(), 0);

        // 本体が届いた。同じハッシュで入れ直す。
        entry.status = BlockStatus::HeaderValid;
        index.insert(entry.clone());
        assert_eq!(index.candidates_above(parent.cumulative_work).count(), 1);

        // 親子関係が二重に登録されていないこと。
        assert_eq!(index.children_of(&parent.hash), &[entry.hash]);
    }

    #[test]
    fn an_invalid_entry_leaves_both_sets() {
        let (mut index, chain) = a_chain(5);
        let tip = chain.last().unwrap();
        let before = chain[chain.len() - 2].cumulative_work;
        assert_eq!(index.candidates_above(before).count(), 1);

        index.set_status(&tip.hash, BlockStatus::Invalid);
        assert_eq!(
            index.candidates_above(before).count(),
            0,
            "無効なのに候補に残っている"
        );
        assert_eq!(
            index.best_header().unwrap().hash,
            chain[chain.len() - 2].hash,
            "最良ヘッダが 1 つ前に戻っていない"
        );
    }

    #[test]
    fn children_are_found_without_scanning() {
        let (mut index, chain) = a_chain(3);
        let parent = &chain[1];
        let fork = entry_at(
            parent.hash,
            2,
            333,
            parent.cumulative_work + 1,
            BlockStatus::HeaderValid,
        );
        index.insert(fork.clone());

        let mut children = index.children_of(&parent.hash).to_vec();
        children.sort_unstable();
        let mut expected = vec![chain[2].hash, fork.hash];
        expected.sort_unstable();
        assert_eq!(children, expected);

        // ジェネシスは親を持たない。0 のハッシュに子を登録しない。
        assert!(index.children_of(&Hash::ZERO).is_empty());
        // 先端には子がいない。
        assert!(index.children_of(&chain[3].hash).is_empty());
    }

    #[test]
    fn setting_the_status_of_an_unknown_hash_does_nothing() {
        let (mut index, _) = a_chain(1);
        assert!(index
            .set_status(&hash::block_hash(b"knowhere"), BlockStatus::Invalid)
            .is_none());
        assert_eq!(index.len(), 2);
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
