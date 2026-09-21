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
/// # 何を持ち、何を持たないか
///
/// **ブロックの実体は持たない。正本は記憶域である。** ここが覚えている
/// のは「先端の候補」だけであり、その件数は鎖の長さではなく**競合する枝の
/// 数**で決まる。分岐が無ければ 1 本ぶんである。
///
/// ブロックを 1 個受け取るたびに知りたいことは 2 つある。
///
/// 1. 先端の候補 — 本体を持ち、現先端より作業量の多いもの
/// 2. 最良ヘッダ — 本体の有無を問わず、最も作業量の多いもの
///
/// どちらも全件を走査すれば求まる。**しかしブロック 1 個あたり O(n) は、
/// 初期同期の全体では O(n²) になる。** 10 万ブロックで 10^10 回の比較
/// であり、公開できる速さではない。そこで作業量順の集合を漸進的に保ち、
/// 末尾だけを見る (O(log n))。Bitcoin の `setBlockIndexCandidates` と
/// `pindexBestHeader` に相当する。
///
/// 先端を下回ったものは [`prune_below`](Self::prune_below) で落とす。
/// 落とさないと、ここが高さに比例して伸びる (`docs/SPEC.md` §19)。
///
/// # ここに無いもの
///
/// - **ブロックの実体** — 記憶域が持つ
///   ([`ChainStore::index_entry`](crate::store::ChainStore::index_entry))。
///   手元の控えは [`Chain`](crate::chain::Chain) が上限つきで抱える
/// - **親から子への写像** — 無効の印を子孫へ広げるときにしか要らない。
///   記憶域が持つ
///   ([`ChainStore::children_of`](crate::store::ChainStore::children_of))
#[derive(Debug, Default)]
pub struct BlockIndex {
    /// 本体を持つもの。先端の候補になりうる。
    with_body: std::collections::BTreeSet<WorkKey>,
    /// 無効と判定されていないもの。本体の有無は問わない。
    valid_headers: std::collections::BTreeSet<WorkKey>,
}

impl BlockIndex {
    /// 空のインデックス。
    pub fn new() -> BlockIndex {
        BlockIndex::default()
    }

    /// 1 件ぶんの所属を書き直す。
    ///
    /// 登録にも状態の変更にも、これ 1 つを通す。作業量は同じハッシュに
    /// 対して不変である (親の作業量 + そのブロックの難易度であり、どちらも
    /// ヘッダから決まる) ため、鍵が入れ替わることはない。変わるのは
    /// **どちらの集合に入るか**だけである。
    pub fn record(&mut self, entry: &BlockIndexEntry) {
        let key = WorkKey {
            work: entry.cumulative_work,
            hash: entry.hash,
        };
        if entry.has_body() {
            self.with_body.insert(key);
        } else {
            self.with_body.remove(&key);
        }
        if entry.is_valid_header() {
            self.valid_headers.insert(key);
        } else {
            self.valid_headers.remove(&key);
        }
    }

    /// 先端の作業量を下回る候補を捨てる。捨てた件数を返す。
    ///
    /// # なぜ捨ててよいか
    ///
    /// [`candidates_above`](Self::candidates_above) に渡される作業量は、
    /// 常に**アクティブチェーンの先端のもの**である。そして先端の作業量は
    /// 決して減らない — 切り替える相手は厳密に上回る枝だけだからである
    /// (`docs/SPEC.md` §10.6)。したがって、いま先端を下回るものが
    /// **この先もう一度候補になることはない。**
    ///
    /// [`best_header`](Self::best_header) も同じである。アクティブチェーンの
    /// 先端は常に有効なヘッダとして入っているので、最大値が先端の作業量を
    /// 下回ることはない。下回るものを持っていても、返り値は変わらない。
    ///
    /// # なぜ必要か
    ///
    /// 捨てないと、この 2 つの集合はブロック 1 個につき 48 バイトの鍵を
    /// 2 つ、**永久に積み続ける**。60 秒間隔では年 52 万ブロック積まれる
    /// ので、常駐量が高さに比例して伸びる (`docs/SPEC.md` §19)。
    ///
    /// 捨てたあとに残るのは、先端と、先端を上回る競合する枝だけである。
    /// 分岐が無ければ **1 件**になる。
    pub fn prune_below(&mut self, work: u128) -> usize {
        // 同じ作業量の中では、ハッシュが大きいものほど「小さい」鍵になる
        // (`WorkKey` の `Ord` はハッシュだけ逆順である)。したがって
        // ハッシュを全ビット 1 にした鍵が、その作業量の**最小**である。
        // ここで切れば、作業量がちょうど `work` のものは残る。
        let floor = WorkKey {
            work,
            hash: Hash::from_bytes([0xff; 32]),
        };
        let before = self.with_body.len() + self.valid_headers.len();
        self.with_body = self.with_body.split_off(&floor);
        self.valid_headers = self.valid_headers.split_off(&floor);
        before - (self.with_body.len() + self.valid_headers.len())
    }

    /// 先端の候補として覚えている件数。
    ///
    /// 常駐量が高さに比例していないことを確かめるために公開している。
    pub fn tip_candidates(&self) -> usize {
        self.with_body.len() + self.valid_headers.len()
    }

    /// 本体を持ち、作業量が `work` を超えるもののハッシュを**多い順に**返す。
    ///
    /// 先端の候補である。走るのは条件を満たす件数だけであり、全件では
    /// ない。先端を 1 個伸ばしただけなら 1 件で止まる。
    pub fn candidates_above(&self, work: u128) -> impl Iterator<Item = Hash> + '_ {
        self.with_body
            .iter()
            .rev()
            .take_while(move |key| key.work > work)
            .map(|key| key.hash)
    }

    /// 最も作業量の多い、無効でないヘッダのハッシュ。
    pub fn best_header(&self) -> Option<Hash> {
        self.valid_headers.iter().next_back().map(|key| key.hash)
    }
}

/// インデックスの 1 件を、上限つきで手元に控える器。
///
/// **正本ではない。** ここに無いことは「そのブロックを知らない」を意味
/// しない。引けなかったときは記憶域に聞き直すこと。この 2 つを混同すると、
/// 正しいブロックを「知らない」と扱って静かにチェーンから外れる。
///
/// 入れた順に落とす。新しいブロックを検証するときに触るのは、難易度の窓
/// (90) と Median Time Past (11)、シードを引くときの祖先 (最大 2112) で
/// あり、いずれも**先端の近く**である。古いものから落として困らない。
#[derive(Debug)]
pub struct EntryCache {
    entries: std::collections::HashMap<Hash, BlockIndexEntry>,
    /// 入れた順。**同じハッシュは 1 度しか入らない。**
    order: std::collections::VecDeque<Hash>,
    limit: usize,
}

impl EntryCache {
    /// 上限を決めて作る。
    pub fn new(limit: usize) -> EntryCache {
        EntryCache {
            entries: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
            limit: limit.max(1),
        }
    }

    /// 控えを引く。
    pub fn get(&self, hash: &Hash) -> Option<&BlockIndexEntry> {
        self.entries.get(hash)
    }

    /// 控える。すでにあれば中身だけ入れ替える (順番は動かさない)。
    pub fn put(&mut self, entry: BlockIndexEntry) {
        let hash = entry.hash;
        if self.entries.insert(hash, entry).is_none() {
            self.order.push_back(hash);
        }
        while self.order.len() > self.limit {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
    }

    /// 控えている件数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 1 件も控えていないか。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
        index.record(&genesis);
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
            index.record(&entry);
            chain.push(entry);
        }
        (index, chain)
    }

    #[test]
    fn the_best_header_is_the_one_with_the_most_work() {
        let (index, chain) = a_chain(20);
        assert_eq!(index.best_header().unwrap(), chain.last().unwrap().hash);
    }

    #[test]
    fn only_candidates_above_the_given_work_are_visited() {
        // **これが O(n²) を避ける根拠である。** 先端を 1 個伸ばしただけ
        // なら、走るのは 1 件でなければならない。全件を舐めていたら、
        // ここが 100 件になる。
        let (index, chain) = a_chain(100);
        let tip_work = chain[chain.len() - 2].cumulative_work;
        let visited: Vec<_> = index.candidates_above(tip_work).collect();
        assert_eq!(visited.len(), 1, "scanned beyond the single tip");
        assert_eq!(visited[0], chain.last().unwrap().hash);

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
        index.record(&heavy);
        index.record(&light);

        let order: Vec<Hash> = index.candidates_above(parent.cumulative_work).collect();
        assert_eq!(
            order[0], heavy.hash,
            "the one with more work did not come first"
        );
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
        index.record(&a);
        index.record(&b);

        let first = index
            .candidates_above(parent.cumulative_work)
            .next()
            .unwrap();
        let expected = if a.hash < b.hash { a.hash } else { b.hash };
        assert_eq!(first, expected, "on a tie, the smaller hash was not chosen");
        assert_eq!(index.best_header().unwrap(), expected);
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
        index.record(&pending);

        assert_eq!(
            index.best_header().unwrap(),
            pending.hash,
            "it can be the best header even without a body"
        );
        assert_eq!(
            index.candidates_above(parent.cumulative_work).count(),
            0,
            "it is a tip candidate although it has no body"
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
        index.record(&entry);
        assert_eq!(index.candidates_above(parent.cumulative_work).count(), 0);

        // 本体が届いた。同じハッシュで書き直す。
        entry.status = BlockStatus::HeaderValid;
        index.record(&entry);
        assert_eq!(index.candidates_above(parent.cumulative_work).count(), 1);
    }

    #[test]
    fn an_invalid_entry_leaves_both_sets() {
        let (mut index, chain) = a_chain(5);
        let tip = chain.last().unwrap();
        let before = chain[chain.len() - 2].cumulative_work;
        assert_eq!(index.candidates_above(before).count(), 1);

        let mut invalid = tip.clone();
        invalid.status = BlockStatus::Invalid;
        index.record(&invalid);
        assert_eq!(
            index.candidates_above(before).count(),
            0,
            "it is still a candidate although it is invalid"
        );
        assert_eq!(
            index.best_header().unwrap(),
            chain[chain.len() - 2].hash,
            "the best header did not fall back by one"
        );
    }

    // ━━━━━━━━ 控え ━━━━━━━━

    #[test]
    fn the_cache_stops_growing_at_its_limit() {
        let mut cache = EntryCache::new(8);
        let (_, chain) = a_chain(100);
        for entry in &chain {
            cache.put(entry.clone());
            assert!(cache.len() <= 8, "holding more than the limit");
        }
        assert_eq!(cache.len(), 8);

        // 残っているのは新しいほうである。
        assert!(cache.get(&chain[100].hash).is_some());
        assert!(cache.get(&chain[0].hash).is_none());
    }

    #[test]
    fn putting_the_same_hash_twice_does_not_take_two_slots() {
        let mut cache = EntryCache::new(4);
        let (_, chain) = a_chain(1);
        let mut entry = chain[1].clone();
        for _ in 0..10 {
            entry.status = BlockStatus::Invalid;
            cache.put(entry.clone());
        }
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&entry.hash).unwrap().status, BlockStatus::Invalid);
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
