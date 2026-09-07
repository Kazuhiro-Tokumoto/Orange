//! チェーン状態。
//!
//! ブロックを受け取り、最良チェーンを選び、必要ならリオーグする。
//!
//! # 最良チェーンの選び方
//!
//! **累積作業量 (各ブロックの難易度の総和) が最大**のチェーンを採用する。
//! ブロック数ではない (SPEC §10.5)。
//!
//! # 二段階の検証
//!
//! ブロックの本体を検証するには、そのブロックの位置における UTXO の状態が
//! 必要である。サイドチェーンのブロックはまだ繋がっていないため、その状態を
//! 用意できない。したがって検証を二段階に分ける。
//!
//! 1. **受け取り時** — ヘッダと PoW を検証する。UTXO を必要としない
//! 2. **接続時** — 本体を検証する。ここで初めて UTXO の状態が定まる
//!
//! この構造の帰結として、**リオーグの途中でブロックが無効と判明することが
//! ありうる**。その場合は元のチェーンに戻したうえで、そのブロックとその子孫を
//! 無効として印を付け、次の候補を試す。

use crate::index::{BlockIndexEntry, BlockStatus};
use oag_consensus::params;
use oag_consensus::utxo::{UndoBlock, UtxoError, UtxoSet};
use oag_consensus::validate::{
    median_time_past, validate_block, validate_header, BlockContext, HeaderContext, PowVerifier,
    ValidationError,
};
use oag_consensus::Block;
use oag_pow::lwma::{self, LwmaError};
use oag_primitives::Hash;
use std::collections::HashMap;

/// ブロックを受け取った結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// すでに知っているブロックだった。
    Duplicate,
    /// アクティブチェーンの先端を 1 つ伸ばした。
    ExtendedTip,
    /// より作業量の多いチェーンへ切り替えた。
    Reorganized(Reorg),
    /// 有効だが、まだ最良ではない。
    SideChain,
}

/// リオーグの内容。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reorg {
    /// 取り消したブロック (先端に近い順)。
    pub disconnected: Vec<Hash>,
    /// 接続したブロック (古い順)。
    pub connected: Vec<Hash>,
}

impl Reorg {
    /// リオーグの深さ。取り消したブロック数。
    pub fn depth(&self) -> usize {
        self.disconnected.len()
    }
}

/// チェーン操作の失敗。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// 親ブロックを知らない。
    #[error("親ブロック {0} を知らない")]
    UnknownParent(Hash),
    /// 親ブロックが無効と判明している。
    #[error("親ブロック {0} が無効である")]
    InvalidAncestor(Hash),
    /// ブロックが大きすぎる。
    #[error("ブロックサイズ {actual} が上限 {max} を超えている")]
    BlockTooLarge {
        /// 実際のサイズ。
        actual: usize,
        /// 上限。
        max: usize,
    },
    /// ジェネシスブロックが不正。
    #[error("ジェネシスブロックが不正: {0}")]
    BadGenesis(&'static str),
    /// 本体を保持していない。
    #[error("ブロック {0} の本体を保持していない")]
    MissingBlockBody(Hash),
    /// 検証に失敗した。
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// UTXO セットの操作に失敗した。
    #[error(transparent)]
    Utxo(#[from] UtxoError),
    /// 難易度調整に失敗した。
    #[error(transparent)]
    Lwma(#[from] LwmaError),
}

/// 接続に失敗したブロックと、その理由。
///
/// リオーグの途中で失敗したとき、**無効なのは切り替え先のブロックではなく、
/// 実際に検証に失敗したブロック**である。切り替え先はその子孫であるために
/// 巻き添えで無効になるにすぎない。どちらに印を付けるかを取り違えると、
/// 無効な祖先を持つブロックが有効なまま残る。
struct ConnectFailure {
    hash: Hash,
    error: ChainError,
}

/// チェーンの状態。
///
/// 本実装はすべてメモリ上に保持する。永続化は後のフェーズで行う。
pub struct Chain {
    index: HashMap<Hash, BlockIndexEntry>,
    pub(crate) bodies: HashMap<Hash, Block>,
    undo: HashMap<Hash, UndoBlock>,
    /// アクティブチェーン。添字が高さに対応する。
    active: Vec<Hash>,
    utxo: UtxoSet,
    genesis_difficulty: u64,
}

impl Chain {
    /// ジェネシスブロックからチェーンを作る。
    ///
    /// ジェネシスは PoW を検証しない。チェーンの定義そのものであるため。
    pub fn new(genesis: Block, genesis_difficulty: u64) -> Result<Chain, ChainError> {
        let header = &genesis.header;
        if header.height != 0 {
            return Err(ChainError::BadGenesis("高さが 0 でない"));
        }
        if header.prev_hash != Hash::ZERO {
            return Err(ChainError::BadGenesis("prev_hash が 0 でない"));
        }
        if header.difficulty != genesis_difficulty {
            return Err(ChainError::BadGenesis("難易度が指定と一致しない"));
        }
        if genesis.coinbase().is_none() {
            return Err(ChainError::BadGenesis("コインベースがない"));
        }
        if !genesis.merkle_root_is_valid() {
            return Err(ChainError::BadGenesis("マークルルートが一致しない"));
        }
        if genesis.size() > params::MAX_BLOCK_SIZE {
            return Err(ChainError::BadGenesis("大きすぎる"));
        }

        let hash = header.hash();
        let mut utxo = UtxoSet::new();
        let undo = utxo.apply_block(&genesis.transactions, 0)?;

        let mut chain = Chain {
            index: HashMap::new(),
            bodies: HashMap::new(),
            undo: HashMap::new(),
            active: vec![hash],
            utxo,
            genesis_difficulty,
        };
        chain.index.insert(
            hash,
            BlockIndexEntry {
                hash,
                header: *header,
                cumulative_work: u128::from(header.difficulty),
                status: BlockStatus::FullyValid,
            },
        );
        chain.undo.insert(hash, undo);
        chain.bodies.insert(hash, genesis);
        Ok(chain)
    }

    /// アクティブチェーンの先端。
    pub fn tip(&self) -> &BlockIndexEntry {
        let hash = self.active.last().expect("ジェネシスは常に存在する");
        &self.index[hash]
    }

    /// 先端の高さ。
    pub fn height(&self) -> u64 {
        self.tip().height()
    }

    /// 現在の UTXO セット。
    pub fn utxo(&self) -> &UtxoSet {
        &self.utxo
    }

    /// インデックスに登録されているブロック数。
    pub fn indexed_blocks(&self) -> usize {
        self.index.len()
    }

    /// このハッシュのブロックを知っているか。
    pub fn contains(&self, hash: &Hash) -> bool {
        self.index.contains_key(hash)
    }

    /// インデックスの 1 件を引く。
    pub fn entry(&self, hash: &Hash) -> Option<&BlockIndexEntry> {
        self.index.get(hash)
    }

    /// アクティブチェーンの指定した高さのブロックハッシュ。
    pub fn hash_at_height(&self, height: u64) -> Option<Hash> {
        self.active.get(usize::try_from(height).ok()?).copied()
    }

    /// そのハッシュがアクティブチェーン上にあるか。
    fn is_active(&self, hash: &Hash) -> bool {
        self.index
            .get(hash)
            .and_then(|e| self.hash_at_height(e.height()))
            .is_some_and(|h| h == *hash)
    }

    /// `from` から親をたどって最大 `count` 件のヘッダを新しい順に集める。
    fn ancestors(&self, from: &Hash, count: usize) -> Vec<&BlockIndexEntry> {
        let mut out = Vec::with_capacity(count);
        let mut cursor = *from;
        while out.len() < count {
            let Some(entry) = self.index.get(&cursor) else {
                break;
            };
            out.push(entry);
            if entry.height() == 0 {
                break;
            }
            cursor = entry.prev_hash();
        }
        out
    }

    /// `parent` を親とするブロックの Median Time Past。
    pub fn median_time_past_for_child_of(&self, parent: &Hash) -> i64 {
        let mut timestamps: Vec<i64> = self
            .ancestors(parent, params::MEDIAN_TIME_SPAN)
            .iter()
            .map(|e| e.header.timestamp)
            .collect();
        timestamps.reverse();
        median_time_past(&timestamps).unwrap_or(i64::MIN)
    }

    /// `parent` を親とするブロックが取るべき難易度。
    pub fn expected_difficulty_for_child_of(&self, parent: &Hash) -> Result<u64, ChainError> {
        let parent_entry = self
            .index
            .get(parent)
            .ok_or(ChainError::UnknownParent(*parent))?;
        let height = parent_entry.height() + 1;

        // 履歴が窓幅に満たない間はジェネシス難易度を用いる (SPEC §12.3)。
        if height < lwma::WINDOW as u64 + 1 {
            return Ok(self.genesis_difficulty);
        }

        // 親を含む WINDOW + 1 件の祖先を古い順に並べる。
        let mut chain = self.ancestors(parent, lwma::WINDOW + 1);
        chain.reverse();
        debug_assert_eq!(chain.len(), lwma::WINDOW + 1);

        let timestamps: Vec<i64> = chain.iter().map(|e| e.header.timestamp).collect();
        let difficulties: Vec<u64> = chain[1..].iter().map(|e| e.header.difficulty).collect();
        Ok(lwma::next_difficulty(&timestamps, &difficulties)?)
    }

    /// ブロックを受け取る。
    ///
    /// ヘッダと PoW を検証してインデックスへ登録し、その結果として最良の
    /// チェーンが変わるなら接続またはリオーグを行う。
    pub fn accept_block(
        &mut self,
        block: Block,
        pow: &dyn PowVerifier,
        now: i64,
    ) -> Result<AcceptOutcome, ChainError> {
        let hash = block.header.hash();
        if self.index.contains_key(&hash) {
            return Ok(AcceptOutcome::Duplicate);
        }

        // 最も安価な検査から行う (SPEC §10.4)。
        let size = block.size();
        if size > params::MAX_BLOCK_SIZE {
            return Err(ChainError::BlockTooLarge {
                actual: size,
                max: params::MAX_BLOCK_SIZE,
            });
        }

        let parent_hash = block.header.prev_hash;
        let parent = self
            .index
            .get(&parent_hash)
            .ok_or(ChainError::UnknownParent(parent_hash))?;
        if parent.status == BlockStatus::Invalid {
            return Err(ChainError::InvalidAncestor(parent_hash));
        }
        let parent_work = parent.cumulative_work;
        let expected_height = parent.height() + 1;

        let ctx = HeaderContext {
            expected_height,
            expected_prev_hash: parent_hash,
            median_time_past: self.median_time_past_for_child_of(&parent_hash),
            expected_difficulty: self.expected_difficulty_for_child_of(&parent_hash)?,
            now,
        };
        validate_header(&block.header, &ctx, pow)?;

        self.index.insert(
            hash,
            BlockIndexEntry {
                hash,
                header: block.header,
                cumulative_work: parent_work + u128::from(block.header.difficulty),
                status: BlockStatus::HeaderValid,
            },
        );
        self.bodies.insert(hash, block);

        self.activate_best_chain(pow, now)
    }

    /// 最良のチェーンへ切り替える。
    fn activate_best_chain(
        &mut self,
        pow: &dyn PowVerifier,
        now: i64,
    ) -> Result<AcceptOutcome, ChainError> {
        loop {
            let tip = self.tip().hash;
            let tip_work = self.index[&tip].cumulative_work;

            // 候補は「無効でなく、本体を保持しており、先端より作業量が多い」もの。
            // 同点なら先に見たものを保つ (最初に受け取ったチェーンを優先する)。
            let best = self
                .index
                .values()
                .filter(|e| e.is_candidate() && self.bodies.contains_key(&e.hash))
                .filter(|e| e.cumulative_work > tip_work)
                .max_by(|a, b| {
                    a.cumulative_work
                        .cmp(&b.cumulative_work)
                        .then_with(|| b.hash.as_bytes().cmp(a.hash.as_bytes()))
                })
                .map(|e| e.hash);

            let Some(target) = best else {
                return Ok(AcceptOutcome::SideChain);
            };

            match self.switch_to(target, pow, now) {
                Ok(reorg) if reorg.disconnected.is_empty() && reorg.connected.len() == 1 => {
                    return Ok(AcceptOutcome::ExtendedTip);
                }
                Ok(reorg) => return Ok(AcceptOutcome::Reorganized(reorg)),
                Err(ConnectFailure {
                    hash,
                    error: ChainError::Validation(_),
                }) => {
                    // 実際に失敗したブロックとその子孫に印を付け、次の候補を試す。
                    self.mark_invalid(&hash);
                    continue;
                }
                Err(ConnectFailure { error, .. }) => return Err(error),
            }
        }
    }

    /// `target` をアクティブチェーンの先端にする。
    fn switch_to(
        &mut self,
        target: Hash,
        pow: &dyn PowVerifier,
        now: i64,
    ) -> Result<Reorg, ConnectFailure> {
        // target からアクティブチェーンに合流するまで遡る。
        let mut to_connect = Vec::new();
        let mut cursor = target;
        while !self.is_active(&cursor) {
            to_connect.push(cursor);
            let Some(entry) = self.index.get(&cursor) else {
                return Err(ConnectFailure {
                    hash: cursor,
                    error: ChainError::UnknownParent(cursor),
                });
            };
            if entry.height() == 0 {
                break;
            }
            cursor = entry.prev_hash();
        }
        to_connect.reverse();
        let fork_point = cursor;

        let fork_height = self.index[&fork_point].height();
        let needs_rollback = self.height() > fork_height;

        // 単純な先端の伸長でない場合のみ、巻き戻しに備えて状態を控える。
        // アクティブチェーンの伸長は最も頻繁に起きるため、そこでは複製しない。
        let snapshot = needs_rollback.then(|| (self.active.clone(), self.utxo.clone()));

        let mut disconnected = Vec::new();
        while self.height() > fork_height {
            let hash = self.disconnect_tip().map_err(|error| ConnectFailure {
                hash: target,
                error,
            })?;
            disconnected.push(hash);
        }

        let mut connected = Vec::new();
        for hash in &to_connect {
            match self.connect_block(*hash, pow, now) {
                Ok(()) => connected.push(*hash),
                Err(error) => {
                    // 元のチェーンに戻す。
                    if let Some((active, utxo)) = snapshot {
                        self.active = active;
                        self.utxo = utxo;
                    } else {
                        // 伸長だったので、接続したものを戻すだけでよい。
                        for _ in 0..connected.len() {
                            let _ = self.disconnect_tip();
                        }
                    }
                    // 途中まで接続した分の巻き戻し情報は残さない。
                    for applied in &connected {
                        self.undo.remove(applied);
                    }
                    return Err(ConnectFailure { hash: *hash, error });
                }
            }
        }

        Ok(Reorg {
            disconnected,
            connected,
        })
    }

    /// 先端のブロックを 1 つ取り消す。
    fn disconnect_tip(&mut self) -> Result<Hash, ChainError> {
        let hash = *self.active.last().expect("ジェネシスは取り消せない");
        let undo = self
            .undo
            .get(&hash)
            .ok_or(ChainError::MissingBlockBody(hash))?;
        self.utxo.undo_block(undo)?;
        self.active.pop();
        Ok(hash)
    }

    /// ブロックを 1 つ接続する。本体の検証はここで行う。
    fn connect_block(
        &mut self,
        hash: Hash,
        pow: &dyn PowVerifier,
        now: i64,
    ) -> Result<(), ChainError> {
        let block = self
            .bodies
            .get(&hash)
            .ok_or(ChainError::MissingBlockBody(hash))?
            .clone();
        let parent_hash = block.header.prev_hash;

        let ctx = BlockContext {
            header: HeaderContext {
                expected_height: self.index[&parent_hash].height() + 1,
                expected_prev_hash: parent_hash,
                median_time_past: self.median_time_past_for_child_of(&parent_hash),
                expected_difficulty: self.expected_difficulty_for_child_of(&parent_hash)?,
                now,
            },
            utxo: &self.utxo,
        };
        validate_block(&block, &ctx, pow)?;

        let undo = self
            .utxo
            .apply_block(&block.transactions, block.header.height)?;
        self.undo.insert(hash, undo);
        self.active.push(hash);
        if let Some(entry) = self.index.get_mut(&hash) {
            entry.status = BlockStatus::FullyValid;
        }
        Ok(())
    }

    /// ブロックとその子孫すべてに無効の印を付ける。
    fn mark_invalid(&mut self, hash: &Hash) {
        let mut frontier = vec![*hash];
        while let Some(current) = frontier.pop() {
            if let Some(entry) = self.index.get_mut(&current) {
                if entry.status == BlockStatus::Invalid {
                    continue;
                }
                entry.status = BlockStatus::Invalid;
            }
            let children: Vec<Hash> = self
                .index
                .values()
                .filter(|e| e.prev_hash() == current && e.height() != 0)
                .map(|e| e.hash)
                .collect();
            frontier.extend(children);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::GenesisSpec;
    use oag_consensus::lock::Lock;
    use oag_consensus::tx::{encode_coinbase_signature, OutPoint, TxInput, CURRENT_TX_VERSION};
    use oag_consensus::utxo::UtxoView;
    use oag_consensus::validate::AcceptAnyPow;
    use oag_consensus::{BlockHeader, Transaction, TxOutput};
    use oag_primitives::{merkle, Amount, Network, SecretKey};

    const NOW: i64 = 3_000_000_000;
    const GENESIS_TIME: i64 = 1_800_000_000;
    const DIFFICULTY: u64 = 1;

    fn genesis() -> Block {
        GenesisSpec::without_reward(Network::Regtest, GENESIS_TIME, b"Orange regtest").build(0)
    }

    fn new_chain() -> Chain {
        Chain::new(genesis(), DIFFICULTY).expect("ジェネシスは有効")
    }

    /// `parent` の上に載る有効なブロックを組み立てる。
    ///
    /// `salt` を変えるとコインベースが変わり、同じ高さの別のブロックになる。
    fn build_on(chain: &Chain, parent: Hash, salt: u64) -> Block {
        let parent_entry = chain.entry(&parent).expect("親を知っている");
        let height = parent_entry.height() + 1;

        let mut input = TxInput::new(OutPoint::null());
        input.signature = encode_coinbase_signature(height, &salt.to_le_bytes());
        let coinbase = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: vec![TxOutput::new(
                oag_consensus::params::block_subsidy(height),
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            )],
            locktime: 0,
        };
        let merkle_root = merkle::merkle_root(&[coinbase.txid()]).unwrap();

        Block {
            header: BlockHeader {
                version: 0,
                prev_hash: parent,
                merkle_root,
                timestamp: GENESIS_TIME + height as i64 * 60,
                difficulty: chain
                    .expected_difficulty_for_child_of(&parent)
                    .expect("難易度を計算できる"),
                height,
                nonce: salt,
            },
            transactions: vec![coinbase],
        }
    }

    /// `parent` の上に `count` 個のブロックを積む。
    fn extend(chain: &mut Chain, mut parent: Hash, count: usize, salt: u64) -> Vec<Hash> {
        let mut hashes = Vec::with_capacity(count);
        for i in 0..count {
            let block = build_on(chain, parent, salt * 1_000_000 + i as u64);
            parent = block.header.hash();
            chain
                .accept_block(block, &AcceptAnyPow, NOW)
                .expect("有効なブロック");
            hashes.push(parent);
        }
        hashes
    }

    // ━━━━━━━━ ジェネシス ━━━━━━━━

    #[test]
    fn the_chain_starts_at_the_genesis() {
        let chain = new_chain();
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.tip().hash, genesis().header.hash());
        assert_eq!(chain.tip().cumulative_work, u128::from(DIFFICULTY));
        assert_eq!(chain.indexed_blocks(), 1);
    }

    #[test]
    fn a_malformed_genesis_is_rejected() {
        let mut bad = genesis();
        bad.header.height = 1;
        assert!(matches!(
            Chain::new(bad, DIFFICULTY),
            Err(ChainError::BadGenesis(_))
        ));

        let mut bad = genesis();
        bad.header.prev_hash = oag_primitives::hash::block_hash(b"x");
        assert!(matches!(
            Chain::new(bad, DIFFICULTY),
            Err(ChainError::BadGenesis(_))
        ));

        let mut bad = genesis();
        bad.header.merkle_root = Hash::ZERO;
        assert!(matches!(
            Chain::new(bad, DIFFICULTY),
            Err(ChainError::BadGenesis(_))
        ));
    }

    // ━━━━━━━━ 先端の伸長 ━━━━━━━━

    #[test]
    fn extending_the_tip() {
        let mut chain = new_chain();
        let block = build_on(&chain, chain.tip().hash, 1);
        let hash = block.header.hash();
        assert_eq!(
            chain.accept_block(block, &AcceptAnyPow, NOW).unwrap(),
            AcceptOutcome::ExtendedTip
        );
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.tip().hash, hash);
        assert_eq!(chain.hash_at_height(1), Some(hash));
    }

    #[test]
    fn the_same_block_twice_is_a_duplicate() {
        let mut chain = new_chain();
        let block = build_on(&chain, chain.tip().hash, 1);
        chain
            .accept_block(block.clone(), &AcceptAnyPow, NOW)
            .unwrap();
        assert_eq!(
            chain.accept_block(block, &AcceptAnyPow, NOW).unwrap(),
            AcceptOutcome::Duplicate
        );
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn an_orphan_is_rejected() {
        let mut chain = new_chain();
        let mut block = build_on(&chain, chain.tip().hash, 1);
        block.header.prev_hash = oag_primitives::hash::block_hash(b"unknown");
        assert!(matches!(
            chain.accept_block(block, &AcceptAnyPow, NOW),
            Err(ChainError::UnknownParent(_))
        ));
    }

    #[test]
    fn cumulative_work_accumulates() {
        let mut chain = new_chain();
        let tip = chain.tip().hash;
        extend(&mut chain, tip, 5, 1);
        assert_eq!(chain.height(), 5);
        assert_eq!(chain.tip().cumulative_work, u128::from(DIFFICULTY) * 6);
    }

    #[test]
    fn coinbase_outputs_enter_the_utxo_set() {
        let mut chain = new_chain();
        assert_eq!(chain.utxo().len(), 0, "ジェネシスは報酬を放棄している");
        let tip = chain.tip().hash;
        extend(&mut chain, tip, 3, 1);
        assert_eq!(chain.utxo().len(), 3);
    }

    // ━━━━━━━━ サイドチェーンとリオーグ ━━━━━━━━

    #[test]
    fn a_shorter_branch_stays_a_side_chain() {
        let mut chain = new_chain();
        let fork = chain.tip().hash;
        let main = extend(&mut chain, fork, 3, 1);

        // 分岐点から 1 ブロックだけ生やす。作業量は足りない。
        let side = build_on(&chain, fork, 999);
        assert_eq!(
            chain.accept_block(side, &AcceptAnyPow, NOW).unwrap(),
            AcceptOutcome::SideChain
        );
        assert_eq!(chain.tip().hash, *main.last().unwrap());
        assert_eq!(chain.height(), 3);
        assert_eq!(chain.indexed_blocks(), 5, "サイドチェーンも記録される");
    }

    #[test]
    fn a_heavier_branch_triggers_a_reorg() {
        let mut chain = new_chain();
        let fork = chain.tip().hash;
        let main = extend(&mut chain, fork, 3, 1);
        assert_eq!(chain.tip().hash, *main.last().unwrap());

        // 分岐点から 4 ブロック生やす。作業量が上回る。
        let mut parent = fork;
        let mut side = Vec::new();
        for i in 0..4 {
            let block = build_on(&chain, parent, 500 + i);
            parent = block.header.hash();
            side.push(parent);
            let outcome = chain.accept_block(block, &AcceptAnyPow, NOW).unwrap();
            if i < 2 {
                assert_eq!(outcome, AcceptOutcome::SideChain, "{i} 本目");
            } else if i == 2 {
                // 3 本目で並ぶが、同点では現先端を保つ。
                assert_eq!(outcome, AcceptOutcome::SideChain, "同点では切り替えない");
            } else {
                match outcome {
                    AcceptOutcome::Reorganized(reorg) => {
                        assert_eq!(reorg.depth(), 3, "3 ブロック取り消すはず");
                        assert_eq!(reorg.disconnected.len(), 3);
                        assert_eq!(reorg.connected.len(), 4);
                    }
                    other => panic!("リオーグしなかった: {other:?}"),
                }
            }
        }

        assert_eq!(chain.height(), 4);
        assert_eq!(chain.tip().hash, *side.last().unwrap());
        for (h, hash) in side.iter().enumerate() {
            assert_eq!(chain.hash_at_height(h as u64 + 1), Some(*hash));
        }
    }

    #[test]
    fn a_reorg_leaves_the_same_state_as_building_that_chain_directly() {
        // リオーグ後の状態が、そのチェーンを最初から積んだ場合と一致すること。
        // これが崩れると、リオーグを経験したノードだけが別の帳簿を持つ。
        let mut forked = new_chain();
        let fork = forked.tip().hash;
        extend(&mut forked, fork, 2, 1); // 捨てられる枝
        let mut parent = fork;
        let mut winner_blocks = Vec::new();
        for i in 0..5 {
            let block = build_on(&forked, parent, 700 + i);
            parent = block.header.hash();
            winner_blocks.push(block.clone());
            forked.accept_block(block, &AcceptAnyPow, NOW).unwrap();
        }

        // 同じ勝ち枝だけを最初から積んだチェーン。
        let mut direct = new_chain();
        for block in &winner_blocks {
            direct
                .accept_block(block.clone(), &AcceptAnyPow, NOW)
                .unwrap();
        }

        assert_eq!(forked.tip().hash, direct.tip().hash);
        assert_eq!(forked.height(), direct.height());
        assert_eq!(
            forked.utxo(),
            direct.utxo(),
            "リオーグ後の UTXO セットが直接構築したものと一致しない"
        );
    }

    #[test]
    fn disconnected_coinbase_outputs_leave_the_utxo_set() {
        let mut chain = new_chain();
        let fork = chain.tip().hash;
        let losing = extend(&mut chain, fork, 2, 1);

        // 捨てられる枝のコインベース出力を控える。
        let losing_outputs: Vec<OutPoint> = losing
            .iter()
            .map(|h| {
                let block = &chain.bodies[h];
                OutPoint::new(block.transactions[0].txid(), 0)
            })
            .collect();
        for out in &losing_outputs {
            assert!(chain.utxo().contains(out).unwrap(), "リオーグ前は存在する");
        }

        extend(&mut chain, fork, 3, 2);
        assert_eq!(chain.height(), 3);
        for out in &losing_outputs {
            assert!(
                !chain.utxo().contains(out).unwrap(),
                "取り消された枝のコインベース出力が残っている"
            );
        }
    }

    // ━━━━━━━━ リオーグ中に無効が判明する場合 ━━━━━━━━

    #[test]
    fn an_invalid_block_in_a_heavier_branch_does_not_break_the_chain() {
        let mut chain = new_chain();
        let fork = chain.tip().hash;
        let main = extend(&mut chain, fork, 2, 1);
        let good_tip = *main.last().unwrap();
        let good_utxo = chain.utxo().clone();

        // 作業量で上回る枝を作るが、2 本目のコインベースを過大にする。
        // ヘッダは正しいので受け取り時には通り、接続時に初めて弾かれる。
        let b1 = build_on(&chain, fork, 800);
        let b1_hash = b1.header.hash();
        chain.accept_block(b1, &AcceptAnyPow, NOW).unwrap();

        let mut b2 = build_on(&chain, b1_hash, 801);
        b2.transactions[0].outputs[0].amount = Amount::from_oag(1_000).unwrap();
        let txids = vec![b2.transactions[0].txid()];
        b2.header.merkle_root = merkle::merkle_root(&txids).unwrap();
        let b2_hash = b2.header.hash();
        chain.accept_block(b2, &AcceptAnyPow, NOW).unwrap();

        // ここまでは同点なのでまだ切り替わらない。3 本目で上回らせる。
        let b3 = build_on(&chain, b2_hash, 802);
        let b3_hash = b3.header.hash();
        let outcome = chain.accept_block(b3, &AcceptAnyPow, NOW).unwrap();

        // 無効が判明したので元のチェーンのままであること。
        assert_eq!(outcome, AcceptOutcome::SideChain);
        assert_eq!(chain.tip().hash, good_tip, "元の先端に戻っていない");
        assert_eq!(chain.height(), 2);
        assert_eq!(chain.utxo(), &good_utxo, "UTXO が元に戻っていない");

        // 実際に失敗した b2 とその子孫 b3 に印が付くこと。
        // b1 自体は正当なので無効にしてはならない。
        assert_eq!(
            chain.entry(&b1_hash).unwrap().status,
            BlockStatus::FullyValid,
            "巻き添えで無効にされている"
        );
        assert_eq!(chain.entry(&b2_hash).unwrap().status, BlockStatus::Invalid);
        assert_eq!(chain.entry(&b3_hash).unwrap().status, BlockStatus::Invalid);
    }

    #[test]
    fn children_of_an_invalid_block_are_rejected_on_arrival() {
        let mut chain = new_chain();
        let fork = chain.tip().hash;
        extend(&mut chain, fork, 3, 1);

        let b1 = build_on(&chain, fork, 900);
        let b1_hash = b1.header.hash();
        chain.accept_block(b1, &AcceptAnyPow, NOW).unwrap();

        let mut b2 = build_on(&chain, b1_hash, 901);
        b2.transactions[0].outputs[0].amount = Amount::from_oag(1_000).unwrap();
        b2.header.merkle_root = merkle::merkle_root(&[b2.transactions[0].txid()]).unwrap();
        let b2_hash = b2.header.hash();
        chain.accept_block(b2, &AcceptAnyPow, NOW).unwrap();

        let b3 = build_on(&chain, b2_hash, 902);
        let b3_hash = b3.header.hash();
        chain.accept_block(b3, &AcceptAnyPow, NOW).unwrap();
        let b4 = build_on(&chain, b3_hash, 903);
        chain.accept_block(b4, &AcceptAnyPow, NOW).unwrap();

        // b2 の子孫はすべて無効になっているので、さらに積もうとしても弾かれる。
        assert_eq!(chain.entry(&b2_hash).unwrap().status, BlockStatus::Invalid);
        let b5 = build_on(&chain, b3_hash, 904);
        assert!(matches!(
            chain.accept_block(b5, &AcceptAnyPow, NOW),
            Err(ChainError::InvalidAncestor(_))
        ));
    }

    // ━━━━━━━━ 難易度調整との連携 ━━━━━━━━

    #[test]
    fn the_difficulty_is_fixed_until_the_lwma_window_is_full() {
        let chain = new_chain();
        // SPEC §12.3: 高さが N + 1 に満たない間はジェネシス難易度。
        assert_eq!(
            chain
                .expected_difficulty_for_child_of(&chain.tip().hash)
                .unwrap(),
            DIFFICULTY
        );
    }

    #[test]
    fn the_lwma_takes_over_once_there_is_enough_history() {
        let mut chain = new_chain();
        let window = oag_pow::lwma::WINDOW as u64;
        let tip = chain.tip().hash;
        extend(&mut chain, tip, window as usize, 1);
        assert_eq!(chain.height(), window);

        // 高さ WINDOW + 1 のブロックから LWMA が効く。
        let next = chain
            .expected_difficulty_for_child_of(&chain.tip().hash)
            .unwrap();
        // ちょうど 60 秒間隔で積んだので、難易度は据え置かれる。
        assert_eq!(next, DIFFICULTY, "等間隔なら難易度は変わらない");
    }

    #[test]
    fn median_time_past_follows_the_chain() {
        let mut chain = new_chain();
        assert_eq!(
            chain.median_time_past_for_child_of(&chain.tip().hash),
            GENESIS_TIME
        );
        let tip = chain.tip().hash;
        extend(&mut chain, tip, 20, 1);
        // 直近 11 ブロック (高さ 10〜20) の中央値は高さ 15 のもの。
        assert_eq!(
            chain.median_time_past_for_child_of(&chain.tip().hash),
            GENESIS_TIME + 15 * 60
        );
    }

    // ━━━━━━━━ 深いリオーグ ━━━━━━━━

    #[test]
    fn a_deep_reorg_restores_a_consistent_state() {
        let mut chain = new_chain();
        let fork = chain.tip().hash;
        extend(&mut chain, fork, 30, 1);
        assert_eq!(chain.height(), 30);

        let mut parent = fork;
        let mut winner = Vec::new();
        for i in 0..31 {
            let block = build_on(&chain, parent, 2_000 + i);
            parent = block.header.hash();
            winner.push(block.clone());
            chain.accept_block(block, &AcceptAnyPow, NOW).unwrap();
        }

        assert_eq!(chain.height(), 31);
        assert_eq!(chain.tip().hash, parent);
        assert_eq!(chain.utxo().len(), 31, "勝ち枝のコインベースのみ");

        let mut direct = new_chain();
        for block in &winner {
            direct
                .accept_block(block.clone(), &AcceptAnyPow, NOW)
                .unwrap();
        }
        assert_eq!(chain.utxo(), direct.utxo());
    }
}
