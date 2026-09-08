//! チェーン状態。
//!
//! ブロックを受け取り、最良チェーンを選び、必要ならリオーグする。
//!
//! # 最良チェーンの選び方
//!
//! **累積作業量 (各ブロックの難易度の総和) が最大**のチェーンを採用する。
//! ブロック数ではない (SPEC §10.6)。同点の場合は現在の先端を保つ。
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
//!
//! # 記憶域との関係
//!
//! アクティブチェーンと UTXO セットの実体は [`ChainStore`] が持つ。
//! `Chain` が保持するのはブロックインデックスだけであり、これは祖先を
//! たどる操作を高速にするための写しである。**先端や高さを二重に持つことは
//! しない**。二重に持つと、誤りの経路で食い違いうる。

use crate::index::{BlockIndexEntry, BlockStatus};
use crate::store::ChainStore;
use oag_consensus::params;
use oag_consensus::validate::{
    median_time_past, validate_block, validate_header, BlockContext, HeaderContext, PowVerifier,
    ValidationError,
};
use oag_consensus::{Block, BlockHeader};
use oag_pow::lwma::{self, LwmaError};
use oag_primitives::Hash;
use std::collections::HashMap;

/// ヘッダを受け取った結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderOutcome {
    /// 初めて見るヘッダで、インデックスに加えた。
    New,
    /// すでに知っていた。
    Known,
}

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
    /// 記憶域に入っているジェネシスが指定と食い違う。
    #[error("記憶域のジェネシスが指定と異なる (別のチェーンのデータベース)")]
    GenesisMismatch,
    /// 本体を保持していない。
    #[error("ブロック {0} の本体を保持していない")]
    MissingBlockBody(Hash),
    /// 記憶域の操作に失敗した。
    #[error("記憶域の操作に失敗した: {0}")]
    Store(String),
    /// リオーグの巻き戻しに失敗した。
    ///
    /// **チェーンの状態が不整合になっている可能性がある。**
    /// 再インデックスが必要である。
    #[error("リオーグの巻き戻しに失敗した (状態が不整合の可能性がある): {0}")]
    RollbackFailed(String),
    /// 検証に失敗した。
    #[error(transparent)]
    Validation(#[from] ValidationError),
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
pub struct Chain<S: ChainStore> {
    store: S,
    /// ブロックインデックスの写し。祖先をたどる操作を高速にするために持つ。
    index: HashMap<Hash, BlockIndexEntry>,
    genesis_difficulty: u64,
}

impl<S: ChainStore> Chain<S> {
    fn store_err(e: S::Error) -> ChainError {
        ChainError::Store(e.to_string())
    }

    /// 記憶域を開き、必要ならジェネシスで初期化する。
    ///
    /// 記憶域がすでに使われている場合は、そのジェネシスが指定と一致することを
    /// 確認したうえで、インデックスを読み込む。
    pub fn open(store: S, genesis: Block, genesis_difficulty: u64) -> Result<Chain<S>, ChainError> {
        check_genesis(&genesis, genesis_difficulty)?;
        let genesis_hash = genesis.header.hash();

        let mut chain = Chain {
            store,
            index: HashMap::new(),
            genesis_difficulty,
        };

        match chain.store.tip().map_err(Self::store_err)? {
            None => {
                let entry = BlockIndexEntry {
                    hash: genesis_hash,
                    header: genesis.header,
                    cumulative_work: u128::from(genesis.header.difficulty),
                    status: BlockStatus::FullyValid,
                };
                chain
                    .store
                    .put_block(&genesis, &entry)
                    .map_err(Self::store_err)?;
                chain
                    .store
                    .connect_block(&genesis)
                    .map_err(Self::store_err)?;
                chain.index.insert(genesis_hash, entry);
            }
            Some(_) => {
                for entry in chain.store.all_index_entries().map_err(Self::store_err)? {
                    chain.index.insert(entry.hash, entry);
                }
                let stored_genesis = chain
                    .store
                    .hash_at_height(0)
                    .map_err(Self::store_err)?
                    .ok_or(ChainError::GenesisMismatch)?;
                if stored_genesis != genesis_hash {
                    return Err(ChainError::GenesisMismatch);
                }
            }
        }
        Ok(chain)
    }

    /// 背後の記憶域。
    pub fn store(&self) -> &S {
        &self.store
    }

    /// アクティブチェーンの先端。
    pub fn tip(&self) -> Result<BlockIndexEntry, ChainError> {
        let hash = self
            .store
            .tip()
            .map_err(Self::store_err)?
            .ok_or(ChainError::BadGenesis("先端が無い"))?;
        self.index
            .get(&hash)
            .cloned()
            .ok_or(ChainError::MissingBlockBody(hash))
    }

    /// 先端の高さ。
    pub fn height(&self) -> Result<u64, ChainError> {
        Ok(self.tip()?.height())
    }

    /// UTXO の読み取りビュー。
    pub fn utxo_view(&self) -> Result<S::View<'_>, ChainError> {
        self.store.utxo_view().map_err(Self::store_err)
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
    pub fn hash_at_height(&self, height: u64) -> Result<Option<Hash>, ChainError> {
        self.store.hash_at_height(height).map_err(Self::store_err)
    }

    /// そのハッシュがアクティブチェーン上にあるか。
    fn is_active(&self, hash: &Hash) -> Result<bool, ChainError> {
        let Some(entry) = self.index.get(hash) else {
            return Ok(false);
        };
        Ok(self.hash_at_height(entry.height())? == Some(*hash))
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

        let mut chain = self.ancestors(parent, lwma::WINDOW + 1);
        chain.reverse();
        debug_assert_eq!(chain.len(), lwma::WINDOW + 1);

        let timestamps: Vec<i64> = chain.iter().map(|e| e.header.timestamp).collect();
        let difficulties: Vec<u64> = chain[1..].iter().map(|e| e.header.difficulty).collect();
        Ok(lwma::next_difficulty(&timestamps, &difficulties)?)
    }

    /// ブロックを受け取る。
    pub fn accept_block(
        &mut self,
        block: Block,
        pow: &dyn PowVerifier,
        now: i64,
    ) -> Result<AcceptOutcome, ChainError> {
        let hash = block.header.hash();

        // 最も安価な検査から行う (SPEC §10.5)。
        let size = block.size();
        if size > params::MAX_BLOCK_SIZE {
            return Err(ChainError::BlockTooLarge {
                actual: size,
                max: params::MAX_BLOCK_SIZE,
            });
        }

        let entry = match self.index.get(&hash) {
            // 本体をすでに持っている。
            Some(known) if known.has_body() => return Ok(AcceptOutcome::Duplicate),
            Some(known) if known.status == BlockStatus::Invalid => {
                return Err(ChainError::InvalidAncestor(hash))
            }
            // ヘッダだけ先に受け取っていた。本体が届いたので格上げする。
            //
            // ヘッダはハッシュが一致する以上まったく同じものであり、
            // 受け取った時点で検証済みである。やり直す必要はない。
            Some(known) => BlockIndexEntry {
                status: BlockStatus::HeaderValid,
                ..known.clone()
            },
            None => self.validated_entry(&block.header, pow, now)?,
        };

        self.store
            .put_block(&block, &entry)
            .map_err(Self::store_err)?;
        self.index.insert(hash, entry);

        self.activate_best_chain(pow, now)
    }

    /// ヘッダだけを受け取る (headers-first 同期)。
    ///
    /// ヘッダと PoW を検証してインデックスに載せる。本体が無いので接続は
    /// しない。どの本体を取り寄せるべきかは
    /// [`Chain::missing_bodies`] が答える。
    ///
    /// すでに知っているヘッダなら [`HeaderOutcome::Known`] を返す。
    pub fn accept_header(
        &mut self,
        header: &BlockHeader,
        pow: &dyn PowVerifier,
        now: i64,
    ) -> Result<HeaderOutcome, ChainError> {
        let hash = header.hash();
        if let Some(known) = self.index.get(&hash) {
            return if known.status == BlockStatus::Invalid {
                Err(ChainError::InvalidAncestor(hash))
            } else {
                Ok(HeaderOutcome::Known)
            };
        }

        let mut entry = self.validated_entry(header, pow, now)?;
        entry.status = BlockStatus::HeaderOnly;
        self.store
            .put_index_entry(&entry)
            .map_err(Self::store_err)?;
        self.index.insert(hash, entry);
        Ok(HeaderOutcome::New)
    }

    /// ヘッダを検証し、インデックスの 1 件を組み立てる。
    ///
    /// 状態は `HeaderValid` (本体あり) を仮に入れる。ヘッダだけの場合は
    /// 呼び出し側が `HeaderOnly` に書き換える。
    fn validated_entry(
        &self,
        header: &BlockHeader,
        pow: &dyn PowVerifier,
        now: i64,
    ) -> Result<BlockIndexEntry, ChainError> {
        let parent_hash = header.prev_hash;
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
        validate_header(header, &ctx, pow)?;

        Ok(BlockIndexEntry {
            hash: header.hash(),
            header: *header,
            cumulative_work: parent_work + u128::from(header.difficulty),
            status: BlockStatus::HeaderValid,
        })
    }

    /// アクティブチェーンに合流するまでの経路が、すべて本体を持っているか。
    ///
    /// headers-first 同期では、ヘッダだけ知っている祖先の先に本体が届く
    /// ことがある。そのまま切り替えにかかると、途中で本体が無いことに
    /// 気づいて巻き戻す羽目になる。切り替える前に確かめる。
    fn path_has_all_bodies(&self, target: &Hash) -> Result<bool, ChainError> {
        let mut cursor = *target;
        loop {
            if self.is_active(&cursor)? {
                return Ok(true);
            }
            let Some(entry) = self.index.get(&cursor) else {
                return Ok(false);
            };
            if !entry.has_body() {
                return Ok(false);
            }
            if entry.height() == 0 {
                return Ok(true);
            }
            cursor = entry.prev_hash();
        }
    }

    /// 最良のチェーンへ切り替える。
    fn activate_best_chain(
        &mut self,
        pow: &dyn PowVerifier,
        now: i64,
    ) -> Result<AcceptOutcome, ChainError> {
        loop {
            let tip_work = self.tip()?.cumulative_work;

            // 作業量の多い順に、経路がそろっているものを探す。
            // 同点なら現先端を保つ。最初に受け取ったチェーンを優先する。
            let mut candidates: Vec<(u128, Hash)> = self
                .index
                .values()
                .filter(|e| e.is_candidate() && e.cumulative_work > tip_work)
                .map(|e| (e.cumulative_work, e.hash))
                .collect();
            candidates.sort_by(|a, b| {
                b.0.cmp(&a.0)
                    .then_with(|| a.1.as_bytes().cmp(b.1.as_bytes()))
            });

            let mut best = None;
            for (_, hash) in candidates {
                if self.path_has_all_bodies(&hash)? {
                    best = Some(hash);
                    break;
                }
            }

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
                    self.mark_invalid(&hash)?;
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
        let fail = |hash: Hash, error: ChainError| ConnectFailure { hash, error };

        // target からアクティブチェーンに合流するまで遡る。
        let mut to_connect = Vec::new();
        let mut cursor = target;
        loop {
            match self.is_active(&cursor) {
                Ok(true) => break,
                Ok(false) => {}
                Err(e) => return Err(fail(target, e)),
            }
            to_connect.push(cursor);
            let Some(entry) = self.index.get(&cursor) else {
                return Err(fail(cursor, ChainError::UnknownParent(cursor)));
            };
            if entry.height() == 0 {
                break;
            }
            cursor = entry.prev_hash();
        }
        to_connect.reverse();

        let fork_height = self.index[&cursor].height();

        let mut disconnected = Vec::new();
        loop {
            let height = self.height().map_err(|e| fail(target, e))?;
            if height <= fork_height {
                break;
            }
            let hash = self
                .store
                .disconnect_tip()
                .map_err(|e| fail(target, Self::store_err(e)))?;
            disconnected.push(hash);
        }

        let mut connected = Vec::new();
        for hash in &to_connect {
            match self.connect_block(*hash, pow, now) {
                Ok(()) => connected.push(*hash),
                Err(error) => {
                    if let Err(rollback) = self.rollback(&connected, &disconnected) {
                        return Err(fail(*hash, rollback));
                    }
                    return Err(fail(*hash, error));
                }
            }
        }

        Ok(Reorg {
            disconnected,
            connected,
        })
    }

    /// 接続に失敗したときに、元のチェーンへ戻す。
    ///
    /// 戻す対象のブロックは以前に検証を通っているため、再検証はしない。
    fn rollback(&mut self, connected: &[Hash], disconnected: &[Hash]) -> Result<(), ChainError> {
        for _ in connected {
            self.store
                .disconnect_tip()
                .map_err(|e| ChainError::RollbackFailed(e.to_string()))?;
        }
        // disconnected は先端に近い順なので、古い順に戻す。
        for hash in disconnected.iter().rev() {
            let block = self
                .store
                .block(hash)
                .map_err(|e| ChainError::RollbackFailed(e.to_string()))?
                .ok_or(ChainError::RollbackFailed(format!(
                    "ブロック {hash} の本体が無い"
                )))?;
            self.store
                .connect_block(&block)
                .map_err(|e| ChainError::RollbackFailed(e.to_string()))?;
        }
        Ok(())
    }

    /// ブロックを 1 つ接続する。本体の検証はここで行う。
    fn connect_block(
        &mut self,
        hash: Hash,
        pow: &dyn PowVerifier,
        now: i64,
    ) -> Result<(), ChainError> {
        let block = self
            .store
            .block(&hash)
            .map_err(Self::store_err)?
            .ok_or(ChainError::MissingBlockBody(hash))?;
        let parent_hash = block.header.prev_hash;

        let header_ctx = HeaderContext {
            expected_height: self.index[&parent_hash].height() + 1,
            expected_prev_hash: parent_hash,
            median_time_past: self.median_time_past_for_child_of(&parent_hash),
            expected_difficulty: self.expected_difficulty_for_child_of(&parent_hash)?,
            now,
        };

        {
            let view = self.store.utxo_view().map_err(Self::store_err)?;
            let ctx = BlockContext {
                header: header_ctx,
                utxo: &view,
            };
            validate_block(&block, &ctx, pow)?;
        }

        self.store.connect_block(&block).map_err(Self::store_err)?;

        if let Some(entry) = self.index.get_mut(&hash) {
            entry.status = BlockStatus::FullyValid;
            let snapshot = entry.clone();
            self.store
                .put_index_entry(&snapshot)
                .map_err(Self::store_err)?;
        }
        Ok(())
    }

    /// 最も作業量の多いヘッダの先端。
    ///
    /// 本体の有無は問わない。同期がどこまで進んだかを測る基準であり、
    /// アクティブチェーンの先端 ([`Chain::tip`]) とは別物である。
    /// headers-first では、ヘッダの先端が本体の先端よりずっと先を行く。
    pub fn best_header(&self) -> Result<BlockIndexEntry, ChainError> {
        self.index
            .values()
            .filter(|e| e.is_valid_header())
            .max_by(|a, b| {
                a.cumulative_work
                    .cmp(&b.cumulative_work)
                    .then_with(|| b.hash.as_bytes().cmp(a.hash.as_bytes()))
            })
            .cloned()
            .ok_or(ChainError::BadGenesis("インデックスが空である"))
    }

    /// 最良ヘッダチェーン上の、指定した高さのブロックハッシュを集める。
    ///
    /// `heights` は**新しい順 (降順)** に与える。ブロックロケータの構築に
    /// 用いる。先端から親をたどって 1 度で集めるため、1 つずつ引くより安い。
    ///
    /// アクティブチェーンではなく**ヘッダの連なり**をたどる。headers-first
    /// では本体がまだ無い高さまでヘッダが伸びており、そこまで「知っている」
    /// と相手に伝えないと、同じヘッダを何度も送らせることになる。
    pub fn header_hashes_at(&self, heights: &[u64]) -> Result<Vec<Hash>, ChainError> {
        let mut cursor = self.best_header()?;
        let mut out = Vec::with_capacity(heights.len());
        for &wanted in heights {
            if wanted > cursor.height() {
                continue;
            }
            while cursor.height() > wanted {
                let Some(parent) = self.index.get(&cursor.prev_hash()) else {
                    return Ok(out);
                };
                cursor = parent.clone();
            }
            out.push(cursor.hash);
        }
        Ok(out)
    }

    /// 本体をまだ持っていないブロックを、繋ぐべき順に最大 `max` 件返す。
    ///
    /// 最良ヘッダチェーンをジェネシス側から順にたどり、本体の無いものを
    /// 拾う。**古い順に返す。** ブロックは親から順にしか繋げないため、
    /// この並びを崩して取り寄せても繋げられない。
    pub fn missing_bodies(&self, max: usize) -> Result<Vec<Hash>, ChainError> {
        if max == 0 {
            return Ok(Vec::new());
        }
        // 最良ヘッダの先端から遡り、本体を持つ祖先に着いたら止める。
        let mut cursor = self.best_header()?.hash;
        let mut missing = Vec::new();
        while let Some(entry) = self.index.get(&cursor) {
            if entry.has_body() {
                break;
            }
            missing.push(cursor);
            if entry.height() == 0 {
                break;
            }
            cursor = entry.prev_hash();
        }
        // 遡って集めたので新しい順である。古い順に直し、頭から max 件返す。
        missing.reverse();
        missing.truncate(max);
        Ok(missing)
    }

    /// `getheaders` に応える。
    ///
    /// ロケータとアクティブチェーンが最後に一致する高さを求め、その次から
    /// 最大 `max` 件のヘッダを古い順に返す。`stop` が非ゼロなら、そこまでで
    /// 打ち切る (そのヘッダを含む)。
    ///
    /// ロケータに一致する点が無ければジェネシスの次から返す。相手が別の
    /// チェーンを見ている場合であり、こちらの分岐点から送り直すことになる。
    pub fn headers_after(
        &self,
        locator: &[Hash],
        stop: &Hash,
        max: usize,
    ) -> Result<Vec<BlockHeader>, ChainError> {
        let fork = locator_fork_height(self, locator)?;
        let tip_height = self.height()?;

        let mut headers = Vec::new();
        let mut height = fork + 1;
        while headers.len() < max && height <= tip_height {
            let Some(hash) = self.hash_at_height(height)? else {
                break;
            };
            let Some(entry) = self.index.get(&hash) else {
                break;
            };
            headers.push(entry.header);
            if hash == *stop {
                break;
            }
            height += 1;
        }
        Ok(headers)
    }

    /// ブロックとその子孫すべてに無効の印を付ける。
    fn mark_invalid(&mut self, hash: &Hash) -> Result<(), ChainError> {
        let mut frontier = vec![*hash];
        let mut changed = Vec::new();
        while let Some(current) = frontier.pop() {
            if let Some(entry) = self.index.get_mut(&current) {
                if entry.status == BlockStatus::Invalid {
                    continue;
                }
                entry.status = BlockStatus::Invalid;
                changed.push(entry.clone());
            }
            let children: Vec<Hash> = self
                .index
                .values()
                .filter(|e| e.prev_hash() == current && e.height() != 0)
                .map(|e| e.hash)
                .collect();
            frontier.extend(children);
        }
        for entry in &changed {
            self.store.put_index_entry(entry).map_err(Self::store_err)?;
        }
        Ok(())
    }
}

/// ジェネシスブロックの形を検査する。
///
/// PoW は検証しない。ジェネシスはチェーンの定義そのものであるため。
fn check_genesis(genesis: &Block, genesis_difficulty: u64) -> Result<(), ChainError> {
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
    Ok(())
}

/// ロケータとアクティブチェーンが最後に一致する高さ。
///
/// 一致する点が無ければ 0 (ジェネシス) を返す。ジェネシスは必ず共通で
/// あるためである。
fn locator_fork_height<S: ChainStore>(
    chain: &Chain<S>,
    locator: &[Hash],
) -> Result<u64, ChainError> {
    for hash in locator {
        let Some(entry) = chain.entry(hash) else {
            continue;
        };
        let height = entry.height();
        if chain.hash_at_height(height)? == Some(*hash) {
            return Ok(height);
        }
    }
    Ok(0)
}
