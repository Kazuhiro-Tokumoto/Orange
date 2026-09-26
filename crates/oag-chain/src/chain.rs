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

use crate::index::{BlockIndex, BlockIndexEntry, BlockStatus, EntryCache};
use crate::store::ChainStore;
use oag_consensus::params;
use oag_consensus::validate::{
    median_time_past, validate_block, validate_header, AcceptAnyPow, BlockContext, HeaderContext,
    PowVerifier, SignatureChecks, ValidationError,
};
use oag_consensus::{Block, BlockHeader};
use oag_pow::lwma::{self, LwmaError};
use oag_primitives::Hash;
use std::cell::RefCell;

/// 難易度調整を行うか。
///
/// regtest では**行わない**。ブロックを望むだけ速く積めるようにするため
/// である。行うと、速く積むほど難易度が上がり、コインベースの成熟
/// ([`params::COINBASE_MATURITY`] ブロック) を待つまでに現実的でない時間が
/// かかる。Bitcoin の regtest も同じ扱いである (SPEC §12.4)。
///
/// **mainnet と testnet では必ず行う。** 行わなければハッシュレートの
/// 変動にまったく追随できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retarget {
    /// 難易度を調整する。mainnet と testnet。
    Enabled,
    /// 難易度をジェネシスの値に固定する。regtest のみ。
    Disabled,
}

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
    #[error("parent block {0} is unknown")]
    UnknownParent(Hash),
    /// 親ブロックが無効と判明している。
    #[error("parent block {0} is invalid")]
    InvalidAncestor(Hash),
    /// ブロックが大きすぎる。
    #[error("block size {actual} exceeds the limit {max}")]
    BlockTooLarge {
        /// 実際のサイズ。
        actual: usize,
        /// 上限。
        max: usize,
    },
    /// ジェネシスブロックが不正。
    #[error("the genesis block is malformed: {0}")]
    BadGenesis(&'static str),
    /// 記憶域に入っているジェネシスが指定と食い違う。
    #[error("the genesis in storage differs from the one given (database of another chain)")]
    GenesisMismatch,
    /// 本体を保持していない。
    #[error("the body of block {0} is not held")]
    MissingBlockBody(Hash),
    /// 記憶域の操作に失敗した。
    #[error("a storage operation failed: {0}")]
    Store(String),
    /// リオーグの巻き戻しに失敗した。
    ///
    /// **チェーンの状態が不整合になっている可能性がある。**
    /// 再インデックスが必要である。
    #[error("rewinding the reorg failed (state may be inconsistent): {0}")]
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

/// 手元に控えるインデックスの件数。
///
/// 新しいブロックを検証するときに触るのは、難易度の窓 (90)、
/// Median Time Past (11)、シードを引くときの祖先 (最大 2112)、
/// `getheaders` に答えるときの祖先 (最大 2000) である。いずれも**先端の
/// 近く**なので、この程度あれば記憶域を引き直すことは滅多にない。
///
/// 1 件およそ 230 バイトなので、**1 MB 前後で頭打ちになる。**
/// 高さには比例しない (`docs/SPEC.md` §19)。
pub const CACHED_ENTRIES: usize = 4096;

/// assumevalid の経路を手元に置く高さの数。
///
/// 経路は assumevalid ブロックから親をたどって作るため、1 回あたり
/// 「assumevalid の高さ − 求める高さ」だけインデックスを引く。窓を出るたびに
/// 引き直すので、**狭いと引き直しが増え、広いと常駐量が増える。**
///
/// 65536 なら常駐は 2 MB で、高さ 50 万からの初期同期でも引き直しは 8 回に
/// 収まる。ブロック 1 個ごとに引き直す実装は O(n²) になって、
/// 節約した署名検証より高くつく。
const ASSUME_VALID_WINDOW: u64 = 65_536;

/// assumevalid の状態 (`docs/SPEC.md` §10.8)。
///
/// **これはコンセンサス規則ではない。** 判定が変わるのは「手元で署名を
/// 検証し直すか」だけであり、受け入れるブロックの集合は変わらない。
struct AssumeValid {
    /// 設定されたブロックのハッシュ。
    hash: Hash,
    /// 経路の窓。`window[i]` が高さ `base + i` のハッシュにあたる。
    base: u64,
    window: Vec<Hash>,
    /// 窓に置く高さの数。試験のために縮められるようにしてある。
    /// **正しさは値によらない。** 狭くすると引き直しが増えるだけである。
    limit: u64,
}

/// チェーンの状態。
pub struct Chain<S: ChainStore> {
    store: S,
    /// 先端の候補。**ブロックの実体は持たない** (`docs/SPEC.md` §19)。
    index: BlockIndex,
    /// 最近引いたインデックスの控え。**正本は記憶域である。**
    ///
    /// 引くのは `&self` の経路 (祖先をたどる、難易度を数える) なので、
    /// 控えるには内側の可変性が要る。
    entries: RefCell<EntryCache>,
    genesis_difficulty: u64,
    retarget: Retarget,
    /// assumevalid。**既定は無効 (`None`) である。**
    ///
    /// 引くのは `&self` の経路なので、窓を持つには内側の可変性が要る。
    assume_valid: RefCell<Option<AssumeValid>>,
}

impl<S: ChainStore> Chain<S> {
    fn store_err(e: S::Error) -> ChainError {
        ChainError::Store(e.to_string())
    }

    /// 記憶域を開き、必要ならジェネシスで初期化する。
    ///
    /// 記憶域がすでに使われている場合は、そのジェネシスが指定と一致することを
    /// 確認したうえで、インデックスを読み込む。
    pub fn open(
        store: S,
        genesis: Block,
        genesis_difficulty: u64,
        retarget: Retarget,
    ) -> Result<Chain<S>, ChainError> {
        Chain::open_with_cache(store, genesis, genesis_difficulty, retarget, CACHED_ENTRIES)
    }

    /// 控えの上限を決めて開く。
    ///
    /// **正しさは上限によらない。** 引けなかったものは記憶域に聞き直すので、
    /// 上限を 1 にしても答えは変わらず、遅くなるだけである。記憶の少ない
    /// 機械と、追い出しを実際に起こす試験のために開けてある。
    pub fn open_with_cache(
        store: S,
        genesis: Block,
        genesis_difficulty: u64,
        retarget: Retarget,
        cache_limit: usize,
    ) -> Result<Chain<S>, ChainError> {
        check_genesis(&genesis, genesis_difficulty)?;
        let genesis_hash = genesis.header.hash();

        let mut index = BlockIndex::new();

        match store.tip().map_err(Self::store_err)? {
            None => {
                let entry = BlockIndexEntry {
                    hash: genesis_hash,
                    header: genesis.header,
                    cumulative_work: u128::from(genesis.header.difficulty),
                    status: BlockStatus::FullyValid,
                };
                store.put_block(&genesis, &entry).map_err(Self::store_err)?;
                store.connect_block(&genesis).map_err(Self::store_err)?;
                index.record(&entry);
            }
            Some(tip_hash) => {
                // **先端を先に読む。** 候補になりうるのは先端を下回らない
                // ものだけなので、読みながら落とせる。全件をいったん
                // 載せてから落とすと、起動の瞬間だけ高さに比例した常駐量を
                // 抱えることになる (`docs/SPEC.md` §19)。
                let floor = store
                    .index_entry(&tip_hash)
                    .map_err(Self::store_err)?
                    .ok_or(ChainError::BadGenesis("the tip is not in the index"))?
                    .cumulative_work;
                store
                    .for_each_index_entry(&mut |entry| {
                        if entry.cumulative_work >= floor {
                            index.record(&entry);
                        }
                    })
                    .map_err(Self::store_err)?;

                let stored_genesis = store
                    .hash_at_height(0)
                    .map_err(Self::store_err)?
                    .ok_or(ChainError::GenesisMismatch)?;
                if stored_genesis != genesis_hash {
                    return Err(ChainError::GenesisMismatch);
                }
            }
        }

        Ok(Chain {
            store,
            index,
            entries: RefCell::new(EntryCache::new(cache_limit)),
            genesis_difficulty,
            retarget,
            assume_valid: RefCell::new(None),
        })
    }

    /// 背後の記憶域。
    pub fn store(&self) -> &S {
        &self.store
    }

    /// チェーンを畳んで記憶域を取り出す。
    ///
    /// 同じ記憶域で開き直すときに用いる。
    pub fn into_store(self) -> S {
        self.store
    }

    /// アクティブチェーンの先端。
    pub fn tip(&self) -> Result<BlockIndexEntry, ChainError> {
        let hash = self
            .store
            .tip()
            .map_err(Self::store_err)?
            .ok_or(ChainError::BadGenesis("there is no tip"))?;
        self.entry(&hash)?.ok_or(ChainError::MissingBlockBody(hash))
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
    ///
    /// **記憶域に聞く。** ここは常駐していない (`docs/SPEC.md` §19)。
    pub fn indexed_blocks(&self) -> Result<u64, ChainError> {
        self.store.index_len().map_err(Self::store_err)
    }

    /// 先端の候補として覚えている件数。
    ///
    /// **高さに比例しないこと**を外から確かめるために公開している。
    /// 分岐が無ければ 1 件で、鎖が伸びても増えない
    /// ([`BlockIndex::prune_below`](crate::index::BlockIndex::prune_below))。
    pub fn tip_candidates(&self) -> usize {
        self.index.tip_candidates()
    }

    /// このハッシュのブロックを知っているか。
    pub fn contains(&self, hash: &Hash) -> Result<bool, ChainError> {
        Ok(self.entry(hash)?.is_some())
    }

    /// インデックスの 1 件を引く。
    ///
    /// まず手元の控えを見て、無ければ記憶域に聞く。聞けたものは控える。
    ///
    /// **`None` は「知らない」であって「読めなかった」ではない。**
    /// 読めなかったときは誤りを返す。この 2 つを混同すると、正しい
    /// ブロックを知らないものとして扱い、静かにチェーンから外れる。
    pub fn entry(&self, hash: &Hash) -> Result<Option<BlockIndexEntry>, ChainError> {
        if let Some(entry) = self.entries.borrow().get(hash) {
            return Ok(Some(entry.clone()));
        }
        let Some(entry) = self.store.index_entry(hash).map_err(Self::store_err)? else {
            return Ok(None);
        };
        self.entries.borrow_mut().put(entry.clone());
        Ok(Some(entry))
    }

    /// 控えている件数。**上限で頭打ちになることを確かめるために公開する。**
    pub fn cached_entries(&self) -> usize {
        self.entries.borrow().len()
    }

    /// インデックスの 1 件を、記憶域・候補・控えのすべてに反映する。
    ///
    /// **記憶域が先である。** 控えだけが新しい状態になると、落ちたときに
    /// 食い違う。
    fn put_entry(&mut self, entry: &BlockIndexEntry) -> Result<(), ChainError> {
        self.store.put_index_entry(entry).map_err(Self::store_err)?;
        self.index.record(entry);
        self.entries.borrow_mut().put(entry.clone());
        Ok(())
    }

    /// 状態だけを書き換える。書き換えた結果を返す。
    ///
    /// 知らないハッシュなら何もせず `None` を返す。
    fn set_status(
        &mut self,
        hash: &Hash,
        status: BlockStatus,
    ) -> Result<Option<BlockIndexEntry>, ChainError> {
        let Some(mut entry) = self.entry(hash)? else {
            return Ok(None);
        };
        entry.status = status;
        self.put_entry(&entry)?;
        Ok(Some(entry))
    }

    /// アクティブチェーンの指定した高さのブロックハッシュ。
    pub fn hash_at_height(&self, height: u64) -> Result<Option<Hash>, ChainError> {
        self.store.hash_at_height(height).map_err(Self::store_err)
    }

    /// `from` から親をたどって、高さ `height` の祖先のハッシュを返す。
    ///
    /// # なぜ [`hash_at_height`](Self::hash_at_height) では足りないのか
    ///
    /// あちらが見ているのは**アクティブチェーン**の高さの索引である。
    /// headers-first の同期では、ヘッダだけが遥か先まで届いていて本体が
    /// 1 つも繋がっていない時期がある。そのときアクティブチェーンの高さは
    /// 0 のままなので、あちらは知っているはずのブロックにも `None` を返す。
    ///
    /// こちらはインデックス (ヘッダの木) を辿るので、本体が無くても引ける。
    /// 枝を指定するため、分岐していても取り違えない。
    pub fn ancestor_hash_at(&self, from: &Hash, height: u64) -> Result<Option<Hash>, ChainError> {
        let Some(mut entry) = self.entry(from)? else {
            return Ok(None);
        };
        if entry.height() < height {
            return Ok(None);
        }
        // アクティブチェーン上なら、高さの索引で 1 回で引ける。
        if self.is_active(from)? {
            return self.hash_at_height(height);
        }
        while entry.height() > height {
            let Some(parent) = self.entry(&entry.prev_hash())? else {
                return Ok(None);
            };
            entry = parent;
        }
        Ok(Some(entry.hash))
    }

    /// そのハッシュがアクティブチェーン上にあるか。
    fn is_active(&self, hash: &Hash) -> Result<bool, ChainError> {
        let Some(entry) = self.entry(hash)? else {
            return Ok(false);
        };
        Ok(self.hash_at_height(entry.height())? == Some(*hash))
    }

    /// assumevalid のブロックを設定する。`None` で無効にする。
    ///
    /// # これは何か
    ///
    /// 指定したブロック**とその祖先**について、手元での署名検証を飛ばす。
    /// 初期同期の大半は創世記から先端までの署名を検証し直す時間であり、
    /// そこが消える。PoW、マークルルート、金額の帳尻、二重使用、成熟期間、
    /// locktime、サイズは**すべて従来どおり検証する**。
    ///
    /// # なぜ安全か
    ///
    /// 飛ばす条件が「**指定したハッシュの祖先であること**」だからである。
    /// 攻撃者が別のチェーンを食わせても、そのブロックは指定ハッシュの祖先に
    /// ならないので、検証は飛ばされない。指定ハッシュそのものを偽造するには
    /// BLAKE3 の原像を求める必要がある。
    ///
    /// 指定したハッシュがインデックスに無い間は、何も起きない (全部検証する)。
    ///
    /// # 何を信じることになるか
    ///
    /// **指定したハッシュが本物のチェーン上にあること**を信じる。これは
    /// 検証ではなく仮定である。だから利用者が無効にできなければならない。
    pub fn set_assume_valid(&mut self, hash: Option<Hash>) {
        *self.assume_valid.borrow_mut() = hash.map(|hash| AssumeValid {
            hash,
            base: 0,
            window: Vec::new(),
            limit: ASSUME_VALID_WINDOW,
        });
    }

    /// 設定されている assumevalid のブロック。
    pub fn assume_valid(&self) -> Option<Hash> {
        self.assume_valid.borrow().as_ref().map(|av| av.hash)
    }

    /// このブロックの署名を検証するか (`docs/SPEC.md` §10.8)。
    ///
    /// **迷ったら [`SignatureChecks::Verify`] を返す。** 引けない、分からない、
    /// 経路が合わない、のいずれも検証する側に倒す。
    fn signature_checks_for(
        &self,
        hash: &Hash,
        height: u64,
    ) -> Result<SignatureChecks, ChainError> {
        let av_hash = match self.assume_valid.borrow().as_ref() {
            Some(av) => av.hash,
            None => return Ok(SignatureChecks::Verify),
        };

        // assumevalid のブロックをまだ受け取っていなければ、何も飛ばさない。
        let Some(av_entry) = self.entry(&av_hash)? else {
            return Ok(SignatureChecks::Verify);
        };
        let av_height = av_entry.height();

        // assumevalid より上は常に完全検証である。**攻撃はそこにしか来ない。**
        if height > av_height {
            return Ok(SignatureChecks::Verify);
        }

        // その高さで assumevalid の経路が通るハッシュと一致するか。
        if self.assume_valid_path_hash(&av_hash, av_height, height)? == Some(*hash) {
            Ok(SignatureChecks::Skip)
        } else {
            Ok(SignatureChecks::Verify)
        }
    }

    /// assumevalid の経路が高さ `height` で通るハッシュ。
    ///
    /// 窓に無ければ引き直す。引けなければ `None` を返し、呼び出し側は
    /// 検証する側に倒す。
    fn assume_valid_path_hash(
        &self,
        av_hash: &Hash,
        av_height: u64,
        height: u64,
    ) -> Result<Option<Hash>, ChainError> {
        let limit = {
            let cache = self.assume_valid.borrow();
            let Some(av) = cache.as_ref() else {
                return Ok(None);
            };
            if height >= av.base {
                if let Some(found) = av.window.get((height - av.base) as usize) {
                    return Ok(Some(*found));
                }
            }
            av.limit
        };

        let window = self.build_assume_valid_window(av_hash, av_height, height, limit)?;
        let found = window.first().copied();
        if let Some(av) = self.assume_valid.borrow_mut().as_mut() {
            av.base = height;
            av.window = window;
        }
        Ok(found)
    }

    /// 高さ `base` から上に向かって、assumevalid の経路を窓の分だけ集める。
    ///
    /// assumevalid から親をたどるため、`base` に届くまでの手数は
    /// `av_height - base` である。届かなければ空を返す。
    fn build_assume_valid_window(
        &self,
        av_hash: &Hash,
        av_height: u64,
        base: u64,
        limit: u64,
    ) -> Result<Vec<Hash>, ChainError> {
        // 指名したブロックより上に経路は無い。ここで断らないと、
        // **窓の先頭が `base` ではない高さのハッシュになる。** 添字が
        // ずれ、別のブロックを「祖先である」と答えてしまう。
        if base > av_height {
            return Ok(Vec::new());
        }

        let top = base.saturating_add(limit.max(1) - 1).min(av_height);
        let mut window = Vec::new();
        let mut cursor = *av_hash;
        // 辿っている先の高さ。1 段ごとにちょうど 1 ずつ下がるはずである。
        let mut expected = av_height;
        loop {
            let Some(entry) = self.entry(&cursor)? else {
                // 経路が途切れた。**部分的な窓を返してはならない。**
                return Ok(Vec::new());
            };
            if entry.height() != expected {
                // インデックスが壊れている。ここで気付けないと、
                // ずれた窓をそのまま信じることになる。
                return Ok(Vec::new());
            }
            if expected <= top {
                window.push(entry.hash);
            }
            if expected == base {
                break;
            }
            expected -= 1;
            cursor = entry.prev_hash();
        }
        // 低い高さが先頭に来るようにする。
        window.reverse();
        Ok(window)
    }

    /// `from` から親をたどって最大 `count` 件のヘッダを新しい順に集める。
    fn ancestors(&self, from: &Hash, count: usize) -> Result<Vec<BlockIndexEntry>, ChainError> {
        let mut out = Vec::with_capacity(count);
        let mut cursor = *from;
        while out.len() < count {
            let Some(entry) = self.entry(&cursor)? else {
                break;
            };
            let height = entry.height();
            cursor = entry.prev_hash();
            out.push(entry);
            if height == 0 {
                break;
            }
        }
        Ok(out)
    }

    /// `parent` を親とするブロックの Median Time Past。
    ///
    /// **記憶域が読めないときに値を返してはならない。** ここが返すのは
    /// 「この時刻より後でなければならない」という下限であり、既定値として
    /// `i64::MIN` を返すと**時刻の規則が無条件に通る**。読めないことと
    /// 「祖先がまだ 1 つも無い」ことは別の事実である。前者は誤りとして
    /// 返し、後者だけが `i64::MIN` (下限なし) になる。
    pub fn median_time_past_for_child_of(&self, parent: &Hash) -> Result<i64, ChainError> {
        let ancestors = self.ancestors(parent, params::MEDIAN_TIME_SPAN)?;
        let mut timestamps: Vec<i64> = ancestors.iter().map(|e| e.header.timestamp).collect();
        timestamps.reverse();
        // 祖先が 1 つも無いのはジェネシスの子だけである。下限を置かない。
        Ok(median_time_past(&timestamps).unwrap_or(i64::MIN))
    }

    /// `parent` を親とするブロックが取るべき難易度。
    pub fn expected_difficulty_for_child_of(&self, parent: &Hash) -> Result<u64, ChainError> {
        let parent_entry = self
            .entry(parent)?
            .ok_or(ChainError::UnknownParent(*parent))?;
        let height = parent_entry.height() + 1;

        // regtest は調整しない (SPEC §12.4)。
        if self.retarget == Retarget::Disabled {
            return Ok(self.genesis_difficulty);
        }

        // 履歴が窓幅に満たない間はジェネシス難易度を用いる (SPEC §12.3)。
        if height < lwma::WINDOW as u64 + 1 {
            return Ok(self.genesis_difficulty);
        }

        let mut chain = self.ancestors(parent, lwma::WINDOW + 1)?;
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

        let entry = match self.entry(&hash)? {
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
                ..known
            },
            None => self.validated_entry(&block.header, pow, now)?,
        };

        self.store
            .put_block(&block, &entry)
            .map_err(Self::store_err)?;
        self.index.record(&entry);
        self.entries.borrow_mut().put(entry);

        self.activate_best_chain(now)
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
        if let Some(known) = self.entry(&hash)? {
            return if known.status == BlockStatus::Invalid {
                Err(ChainError::InvalidAncestor(hash))
            } else {
                Ok(HeaderOutcome::Known)
            };
        }

        let mut entry = self.validated_entry(header, pow, now)?;
        entry.status = BlockStatus::HeaderOnly;
        self.put_entry(&entry)?;
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
            .entry(&parent_hash)?
            .ok_or(ChainError::UnknownParent(parent_hash))?;
        if parent.status == BlockStatus::Invalid {
            return Err(ChainError::InvalidAncestor(parent_hash));
        }
        let parent_work = parent.cumulative_work;
        let expected_height = parent.height() + 1;

        let ctx = HeaderContext {
            expected_height,
            expected_prev_hash: parent_hash,
            median_time_past: self.median_time_past_for_child_of(&parent_hash)?,
            expected_difficulty: self.expected_difficulty_for_child_of(&parent_hash)?,
            now,
        };
        validate_header(header, &ctx, pow)?;

        Ok(BlockIndexEntry {
            hash: header.hash(),
            header: *header,
            cumulative_work: parent_work.saturating_add(u128::from(header.difficulty)),
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
            let Some(entry) = self.entry(&cursor)? else {
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

    /// 先端を下回る候補を落とす。
    ///
    /// **先端の作業量は決して減らない**ので、ここより下は二度と候補に
    /// ならない ([`BlockIndex::prune_below`](crate::index::BlockIndex::prune_below))。
    /// 残すのは先端と、先端を上回る競合する枝だけである。
    fn prune_tip_candidates(&mut self) -> Result<(), ChainError> {
        let tip_work = self.tip()?.cumulative_work;
        self.index.prune_below(tip_work);
        Ok(())
    }

    /// 最良のチェーンへ切り替える。
    fn activate_best_chain(&mut self, now: i64) -> Result<AcceptOutcome, ChainError> {
        loop {
            let tip_work = self.tip()?.cumulative_work;

            // 作業量の多い順に、経路がそろっているものを探す。
            // 同点なら現先端を保つ。最初に受け取ったチェーンを優先する。
            //
            // **走るのは現先端を上回る候補だけである。** 先端を 1 個
            // 伸ばしただけなら 1 件で止まる。全件を走査すると、ブロック
            // 1 個あたり O(n)、初期同期の全体では O(n²) になる。
            let candidates: Vec<Hash> = self.index.candidates_above(tip_work).collect();

            let mut best = None;
            for hash in candidates {
                if self.path_has_all_bodies(&hash)? {
                    best = Some(hash);
                    break;
                }
            }

            let Some(target) = best else {
                return Ok(AcceptOutcome::SideChain);
            };

            match self.switch_to(target, now) {
                Ok(reorg) if reorg.disconnected.is_empty() && reorg.connected.len() == 1 => {
                    // 先端が進んだので、今の先端を下回るものを落とす。
                    // **切り替えた直後に落とす**ことで、抱えるのは常に
                    // 「先端と、先端を上回る枝」だけになる。
                    self.prune_tip_candidates()?;
                    return Ok(AcceptOutcome::ExtendedTip);
                }
                Ok(reorg) => {
                    self.prune_tip_candidates()?;
                    return Ok(AcceptOutcome::Reorganized(reorg));
                }
                Err(ConnectFailure {
                    hash,
                    error: ChainError::Validation(ref e),
                }) if !e.is_storage_failure() => {
                    // 実際に失敗したブロックとその子孫に印を付け、次の候補を試す。
                    self.mark_invalid(&hash)?;
                    continue;
                }
                // 記憶装置が読めなかっただけのときは、印を付けずに投げ返す。
                // 印は永続化され子孫へ広がるため、一時的な障害で付けると
                // 正しいチェーンへ二度と戻れなくなる。
                Err(ConnectFailure { error, .. }) => return Err(error),
            }
        }
    }

    /// `target` をアクティブチェーンの先端にする。
    fn switch_to(&mut self, target: Hash, now: i64) -> Result<Reorg, ConnectFailure> {
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
            let entry = match self.entry(&cursor) {
                Ok(Some(entry)) => entry,
                Ok(None) => return Err(fail(cursor, ChainError::UnknownParent(cursor))),
                Err(e) => return Err(fail(cursor, e)),
            };
            if entry.height() == 0 {
                break;
            }
            cursor = entry.prev_hash();
        }
        to_connect.reverse();

        let fork_height = match self.entry(&cursor) {
            Ok(Some(entry)) => entry.height(),
            Ok(None) => return Err(fail(cursor, ChainError::UnknownParent(cursor))),
            Err(e) => return Err(fail(cursor, e)),
        };

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
            match self.connect_block(*hash, now) {
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
                    "the body of block {hash} is missing"
                )))?;
            self.store
                .connect_block(&block)
                .map_err(|e| ChainError::RollbackFailed(e.to_string()))?;
        }
        Ok(())
    }

    /// ブロックを 1 つ接続する。本体の検証はここで行う。
    ///
    /// # PoW はここでは確かめない
    ///
    /// インデックスに載っているブロックは、載る時点で PoW を確かめてある
    /// ([`Chain::validated_entry`])。そのときの検証器は、**そのブロック自身の
    /// 高さ**のシードで組まれている。
    ///
    /// ここで確かめ直していたのが 0.1.1 までの誤りだった。1 度の切り替えで
    /// 繋ぐブロックは何個もあり、シードのエポックをまたぐことがある。
    /// 受け取った側が渡す検証器は 1 つで、**引き金になったブロックの**
    /// エポックのものである。他のエポックのブロックは PoW が必ず合わず、
    /// 正しいブロックに無効の印が付いた。印は永続化され子孫へ広がるので、
    /// ノードは正しいチェーンへ二度と戻れなくなった。
    ///
    /// 確かめ直す意味もない。ヘッダはハッシュで本体と結び付いており、
    /// 本体が届いてもヘッダは変わらない。
    fn connect_block(&mut self, hash: Hash, now: i64) -> Result<(), ChainError> {
        let block = self
            .store
            .block(&hash)
            .map_err(Self::store_err)?
            .ok_or(ChainError::MissingBlockBody(hash))?;
        let parent_hash = block.header.prev_hash;

        let height = self
            .entry(&parent_hash)?
            .ok_or(ChainError::UnknownParent(parent_hash))?
            .height()
            + 1;

        let header_ctx = HeaderContext {
            expected_height: height,
            expected_prev_hash: parent_hash,
            median_time_past: self.median_time_past_for_child_of(&parent_hash)?,
            expected_difficulty: self.expected_difficulty_for_child_of(&parent_hash)?,
            now,
        };

        {
            let view = self.store.utxo_view().map_err(Self::store_err)?;
            let ctx = BlockContext {
                header: header_ctx,
                utxo: &view,
                signature_checks: self.signature_checks_for(&hash, height)?,
            };
            validate_block(&block, &ctx, &AcceptAnyPow)?;
        }

        self.store.connect_block(&block).map_err(Self::store_err)?;

        self.set_status(&hash, BlockStatus::FullyValid)?;
        Ok(())
    }

    /// 最も作業量の多いヘッダの先端。
    ///
    /// 本体の有無は問わない。同期がどこまで進んだかを測る基準であり、
    /// アクティブチェーンの先端 ([`Chain::tip`]) とは別物である。
    /// headers-first では、ヘッダの先端が本体の先端よりずっと先を行く。
    pub fn best_header(&self) -> Result<BlockIndexEntry, ChainError> {
        let hash = self
            .index
            .best_header()
            .ok_or(ChainError::BadGenesis("the index is empty"))?;
        self.entry(&hash)?.ok_or(ChainError::BadGenesis(
            "the best header is not in the index",
        ))
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
                let Some(parent) = self.entry(&cursor.prev_hash())? else {
                    return Ok(out);
                };
                cursor = parent;
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
        while let Some(entry) = self.entry(&cursor)? {
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
            let Some(entry) = self.entry(&hash)? else {
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
        while let Some(current) = frontier.pop() {
            match self.entry(&current)? {
                // すでに印が付いている。子孫にも付いているので、たどらない。
                Some(entry) if entry.status == BlockStatus::Invalid => continue,
                Some(_) => {}
                None => continue,
            }
            self.set_status(&current, BlockStatus::Invalid)?;
            // 子は親から引く。全件を走査すると、印を広げるだけで
            // インデックス全体を何度も舐めることになる。
            //
            // **引き先は記憶域である。** メモリに持つと高さに比例して
            // 伸びるためで、ここを引くのは無効の印を付けるときだけである
            // (`docs/SPEC.md` §19)。
            let children = self.store.children_of(&current).map_err(Self::store_err)?;
            frontier.extend_from_slice(&children);
        }
        Ok(())
    }

    /// 無効の印をすべて外し、最良のチェーンへの切り替えをやり直す。
    /// 外した件数を返す。
    ///
    /// # なぜ要るのか
    ///
    /// 0.1.1 までは、初期同期でシードのエポックをまたぐと、正しいブロックに
    /// 無効の印が付くことがあった (`connect_block` の説明を見よ)。印は
    /// 永続化されるので、直した版に上げても外れない。そのノードは、正しい
    /// チェーンの続きを送ってくる相手を全員切り続ける。
    ///
    /// # 外して困らない理由
    ///
    /// 本当に無効なブロックなら、繋ごうとした時点でまた印が付く。かかるのは
    /// そのブロックを 1 度検証し直す手間だけである。PoW を満たさないヘッダは
    /// そもそもインデックスに載らないので、ここで蘇ることはない。
    pub fn reconsider_invalid(&mut self, now: i64) -> Result<usize, ChainError> {
        let mut invalid = Vec::new();
        self.store
            .for_each_index_entry(&mut |entry| {
                if entry.status == BlockStatus::Invalid {
                    invalid.push(entry);
                }
            })
            .map_err(Self::store_err)?;
        if invalid.is_empty() {
            return Ok(0);
        }

        for mut entry in invalid.iter().cloned() {
            // 印は本体の有無を覚えていない。記憶域に聞いて戻す。
            let has_body = self
                .store
                .block(&entry.hash)
                .map_err(Self::store_err)?
                .is_some();
            entry.status = if has_body {
                BlockStatus::HeaderValid
            } else {
                BlockStatus::HeaderOnly
            };
            self.put_entry(&entry)?;
        }

        self.activate_best_chain(now)?;
        Ok(invalid.len())
    }
}

/// ジェネシスブロックの形を検査する。
///
/// PoW は検証しない。ジェネシスはチェーンの定義そのものであるため。
fn check_genesis(genesis: &Block, genesis_difficulty: u64) -> Result<(), ChainError> {
    let header = &genesis.header;
    if header.height != 0 {
        return Err(ChainError::BadGenesis("height is not 0"));
    }
    if header.prev_hash != Hash::ZERO {
        return Err(ChainError::BadGenesis("prev_hash is not 0"));
    }
    if header.difficulty != genesis_difficulty {
        return Err(ChainError::BadGenesis(
            "difficulty does not match the one given",
        ));
    }
    if genesis.coinbase().is_none() {
        return Err(ChainError::BadGenesis("there is no coinbase"));
    }
    if !genesis.merkle_root_is_valid() {
        return Err(ChainError::BadGenesis("the merkle root does not match"));
    }
    if genesis.size() > params::MAX_BLOCK_SIZE {
        return Err(ChainError::BadGenesis("too large"));
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
        let Some(entry) = chain.entry(hash)? else {
            continue;
        };
        let height = entry.height();
        if chain.hash_at_height(height)? == Some(*hash) {
            return Ok(height);
        }
    }
    Ok(0)
}

#[cfg(test)]
mod assume_valid_tests {
    use super::*;
    use crate::scenarios::{self, NOW};
    use crate::MemoryStore;
    use oag_consensus::validate::AcceptAnyPow;

    /// 窓を狭めて開く。**正しさは窓の広さによらない**ので、境界を跨ぐ
    /// 振る舞いを短いチェーンで確かめられる。
    fn with_window(chain: &Chain<MemoryStore>, hash: Hash, limit: u64) {
        *chain.assume_valid.borrow_mut() = Some(AssumeValid {
            hash,
            base: 0,
            window: Vec::new(),
            limit,
        });
    }

    /// 高さ 0..=n のハッシュを持つ一本道を作る。
    fn straight_chain(n: usize) -> (Chain<MemoryStore>, Vec<Hash>) {
        let mut chain = scenarios::open(MemoryStore::new());
        let genesis = chain.tip().unwrap().hash;
        let mut hashes = vec![genesis];
        let mut parent = genesis;
        for i in 0..n {
            let block = scenarios::build_on(&chain, parent, i as u64 + 1);
            parent = block.header.hash();
            chain
                .accept_block(block, &AcceptAnyPow, NOW)
                .expect("a valid block");
            hashes.push(parent);
        }
        (chain, hashes)
    }

    #[test]
    fn the_window_answers_every_height_on_the_path() {
        // 窓を 4 に縮めて、高さ 0..=20 をすべて引く。**引き直しが何度も
        // 起きる**が、答えは経路そのものと一致しなければならない。
        let (chain, hashes) = straight_chain(20);
        with_window(&chain, hashes[20], 4);

        for (height, expected) in hashes.iter().enumerate() {
            let got = chain
                .assume_valid_path_hash(&hashes[20], 20, height as u64)
                .expect("the index is readable");
            assert_eq!(
                got,
                Some(*expected),
                "the window gave the wrong hash at height {height}"
            );
        }
    }

    #[test]
    fn the_window_answers_the_same_going_backwards() {
        // 繋ぎ替えでは高さが戻る。降順でも同じ答えが出ること。
        let (chain, hashes) = straight_chain(20);
        with_window(&chain, hashes[20], 4);

        for height in (0..=20u64).rev() {
            let got = chain
                .assume_valid_path_hash(&hashes[20], 20, height)
                .expect("the index is readable");
            assert_eq!(got, Some(hashes[height as usize]));
        }
    }

    #[test]
    fn a_height_above_the_named_block_has_no_answer() {
        let (chain, hashes) = straight_chain(10);
        with_window(&chain, hashes[5], 4);
        assert_eq!(
            chain
                .assume_valid_path_hash(&hashes[5], 5, 6)
                .expect("the index is readable"),
            None,
            "there is no path above the named block"
        );
    }

    #[test]
    fn a_block_off_the_path_is_verified() {
        // 分岐を作り、枝の側のブロックが Skip にならないことを確かめる。
        let (mut chain, hashes) = straight_chain(5);
        let fork = scenarios::build_on(&chain, hashes[2], 777);
        let fork_hash = fork.header.hash();
        chain
            .accept_block(fork, &AcceptAnyPow, NOW)
            .expect("a valid block");

        chain.set_assume_valid(Some(hashes[5]));

        // 本線の高さ 3 は祖先なので飛ばす。
        assert_eq!(
            chain.signature_checks_for(&hashes[3], 3).unwrap(),
            SignatureChecks::Skip
        );
        // 同じ高さの枝は祖先ではないので飛ばさない。
        assert_eq!(
            chain.signature_checks_for(&fork_hash, 3).unwrap(),
            SignatureChecks::Verify
        );
    }

    #[test]
    fn the_named_block_itself_is_skipped_and_its_child_is_not() {
        let (mut chain, hashes) = straight_chain(5);
        chain.set_assume_valid(Some(hashes[3]));

        assert_eq!(
            chain.signature_checks_for(&hashes[3], 3).unwrap(),
            SignatureChecks::Skip
        );
        assert_eq!(
            chain.signature_checks_for(&hashes[4], 4).unwrap(),
            SignatureChecks::Verify
        );
    }

    #[test]
    fn a_right_hash_at_a_wrong_height_is_verified() {
        // 高さとハッシュの組が経路と食い違う場合。窓の添字がずれていると
        // ここを通してしまう。
        let (mut chain, hashes) = straight_chain(5);
        chain.set_assume_valid(Some(hashes[5]));

        assert_eq!(
            chain.signature_checks_for(&hashes[2], 3).unwrap(),
            SignatureChecks::Verify
        );
    }

    #[test]
    fn without_a_setting_everything_is_verified() {
        let (chain, hashes) = straight_chain(3);
        assert_eq!(chain.assume_valid(), None);
        for (height, hash) in hashes.iter().enumerate() {
            assert_eq!(
                chain.signature_checks_for(hash, height as u64).unwrap(),
                SignatureChecks::Verify
            );
        }
    }

    #[test]
    fn a_hash_that_is_not_in_the_index_verifies_everything() {
        let (mut chain, hashes) = straight_chain(3);
        chain.set_assume_valid(Some(oag_primitives::hash::block_hash(b"elsewhere")));
        for (height, hash) in hashes.iter().enumerate() {
            assert_eq!(
                chain.signature_checks_for(hash, height as u64).unwrap(),
                SignatureChecks::Verify
            );
        }
    }
}
