//! ノード本体。
//!
//! 記憶域を開き、チェーンを復元し、採掘する。
//!
//! # RandomX の検証器はエポックごとに作り直す
//!
//! RandomX のシードは 2048 ブロックごとに切り替わる (`docs/SPEC.md` §11.3)。
//! 検証器の初期化には 256 MB の確保が伴うため、切り替わるまでは使い回す。
//!
//! # 中断について
//!
//! ブロックを 1 個受け入れるたびに記憶域への書き込みが確定する。途中で
//! 強制終了しても、そのブロックが入っているか入っていないかのどちらかに
//! なり、中途半端な状態は残らない。信号を捕まえる仕掛けを置いていないのは
//! そのためである。

use crate::addrbook::AddressBook;
use oag_chain::chain::{AcceptOutcome, Chain, ChainError, HeaderOutcome, Retarget};
use oag_consensus::lock::Lock;
use oag_consensus::params;
use oag_consensus::{Block, BlockHeader};
use oag_mempool::Mempool;
use oag_miner::mine::{MiningOutcome, NeverStop};
use oag_miner::{build_template, TemplateError, TemplateRequest};
use oag_pow::randomx::{RandomXMiner, RandomXPowError, RandomXVerifier};
use oag_pow::seed_height;
use oag_primitives::{Hash, Network};
use oag_store::{Store, StoreError};
use std::path::Path;

/// 1 回の探索で試す nonce の数。
///
/// これを試し切ったら追加ノンスを変えて組み直す。light モードの RandomX は
/// 1 秒に数百回しか計算できないため、大きすぎると中断の判断が遅れる。
const NONCE_BATCH: u64 = 1_000;

/// ノードの失敗。
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// 記憶域の操作に失敗した。
    #[error(transparent)]
    Store(#[from] StoreError),
    /// チェーンの操作に失敗した。
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// テンプレートの組み立てに失敗した。
    #[error(transparent)]
    Template(#[from] TemplateError),
    /// RandomX の操作に失敗した。
    #[error(transparent)]
    RandomX(#[from] RandomXPowError),
    /// 採掘に失敗した。
    #[error(transparent)]
    Mine(#[from] oag_miner::MineError),
    /// 作業スレッドを起こせない、あるいは落ちた。
    #[error("ノードの作業スレッド: {0}")]
    Thread(String),
    /// 掘ったブロックが受理されなかった。
    #[error("自分で掘ったブロックが受理されなかった: {0:?}")]
    SelfMinedRejected(AcceptOutcome),
    /// タイムスタンプを決められない。
    #[error("チェーンの先端が未来すぎる (Median Time Past {mtp}、現在 {now})")]
    ClockTooFarBehind {
        /// 先端の Median Time Past。
        mtp: i64,
        /// ノードの現在時刻。
        now: i64,
    },
}

/// ノードの現在の様子。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatus {
    /// ネットワーク。
    pub network: Network,
    /// 先端の高さ。
    pub height: u64,
    /// 先端のブロックハッシュ。
    pub tip: Hash,
    /// 先端までの累積作業量。
    pub cumulative_work: u128,
    /// 次のブロックの難易度。
    pub next_difficulty: u64,
    /// UTXO の件数。
    pub utxo_count: u64,
    /// 知っているブロックの数 (サイドチェーンを含む)。
    pub indexed_blocks: usize,
    /// mempool の件数。
    pub mempool_len: usize,
    /// 住所帳に覚えているピアの数。
    pub known_addresses: usize,
}

/// 採掘の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinedBlock {
    /// 掘れて、先端になった。
    Accepted {
        /// 掘ったブロックのハッシュ。
        hash: Hash,
        /// 新しい高さ。
        height: u64,
        /// 試した回数。
        attempts: u64,
    },
    /// 与えられた回数では見つからなかった。
    NotFound {
        /// 試した回数。
        attempts: u64,
    },
}

/// ノード。
pub struct Node {
    chain: Chain<Store>,
    mempool: Mempool,
    network: Network,
    /// 現在のシードエポックの検証器 (light、256 MB)。
    ///
    /// **検証には常にこちらを使う。** 採掘を fast モードで行っていても、
    /// 掘れたブロックは light の検証器に通す。両者が同じハッシュを返す
    /// ことは `oag-pow` の試験で確かめてあるが、確かめてあることと
    /// 実際に通すことは別である。
    verifier: Option<(u64, RandomXVerifier)>,
    /// 現在のシードエポックの採掘器 (fast、2 GB)。
    ///
    /// `None` なら light モードで掘る。
    miner: Option<(u64, RandomXMiner)>,
    /// fast モードで掘るか。
    fast_mining: bool,
    /// ピアの住所帳。
    addresses: AddressBook,
}

impl Node {
    /// 記憶域を開き、必要ならジェネシスで初期化する。
    pub fn open(network: Network, data_dir: &Path) -> Result<Node, NodeError> {
        let genesis = crate::genesis::genesis_for(network);
        std::fs::create_dir_all(data_dir)
            .map_err(|e| StoreError::Io(format!("{} を作れない: {e}", data_dir.display())))?;
        let store = Store::open(data_dir.join("chain.redb"))?;
        let retarget = if network.retargets() {
            Retarget::Enabled
        } else {
            Retarget::Disabled
        };
        let chain = Chain::open(store, genesis, network.genesis_difficulty(), retarget)?;
        let addresses = AddressBook::open(network, &data_dir.join("peers.json"));
        Ok(Node {
            chain,
            mempool: Mempool::new(),
            network,
            verifier: None,
            miner: None,
            fast_mining: false,
            addresses,
        })
    }

    /// ピアの住所帳。
    pub fn addresses(&self) -> &AddressBook {
        &self.addresses
    }

    /// ピアの住所帳 (書き換え可)。
    pub fn addresses_mut(&mut self) -> &mut AddressBook {
        &mut self.addresses
    }

    /// チェーン。
    pub fn chain(&self) -> &Chain<Store> {
        &self.chain
    }

    /// mempool。
    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    /// mempool (書き換え可能)。
    pub fn mempool_mut(&mut self) -> &mut Mempool {
        &mut self.mempool
    }

    /// 現在の様子。
    pub fn status(&self) -> Result<NodeStatus, NodeError> {
        let tip = self.chain.tip()?;
        Ok(NodeStatus {
            network: self.network,
            height: tip.height(),
            tip: tip.hash,
            cumulative_work: tip.cumulative_work,
            next_difficulty: self.chain.expected_difficulty_for_child_of(&tip.hash)?,
            utxo_count: self.chain.store().utxo_count()?,
            indexed_blocks: self.chain.indexed_blocks(),
            mempool_len: self.mempool.len(),
            known_addresses: self.addresses.len(),
        })
    }

    /// この高さのシードエポックに合う検証器を用意する。
    ///
    /// エポックが変わっていなければ何もしない。初期化には 256 MB の確保が
    /// 伴うため、毎ブロック作り直すわけにはいかない。
    fn ensure_verifier(&mut self, height: u64) -> Result<(), NodeError> {
        let wanted = seed_height(height);
        if self
            .verifier
            .as_ref()
            .is_some_and(|(current, _)| *current == wanted)
        {
            return Ok(());
        }
        let seed = self.seed_for(wanted)?;
        self.verifier = Some((wanted, RandomXVerifier::new(&seed, wanted)?));
        Ok(())
    }

    /// その高さの検証器を用意し、それを借りたまま `f` を走らせる。
    ///
    /// 検証器を一旦 `self` から取り出す。こうしないと、検証器を借りたまま
    /// チェーンを変更できない。`f` が失敗しても必ず戻す。
    fn with_verifier<T>(
        &mut self,
        height: u64,
        f: impl FnOnce(&mut Self, &RandomXVerifier) -> Result<T, NodeError>,
    ) -> Result<T, NodeError> {
        self.ensure_verifier(height)?;
        let (epoch, verifier) = self.verifier.take().expect("直前に用意した");
        let result = f(self, &verifier);
        self.verifier = Some((epoch, verifier));
        result
    }

    /// 他所から来たブロックを受け取る。
    pub fn accept_block(&mut self, block: Block, now: i64) -> Result<AcceptOutcome, NodeError> {
        let height = block.header.height;
        self.with_verifier(height, |node, verifier| {
            let outcome = node.chain.accept_block(block.clone(), verifier, now)?;
            if !matches!(outcome, AcceptOutcome::Duplicate) {
                node.mempool.on_block_connected(&block);
            }
            Ok(outcome)
        })
    }

    /// 他所から来たヘッダを受け取る。
    pub fn accept_header(
        &mut self,
        header: &BlockHeader,
        now: i64,
    ) -> Result<HeaderOutcome, NodeError> {
        let height = header.height;
        self.with_verifier(height, |node, verifier| {
            Ok(node.chain.accept_header(header, verifier, now)?)
        })
    }

    /// 次のブロックを掘る。
    ///
    /// `now` はノードの現在時刻 (Unix 秒)。`max_attempts` を試して見つから
    /// なければ諦めて戻る。呼び出し側が繰り返す。
    pub fn mine_next(
        &mut self,
        payout: &Lock,
        now: i64,
        max_attempts: u64,
    ) -> Result<MinedBlock, NodeError> {
        let tip = self.chain.tip()?;
        let height = tip.height() + 1;
        self.ensure_miner(height);
        // 採掘器も一旦取り出す。検証器と同じ理由で、借りたままチェーンを
        // 変更できないためである。失敗しても必ず戻す。
        let miner = self.miner.take();
        let result = self.with_verifier(height, |node, verifier| {
            let fast = miner.as_ref().map(|(_, m)| m);
            node.mine_with(verifier, fast, &tip.hash, height, payout, now, max_attempts)
        });
        self.miner = miner;
        result
    }

    /// fast モード (2 GB) で掘るようにする。
    ///
    /// データセットの構築に 1 分前後かかる。**ここで済ませておく。**
    /// 掘り始めてから固まったように見えるのを避けるためである。
    ///
    /// 2 GB を確保できなければ誤りを返す。呼び出し側は light モードの
    /// まま続けてよい。
    pub fn enable_fast_mining(&mut self, height: u64) -> Result<(), NodeError> {
        self.fast_mining = true;
        let wanted = seed_height(height);
        let seed = self.seed_for(wanted)?;
        self.miner = Some((wanted, RandomXMiner::new(&seed, wanted)?));
        Ok(())
    }

    /// fast モードで掘っているか。
    pub fn is_fast_mining(&self) -> bool {
        self.miner.is_some()
    }

    /// この高さのシードエポックに合う採掘器を用意する。
    ///
    /// fast モードでないなら何もしない。エポックが変わっていたら作り直す。
    /// **作り直しには 1 分前後かかり、その間は掘れない。** 2048 ブロック
    /// (約 34 時間) に 1 度である。
    ///
    /// 確保に失敗したら light モードに退き、以後 fast は試みない。
    /// 採掘そのものは続く。
    fn ensure_miner(&mut self, height: u64) {
        if !self.fast_mining {
            return;
        }
        let wanted = seed_height(height);
        if self.miner.as_ref().is_some_and(|(e, _)| *e == wanted) {
            return;
        }
        let built = self
            .seed_for(wanted)
            .and_then(|seed| Ok(RandomXMiner::new(&seed, wanted)?));
        match built {
            Ok(miner) => self.miner = Some((wanted, miner)),
            Err(e) => {
                eprintln!(
                    "fast モードのデータセットを用意できない: {e}\n\
                     light モード (256 MB) で採掘を続ける。速さはおよそ 6 分の 1 になる。"
                );
                self.fast_mining = false;
                self.miner = None;
            }
        }
    }

    /// そのシード高さのブロックハッシュ。
    fn seed_for(&self, seed_height: u64) -> Result<Hash, NodeError> {
        Ok(self
            .chain
            .hash_at_height(seed_height)?
            .unwrap_or(self.chain.tip()?.hash))
    }

    #[allow(clippy::too_many_arguments)]
    fn mine_with(
        &mut self,
        verifier: &RandomXVerifier,
        fast: Option<&RandomXMiner>,
        prev_hash: &Hash,
        height: u64,
        payout: &Lock,
        now: i64,
        max_attempts: u64,
    ) -> Result<MinedBlock, NodeError> {
        let difficulty = self.chain.expected_difficulty_for_child_of(prev_hash)?;
        let mtp = self.chain.median_time_past_for_child_of(prev_hash);

        // タイムスタンプは Median Time Past より後でなければならない。
        let timestamp = now.max(mtp + 1);
        if timestamp > now + params::MAX_FUTURE_TIME_DRIFT_SECS {
            return Err(NodeError::ClockTooFarBehind { mtp, now });
        }

        let mut attempts = 0u64;
        let mut extra_nonce: u64 = 0;

        while attempts < max_attempts {
            let request = TemplateRequest {
                prev_hash: *prev_hash,
                height,
                difficulty,
                timestamp,
                payout: payout.clone(),
                extra_nonce: extra_nonce.to_le_bytes().to_vec(),
            };
            let template = build_template(&request, &self.mempool)?;

            let batch = NONCE_BATCH.min(max_attempts - attempts);
            // 探すのは fast、確かめるのは light。どちらも同じハッシュを返す。
            let hasher: &dyn oag_miner::mine::PowHasher =
                fast.map_or(verifier as &dyn oag_miner::mine::PowHasher, |m| m);
            let outcome = oag_miner::mine(&template, hasher, 0, batch, &NeverStop)?;
            attempts += outcome.attempts();

            if let MiningOutcome::Found { block, .. } = outcome {
                let hash = block.header.hash();
                // 自分で掘ったものも、他所から来たものと同じ道を通す。
                let accepted = self
                    .chain
                    .accept_block(*block.clone(), verifier, timestamp)?;
                self.mempool.on_block_connected(&block);
                return match accepted {
                    AcceptOutcome::ExtendedTip | AcceptOutcome::Reorganized(_) => {
                        Ok(MinedBlock::Accepted {
                            hash,
                            height,
                            attempts,
                        })
                    }
                    other => Err(NodeError::SelfMinedRejected(other)),
                };
            }

            // この追加ノンスでは見つからなかった。組み直して続ける。
            extra_nonce = extra_nonce.wrapping_add(1);
        }

        Ok(MinedBlock::NotFound { attempts })
    }

    /// ブロックをファイルに書き出す。
    pub fn export_blocks(&self, dir: &Path) -> Result<usize, NodeError> {
        Ok(self.chain.store().export_blocks(dir)?)
    }
}
