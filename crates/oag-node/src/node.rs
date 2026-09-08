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

use oag_chain::chain::{AcceptOutcome, Chain, ChainError, HeaderOutcome};
use oag_consensus::lock::Lock;
use oag_consensus::params;
use oag_consensus::{Block, BlockHeader};
use oag_mempool::Mempool;
use oag_miner::mine::{MiningOutcome, NeverStop};
use oag_miner::{build_template, TemplateError, TemplateRequest};
use oag_pow::randomx::{RandomXPowError, RandomXVerifier};
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
    /// ジェネシスが確定していない。
    #[error(transparent)]
    Genesis(#[from] crate::genesis::GenesisUndecided),
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
    /// 現在のシードエポックの検証器。
    verifier: Option<(u64, RandomXVerifier)>,
}

impl Node {
    /// 記憶域を開き、必要ならジェネシスで初期化する。
    pub fn open(network: Network, data_dir: &Path) -> Result<Node, NodeError> {
        // ジェネシスを先に決める。確定していないネットワークで空の
        // データベースを作ってしまわないようにするためである。
        let genesis = crate::genesis::genesis_for(network)?;
        std::fs::create_dir_all(data_dir)
            .map_err(|e| StoreError::Io(format!("{} を作れない: {e}", data_dir.display())))?;
        let store = Store::open(data_dir.join("chain.redb"))?;
        let chain = Chain::open(store, genesis, network.genesis_difficulty())?;
        Ok(Node {
            chain,
            mempool: Mempool::new(),
            network,
            verifier: None,
        })
    }

    /// チェーン。
    pub fn chain(&self) -> &Chain<Store> {
        &self.chain
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
        let seed = self
            .chain
            .hash_at_height(wanted)?
            .unwrap_or(self.chain.tip()?.hash);
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
        self.with_verifier(height, |node, verifier| {
            node.mine_with(verifier, &tip.hash, height, payout, now, max_attempts)
        })
    }

    fn mine_with(
        &mut self,
        verifier: &RandomXVerifier,
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
            let outcome = oag_miner::mine(&template, verifier, 0, batch, &NeverStop)?;
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
