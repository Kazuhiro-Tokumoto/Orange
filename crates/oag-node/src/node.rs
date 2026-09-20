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
use oag_chain::chain::{AcceptOutcome, Chain, ChainError, HeaderOutcome, Reorg, Retarget};
use oag_consensus::lock::Lock;
use oag_consensus::params;
use oag_consensus::{Block, BlockHeader};
use oag_mempool::Mempool;
use oag_miner::{build_template, BlockTemplate, TemplateError, TemplateRequest};
use oag_pow::randomx::{RandomXPowError, RandomXVerifier};
use oag_pow::seed_height;
use oag_primitives::{Hash, Network};
use oag_store::{Store, StoreError};
use std::path::Path;

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
    /// RandomX のシードになるブロックを知らない。
    ///
    /// **ここで代わりのハッシュを使ってはならない。** 鍵が違えば RandomX は
    /// 違うハッシュを返し、正しいブロックの PoW が落ちる。
    #[error("高さ {seed_height} のブロックを知らないため、RandomX のシードを決められない")]
    UnknownSeedBlock {
        /// シードになるはずの高さ。
        seed_height: u64,
    },
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
    pub indexed_blocks: u64,
    /// mempool の件数。
    pub mempool_len: usize,
    /// 住所帳に覚えているピアの数。
    pub known_addresses: usize,
}

/// 掘れて、先端になったブロック。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinedBlock {
    /// 掘ったブロックのハッシュ。
    pub hash: Hash,
    /// 新しい高さ。
    pub height: u64,
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
            indexed_blocks: self.chain.indexed_blocks()?,
            mempool_len: self.mempool.len(),
            known_addresses: self.addresses.len(),
        })
    }

    /// この高さのシードエポックに合う検証器を用意する。
    ///
    /// `branch` は検証しようとしているブロックの**親**のハッシュである。
    /// シードはその枝の祖先から引く。`seed_height(h) < h` なので、シードは
    /// 必ず親か親の祖先にあたる。
    ///
    /// エポックが変わっていなければ何もしない。初期化には 256 MB の確保が
    /// 伴うため、毎ブロック作り直すわけにはいかない。
    ///
    /// **エポックが同じなら枝は見直さない。** 見直すには毎回祖先を辿る
    /// ことになり、初期同期の全体で効いてくる。シードのブロックは
    /// [`SEED_LAG`](oag_consensus::params::SEED_LAG) だけ後ろにあるので、
    /// それより浅いリオーグでシードは動かない (`docs/SPEC.md` §11.3)。
    fn ensure_verifier(&mut self, height: u64, branch: &Hash) -> Result<(), NodeError> {
        let wanted = seed_height(height);
        if self
            .verifier
            .as_ref()
            .is_some_and(|(current, _)| *current == wanted)
        {
            return Ok(());
        }
        let seed = self.seed_for(wanted, branch)?;
        let verifier = RandomXVerifier::new(&seed, wanted)?;
        if !verifier.uses_jit() {
            // JIT を使えない環境である。検証は動くが 10 倍ほど遅い。
            // 黙っていると「なぜか同期が進まない」に見えるので伝える。
            crate::log_warn!(
                "RandomX の JIT を使えないため、インタプリタで検証する ({:?})。\n                 動作はするが、ブロックの検証がおよそ 10 倍遅くなる。\n                 実行可能メモリを禁じる設定 (SELinux の deny_execmem など) が\n                 掛かっていないか確かめること。",
                verifier.flags()
            );
        }
        crate::log_verify!(
            "RandomX のシードを高さ {wanted} のブロック {} に切り替えた",
            crate::log::short(&seed)
        );
        self.verifier = Some((wanted, verifier));
        Ok(())
    }

    /// その高さの検証器を用意し、それを借りたまま `f` を走らせる。
    ///
    /// 検証器を一旦 `self` から取り出す。こうしないと、検証器を借りたまま
    /// チェーンを変更できない。`f` が失敗しても必ず戻す。
    fn with_verifier<T>(
        &mut self,
        height: u64,
        branch: &Hash,
        f: impl FnOnce(&mut Self, &RandomXVerifier) -> Result<T, NodeError>,
    ) -> Result<T, NodeError> {
        self.ensure_verifier(height, branch)?;
        let (epoch, verifier) = self.verifier.take().expect("直前に用意した");
        let result = f(self, &verifier);
        self.verifier = Some((epoch, verifier));
        result
    }

    /// 他所から来たブロックを受け取る。
    pub fn accept_block(&mut self, block: Block, now: i64) -> Result<AcceptOutcome, NodeError> {
        let height = block.header.height;
        let branch = block.header.prev_hash;
        let outcome = self.with_verifier(height, &branch, |node, verifier| {
            Ok(node.chain.accept_block(block.clone(), verifier, now)?)
        })?;
        self.sync_mempool(&outcome, &block)?;
        Ok(outcome)
    }

    /// ブロックを受け取った結果に合わせて mempool を直す。
    ///
    /// mempool は**アクティブチェーンの先を写したもの**である。先端が動いた
    /// ときだけ直す。
    fn sync_mempool(&mut self, outcome: &AcceptOutcome, block: &Block) -> Result<(), NodeError> {
        match outcome {
            // 知っていたもの。
            AcceptOutcome::Duplicate => Ok(()),
            // **負けた枝に入っただけのものは外さない。** そのブロックは
            // アクティブチェーンに無く、入っているトランザクションは依然
            // 未確認である。ここで外すと、まだ有効な支払いを中継しなくなり、
            // 自分が掘るときにも詰めなくなる。
            AcceptOutcome::SideChain => Ok(()),
            AcceptOutcome::ExtendedTip => {
                self.mempool.on_block_connected(block);
                Ok(())
            }
            AcceptOutcome::Reorganized(reorg) => self.rebuild_mempool(reorg),
        }
    }

    /// リオーグの後、mempool を組み直す。
    ///
    /// 取り消された枝のトランザクションを集めて戻し、残っているものも含めて
    /// リオーグ後の UTXO で検証し直す ([`Mempool::rebuild_after_reorg`])。
    ///
    /// 受け取ったブロック 1 個だけを見て済ませるわけにはいかない。リオーグ
    /// では複数のブロックが一度に繋がり、同時に複数が取り消されるためで
    /// ある。取り消された枝にあった支払いを戻さなければ、それは誰の mempool
    /// にも無いまま消える。新しい枝で確認済みになったものを外さなければ、
    /// 次に自分で掘るブロックがその分だけ無効になる。
    fn rebuild_mempool(&mut self, reorg: &Reorg) -> Result<(), NodeError> {
        let orphaned = orphaned_transactions(reorg, |hash| self.chain.store().block(hash))?;

        let tip = self.chain.tip()?;
        let next_height = tip.height() + 1;
        let median_time_past = self.chain.median_time_past_for_child_of(&tip.hash)?;
        let view = self.chain.utxo_view()?;
        self.mempool
            .rebuild_after_reorg(orphaned, &view, next_height, median_time_past);
        Ok(())
    }

    /// 他所から来たヘッダを受け取る。
    pub fn accept_header(
        &mut self,
        header: &BlockHeader,
        now: i64,
    ) -> Result<HeaderOutcome, NodeError> {
        let height = header.height;
        let branch = header.prev_hash;
        self.with_verifier(height, &branch, |node, verifier| {
            Ok(node.chain.accept_header(header, verifier, now)?)
        })
    }

    /// 次のブロックを掘る土台を組む。
    ///
    /// `now` はノードの現在時刻 (Unix 秒)。組んだ土台は
    /// [`MiningPool`](oag_miner::MiningPool) に配る。**組むのはここ、
    /// 探すのは作業スレッドである。** チェーンと mempool に触るのは
    /// ノードのスレッドだけに保つ。
    ///
    /// 時計が Median Time Past より大きく遅れていると組めない。掘れても
    /// 他のノードが撥ねるブロックにしかならないためである。
    pub fn mining_template(
        &self,
        payout: &Lock,
        now: i64,
        extra_nonce: u64,
    ) -> Result<BlockTemplate, NodeError> {
        let tip = self.chain.tip()?;
        let prev_hash = tip.hash;
        let height = tip.height() + 1;
        let difficulty = self.chain.expected_difficulty_for_child_of(&prev_hash)?;
        let mtp = self.chain.median_time_past_for_child_of(&prev_hash)?;

        // タイムスタンプは Median Time Past より後でなければならない。
        let timestamp = now.max(mtp + 1);
        if timestamp > now + params::MAX_FUTURE_TIME_DRIFT_SECS {
            return Err(NodeError::ClockTooFarBehind { mtp, now });
        }

        let request = TemplateRequest {
            prev_hash,
            height,
            difficulty,
            timestamp,
            payout: payout.clone(),
            extra_nonce: extra_nonce.to_le_bytes().to_vec(),
        };
        Ok(build_template(&request, &self.mempool)?)
    }

    /// 自分で掘ったブロックを自分のチェーンに入れる。
    ///
    /// **他所から来たものと同じ道を通す。** 掘った側だからといって検証を
    /// 省かない。省けば、自分だけが正しいと思っているブロックを撒くことに
    /// なる。
    ///
    /// 先端にならなかったときは [`NodeError::SelfMinedRejected`] を返す。
    pub fn accept_mined(&mut self, block: Block, now: i64) -> Result<MinedBlock, NodeError> {
        let hash = block.header.hash();
        let height = block.header.height;
        match self.accept_block(block, now)? {
            AcceptOutcome::ExtendedTip | AcceptOutcome::Reorganized(_) => {
                Ok(MinedBlock { hash, height })
            }
            other => Err(NodeError::SelfMinedRejected(other)),
        }
    }

    /// 次のブロックを掘るときの RandomX シード (高さと値)。
    ///
    /// 採掘器はこれで建てる。**エポックが変われば建て直しである。**
    /// 呼び出し側は返ってきた高さを覚えておき、変わったかどうかを見る。
    pub fn mining_seed(&self) -> Result<(u64, Hash), NodeError> {
        let tip = self.chain.tip()?;
        let wanted = seed_height(tip.height() + 1);
        Ok((wanted, self.seed_for(wanted, &tip.hash)?))
    }

    /// `branch` の枝で、そのシード高さにあたるブロックハッシュ。
    ///
    /// **アクティブチェーンの高さの索引では引けない。** headers-first の
    /// 同期では、ヘッダが高さ数千まで届いていても本体が 1 つも繋がって
    /// いない時期がある。その間アクティブチェーンの高さは 0 のままなので、
    /// 索引は知っているはずのシードにも `None` を返す。
    ///
    /// 以前はそこで先端のハッシュを代わりに使っていた。鍵が違えば RandomX は
    /// 違うハッシュを返すので、**正しいヘッダの PoW が全部落ちる**。最初の
    /// エポック境界 (高さ 2112) で同期が止まり、二度と先へ進めなくなる。
    fn seed_for(&self, seed_height: u64, branch: &Hash) -> Result<Hash, NodeError> {
        // 最初のエポックのシードはジェネシスのハッシュであり、枝によらない。
        // 高さ 2112 未満はすべてここを通る。
        if seed_height == 0 {
            return self
                .chain
                .hash_at_height(0)?
                .ok_or(NodeError::UnknownSeedBlock { seed_height });
        }
        // 親を知らなければシードも決められないが、**断る理由はシードでは
        // なく親である**。そのまま名乗る。
        if !self.chain.contains(branch)? {
            return Err(ChainError::UnknownParent(*branch).into());
        }
        self.chain
            .ancestor_hash_at(branch, seed_height)?
            .ok_or(NodeError::UnknownSeedBlock { seed_height })
    }

    /// ブロックをファイルに書き出す。
    pub fn export_blocks(&self, dir: &Path) -> Result<usize, NodeError> {
        Ok(self.chain.store().export_blocks(dir)?)
    }
}

/// 取り消された枝に入っていたトランザクションを、**古い順に**集める。
///
/// `Reorg::disconnected` は先端に近い順に並んでいる。そのまま戻すと子が親
/// より先になり、親をまだ知らない時点で子を検証することになる。逆から見る。
///
/// コインベースは戻さない。取り消された枝のコインベースはもう存在しない
/// 報酬であり、mempool は受け付けない (`docs/SPEC.md` §10.6)。
///
/// 本体を持っていないブロックは飛ばす。取り消したばかりの枝なので通常は
/// 揃っているが、揃っていないことを失敗にはしない。戻せなかった支払いは
/// 送った側が送り直せるが、ここで止まるとノードが先へ進めない。
fn orphaned_transactions(
    reorg: &Reorg,
    mut block_of: impl FnMut(&Hash) -> Result<Option<Block>, StoreError>,
) -> Result<Vec<oag_consensus::Transaction>, NodeError> {
    let mut orphaned = Vec::new();
    for hash in reorg.disconnected.iter().rev() {
        if let Some(block) = block_of(hash)? {
            orphaned.extend(Mempool::transactions_to_resubmit(&block));
        }
    }
    Ok(orphaned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_consensus::tx::{OutPoint, TxInput, CURRENT_TX_VERSION};
    use oag_consensus::{Transaction, TxOutput};
    use oag_primitives::hash;
    use std::collections::HashMap;

    /// 指定した親を使うトランザクション。`tag` を変えれば別の txid になる。
    fn spending(tag: &[u8], parent: Hash) -> Transaction {
        let mut input = TxInput::new(OutPoint::new(parent, 0));
        input.signature = tag.to_vec();
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: vec![TxOutput::new("1".parse().unwrap(), Lock::unspendable())],
            locktime: 0,
        }
    }

    fn coinbase(tag: &[u8]) -> Transaction {
        let mut input = TxInput::new(OutPoint::null());
        input.signature = tag.to_vec();
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: vec![TxOutput::new("50".parse().unwrap(), Lock::unspendable())],
            locktime: 0,
        }
    }

    fn block_of(transactions: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_hash: Hash::ZERO,
                merkle_root: Hash::ZERO,
                timestamp: 0,
                difficulty: 1,
                height: 0,
                nonce: 0,
            },
            transactions,
        }
    }

    #[test]
    fn the_undone_branch_is_collected_oldest_first() {
        // `disconnected` は先端に近い順である。そのまま戻すと、子が親より
        // 先に来る。
        let parent = spending(b"parent", hash::txid(b"funding"));
        let child = spending(b"child", parent.txid());
        let older = block_of(vec![coinbase(b"cb1"), parent.clone()]);
        let newer = block_of(vec![coinbase(b"cb2"), child.clone()]);

        let blocks: HashMap<Hash, Block> =
            HashMap::from([(hash::txid(b"older"), older), (hash::txid(b"newer"), newer)]);
        let reorg = Reorg {
            // 先端に近い順。
            disconnected: vec![hash::txid(b"newer"), hash::txid(b"older")],
            connected: Vec::new(),
        };

        let orphaned = orphaned_transactions(&reorg, |h| Ok(blocks.get(h).cloned())).unwrap();

        assert_eq!(
            orphaned,
            vec![parent, child],
            "古い順に並んでいない (親より子が先に来ている)"
        );
    }

    #[test]
    fn a_coinbase_from_the_undone_branch_is_not_put_back() {
        // 取り消した枝のコインベースはもう存在しない報酬である。
        let payment = spending(b"payment", hash::txid(b"funding"));
        let block = block_of(vec![coinbase(b"cb"), payment.clone()]);
        let blocks: HashMap<Hash, Block> = HashMap::from([(hash::txid(b"only"), block)]);
        let reorg = Reorg {
            disconnected: vec![hash::txid(b"only")],
            connected: Vec::new(),
        };

        let orphaned = orphaned_transactions(&reorg, |h| Ok(blocks.get(h).cloned())).unwrap();

        assert_eq!(orphaned, vec![payment]);
    }

    #[test]
    fn a_missing_body_does_not_stop_the_reorg() {
        let reorg = Reorg {
            disconnected: vec![hash::txid(b"gone")],
            connected: Vec::new(),
        };

        let orphaned = orphaned_transactions(&reorg, |_| Ok(None)).unwrap();

        assert!(orphaned.is_empty());
    }
}
