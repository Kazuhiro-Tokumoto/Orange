//! ノードを専用の作業スレッドに載せ、非同期側から使えるようにする。
//!
//! # なぜスレッドを分けるのか
//!
//! RandomX の検証器は `Send` ではない。仮想機械の状態を持つため、作った
//! スレッドの上でしか使えない。したがってチェーンの状態も、それを触る
//! 一連の処理も、**動かないスレッドの上に置く**必要がある。
//!
//! ```text
//!  非同期 (tokio)                     専用スレッド
//! ┌──────────────┐   要求 (mpsc)   ┌──────────────────┐
//! │ ピアとの通信 │ ──────────────▶ │ Node             │
//! │ 待ち受け     │ ◀────────────── │  チェーン        │
//! └──────────────┘   応答 (oneshot) │  mempool         │
//!        ▲                          │  RandomX 検証器  │
//!        └── 報せ (broadcast) ───────│  採掘            │
//!                                   └──────────────────┘
//! ```
//!
//! # 採掘と応答の兼ね合い
//!
//! 専用スレッドは採掘もする。掘りっぱなしでは要求に答えられないため、
//! **少数の nonce を試すごとに要求を捌く**。応答が遅れる上限が
//! 少数の nonce 分の計算時間になる。

use crate::node::{MinedBlock, Node, NodeError, NodeStatus};
use oag_chain::chain::{AcceptOutcome, HeaderOutcome};
use oag_chain::index::BlockIndexEntry;
use oag_consensus::lock::Lock;
use oag_consensus::tx::{OutPoint, TxOutput};
use oag_consensus::utxo::UtxoEntry;
use oag_consensus::{Block, BlockHeader, Transaction};
use oag_miner::pool::{HasherFactory, MiningPool};
use oag_miner::PowHasher;
use oag_net::message::NetAddress;
use oag_net::message::MAX_HEADERS;
use oag_net::sync::{BlockDownload, PeerId, TxRequests};
use oag_pow::randomx::{RandomXMiner, RandomXVerifier};
use oag_primitives::{Hash, Network};
use oag_store::{BlockSummary, IndexStats, TxLocation};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, oneshot};

/// 当たりを待ちながら要求を捌き直すまでの間。
///
/// 採掘そのものは作業スレッドが回しているので、ノードのスレッドはここで
/// 眠っていられる。短すぎると起きるだけで CPU を使い、長すぎると要求への
/// 応答が遅れる。
const MINING_POLL: Duration = Duration::from_millis(20);

/// 掘る土台を組み直すまでの間。
///
/// 先端が動いたときは待たずに組み直す。これは**それ以外の理由**、つまり
/// mempool に取引が増えたことと、ヘッダの時刻が古くなることのためである。
const TEMPLATE_REFRESH: Duration = Duration::from_secs(10);

/// fast モードのデータセット 1 個分の目安 (GB)。運用者への表示に使う。
const DATASET_GIB: f64 = oag_pow::randomx::DATASET_BYTES as f64 / (1 << 30) as f64;

/// 報せを溜めておける数。
///
/// 溜まりきったピアは古い報せを取り落とす。取り落としても、次の報せか
/// 定期の問い合わせで追いつける。
const EVENT_CAPACITY: usize = 256;

/// 要求を溜めておける数。
const REQUEST_CAPACITY: usize = 1_024;

/// 終了を伝えるのを諦めるまでの試行回数。
const SHUTDOWN_ATTEMPTS: usize = 100;

/// 採掘のやり方。
///
/// スレッドを増やすと、その数だけ RandomX の採掘器が要る。**採掘器は
/// スレッドをまたげない**ので、共有はできない (`oag-miner` の `pool`
/// モジュールを見よ)。memory は掛け算で効く。
///
/// | モード | 1 スレッドあたり | 4 スレッドなら |
/// | --- | ---: | ---: |
/// | light | 256 MB | 1 GB |
/// | fast | 2 GB | 8 GB |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MiningMode {
    /// fast モード (2 GB) を使うか。
    pub fast: bool,
    /// 何スレッドで掘るか。`0` なら機械に合わせて決める。
    pub threads: usize,
}

impl Default for MiningMode {
    /// light モード、1 スレッド。**積んでいる memory を当てにしない。**
    fn default() -> MiningMode {
        MiningMode {
            fast: false,
            threads: 1,
        }
    }
}

impl MiningMode {
    /// light モードで 1 スレッド。
    pub fn light() -> MiningMode {
        MiningMode::default()
    }

    /// fast モードで 1 スレッド。
    pub fn fast() -> MiningMode {
        MiningMode {
            fast: true,
            threads: 1,
        }
    }

    /// スレッド数を指定する。
    pub fn with_threads(self, threads: usize) -> MiningMode {
        MiningMode { threads, ..self }
    }

    /// 実際に起こすスレッドの数。
    ///
    /// `threads` が `0` のときだけ機械を見る。**fast モードでは増やさない。**
    /// 1 本あたり 2 GB 要るのに、積んでいる量が分からないためである。
    /// 増やしたければ本数を明示する。
    pub fn resolved_threads(self) -> NonZeroUsize {
        if let Some(threads) = NonZeroUsize::new(self.threads) {
            return threads;
        }
        if self.fast {
            return NonZeroUsize::MIN;
        }
        std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN)
    }
}

/// ノードからの報せ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvent {
    /// アクティブチェーンの先端が変わった。
    NewTip {
        /// 新しい先端。
        hash: Hash,
        /// 新しい高さ。
        height: u64,
        /// このブロックをくれたピア。自分で掘ったなら `None`。
        ///
        /// **このピアには報せ直さない。** 相手は既に持っている。
        from: Option<PeerId>,
    },
    /// mempool に新しいトランザクションが入った。
    ///
    /// **検証を通ったものだけがここに来る。** 受け付けなかったものを
    /// 流すことはない。
    NewTx {
        /// トランザクション ID。
        txid: Hash,
        /// これをくれたピア。自分の財布から出したなら `None`。
        from: Option<PeerId>,
    },
    /// 採掘が止まった (指定した数だけ掘り終えた、または失敗した)。
    MiningStopped,
    /// 新たに到達を確かめた住所。
    ///
    /// 繋がっているピアに流す。**これがピア発見の伝わり方である。**
    /// `getaddr` は 1 本の接続につき 1 度しか応えないので、あとから
    /// 判明した住所はこの経路で伝える。
    NewAddress(NetAddress),
}

/// 繋ぎに行った結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialOutcome {
    /// 繋がった。
    Connected,
    /// 繋がらなかった。
    Failed,
}

/// ブロックを受け取った結果 (非同期側に返す形)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockAccepted {
    /// チェーンとしての結果。
    pub outcome: AcceptOutcome,
    /// この結果、先端が動いたか。
    pub moved_tip: bool,
}

/// ヘッダの列を受け取った結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadersAccepted {
    /// 初めて見たヘッダの数。
    pub new: usize,
    /// 受け取ったヘッダの総数。
    pub total: usize,
}

/// 専用スレッドへの要求。
enum Request {
    Status(oneshot::Sender<Result<NodeStatus, String>>),
    /// 自分の状態を名乗るための、先端の高さ。
    BestHeaderHeight(oneshot::Sender<Result<u64, String>>),
    /// ブロックロケータ。
    Locator(oneshot::Sender<Result<Vec<Hash>, String>>),
    /// `getheaders` への応答。
    HeadersAfter {
        locator: Vec<Hash>,
        stop: Hash,
        reply: oneshot::Sender<Result<Vec<BlockHeader>, String>>,
    },
    /// 受け取ったヘッダの列を取り込む。
    AcceptHeaders {
        headers: Vec<BlockHeader>,
        reply: oneshot::Sender<Result<HeadersAccepted, String>>,
    },
    /// 受け取ったブロックを取り込む。
    AcceptBlock {
        block: Box<Block>,
        /// どのピアからもらったか。自分で掘ったなら `None`。
        from: Option<PeerId>,
        reply: oneshot::Sender<Result<BlockAccepted, String>>,
    },
    /// ブロックの実体を引く。
    GetBlock {
        hash: Hash,
        reply: oneshot::Sender<Result<Option<Block>, String>>,
    },
    /// このピアに次に頼む本体を割り振る。
    AssignDownloads {
        peer: PeerId,
        now: i64,
        reply: oneshot::Sender<Result<Vec<Hash>, String>>,
    },
    /// ピアが「そのブロックは持っていない」と答えた。待ち行列に戻す。
    BlocksNotFound {
        peer: PeerId,
        hashes: Vec<Hash>,
    },
    /// ピアが切れた。頼んでいた分を待ち行列に戻す。
    PeerGone(PeerId),
    /// 採掘を始める、または止める。
    SetMining {
        /// 受取先。`None` で止める。
        payout: Option<Lock>,
        /// この数だけ掘ったら止める。`None` なら止まらない。
        blocks: Option<u64>,
        /// 掘り方。
        mode: MiningMode,
    },
    /// 聞いた住所を住所帳に入れる。
    AddAddresses {
        /// 聞いた住所。
        addrs: Vec<NetAddress>,
        /// 教えてくれた相手。`new` 表のどのバケットに入るかを決める。
        /// **これが無いと、1 つの相手が `new` 表の好きな場所を狙える。**
        source: Option<SocketAddr>,
    },
    /// `getaddr` に返す住所を選ぶ。
    AddressesToShare(oneshot::Sender<Result<Vec<NetAddress>, String>>),
    /// 次に繋ぎに行く候補を選ぶ。
    AddressCandidates {
        /// 欲しい件数。
        want: usize,
        /// いま繋がっている・繋ぎに行っている住所。返さない。
        busy: Vec<SocketAddr>,
        /// 返す先。
        reply: oneshot::Sender<Result<Vec<SocketAddr>, String>>,
    },
    /// 繋ぎに行った結果を記録する。
    AddressOutcome {
        /// 相手。
        addr: SocketAddr,
        /// 結果。
        outcome: DialOutcome,
    },
    /// 自分自身の住所を登録する。以後これを覚えない。
    OwnAddresses(Vec<SocketAddr>),
    /// 自分自身の住所を引く。ピアに名乗るために使う。
    GetOwnAddresses(oneshot::Sender<Result<Vec<SocketAddr>, String>>),
    /// 住所帳をファイルに書き出す。
    SaveAddresses,
    /// 高さからブロックハッシュを引く。
    HashAtHeight {
        height: u64,
        reply: oneshot::Sender<Result<Option<Hash>, String>>,
    },
    /// 先端から遡って何件かの要約を、新しい順に引く。
    RecentBlocks {
        max: usize,
        reply: oneshot::Sender<Result<Vec<BlockSummary>, String>>,
    },
    /// インデックスの 1 件を引く。
    GetEntry {
        hash: Hash,
        reply: oneshot::Sender<Result<Option<BlockIndexEntry>, String>>,
    },
    /// トランザクションを mempool に入れる。
    SubmitTx {
        tx: Box<Transaction>,
        /// どのピアからもらったか。自分の財布から出したなら `None`。
        ///
        /// ピアから来たものは、**そのピアに頼んであった場合だけ**検証する。
        from: Option<PeerId>,
        reply: oneshot::Sender<Result<Hash, String>>,
    },
    /// ピアが `inv` で知らせてきたトランザクションのうち、要るものを選ぶ。
    ///
    /// すでに mempool にあるもの、すでに誰かに頼んであるものは外す。
    /// 返ってきた分だけ `getdata` で求める。
    WantTxs {
        peer: PeerId,
        txids: Vec<Hash>,
        now: i64,
        reply: oneshot::Sender<Result<Vec<Hash>, String>>,
    },
    /// mempool の中身。
    MempoolTxids(oneshot::Sender<Result<Vec<Hash>, String>>),
    /// mempool のトランザクションを引く。
    MempoolTx {
        txid: Hash,
        reply: oneshot::Sender<Result<Option<Transaction>, String>>,
    },
    /// 支払い条件が一致する UTXO を集める。
    ScanUtxos {
        locks: Vec<Lock>,
        max: usize,
        reply: oneshot::Sender<Result<Vec<UtxoRecord>, String>>,
    },
    /// 索引がどの高さから作られているか。
    IndexFrom(oneshot::Sender<Result<Option<u64>, String>>),
    /// txid から確定した取引を引く。索引が要る。
    TxRecord {
        txid: Hash,
        reply: oneshot::Sender<Result<Option<TxRecord>, String>>,
    },
    /// 支払い条件に触れた取引を古い順に引く。索引が要る。
    AddressHistory {
        lock: Lock,
        from: u64,
        max: usize,
        reply: oneshot::Sender<Result<Vec<TxRecord>, String>>,
    },
    /// 索引を作る、または組み直す。
    BuildIndex(oneshot::Sender<Result<IndexStats, String>>),
    /// 索引を捨てる。
    DropIndex(oneshot::Sender<Result<(), String>>),
    /// 作業スレッドを終わらせる。
    Shutdown,
}

/// 走査で見つかった UTXO の 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoRecord {
    /// 出力の参照。
    pub outpoint: OutPoint,
    /// 出力の中身と、生成された高さ。
    pub entry: UtxoEntry,
}

/// 索引が見つけた、確定した取引の 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxRecord {
    /// どこに入っているか。
    pub location: TxLocation,
    /// 取引そのもの。
    pub tx: Transaction,
    /// 各入力が指している出力。入力と同じ並び。
    ///
    /// **これが無いと入力側の金額も相手も表示できない。** 入力は
    /// `OutPoint` しか持たず、指している出力は UTXO セットから消えて
    /// いるためである。コインベースでは `None` が並ぶ。
    pub spent: Vec<Option<TxOutput>>,
}

/// 非同期側から専用スレッドを使うための取っ手。
///
/// 複製して各ピアに渡せる。
#[derive(Clone)]
pub struct NodeHandle {
    tx: mpsc::Sender<Request>,
    events: broadcast::Sender<NodeEvent>,
    network: Network,
    nonce: u64,
}

/// 自己接続を見分けるための乱数を作る。
///
/// **ノードごとに 1 つ**である。プロセスごとにすると、1 つのプロセスで
/// 2 台を動かしたときに互いを自分自身と見なしてしまう。
///
/// 秘密である必要はないが、時刻から作ると同時に起こした 2 台が同じ値を
/// 引きうる。鍵と同じ乱数源から取る。
fn make_nonce() -> u64 {
    let bytes = oag_primitives::SecretKey::generate().to_bytes();
    u64::from_le_bytes(bytes[..8].try_into().expect("32 バイトある"))
}

/// 専用スレッドが死んだときの文言。
fn gone() -> String {
    "ノードの作業スレッドが応答しない".to_string()
}

impl NodeHandle {
    /// このノードのネットワーク。
    pub fn network(&self) -> Network {
        self.network
    }

    /// 自己接続を見分けるための乱数。
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// 報せを受け取る口を開く。
    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.events.subscribe()
    }

    async fn ask<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<T, String>>) -> Request,
    ) -> Result<T, String> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(make(tx)).await.map_err(|_| gone())?;
        rx.await.map_err(|_| gone())?
    }

    async fn tell(&self, request: Request) -> Result<(), String> {
        self.tx.send(request).await.map_err(|_| gone())
    }

    /// 現在の様子。
    pub async fn status(&self) -> Result<NodeStatus, String> {
        self.ask(Request::Status).await
    }

    /// 最良ヘッダの高さ。
    pub async fn best_header_height(&self) -> Result<u64, String> {
        self.ask(Request::BestHeaderHeight).await
    }

    /// ブロックロケータ。
    pub async fn locator(&self) -> Result<Vec<Hash>, String> {
        self.ask(Request::Locator).await
    }

    /// `getheaders` に応えるヘッダの列。
    pub async fn headers_after(
        &self,
        locator: Vec<Hash>,
        stop: Hash,
    ) -> Result<Vec<BlockHeader>, String> {
        self.ask(|reply| Request::HeadersAfter {
            locator,
            stop,
            reply,
        })
        .await
    }

    /// ヘッダの列を取り込む。
    pub async fn accept_headers(
        &self,
        headers: Vec<BlockHeader>,
    ) -> Result<HeadersAccepted, String> {
        self.ask(|reply| Request::AcceptHeaders { headers, reply })
            .await
    }

    /// ブロックを取り込む。
    pub async fn accept_block(&self, block: Block) -> Result<BlockAccepted, String> {
        self.accept_block_from(block, None).await
    }

    /// ブロックを受け取る。くれたピアを添える。
    ///
    /// そのピアには報せ直さない。相手は既に持っている。
    pub async fn accept_block_from(
        &self,
        block: Block,
        from: Option<PeerId>,
    ) -> Result<BlockAccepted, String> {
        self.ask(|reply| Request::AcceptBlock {
            block: Box::new(block),
            from,
            reply,
        })
        .await
    }

    /// ブロックの実体を引く。
    pub async fn block(&self, hash: Hash) -> Result<Option<Block>, String> {
        self.ask(|reply| Request::GetBlock { hash, reply }).await
    }

    /// このピアに次に頼む本体を割り振る。
    pub async fn assign_downloads(&self, peer: PeerId, now: i64) -> Result<Vec<Hash>, String> {
        self.ask(|reply| Request::AssignDownloads { peer, now, reply })
            .await
    }

    /// ピアが「持っていない」と答えたブロックを待ち行列に戻す。
    ///
    /// **戻さないと、返事は来ているのに時間切れまで待つことになる。**
    pub async fn blocks_not_found(&self, peer: PeerId, hashes: Vec<Hash>) -> Result<(), String> {
        self.tell(Request::BlocksNotFound { peer, hashes }).await
    }

    /// ピアが切れたことを伝える。
    pub async fn peer_gone(&self, peer: PeerId) -> Result<(), String> {
        self.tell(Request::PeerGone(peer)).await
    }

    /// `addr` で聞いた住所を住所帳に入れる。
    ///
    /// `source` は教えてくれた相手。住所帳の `new` 表でどのバケットに
    /// 入るかがこれで決まる。
    pub async fn add_addresses(
        &self,
        addrs: Vec<NetAddress>,
        source: Option<SocketAddr>,
    ) -> Result<(), String> {
        self.tell(Request::AddAddresses { addrs, source }).await
    }

    /// `getaddr` に返す住所。
    pub async fn addresses_to_share(&self) -> Result<Vec<NetAddress>, String> {
        self.ask(Request::AddressesToShare).await
    }

    /// 次に繋ぎに行く候補を、最大 `want` 件。
    ///
    /// `busy` はいま繋がっている・繋ぎに行っている住所。返らない。
    pub async fn address_candidates(
        &self,
        want: usize,
        busy: Vec<SocketAddr>,
    ) -> Result<Vec<SocketAddr>, String> {
        self.ask(|reply| Request::AddressCandidates { want, busy, reply })
            .await
    }

    /// 繋ぎに行った結果を記録する。
    pub async fn address_outcome(
        &self,
        addr: SocketAddr,
        outcome: DialOutcome,
    ) -> Result<(), String> {
        self.tell(Request::AddressOutcome { addr, outcome }).await
    }

    /// 自分自身の住所を登録する。
    pub async fn set_own_addresses(&self, addrs: Vec<SocketAddr>) -> Result<(), String> {
        self.tell(Request::OwnAddresses(addrs)).await
    }

    /// ピアに名乗る自分自身の住所。
    pub async fn own_addresses(&self) -> Result<Vec<SocketAddr>, String> {
        self.ask(Request::GetOwnAddresses).await
    }

    /// 住所帳を書き出す。
    pub async fn save_addresses(&self) -> Result<(), String> {
        self.tell(Request::SaveAddresses).await
    }

    /// 採掘を始める。
    ///
    /// `blocks` を与えると、その数だけ掘ったところで止まり
    /// [`NodeEvent::MiningStopped`] を報せる。**すでに掘った数とは無関係に、
    /// ここから数える。** 止まったあとに掘り増したいときも同じ呼び方で
    /// 済む。
    ///
    /// `mode` で掘り方を決める ([`MiningMode`])。fast モードを立てると
    /// 2 GB のデータセットを構築してから掘る。light モードより速い
    /// (何倍かは機械による。[`RandomXMiner`] を見よ)。**構築に 1 分前後
    /// かかり、その間ノードは他の要求に応えない。** 確保できなければ
    /// light モードで掘る。
    ///
    /// スレッドを増やすと、その数だけ採掘器を建てる。**memory は掛け算で
    /// 効く。**
    ///
    /// [`RandomXMiner`]: oag_pow::randomx::RandomXMiner
    pub async fn start_mining(
        &self,
        payout: Lock,
        blocks: Option<u64>,
        mode: MiningMode,
    ) -> Result<(), String> {
        self.tell(Request::SetMining {
            payout: Some(payout),
            blocks,
            mode,
        })
        .await
    }

    /// 採掘を止める。
    pub async fn stop_mining(&self) -> Result<(), String> {
        self.tell(Request::SetMining {
            payout: None,
            blocks: None,
            mode: MiningMode::light(),
        })
        .await
    }

    /// アクティブチェーンの、その高さのブロックハッシュ。
    pub async fn hash_at_height(&self, height: u64) -> Result<Option<Hash>, String> {
        self.ask(|reply| Request::HashAtHeight { height, reply })
            .await
    }

    /// 先端から遡って `max` 件ぶんの要約。新しい順。
    ///
    /// 一覧を描くためのもの。高さごとに往復する代わりに 1 回で済み、
    /// 返ってくる並びは**ひとつの断面**である。
    pub async fn recent_blocks(&self, max: usize) -> Result<Vec<BlockSummary>, String> {
        self.ask(|reply| Request::RecentBlocks { max, reply }).await
    }

    /// インデックスの 1 件。
    pub async fn entry(&self, hash: Hash) -> Result<Option<BlockIndexEntry>, String> {
        self.ask(|reply| Request::GetEntry { hash, reply }).await
    }

    /// トランザクションを mempool に入れる。
    pub async fn submit_tx(&self, tx: Transaction) -> Result<Hash, String> {
        self.submit_tx_from(tx, None).await
    }

    /// ピアから来たトランザクションを mempool に入れる。
    ///
    /// **頼んでいなかったものは検証せずに断る。** 署名の検証は重い。
    /// 頼んだ覚えのないものを検証するのは、相手に計算を命じられて
    /// いるのと変わらない。
    pub async fn submit_tx_from(
        &self,
        tx: Transaction,
        from: Option<PeerId>,
    ) -> Result<Hash, String> {
        self.ask(|reply| Request::SubmitTx {
            tx: Box::new(tx),
            from,
            reply,
        })
        .await
    }

    /// `inv` で知らされた txid のうち、取り寄せるものを選ぶ。
    pub async fn want_txs(&self, peer: PeerId, txids: Vec<Hash>) -> Result<Vec<Hash>, String> {
        let now = now();
        self.ask(|reply| Request::WantTxs {
            peer,
            txids,
            now,
            reply,
        })
        .await
    }

    /// mempool にある txid の一覧。
    pub async fn mempool_txids(&self) -> Result<Vec<Hash>, String> {
        self.ask(Request::MempoolTxids).await
    }

    /// mempool のトランザクション。
    pub async fn mempool_tx(&self, txid: Hash) -> Result<Option<Transaction>, String> {
        self.ask(|reply| Request::MempoolTx { txid, reply }).await
    }

    /// 索引がどの高さから作られているか。持っていなければ `None`。
    pub async fn index_from(&self) -> Result<Option<u64>, String> {
        self.ask(Request::IndexFrom).await
    }

    /// 索引を作る、または組み直す。
    ///
    /// アクティブチェーン全体を走査するので、鎖が長いと時間がかかる。
    pub async fn build_index(&self) -> Result<IndexStats, String> {
        self.ask(Request::BuildIndex).await
    }

    /// 索引を捨てる。
    pub async fn drop_index(&self) -> Result<(), String> {
        self.ask(Request::DropIndex).await
    }

    /// txid から確定した取引を引く。
    pub async fn tx_record(&self, txid: Hash) -> Result<Option<TxRecord>, String> {
        self.ask(|reply| Request::TxRecord { txid, reply }).await
    }

    /// 支払い条件に触れた取引を古い順に引く。
    pub async fn address_history(
        &self,
        lock: Lock,
        from: u64,
        max: usize,
    ) -> Result<Vec<TxRecord>, String> {
        self.ask(|reply| Request::AddressHistory {
            lock,
            from,
            max,
            reply,
        })
        .await
    }

    /// 支払い条件が一致する UTXO を集める。
    pub async fn scan_utxos(
        &self,
        locks: Vec<Lock>,
        max: usize,
    ) -> Result<Vec<UtxoRecord>, String> {
        self.ask(|reply| Request::ScanUtxos { locks, max, reply })
            .await
    }
}

/// 専用スレッドの本体。
struct Service {
    node: Node,
    download: BlockDownload,
    /// トランザクションの取り寄せ。**頼んだものだけを受け取るための記録。**
    tx_requests: TxRequests,
    mining: Option<Lock>,
    events: broadcast::Sender<NodeEvent>,
    /// これまでに掘れたブロックの数。
    mined: u64,
    /// 外に名乗る自分自身の住所。運用者が明示したものだけを入れる。
    own_addresses: Vec<SocketAddr>,
    /// 畳んだ採掘スレッドの試行回数。いま走っている分は足していない。
    ///
    /// 実効ハッシュレートを出すために持つ。**掘れたブロック数から
    /// 逆算すると振れが大きすぎて比較にならない** (難易度 1,000 で
    /// 5 ブロックなら 1 標準偏差が 45 % ある)。試行回数を直接数える。
    attempts_base: u64,
    /// 数え始めた時刻。**採掘器が建ってから**である。
    mining_since: Option<Instant>,
    /// 掘った数がここに達したら止める。
    mine_until: Option<u64>,
    /// 採掘スレッドの束。掘っていなければ `None`。
    pool: Option<MiningPool>,
    /// いまの束を建てたときのシードエポックと掘り方。
    ///
    /// **どちらかが変われば建て直しである。**
    pool_built_for: Option<(u64, MiningMode)>,
    /// 掘り方の指定。
    mode: MiningMode,
    /// 土台を組み直す必要があるか。先端が動いた可能性があれば立てる。
    stale_template: bool,
    /// いまの土台を組んだ時刻。
    template_built: Option<Instant>,
}

/// 起動した専用スレッド。
///
/// これを落とすと要求の口が閉じ、スレッドが終わる。
pub struct NodeService {
    handle: NodeHandle,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl NodeService {
    /// 記憶域を開き、専用スレッドを起こす。
    ///
    /// 開くのは呼び出し元のスレッドではなく専用スレッドの上で行う。
    /// 開いた結果を待ち合わせてから返すため、失敗はここで分かる。
    pub fn start(network: Network, data_dir: &Path) -> Result<NodeService, NodeError> {
        let (tx, rx) = mpsc::channel(REQUEST_CAPACITY);
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let data_dir = data_dir.to_path_buf();
        let events_for_thread = events.clone();
        let thread = std::thread::Builder::new()
            .name("oag-node".to_string())
            .spawn(move || {
                let node = match Node::open(network, &data_dir) {
                    Ok(node) => {
                        let _ = ready_tx.send(Ok(()));
                        node
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                Service {
                    node,
                    download: BlockDownload::new(),
                    tx_requests: TxRequests::new(),
                    mining: None,
                    events: events_for_thread,
                    mined: 0,
                    own_addresses: Vec::new(),
                    attempts_base: 0,
                    mining_since: None,
                    mine_until: None,
                    pool: None,
                    pool_built_for: None,
                    mode: MiningMode::light(),
                    stale_template: true,
                    template_built: None,
                }
                .run(rx);
            })
            .map_err(|e| NodeError::Thread(e.to_string()))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(NodeService {
                handle: NodeHandle {
                    tx,
                    events,
                    network,
                    nonce: make_nonce(),
                },
                thread: Some(thread),
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(NodeError::Thread("作業スレッドが起動前に終わった".into())),
        }
    }

    /// 非同期側から使う取っ手。
    pub fn handle(&self) -> NodeHandle {
        self.handle.clone()
    }
}

impl Drop for NodeService {
    fn drop(&mut self) {
        // 終わるよう明示的に伝える。
        //
        // **取っ手を落とすだけでは終わらない。** 取っ手は複製して各ピアに
        // 渡してあり、そちらが生きている限り要求の口は閉じない。
        //
        // 待ってから戻るのは、記憶域を確かに閉じるためである。待たずに
        // 落とすと、開いたままのデータベースを次の処理が開こうとする。
        for _ in 0..SHUTDOWN_ATTEMPTS {
            match self.handle.tx.try_send(Request::Shutdown) {
                Ok(()) => break,
                // 詰まっているだけなら、捌けるのを待って送り直す。
                Err(mpsc::error::TrySendError::Full(_)) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                // すでに終わっている。
                Err(mpsc::error::TrySendError::Closed(_)) => break,
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// ノードの現在時刻 (Unix 秒)。
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Service {
    fn run(mut self, mut rx: mpsc::Receiver<Request>) {
        loop {
            // 溜まっている要求を先に捌く。
            loop {
                match rx.try_recv() {
                    Ok(Request::Shutdown) => return,
                    Ok(request) => self.handle(request),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => return,
                }
            }

            if self.mining.is_some() {
                self.mine();
            } else {
                // 掘らないなら、採掘スレッドを畳んで次の要求まで眠る。
                self.retire_pool();
                match rx.blocking_recv() {
                    Some(Request::Shutdown) | None => return,
                    Some(request) => self.handle(request),
                }
            }
        }
    }

    /// 採掘スレッドを回す。
    ///
    /// ここでやるのは**配ることと受け取ること**だけである。ハッシュを
    /// 計算するのは作業スレッドであり、このスレッドはその間眠っている。
    fn mine(&mut self) {
        let Some(payout) = self.mining.clone() else {
            return;
        };
        // シードエポックが変わるのは先端が動いたときだけである。先端が
        // 動いていないなら、記憶域を引きに行く必要はない。
        if (self.pool.is_none() || self.stale_template) && !self.ensure_pool() {
            self.stop_mining();
            return;
        }

        let aged = self
            .template_built
            .is_none_or(|built| built.elapsed() >= TEMPLATE_REFRESH);
        if self.stale_template || aged {
            match self.node.mining_template(&payout, now(), 0) {
                Ok(template) => {
                    if let Some(pool) = &mut self.pool {
                        pool.dispatch(template);
                    }
                    self.stale_template = false;
                    self.template_built = Some(Instant::now());
                }
                Err(e) => {
                    eprintln!("採掘の土台を組めない: {e}。採掘を止める。");
                    self.stop_mining();
                    return;
                }
            }
        }

        // 当たるまで、あるいは要求を捌き直すまで眠る。
        let Some(block) = self.pool.as_mut().and_then(|pool| pool.wait(MINING_POLL)) else {
            return;
        };

        match self.node.accept_mined(block, now()) {
            Ok(MinedBlock { hash, height }) => {
                self.mined += 1;
                println!("掘れた: 高さ {height}  {hash}{}", self.rate_suffix());
                self.announce_tip(None);
                self.stale_template = true;
                if self.mine_until.is_some_and(|limit| self.mined >= limit) {
                    self.stop_mining();
                }
            }
            Err(e) => {
                // 掘り当てたが先端になれなかった。**土台が古い。**
                // 組み直して続ける。止める理由ではない。
                eprintln!("掘ったブロックが先端にならなかった: {e}");
                self.stale_template = true;
            }
        }
    }

    /// 掘れる採掘スレッドが揃っているか確かめ、無ければ建てる。
    ///
    /// シードエポックが変わったとき、掘り方が変わったときは建て直す。
    /// **建て直しには fast モードで 1 分前後かかり、その間ノードは他の
    /// 要求に応えない。** 2048 ブロック (約 34 時間) に 1 度である。
    ///
    /// 建てられなければ偽を返す。呼び出し側は採掘を止める。
    fn ensure_pool(&mut self) -> bool {
        let (epoch, seed) = match self.node.mining_seed() {
            Ok(found) => found,
            Err(e) => {
                eprintln!("採掘のシードを引けない: {e}");
                return false;
            }
        };

        let wanted = (epoch, self.mode);
        if self.pool.is_some() && self.pool_built_for == Some(wanted) {
            return true;
        }
        self.retire_pool();

        let threads = self.mode.resolved_threads();
        let fast = self.mode.fast;
        if fast {
            println!(
                "fast モードのデータセットを {threads} 個構築する \
                 (合計 {:.1} GB、1 分前後かかる)",
                DATASET_GIB * threads.get() as f64
            );
        }

        // **採掘器の作り方を渡す。採掘器そのものは渡せない。**
        // RandomX の VM もデータセットもスレッドをまたげないので、
        // それぞれの作業スレッドが自分の分を建てる。
        let fell_back = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&fell_back);
        let factory: HasherFactory = Arc::new(move |_| {
            if fast {
                match RandomXMiner::new(&seed, epoch) {
                    Ok(miner) => return Ok(Box::new(miner) as Box<dyn PowHasher>),
                    // 2 GB を確保できない。この 1 本は light で掘る。
                    Err(_) => {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
            RandomXVerifier::new(&seed, epoch)
                .map(|verifier| Box::new(verifier) as Box<dyn PowHasher>)
                .map_err(|e| e.to_string())
        });

        match MiningPool::spawn(threads, factory) {
            Ok(pool) => {
                let light = fell_back.load(Ordering::SeqCst);
                let kind = if !fast {
                    "light モード".to_string()
                } else if light == 0 {
                    "fast モード".to_string()
                } else {
                    format!("fast {} 本・light {light} 本", threads.get() - light)
                };
                println!("{threads} スレッドで採掘する ({kind})");
                if fast && light > 0 {
                    eprintln!(
                        "2 GB を確保できなかった分は light モード (256 MB) で掘る。\n\
                         本数を減らすか、積んでいる memory を確かめること。"
                    );
                }
                self.pool = Some(pool);
                self.pool_built_for = Some(wanted);
                self.stale_template = true;
                // 数え始めは**採掘器が建ってから**である。構築にかかった
                // 1 分を混ぜると、ハッシュレートが低く出る。
                if self.mining_since.is_none() {
                    self.mining_since = Some(Instant::now());
                }
                true
            }
            Err(e) => {
                eprintln!("採掘を始められない: {e}");
                false
            }
        }
    }

    /// 採掘スレッドを畳む。試した回数は持ち越す。
    fn retire_pool(&mut self) {
        if let Some(pool) = self.pool.take() {
            self.attempts_base = self.attempts_base.saturating_add(pool.attempts());
        }
        self.pool_built_for = None;
        self.template_built = None;
    }

    /// これまでに試した回数。畳んだ分と、いま走っている分の合計。
    fn attempts(&self) -> u64 {
        self.attempts_base
            .saturating_add(self.pool.as_ref().map_or(0, MiningPool::attempts))
    }

    /// 「  12,345 回、40 H/s」のような後置き。まだ数えていなければ空。
    fn rate_suffix(&self) -> String {
        let Some(started) = self.mining_since else {
            return String::new();
        };
        let seconds = started.elapsed().as_secs_f64();
        let attempts = self.attempts();
        if seconds <= 0.0 || attempts == 0 {
            return String::new();
        }
        format!("  ({attempts} 回、{:.0} H/s)", attempts as f64 / seconds)
    }

    fn stop_mining(&mut self) {
        self.mining = None;
        self.retire_pool();
        let _ = self.events.send(NodeEvent::MiningStopped);
    }

    /// 先端が変わったことを報せる。
    ///
    /// `from` はそのブロックをくれたピア。そのピアには報せが届かない。
    fn announce_tip(&self, from: Option<PeerId>) {
        if let Ok(tip) = self.node.chain().tip() {
            // 受け手が居なければ落ちるが、それは失敗ではない。
            let _ = self.events.send(NodeEvent::NewTip {
                hash: tip.hash,
                height: tip.height(),
                from,
            });
        }
    }

    fn handle(&mut self, request: Request) {
        // 先端か mempool が動きうる要求なら、掘る土台を組み直す。
        // **先端が動いたのに組み直さないと、1 つ前の先端に繋がる
        // ブロックを掘ることになる。** 逆に、動かない要求まで印を
        // 付けると、問い合わせが来るたびに土台を組み直して採掘を
        // 止めることになる。
        if matches!(
            request,
            Request::AcceptBlock { .. } | Request::SubmitTx { .. }
        ) {
            self.stale_template = true;
        }
        match request {
            Request::Status(reply) => {
                let _ = reply.send(self.node.status().map_err(|e| e.to_string()));
            }
            Request::BestHeaderHeight(reply) => {
                let result = self
                    .node
                    .chain()
                    .best_header()
                    .map(|e| e.height())
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            Request::Locator(reply) => {
                let _ = reply.send(self.locator());
            }
            Request::HeadersAfter {
                locator,
                stop,
                reply,
            } => {
                let result = self
                    .node
                    .chain()
                    .headers_after(&locator, &stop, MAX_HEADERS)
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            Request::AcceptHeaders { headers, reply } => {
                let _ = reply.send(self.accept_headers(&headers));
            }
            Request::AcceptBlock { block, from, reply } => {
                let _ = reply.send(self.accept_block(*block, from));
            }
            Request::GetBlock { hash, reply } => {
                let result = self
                    .node
                    .chain()
                    .store()
                    .block(&hash)
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            Request::AssignDownloads { peer, now, reply } => {
                let _ = reply.send(self.assign_downloads(peer, now));
            }
            Request::BlocksNotFound { peer, hashes } => {
                for hash in hashes {
                    self.download.not_found(&hash, peer);
                }
            }
            Request::PeerGone(peer) => {
                self.download.peer_disconnected(peer);
                self.tx_requests.peer_disconnected(peer);
            }
            Request::SetMining {
                payout,
                blocks,
                mode,
            } => {
                // 掘る数は「ここから」数える。前に掘った分は関係ない。
                self.mine_until = blocks.map(|n| self.mined.saturating_add(n));
                self.mining = payout;
                self.mode = mode;
                // 数え直す。始まりの時刻は採掘器が建ってから入れる
                // ([`Service::ensure_pool`])。
                self.attempts_base = 0;
                self.mining_since = None;
                if self.mining.is_none() {
                    self.retire_pool();
                }
            }
            Request::AddAddresses { addrs, source } => {
                self.node.addresses_mut().add_many(&addrs, source, now());
            }
            Request::AddressesToShare(reply) => {
                let addrs = self
                    .node
                    .addresses()
                    .to_share(now(), crate::addrbook::MAX_TO_SHARE);
                let _ = reply.send(Ok(addrs));
            }
            Request::AddressCandidates { want, busy, reply } => {
                let picked = self.node.addresses().candidates(now(), want, &busy);
                // 繋ぎに行くと決めた時点で印を付ける。付けないと、
                // 結果が返るまでの間に同じ住所をもう一度選んでしまう。
                let at = now();
                for addr in &picked {
                    self.node.addresses_mut().mark_attempt(addr, at);
                }
                let _ = reply.send(Ok(picked));
            }
            Request::AddressOutcome { addr, outcome } => {
                let at = now();
                match outcome {
                    DialOutcome::Connected => {
                        let was_known = self
                            .node
                            .addresses()
                            .get(&addr)
                            .is_some_and(|e| e.is_proven());
                        self.node.addresses_mut().mark_success(&addr, at);
                        // 初めて到達を確かめた住所だけを流す。すでに
                        // 知られている住所を繰り返し流しても仕方がない。
                        if !was_known && self.node.addresses().get(&addr).is_some() {
                            let _ = self
                                .events
                                .send(NodeEvent::NewAddress(NetAddress::from_socket(addr, 0, at)));
                        }
                    }
                    DialOutcome::Failed => self.node.addresses_mut().mark_failure(&addr, at),
                }
            }
            Request::OwnAddresses(addrs) => {
                self.own_addresses = addrs.clone();
                self.node.addresses_mut().set_own(addrs);
            }
            Request::GetOwnAddresses(reply) => {
                let _ = reply.send(Ok(self.own_addresses.clone()));
            }
            Request::SaveAddresses => {
                if self.node.addresses().is_dirty() {
                    if let Err(e) = self.node.addresses_mut().save() {
                        eprintln!("住所帳を書き出せない: {e}");
                    }
                }
            }
            Request::RecentBlocks { max, reply } => {
                let result = self
                    .node
                    .chain()
                    .store()
                    .recent_summaries(max)
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            Request::HashAtHeight { height, reply } => {
                let result = self
                    .node
                    .chain()
                    .hash_at_height(height)
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            Request::GetEntry { hash, reply } => {
                let _ = reply.send(Ok(self.node.chain().entry(&hash).cloned()));
            }
            Request::SubmitTx { tx, from, reply } => {
                let _ = reply.send(self.submit_tx(*tx, from));
            }
            Request::WantTxs {
                peer,
                txids,
                now,
                reply,
            } => {
                let _ = reply.send(Ok(self.want_txs(peer, txids, now)));
            }
            Request::MempoolTxids(reply) => {
                let _ = reply.send(Ok(self.node.mempool().txids()));
            }
            Request::MempoolTx { txid, reply } => {
                let result = self.node.mempool().get(&txid).map(|e| e.tx.clone());
                let _ = reply.send(Ok(result));
            }
            Request::ScanUtxos { locks, max, reply } => {
                let result = self
                    .node
                    .chain()
                    .store()
                    .scan_utxos(&locks, max)
                    .map(|found| {
                        found
                            .into_iter()
                            .map(|(outpoint, entry)| UtxoRecord { outpoint, entry })
                            .collect()
                    })
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            Request::IndexFrom(reply) => {
                let result = self
                    .node
                    .chain()
                    .store()
                    .index_from()
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            Request::TxRecord { txid, reply } => {
                let _ = reply.send(self.tx_record(txid));
            }
            Request::AddressHistory {
                lock,
                from,
                max,
                reply,
            } => {
                let _ = reply.send(self.address_history(&lock, from, max));
            }
            Request::BuildIndex(reply) => {
                let result = self
                    .node
                    .chain()
                    .store()
                    .build_index()
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            Request::DropIndex(reply) => {
                let result = self
                    .node
                    .chain()
                    .store()
                    .drop_index()
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            // ここには来ない。run が先に捕まえる。
            Request::Shutdown => {}
        }
    }

    /// 索引が見つけた位置から、取引と入力側の出力まで組み立てる。
    fn record_at(&self, location: TxLocation) -> Result<Option<TxRecord>, String> {
        let store = self.node.chain().store();
        let Some(tx) = store
            .transaction_at(location.height, location.position)
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        let spent = store
            .spent_outputs(location.height, &tx)
            .map_err(|e| e.to_string())?;
        Ok(Some(TxRecord {
            location,
            tx,
            spent,
        }))
    }

    fn tx_record(&self, txid: Hash) -> Result<Option<TxRecord>, String> {
        let found = self
            .node
            .chain()
            .store()
            .tx_location(&txid)
            .map_err(|e| e.to_string())?;
        match found {
            Some(location) => self.record_at(location),
            None => Ok(None),
        }
    }

    fn address_history(&self, lock: &Lock, from: u64, max: usize) -> Result<Vec<TxRecord>, String> {
        let found = self
            .node
            .chain()
            .store()
            .address_history(lock, from, max)
            .map_err(|e| e.to_string())?;
        let mut out = Vec::with_capacity(found.len());
        for location in found {
            if let Some(record) = self.record_at(location)? {
                out.push(record);
            }
        }
        Ok(out)
    }

    fn locator(&self) -> Result<Vec<Hash>, String> {
        let tip = self
            .node
            .chain()
            .best_header()
            .map_err(|e| e.to_string())?
            .height();
        let heights = oag_net::locator::locator_heights(tip);
        self.node
            .chain()
            .header_hashes_at(&heights)
            .map_err(|e| e.to_string())
    }

    fn accept_headers(&mut self, headers: &[BlockHeader]) -> Result<HeadersAccepted, String> {
        let now = now();
        let mut new = 0;
        for header in headers {
            match self.node.accept_header(header, now) {
                Ok(HeaderOutcome::New) => new += 1,
                Ok(HeaderOutcome::Known) => {}
                // 1 個でも駄目なら、そこで止める。以降は繋がらない。
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(HeadersAccepted {
            new,
            total: headers.len(),
        })
    }

    fn accept_block(
        &mut self,
        block: Block,
        from: Option<PeerId>,
    ) -> Result<BlockAccepted, String> {
        let hash = block.header.hash();
        let before = self.node.chain().tip().map_err(|e| e.to_string())?.hash;
        let outcome = self.node.accept_block(block, now()).map_err(|e| {
            // 頼んだものが駄目だったのだから、依頼中の印は外す。
            self.download.received(&hash);
            e.to_string()
        })?;
        self.download.received(&hash);

        let after = self.node.chain().tip().map_err(|e| e.to_string())?.hash;
        let moved_tip = before != after;
        if moved_tip {
            self.announce_tip(from);
        }
        Ok(BlockAccepted { outcome, moved_tip })
    }

    /// トランザクションを mempool に入れる。
    ///
    /// 中継の方針も含めてここで判断する。受け入れられなければ理由を返す。
    ///
    /// `from` があるなら、それはピアから来たものである。**そのピアに
    /// 頼んであった場合だけ検証する。** 頼んでいないものは中身を見ずに
    /// 断る。署名の検証は高い計算であり、誰でも好きなだけこちらに
    /// 行わせられる状態にしてはならない。
    fn submit_tx(&mut self, tx: Transaction, from: Option<PeerId>) -> Result<Hash, String> {
        let txid = tx.txid();
        if let Some(peer) = from {
            if !self.tx_requests.was_requested_from(peer, &txid) {
                return Err("頼んでいないトランザクションが来た".to_string());
            }
            // 頼んだ分は使い切る。以降の検証が失敗しても、同じものを
            // もう一度この相手から受け取ることはない。
            self.tx_requests.received(&txid);
        }

        let tip = self.node.chain().tip().map_err(|e| e.to_string())?;
        let next_height = tip.height() + 1;
        let mtp = self.node.chain().median_time_past_for_child_of(&tip.hash);
        let view = self.node.chain().utxo_view().map_err(|e| e.to_string())?;
        let accepted = self
            .node
            .mempool_mut()
            .accept(tx, &view, next_height, mtp)
            .map_err(|e| e.to_string())?;

        // **通ったものだけを流す。** くれた相手には流し返さない。
        let _ = self.events.send(NodeEvent::NewTx {
            txid: accepted,
            from,
        });
        Ok(accepted)
    }

    /// `inv` で知らされた txid のうち、取り寄せるものを選ぶ。
    ///
    /// すでに mempool にあるもの、すでに誰かに頼んであるものは外す。
    fn want_txs(&mut self, peer: PeerId, txids: Vec<Hash>, now: i64) -> Vec<Hash> {
        // 返ってこないものを忘れてから積む。
        self.tx_requests.expire(now);

        let fresh: Vec<Hash> = txids
            .into_iter()
            .filter(|txid| !self.node.mempool().contains(txid))
            .collect();
        self.tx_requests.want(fresh);
        self.tx_requests.assign(peer, now)
    }

    fn assign_downloads(&mut self, peer: PeerId, now: i64) -> Result<Vec<Hash>, String> {
        // 返ってこないものを回収してから割り振る。
        self.download.expire(now);

        // 本体が要るブロックを待ち行列に補充する。
        let missing = self
            .node
            .chain()
            .missing_bodies(oag_net::sync::MAX_IN_FLIGHT_PER_PEER * 8)
            .map_err(|e| e.to_string())?;
        self.download.want(missing);

        Ok(self.download.assign(peer, now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_one_light_thread() {
        // **積んでいる memory を当てにしない。** 既定で 8 本建てると、
        // light でも 2 GB を勝手に確保することになる。
        let mode = MiningMode::default();
        assert!(!mode.fast);
        assert_eq!(mode.resolved_threads().get(), 1);
    }

    #[test]
    fn a_thread_count_is_taken_as_given() {
        let mode = MiningMode::light().with_threads(4);
        assert_eq!(mode.resolved_threads().get(), 4);
        let mode = MiningMode::fast().with_threads(3);
        assert_eq!(mode.resolved_threads().get(), 3);
    }

    #[test]
    fn zero_means_ask_the_machine() {
        let mode = MiningMode::light().with_threads(0);
        let wanted = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        assert_eq!(mode.resolved_threads().get(), wanted);
    }

    #[test]
    fn asking_the_machine_does_not_multiply_the_dataset() {
        // fast は 1 本あたり 2 GB 要る。コア数だけ建てれば 16 コアで
        // 32 GB である。**本数を明示しない限り増やさない。**
        let mode = MiningMode::fast().with_threads(0);
        assert_eq!(mode.resolved_threads().get(), 1);
    }

    #[test]
    fn the_mode_carries_over_when_the_thread_count_changes() {
        assert!(MiningMode::fast().with_threads(8).fast);
        assert!(!MiningMode::light().with_threads(8).fast);
    }
}
