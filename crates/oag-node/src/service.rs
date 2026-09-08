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
use oag_consensus::tx::OutPoint;
use oag_consensus::utxo::UtxoEntry;
use oag_consensus::{Block, BlockHeader, Transaction};
use oag_net::message::NetAddress;
use oag_net::message::MAX_HEADERS;
use oag_net::sync::{BlockDownload, PeerId};
use oag_primitives::{Hash, Network};
use std::net::SocketAddr;
use std::path::Path;
use tokio::sync::{broadcast, mpsc, oneshot};

/// 1 度に試す nonce の数。
///
/// これを試すごとに要求を捌く。light モードの RandomX は 1 秒に数百回
/// しか計算できないため、大きくすると応答が目に見えて遅れる。
const MINING_SLICE: u64 = 32;

/// 報せを溜めておける数。
///
/// 溜まりきったピアは古い報せを取り落とす。取り落としても、次の報せか
/// 定期の問い合わせで追いつける。
const EVENT_CAPACITY: usize = 256;

/// 要求を溜めておける数。
const REQUEST_CAPACITY: usize = 1_024;

/// 終了を伝えるのを諦めるまでの試行回数。
const SHUTDOWN_ATTEMPTS: usize = 100;

/// ノードからの報せ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvent {
    /// アクティブチェーンの先端が変わった。
    NewTip {
        /// 新しい先端。
        hash: Hash,
        /// 新しい高さ。
        height: u64,
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
    /// ピアが切れた。頼んでいた分を待ち行列に戻す。
    PeerGone(PeerId),
    /// 採掘を始める、または止める。
    SetMining {
        /// 受取先。`None` で止める。
        payout: Option<Lock>,
        /// この数だけ掘ったら止める。`None` なら止まらない。
        blocks: Option<u64>,
        /// fast モード (2 GB) で掘るか。
        fast: bool,
    },
    /// 聞いた住所を住所帳に入れる。
    AddAddresses(Vec<NetAddress>),
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
    /// インデックスの 1 件を引く。
    GetEntry {
        hash: Hash,
        reply: oneshot::Sender<Result<Option<BlockIndexEntry>, String>>,
    },
    /// トランザクションを mempool に入れる。
    SubmitTx {
        tx: Box<Transaction>,
        reply: oneshot::Sender<Result<Hash, String>>,
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
        self.ask(|reply| Request::AcceptBlock {
            block: Box::new(block),
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

    /// ピアが切れたことを伝える。
    pub async fn peer_gone(&self, peer: PeerId) -> Result<(), String> {
        self.tell(Request::PeerGone(peer)).await
    }

    /// `addr` で聞いた住所を住所帳に入れる。
    pub async fn add_addresses(&self, addrs: Vec<NetAddress>) -> Result<(), String> {
        self.tell(Request::AddAddresses(addrs)).await
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
    /// 採掘を始める。
    ///
    /// `fast` を立てると 2 GB のデータセットを構築して掘る。light モードの
    /// およそ 6 倍速い。**構築に 1 分前後かかり、その間ノードは他の要求に
    /// 応えない。** 確保できなければ light モードのまま続ける。
    pub async fn start_mining(
        &self,
        payout: Lock,
        blocks: Option<u64>,
        fast: bool,
    ) -> Result<(), String> {
        self.tell(Request::SetMining {
            payout: Some(payout),
            blocks,
            fast,
        })
        .await
    }

    /// 採掘を止める。
    pub async fn stop_mining(&self) -> Result<(), String> {
        self.tell(Request::SetMining {
            payout: None,
            blocks: None,
            fast: false,
        })
        .await
    }

    /// アクティブチェーンの、その高さのブロックハッシュ。
    pub async fn hash_at_height(&self, height: u64) -> Result<Option<Hash>, String> {
        self.ask(|reply| Request::HashAtHeight { height, reply })
            .await
    }

    /// インデックスの 1 件。
    pub async fn entry(&self, hash: Hash) -> Result<Option<BlockIndexEntry>, String> {
        self.ask(|reply| Request::GetEntry { hash, reply }).await
    }

    /// トランザクションを mempool に入れる。
    pub async fn submit_tx(&self, tx: Transaction) -> Result<Hash, String> {
        self.ask(|reply| Request::SubmitTx {
            tx: Box::new(tx),
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
    mining: Option<Lock>,
    events: broadcast::Sender<NodeEvent>,
    /// これまでに掘れたブロックの数。
    mined: u64,
    /// 外に名乗る自分自身の住所。運用者が明示したものだけを入れる。
    own_addresses: Vec<SocketAddr>,
    /// 採掘を始めてからの試行回数と、始めた時刻。
    ///
    /// 実効ハッシュレートを出すために持つ。**掘れたブロック数から
    /// 逆算すると振れが大きすぎて比較にならない** (難易度 1,000 で
    /// 5 ブロックなら 1 標準偏差が 45 % ある)。試行回数を直接数える。
    attempts: u64,
    mining_since: Option<std::time::Instant>,
    /// 掘った数がここに達したら止める。
    mine_until: Option<u64>,
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
                    mining: None,
                    events: events_for_thread,
                    mined: 0,
                    own_addresses: Vec::new(),
                    attempts: 0,
                    mining_since: None,
                    mine_until: None,
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
                self.mine_slice();
            } else {
                // 掘らないなら、次の要求まで眠る。
                match rx.blocking_recv() {
                    Some(Request::Shutdown) | None => return,
                    Some(request) => self.handle(request),
                }
            }
        }
    }

    /// nonce を少しだけ試す。
    fn mine_slice(&mut self) {
        let Some(payout) = self.mining.clone() else {
            return;
        };
        match self.node.mine_next(&payout, now(), MINING_SLICE) {
            Ok(MinedBlock::Accepted {
                hash,
                height,
                attempts,
            }) => {
                self.mined += 1;
                self.attempts += attempts;
                println!("掘れた: 高さ {height}  {hash}{}", self.rate_suffix());
                self.announce_tip();
                if self.mine_until.is_some_and(|limit| self.mined >= limit) {
                    self.stop_mining();
                }
            }
            Ok(MinedBlock::NotFound { attempts }) => {
                self.attempts += attempts;
            }
            Err(e) => {
                eprintln!("採掘に失敗した: {e}。採掘を止める。");
                self.stop_mining();
            }
        }
    }

    /// 「  12,345 回、40 H/s」のような後置き。まだ数えていなければ空。
    fn rate_suffix(&self) -> String {
        let Some(started) = self.mining_since else {
            return String::new();
        };
        let seconds = started.elapsed().as_secs_f64();
        if seconds <= 0.0 || self.attempts == 0 {
            return String::new();
        }
        format!(
            "  ({} 回、{:.0} H/s)",
            self.attempts,
            self.attempts as f64 / seconds
        )
    }

    /// fast モードを用意する。**1 分前後かかる。**
    ///
    /// その間この関数を呼んだスレッド (ノードのスレッド) は他の要求に
    /// 応えない。掘り始める合図を受けた直後に済ませてしまう。
    fn enable_fast_mining(&mut self) {
        let height = self.node.chain().height().unwrap_or(0) + 1;
        println!("fast モードのデータセットを構築する (2 GB、1 分前後かかる)");
        match self.node.enable_fast_mining(height) {
            Ok(()) => println!("fast モードで採掘する"),
            Err(e) => eprintln!(
                "fast モードを用意できない: {e}\n\
                 light モード (256 MB) で採掘する。速さはおよそ 6 分の 1 になる。"
            ),
        }
    }

    fn stop_mining(&mut self) {
        self.mining = None;
        let _ = self.events.send(NodeEvent::MiningStopped);
    }

    /// 先端が変わったことを報せる。
    fn announce_tip(&self) {
        if let Ok(tip) = self.node.chain().tip() {
            // 受け手が居なければ落ちるが、それは失敗ではない。
            let _ = self.events.send(NodeEvent::NewTip {
                hash: tip.hash,
                height: tip.height(),
            });
        }
    }

    fn handle(&mut self, request: Request) {
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
            Request::AcceptBlock { block, reply } => {
                let _ = reply.send(self.accept_block(*block));
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
            Request::PeerGone(peer) => {
                self.download.peer_disconnected(peer);
            }
            Request::SetMining {
                payout,
                blocks,
                fast,
            } => {
                // 掘る数は「ここから」数える。前に掘った分は関係ない。
                self.mine_until = blocks.map(|n| self.mined.saturating_add(n));
                self.mining = payout;
                if fast && self.mining.is_some() && !self.node.is_fast_mining() {
                    self.enable_fast_mining();
                }
                // 数え始めは**データセットを用意したあと**である。構築に
                // かかった 1 分を混ぜると、ハッシュレートが低く出る。
                self.attempts = 0;
                self.mining_since = self.mining.is_some().then(std::time::Instant::now);
            }
            Request::AddAddresses(addrs) => {
                self.node.addresses_mut().add_many(&addrs, now());
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
            Request::SubmitTx { tx, reply } => {
                let _ = reply.send(self.submit_tx(*tx));
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
            // ここには来ない。run が先に捕まえる。
            Request::Shutdown => {}
        }
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

    fn accept_block(&mut self, block: Block) -> Result<BlockAccepted, String> {
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
            self.announce_tip();
        }
        Ok(BlockAccepted { outcome, moved_tip })
    }

    /// トランザクションを mempool に入れる。
    ///
    /// 中継の方針も含めてここで判断する。受け入れられなければ理由を返す。
    fn submit_tx(&mut self, tx: Transaction) -> Result<Hash, String> {
        let tip = self.node.chain().tip().map_err(|e| e.to_string())?;
        let next_height = tip.height() + 1;
        let mtp = self.node.chain().median_time_past_for_child_of(&tip.hash);
        let view = self.node.chain().utxo_view().map_err(|e| e.to_string())?;
        self.node
            .mempool_mut()
            .accept(tx, &view, next_height, mtp)
            .map_err(|e| e.to_string())
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
