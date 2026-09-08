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
use oag_consensus::lock::Lock;
use oag_consensus::{Block, BlockHeader};
use oag_net::message::MAX_HEADERS;
use oag_net::sync::{BlockDownload, PeerId};
use oag_primitives::{Hash, Network};
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
    /// 採掘の受取先を設定する。`None` で止める。
    SetMining(Option<Lock>),
    /// 作業スレッドを終わらせる。
    Shutdown,
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

    /// 採掘を始める。
    pub async fn start_mining(&self, payout: Lock) -> Result<(), String> {
        self.tell(Request::SetMining(Some(payout))).await
    }
}

/// 専用スレッドの本体。
struct Service {
    node: Node,
    download: BlockDownload,
    mining: Option<Lock>,
    events: broadcast::Sender<NodeEvent>,
    /// 掘れたブロックの数。
    mined: u64,
    /// この数だけ掘ったら採掘を止める。
    mine_limit: Option<u64>,
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
    pub fn start(
        network: Network,
        data_dir: &Path,
        mine_limit: Option<u64>,
    ) -> Result<NodeService, NodeError> {
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
                    mine_limit,
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
            Ok(MinedBlock::Accepted { hash, height, .. }) => {
                self.mined += 1;
                println!("掘れた: 高さ {height}  {hash}");
                self.announce_tip();
                if self.mine_limit.is_some_and(|limit| self.mined >= limit) {
                    self.stop_mining();
                }
            }
            Ok(MinedBlock::NotFound { .. }) => {}
            Err(e) => {
                eprintln!("採掘に失敗した: {e}。採掘を止める。");
                self.stop_mining();
            }
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
            Request::SetMining(payout) => {
                self.mining = payout;
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
