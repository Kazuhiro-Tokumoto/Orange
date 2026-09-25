//! 1 本の接続の面倒を見る。
//!
//! ハンドシェイクを済ませたあと、次の 3 つを並行して行う。
//!
//! ```text
//!  読む作業  ── 受け取ったメッセージ ──▶ 本体の作業 ──▶ 送る作業
//!                                          ▲   │
//!                     ノードからの報せ ─────┘   └──▶ ノードへの要求
//!                     定期の見直し ─────────┘
//! ```
//!
//! # なぜ読む作業を分けるのか
//!
//! 1 本の作業で「受信」と「時計」の両方を待つと、待ち合わせのどちらかを
//! 打ち切ることになる。打ち切られた受信が読みかけの内容を抱えていると、
//! それが失われる。作業を分ければ、それぞれが待つものは 1 つだけになる。
//!
//! # 同期の進め方
//!
//! headers-first である ([`oag_net::sync`])。
//!
//! 1. 相手が自分より先を行っているなら `getheaders` を送る
//! 2. `headers` を取り込む。満杯 (2000 件) なら続きをすぐ求める
//! 3. ヘッダの分だけ本体を `getdata` で求める
//! 4. `block` が届いたら取り込み、次の分を求める
//!
//! 相手からの `getheaders` や `getdata` にも同じ作業の中で応える。
//!
//! # 死んだ接続を見つける
//!
//! TCP は、相手が黙って消えたこと (電源断・スリープ・NAT の期限切れ・
//! 回線の瞬断) を報せてくれない。何も送らずに待っていると、**死んだ
//! 接続を「繋がっている」と思ったまま待ち続ける。** 0.1.1 までがそうで、
//! ピアが 1 本しか無いノードが 37 分間ブロックを受け取らず、古い先端の上で
//! 掘り続けた。
//!
//! 次の 3 つで塞ぐ。
//!
//! - `PING_INTERVAL_SECS` ごとに `ping` を送り、`PONG_TIMEOUT_SECS` 返事が
//!   無ければ切る (`Liveness`)。0.1.0 のノードも `ping` には `pong` を返す
//! - 送るのに `WRITE_TIMEOUT` 以上かかったら切る。死んだ相手への送信は、
//!   送り側のバッファが埋まると永久に終わらない
//! - 先端が `QUIET_TIP_SECS` 動かなければ、相手に `getheaders` を送り直す。
//!   相手の `inv` を取りこぼしていても、それで追いつく
//!
//! 外向きの接続は、切れれば [`crate::connect`] が補充する。

use crate::service::NodeHandle;
use oag_net::message::{
    effective_services, GetHeaders, InvItem, InvKind, Message, VersionMessage, MAX_HEADERS,
    PROTOCOL_VERSION,
};
use oag_net::sync::PeerId;
use oag_net::transport::{Connection, TransportError};
use oag_primitives::Hash;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;

/// 送信待ちを溜めておける数。
const SEND_QUEUE: usize = 256;

/// 定期の見直しの間隔。
///
/// 取りこぼしの回収と、止まった同期のやり直しを担う。報せが届けば
/// それで動くため、これは保険である。
const TICK: Duration = Duration::from_secs(2);

/// 生存確認 (`ping`) を送る間隔 (秒)。
const PING_INTERVAL_SECS: i64 = 60;

/// `ping` にこの秒数だけ返事が無ければ、相手は消えたと見て切る。
///
/// 短すぎると、大きなブロックを捌いていて返事が遅れた相手まで切る。
/// ブロックは 1 分に 1 個なので、5 分は 5 個分の遅れにあたる。
const PONG_TIMEOUT_SECS: i64 = 300;

/// 1 通を送り終えるまでの上限。
///
/// 最大のブロック (200 KB) でも、毎秒 2 KB 出れば間に合う。
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);

/// 先端がこの秒数だけ動かなければ、相手に続きを聞き直す。
///
/// 目標のブロック間隔の 5 倍。平均どおりに掘れていれば、5 分ブロックが
/// 出ないことはまず無い (e^-5 ≈ 0.7%)。
const QUIET_TIP_SECS: i64 = 300;

/// このノードの名乗り。
const USER_AGENT: &str = concat!("/oag-node:", env!("CARGO_PKG_VERSION"), "/");

/// ピアに振る通し番号。
static NEXT_PEER_ID: AtomicU64 = AtomicU64::new(1);

fn next_peer_id() -> PeerId {
    NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// このノードの `version`。
async fn our_version(handle: &NodeHandle) -> Result<VersionMessage, String> {
    Ok(VersionMessage {
        protocol_version: PROTOCOL_VERSION,
        // 剪定していれば SERVICE_LIMITED、していなければ
        // SERVICE_FULL_NODE になる (SPEC §14.5)。**配れないものを配れると
        // 名乗ってはならない。**
        services: handle.services(),
        timestamp: now(),
        nonce: handle.nonce(),
        user_agent: USER_AGENT.to_string(),
        start_height: handle.best_header_height().await?,
        relay: true,
    })
}

/// 1 本の接続を、切れるまで面倒を見る。
///
/// ハンドシェイクから始め、切れたら戻る。失敗しても呼び出し側は
/// そのピアを諦めればよい。
pub async fn run(handle: NodeHandle, conn: Connection) -> Result<(), String> {
    run_as(handle, conn, Direction::Inbound).await
}

/// こちらから繋いだのか、相手から繋がれたのか。
///
/// **住所を求めるのはこちらから繋いだ相手にだけ**にする。相手から
/// 繋がれた接続は、相手が誰であれ好きに開けるので、そこから住所を集めると
/// 攻撃者が「聞かれる側」に回りやすい。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// こちらから繋いだ。
    Outbound,
    /// 相手から繋がれた。
    Inbound,
}

/// 1 本の接続を、向きを指定して面倒を見る。
pub async fn run_as(
    handle: NodeHandle,
    mut conn: Connection,
    direction: Direction,
) -> Result<(), String> {
    let peer = next_peer_id();
    let addr = conn
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".to_string());

    let version = our_version(&handle).await?;
    let theirs = conn
        .handshake(version)
        .await
        .map_err(|e| format!("the handshake with {addr} failed: {e}"))?;
    crate::log_peer!(
        "connected to {addr} ({}, height {})",
        theirs.user_agent,
        theirs.start_height
    );

    let source = conn.peer_addr().ok();
    // 名乗りを住所帳に控える。**こちらから繋いだ相手だけ**である。繋がれた
    // 側の住所は相手の一時ポートであり、次に繋ぎ直せる宛先ではない。
    if direction == Direction::Outbound {
        if let Some(addr) = source {
            let services = effective_services(theirs.protocol_version, theirs.services);
            let _ = handle.record_peer_services(addr, services).await;
        }
    }
    let result = session(&handle, peer, conn, theirs.start_height, direction, source).await;
    handle.peer_gone(peer).await?;
    crate::log_peer!("the connection to {addr} dropped");
    result
}

async fn session(
    handle: &NodeHandle,
    peer: PeerId,
    conn: Connection,
    peer_height: u64,
    direction: Direction,
    source: Option<SocketAddr>,
) -> Result<(), String> {
    let (mut reader, mut writer) = conn.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(SEND_QUEUE);
    let (in_tx, mut in_rx) = mpsc::channel::<Message>(SEND_QUEUE);

    // 送る作業。
    //
    // 送れなくなったら抜ける。受け口が閉じるので、本体の作業は次に送ろう
    // としたところで切れたと気づく。
    let sender = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            match tokio::time::timeout(WRITE_TIMEOUT, writer.send(&message)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => break,
                Err(_) => {
                    crate::log_warn!(
                        "sending took more than {WRITE_TIMEOUT:?}, so dropping the peer"
                    );
                    break;
                }
            }
        }
    });

    // 読む作業。
    let receiver = tokio::spawn(async move {
        loop {
            match reader.recv().await {
                Ok(message) => {
                    if in_tx.send(message).await.is_err() {
                        break;
                    }
                }
                Err(TransportError::Closed) => break,
                Err(e) => {
                    crate::log_warn!("receiving failed: {e}");
                    break;
                }
            }
        }
    });

    let mut events = handle.subscribe();
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let started = now();
    let mut state = Session {
        peer,
        source,
        peer_height,
        asked_headers_at: 0,
        addr_requests: 0,
        rejected_txs: 0,
        last_body_at: started,
        stall_reported: false,
        // nonce は見分けがつけばよい。推測されて困るものではない。
        liveness: Liveness::new(started, handle.nonce() ^ peer.rotate_left(32)),
        last_tip_at: started,
    };

    // 相手が先を行っていれば、まずヘッダを求める。
    state.maybe_request_headers(handle, &out_tx).await?;

    if direction == Direction::Outbound {
        // 知っている住所を教えてもらう。**こちらから繋いだ相手にだけ
        // 頼む。** これが住所帳の主な育ち方であり、シードを引くのは
        // 最初の 1 回だけで済む。
        send(&out_tx, Message::GetAddr).await?;
        // こちらの住所も名乗る。**名乗らないと誰にも見つけてもらえない。**
        // 名乗る住所は運用者が --external-addr で明示したものに限る。
        // 自分の外向きの住所は自分では分からない。
        let own = handle.own_addresses().await?;
        if !own.is_empty() {
            let at = now();
            let addrs = own
                .into_iter()
                .map(|a| oag_net::message::NetAddress::from_socket(a, 0, at))
                .collect();
            send(&out_tx, Message::Addr(addrs)).await?;
        }
    }

    let outcome = loop {
        tokio::select! {
            incoming = in_rx.recv() => {
                let Some(message) = incoming else { break Ok(()) };
                if let Err(e) = state.on_message(handle, &out_tx, message).await {
                    break Err(e);
                }
            }
            event = events.recv() => {
                match event {
                    Ok(crate::service::NodeEvent::NewTip { hash, from, .. }) => {
                        state.last_tip_at = now();
                        // 新しい先端を持っていることを知らせる。
                        // **くれた相手には言わない。** 相手は既に持って
                        // いるので、先端が動かず中継もしない。送るだけ無駄。
                        if from != Some(state.peer) {
                            let inv = Message::Inv(vec![InvItem::block(hash)]);
                            if out_tx.send(inv).await.is_err() {
                                break Ok(());
                            }
                        }
                    }
                    Ok(crate::service::NodeEvent::NewTx { txid, from }) => {
                        // 検証を通ったトランザクションだけがここに来る。
                        // ブロックと同じく、くれた相手には言わない。
                        if from != Some(state.peer) {
                            let inv = Message::Inv(vec![InvItem::tx(txid)]);
                            if out_tx.send(inv).await.is_err() {
                                break Ok(());
                            }
                        }
                    }
                    Ok(crate::service::NodeEvent::NewAddress(addr)) => {
                        // 新しく到達を確かめた住所を流す。相手が知って
                        // いれば捨てられるだけで、害は無い。
                        if out_tx.send(Message::Addr(vec![addr])).await.is_err() {
                            break Ok(());
                        }
                    }
                    // 採掘の報せはピアに関係ない。
                    Ok(crate::service::NodeEvent::MiningStopped) => {}
                    // 溜まりきって取り落とした。次の見直しで追いつく。
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break Ok(()),
                }
            }
            _ = ticker.tick() => {
                if let Err(e) = state.on_tick(handle, &out_tx).await {
                    break Err(e);
                }
            }
        }
    };

    drop(out_tx);
    receiver.abort();
    let _ = sender.await;
    outcome
}

/// 1 本の接続についての覚え書き。
struct Session {
    peer: PeerId,
    /// 相手の住所。`addr` で聞いた住所の**出どころ**として住所帳に渡す。
    ///
    /// 相手から繋がれた接続では送信元ポートが一時的なものだが、
    /// 括りに使うのは /16 なので差し支えない。
    source: Option<SocketAddr>,
    /// 相手が名乗った高さ。`inv` や `headers` が来るたびに更新する。
    peer_height: u64,
    /// 最後に `getheaders` を送った時刻。
    asked_headers_at: i64,
    /// この接続で `getaddr` を受けた回数。**応えるのは 1 度だけ。**
    addr_requests: u32,
    /// 受け付けなかったトランザクションの数。記録だけで、切る材料にはしない。
    rejected_txs: u64,
    /// この相手から最後にブロックの本体を受け取った時刻。
    last_body_at: i64,
    /// 止まっていることを既に報せたか。**1 回だけ出す。**
    stall_reported: bool,
    /// 相手が生きているかの見張り。
    liveness: Liveness,
    /// 最後に先端が動いた時刻。誰がくれたか、自分で掘ったかは問わない。
    last_tip_at: i64,
}

/// 相手が生きているかの見張り。
///
/// 時刻は壁時計 (秒) である。機械がスリープから戻ると一気に進み、返事を
/// 待っていた `ping` が時間切れになって切れる。スリープの間に相手が
/// 消えていてもおかしくないので、それで正しい。時計が戻ったときは、
/// 経過が負になるだけで切りはしない。
#[derive(Debug)]
struct Liveness {
    /// 最後に `ping` を送った時刻。
    pinged_at: i64,
    /// 返事を待っている `ping` の nonce。
    waiting: Option<u64>,
    /// 次に使う nonce。
    next_nonce: u64,
}

/// [`Liveness::check`] の答え。
#[derive(Debug, PartialEq, Eq)]
enum Check {
    /// 何もしなくてよい。
    Quiet,
    /// この nonce で `ping` を送る。
    Ping(u64),
    /// この秒数だけ返事が無い。切る。
    Silent(i64),
}

impl Liveness {
    fn new(now: i64, first_nonce: u64) -> Liveness {
        Liveness {
            pinged_at: now,
            waiting: None,
            next_nonce: first_nonce,
        }
    }

    /// 今すべきことを答える。`ping` を送るなら、送ったものとして覚える。
    fn check(&mut self, now: i64) -> Check {
        let since = now - self.pinged_at;
        if self.waiting.is_some() {
            if since >= PONG_TIMEOUT_SECS {
                return Check::Silent(since);
            }
            return Check::Quiet;
        }
        if since < PING_INTERVAL_SECS {
            return Check::Quiet;
        }
        let nonce = self.next_nonce;
        self.next_nonce = self.next_nonce.wrapping_add(1);
        self.pinged_at = now;
        self.waiting = Some(nonce);
        Check::Ping(nonce)
    }

    /// `pong` が来た。待っていたものでなければ無視する。
    ///
    /// 頼んでいない `pong` や古い nonce の `pong` で、生きていることには
    /// しない。
    fn pong(&mut self, nonce: u64) {
        if self.waiting == Some(nonce) {
            self.waiting = None;
        }
    }
}

/// この秒数だけ本体が来なければ、止まっていると見て記録に出す。
///
/// 相手が寄越さないのか、こちらが捌けていないのかで対処が正反対になる。
/// **黙って待っているだけの時間を作らない。**
const STALL_SECS: i64 = 30;

/// `getheaders` を送り直すまでの間隔。
///
/// 応答が来ないまま何度も送っても仕方がない。
const HEADERS_RETRY_SECS: i64 = 10;

impl Session {
    /// 自分が遅れていればヘッダを求める。
    async fn maybe_request_headers(
        &mut self,
        handle: &NodeHandle,
        out: &mpsc::Sender<Message>,
    ) -> Result<(), String> {
        let ours = handle.best_header_height().await?;
        if self.peer_height <= ours {
            return Ok(());
        }
        let now = now();
        if now - self.asked_headers_at < HEADERS_RETRY_SECS {
            return Ok(());
        }
        self.asked_headers_at = now;
        self.request_headers(handle, out).await
    }

    async fn request_headers(
        &mut self,
        handle: &NodeHandle,
        out: &mpsc::Sender<Message>,
    ) -> Result<(), String> {
        let locator = handle.locator().await?;
        send(
            out,
            Message::GetHeaders(GetHeaders {
                protocol_version: PROTOCOL_VERSION,
                locator,
                stop: Hash::ZERO,
            }),
        )
        .await
    }

    /// 本体の取り寄せを進める。
    async fn request_bodies(
        &mut self,
        handle: &NodeHandle,
        out: &mpsc::Sender<Message>,
    ) -> Result<(), String> {
        let wanted = handle.assign_downloads(self.peer, now()).await?;
        if wanted.is_empty() {
            return Ok(());
        }
        let items = wanted.into_iter().map(InvItem::block).collect();
        send(out, Message::GetData(items)).await
    }

    /// 定期の見直し。
    async fn on_tick(
        &mut self,
        handle: &NodeHandle,
        out: &mpsc::Sender<Message>,
    ) -> Result<(), String> {
        self.check_alive(out).await?;
        self.report_stall(handle).await?;
        self.maybe_request_headers(handle, out).await?;
        self.poll_quiet_tip(handle, out).await?;
        self.request_bodies(handle, out).await
    }

    /// 要れば `ping` を送る。返事が来ないまま時間が過ぎていれば切る。
    async fn check_alive(&mut self, out: &mpsc::Sender<Message>) -> Result<(), String> {
        match self.liveness.check(now()) {
            Check::Quiet => Ok(()),
            Check::Ping(nonce) => send(out, Message::Ping(nonce)).await,
            Check::Silent(waited) => Err(format!("no reply to ping for {waited} seconds")),
        }
    }

    /// 先端がしばらく動かなければ、相手に続きを聞き直す。
    ///
    /// 相手が先へ進んだことは、相手の `inv` で知る。**`inv` を取りこぼすと、
    /// 相手が先を行っていることに気づかないまま待ち続ける。** 相手の側で
    /// 報せが溢れたときなどに起きる。`getheaders` で確かめれば、相手も同じ
    /// 先端なら空の `headers` が返るだけである。
    async fn poll_quiet_tip(
        &mut self,
        handle: &NodeHandle,
        out: &mpsc::Sender<Message>,
    ) -> Result<(), String> {
        let now = now();
        if now - self.last_tip_at < QUIET_TIP_SECS || now - self.asked_headers_at < QUIET_TIP_SECS {
            return Ok(());
        }
        self.asked_headers_at = now;
        self.request_headers(handle, out).await
    }

    /// 遅れているのに本体が来ないことを、1 度だけ報せる。
    ///
    /// 進み具合の行は**ブロックが繋がったときにしか出ない**。止まると
    /// 記録も止まり、外からは「同期し終わった」のと区別がつかなくなる。
    async fn report_stall(&mut self, handle: &NodeHandle) -> Result<(), String> {
        let ours = handle.best_header_height().await?;
        if self.peer_height <= ours {
            // 遅れていない。待っているのは当たり前である。
            self.stall_reported = false;
            return Ok(());
        }
        let waited = now() - self.last_body_at;
        if waited < STALL_SECS || self.stall_reported {
            return Ok(());
        }
        self.stall_reported = true;
        crate::log_sync!(
            "no block body for {waited} seconds (peer {}, us {ours})",
            self.peer_height
        );
        Ok(())
    }

    async fn on_message(
        &mut self,
        handle: &NodeHandle,
        out: &mpsc::Sender<Message>,
        message: Message,
    ) -> Result<(), String> {
        match message {
            Message::Ping(nonce) => send(out, Message::Pong(nonce)).await,
            Message::Pong(nonce) => {
                self.liveness.pong(nonce);
                Ok(())
            }

            // ハンドシェイクは済んでいる。重ねて来たら断る。
            Message::Version(_) | Message::Verack => {
                Err("version/verack arrived after the handshake".to_string())
            }

            Message::GetHeaders(request) => {
                let headers = handle.headers_after(request.locator, request.stop).await?;
                send(out, Message::Headers(headers)).await
            }

            Message::Headers(headers) => self.on_headers(handle, out, headers).await,

            Message::GetData(items) => self.on_getdata(handle, out, items).await,

            Message::Block(block) => self.on_block(handle, out, *block).await,

            Message::Tx(tx) => self.on_tx(handle, *tx).await,

            Message::Inv(items) => self.on_inv(handle, out, items).await,

            Message::GetAddr => {
                // **1 本の接続につき 1 度だけ応える。** 繰り返し聞かれる
                // まま返し続けると、こちらの住所帳を丸ごと吸い出す道具に
                // なる。誰と繋がっているかは相手に教えたくない。
                self.addr_requests += 1;
                if self.addr_requests > 1 {
                    return Ok(());
                }
                let addrs = handle.addresses_to_share().await?;
                if addrs.is_empty() {
                    return Ok(());
                }
                send(out, Message::Addr(addrs)).await
            }

            Message::Addr(addrs) => {
                // 中身は相手が決める。住所帳の側でバケットと上限に
                // 従わせる。誰から聞いたかを渡すのが要で、これが無いと
                // 1 つの相手が new 表の好きな場所を狙える。
                handle.add_addresses(addrs, self.source).await
            }

            // 頼んだものを相手が持っていなかった。**待ち行列に戻す。**
            Message::NotFound(items) => self.on_notfound(handle, items).await,

            // まだ扱わないもの。無視してよい。相手を切る理由にはならない。
            Message::Mempool
            | Message::SendCompact(_)
            | Message::CompactBlock(_)
            | Message::GetBlockTxn(_)
            | Message::BlockTxn(_) => Ok(()),
        }
    }

    async fn on_headers(
        &mut self,
        handle: &NodeHandle,
        out: &mpsc::Sender<Message>,
        headers: Vec<oag_consensus::BlockHeader>,
    ) -> Result<(), String> {
        if headers.is_empty() {
            // 相手はもう送るものが無い。本体の取り寄せだけ進める。
            return self.request_bodies(handle, out).await;
        }
        if let Some(last) = headers.last() {
            self.peer_height = self.peer_height.max(last.height);
        }
        let full = headers.len() >= MAX_HEADERS;

        // 何件取り込めたかはサービス側が出す。ここで出すと、同じ話が
        // ピアの数だけ別の口から流れる。
        let accepted = handle.accept_headers(headers).await?;

        // 満杯で返ってきたなら、まだ続きがある。すぐ求める。
        if full && accepted.new > 0 {
            self.asked_headers_at = now();
            self.request_headers(handle, out).await?;
        }
        self.request_bodies(handle, out).await
    }

    /// 「そのブロックは持っていない」と言われた。
    ///
    /// 頼んだ分を待ち行列に戻し、次の見直しで別の相手に回す。**戻さないと、
    /// 返事は来ているのに時間切れまでそのブロックは止まったままになる**
    /// ([`oag_net::sync::BlockDownload::not_found`])。ブロックは親から順に
    /// しか繋げないので、止まるのはその 1 個では済まない。
    ///
    /// この接続へ頼み直しはしない。相手は持っていないのだから、同じ相手に
    /// すぐ聞き直しても同じ答えが返るだけである。
    ///
    /// トランザクションは戻さない。**1 度で諦める方針** (SPEC §14.5) なので、
    /// 戻したところで次に頼む先がない。
    async fn on_notfound(
        &mut self,
        handle: &NodeHandle,
        items: Vec<InvItem>,
    ) -> Result<(), String> {
        let blocks: Vec<Hash> = items
            .into_iter()
            .filter(|item| item.kind == InvKind::Block)
            .map(|item| item.hash)
            .collect();
        if blocks.is_empty() {
            return Ok(());
        }
        handle.blocks_not_found(self.peer, blocks).await
    }

    async fn on_getdata(
        &mut self,
        handle: &NodeHandle,
        out: &mpsc::Sender<Message>,
        items: Vec<InvItem>,
    ) -> Result<(), String> {
        let mut missing = Vec::new();
        for item in items {
            match item.kind {
                InvKind::Block => match handle.block(item.hash).await? {
                    Some(block) => send(out, Message::Block(Box::new(block))).await?,
                    None => missing.push(item),
                },
                // **自分の mempool にあるものだけを渡す。** 持っていない
                // ものを探しに行ったりはしない。
                InvKind::Tx => match handle.mempool_tx(item.hash).await? {
                    Some(tx) => send(out, Message::Tx(Box::new(tx))).await?,
                    None => missing.push(item),
                },
            }
        }
        if !missing.is_empty() {
            send(out, Message::NotFound(missing)).await?;
        }
        Ok(())
    }

    async fn on_block(
        &mut self,
        handle: &NodeHandle,
        out: &mpsc::Sender<Message>,
        block: oag_consensus::Block,
    ) -> Result<(), String> {
        let height = block.header.height;
        self.last_body_at = now();
        self.stall_reported = false;
        // くれた相手を添える。通ったとき、この相手には報せ返さない。
        //
        // 接続できたことを出すのはサービス側である。ここは「運んできた」
        // までで、中身を確かめたかどうかは別の話として扱う。
        handle
            .accept_block_from(block, Some(self.peer))
            .await
            // 不正なブロックを送ってきた相手は切る。
            .map_err(|e| format!("cannot accept the block at height {height}: {e}"))?;
        self.request_bodies(handle, out).await
    }

    async fn on_inv(
        &mut self,
        handle: &NodeHandle,
        out: &mpsc::Sender<Message>,
        items: Vec<InvItem>,
    ) -> Result<(), String> {
        let txids: Vec<Hash> = items
            .iter()
            .filter(|i| i.kind == InvKind::Tx)
            .map(|i| i.hash)
            .collect();
        if !txids.is_empty() {
            // 要るものだけを選んでもらう。すでに持っているもの、すでに
            // 誰かに頼んであるものは外れる。ここで頼んだという記録が
            // 残り、それが `tx` を受け取る条件になる。
            let announced = txids.len();
            let wanted = handle.want_txs(self.peer, txids).await?;
            if !wanted.is_empty() {
                crate::log_tx!("{announced} announced  requested {}", wanted.len());
                let items = wanted.into_iter().map(InvItem::tx).collect();
                send(out, Message::GetData(items)).await?;
            }
        }

        let has_block = items.iter().any(|i| i.kind == InvKind::Block);
        if !has_block {
            return Ok(());
        }
        // 知らないブロックを持っているらしい。ヘッダから確かめる。
        // ハッシュだけでは高さも繋がりも分からないため、本体を直接
        // 求めることはしない。
        self.asked_headers_at = now();
        self.request_headers(handle, out).await
    }

    /// トランザクションを受け取る。
    ///
    /// **頼んでいなかったものは断られる。** そのときは黙って捨てる。
    /// 相手を切りはしない。こちらが時間切れで忘れた直後に届く、といった
    /// 行き違いは普通に起きる。
    ///
    /// 検証に落ちたときも切らない。ブロックと違い、トランザクションが
    /// 受け付けられない理由には無害なものが多い (手数料がこちらの方針に
    /// 足りない、同じ UTXO を使う別のものを先に持っている、など)。
    /// **方針の違いで接続を切ると、ネットワークが方針ごとに割れる。**
    async fn on_tx(
        &mut self,
        handle: &NodeHandle,
        tx: oag_consensus::Transaction,
    ) -> Result<(), String> {
        if let Err(e) = handle.submit_tx_from(tx, Some(self.peer)).await {
            // 記録だけ残す。切る理由にはしない。
            self.rejected_txs = self.rejected_txs.saturating_add(1);
            if self.rejected_txs % 100 == 1 {
                crate::log_warn!(
                    "a transaction was not accepted (entry {}): {e}",
                    self.rejected_txs
                );
            }
        }
        Ok(())
    }
}

async fn send(out: &mpsc::Sender<Message>, message: Message) -> Result<(), String> {
    out.send(message)
        .await
        .map_err(|_| "the send channel is closed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_800_000_000;

    #[test]
    fn it_pings_only_after_the_interval() {
        let mut live = Liveness::new(T0, 7);
        assert_eq!(live.check(T0), Check::Quiet);
        assert_eq!(live.check(T0 + PING_INTERVAL_SECS - 1), Check::Quiet);
        assert_eq!(live.check(T0 + PING_INTERVAL_SECS), Check::Ping(7));
    }

    #[test]
    fn it_does_not_ping_again_while_waiting() {
        let mut live = Liveness::new(T0, 7);
        assert_eq!(live.check(T0 + PING_INTERVAL_SECS), Check::Ping(7));
        // 返事を待っている間は、間隔が過ぎても重ねて送らない。
        let later = T0 + PING_INTERVAL_SECS + PING_INTERVAL_SECS * 2;
        assert_eq!(live.check(later), Check::Quiet);
    }

    #[test]
    fn a_silent_peer_is_dropped_after_the_timeout() {
        let mut live = Liveness::new(T0, 7);
        let sent = T0 + PING_INTERVAL_SECS;
        assert_eq!(live.check(sent), Check::Ping(7));
        assert_eq!(live.check(sent + PONG_TIMEOUT_SECS - 1), Check::Quiet);
        assert_eq!(
            live.check(sent + PONG_TIMEOUT_SECS),
            Check::Silent(PONG_TIMEOUT_SECS)
        );
    }

    #[test]
    fn the_right_pong_keeps_the_peer() {
        let mut live = Liveness::new(T0, 7);
        let sent = T0 + PING_INTERVAL_SECS;
        assert_eq!(live.check(sent), Check::Ping(7));
        live.pong(7);
        // 返事が来たので、時間切れにはならない。次の ping は間隔どおり。
        assert_eq!(live.check(sent + PONG_TIMEOUT_SECS), Check::Ping(8));
    }

    #[test]
    fn a_wrong_or_unasked_pong_is_ignored() {
        let mut live = Liveness::new(T0, 7);
        // 頼んでいない pong。
        live.pong(7);
        let sent = T0 + PING_INTERVAL_SECS;
        assert_eq!(live.check(sent), Check::Ping(7));
        // 違う nonce の pong では生きていることにしない。
        live.pong(6);
        live.pong(8);
        assert_eq!(
            live.check(sent + PONG_TIMEOUT_SECS),
            Check::Silent(PONG_TIMEOUT_SECS)
        );
    }

    #[test]
    fn waking_from_sleep_drops_a_peer_that_was_being_waited_on() {
        let mut live = Liveness::new(T0, 7);
        let sent = T0 + PING_INTERVAL_SECS;
        assert_eq!(live.check(sent), Check::Ping(7));
        // 機械が 1 時間眠っていた。
        assert_eq!(live.check(sent + 3600), Check::Silent(3600));
    }

    #[test]
    fn a_clock_going_backwards_does_not_drop_the_peer() {
        let mut live = Liveness::new(T0, 7);
        let sent = T0 + PING_INTERVAL_SECS;
        assert_eq!(live.check(sent), Check::Ping(7));
        assert_eq!(live.check(sent - 3600), Check::Quiet);
    }

    #[test]
    fn the_nonce_wraps_around() {
        let mut live = Liveness::new(T0, u64::MAX);
        let first = T0 + PING_INTERVAL_SECS;
        assert_eq!(live.check(first), Check::Ping(u64::MAX));
        live.pong(u64::MAX);
        assert_eq!(live.check(first + PING_INTERVAL_SECS), Check::Ping(0));
    }
}
