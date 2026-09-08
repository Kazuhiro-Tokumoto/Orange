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

use crate::service::NodeHandle;
use oag_net::message::{
    GetHeaders, InvItem, InvKind, Message, VersionMessage, MAX_HEADERS, PROTOCOL_VERSION,
};
use oag_net::sync::PeerId;
use oag_net::transport::{Connection, TransportError};
use oag_primitives::Hash;
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
        services: 0,
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
        .map_err(|e| format!("{addr} とのハンドシェイクに失敗した: {e}"))?;
    println!(
        "ピア {addr} と繋がった ({}、高さ {})",
        theirs.user_agent, theirs.start_height
    );

    let result = session(&handle, peer, conn, theirs.start_height, direction).await;
    handle.peer_gone(peer).await?;
    println!("ピア {addr} との接続が切れた");
    result
}

async fn session(
    handle: &NodeHandle,
    peer: PeerId,
    conn: Connection,
    peer_height: u64,
    direction: Direction,
) -> Result<(), String> {
    let (mut reader, mut writer) = conn.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(SEND_QUEUE);
    let (in_tx, mut in_rx) = mpsc::channel::<Message>(SEND_QUEUE);

    // 送る作業。
    let sender = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if writer.send(&message).await.is_err() {
                break;
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
                    eprintln!("受信に失敗した: {e}");
                    break;
                }
            }
        }
    });

    let mut events = handle.subscribe();
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut state = Session {
        peer,
        peer_height,
        asked_headers_at: 0,
        addr_requests: 0,
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
                    Ok(crate::service::NodeEvent::NewTip { hash, .. }) => {
                        // 新しい先端を持っていることを知らせる。
                        let inv = Message::Inv(vec![InvItem::block(hash)]);
                        if out_tx.send(inv).await.is_err() {
                            break Ok(());
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
    /// 相手が名乗った高さ。`inv` や `headers` が来るたびに更新する。
    peer_height: u64,
    /// 最後に `getheaders` を送った時刻。
    asked_headers_at: i64,
    /// この接続で `getaddr` を受けた回数。**応えるのは 1 度だけ。**
    addr_requests: u32,
}

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
        self.maybe_request_headers(handle, out).await?;
        self.request_bodies(handle, out).await
    }

    async fn on_message(
        &mut self,
        handle: &NodeHandle,
        out: &mpsc::Sender<Message>,
        message: Message,
    ) -> Result<(), String> {
        match message {
            Message::Ping(nonce) => send(out, Message::Pong(nonce)).await,
            Message::Pong(_) => Ok(()),

            // ハンドシェイクは済んでいる。重ねて来たら断る。
            Message::Version(_) | Message::Verack => {
                Err("ハンドシェイク後に version/verack が来た".to_string())
            }

            Message::GetHeaders(request) => {
                let headers = handle.headers_after(request.locator, request.stop).await?;
                send(out, Message::Headers(headers)).await
            }

            Message::Headers(headers) => self.on_headers(handle, out, headers).await,

            Message::GetData(items) => self.on_getdata(handle, out, items).await,

            Message::Block(block) => self.on_block(handle, out, *block).await,

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
                // 中身は相手が決める。住所帳の側で上限と括りに従わせる。
                handle.add_addresses(addrs).await
            }

            // まだ扱わないもの。無視してよい。相手を切る理由にはならない。
            Message::NotFound(_)
            | Message::Tx(_)
            | Message::Mempool
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

        let accepted = handle.accept_headers(headers).await?;
        println!(
            "ヘッダを {} 件受け取った (うち新規 {})",
            accepted.total, accepted.new
        );

        // 満杯で返ってきたなら、まだ続きがある。すぐ求める。
        if full && accepted.new > 0 {
            self.asked_headers_at = now();
            self.request_headers(handle, out).await?;
        }
        self.request_bodies(handle, out).await
    }

    async fn on_getdata(
        &mut self,
        handle: &NodeHandle,
        out: &mpsc::Sender<Message>,
        items: Vec<InvItem>,
    ) -> Result<(), String> {
        let mut missing = Vec::new();
        for item in items {
            if item.kind != InvKind::Block {
                missing.push(item);
                continue;
            }
            match handle.block(item.hash).await? {
                Some(block) => send(out, Message::Block(Box::new(block))).await?,
                None => missing.push(item),
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
        match handle.accept_block(block).await {
            Ok(accepted) => {
                if accepted.moved_tip {
                    println!("高さ {height} まで繋がった");
                }
            }
            // 不正なブロックを送ってきた相手は切る。
            Err(e) => return Err(format!("高さ {height} のブロックを受け付けられない: {e}")),
        }
        self.request_bodies(handle, out).await
    }

    async fn on_inv(
        &mut self,
        handle: &NodeHandle,
        out: &mpsc::Sender<Message>,
        items: Vec<InvItem>,
    ) -> Result<(), String> {
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
}

async fn send(out: &mpsc::Sender<Message>, message: Message) -> Result<(), String> {
    out.send(message)
        .await
        .map_err(|_| "送信の口が閉じている".to_string())
}
