//! Orange (OAG) のノード。
//!
//! - [`addrbook`] — ピアの住所帳
//! - [`connect`] — 外向きの接続を保つ
//! - [`log`] — 記録の印付け
//! - [`genesis`] — ネットワークごとのジェネシスブロック
//! - [`node`] — チェーン・mempool・採掘を束ねた本体
//! - [`service`] — 本体を専用スレッドに載せ、非同期側から使えるようにする
//! - [`peer`] — 1 本の接続の面倒を見る
//! - [`rpc`] — JSON-RPC の手続き
//! - [`seeds`] — 最初の繋ぎ先 (DNS シード)
//!
//! 実行ファイルは `main.rs` にあり、ここを呼ぶだけの薄い層である。
//! 束ねる部分を library に置いているのは、**2 台のノードを実際に繋いだ
//! 試験**を書けるようにするためである。

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod addrbook;
pub mod connect;
pub mod explorer;
pub mod genesis;
pub mod light;
pub mod log;
pub mod node;
pub mod peer;
pub mod rpc;
pub mod seeds;
pub mod service;
pub mod wallet;

use oag_net::magic::magic_for;
use oag_net::transport::{Connection, Listener};
use oag_rpc::auth::{write_cookie, AuthError, Credential, COOKIE_USER};
use service::NodeHandle;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

/// 待ち受けた接続を順に受け入れる。
///
/// 待ち受けが壊れるまで戻らない。
pub async fn accept_loop(handle: NodeHandle, listener: Listener) {
    // 断っている最中か。記録を 1 度ずつ出すために覚える。
    let mut refusing = false;
    loop {
        match listener.accept().await {
            Ok(conn) => {
                // **同期の最中は繋がれても応えない。** 追いつくまで渡せる
                // ものが無く、相手の外向きの枠を 1 本無駄にさせるだけである。
                // 名乗り合う前に閉じるので、相手は住所帳でこちらを減点しない。
                if handle.is_syncing().await.unwrap_or(false) {
                    if !refusing {
                        crate::log_peer!("syncing, so not accepting connections until caught up");
                        refusing = true;
                    }
                    drop(conn);
                    continue;
                }
                if refusing {
                    crate::log_peer!("caught up, so accepting connections again");
                    refusing = false;
                }
                let handle = handle.clone();
                tokio::spawn(async move {
                    if let Err(e) = peer::run(handle, conn).await {
                        crate::log_warn!("dropped the exchange with the peer: {e}");
                    }
                });
            }
            Err(e) => {
                crate::log_warn!("cannot accept the connection: {e}");
                return;
            }
        }
    }
}

/// 相手に繋ぎにいく。
pub async fn dial(handle: NodeHandle, addr: SocketAddr) {
    let network = handle.network();
    match Connection::connect(magic_for(network), addr).await {
        Ok(conn) => {
            if let Err(e) = peer::run(handle, conn).await {
                crate::log_warn!("dropped the exchange with {addr}: {e}");
            }
        }
        Err(e) => crate::log_warn!("cannot connect to {addr}: {e}"),
    }
}

/// 相手に繋ぎに行き、切れたら繋ぎ直す。**戻らない。**
///
/// `--no-discovery` で名指しした相手用である。住所帳を使わないので、
/// 切れた相手を補充する仕組みが他に無い。**返事の無い相手は `ping` で
/// 切る** ([`peer`]) ので、繋ぎ直さないと二度と繋がらない。
pub async fn keep_dialling(handle: NodeHandle, addr: SocketAddr) {
    /// 切れてから繋ぎ直すまでの間。
    const REDIAL: std::time::Duration = std::time::Duration::from_secs(5);
    loop {
        dial(handle.clone(), addr).await;
        tokio::time::sleep(REDIAL).await;
    }
}

/// RPC の待ち受けを起こす。
///
/// 使い捨ての合言葉を作り、データディレクトリの `.cookie` に書き出す。
/// 呼び出し側 (ウォレットの CLI) はそれを読んで認証する。
///
/// 実際に開いた住所を返す。
pub async fn start_rpc(
    handle: NodeHandle,
    addr: SocketAddr,
    data_dir: &Path,
) -> Result<SocketAddr, String> {
    // 合言葉は起動のたびに作り直す。漏れても次の起動で無効になる。
    let secret: String = oag_primitives::SecretKey::generate()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let userpass = format!("{COOKIE_USER}:{secret}");
    let path = write_cookie(data_dir, &userpass).map_err(|e: AuthError| e.to_string())?;
    let credential = Credential::from_userpass(&userpass);

    let rpc_handle: oag_rpc::http::Handler = Arc::new(move |body: String| {
        let handle = handle.clone();
        Box::pin(async move { rpc::handle(handle, body).await })
    });

    let server =
        oag_rpc::http::Server::bind(addr, credential.header_value().to_string(), rpc_handle)
            .await
            .map_err(|e| format!("cannot listen for RPC on {addr}: {e}"))?;
    let bound = server.local_addr().map_err(|e| e.to_string())?;
    println!("listening for RPC on {bound} (cookie: {})", path.display());
    tokio::spawn(server.serve());
    Ok(bound)
}
