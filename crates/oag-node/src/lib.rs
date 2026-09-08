//! Orange (OAG) のノード。
//!
//! - [`genesis`] — ネットワークごとのジェネシスブロック
//! - [`node`] — チェーン・mempool・採掘を束ねた本体
//! - [`service`] — 本体を専用スレッドに載せ、非同期側から使えるようにする
//! - [`peer`] — 1 本の接続の面倒を見る
//! - [`rpc`] — JSON-RPC の手続き
//!
//! 実行ファイルは `main.rs` にあり、ここを呼ぶだけの薄い層である。
//! 束ねる部分を library に置いているのは、**2 台のノードを実際に繋いだ
//! 試験**を書けるようにするためである。

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod genesis;
pub mod node;
pub mod peer;
pub mod rpc;
pub mod service;

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
    loop {
        match listener.accept().await {
            Ok(conn) => {
                let handle = handle.clone();
                tokio::spawn(async move {
                    if let Err(e) = peer::run(handle, conn).await {
                        eprintln!("ピアとのやり取りを打ち切った: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("接続を受け入れられない: {e}");
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
                eprintln!("{addr} とのやり取りを打ち切った: {e}");
            }
        }
        Err(e) => eprintln!("{addr} に繋げない: {e}"),
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
            .map_err(|e| format!("{addr} で RPC を待ち受けられない: {e}"))?;
    let bound = server.local_addr().map_err(|e| e.to_string())?;
    println!("RPC を {bound} で待ち受ける (合言葉: {})", path.display());
    tokio::spawn(server.serve());
    Ok(bound)
}
