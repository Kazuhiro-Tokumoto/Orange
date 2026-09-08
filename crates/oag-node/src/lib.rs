//! Orange (OAG) のノード。
//!
//! - [`genesis`] — ネットワークごとのジェネシスブロック
//! - [`node`] — チェーン・mempool・採掘を束ねた本体
//! - [`service`] — 本体を専用スレッドに載せ、非同期側から使えるようにする
//! - [`peer`] — 1 本の接続の面倒を見る
//!
//! 実行ファイルは `main.rs` にあり、ここを呼ぶだけの薄い層である。
//! 束ねる部分を library に置いているのは、**2 台のノードを実際に繋いだ
//! 試験**を書けるようにするためである。

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod genesis;
pub mod node;
pub mod peer;
pub mod service;

use oag_net::magic::magic_for;
use oag_net::transport::{Connection, Listener};
use service::NodeHandle;
use std::net::SocketAddr;

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
