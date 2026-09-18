//! ブラウザで動くウォレットを配る口。
//!
//! 既定では `127.0.0.1:25565` で待ち受ける。開くと画面がそのまま出る。
//!
//! # 鍵はここを通らない
//!
//! 署名は**ブラウザの中の wasm** で済む。この口が受け取るのは、署名まで
//! 終わったトランザクションの 16 進だけである。種も秘密鍵も、この過程で
//! ノードへ渡らないし、ネットワークにも出ない。
//!
//! だからこちらが差し出すのは 4 つしかない。
//!
//! | 口 | できること |
//! |---|---|
//! | `/api/info` | 高さとネットワークを見る |
//! | `/api/scan` | 渡されたアドレスの未使用出力を数える |
//! | `/api/history` | 渡されたアドレスの履歴を読む |
//! | `/api/send` | 署名済みのものを mempool へ渡す |
//!
//! **どれも P2P で既に誰にでもできることである。** 放送は元から全員の
//! 権利であり、鎖の中身は公開情報である。ここを開けても、ノードにできる
//! ことは増えない。
//!
//! # なぜエクスプローラと同じ口にしないのか
//!
//! ブラウザの localStorage は `scheme + host + port` ごとに仕切られる。
//! **別のポートにすれば、仕切りも別になる。** エクスプローラ側に万一
//! 差し込みの穴があっても、暗号化された記録はそちらから読めない。
//! 同じ口に相乗りさせると、その仕切りが消える。

use crate::service::NodeHandle;
use oag_consensus::codec::{Decode, Encode};
use oag_consensus::lock::Lock;
use oag_consensus::Transaction;
use oag_primitives::{Address, Amount, Network};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// 要求の頭の上限。
const MAX_HEAD: usize = 8 * 1024;
/// 本体の上限。
///
/// まとめのトランザクションは 100,000 バイトまで在りうる。16 進にすると
/// 倍になり、JSON の飾りも乗る。**それが通る幅は要る。**
const MAX_BODY: usize = 512 * 1024;
/// 要求が来ないまま接続を保つ上限。
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// 一度に問い合わせられるアドレスの数。
///
/// 語から復元したときの探索は、これを 1 回分の窓として使う。
const MAX_ADDRESSES: usize = 500;
/// `scanutxos` と同じ上限。
const MAX_SCAN_RESULTS: usize = 10_000;
/// 履歴の 1 回分。
const MAX_HISTORY: usize = 200;

/// 証明書と鍵を読む。
///
/// **証明書だけでは足りない。** 証明書は公開してよいもので、秘密なのは
/// 鍵の方である。片方だけ渡されたら、その場で断る。
pub fn load_tls(cert: &Path, key: &Path) -> Result<TlsAcceptor, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("{} を読めない: {e}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{} を証明書として読めない: {e}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!("{} に証明書が入っていない", cert.display()));
    }
    let private = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| format!("{} を鍵として読めない: {e}", key.display()))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, private)
        .map_err(|e| format!("証明書と鍵が対応していない: {e}"))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// 待ち受けを始める。実際に結びついた住所を返す。
///
/// `tls` を渡さない場合、**この口は平文で配る**。ループバック以外で
/// そうしてよいかの判断は呼んだ側が行う (実行ファイルは断る)。
pub async fn start_wallet(
    handle: NodeHandle,
    addr: SocketAddr,
    tls: Option<TlsAcceptor>,
) -> Result<SocketAddr, String> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("{addr} でウォレットを待ち受けられない: {e}"))?;
    let bound = listener
        .local_addr()
        .map_err(|e| format!("住所を確かめられない: {e}"))?;

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("ウォレットの接続を受け入れられない: {e}");
                    return;
                }
            };
            let handle = handle.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                match tls {
                    // 握手が済むまで中身を読まない。**平文で入ってきた
                    // 要求をうっかり処理しない。** 握手に失敗した相手には
                    // 何も返さず、黙って切る。
                    Some(acceptor) => {
                        if let Ok(stream) = acceptor.accept(stream).await {
                            let _ = serve_connection(stream, handle).await;
                        }
                    }
                    None => {
                        let _ = serve_connection(stream, handle).await;
                    }
                }
            });
        }
    });
    Ok(bound)
}

/// 応答 1 個。
struct Response {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

impl Response {
    fn html(body: String) -> Response {
        Response {
            status: "200 OK",
            content_type: "text/html; charset=utf-8",
            body: body.into_bytes(),
        }
    }

    fn json(status: &'static str, body: String) -> Response {
        Response {
            status,
            content_type: "application/json; charset=utf-8",
            body: body.into_bytes(),
        }
    }

    /// 誤りを JSON で返す。**文言はそのまま画面に出る。**
    fn fault(status: &'static str, message: &str) -> Response {
        Response::json(status, serde_json::json!({ "error": message }).to_string())
    }
}

/// 要求の頭。
struct Head {
    method: String,
    path: String,
    length: usize,
}

async fn serve_connection<S>(mut stream: S, handle: NodeHandle) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = Vec::with_capacity(2048);

    let Some((head, mut body)) = read_head(&mut stream, &mut buffer).await else {
        return write_response(
            &mut stream,
            &Response::fault("400 Bad Request", "要求を読めない"),
        )
        .await;
    };
    if head.length > MAX_BODY {
        return write_response(
            &mut stream,
            &Response::fault("413 Payload Too Large", "本体が大きすぎる"),
        )
        .await;
    }
    // 頭と一緒に届いた分では足りなければ、残りを待つ。
    while body.len() < head.length {
        let mut chunk = vec![0u8; (head.length - body.len()).min(64 * 1024)];
        let read = match tokio::time::timeout(IDLE_TIMEOUT, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
            Ok(Ok(n)) => n,
        };
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(head.length);

    let response = route(&handle, &head, &body).await;
    write_response(&mut stream, &response).await
}

async fn read_head<S>(stream: &mut S, buffer: &mut Vec<u8>) -> Option<(Head, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 2048];
    let split = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if buffer.len() > MAX_HEAD {
            return None;
        }
        let read = tokio::time::timeout(IDLE_TIMEOUT, stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let text = String::from_utf8_lossy(&buffer[..split]).to_string();
    let mut lines = text.lines();
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let path = first.next()?.to_string();

    let mut length = 0usize;
    for line in lines {
        if let Some(value) = line
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim())
        {
            length = value.parse().ok()?;
        }
    }
    Some((
        Head {
            method,
            path,
            length,
        },
        buffer[split..].to_vec(),
    ))
}

async fn write_response<S>(stream: &mut S, response: &Response) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    // **外から何も引き込ませない。** 画面も JS も wasm も、この口が
    // 配ったものだけで完結する。差し替えられたら鍵が抜かれる場所なので、
    // 読み込み元を自分自身に限る。
    let head = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {ctype}\r\n\
         Content-Length: {len}\r\n\
         Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; \
         style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; \
         base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         X-Robots-Tag: noindex, nofollow\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        status = response.status,
        ctype = response.content_type,
        len = response.body.len(),
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    stream.flush().await
}

// ━━━━━━━━ 経路 ━━━━━━━━

async fn route(handle: &NodeHandle, head: &Head, body: &[u8]) -> Response {
    let path = head.path.split('?').next().unwrap_or("/");
    match (head.method.as_str(), path) {
        ("GET", "/") => Response::html(page()),
        ("GET", "/app.js") => Response {
            status: "200 OK",
            content_type: "text/javascript; charset=utf-8",
            body: APP_JS.as_bytes().to_vec(),
        },
        ("GET", "/wallet.wasm") => Response {
            status: "200 OK",
            content_type: "application/wasm",
            body: WALLET_WASM.to_vec(),
        },
        ("POST", "/api/info") => api_info(handle).await,
        ("POST", "/api/scan") => api_scan(handle, body).await,
        ("POST", "/api/history") => api_history(handle, body).await,
        ("POST", "/api/send") => api_send(handle, body).await,
        ("GET", _) => Response::fault("404 Not Found", "そのような頁は無い"),
        _ => Response::fault("405 Method Not Allowed", "その手続きは受け付けない"),
    }
}

fn parse(body: &[u8]) -> Result<serde_json::Value, Response> {
    serde_json::from_slice(body)
        .map_err(|e| Response::fault("400 Bad Request", &format!("要求が読めない: {e}")))
}

/// 問い合わせ用のアドレスを読む。**知らない形は先に断る。**
fn locks_of(
    value: &serde_json::Value,
    network: Network,
) -> Result<(Vec<Lock>, Vec<String>), Response> {
    let list = value
        .get("addresses")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Response::fault("400 Bad Request", "addresses が無い"))?;
    if list.len() > MAX_ADDRESSES {
        return Err(Response::fault(
            "400 Bad Request",
            &format!("一度に問い合わせられるのは {MAX_ADDRESSES} 個まで"),
        ));
    }
    let mut locks = Vec::with_capacity(list.len());
    let mut texts = Vec::with_capacity(list.len());
    for item in list {
        let text = item
            .as_str()
            .ok_or_else(|| Response::fault("400 Bad Request", "アドレスは文字列であること"))?;
        let address = Address::decode_on(network, text).map_err(|e| {
            Response::fault("400 Bad Request", &format!("アドレス {text} が不正: {e}"))
        })?;
        locks.push(Lock::from_address(&address));
        texts.push(text.to_string());
    }
    Ok((locks, texts))
}

async fn api_info(handle: &NodeHandle) -> Response {
    let height = match handle.status().await {
        Ok(status) => status.height,
        Err(e) => return Response::fault("500 Internal Server Error", &e),
    };
    let indexed = handle.index_from().await.ok().flatten().is_some();
    Response::json(
        "200 OK",
        serde_json::json!({
            "network": handle.network().to_string(),
            "height": height,
            "indexed": indexed,
            "maturity": oag_consensus::params::COINBASE_MATURITY,
            "feerate": oag_consensus::params::MIN_RELAY_FEE_RATE_PER_BYTE.to_atomic().to_string(),
            "dust": oag_consensus::params::DUST_THRESHOLD.to_atomic().to_string(),
        })
        .to_string(),
    )
}

async fn api_scan(handle: &NodeHandle, body: &[u8]) -> Response {
    let request = match parse(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let network = handle.network();
    let (locks, texts) = match locks_of(&request, network) {
        Ok(pair) => pair,
        Err(response) => return response,
    };

    let found = match handle.scan_utxos(locks.clone(), MAX_SCAN_RESULTS).await {
        Ok(found) => found,
        Err(e) => return Response::fault("500 Internal Server Error", &e),
    };
    let total = match Amount::sum(found.iter().map(|r| r.entry.output.amount)) {
        Some(total) => total,
        None => return Response::fault("500 Internal Server Error", "合計が桁あふれした"),
    };

    let utxos: Vec<serde_json::Value> = found
        .iter()
        .map(|record| {
            let address = locks
                .iter()
                .position(|l| *l == record.entry.output.lock)
                .map(|i| texts[i].clone());
            serde_json::json!({
                "txid": record.outpoint.txid.to_string(),
                "index": record.outpoint.index,
                "amount": record.entry.output.amount.to_atomic().to_string(),
                "amountoag": record.entry.output.amount.to_string(),
                "height": record.entry.height,
                "coinbase": record.entry.is_coinbase,
                "address": address,
            })
        })
        .collect();

    Response::json(
        "200 OK",
        serde_json::json!({
            "total": total.to_atomic().to_string(),
            "totaloag": total.to_string(),
            "count": found.len(),
            // 上限に達したなら、返した分がすべてではない。
            "truncated": found.len() >= MAX_SCAN_RESULTS,
            "utxos": utxos,
        })
        .to_string(),
    )
}

/// 履歴。**探索にも使う。**
///
/// 未使用出力だけを見ると、「受け取って全部使ったアドレス」が空に見える。
/// 語から復元したときにそれを空と誤ると、その先を探すのをやめてしまう。
async fn api_history(handle: &NodeHandle, body: &[u8]) -> Response {
    let request = match parse(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let network = handle.network();
    let (locks, texts) = match locks_of(&request, network) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let from = request
        .get("from")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let max = request
        .get("max")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(MAX_HISTORY as u64)
        .min(MAX_HISTORY as u64) as usize;

    let mut used = Vec::new();
    for (lock, text) in locks.iter().zip(texts.iter()) {
        match handle.address_history(lock.clone(), from, max).await {
            Ok(records) if !records.is_empty() => used.push(serde_json::json!({
                "address": text,
                "count": records.len(),
                "last": records.last().map(|r| r.location.height),
            })),
            Ok(_) => {}
            Err(e) => return Response::fault("500 Internal Server Error", &e),
        }
    }
    Response::json("200 OK", serde_json::json!({ "used": used }).to_string())
}

async fn api_send(handle: &NodeHandle, body: &[u8]) -> Response {
    let request = match parse(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some(text) = request.get("hex").and_then(serde_json::Value::as_str) else {
        return Response::fault("400 Bad Request", "hex が無い");
    };
    let Ok(raw) = hex::decode(text) else {
        return Response::fault("400 Bad Request", "hex が 16 進として読めない");
    };
    let tx = match Transaction::decode(&raw) {
        Ok(tx) => tx,
        Err(e) => return Response::fault("400 Bad Request", &format!("取引として読めない: {e}")),
    };
    // **読み直して同じにならないものは断る。** 余計な尾が付いたものを
    // 通すと、放送した中身と手元の表示がずれる。
    if tx.encode() != raw {
        return Response::fault("400 Bad Request", "取引の符号化が一意でない");
    }

    match handle.submit_tx(tx).await {
        Ok(txid) => Response::json(
            "200 OK",
            serde_json::json!({ "txid": txid.to_string() }).to_string(),
        ),
        Err(e) => Response::fault("400 Bad Request", &e),
    }
}

// ━━━━━━━━ 配りもの ━━━━━━━━

/// ブラウザで動く本体。`cargo build` だけで作れる。
///
/// 作り直し方は `crates/oag-node/assets/README.md` にある。
static WALLET_WASM: &[u8] = include_bytes!("../assets/wallet.wasm");
const APP_JS: &str = include_str!("../assets/wallet.js");
const APP_HTML: &str = include_str!("../assets/wallet.html");

/// 画面を組む。様式はエクスプローラと同じものを使う。
fn page() -> String {
    APP_HTML.replace("/*CSS*/", crate::explorer::CSS)
}
