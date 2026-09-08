//! JSON-RPC を運ぶための、必要最小限の HTTP/1.1。
//!
//! # なぜ HTTP の実装を持つのか
//!
//! bitcoind と同じく JSON-RPC over HTTP を提供する。取引所やエクスプ
//! ローラの繋ぎこみ先として最も広く通じる形だからである。一方、必要な
//! のは「`POST /` に JSON の本文を 1 個」という一点に尽きる。汎用の
//! HTTP 実装を引き込むのは釣り合わない。
//!
//! **したがって、ここで受け付けるのは次だけである。**
//!
//! - メソッドは `POST`、パスは `/`
//! - `Content-Length` が必ずある (`Transfer-Encoding` は断る)
//! - 本文は [`MAX_BODY`] まで、ヘッダは [`MAX_HEADERS`] まで
//!
//! 接続の使い回し (keep-alive) には応じるが、要求と応答は 1 対 1 で
//! 順に処理する。並行して詰め込む形 (pipelining) は前提にしない。
//!
//! # 締め出しの既定値
//!
//! **待ち受けはループバックのみを既定とする** (SPEC §14.1)。RPC を外部
//! 公開した結果として資金を喪失する事故は複数のプロジェクトで起きている。
//! そのうえで合言葉による認証を必須とする。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// ヘッダ全体の上限。
pub const MAX_HEADERS: usize = 8 * 1024;

/// 本文の上限。
///
/// 最も大きな引数は生のブロック (200,000 バイト) を 16 進にしたもので、
/// 400,000 文字である。10 倍の余裕を見てある。
pub const MAX_BODY: usize = 4 * 1024 * 1024;

/// 1 回の読み取りの大きさ。
const READ_CHUNK: usize = 8 * 1024;

/// 要求が来ないまま接続を保つ上限。
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// HTTP 層の失敗。
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// 入出力の誤り。
    #[error("入出力に失敗した: {0}")]
    Io(#[from] std::io::Error),
    /// 相手が接続を閉じた。
    #[error("相手が接続を閉じた")]
    Closed,
}

/// 受け付けた要求の中身。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    /// 本文。
    pub text: String,
    /// `Authorization` ヘッダの中身。無ければ `None`。
    pub authorization: Option<String>,
    /// 相手が `Connection: close` を求めたか。
    ///
    /// **求められたら応答したあとに閉じる。** 閉じずにいると、終わりを
    /// 待っている相手が待ち続けることになる。
    pub close: bool,
}

/// 断る理由。応答の状態行に対応する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    BadRequest,
    NotFound,
    MethodNotAllowed,
    PayloadTooLarge,
    Unauthorized,
}

impl Refusal {
    fn status(self) -> (u16, &'static str) {
        match self {
            Refusal::BadRequest => (400, "Bad Request"),
            Refusal::Unauthorized => (401, "Unauthorized"),
            Refusal::NotFound => (404, "Not Found"),
            Refusal::MethodNotAllowed => (405, "Method Not Allowed"),
            Refusal::PayloadTooLarge => (413, "Payload Too Large"),
        }
    }
}

/// 要求を受け取って応答の JSON を返す handler。
pub type Handler = Arc<
    dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = String> + Send>>
        + Send
        + Sync,
>;

/// JSON-RPC の待ち受け。
pub struct Server {
    listener: TcpListener,
    /// 認証に用いる合言葉。`Authorization` ヘッダと丸ごと突き合わせる。
    credential: String,
    handler: Handler,
}

impl Server {
    /// 待ち受けを始める。
    ///
    /// ポートに 0 を指定すると空いているポートが選ばれる。実際の住所は
    /// [`Server::local_addr`] で得られる。
    pub async fn bind(
        addr: SocketAddr,
        credential: String,
        handler: Handler,
    ) -> Result<Server, HttpError> {
        Ok(Server {
            listener: TcpListener::bind(addr).await?,
            credential,
            handler,
        })
    }

    /// 待ち受けている住所。
    pub fn local_addr(&self) -> Result<SocketAddr, HttpError> {
        Ok(self.listener.local_addr()?)
    }

    /// 接続を受け付け続ける。待ち受けが壊れるまで戻らない。
    pub async fn serve(self) {
        loop {
            let (stream, _) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("RPC の接続を受け入れられない: {e}");
                    return;
                }
            };
            let credential = self.credential.clone();
            let handler = Arc::clone(&self.handler);
            tokio::spawn(async move {
                if let Err(e) = serve_connection(stream, &credential, handler).await {
                    // 相手が黙って切るのは日常であり、報せる価値がない。
                    if !matches!(e, HttpError::Closed) {
                        eprintln!("RPC の接続を打ち切った: {e}");
                    }
                }
            });
        }
    }
}

async fn serve_connection(
    mut stream: TcpStream,
    credential: &str,
    handler: Handler,
) -> Result<(), HttpError> {
    stream.set_nodelay(true)?;
    let mut buffer = Vec::with_capacity(READ_CHUNK);

    loop {
        let body = match read_request(&mut stream, &mut buffer).await {
            Ok(Some(body)) => body,
            // 接続の使い回しの終わり。
            Ok(None) => return Ok(()),
            Err(RequestError::Closed) => return Ok(()),
            Err(RequestError::Io(e)) => return Err(HttpError::Io(e)),
            Err(RequestError::Refused(refusal)) => {
                write_refusal(&mut stream, refusal).await?;
                // 形が壊れているなら、続きも信用できない。切る。
                return Ok(());
            }
        };

        // 合言葉は一致しなければならない。**引く前に確かめる**。
        if body.authorization.as_deref() != Some(credential) {
            write_refusal(&mut stream, Refusal::Unauthorized).await?;
            return Ok(());
        }

        let close = body.close;
        let reply = handler(body.text).await;
        write_json(&mut stream, &reply, close).await?;
        if close {
            return Ok(());
        }
    }
}

/// 要求の読み取りで起きうること。
enum RequestError {
    Closed,
    Io(std::io::Error),
    Refused(Refusal),
}

impl From<std::io::Error> for RequestError {
    fn from(e: std::io::Error) -> RequestError {
        RequestError::Io(e)
    }
}

/// 要求を 1 個読む。接続の使い回しの終わりなら `Ok(None)`。
async fn read_request(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
) -> Result<Option<Body>, RequestError> {
    // ヘッダの終わりまで読む。
    let header_end = loop {
        if let Some(at) = find_header_end(buffer) {
            break at;
        }
        if buffer.len() > MAX_HEADERS {
            return Err(RequestError::Refused(Refusal::BadRequest));
        }
        let read = read_more(stream, buffer).await?;
        if read == 0 {
            return if buffer.is_empty() {
                Ok(None)
            } else {
                Err(RequestError::Closed)
            };
        }
    };

    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();

    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(RequestError::Refused(Refusal::BadRequest));
    }

    let mut content_length: Option<usize> = None;
    let mut authorization: Option<String> = None;
    let mut close = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            // 長さを宣言しない送り方は受け付けない。読み終わりを
            // 相手任せにすると、いくらでも送り続けられる。
            "transfer-encoding" => return Err(RequestError::Refused(Refusal::BadRequest)),
            "content-length" => {
                content_length = Some(
                    value
                        .parse()
                        .map_err(|_| RequestError::Refused(Refusal::BadRequest))?,
                );
            }
            "authorization" => authorization = Some(value.to_string()),
            "connection" => close = value.eq_ignore_ascii_case("close"),
            _ => {}
        }
    }

    // 経路とメソッドの検査は、本文を読む前に済ませる。
    if method != "POST" {
        return Err(RequestError::Refused(Refusal::MethodNotAllowed));
    }
    if path != "/" {
        return Err(RequestError::Refused(Refusal::NotFound));
    }

    let Some(length) = content_length else {
        return Err(RequestError::Refused(Refusal::BadRequest));
    };
    // **宣言された長さを、読む前に検査する。** 読みながら数えたのでは、
    // 上限を超えていると分かる頃には受け取ってしまっている。
    if length > MAX_BODY {
        return Err(RequestError::Refused(Refusal::PayloadTooLarge));
    }

    let body_start = header_end + 4;
    while buffer.len() < body_start + length {
        let read = read_more(stream, buffer).await?;
        if read == 0 {
            return Err(RequestError::Closed);
        }
    }

    let text = String::from_utf8_lossy(&buffer[body_start..body_start + length]).into_owned();
    buffer.drain(..body_start + length);
    Ok(Some(Body {
        text,
        authorization,
        close,
    }))
}

async fn read_more(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Result<usize, RequestError> {
    let mut chunk = [0u8; READ_CHUNK];
    let read = match tokio::time::timeout(IDLE_TIMEOUT, stream.read(&mut chunk)).await {
        Ok(result) => result?,
        // 黙り込んだ相手に接続を握られ続けないようにする。
        Err(_) => return Err(RequestError::Closed),
    };
    buffer.extend_from_slice(&chunk[..read]);
    Ok(read)
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n")
}

async fn write_json(stream: &mut TcpStream, body: &str, close: bool) -> Result<(), HttpError> {
    let connection = if close { "close" } else { "keep-alive" };
    let head = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: {connection}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn write_refusal(stream: &mut TcpStream, refusal: Refusal) -> Result<(), HttpError> {
    let (code, reason) = refusal.status();
    // 断る理由は状態行だけで伝える。本文で詳しく述べても、認証を通って
    // いない相手に手掛かりを与えるだけである。
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}
