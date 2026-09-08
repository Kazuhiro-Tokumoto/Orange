//! JSON-RPC の呼び出し側。
//!
//! ウォレットの CLI がノードを呼ぶために使う。[`crate::http`] が受け付ける
//! 範囲だけを話す。

use crate::auth::Credential;
use crate::jsonrpc::{Request, Response, RpcError};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 応答を待つ上限。
const TIMEOUT: Duration = Duration::from_secs(60);

/// 読み取りの単位。
const READ_CHUNK: usize = 8 * 1024;

/// 受け取る応答の上限。
const MAX_RESPONSE: usize = crate::http::MAX_BODY;

/// 呼び出しの失敗。
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// 繋がらない、または途中で切れた。
    #[error("RPC に繋がらない: {0}")]
    Io(#[from] std::io::Error),
    /// 応答が返らなかった。
    #[error("RPC の応答が {0:?} 以内に返らなかった")]
    Timeout(Duration),
    /// HTTP として断られた。
    #[error("RPC に断られた: {status}")]
    Http {
        /// 状態行。
        status: String,
    },
    /// 応答が JSON として読めない。
    #[error("RPC の応答を読めない: {0}")]
    Malformed(String),
    /// ノードが誤りを返した。
    #[error("{}: {}", .0.code, .0.message)]
    Rpc(RpcError),
}

/// ノードへの呼び出し口。
pub struct Client {
    addr: SocketAddr,
    credential: Credential,
    next_id: AtomicI64,
}

impl Client {
    /// 呼び出し口を作る。繋ぐのは呼び出しのときである。
    pub fn new(addr: SocketAddr, credential: Credential) -> Client {
        Client {
            addr,
            credential,
            next_id: AtomicI64::new(1),
        }
    }

    /// 手続きを 1 個呼ぶ。
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, ClientError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = Request::new(id, method, params);
        let body = serde_json::to_string(&request).expect("要求は必ず JSON になる");

        let text = tokio::time::timeout(TIMEOUT, self.round_trip(&body))
            .await
            .map_err(|_| ClientError::Timeout(TIMEOUT))??;

        let response: Response =
            serde_json::from_str(&text).map_err(|e| ClientError::Malformed(e.to_string()))?;
        if let Some(error) = response.error {
            return Err(ClientError::Rpc(error));
        }
        response
            .result
            .ok_or_else(|| ClientError::Malformed("result も error も無い".to_string()))
    }

    async fn round_trip(&self, body: &str) -> Result<String, ClientError> {
        let mut stream = TcpStream::connect(self.addr).await?;
        stream.set_nodelay(true)?;

        let head = format!(
            "POST / HTTP/1.1\r\n\
             Host: {}\r\n\
             Authorization: {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            self.addr,
            self.credential.header_value(),
            body.len()
        );
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body.as_bytes()).await?;
        stream.flush().await?;

        // ヘッダの終わりまで読む。
        let mut buffer = Vec::with_capacity(READ_CHUNK);
        let header_end = loop {
            if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                break at;
            }
            if read_more(&mut stream, &mut buffer).await? == 0 {
                return Err(ClientError::Malformed("ヘッダの終わりが無い".to_string()));
            }
        };

        let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
        let status = head.lines().next().unwrap_or_default().to_string();
        if !status.contains(" 200 ") {
            return Err(ClientError::Http { status });
        }

        // **本文は宣言された長さだけ読む。** 相手が閉じるのを待つと、
        // 接続を使い回す相手とは永久にすれ違う。
        let length = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .ok_or_else(|| ClientError::Malformed("Content-Length が無い".to_string()))?;
        if length > MAX_RESPONSE {
            return Err(ClientError::Malformed(format!(
                "応答が上限 {MAX_RESPONSE} を超えた"
            )));
        }

        let body_start = header_end + 4;
        while buffer.len() < body_start + length {
            if read_more(&mut stream, &mut buffer).await? == 0 {
                return Err(ClientError::Malformed("応答が途中で切れた".to_string()));
            }
        }
        Ok(String::from_utf8_lossy(&buffer[body_start..body_start + length]).into_owned())
    }
}

async fn read_more(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Result<usize, ClientError> {
    let mut chunk = [0u8; READ_CHUNK];
    let read = stream.read(&mut chunk).await?;
    buffer.extend_from_slice(&chunk[..read]);
    Ok(read)
}
