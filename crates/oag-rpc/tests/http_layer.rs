//! HTTP 層を、実際にソケットに繋いで試す。
//!
//! この層は手で書いてある。受け付ける範囲が狭いことこそが安全の根拠で
//! あり、**範囲の外をきちんと断ること**を確かめないと意味がない。

use oag_rpc::auth::Credential;
use oag_rpc::http::{Handler, Server, MAX_BODY};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SECRET: &str = "__cookie__:0123456789abcdef";

fn credential() -> Credential {
    Credential::from_userpass(SECRET)
}

/// 受け取った本文をそのまま返す handler。
fn echo() -> Handler {
    Arc::new(|body: String| Box::pin(async move { format!("{{\"echo\":{}}}", body.len()) }))
}

/// 待ち受けを起こし、その住所を返す。
async fn start(handler: Handler) -> SocketAddr {
    let server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        credential().header_value().to_string(),
        handler,
    )
    .await
    .expect("待ち受けられる");
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());
    addr
}

/// 生のバイト列を送り、**相手が接続を閉じるまで**読む。
///
/// 閉じるのを待ち切ることに意味がある。閉じないまま応答だけ読んで
/// 済ませると、「閉じるべきときに閉じていない」不具合を見逃す。
/// 実際にそれで一度取り逃がした。
async fn raw(addr: SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request).await.unwrap();
    stream.flush().await.unwrap();

    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
        .await
        .expect("相手が接続を閉じるはず")
        .expect("読み取りに失敗した");
    String::from_utf8_lossy(&out).into_owned()
}

fn post(body: &str, authorization: Option<&str>) -> Vec<u8> {
    let auth = match authorization {
        Some(value) => format!("Authorization: {value}\r\n"),
        None => String::new(),
    };
    format!(
        "POST / HTTP/1.1\r\nHost: x\r\n{auth}Connection: close\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[tokio::test]
async fn a_valid_request_is_answered() {
    let addr = start(echo()).await;
    let reply = raw(addr, &post("{\"a\":1}", Some(credential().header_value()))).await;
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
    assert!(reply.contains("{\"echo\":7}"), "{reply}");
}

#[tokio::test]
async fn a_request_without_a_credential_is_refused() {
    let addr = start(echo()).await;
    let reply = raw(addr, &post("{}", None)).await;
    assert!(reply.starts_with("HTTP/1.1 401"), "{reply}");
}

#[tokio::test]
async fn a_request_with_the_wrong_credential_is_refused() {
    let addr = start(echo()).await;
    let wrong = Credential::from_userpass("__cookie__:deadbeef");
    let reply = raw(addr, &post("{}", Some(wrong.header_value()))).await;
    assert!(reply.starts_with("HTTP/1.1 401"), "{reply}");
    // 断る理由を本文で述べない。認証を通っていない相手に手掛かりを与えない。
    assert!(!reply.contains("cookie"), "{reply}");
}

#[tokio::test]
async fn the_handler_is_not_reached_without_a_credential() {
    // handler が走ったら分かるようにしておく。
    let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&reached);
    let handler: Handler = Arc::new(move |_body: String| {
        let flag = Arc::clone(&flag);
        Box::pin(async move {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            "{}".to_string()
        })
    });

    let addr = start(handler).await;
    raw(addr, &post("{}", None)).await;
    assert!(
        !reached.load(std::sync::atomic::Ordering::SeqCst),
        "認証を通す前に handler が走っている"
    );
}

#[tokio::test]
async fn a_get_is_refused() {
    let addr = start(echo()).await;
    let reply = raw(addr, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(reply.starts_with("HTTP/1.1 405"), "{reply}");
}

#[tokio::test]
async fn another_path_is_refused() {
    let addr = start(echo()).await;
    let request = format!(
        "POST /admin HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\n\
         Connection: close\r\nContent-Length: 2\r\n\r\n{{}}",
        credential().header_value()
    );
    let reply = raw(addr, request.as_bytes()).await;
    assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
}

#[tokio::test]
async fn a_request_without_a_content_length_is_refused() {
    let addr = start(echo()).await;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\nConnection: close\r\n\r\n{{}}",
        credential().header_value()
    );
    let reply = raw(addr, request.as_bytes()).await;
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
}

#[tokio::test]
async fn a_chunked_request_is_refused() {
    // 長さを宣言しない送り方は受け付けない。読み終わりを相手任せに
    // すると、いくらでも送り続けられる。
    let addr = start(echo()).await;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\n\
         Transfer-Encoding: chunked\r\n\r\n2\r\n{{}}\r\n0\r\n\r\n",
        credential().header_value()
    );
    let reply = raw(addr, request.as_bytes()).await;
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
}

#[tokio::test]
async fn an_oversized_body_is_refused_before_it_is_read() {
    // 宣言だけ大きくして、本文は送らない。読む前に断っているなら、
    // 本文を待たずに応答が返る。
    let addr = start(echo()).await;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\nConnection: close\r\n\
         Content-Length: {}\r\n\r\n",
        credential().header_value(),
        MAX_BODY + 1
    );
    let reply = tokio::time::timeout(Duration::from_secs(5), raw(addr, request.as_bytes()))
        .await
        .expect("本文を待たずに断るはず");
    assert!(reply.starts_with("HTTP/1.1 413"), "{reply}");
}

#[tokio::test]
async fn endless_headers_are_refused() {
    let addr = start(echo()).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    // ヘッダの終わりを送らずに詰め込み続ける。上限で断られたら、
    // 相手は書いている途中でも閉じる。書き込みが失敗するのはそのため
    // であり、断られた証拠でもある。
    let mut wrote_all = true;
    if stream
        .write_all(b"POST / HTTP/1.1\r\nHost: x\r\n")
        .await
        .is_ok()
    {
        for i in 0..2_000 {
            let line = format!("X-Filler-{i}: {}\r\n", "a".repeat(64));
            if stream.write_all(line.as_bytes()).await.is_err() {
                wrote_all = false;
                break;
            }
        }
    }

    let mut out = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
        .await
        .expect("上限で断って閉じるはず");
    let reply = String::from_utf8_lossy(&out).into_owned();

    assert!(
        reply.starts_with("HTTP/1.1 400") || (!wrote_all && read.is_err()),
        "上限を超えても受け付け続けている: 書き切った={wrote_all}、応答={reply:?}"
    );
}

#[tokio::test]
async fn a_body_split_across_packets_is_reassembled() {
    // TCP は境界を保たない。本文が分かれて届いても組み直せること。
    let addr = start(echo()).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let body = "{\"method\":\"getinfo\"}";
    let head = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\nContent-Length: {}\r\n\r\n",
        credential().header_value(),
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    for byte in body.as_bytes() {
        tokio::time::sleep(Duration::from_millis(1)).await;
        stream.write_all(&[*byte]).await.unwrap();
        stream.flush().await.unwrap();
    }

    let mut out = vec![0u8; 512];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut out))
        .await
        .expect("応答が返る")
        .unwrap();
    let reply = String::from_utf8_lossy(&out[..read]).into_owned();
    assert!(
        reply.contains(&format!("{{\"echo\":{}}}", body.len())),
        "{reply}"
    );
}

#[tokio::test]
async fn two_requests_share_one_connection() {
    let addr = start(echo()).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    for expected in ["{\"echo\":2}", "{\"echo\":7}"] {
        let body = if expected.contains("2}") {
            "{}"
        } else {
            "{\"a\":1}"
        };
        let head = format!(
            "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\nContent-Length: {}\r\n\r\n{body}",
            credential().header_value(),
            body.len()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut out = vec![0u8; 512];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut out))
            .await
            .expect("応答が返る")
            .unwrap();
        let reply = String::from_utf8_lossy(&out[..read]).into_owned();
        assert!(reply.contains(expected), "{reply}");
    }
}

#[tokio::test]
async fn a_connection_close_request_closes_the_connection() {
    // 相手が「応答したら閉じてくれ」と言ったのに閉じずにいると、
    // 終わりを待つ相手が待ち続ける。ウォレットが実際にこれで固まった。
    let addr = start(echo()).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(&post("{}", Some(credential().header_value())))
        .await
        .unwrap();
    stream.flush().await.unwrap();

    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
        .await
        .expect("Connection: close を求めたのに閉じない")
        .unwrap();
    let reply = String::from_utf8_lossy(&out).into_owned();
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
    assert!(reply.contains("Connection: close"), "{reply}");
}

#[tokio::test]
async fn a_keep_alive_request_does_not_close_the_connection() {
    // 逆も要る。求められていないのに閉じると、使い回しが成り立たない。
    let addr = start(echo()).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\nContent-Length: 2\r\n\r\n{{}}",
        credential().header_value()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    let mut out = vec![0u8; 512];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut out))
        .await
        .expect("応答が返る")
        .unwrap();
    let reply = String::from_utf8_lossy(&out[..read]).into_owned();
    assert!(reply.contains("Connection: keep-alive"), "{reply}");

    // まだ開いている。次の要求を受け付けるはず。
    let mut tail = Vec::new();
    let closed =
        tokio::time::timeout(Duration::from_millis(300), stream.read_to_end(&mut tail)).await;
    assert!(closed.is_err(), "求めていないのに閉じている");
}
