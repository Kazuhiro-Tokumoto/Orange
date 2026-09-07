//! TCP の上でメッセージをやり取りする層。
//!
//! 本クレートの他のモジュールは入出力を行わない。ここだけが実際に
//! ソケットに触れる。feature `tokio` が有効なときにのみ現れる。
//!
//! # 受信の作法
//!
//! TCP は境界を保たない。1 回の読み取りでメッセージが半分しか来ないことも、
//! 3 個分まとめて来ることもある。[`Connection::recv`] は溜めながら
//! [`crate::frame::decode`] を試し、1 個そろうたびに返す。
//!
//! # 上限
//!
//! 溜め込む量に上限を設ける。枠組みの層が「宣言された長さ」を検査するのに
//! 加え、**実際に溜まった量**も見張る。長さの宣言をせずに延々と送り続ける
//! 相手からメモリを守るためである。

use crate::frame::{self, FrameError, HEADER_LEN, MAX_PAYLOAD};
use crate::handshake::{Handshake, HandshakeError};
use crate::magic::MAGIC_LEN;
use crate::message::{Message, VersionMessage};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 一度に読み取る大きさ。
const READ_CHUNK: usize = 16 * 1024;

/// 溜め込む量の上限。1 個分の枠組みに少し余裕を足した値。
const MAX_BUFFERED: usize = HEADER_LEN + MAX_PAYLOAD + READ_CHUNK;

/// 通信の失敗。
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// 入出力の誤り。
    #[error("入出力に失敗した: {0}")]
    Io(#[from] std::io::Error),
    /// 相手が接続を閉じた。
    #[error("相手が接続を閉じた")]
    Closed,
    /// 受け取ったバイト列が枠組みとして不正。
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// ハンドシェイクに失敗した。
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    /// 溜め込む量が上限を超えた。
    #[error("受信バッファが上限 {max} を超えた")]
    BufferOverflow {
        /// 上限。
        max: usize,
    },
}

/// 1 本の接続。
pub struct Connection {
    stream: TcpStream,
    magic: [u8; MAGIC_LEN],
    buffer: Vec<u8>,
}

impl Connection {
    /// 既にある接続を包む。
    pub fn new(magic: [u8; MAGIC_LEN], stream: TcpStream) -> Connection {
        Connection {
            stream,
            magic,
            buffer: Vec::with_capacity(READ_CHUNK),
        }
    }

    /// 接続する。
    pub async fn connect(
        magic: [u8; MAGIC_LEN],
        addr: SocketAddr,
    ) -> Result<Connection, TransportError> {
        let stream = TcpStream::connect(addr).await?;
        // 小さなメッセージを溜めずにすぐ送る。応答の往復が支配的なため。
        stream.set_nodelay(true)?;
        Ok(Connection::new(magic, stream))
    }

    /// 相手の住所。
    pub fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.stream.peer_addr()?)
    }

    /// メッセージを 1 個送る。
    pub async fn send(&mut self, message: &Message) -> Result<(), TransportError> {
        let bytes = frame::encode(self.magic, message);
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// メッセージを 1 個受け取る。そろうまで待つ。
    pub async fn recv(&mut self) -> Result<Message, TransportError> {
        loop {
            // 溜まっている分から取り出せるなら、読まずに返す。
            if let Some((message, consumed)) = frame::decode(self.magic, &self.buffer)? {
                self.buffer.drain(..consumed);
                return Ok(message);
            }

            if self.buffer.len() > MAX_BUFFERED {
                return Err(TransportError::BufferOverflow { max: MAX_BUFFERED });
            }

            let mut chunk = [0u8; READ_CHUNK];
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(TransportError::Closed);
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// ハンドシェイクを行い、相手の `version` を返す。
    ///
    /// 自分から接続した側でも、受けた側でも、同じ手順でよい。
    pub async fn handshake(
        &mut self,
        our_version: VersionMessage,
    ) -> Result<VersionMessage, TransportError> {
        let mut state = Handshake::new(our_version.nonce);
        let ours = state.start(our_version);
        self.send(&ours).await?;

        while !state.is_ready() {
            let message = self.recv().await?;
            for reply in state.on_message(&message)? {
                self.send(&reply).await?;
            }
        }

        Ok(state
            .peer_version()
            .cloned()
            .expect("完了しているなら相手の version はある"))
    }
}

/// 接続を待ち受ける。
pub struct Listener {
    inner: TcpListener,
    magic: [u8; MAGIC_LEN],
}

impl Listener {
    /// 待ち受けを始める。
    ///
    /// ポートに 0 を指定すると、空いているポートが選ばれる。
    /// 実際のポートは [`Listener::local_addr`] で得られる。
    pub async fn bind(
        magic: [u8; MAGIC_LEN],
        addr: SocketAddr,
    ) -> Result<Listener, TransportError> {
        Ok(Listener {
            inner: TcpListener::bind(addr).await?,
            magic,
        })
    }

    /// 待ち受けている住所。
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.inner.local_addr()?)
    }

    /// 接続を 1 本受け入れる。
    pub async fn accept(&self) -> Result<Connection, TransportError> {
        let (stream, _) = self.inner.accept().await?;
        stream.set_nodelay(true)?;
        Ok(Connection::new(self.magic, stream))
    }
}
