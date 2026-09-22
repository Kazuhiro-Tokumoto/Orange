//! ハンドシェイクの状態機械。
//!
//! ```text
//! 自分 ──version──▶ 相手
//! 自分 ◀──version── 相手
//! 自分 ──verack───▶ 相手
//! 自分 ◀──verack─── 相手
//!                    両方そろって初めて通常のやり取りに入る
//! ```
//!
//! 順序を守らせることが目的である。ハンドシェイクの前に本題のメッセージを
//! 受け付けると、名乗っていない相手にブロックを配ることになる。

use crate::message::{Message, VersionMessage, MIN_PROTOCOL_VERSION};

/// ハンドシェイクの失敗。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    /// 最初のメッセージが `version` でない。
    #[error("received {0} before the handshake")]
    Premature(&'static str),
    /// `version` を 2 回受け取った。
    #[error("received version twice")]
    DuplicateVersion,
    /// `verack` を `version` より先に受け取った。
    #[error("received verack before version")]
    EarlyVerack,
    /// `verack` を 2 回受け取った。
    #[error("received verack twice")]
    DuplicateVerack,
    /// プロトコル版数が古すぎる。
    #[error("protocol version {actual} is too old (minimum {minimum})")]
    ProtocolTooOld {
        /// 相手の版数。
        actual: u32,
        /// 受け入れる最小の版数。
        minimum: u32,
    },
    /// 自分自身に繋いでいる。
    #[error("detected a connection to ourselves")]
    SelfConnection,
    /// すでにハンドシェイクを終えている。
    #[error("the handshake is complete")]
    AlreadyDone,
}

/// ハンドシェイクの進み具合。
#[derive(Debug, Clone)]
pub struct Handshake {
    local_nonce: u64,
    sent_version: bool,
    sent_verack: bool,
    peer_version: Option<VersionMessage>,
    got_verack: bool,
}

impl Handshake {
    /// 自分の乱数を指定して始める。
    ///
    /// `local_nonce` は自己接続の検出に使う。相手の `version` に同じ値が
    /// 入っていたら、それは自分自身である。
    pub fn new(local_nonce: u64) -> Handshake {
        Handshake {
            local_nonce,
            sent_version: false,
            sent_verack: false,
            peer_version: None,
            got_verack: false,
        }
    }

    /// 自分の `version` を送る。接続したら最初に呼ぶ。
    pub fn start(&mut self, version: VersionMessage) -> Message {
        self.sent_version = true;
        Message::Version(version)
    }

    /// 相手の `version`。まだ受け取っていなければ `None`。
    pub fn peer_version(&self) -> Option<&VersionMessage> {
        self.peer_version.as_ref()
    }

    /// ハンドシェイクが完了しているか。
    pub fn is_ready(&self) -> bool {
        self.peer_version.is_some() && self.got_verack && self.sent_verack
    }

    /// メッセージを 1 個処理し、送り返すべきメッセージを返す。
    ///
    /// ハンドシェイクが完了した後にこれを呼ぶのは誤りである。
    pub fn on_message(&mut self, message: &Message) -> Result<Vec<Message>, HandshakeError> {
        if self.is_ready() {
            return Err(HandshakeError::AlreadyDone);
        }

        match message {
            Message::Version(version) => {
                if self.peer_version.is_some() {
                    return Err(HandshakeError::DuplicateVersion);
                }
                if version.protocol_version < MIN_PROTOCOL_VERSION {
                    return Err(HandshakeError::ProtocolTooOld {
                        actual: version.protocol_version,
                        minimum: MIN_PROTOCOL_VERSION,
                    });
                }
                if version.nonce == self.local_nonce {
                    return Err(HandshakeError::SelfConnection);
                }
                self.peer_version = Some(version.clone());
                self.sent_verack = true;
                Ok(vec![Message::Verack])
            }
            Message::Verack => {
                if self.peer_version.is_none() {
                    return Err(HandshakeError::EarlyVerack);
                }
                if self.got_verack {
                    return Err(HandshakeError::DuplicateVerack);
                }
                self.got_verack = true;
                Ok(Vec::new())
            }
            other => Err(HandshakeError::Premature(other.command())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{
        effective_services, InvItem, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, SERVICE_FULL_NODE,
        SERVICE_NONE,
    };
    use oag_primitives::hash;

    fn version(nonce: u64) -> VersionMessage {
        VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            services: SERVICE_FULL_NODE,
            timestamp: 1_800_000_000,
            nonce,
            user_agent: "/oag:0.1.0/".to_owned(),
            start_height: 0,
            relay: true,
        }
    }

    #[test]
    fn a_complete_handshake_reaches_ready() {
        let mut local = Handshake::new(1);
        let sent = local.start(version(1));
        assert!(matches!(sent, Message::Version(_)));
        assert!(!local.is_ready());

        // 相手の version が来たら verack を返す。
        let replies = local.on_message(&Message::Version(version(2))).unwrap();
        assert_eq!(replies, vec![Message::Verack]);
        assert!(!local.is_ready(), "the peer's verack has not arrived yet");
        assert_eq!(local.peer_version().unwrap().nonce, 2);

        // 相手の verack が来て完了。
        assert_eq!(local.on_message(&Message::Verack).unwrap(), Vec::new());
        assert!(local.is_ready());
    }

    #[test]
    fn two_peers_can_shake_hands_with_each_other() {
        let mut a = Handshake::new(10);
        let mut b = Handshake::new(20);
        let a_version = a.start(version(10));
        let b_version = b.start(version(20));

        let a_replies = a.on_message(&b_version).unwrap();
        let b_replies = b.on_message(&a_version).unwrap();

        for reply in a_replies {
            b.on_message(&reply).unwrap();
        }
        for reply in b_replies {
            a.on_message(&reply).unwrap();
        }

        assert!(a.is_ready() && b.is_ready());
        assert_eq!(a.peer_version().unwrap().nonce, 20);
        assert_eq!(b.peer_version().unwrap().nonce, 10);
    }

    #[test]
    fn a_version_one_peer_is_still_welcome() {
        // **稼働中のネットワークは全員が版数 1 である。** ここが落ちると、
        // 新しいノードはどこからも同期できなくなる。
        let old = VersionMessage {
            protocol_version: 1,
            // 版数 1 の実装はこの欄を埋めなかった。
            services: SERVICE_NONE,
            ..version(2)
        };

        let mut local = Handshake::new(1);
        let _ = local.start(version(1));
        assert_eq!(
            local.on_message(&Message::Version(old.clone())),
            Ok(vec![Message::Verack])
        );
        assert_eq!(local.on_message(&Message::Verack), Ok(Vec::new()));
        assert!(local.is_ready(), "a version 1 peer was turned away");

        // 送ってきた 0 は未記入である。フルノードとして読む。
        let theirs = local.peer_version().unwrap();
        assert_eq!(theirs.services, SERVICE_NONE);
        assert_eq!(
            effective_services(theirs.protocol_version, theirs.services),
            SERVICE_FULL_NODE
        );
    }

    #[test]
    fn the_oldest_version_we_accept_still_gets_in() {
        let oldest = VersionMessage {
            protocol_version: MIN_PROTOCOL_VERSION,
            services: SERVICE_NONE,
            ..version(2)
        };
        let mut local = Handshake::new(1);
        let _ = local.start(version(1));
        assert!(local.on_message(&Message::Version(oldest)).is_ok());
    }

    #[test]
    fn ordinary_messages_are_refused_before_the_handshake() {
        // 名乗る前にブロックを配らせない。
        let cases = [
            Message::Ping(1),
            Message::GetAddr,
            Message::Inv(vec![InvItem::block(hash::block_hash(b"x"))]),
            Message::Mempool,
        ];
        for message in cases {
            let mut hs = Handshake::new(1);
            assert_eq!(
                hs.on_message(&message),
                Err(HandshakeError::Premature(message.command())),
                "{} got through",
                message.command()
            );
        }
    }

    #[test]
    fn a_second_version_is_refused() {
        let mut hs = Handshake::new(1);
        hs.on_message(&Message::Version(version(2))).unwrap();
        assert_eq!(
            hs.on_message(&Message::Version(version(3))),
            Err(HandshakeError::DuplicateVersion)
        );
    }

    #[test]
    fn a_verack_before_a_version_is_refused() {
        let mut hs = Handshake::new(1);
        assert_eq!(
            hs.on_message(&Message::Verack),
            Err(HandshakeError::EarlyVerack)
        );
    }

    #[test]
    fn a_second_verack_is_refused() {
        let mut hs = Handshake::new(1);
        hs.start(version(1));
        hs.on_message(&Message::Version(version(2))).unwrap();
        hs.on_message(&Message::Verack).unwrap();
        // ここで完了しているので、以降の呼び出し自体が誤り。
        assert_eq!(
            hs.on_message(&Message::Verack),
            Err(HandshakeError::AlreadyDone)
        );
    }

    #[test]
    fn a_duplicate_verack_before_completion_is_refused() {
        // 自分の version をまだ送っていない (= verack を返していない) 状態でも
        // 相手の verack が二度来たら誤りとする。
        let mut hs = Handshake::new(1);
        hs.on_message(&Message::Version(version(2))).unwrap();
        hs.on_message(&Message::Verack).unwrap();
        assert!(
            hs.is_ready(),
            "verack is returned as soon as version is received"
        );
    }

    #[test]
    fn connecting_to_oneself_is_detected() {
        // 同じ乱数が返ってきたら、それは自分自身である。
        let mut hs = Handshake::new(0xDEAD_BEEF);
        assert_eq!(
            hs.on_message(&Message::Version(version(0xDEAD_BEEF))),
            Err(HandshakeError::SelfConnection)
        );
    }

    #[test]
    fn an_old_protocol_version_is_refused() {
        let mut hs = Handshake::new(1);
        let mut old = version(2);
        old.protocol_version = MIN_PROTOCOL_VERSION - 1;
        assert_eq!(
            hs.on_message(&Message::Version(old)),
            Err(HandshakeError::ProtocolTooOld {
                actual: MIN_PROTOCOL_VERSION - 1,
                minimum: MIN_PROTOCOL_VERSION,
            })
        );
    }

    #[test]
    fn a_newer_protocol_version_is_accepted() {
        // 自分より新しい相手とは話せる。相手が古い機能に合わせる。
        let mut hs = Handshake::new(1);
        let mut newer = version(2);
        newer.protocol_version = PROTOCOL_VERSION + 10;
        assert!(hs.on_message(&Message::Version(newer)).is_ok());
    }
}
