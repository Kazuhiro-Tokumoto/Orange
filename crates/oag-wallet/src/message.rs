//! メッセージへの署名と、その検証。
//!
//! 「このアドレスは自分のものである」を、硬貨を動かさずに示すための道具で
//! ある。シードノードの運用者が名乗るとき、寄付先を告知するとき、取引所に
//! 出金先の持ち主を示すとき — いずれも鍵を持っていることだけを言えばよく、
//! 送金する必要はない。
//!
//! # 取引の署名と混ざってはならない
//!
//! **同じ鍵で「メッセージ」に署名させて、その署名が取引にも通ってしまう**
//! のが、この手の機能で一番怖い事故である。「これに署名してください」と
//! 渡されたものが、実は送金トランザクションの sighash だった、という形で
//! 成立する。
//!
//! ここでは [`oag_primitives::hash::tagged`] のタグを取引と分けることで
//! 防ぐ。タグ付きハッシュは `tag || 0x00 || data` を BLAKE3 に通すもので、
//! タグに NUL を含められないため**前置符号**になっている。つまり
//! `OAG/sighash` を使う側と `OAG/signedmessage` を使う側で、同じ入力列が
//! 生じることはない。
//!
//! 別の言い方をすると、ここで作った署名を取引に流用するには **BLAKE3 の
//! 衝突を見つける必要がある**。
//!
//! # 何を証明し、何を証明しないのか
//!
//! 証明するのは「署名を作った者がそのアドレスの秘密鍵を持っていた」こと
//! だけである。
//!
//! **いつ署名したかは分からない。** メッセージに時刻や乱数が入っていなけ
//! れば、一度公開された署名は誰でも複製して自分のものだと主張できる。
//! 本人確認に使うなら、**確かめる側が予測できない文字列を指定する**こと。
//!
//! 残高も証明しない。鍵を持っていることと、そのアドレスに硬貨があることは
//! 別である。

use oag_consensus::Lock;
use oag_primitives::{hash, Address, PublicKey, SecretKey, Signature};

/// 署名対象を作るときのタグ。
///
/// **取引の `OAG/sighash` と別であることが、この模組の安全性の全部である。**
/// 変えてはならない。変えれば、それ以前に作られた署名はすべて検証に通らなく
/// なる。
const TAG: &str = "OAG/signedmessage";

/// 署名の 16 進表記の長さ。
const SIGNATURE_HEX_LEN: usize = oag_primitives::keys::SIGNATURE_LEN * 2;

/// メッセージの署名に関する誤り。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageError {
    /// 公開鍵を取り出せないアドレス。
    ///
    /// 版数 0 以外のアドレスは、支払い先ではあっても**鍵そのものを含んで
    /// いない**ので、検証しようがない。
    #[error("this address (version {version}) carries no public key, so nothing can be verified against it")]
    NoPublicKey {
        /// アドレスの版数。
        version: u8,
    },
    /// 署名の書式が読めない。
    #[error("the signature is not {SIGNATURE_HEX_LEN} hex characters")]
    MalformedSignature,
    /// 署名が合わない。
    #[error("the signature does not match")]
    NotSigned,
}

/// メッセージから、署名対象の 32 バイトを作る。
///
/// 検証する側も署名する側もここを通る。**片方だけ別の計算をすると、
/// 永久に噛み合わない。**
pub fn digest(message: &[u8]) -> [u8; 32] {
    hash::tagged(TAG, message).to_bytes()
}

/// メッセージに署名する。
///
/// 補助乱数を使うので、**同じメッセージでも毎回異なる署名になる**。
/// どれも等しく有効である。決定性が欲しくなる場面はここには無く、
/// サイドチャネル耐性のほうが要る。
pub fn sign(key: &SecretKey, message: &[u8]) -> Signature {
    key.sign(&digest(message))
}

/// 公開鍵に対して検証する。
pub fn verify_with_pubkey(pubkey: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    pubkey.verify(&digest(message), sig)
}

/// アドレスに対して検証する。
///
/// アドレスは公開鍵をそのまま含んでいる (版数 0) ので、**別途公開鍵を
/// 受け取る必要も、署名から鍵を復元する必要もない**。確かめる側が持つのは
/// アドレスと、メッセージと、署名の 3 つだけでよい。
pub fn verify(address: &Address, message: &[u8], sig: &Signature) -> Result<(), MessageError> {
    let pubkey = address.to_pubkey().ok_or(MessageError::NoPublicKey {
        version: address.version(),
    })?;
    if verify_with_pubkey(&pubkey, message, sig) {
        Ok(())
    } else {
        Err(MessageError::NotSigned)
    }
}

/// アドレスに対応する錠前。鍵を引くときに使う。
pub fn lock_for(address: &Address) -> Lock {
    Lock::from_address(address)
}

/// 署名を 16 進で表す。
pub fn encode_signature(sig: &Signature) -> String {
    hex::encode(sig.to_bytes())
}

/// 16 進の署名を読む。
pub fn decode_signature(text: &str) -> Result<Signature, MessageError> {
    let text = text.trim();
    if text.len() != SIGNATURE_HEX_LEN {
        return Err(MessageError::MalformedSignature);
    }
    let bytes = hex::decode(text).map_err(|_| MessageError::MalformedSignature)?;
    Signature::from_slice(&bytes).map_err(|_| MessageError::MalformedSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_primitives::Network;

    fn key() -> SecretKey {
        SecretKey::from_bytes([7u8; 32]).unwrap()
    }

    fn address_of(key: &SecretKey) -> Address {
        Address::from_pubkey(Network::Regtest, &key.public_key())
    }

    #[test]
    fn signs_and_verifies() {
        let k = key();
        let sig = sign(&k, b"Orange");
        assert_eq!(verify(&address_of(&k), b"Orange", &sig), Ok(()));
    }

    #[test]
    fn a_different_message_does_not_verify() {
        let k = key();
        let sig = sign(&k, b"Orange");
        assert_eq!(
            verify(&address_of(&k), b"orange", &sig),
            Err(MessageError::NotSigned)
        );
    }

    #[test]
    fn a_different_key_does_not_verify() {
        let sig = sign(&key(), b"Orange");
        let other = SecretKey::from_bytes([9u8; 32]).unwrap();
        assert_eq!(
            verify(&address_of(&other), b"Orange", &sig),
            Err(MessageError::NotSigned)
        );
    }

    #[test]
    fn one_flipped_bit_does_not_verify() {
        let k = key();
        let sig = sign(&k, b"Orange");
        let mut bytes = sig.to_bytes();
        bytes[0] ^= 1;
        let tampered = Signature::from_bytes(bytes);
        assert_eq!(
            verify(&address_of(&k), b"Orange", &tampered),
            Err(MessageError::NotSigned)
        );
    }

    /// **この模組の肝。** メッセージの署名対象が、取引の署名対象と
    /// 同じ値になってはならない。
    #[test]
    fn the_message_digest_is_not_a_sighash() {
        // 同じ入力列を、取引のタグとメッセージのタグの両方に通す。
        for data in [b"".as_slice(), b"Orange", &[0u8; 32], &[0xff; 200]] {
            assert_ne!(
                digest(data),
                hash::tagged("OAG/sighash", data).to_bytes(),
                "タグが効いていない"
            );
        }
    }

    /// 空のメッセージにも署名できる。**できてはいけない理由は無い**が、
    /// 意味のある証明にはならないので、呼ぶ側が止めるべきものである。
    #[test]
    fn an_empty_message_still_round_trips() {
        let k = key();
        let sig = sign(&k, b"");
        assert_eq!(verify(&address_of(&k), b"", &sig), Ok(()));
    }

    #[test]
    fn the_signature_survives_hex() {
        let sig = sign(&key(), b"Orange");
        let text = encode_signature(&sig);
        assert_eq!(text.len(), SIGNATURE_HEX_LEN);
        assert_eq!(decode_signature(&text).unwrap().to_bytes(), sig.to_bytes());
    }

    #[test]
    fn a_malformed_signature_is_refused() {
        for text in [
            "",
            "zz",
            &"0".repeat(SIGNATURE_HEX_LEN - 2),
            &"g".repeat(SIGNATURE_HEX_LEN),
        ] {
            assert_eq!(
                decode_signature(text),
                Err(MessageError::MalformedSignature),
                "{text:?} を受け入れてしまった"
            );
        }
    }

    #[test]
    fn surrounding_space_in_the_signature_is_forgiven() {
        let sig = sign(&key(), b"Orange");
        let text = format!("  {}\n", encode_signature(&sig));
        assert_eq!(decode_signature(&text).unwrap().to_bytes(), sig.to_bytes());
    }

    /// 同じメッセージでも署名は毎回変わる。どれも有効である。
    #[test]
    fn signing_twice_gives_two_valid_signatures() {
        let k = key();
        let a = sign(&k, b"Orange");
        let b = sign(&k, b"Orange");
        assert_ne!(a.to_bytes(), b.to_bytes(), "補助乱数が効いていない");
        let addr = address_of(&k);
        assert_eq!(verify(&addr, b"Orange", &a), Ok(()));
        assert_eq!(verify(&addr, b"Orange", &b), Ok(()));
    }

    /// 改行や NUL が入っていても、バイト列としてそのまま扱う。
    #[test]
    fn arbitrary_bytes_are_signed_as_they_are() {
        let k = key();
        let msg = b"one\ntwo\r\n\0three ";
        let sig = sign(&k, msg);
        let addr = address_of(&k);
        assert_eq!(verify(&addr, msg, &sig), Ok(()));
        // 末尾の空白ひとつで別物になる。
        assert_eq!(
            verify(&addr, b"one\ntwo\r\n\0three", &sig),
            Err(MessageError::NotSigned)
        );
    }

    #[test]
    fn an_address_without_a_public_key_is_refused() {
        let addr = Address::new(Network::Regtest, 1, vec![0u8; 32]).unwrap();
        let sig = sign(&key(), b"Orange");
        assert_eq!(
            verify(&addr, b"Orange", &sig),
            Err(MessageError::NoPublicKey { version: 1 })
        );
    }

    /// ネットワークが違っても、鍵が同じなら通る。**アドレスの hrp は
    /// 鍵の一部ではない。**
    #[test]
    fn the_network_does_not_change_the_key() {
        let k = key();
        let sig = sign(&k, b"Orange");
        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            let addr = Address::from_pubkey(network, &k.public_key());
            assert_eq!(verify(&addr, b"Orange", &sig), Ok(()));
        }
    }
}
