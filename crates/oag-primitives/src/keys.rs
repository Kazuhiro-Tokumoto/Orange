//! secp256k1 の鍵と BIP340 Schnorr 署名。
//!
//! 参照: `docs/SPEC.md` §5.2, §5.3

use core::fmt;
use core::str::FromStr;
use secp256k1::{schnorr, Keypair, XOnlyPublicKey};

/// 秘密鍵のバイト長。
pub const SECRET_KEY_LEN: usize = 32;
/// x-only 公開鍵のバイト長。
pub const PUBLIC_KEY_LEN: usize = 32;
/// BIP340 署名のバイト長。常に固定長である。
pub const SIGNATURE_LEN: usize = 64;

/// 鍵と署名の取り扱いで起きうる誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// 0 または曲線の位数以上の値。
    #[error("秘密鍵が不正 (0 または曲線の位数以上)")]
    InvalidSecretKey,
    /// 曲線上の点に対応しない x 座標。
    #[error("公開鍵が曲線上の点として解釈できない")]
    InvalidPublicKey,
    /// BIP340 の形式に合わない署名。
    #[error("署名が BIP340 の形式に合わない")]
    InvalidSignature,
    /// 想定と異なる長さの入力。
    #[error("長さが不正: {actual} バイト ({expected} バイトである必要がある)")]
    BadLength {
        /// 期待される長さ。
        expected: usize,
        /// 実際に与えられた長さ。
        actual: usize,
    },
    /// 16 進文字列として解釈できない入力。
    #[error("16 進表記として解釈できない")]
    BadHex,
}

fn to_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], KeyError> {
    bytes.try_into().map_err(|_| KeyError::BadLength {
        expected: N,
        actual: bytes.len(),
    })
}

/// 秘密鍵。
///
/// 内部に鍵ペアを保持し、公開鍵の再計算を避ける。
#[derive(Clone)]
pub struct SecretKey(Keypair);

impl SecretKey {
    /// 32 バイトから生成する。
    pub fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Result<SecretKey, KeyError> {
        let sk = secp256k1::SecretKey::from_secret_bytes(bytes)
            .map_err(|_| KeyError::InvalidSecretKey)?;
        Ok(SecretKey(sk.keypair()))
    }

    /// スライスから生成する。
    pub fn from_slice(bytes: &[u8]) -> Result<SecretKey, KeyError> {
        SecretKey::from_bytes(to_array(bytes)?)
    }

    /// 暗号学的乱数から新しい鍵を生成する。
    pub fn generate() -> SecretKey {
        SecretKey(Keypair::new(&mut secp256k1::rand::rng()))
    }

    /// 対応する x-only 公開鍵。
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.x_only_public_key().0)
    }

    /// 秘密鍵のバイト列。
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.0.secret_key().to_secret_bytes()
    }

    /// 32 バイトのメッセージに BIP340 署名を行う。
    ///
    /// 補助乱数を用いるため、同じメッセージでも毎回異なる署名となる
    /// (いずれも有効)。サイドチャネル耐性のため推奨される方式である。
    pub fn sign(&self, msg: &[u8; 32]) -> Signature {
        Signature(schnorr::sign(msg, &self.0))
    }

    /// 補助乱数を用いずに決定的な BIP340 署名を行う。
    ///
    /// テストベクタの照合に用いる。
    pub fn sign_deterministic(&self, msg: &[u8; 32]) -> Signature {
        Signature(schnorr::sign_no_aux_rand(msg, &self.0))
    }
}

impl fmt::Debug for SecretKey {
    /// 秘密鍵の値はログに残さない。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// x-only 公開鍵 (BIP340)。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(XOnlyPublicKey);

impl PublicKey {
    /// 32 バイトから生成する。曲線上の点でなければ拒否する。
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Result<PublicKey, KeyError> {
        XOnlyPublicKey::from_byte_array(bytes)
            .map(PublicKey)
            .map_err(|_| KeyError::InvalidPublicKey)
    }

    /// スライスから生成する。
    pub fn from_slice(bytes: &[u8]) -> Result<PublicKey, KeyError> {
        PublicKey::from_bytes(to_array(bytes)?)
    }

    /// 32 バイトのバイト列。
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_byte_array()
    }

    /// 署名を検証する。
    pub fn verify(&self, msg: &[u8; 32], sig: &Signature) -> bool {
        schnorr::verify(&sig.0, msg, &self.0).is_ok()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.to_bytes()))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl FromStr for PublicKey {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<PublicKey, KeyError> {
        let bytes = hex::decode(s).map_err(|_| KeyError::BadHex)?;
        PublicKey::from_slice(&bytes)
    }
}

/// BIP340 Schnorr 署名。常に 64 バイト固定長。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature(schnorr::Signature);

impl Signature {
    /// 64 バイトから生成する。
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Signature {
        Signature(schnorr::Signature::from_byte_array(bytes))
    }

    /// スライスから生成する。
    pub fn from_slice(bytes: &[u8]) -> Result<Signature, KeyError> {
        Ok(Signature::from_bytes(to_array(bytes)?))
    }

    /// 64 バイトのバイト列。
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0.to_byte_array()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.to_bytes()))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({self})")
    }
}

impl FromStr for Signature {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Signature, KeyError> {
        let bytes = hex::decode(s).map_err(|_| KeyError::BadHex)?;
        Signature::from_slice(&bytes)
    }
}

/// 複数の (公開鍵, メッセージ, 署名) をまとめて検証する。
///
/// # 現状の実装について
///
/// BIP340 は数学的にバッチ検証が可能であり、`docs/SPEC.md` §5.3 は
/// ブロック内の全署名をバッチ検証することを SHOULD としている。
/// しかし libsecp256k1 は現時点でバッチ検証 API を安定版に含めていないため、
/// **本関数は個別検証を順に行う暫定実装である**。
/// 真のバッチ検証は将来の最適化として別途実装する。
pub fn verify_batch(items: &[(PublicKey, [u8; 32], Signature)]) -> bool {
    items.iter().all(|(pk, msg, sig)| pk.verify(msg, sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_from_seed(seed: &str) -> SecretKey {
        let digest = blake3::hash(seed.as_bytes());
        SecretKey::from_bytes(*digest.as_bytes()).expect("有効な秘密鍵")
    }

    #[test]
    fn sign_and_verify() {
        let sk = key_from_seed("orange");
        let pk = sk.public_key();
        let msg = *blake3::hash(b"message").as_bytes();

        let sig = sk.sign(&msg);
        assert!(pk.verify(&msg, &sig));
    }

    #[test]
    fn signature_is_64_bytes() {
        let sk = key_from_seed("orange");
        let sig = sk.sign(&[0x42; 32]);
        assert_eq!(sig.to_bytes().len(), SIGNATURE_LEN);
    }

    #[test]
    fn rejects_wrong_message() {
        let sk = key_from_seed("orange");
        let pk = sk.public_key();
        let sig = sk.sign(&[1u8; 32]);
        assert!(!pk.verify(&[2u8; 32], &sig));
    }

    #[test]
    fn rejects_wrong_key() {
        let sk = key_from_seed("orange");
        let other = key_from_seed("apple").public_key();
        let msg = [3u8; 32];
        let sig = sk.sign(&msg);
        assert!(!other.verify(&msg, &sig));
    }

    #[test]
    fn rejects_tampered_signature() {
        let sk = key_from_seed("orange");
        let pk = sk.public_key();
        let msg = [4u8; 32];
        let mut bytes = sk.sign(&msg).to_bytes();
        bytes[0] ^= 0x01;
        assert!(!pk.verify(&msg, &Signature::from_bytes(bytes)));
    }

    #[test]
    fn deterministic_signing_is_stable() {
        let sk = key_from_seed("orange");
        let msg = [5u8; 32];
        assert_eq!(
            sk.sign_deterministic(&msg).to_bytes(),
            sk.sign_deterministic(&msg).to_bytes()
        );
    }

    #[test]
    fn aux_rand_signing_varies_but_stays_valid() {
        let sk = key_from_seed("orange");
        let pk = sk.public_key();
        let msg = [6u8; 32];
        let a = sk.sign(&msg);
        let b = sk.sign(&msg);
        assert_ne!(a.to_bytes(), b.to_bytes(), "補助乱数により署名は毎回変わる");
        assert!(pk.verify(&msg, &a) && pk.verify(&msg, &b));
    }

    #[test]
    fn key_round_trip() {
        let sk = key_from_seed("orange");
        assert_eq!(
            SecretKey::from_bytes(sk.to_bytes()).unwrap().to_bytes(),
            sk.to_bytes()
        );

        let pk = sk.public_key();
        assert_eq!(PublicKey::from_bytes(pk.to_bytes()).unwrap(), pk);
        assert_eq!(pk.to_string().parse::<PublicKey>().unwrap(), pk);
    }

    #[test]
    fn rejects_zero_secret_key() {
        assert_eq!(
            SecretKey::from_bytes([0u8; 32]).unwrap_err(),
            KeyError::InvalidSecretKey
        );
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(matches!(
            SecretKey::from_slice(&[1u8; 31]),
            Err(KeyError::BadLength {
                expected: 32,
                actual: 31
            })
        ));
        assert!(matches!(
            Signature::from_slice(&[0u8; 63]),
            Err(KeyError::BadLength {
                expected: 64,
                actual: 63
            })
        ));
    }

    #[test]
    fn secret_key_is_not_leaked_by_debug() {
        let sk = key_from_seed("orange");
        assert_eq!(format!("{sk:?}"), "SecretKey(<redacted>)");
    }

    #[test]
    fn generated_keys_are_distinct() {
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn batch_verify() {
        let items: Vec<_> = (0u8..8)
            .map(|i| {
                let sk = key_from_seed(&format!("key{i}"));
                let msg = [i; 32];
                let sig = sk.sign(&msg);
                (sk.public_key(), msg, sig)
            })
            .collect();
        assert!(verify_batch(&items));

        let mut broken = items.clone();
        broken[3].1[0] ^= 0xff;
        assert!(!verify_batch(&broken));
    }
}
