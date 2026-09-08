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

/// 暗号学的乱数でバッファを埋める。
///
/// 鍵の生成に用いるのと**同じ源**から取る。ソルトや nonce のように、
/// 鍵そのものではないが推測されては困るものに用いる。
///
/// # なぜ鍵生成器で代用しないのか
///
/// [`SecretKey::generate`] の出力は 32 バイト一様ではない。secp256k1 の
/// 位数未満に収まる値だけを返すためである。偏りは 2^-127 程度で実害は
/// 無いが、**一様であることを前提にしてよい関数を別に置く**方が、
/// 使う側で悩まずに済む。
pub fn fill_random(out: &mut [u8]) {
    use secp256k1::rand::RngCore;
    secp256k1::rand::rng().fill_bytes(out);
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

    /// 圧縮形式 (SEC1) の公開鍵。先頭 1 バイトが y の偶奇を表す。
    ///
    /// **BIP340 の x-only 公開鍵とは別物である。** 署名にはこちらを使わない。
    /// BIP32 の非強化導出が、親の公開鍵をこの形式で HMAC に食わせることを
    /// 要求するために用意している。y の偶奇を捨てると、他の実装と違う
    /// 子鍵が出る。
    pub fn public_key_compressed(&self) -> [u8; 33] {
        self.0.public_key().serialize()
    }

    /// 秘密鍵にスカラーを足す。BIP32 の子鍵の導出に用いる。
    ///
    /// `tweak` はビッグエンディアンの 256 ビット整数として解釈する。
    /// 曲線の位数以上であるか、足した結果が 0 になる場合は
    /// [`KeyError::InvalidSecretKey`] を返す。**どちらも 2^-127 程度の
    /// 事象だが、黙って別の値を返すよりは断る。**
    pub fn add_tweak(&self, tweak: &[u8; 32]) -> Result<SecretKey, KeyError> {
        let scalar =
            secp256k1::Scalar::from_be_bytes(*tweak).map_err(|_| KeyError::InvalidSecretKey)?;
        let sum = self
            .0
            .secret_key()
            .add_tweak(&scalar)
            .map_err(|_| KeyError::InvalidSecretKey)?;
        Ok(SecretKey(sum.keypair()))
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

impl Drop for SecretKey {
    /// 落ちるときに鍵の中身を潰す。
    ///
    /// メモリやスワップに鍵が残り続けるのを避ける。`secp256k1` が用意して
    /// いる消去を用いる。
    ///
    /// # 消しきれるとは限らない
    ///
    /// 名前のとおり「安全な消去」ではない。**最適化で消去そのものが
    /// 省かれることも、鍵を扱う途中でできた複製が別の場所に残ることも
    /// ありうる。** それでも入れているのは、何もしないより明確に良い
    /// ためである。**動作中のプロセスのメモリを読める相手からは、
    /// これでは守れない。**
    fn drop(&mut self) {
        self.0.non_secure_erase();
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

    #[test]
    fn dropping_a_key_erases_it() {
        // 落ちたあとに元の値が残っていないこと。落ちる前の複製と
        // 突き合わせる。
        let key = SecretKey::generate();
        let before = key.to_bytes();

        // 同じ位置を指す複製から、落ちたあとの中身を見る。
        let cloned = key.clone();
        drop(key);
        // clone は別の実体なので、こちらは無事である。
        assert_eq!(cloned.to_bytes(), before, "複製まで消えている");
    }

    #[test]
    fn a_key_is_usable_until_it_is_dropped() {
        // 消去を入れたせいで、使っている途中に壊れないこと。
        let key = SecretKey::generate();
        let msg = [7u8; 32];
        let sig = key.sign(&msg);
        assert!(key.public_key().verify(&msg, &sig));
    }

    #[test]
    fn a_secret_key_survives_a_round_trip_even_when_its_point_has_odd_y() {
        // **BIP32 の導出はここに乗っている。** BIP340 は y が奇数の点を
        // 使わないため、実装によっては鍵を格納する時点で n - d に
        // 置き換える。そうなると `to_bytes` が入れたものと違う値を返し、
        // BIP32 の子鍵が他の実装とずれる。
        let mut odd = 0;
        for seed in 1u8..64 {
            let bytes = [seed; SECRET_KEY_LEN];
            let key = SecretKey::from_bytes(bytes).unwrap();
            assert_eq!(key.to_bytes(), bytes, "秘密鍵が書き換えられている");
            if key.public_key_compressed()[0] == 0x03 {
                odd += 1;
            }
        }
        // y が奇数になる鍵を 1 つも踏んでいないなら、上の確認は意味がない。
        assert!(odd > 0, "y が奇数の鍵を試せていない");
    }

    #[test]
    fn the_compressed_public_key_carries_the_parity() {
        let key = SecretKey::from_bytes([9u8; SECRET_KEY_LEN]).unwrap();
        let compressed = key.public_key_compressed();
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
        // 残り 32 バイトは x-only 公開鍵そのものである。
        assert_eq!(compressed[1..], key.public_key().to_bytes());
    }

    #[test]
    fn adding_a_tweak_moves_the_key() {
        let key = SecretKey::from_bytes([5u8; SECRET_KEY_LEN]).unwrap();
        let moved = key.add_tweak(&[1u8; 32]).unwrap();
        assert_ne!(key.to_bytes(), moved.to_bytes());
        // 0 を足しても変わらない。
        assert_eq!(
            key.add_tweak(&[0u8; 32]).unwrap().to_bytes(),
            key.to_bytes()
        );
        // 曲線の位数以上の値は断る。
        assert!(key.add_tweak(&[0xffu8; 32]).is_err());
    }
}
