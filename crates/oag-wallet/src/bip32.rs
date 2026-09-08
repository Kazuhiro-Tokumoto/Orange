//! BIP32 の階層決定性導出。
//!
//! # なぜ標準に合わせるのか
//!
//! 独自の導出でも「控えが 1 度で済む」性質は作れる。標準に合わせる理由は
//! **控えの持ち運び**である。BIP39 の語彙で書いた控えを他のウォレットが
//! 受け付け、しかし別の鍵を導く状態は、互換でないことが一見して分からない
//! ぶん独自形式より危険である。復元した利用者が見るのは「残高 0」だけに
//! なる。語彙を BIP39 にするなら導出も BIP32 にする。
//!
//! # BIP340 との関係
//!
//! **導出は BIP340 の x-only 鍵で行わない。** 非強化導出は親の公開鍵を
//! 圧縮形式 (33 バイト、先頭が y の偶奇) で HMAC に食わせる。y の偶奇を
//! 捨てると他の実装と違う子鍵が出る。x-only への正規化は、導出が終わって
//! 署名する段でのみ効く。

use hmac::{Hmac, Mac};
use oag_primitives::SecretKey;
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

/// 強化導出の下限。`index | HARDENED` が強化導出を表す。
pub const HARDENED: u32 = 0x8000_0000;

/// 主鍵を作るときに HMAC の鍵として用いる文字列。
///
/// BIP32 が定める値であり、**変えたら別の鍵になる**。Bitcoin 由来の
/// 文字列だが、これを変えると BIP39 の控えを他のウォレットへ持ち込めなく
/// なるため、そのまま用いる。
const MASTER_KEY: &[u8] = b"Bitcoin seed";

/// 導出で起きる失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Bip32Error {
    /// 種の長さが 16〜64 バイトの範囲外。
    #[error("種は 16〜64 バイトであること (受け取った長さ: {found})")]
    BadSeedLength {
        /// 受け取った長さ。
        found: usize,
    },
    /// 導出結果が秘密鍵として無効だった。
    #[error("{index} 番の子鍵を導出できない")]
    Underivable {
        /// 導出しようとした番号。
        index: u32,
    },
}

/// 拡張秘密鍵。秘密鍵とチェーンコードの対。
#[derive(Clone)]
pub struct ExtendedKey {
    key: SecretKey,
    chain_code: [u8; 32],
}

impl std::fmt::Debug for ExtendedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExtendedKey(<伏せ字>)")
    }
}

impl Drop for ExtendedKey {
    fn drop(&mut self) {
        // 鍵そのものは `SecretKey` が消す。チェーンコードは単体では鍵に
        // ならないが、鍵と揃うと子孫すべてを導けるため同様に消す。
        self.chain_code.zeroize();
    }
}

impl ExtendedKey {
    /// 種から主鍵を作る。
    ///
    /// `I = HMAC-SHA512("Bitcoin seed", 種)` の前半を秘密鍵、後半を
    /// チェーンコードとする。
    pub fn master(seed: &[u8]) -> Result<ExtendedKey, Bip32Error> {
        if !(16..=64).contains(&seed.len()) {
            return Err(Bip32Error::BadSeedLength { found: seed.len() });
        }
        let i = hmac512(MASTER_KEY, &[seed]);
        split(&i, |left| SecretKey::from_slice(left).ok())
            .ok_or(Bip32Error::Underivable { index: 0 })
    }

    /// 子鍵を 1 段導く。
    ///
    /// `index >= HARDENED` なら強化導出。
    ///
    /// # 無効な結果を飛ばさない理由
    ///
    /// BIP32 は「導出結果が無効なら次の番号へ進む」と定めるが、ここでは
    /// 断る。**黙って番号をずらすと、同じ経路の表記が別の鍵を指す。**
    /// 起こる確率は 2^-127 程度であり、実際に踏むことはない。
    pub fn derive_child(&self, index: u32) -> Result<ExtendedKey, Bip32Error> {
        let suffix = index.to_be_bytes();
        let key_bytes = Zeroizing::new(self.key.to_bytes());
        let i = if index >= HARDENED {
            // 強化: 0x00 ‖ ser256(k) ‖ ser32(i)
            hmac512(&self.chain_code, &[&[0u8], key_bytes.as_ref(), &suffix])
        } else {
            // 非強化: serP(K) ‖ ser32(i)
            hmac512(
                &self.chain_code,
                &[&self.key.public_key_compressed(), &suffix],
            )
        };
        split(&i, |left| {
            let mut tweak = [0u8; 32];
            tweak.copy_from_slice(left);
            let child = self.key.add_tweak(&tweak).ok();
            tweak.zeroize();
            child
        })
        .ok_or(Bip32Error::Underivable { index })
    }

    /// 経路をたどる。
    pub fn derive_path(&self, path: &[u32]) -> Result<ExtendedKey, Bip32Error> {
        let mut node = self.clone();
        for &index in path {
            node = node.derive_child(index)?;
        }
        Ok(node)
    }

    /// 秘密鍵。
    pub fn secret_key(&self) -> &SecretKey {
        &self.key
    }

    /// チェーンコード。
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }
}

/// HMAC-SHA512。断片を順に食わせる。
fn hmac512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC は任意長の鍵を受け付ける");
    for part in parts {
        mac.update(part);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// `I` を前後に割り、前半から鍵を作る。
fn split(i: &[u8; 64], to_key: impl FnOnce(&[u8]) -> Option<SecretKey>) -> Option<ExtendedKey> {
    let key = to_key(&i[..32])?;
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&i[32..]);
    Some(ExtendedKey { key, chain_code })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// BIP32 が定める試験ベクタ。(種, [(経路の表記, 経路, xprv)])
    #[allow(clippy::type_complexity)]
    const BIP32_VECTORS: &[(&str, &[(&str, &[u32], &str)])] = &[
        (
            "000102030405060708090a0b0c0d0e0f",
            &[
                ("m", &[], "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"),
                ("m/0'", &[2147483648], "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"),
                ("m/0'/1", &[2147483648, 1], "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"),
                ("m/0'/1/2'", &[2147483648, 1, 2147483650], "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"),
                ("m/0'/1/2'/2", &[2147483648, 1, 2147483650, 2], "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"),
                ("m/0'/1/2'/2/1000000000", &[2147483648, 1, 2147483650, 2, 1000000000], "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"),
            ],
        ),
        (
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            &[
                ("m", &[], "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"),
                ("m/0", &[0], "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"),
                ("m/0/2147483647'", &[0, 4294967295], "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"),
                ("m/0/2147483647'/1", &[0, 4294967295, 1], "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"),
                ("m/0/2147483647'/1/2147483646'", &[0, 4294967295, 1, 4294967294], "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"),
                ("m/0/2147483647'/1/2147483646'/2", &[0, 4294967295, 1, 4294967294, 2], "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"),
            ],
        ),
        (
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
            &[
                ("m", &[], "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"),
                ("m/0'", &[2147483648], "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"),
            ],
        ),
        (
            "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
            &[
                ("m", &[], "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"),
                ("m/0'", &[2147483648], "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"),
                ("m/0'/1'", &[2147483648, 2147483649], "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"),
            ],
        ),
    ];

    fn from_hex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// base58check を解く。**試験のためだけにある。**
    ///
    /// BIP32 の試験ベクタは拡張鍵を base58 で書いている。こちらは xprv を
    /// 書き出す機能を持たないので、ベクタの側を解いて中身を突き合わせる。
    fn base58check(text: &str) -> Vec<u8> {
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut num: Vec<u8> = vec![0];
        for c in text.bytes() {
            let mut carry = ALPHABET
                .iter()
                .position(|&a| a == c)
                .expect("base58 の文字") as u32;
            for byte in num.iter_mut().rev() {
                let x = u32::from(*byte) * 58 + carry;
                *byte = (x & 0xff) as u8;
                carry = x >> 8;
            }
            while carry > 0 {
                num.insert(0, (carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        let leading = text.bytes().take_while(|&c| c == b'1').count();
        let first = num.iter().position(|&b| b != 0).unwrap_or(num.len());
        let mut out = vec![0u8; leading];
        out.extend_from_slice(&num[first..]);

        let (body, check) = out.split_at(out.len() - 4);
        let digest = Sha256::digest(Sha256::digest(body));
        assert_eq!(&digest[..4], check, "base58check の検査符号");
        body.to_vec()
    }

    /// xprv からチェーンコードと秘密鍵を取り出す。
    ///
    /// 78 バイト。版数 4 ‖ 深さ 1 ‖ 親の指紋 4 ‖ 子番号 4 ‖
    /// チェーンコード 32 ‖ 0x00 ‖ 鍵 32。
    fn parts_of(xprv: &str) -> ([u8; 32], [u8; 32]) {
        let raw = base58check(xprv);
        assert_eq!(raw.len(), 78, "拡張鍵は 78 バイト");
        assert_eq!(raw[45], 0, "秘密鍵の前には 0x00 が入る");
        let mut chain_code = [0u8; 32];
        let mut key = [0u8; 32];
        chain_code.copy_from_slice(&raw[13..45]);
        key.copy_from_slice(&raw[46..78]);
        (chain_code, key)
    }

    #[test]
    fn the_official_vectors_pass() {
        // **ここが外れると、BIP39 の控えを他のウォレットへ持ち込めない。**
        // 語が同じでも導く鍵が違えば、復元しても残高 0 に見える。
        for (seed, steps) in BIP32_VECTORS {
            let master = ExtendedKey::master(&from_hex(seed)).unwrap();
            for (label, path, xprv) in *steps {
                let node = master.derive_path(path).unwrap();
                let (chain_code, key) = parts_of(xprv);
                assert_eq!(node.chain_code(), &chain_code, "{label} のチェーンコード");
                assert_eq!(node.secret_key().to_bytes(), key, "{label} の秘密鍵");
            }
        }
    }

    #[test]
    fn a_child_is_reached_the_same_way_step_by_step() {
        // derive_path は derive_child の繰り返しでしかない。まとめて
        // たどった結果と 1 段ずつの結果が食い違えば、経路の解釈が違う。
        let master = ExtendedKey::master(&[7u8; 32]).unwrap();
        let path = [44 | HARDENED, 1 | HARDENED, HARDENED, 0, 5];
        let at_once = master.derive_path(&path).unwrap();
        let mut node = master.clone();
        for index in path {
            node = node.derive_child(index).unwrap();
        }
        assert_eq!(
            node.secret_key().to_bytes(),
            at_once.secret_key().to_bytes()
        );
    }

    #[test]
    fn hardened_and_normal_children_differ() {
        // 強化と非強化で HMAC に食わせる素材が違う。同じ番号でも別の鍵に
        // なる。ここが一致するなら、強化の判定が効いていない。
        let master = ExtendedKey::master(&[3u8; 32]).unwrap();
        let normal = master.derive_child(0).unwrap();
        let hardened = master.derive_child(HARDENED).unwrap();
        assert_ne!(
            normal.secret_key().to_bytes(),
            hardened.secret_key().to_bytes()
        );
    }

    #[test]
    fn the_seed_length_is_checked() {
        assert_eq!(
            ExtendedKey::master(&[0u8; 15]).unwrap_err(),
            Bip32Error::BadSeedLength { found: 15 }
        );
        assert_eq!(
            ExtendedKey::master(&[0u8; 65]).unwrap_err(),
            Bip32Error::BadSeedLength { found: 65 }
        );
        assert!(ExtendedKey::master(&[0u8; 16]).is_ok());
        assert!(ExtendedKey::master(&[0u8; 64]).is_ok());
    }

    #[test]
    fn the_chain_code_is_not_the_key() {
        // 取り違えると、鍵にチェーンコードを使うことになる。
        let master = ExtendedKey::master(&[9u8; 32]).unwrap();
        assert_ne!(&master.secret_key().to_bytes(), master.chain_code());
    }
}
