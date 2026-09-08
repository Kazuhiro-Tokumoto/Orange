//! 種と、そこからの鍵の導出。
//!
//! # なぜ種を持つのか
//!
//! 鍵を 1 個ずつ作って並べる方式では、**アドレスを増やすたびに控えが
//! 古くなる**。増やしたあとに控えから復元すると、新しいアドレスの資金が
//! 見えない。種から導けば、控えは種 1 つで済み、あとから何個増やしても
//! 同じ控えで復元できる。
//!
//! # 導出
//!
//! ```text
//! 鍵[i] = BLAKE3_derive_key("Orange wallet key v1", 種 ‖ i) を
//!         secp256k1 の秘密鍵として解釈する
//! ```
//!
//! `i` は 8 バイトのリトルエンディアン。BLAKE3 の鍵導出用の様式を用いる
//! ため、同じ種でも別の用途に使う値とは決して衝突しない。
//!
//! 導出した 32 バイトが secp256k1 の秘密鍵として無効になる確率は
//! 2^-128 程度である。**それでも起こりうる以上、無視せず次の番号へ
//! 進む。** 黙って失敗すると鍵の並びが食い違う。
//!
//! # BIP32 / BIP39 とは互換でない
//!
//! 独自の導出である ([`docs/SPEC.md` の未決事項])。BIP32 は SLIP-0044 の
//! コインタイプ番号が決まらないと導出経路を確定できず、まだ登録されて
//! いない。ここでは**控えが 1 度で済む**という肝心の性質だけを先に
//! 確保している。
//!
//! [`docs/SPEC.md` の未決事項]: https://github.com/Kazuhiro-Tokumoto/Orange/blob/main/docs/SPEC.md

use oag_primitives::SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 種の長さ。
pub const SEED_LEN: usize = 32;

/// 鍵導出の用途を表す文字列。
///
/// BLAKE3 の鍵導出はこの文字列で領域を分ける。**変えたら別の鍵になる。**
const DERIVE_CONTEXT: &str = "Orange (OAG) wallet key derivation v1";

/// 1 つの番号で試す上限。
///
/// 導出結果が secp256k1 の秘密鍵として無効だった場合に次を試す。
/// 2^-128 の事象であり、ここに達することは実際にはない。
const MAX_TWEAKS: u32 = 256;

/// ウォレットの種。
///
/// 落ちるときに中身を消す。`Debug` でも中身を出さない。
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; SEED_LEN]);

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(<伏せ字>)")
    }
}

/// 種の扱いで起きる失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SeedError {
    /// 16 進として読めない、または長さが違う。
    #[error("種は {SEED_LEN} バイト (16 進 {} 文字) であること", SEED_LEN * 2)]
    Malformed,
    /// 鍵を導出できなかった。
    #[error("{index} 番目の鍵を導出できない")]
    Underivable {
        /// 導出しようとした番号。
        index: u32,
    },
}

impl Seed {
    /// 暗号学的乱数から新しい種を作る。
    ///
    /// 鍵と同じ乱数源から取る。**ここが読めれば、この種から導かれる
    /// すべての鍵が読める。**
    pub fn generate() -> Seed {
        let mut bytes = [0u8; SEED_LEN];
        oag_primitives::fill_random(&mut bytes);
        Seed(bytes)
    }

    /// バイト列から作る。
    pub fn from_bytes(bytes: [u8; SEED_LEN]) -> Seed {
        Seed(bytes)
    }

    /// 16 進から作る。控えからの復元に用いる。
    pub fn from_hex(text: &str) -> Result<Seed, SeedError> {
        let text = text.trim();
        if text.len() != SEED_LEN * 2 {
            return Err(SeedError::Malformed);
        }
        let mut bytes = [0u8; SEED_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .map_err(|_| SeedError::Malformed)?;
        }
        Ok(Seed(bytes))
    }

    /// 16 進に直す。**控えを取る以外に使ってはならない。**
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// バイト列。暗号化して保存するために用いる。
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }

    /// `index` 番目の鍵を導出する。
    pub fn derive(&self, index: u32) -> Result<SecretKey, SeedError> {
        for tweak in 0..MAX_TWEAKS {
            let mut material = Vec::with_capacity(SEED_LEN + 8);
            material.extend_from_slice(&self.0);
            material.extend_from_slice(&index.to_le_bytes());
            material.extend_from_slice(&tweak.to_le_bytes());

            let mut derived = blake3::derive_key(DERIVE_CONTEXT, &material);
            material.zeroize();

            // 導出結果が秘密鍵として無効なことがまれにありうる。
            // 黙って飛ばさず、次の値を試す。
            let key = SecretKey::from_bytes(derived);
            // 鍵になったかどうかに関わらず、素材は手元に残さない。
            derived.zeroize();
            if let Ok(key) = key {
                return Ok(key);
            }
        }
        Err(SeedError::Underivable { index })
    }

    /// 先頭から `count` 個の鍵を導出する。
    pub fn derive_many(&self, count: u32) -> Result<Vec<SecretKey>, SeedError> {
        (0..count).map(|i| self.derive(i)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> Seed {
        Seed::from_bytes([7u8; SEED_LEN])
    }

    #[test]
    fn the_same_seed_derives_the_same_keys() {
        // ここが揺らぐと、控えから復元しても資金が見えない。
        let a = seed().derive_many(5).unwrap();
        let b = seed().derive_many(5).unwrap();
        for (x, y) in a.iter().zip(&b) {
            assert_eq!(x.to_bytes(), y.to_bytes());
        }
    }

    #[test]
    fn different_indices_give_different_keys() {
        let seed = seed();
        let keys: Vec<[u8; 32]> = (0..16)
            .map(|i| seed.derive(i).unwrap().to_bytes())
            .collect();
        for (i, a) in keys.iter().enumerate() {
            for (j, b) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "{i} 番目と {j} 番目が同じ鍵");
                }
            }
        }
    }

    #[test]
    fn different_seeds_give_different_keys() {
        let a = Seed::from_bytes([1u8; SEED_LEN]).derive(0).unwrap();
        let b = Seed::from_bytes([2u8; SEED_LEN]).derive(0).unwrap();
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn a_single_bit_change_in_the_seed_changes_the_key() {
        let mut bytes = [0u8; SEED_LEN];
        let a = Seed::from_bytes(bytes).derive(0).unwrap();
        bytes[SEED_LEN - 1] = 1;
        let b = Seed::from_bytes(bytes).derive(0).unwrap();
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn the_derivation_is_fixed() {
        // 変えたら、既存の控えから復元できなくなる。値を固定しておく。
        let key = Seed::from_bytes([0u8; SEED_LEN]).derive(0).unwrap();
        let hex: String = key.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "5a3262aa98305ef72bc477e6f34f7e841da89fab492d034f026964e7a90c0d20",
            "導出が変わっている。既存の控えから復元できなくなる"
        );
    }

    #[test]
    fn hex_round_trips() {
        let original = seed();
        let restored = Seed::from_hex(&original.to_hex()).unwrap();
        assert_eq!(restored.as_bytes(), original.as_bytes());
    }

    #[test]
    fn short_or_invalid_hex_is_refused() {
        // 黙って受け入れると、別の種で復元したことになる。
        for bad in [
            "",
            "00",
            "zz".repeat(32).as_str(),
            &"0".repeat(63),
            &"0".repeat(65),
        ] {
            assert!(Seed::from_hex(bad).is_err(), "{bad:?} が通った");
        }
    }

    #[test]
    fn the_seed_is_not_printed() {
        let text = format!("{:?}", seed());
        assert!(!text.contains("07"), "種が漏れている: {text}");
    }
}
