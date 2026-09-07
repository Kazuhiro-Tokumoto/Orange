//! BLAKE3 によるハッシュとドメイン分離。
//!
//! 参照: `docs/SPEC.md` §5.1

use core::fmt;
use core::str::FromStr;

/// ハッシュ値のバイト長。
pub const HASH_LEN: usize = 32;

/// ハッシュの用途を表すドメイン分離プレフィックス。
///
/// 異なる用途のハッシュが偶然一致することを防ぐ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Domain {
    /// トランザクション ID。
    Txid = 0x00,
    /// マークルツリーの葉。
    MerkleLeaf = 0x01,
    /// マークルツリーの内部ノード。
    MerkleNode = 0x02,
    /// ブロックハッシュ。
    BlockHash = 0x03,
}

/// ハッシュ値の生成で起きうる誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HashError {
    /// 32 バイトではない入力。
    #[error("ハッシュの長さが不正: {0} バイト (32 バイトである必要がある)")]
    BadLength(usize),
    /// 16 進文字列として解釈できない入力。
    #[error("16 進表記として解釈できない")]
    BadHex,
}

/// 32 バイトの BLAKE3 ハッシュ値。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash([u8; HASH_LEN]);

impl Hash {
    /// すべてのバイトが 0 のハッシュ。ジェネシスブロックの `prev_hash` 等に用いる。
    pub const ZERO: Hash = Hash([0u8; HASH_LEN]);

    /// バイト配列から生成する。
    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Hash {
        Hash(bytes)
    }

    /// スライスから生成する。長さが 32 でなければ拒否する。
    pub fn from_slice(bytes: &[u8]) -> Result<Hash, HashError> {
        let array: [u8; HASH_LEN] = bytes
            .try_into()
            .map_err(|_| HashError::BadLength(bytes.len()))?;
        Ok(Hash(array))
    }

    /// バイト列への参照。
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// バイト配列を返す。
    pub const fn to_bytes(self) -> [u8; HASH_LEN] {
        self.0
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", hex::encode(self.0))
    }
}

impl FromStr for Hash {
    type Err = HashError;

    fn from_str(s: &str) -> Result<Hash, HashError> {
        let bytes = hex::decode(s).map_err(|_| HashError::BadHex)?;
        Hash::from_slice(&bytes)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// ドメイン分離プレフィックスを付けて `data` をハッシュする。
pub fn hash_with_domain(domain: Domain, data: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[domain as u8]);
    hasher.update(data);
    Hash(*hasher.finalize().as_bytes())
}

/// タグ付きハッシュ。
///
/// 用途ごとに異なる `tag` を与えることで、ある文脈のハッシュを別の文脈で
/// 再利用する攻撃を防ぐ。
///
/// BIP340 は `SHA256(SHA256(tag) || SHA256(tag) || msg)` という構成を用いるが、
/// これは SHA-256 が長さ拡張攻撃を受けることへの対処である。BLAKE3 は
/// 構造的に長さ拡張耐性を持つため、タグと NUL 区切りを前置するだけで
/// 十分である。タグに NUL は含まれないため、この符号化は前置符号となり、
/// 異なるタグが同じ入力列を生じることはない。
///
/// # Panics
/// `tag` に NUL バイトが含まれる場合。
pub fn tagged(tag: &str, data: &[u8]) -> Hash {
    assert!(
        !tag.as_bytes().contains(&0),
        "タグに NUL を含めてはならない"
    );
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag.as_bytes());
    hasher.update(&[0x00]);
    hasher.update(data);
    Hash(*hasher.finalize().as_bytes())
}

/// シリアライズ済みトランザクションから txid を計算する。
pub fn txid(serialized_tx: &[u8]) -> Hash {
    hash_with_domain(Domain::Txid, serialized_tx)
}

/// シリアライズ済みブロックヘッダからブロックハッシュを計算する。
pub fn block_hash(serialized_header: &[u8]) -> Hash {
    hash_with_domain(Domain::BlockHash, serialized_header)
}

/// マークルツリーの葉ハッシュ。
pub fn merkle_leaf(txid: &Hash) -> Hash {
    hash_with_domain(Domain::MerkleLeaf, txid.as_bytes())
}

/// マークルツリーの内部ノードハッシュ。
pub fn merkle_node(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; HASH_LEN * 2];
    buf[..HASH_LEN].copy_from_slice(left.as_bytes());
    buf[HASH_LEN..].copy_from_slice(right.as_bytes());
    hash_with_domain(Domain::MerkleNode, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_produce_different_hashes() {
        let data = b"orange";
        let all = [
            hash_with_domain(Domain::Txid, data),
            hash_with_domain(Domain::MerkleLeaf, data),
            hash_with_domain(Domain::MerkleNode, data),
            hash_with_domain(Domain::BlockHash, data),
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "ドメインが違えばハッシュも異なるべき");
            }
        }
    }

    #[test]
    fn hex_round_trip() {
        let h = txid(b"orange");
        let s = h.to_string();
        assert_eq!(s.len(), 64);
        assert_eq!(s.parse::<Hash>().unwrap(), h);
    }

    #[test]
    fn rejects_bad_hex() {
        assert_eq!("zz".parse::<Hash>(), Err(HashError::BadHex));
        assert_eq!("00".parse::<Hash>(), Err(HashError::BadLength(1)));
    }

    #[test]
    fn merkle_node_is_order_sensitive() {
        let a = txid(b"a");
        let b = txid(b"b");
        assert_ne!(merkle_node(&a, &b), merkle_node(&b, &a));
    }

    #[test]
    fn tagged_hashes_are_separated_by_tag() {
        assert_ne!(tagged("a", b"x"), tagged("b", b"x"));
        // タグと本文の境界が曖昧にならないこと。
        assert_ne!(tagged("ab", b"c"), tagged("a", b"bc"));
        assert_eq!(tagged("a", b"x"), tagged("a", b"x"));
    }

    #[test]
    #[should_panic(expected = "タグに NUL")]
    fn tagged_rejects_nul_in_tag() {
        tagged("a\0b", b"x");
    }

    #[test]
    fn zero_hash() {
        assert_eq!(Hash::ZERO.to_string(), "0".repeat(64));
    }
}
