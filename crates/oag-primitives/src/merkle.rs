//! RFC 6962 方式のマークルツリー。
//!
//! Bitcoin のマークルツリーは奇数個のノードを複製して埋めるため、
//! 異なるトランザクション列から同一のマークルルートを構成できる
//! (CVE-2012-2459)。本実装は葉と内部ノードでドメイン分離を行い、
//! 奇数ノードの複製を行わない RFC 6962 の構成を用いることで、
//! この問題を構造的に回避する。
//!
//! 参照: `docs/SPEC.md` §5.4

use crate::hash::{merkle_leaf, merkle_node, Hash};

/// txid の列からマークルルートを計算する。
///
/// 空の列に対しては `None` を返す。ブロックは必ずコインベースを含むため、
/// コンセンサス経路では空の列は現れない。
pub fn merkle_root(txids: &[Hash]) -> Option<Hash> {
    match txids.len() {
        0 => None,
        1 => Some(merkle_leaf(&txids[0])),
        n => {
            let k = split_point(n);
            let left = merkle_root(&txids[..k])?;
            let right = merkle_root(&txids[k..])?;
            Some(merkle_node(&left, &right))
        }
    }
}

/// `n` 未満で最大の 2 冪を返す。`n > 1` を前提とする。
fn split_point(n: usize) -> usize {
    debug_assert!(n > 1);
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::txid;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| txid(&(i as u64).to_le_bytes())).collect()
    }

    #[test]
    fn empty_has_no_root() {
        assert_eq!(merkle_root(&[]), None);
    }

    #[test]
    fn single_leaf_is_hashed() {
        let l = leaves(1);
        // ルートは葉のハッシュそのもの。txid をそのまま使わないことが重要
        // (葉ハッシュのドメイン分離により第二原像攻撃を防ぐ)。
        assert_eq!(merkle_root(&l), Some(merkle_leaf(&l[0])));
        assert_ne!(merkle_root(&l), Some(l[0]));
    }

    #[test]
    fn split_points_are_correct() {
        assert_eq!(split_point(2), 1);
        assert_eq!(split_point(3), 2);
        assert_eq!(split_point(4), 2);
        assert_eq!(split_point(5), 4);
        assert_eq!(split_point(8), 4);
        assert_eq!(split_point(9), 8);
    }

    #[test]
    fn distinct_leaf_sets_give_distinct_roots() {
        let mut seen = std::collections::HashSet::new();
        for n in 1..=64 {
            assert!(
                seen.insert(merkle_root(&leaves(n)).unwrap()),
                "{n} 枚のルートが他と衝突した"
            );
        }
    }

    #[test]
    fn resists_cve_2012_2459_duplication() {
        // Bitcoin 方式では、奇数個の末尾を複製して埋めるため
        // [a, b, c] と [a, b, c, c] が同じルートを持つ。
        // RFC 6962 方式ではこれが起きないことを確認する。
        let l = leaves(3);
        let mut duplicated = l.clone();
        duplicated.push(l[2]);
        assert_ne!(merkle_root(&l), merkle_root(&duplicated));
    }

    #[test]
    fn order_matters() {
        let l = leaves(4);
        let mut swapped = l.clone();
        swapped.swap(0, 1);
        assert_ne!(merkle_root(&l), merkle_root(&swapped));
    }

    #[test]
    fn handles_realistic_block_size() {
        // SPEC §7.2: 200,000 バイトのブロックに約 1,036 件。
        assert!(merkle_root(&leaves(1_036)).is_some());
    }
}
