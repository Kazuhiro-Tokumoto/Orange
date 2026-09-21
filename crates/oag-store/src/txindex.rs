//! 取引索引とアドレス索引の鍵。
//!
//! コンセンサスはこの 2 つを必要としない (SPEC §19)。UTXO セットだけで
//! 検証は完結する。ここにあるのは**エクスプローラとウォレットの履歴表示の
//! ためだけの索引**であり、運用者が `--index` で選んだときにのみ作られる。
//!
//! # 鍵を縮める
//!
//! 素直に作ると、txid 32 バイトと lock ハッシュ 32 バイトがそのまま鍵に
//! なる。満杯のブロックが続く場合、これは年間 124 GB を要する。チェーン
//! 本体の 105 GB/年より**索引のほうが重い**。
//!
//! そこで鍵を次の 14 バイトに圧縮する。
//!
//! ```text
//! ┌──────────────┬──────────┬────────┐
//! │ 接頭辞 8 B   │ 高さ 4 B │ 位置 2 B│
//! └──────────────┴──────────┴────────┘
//!   ハッシュの頭   u32 BE     u16 BE
//! ```
//!
//! 値は持たない。これで 124 GB/年 が 37 GB/年 になる。
//!
//! # 接頭辞が短くて衝突しないのか
//!
//! **衝突する。しかし誤答にはならない。**
//!
//! 索引が返すのは「ここを見ろ」という位置であって答えそのものではない。
//! 呼び出し側はその位置のブロックを読み、取引を取り出し、**完全な txid
//! または完全な lock と突き合わせる**。一致しなければ捨てる。つまり衝突
//! は余計な候補が 1 件増えるだけで、間違った取引が返ることはない。
//!
//! 8 バイト (2^64) に 3.5 億件を入れたときの衝突の期待値は約 0.003 件で
//! ある。狙って作ることは 2^64 の作業を要するうえ、成功しても得られるのは
//! 「相手の照会に無駄足を 1 回踏ませる」ことだけである。
//!
//! # 高さを u32、位置を u16 にしてよい理由
//!
//! 高さは u32 で 42 億ブロック、1 ブロック 60 秒で 8,100 年分である。
//! 発行完了が高さ 1 億 (SPEC §11) なのでその 42 倍の余裕がある。
//!
//! 位置はブロック内の取引の並び順である。ブロックの上限 200,000 バイトに
//! 対し取引の符号化の下限は 7 バイトなので、詰め込んでも 28,571 件であり
//! u16 (65,535) に収まる。[`key`] は念のため確かめる。
//!
//! # なぜビッグエンディアンなのか
//!
//! redb は鍵をバイト列として並べる。高さと位置をビッグエンディアンで
//! 置くと、**バイト順がそのままチェーン順になる**。同じ接頭辞を持つ鍵を
//! 前方一致で範囲走査すれば、履歴が古い順に並んで出てくる。並べ替えが
//! 要らず、続きから読むだけでページ送りになる。
//!
//! リトルエンディアンにすると高さ 1 と高さ 256 の並びが入れ替わり、
//! この性質がすべて失われる。

use oag_consensus::codec::Encode;
use oag_consensus::lock::Lock;
use oag_primitives::Hash;

/// 鍵に使うハッシュの接頭辞の長さ。
pub const PREFIX_LEN: usize = 8;

/// 索引の鍵の長さ。接頭辞 8 + 高さ 4 + 位置 2。
pub const KEY_LEN: usize = PREFIX_LEN + 4 + 2;

/// ブロック内の取引の位置の上限。
///
/// これを超えるブロックは符号化の上限から作れないが、索引が黙って
/// 取りこぼすことのないよう [`key`] で確かめる。
pub const MAX_POSITION: usize = u16::MAX as usize;

/// 索引に収まらない値を渡された。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// 高さが u32 に収まらない。
    #[error("height {0} does not fit in the index key")]
    HeightTooLarge(u64),
    /// ブロック内の位置が u16 に収まらない。
    #[error("the index {0} within the block does not fit in the index key")]
    PositionTooLarge(usize),
}

/// 取引索引の接頭辞。
///
/// txid は既にハッシュなので、頭をそのまま取る。
pub fn tx_prefix(txid: &Hash) -> [u8; PREFIX_LEN] {
    let mut out = [0u8; PREFIX_LEN];
    out.copy_from_slice(&txid.as_bytes()[..PREFIX_LEN]);
    out
}

/// アドレス索引の接頭辞。
///
/// `Lock` は版数 + 可変長ペイロードなので、そのままでは頭を取れない
/// (版数 0 のペイロードは公開鍵そのものであり、版数が違えば長さも違う)。
/// タグ付きハッシュを通してから頭を取る。
pub fn lock_prefix(lock: &Lock) -> [u8; PREFIX_LEN] {
    let hash = oag_primitives::hash::tagged("OAG/addrindex", &lock.encode());
    let mut out = [0u8; PREFIX_LEN];
    out.copy_from_slice(&hash.as_bytes()[..PREFIX_LEN]);
    out
}

/// 接頭辞・高さ・位置から鍵を組み立てる。
pub fn key(
    prefix: [u8; PREFIX_LEN],
    height: u64,
    position: usize,
) -> Result<[u8; KEY_LEN], KeyError> {
    let height: u32 = height
        .try_into()
        .map_err(|_| KeyError::HeightTooLarge(height))?;
    let position: u16 = position
        .try_into()
        .map_err(|_| KeyError::PositionTooLarge(position))?;
    let mut out = [0u8; KEY_LEN];
    out[..PREFIX_LEN].copy_from_slice(&prefix);
    out[PREFIX_LEN..PREFIX_LEN + 4].copy_from_slice(&height.to_be_bytes());
    out[PREFIX_LEN + 4..].copy_from_slice(&position.to_be_bytes());
    Ok(out)
}

/// 接頭辞が一致する鍵すべてを覆う範囲。
///
/// 高さ `from` 以降に絞る。`from` が 0 なら全件である。
pub fn range(prefix: [u8; PREFIX_LEN], from: u64) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let from = u32::try_from(from).unwrap_or(u32::MAX);
    let mut lo = [0u8; KEY_LEN];
    lo[..PREFIX_LEN].copy_from_slice(&prefix);
    lo[PREFIX_LEN..PREFIX_LEN + 4].copy_from_slice(&from.to_be_bytes());

    let mut hi = [0xFFu8; KEY_LEN];
    hi[..PREFIX_LEN].copy_from_slice(&prefix);
    (lo, hi)
}

/// 鍵から高さと位置を取り出す。
pub fn split(key: &[u8]) -> Option<(u64, usize)> {
    if key.len() != KEY_LEN {
        return None;
    }
    let height = u32::from_be_bytes(key[PREFIX_LEN..PREFIX_LEN + 4].try_into().ok()?);
    let position = u16::from_be_bytes(key[PREFIX_LEN + 4..].try_into().ok()?);
    Some((u64::from(height), usize::from(position)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(byte: u8) -> [u8; PREFIX_LEN] {
        [byte; PREFIX_LEN]
    }

    #[test]
    fn keys_sort_in_chain_order() {
        // ビッグエンディアンにしている理由そのもの。高さ 2 が 10 より
        // 手前に並ばなければ、範囲走査の結果を並べ替える必要が出る。
        let mut keys = [
            key(prefix(1), 10, 0).unwrap(),
            key(prefix(1), 2, 5).unwrap(),
            key(prefix(1), 2, 0).unwrap(),
            key(prefix(1), 256, 0).unwrap(),
        ];
        keys.sort();
        let order: Vec<(u64, usize)> = keys.iter().map(|k| split(k).unwrap()).collect();
        assert_eq!(order, vec![(2, 0), (2, 5), (10, 0), (256, 0)]);
    }

    #[test]
    fn a_range_covers_only_its_own_prefix() {
        let (lo, hi) = range(prefix(5), 0);
        assert!(key(prefix(5), 0, 0).unwrap() >= lo);
        assert!(key(prefix(5), u32::MAX as u64, u16::MAX as usize).unwrap() <= hi);
        // 隣の接頭辞は外れる。
        assert!(key(prefix(4), 99, 0).unwrap() < lo);
        assert!(key(prefix(6), 0, 0).unwrap() > hi);
    }

    #[test]
    fn a_range_can_start_partway_through() {
        let (lo, _) = range(prefix(5), 100);
        assert!(key(prefix(5), 99, 0).unwrap() < lo);
        assert!(key(prefix(5), 100, 0).unwrap() >= lo);
    }

    #[test]
    fn a_height_beyond_u32_is_refused() {
        // 黙って切り捨てると、別の高さの取引として索引されてしまう。
        assert_eq!(
            key(prefix(1), u64::from(u32::MAX) + 1, 0),
            Err(KeyError::HeightTooLarge(u64::from(u32::MAX) + 1))
        );
    }

    #[test]
    fn a_position_beyond_u16_is_refused() {
        assert_eq!(
            key(prefix(1), 0, MAX_POSITION + 1),
            Err(KeyError::PositionTooLarge(MAX_POSITION + 1))
        );
    }

    #[test]
    fn split_refuses_a_key_of_the_wrong_length() {
        assert_eq!(split(&[0u8; KEY_LEN - 1]), None);
        assert_eq!(split(&[0u8; KEY_LEN + 1]), None);
    }
}
