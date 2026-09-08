//! ブロックロケータ。
//!
//! 「自分はどこまで持っているか」を相手に伝えるための、ブロックハッシュの
//! 列である。新しい方は 1 個ずつ、古くなるにつれて間隔を指数的に広げる。
//!
//! ```text
//! 先端 ─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬───┬─────┬─────────┬──── ジェネシス
//!       0 1 2 3 4 5 6 7 8 9  +2   +4      +8
//! ```
//!
//! # なぜ等間隔ではないのか
//!
//! 相手との分岐点を見つけるのが目的である。分岐は普通ごく浅い場所で起きる
//! ため、新しい側を細かく、古い側を粗くする。**高さ 1 億のチェーンでも
//! 64 個以内に収まる**ので、`getheaders` が肥大しない。
//!
//! 参照: `docs/SPEC.md` §14.5

use crate::message::MAX_LOCATOR;
use oag_primitives::Hash;

/// 先端から遡って、間隔を広げた高さの列を作る。
///
/// 先頭は必ず `tip`、末尾は必ず 0 (ジェネシス) になる。
pub fn locator_heights(tip: u64) -> Vec<u64> {
    let mut heights = Vec::with_capacity(MAX_LOCATOR);
    let mut step: u64 = 1;
    let mut height = tip;

    loop {
        heights.push(height);
        if heights.len() >= MAX_LOCATOR {
            break;
        }
        // 新しい側の 10 個は 1 個ずつ、その後は間隔を倍にしていく。
        if heights.len() > 10 {
            step = step.saturating_mul(2);
        }
        if height < step {
            break;
        }
        height -= step;
    }

    // ジェネシスは必ず含める。これが無いと、相手と何も共有していない場合に
    // 分岐点を決められない。
    if *heights.last().expect("必ず 1 個はある") != 0 {
        if heights.len() >= MAX_LOCATOR {
            *heights.last_mut().expect("必ず 1 個はある") = 0;
        } else {
            heights.push(0);
        }
    }
    heights
}

/// ロケータを組み立てる。
///
/// `hash_at` はアクティブチェーンの指定した高さのハッシュを返す。
/// 引けなかった高さは飛ばす。
pub fn build_locator<F>(tip_height: u64, hash_at: F) -> Vec<Hash>
where
    F: Fn(u64) -> Option<Hash>,
{
    locator_heights(tip_height)
        .into_iter()
        .filter_map(hash_at)
        .collect()
}

/// 受け取ったロケータから、そこから送り始めるべき高さを求める。
///
/// `height_of` は、そのハッシュが自分のアクティブチェーン上にあれば高さを
/// 返す。どれも共有していなければ 0 (ジェネシスから送る) とする。
///
/// # 得られるのは近似である
///
/// 返るのは「**ロケータに載っている中で**最も新しい共有点」であり、実際に
/// 共有している最も新しいブロックとは限らない。ロケータは古い側を粗く
/// 間引いているためである。
///
/// たとえば相手が高さ 50 まで共有していても、ロケータに 60 と 28 しか
/// 載っていなければ 28 が返る。これで構わない。**多めに送るだけで、
/// 足りなくなることはない**からである。要求側は既に持っているヘッダを
/// 捨てればよい。
pub fn find_fork_height<F>(locator: &[Hash], height_of: F) -> u64
where
    F: Fn(&Hash) -> Option<u64>,
{
    // ロケータは新しい順に並んでいる。最初に見つかったものが分岐点である。
    locator.iter().find_map(height_of).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_primitives::hash;

    fn hash_for(height: u64) -> Hash {
        hash::block_hash(&height.to_le_bytes())
    }

    #[test]
    fn it_starts_at_the_tip_and_ends_at_the_genesis() {
        for tip in [0u64, 1, 5, 10, 100, 10_000, 100_000_000] {
            let heights = locator_heights(tip);
            assert_eq!(heights[0], tip, "先端が先頭でない (tip={tip})");
            assert_eq!(
                *heights.last().unwrap(),
                0,
                "ジェネシスが末尾でない (tip={tip})"
            );
        }
    }

    #[test]
    fn the_heights_strictly_decrease() {
        for tip in [1u64, 9, 10, 11, 1_000, 1_000_000] {
            let heights = locator_heights(tip);
            for pair in heights.windows(2) {
                assert!(pair[0] > pair[1], "単調でない: {pair:?} (tip={tip})");
            }
        }
    }

    #[test]
    fn the_newest_ten_are_consecutive() {
        let heights = locator_heights(100);
        for (i, height) in heights.iter().take(10).enumerate() {
            assert_eq!(*height, 100 - i as u64, "{i} 番目が飛んでいる");
        }
    }

    #[test]
    fn the_gaps_grow_exponentially() {
        let heights = locator_heights(10_000);
        let gaps: Vec<u64> = heights.windows(2).map(|p| p[0] - p[1]).collect();
        // 最初の 10 個の間隔は 1。
        assert!(
            gaps[..9].iter().all(|g| *g == 1),
            "実際には {:?}",
            &gaps[..9]
        );
        // その後は倍々になる (末尾のジェネシスへの飛びを除く)。
        for pair in gaps[10..gaps.len() - 1].windows(2) {
            assert_eq!(pair[1], pair[0] * 2, "間隔が倍になっていない: {gaps:?}");
        }
    }

    #[test]
    fn a_very_long_chain_still_fits() {
        // 発行完了時点の高さでも上限に収まること。
        let heights = locator_heights(100_000_000);
        assert!(
            heights.len() <= MAX_LOCATOR,
            "{} 個になった (上限 {MAX_LOCATOR})",
            heights.len()
        );
        assert_eq!(heights[0], 100_000_000);
        assert_eq!(*heights.last().unwrap(), 0);
        // 途中が抜け落ちて短くなりすぎていないこと。
        assert!(heights.len() > 30, "{} 個しかない", heights.len());
    }

    #[test]
    fn a_short_chain_is_listed_completely() {
        assert_eq!(locator_heights(0), vec![0]);
        assert_eq!(locator_heights(1), vec![1, 0]);
        assert_eq!(locator_heights(3), vec![3, 2, 1, 0]);
    }

    #[test]
    fn building_skips_heights_that_cannot_be_read() {
        // 途中が引けなくても組み立ては続く。
        let locator = build_locator(20, |h| (h % 2 == 0).then(|| hash_for(h)));
        assert!(!locator.is_empty());
        assert!(locator.contains(&hash_for(20)));
        assert!(locator.contains(&hash_for(0)));
    }

    #[test]
    fn the_fork_point_is_the_newest_shared_entry_in_the_locator() {
        let heights = locator_heights(100);
        let locator = build_locator(100, |h| Some(hash_for(h)));
        // 相手は高さ 50 以下だけを共有している。
        let shared = |hash: &Hash| (0..=50u64).find(|h| hash_for(*h) == *hash);

        // ロケータに載っている中で 50 以下の最も新しいもの。
        let expected = *heights.iter().find(|h| **h <= 50).unwrap();
        assert_eq!(find_fork_height(&locator, shared), expected);

        // 実際の共有点 (50) より古い場所から送り始めることになる。
        // 多めに送るだけなので問題にならない。
        assert!(expected <= 50, "共有していない高さから送ろうとしている");
    }

    #[test]
    fn an_exact_shared_tip_is_found_exactly() {
        // ロケータの新しい側 10 個は 1 個刻みなので、浅い分岐は厳密に当たる。
        let locator = build_locator(100, |h| Some(hash_for(h)));
        for shared_tip in 91..=100u64 {
            let shared = |hash: &Hash| (0..=shared_tip).find(|h| hash_for(*h) == *hash);
            assert_eq!(
                find_fork_height(&locator, shared),
                shared_tip,
                "深さ {} の分岐が厳密に当たらない",
                100 - shared_tip
            );
        }
    }

    #[test]
    fn nothing_shared_means_start_from_the_genesis() {
        let locator = build_locator(100, |h| Some(hash_for(h)));
        assert_eq!(find_fork_height(&locator, |_| None), 0);
    }

    #[test]
    fn an_empty_locator_means_start_from_the_genesis() {
        assert_eq!(find_fork_height(&[], |_| Some(42)), 0);
    }

    #[test]
    fn the_fork_point_ignores_older_entries_once_one_matches() {
        // ロケータは新しい順なので、最初に一致したものを採る。
        let locator = vec![hash_for(30), hash_for(20), hash_for(10)];
        let shared = |hash: &Hash| [10u64, 20].into_iter().find(|h| hash_for(*h) == *hash);
        assert_eq!(find_fork_height(&locator, shared), 20);
    }
}
