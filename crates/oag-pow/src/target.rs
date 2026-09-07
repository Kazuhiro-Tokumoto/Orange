//! 難易度とターゲットの相互変換、および PoW の判定。
//!
//! Bitcoin の `nBits` (4 バイト圧縮形式) は採用しない。非正準な符号化や
//! 符号ビットの扱いに起因するバグを歴史的に生んでいること、および LWMA が
//! 難易度を直接扱うことから、難易度を `u64` で素直に保持する。
//!
//! 参照: `docs/SPEC.md` §9.3, §11.1

use oag_primitives::Hash;

/// ターゲットの上限。`2^256 − 1`。難易度 1 に対応する。
pub const MAX_TARGET: [u8; 32] = [0xff; 32];

/// 難易度が不正。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("難易度は 1 以上でなければならない")]
pub struct ZeroDifficulty;

/// 難易度からターゲットを求める。
///
/// ```text
/// target = (2^256 − 1) / difficulty
/// ```
///
/// ハッシュをビッグエンディアンの 256 ビット整数として解釈したとき、
/// この値以下であれば PoW を満たす。
pub fn target_from_difficulty(difficulty: u64) -> Result<[u8; 32], ZeroDifficulty> {
    if difficulty == 0 {
        return Err(ZeroDifficulty);
    }
    // 2^256 − 1 を 64 ビットずつ 4 個の桁に分けて筆算で割る。
    let divisor = u128::from(difficulty);
    let mut quotient = [0u64; 4];
    let mut remainder: u128 = 0;
    for limb in quotient.iter_mut() {
        // remainder < difficulty ≤ 2^64 − 1 なので、この左シフトは溢れない。
        let current = (remainder << 64) | u128::from(u64::MAX);
        *limb = (current / divisor) as u64;
        remainder = current % divisor;
    }

    let mut target = [0u8; 32];
    for (i, limb) in quotient.iter().enumerate() {
        target[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
    }
    Ok(target)
}

/// ハッシュがターゲットを満たすか。
///
/// ハッシュはビッグエンディアンの 256 ビット整数として解釈する。
pub fn meets_target(hash: &Hash, target: &[u8; 32]) -> bool {
    hash.as_bytes() <= target
}

/// ハッシュが難易度を満たすか。
pub fn meets_difficulty(hash: &Hash, difficulty: u64) -> Result<bool, ZeroDifficulty> {
    Ok(meets_target(hash, &target_from_difficulty(difficulty)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_u256(bytes: &[u8; 32]) -> f64 {
        // 比較用の近似値。厳密な比較には使わない。
        bytes
            .iter()
            .fold(0.0f64, |acc, &b| acc * 256.0 + f64::from(b))
    }

    #[test]
    fn difficulty_one_allows_every_hash() {
        let target = target_from_difficulty(1).unwrap();
        assert_eq!(target, MAX_TARGET);
        assert!(meets_target(&Hash::from_bytes([0xff; 32]), &target));
    }

    #[test]
    fn zero_difficulty_is_rejected() {
        assert_eq!(target_from_difficulty(0), Err(ZeroDifficulty));
    }

    #[test]
    fn target_halves_when_difficulty_doubles() {
        let a = to_u256(&target_from_difficulty(1_000).unwrap());
        let b = to_u256(&target_from_difficulty(2_000).unwrap());
        assert!((a / b - 2.0).abs() < 1e-9, "比が {} になっている", a / b);
    }

    #[test]
    fn target_is_monotonically_decreasing() {
        let mut previous = MAX_TARGET;
        for difficulty in [1u64, 2, 10, 1_000, 100_000, 1 << 32, u64::MAX] {
            let target = target_from_difficulty(difficulty).unwrap();
            assert!(
                target <= previous,
                "難易度 {difficulty} でターゲットが増えた"
            );
            previous = target;
        }
    }

    #[test]
    fn known_values() {
        // 難易度 2 → 2^255 − 1 に相当する (先頭バイトが 0x7f)。
        let target = target_from_difficulty(2).unwrap();
        assert_eq!(target[0], 0x7f);
        assert_eq!(target[31], 0xff);

        // 難易度 256 → 先頭バイトが 0x00、次が 0xff。
        let target = target_from_difficulty(256).unwrap();
        assert_eq!(target[0], 0x00);
        assert_eq!(target[1], 0xff);

        // 難易度 2^64 − 1 → 先頭 8 バイトがほぼ 0。
        let target = target_from_difficulty(u64::MAX).unwrap();
        assert_eq!(&target[..7], &[0u8; 7]);
        assert_eq!(target[7], 0x01);
    }

    #[test]
    fn the_pass_rate_matches_the_difficulty() {
        // 難易度 D のとき、無作為なハッシュが通る確率は約 1/D。
        for difficulty in [2u64, 4, 16, 256] {
            let target = target_from_difficulty(difficulty).unwrap();
            let trials = 200_000u32;
            let mut passed = 0u32;
            let mut state = 0x0123_4567_89ab_cdefu64;
            for _ in 0..trials {
                let mut bytes = [0u8; 32];
                for chunk in bytes.chunks_mut(8) {
                    // splitmix64
                    state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                    let mut z = state;
                    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                    chunk.copy_from_slice(&(z ^ (z >> 31)).to_be_bytes());
                }
                if meets_target(&Hash::from_bytes(bytes), &target) {
                    passed += 1;
                }
            }
            let observed = f64::from(passed) / f64::from(trials);
            let expected = 1.0 / difficulty as f64;
            assert!(
                (observed / expected - 1.0).abs() < 0.15,
                "難易度 {difficulty}: 期待 {expected:.5} に対し実測 {observed:.5}"
            );
        }
    }
}
