//! LWMA-1 による難易度調整。
//!
//! 毎ブロック調整する。タイムスタンプの逆転 (負の solvetime) を許容し、
//! クランプで扱う点が LWMA の特徴である。
//!
//! 参照: `docs/SPEC.md` §12
//! 出典: <https://github.com/zawy12/difficulty-algorithms>

use oag_consensus::params;

/// 窓幅 N。
pub const WINDOW: usize = params::LWMA_WINDOW as usize;

/// 目標ブロック時間 T (秒)。
pub const TARGET_SPACING: i64 = params::TARGET_BLOCK_TIME_SECS as i64;

/// solvetime のクランプ幅。`±CLAMP × T`。
pub const CLAMP: i64 = params::LWMA_SOLVETIME_CLAMP;

/// 重み付き solvetime 和 `L` の下限に用いる係数。
///
/// `L` がこの下限に達したとき、難易度は 1 ブロックあたり最大
/// [`MAX_RISE_FACTOR`] 倍まで上がる。
const L_FLOOR_DIVISOR: i64 = 10;

/// 1 ブロックあたりの難易度上昇の上限倍率。
pub const MAX_RISE_FACTOR: u128 = L_FLOOR_DIVISOR as u128;

/// 履歴が足りない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LwmaError {
    /// タイムスタンプが `WINDOW + 1` 件に満たない。
    #[error("タイムスタンプが {given} 件しかない ({needed} 件必要)")]
    InsufficientTimestamps {
        /// 与えられた件数。
        given: usize,
        /// 必要な件数。
        needed: usize,
    },
    /// 難易度が `WINDOW` 件に満たない。
    #[error("難易度が {given} 件しかない ({needed} 件必要)")]
    InsufficientDifficulties {
        /// 与えられた件数。
        given: usize,
        /// 必要な件数。
        needed: usize,
    },
}

/// `k = N(N+1)T / 2`。
pub const fn k() -> i64 {
    let n = WINDOW as i64;
    n * (n + 1) * TARGET_SPACING / 2
}

/// 次のブロックの難易度を求める。
///
/// `timestamps` は直近 `WINDOW + 1` 件、`difficulties` は直近 `WINDOW` 件を
/// **古い順**に並べたもの。それより多い場合は末尾 (新しい方) を用いる。
pub fn next_difficulty(timestamps: &[i64], difficulties: &[u64]) -> Result<u64, LwmaError> {
    if timestamps.len() < WINDOW + 1 {
        return Err(LwmaError::InsufficientTimestamps {
            given: timestamps.len(),
            needed: WINDOW + 1,
        });
    }
    if difficulties.len() < WINDOW {
        return Err(LwmaError::InsufficientDifficulties {
            given: difficulties.len(),
            needed: WINDOW,
        });
    }

    let timestamps = &timestamps[timestamps.len() - (WINDOW + 1)..];
    let difficulties = &difficulties[difficulties.len() - WINDOW..];

    let bound = CLAMP * TARGET_SPACING;
    let mut weighted_solvetime: i64 = 0;
    let mut sum_difficulty: u128 = 0;

    for i in 1..=WINDOW {
        let solvetime = timestamps[i]
            .saturating_sub(timestamps[i - 1])
            .clamp(-bound, bound);
        weighted_solvetime += solvetime * i as i64;
        sum_difficulty += u128::from(difficulties[i - 1]);
    }

    // 難易度の急騰を抑える下限。タイムスタンプ操作への耐性も兼ねる。
    let l = weighted_solvetime.max(k() / L_FLOOR_DIVISOR);

    // sum_difficulty ≤ 90 × (2^64 − 1) ≈ 1.7×10^21、k = 245,700 なので、
    // 積は約 4.1×10^26 であり u128 (最大 3.4×10^38) に収まる。
    let next = sum_difficulty * (k() as u128) / ((WINDOW as u128) * (l as u128));

    Ok(next.clamp(1, u128::from(u64::MAX)) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 決定的な擬似乱数 (splitmix64)。シミュレーションを再現可能にする。
    struct Rng(u64);

    impl Rng {
        fn new(seed: u64) -> Rng {
            Rng(seed)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        /// `(0, 1]` の一様乱数。
        fn unit(&mut self) -> f64 {
            1.0 - (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
        }

        /// 平均 `mean` の指数分布。ブロック発見時間の分布である。
        fn exponential(&mut self, mean: f64) -> f64 {
            -mean * self.unit().ln()
        }
    }

    /// 難易度調整のシミュレーション。
    struct Sim {
        timestamps: Vec<i64>,
        difficulties: Vec<u64>,
        clock: f64,
        rng: Rng,
    }

    impl Sim {
        /// ハッシュレート `hashrate` と釣り合った状態から始める。
        fn new(hashrate: f64, seed: u64) -> Sim {
            let equilibrium = (hashrate * TARGET_SPACING as f64) as u64;
            let mut timestamps = Vec::new();
            let mut difficulties = Vec::new();
            for i in 0..=WINDOW {
                timestamps.push(i as i64 * TARGET_SPACING);
                if i < WINDOW {
                    difficulties.push(equilibrium);
                }
            }
            Sim {
                clock: (WINDOW as i64 * TARGET_SPACING) as f64,
                timestamps,
                difficulties,
                rng: Rng::new(seed),
            }
        }

        fn current_difficulty(&self) -> u64 {
            *self.difficulties.last().unwrap()
        }

        /// 1 ブロック採掘する。solvetime は指数分布に従う。
        fn mine(&mut self, hashrate: f64) -> f64 {
            let difficulty = next_difficulty(&self.timestamps, &self.difficulties).unwrap();
            let solvetime = self.rng.exponential(difficulty as f64 / hashrate);
            self.clock += solvetime;
            self.timestamps.push(self.clock as i64);
            self.difficulties.push(difficulty);
            solvetime
        }

        /// `count` ブロック採掘し、solvetime の平均を返す。
        fn run(&mut self, hashrate: f64, count: usize) -> f64 {
            let total: f64 = (0..count).map(|_| self.mine(hashrate)).sum();
            total / count as f64
        }
    }

    // ━━━━━━━━ 基本的な性質 ━━━━━━━━

    #[test]
    fn constants_match_spec() {
        assert_eq!(WINDOW, 90);
        assert_eq!(TARGET_SPACING, 60);
        assert_eq!(CLAMP, 6);
        assert_eq!(k(), 90 * 91 * 60 / 2);
        assert_eq!(k(), 245_700);
    }

    #[test]
    fn a_perfectly_paced_chain_keeps_its_difficulty() {
        // すべての solvetime がちょうど T なら、難易度は変わらない。
        let timestamps: Vec<i64> = (0..=WINDOW as i64).map(|i| i * TARGET_SPACING).collect();
        let difficulties = vec![1_000_000u64; WINDOW];
        assert_eq!(
            next_difficulty(&timestamps, &difficulties).unwrap(),
            1_000_000
        );
    }

    #[test]
    fn slow_blocks_lower_the_difficulty() {
        let timestamps: Vec<i64> = (0..=WINDOW as i64)
            .map(|i| i * TARGET_SPACING * 2)
            .collect();
        let difficulties = vec![1_000_000u64; WINDOW];
        let next = next_difficulty(&timestamps, &difficulties).unwrap();
        assert!(next < 1_000_000, "遅いのに難易度が下がっていない: {next}");
        // solvetime が 2T なら難易度は約半分になる。
        assert!((450_000..550_000).contains(&next), "実際には {next}");
    }

    #[test]
    fn fast_blocks_raise_the_difficulty() {
        let timestamps: Vec<i64> = (0..=WINDOW as i64)
            .map(|i| i * TARGET_SPACING / 2)
            .collect();
        let difficulties = vec![1_000_000u64; WINDOW];
        let next = next_difficulty(&timestamps, &difficulties).unwrap();
        assert!((1_900_000..2_100_000).contains(&next), "実際には {next}");
    }

    #[test]
    fn difficulty_never_reaches_zero() {
        // 極端に遅いチェーンでも難易度は 1 を下回らない。
        let timestamps: Vec<i64> = (0..=WINDOW as i64)
            .map(|i| i * TARGET_SPACING * 1_000)
            .collect();
        let difficulties = vec![1u64; WINDOW];
        assert_eq!(next_difficulty(&timestamps, &difficulties).unwrap(), 1);
    }

    #[test]
    fn the_rise_per_block_is_capped() {
        // すべてのタイムスタンプが同一 (solvetime = 0) でも、
        // 難易度の上昇は 1 ブロックあたり L の下限で頭打ちになる。
        let timestamps = vec![0i64; WINDOW + 1];
        let difficulties = vec![1_000_000u64; WINDOW];
        let next = next_difficulty(&timestamps, &difficulties).unwrap();
        assert_eq!(
            u128::from(next),
            1_000_000 * MAX_RISE_FACTOR,
            "上昇は 1 ブロックあたり 10 倍で頭打ちになるべき"
        );
    }

    #[test]
    fn negative_solvetimes_are_clamped() {
        // タイムスタンプを大きく過去に偽っても、影響は -6T で止まる。
        let mut honest: Vec<i64> = (0..=WINDOW as i64).map(|i| i * TARGET_SPACING).collect();
        let difficulties = vec![1_000_000u64; WINDOW];
        let baseline = next_difficulty(&honest, &difficulties).unwrap();

        // 最後のブロックのタイムスタンプを 1 年前に偽る。
        *honest.last_mut().unwrap() -= 31_536_000;
        let attacked = next_difficulty(&honest, &difficulties).unwrap();

        // クランプにより、1 ブロック分の -6T しか効かない。
        let cap = baseline * 2;
        assert!(
            attacked < cap,
            "クランプが効いていない: {baseline} → {attacked}"
        );
    }

    #[test]
    fn rejects_insufficient_history() {
        let short: Vec<i64> = (0..WINDOW as i64).collect();
        assert!(matches!(
            next_difficulty(&short, &vec![1u64; WINDOW]),
            Err(LwmaError::InsufficientTimestamps { .. })
        ));
        let timestamps: Vec<i64> = (0..=WINDOW as i64).collect();
        assert!(matches!(
            next_difficulty(&timestamps, &vec![1u64; WINDOW - 1]),
            Err(LwmaError::InsufficientDifficulties { .. })
        ));
    }

    #[test]
    fn does_not_overflow_at_maximum_difficulty() {
        let timestamps = vec![0i64; WINDOW + 1];
        let difficulties = vec![u64::MAX; WINDOW];
        assert_eq!(
            next_difficulty(&timestamps, &difficulties).unwrap(),
            u64::MAX
        );
    }

    // ━━━━━━━━ シミュレーションによる N = 90 の検証 ━━━━━━━━
    //
    // SPEC §12.2 が要求する検証項目に対応する。

    #[test]
    fn steady_state_holds_the_target_block_time() {
        let hashrate = 1_000.0;
        let mut sim = Sim::new(hashrate, 0xC0FFEE);
        sim.run(hashrate, 500); // 慣らし
        let mean = sim.run(hashrate, 5_000);
        assert!(
            (57.0..63.0).contains(&mean),
            "定常状態の平均ブロック間隔が {mean:.1} 秒 (目標 60 秒)"
        );
    }

    #[test]
    fn steady_state_difficulty_stays_near_equilibrium() {
        let hashrate = 1_000.0;
        let equilibrium = hashrate * TARGET_SPACING as f64;
        let mut sim = Sim::new(hashrate, 0xBEEF);
        sim.run(hashrate, 500);

        let mut worst = 1.0f64;
        for _ in 0..3_000 {
            sim.mine(hashrate);
            let ratio = sim.current_difficulty() as f64 / equilibrium;
            worst = worst.max(ratio).max(1.0 / ratio);
        }
        assert!(
            worst < 2.0,
            "定常状態で難易度が均衡値の {worst:.2} 倍まで振れた"
        );
    }

    #[test]
    fn adapts_to_a_tenfold_hashrate_increase() {
        let before = 1_000.0;
        let after = 10_000.0;
        let new_equilibrium = after * TARGET_SPACING as f64;

        let mut sim = Sim::new(before, 0x1234);
        sim.run(before, 500);

        // ハッシュレートが 10 倍になった直後の追随を測る。
        let mut blocks_to_adapt = None;
        for i in 1..=400 {
            sim.mine(after);
            let ratio = sim.current_difficulty() as f64 / new_equilibrium;
            if blocks_to_adapt.is_none() && (0.8..1.25).contains(&ratio) {
                blocks_to_adapt = Some(i);
            }
        }
        let blocks = blocks_to_adapt.expect("400 ブロック以内に追随しなかった");
        assert!(
            blocks <= 2 * WINDOW,
            "追随に {blocks} ブロックかかった (窓幅の 2 倍 = {} 以内であるべき)",
            2 * WINDOW
        );
    }

    #[test]
    fn recovers_from_losing_ninety_percent_of_the_hashrate() {
        let before = 10_000.0;
        let after = 1_000.0;
        let new_equilibrium = after * TARGET_SPACING as f64;

        let mut sim = Sim::new(before, 0x5678);
        sim.run(before, 500);

        let mut blocks_to_adapt = None;
        for i in 1..=400 {
            sim.mine(after);
            let ratio = sim.current_difficulty() as f64 / new_equilibrium;
            if blocks_to_adapt.is_none() && (0.8..1.25).contains(&ratio) {
                blocks_to_adapt = Some(i);
            }
        }
        let blocks = blocks_to_adapt.expect("400 ブロック以内に回復しなかった");
        assert!(
            blocks <= 2 * WINDOW,
            "回復に {blocks} ブロックかかった (窓幅の 2 倍 = {} 以内であるべき)",
            2 * WINDOW
        );
    }

    #[test]
    fn survives_repeated_hashrate_swings() {
        // 攻撃者が繰り返し出入りしても、平均ブロック間隔が破綻しないこと。
        let base = 1_000.0;
        let mut sim = Sim::new(base, 0xABCD);
        sim.run(base, 300);

        let mut total = 0.0;
        let mut count = 0usize;
        for round in 0..10 {
            let hashrate = if round % 2 == 0 { base * 20.0 } else { base };
            for _ in 0..100 {
                total += sim.mine(hashrate);
                count += 1;
            }
        }
        let mean = total / count as f64;
        assert!(
            (30.0..120.0).contains(&mean),
            "変動下の平均ブロック間隔が {mean:.1} 秒"
        );
    }
}
