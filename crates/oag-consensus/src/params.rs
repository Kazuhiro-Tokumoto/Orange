//! コンセンサスパラメータと手数料ポリシー。
//!
//! ここに定義した値は `docs/SPEC.md` の付録 A に対応する。
//! 仕様書が正典であり、差異は仕様書側を優先して解消する。

use oag_primitives::Amount;

// ━━━ コンセンサス (SPEC §10.1) ━━━

/// 目標ブロック時間 (秒)。
pub const TARGET_BLOCK_TIME_SECS: u64 = 60;

/// ブロックのシリアライズサイズ上限 (バイト)。
pub const MAX_BLOCK_SIZE: usize = 200_000;

/// トランザクションのシリアライズサイズ上限 (バイト)。
pub const MAX_TX_SIZE: usize = 100_000;

/// コインベース出力が使用可能になるまでのブロック数。
pub const COINBASE_MATURITY: u64 = 120;

/// Median Time Past の算出に用いるブロック数。
pub const MEDIAN_TIME_SPAN: usize = 11;

/// ノードの現在時刻より先のタイムスタンプを許容する秒数。
///
/// Bitcoin の 2 時間は 60 秒ブロックには緩すぎる (120 ブロック分の裁量を
/// 与えることになり、難易度操作の余地が大きい)。
pub const MAX_FUTURE_TIME_DRIFT_SECS: i64 = 300;

// ━━━ 発行 (SPEC §4) ━━━

/// ブロック報酬。固定・不変。10 OAG。
pub const BLOCK_REWARD: Amount = Amount::from_atomic_const(100_000_000_000_000_000);

/// この高さ以降のブロック報酬は 0 になる。
pub const EMISSION_END_HEIGHT: u64 = 100_000_000;

/// 1 年あたりのブロック数 (365 日換算)。
pub const BLOCKS_PER_YEAR: u64 = 525_600;

/// 指定した高さのブロック報酬。
///
/// 半減期は存在しない。発行終了高さまで一定である。
pub const fn block_subsidy(height: u64) -> Amount {
    if height < EMISSION_END_HEIGHT {
        BLOCK_REWARD
    } else {
        Amount::ZERO
    }
}

// ━━━ 難易度調整 (SPEC §12) ━━━

/// LWMA の窓幅。**暫定値**。シミュレーションによる検証を要する。
pub const LWMA_WINDOW: u64 = 90;

/// solvetime をクランプする倍率。`±LWMA_SOLVETIME_CLAMP × T` に制限する。
pub const LWMA_SOLVETIME_CLAMP: i64 = 6;

// ━━━ Proof of Work (SPEC §11) ━━━

/// RandomX のシードを切り替える周期 (ブロック数)。
pub const SEED_EPOCH_BLOCKS: u64 = 2048;

/// シード切り替えの遅延 (ブロック数)。リオーグでシードが変わることを防ぐ。
pub const SEED_LAG: u64 = 64;

// ━━━ 手数料ポリシー (SPEC §13) ━━━
//
// 以下はコンセンサスルールではなく **ノードポリシー** である。
// ハードフォークなしに各ノードが調整できる。

/// 最低中継料率 (atomic / バイト)。既定 0.000005 OAG/バイト。
pub const MIN_RELAY_FEE_RATE_PER_BYTE: Amount = Amount::from_atomic_const(50_000_000_000);

/// ダスト閾値。既定 0.0015 OAG。
///
/// 1 入力を消費するコスト (102 バイト × 料率 = 0.00051 OAG) の約 3 倍。
/// これ未満の出力は UTXO セットを恒久的に汚染するため中継しない。
pub const DUST_THRESHOLD: Amount = Amount::from_atomic_const(15_000_000_000_000);

/// `size` バイトのトランザクションに対する最低手数料。
pub fn min_relay_fee(size: usize) -> Option<Amount> {
    MIN_RELAY_FEE_RATE_PER_BYTE.checked_mul(u64::try_from(size).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_primitives::amount::MAX_SUPPLY_ATOMIC;

    #[test]
    fn total_emission_equals_max_supply() {
        // 報酬が一定なので、総発行量は 高さ × 報酬 で厳密に一致する。
        let total = BLOCK_REWARD
            .checked_mul(EMISSION_END_HEIGHT)
            .expect("総発行量に収まる");
        assert_eq!(total, Amount::MAX);
        assert_eq!(total.to_atomic(), MAX_SUPPLY_ATOMIC);
    }

    #[test]
    fn subsidy_stops_exactly_at_emission_end() {
        assert_eq!(block_subsidy(0), BLOCK_REWARD);
        assert_eq!(block_subsidy(EMISSION_END_HEIGHT - 1), BLOCK_REWARD);
        assert_eq!(block_subsidy(EMISSION_END_HEIGHT), Amount::ZERO);
        assert_eq!(block_subsidy(u64::MAX), Amount::ZERO);
    }

    #[test]
    fn emission_takes_about_190_years() {
        let seconds = EMISSION_END_HEIGHT * TARGET_BLOCK_TIME_SECS;
        let years = seconds as f64 / (BLOCKS_PER_YEAR * TARGET_BLOCK_TIME_SECS) as f64;
        assert!((190.0..191.0).contains(&years), "実際には {years} 年");
    }

    #[test]
    fn annual_emission_matches_spec() {
        // SPEC §4: 年間 5,256,000 OAG
        let annual = BLOCK_REWARD.checked_mul(BLOCKS_PER_YEAR).unwrap();
        assert_eq!(annual.to_string(), "5256000");
    }

    #[test]
    fn blocks_per_year_is_consistent() {
        assert_eq!(BLOCKS_PER_YEAR, 365 * 24 * 60 * 60 / TARGET_BLOCK_TIME_SECS);
    }

    #[test]
    fn policy_values_match_spec() {
        assert_eq!(MIN_RELAY_FEE_RATE_PER_BYTE.to_string(), "0.000005");
        assert_eq!(DUST_THRESHOLD.to_string(), "0.0015");
    }

    #[test]
    fn standard_transaction_fee_is_about_one_milli_oag() {
        // SPEC §7.2: 標準送金は約 195 バイト。
        let fee = min_relay_fee(195).unwrap();
        assert_eq!(fee.to_string(), "0.000975");
    }

    #[test]
    fn filling_a_block_costs_one_oag() {
        // SPEC §13.4
        let cost = min_relay_fee(MAX_BLOCK_SIZE).unwrap();
        assert_eq!(cost.to_string(), "1");
    }

    #[test]
    fn dust_threshold_is_about_three_times_input_cost() {
        // 1 入力は 102 バイト (SPEC §7.2)。厳密な 3 倍は 0.00153 OAG だが、
        // 政策値として 0.0015 に丸めている。
        let input_cost = min_relay_fee(102).unwrap();
        assert_eq!(input_cost.to_string(), "0.00051");
        let ratio = DUST_THRESHOLD.to_atomic() as f64 / input_cost.to_atomic() as f64;
        assert!((2.5..=3.5).contains(&ratio), "実際の倍率は {ratio}");
    }
}
