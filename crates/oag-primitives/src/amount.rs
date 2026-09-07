//! OAG の金額型。
//!
//! # 設計上の制約
//!
//! 本型は算術演算子 (`+`, `-`, `*`) を **意図的に実装していない**。
//! コンセンサスに関わる経路でオーバーフローが静かに発生することを防ぐため、
//! すべての演算を [`Amount::checked_add`] 等の明示的な検査付き演算に限定する。
//!
//! 参照: `docs/SPEC.md` §3

use crate::varint::{self, VarIntError};
use core::fmt;
use core::str::FromStr;

/// 小数桁数。
pub const DECIMALS: u32 = 16;

/// 1 OAG を最小単位 (atomic) で表した値。`10^16`
pub const ATOMIC_PER_OAG: u128 = 10_000_000_000_000_000;

/// 総発行量 (OAG 単位)。10 億。
pub const MAX_SUPPLY_OAG: u128 = 1_000_000_000;

/// 総発行量 (atomic 単位)。`10^25`
pub const MAX_SUPPLY_ATOMIC: u128 = MAX_SUPPLY_OAG * ATOMIC_PER_OAG;

/// 金額の生成・解釈で起きうる誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AmountError {
    /// 総発行量を超える金額。
    #[error("金額 {0} atomic が総発行量 {MAX_SUPPLY_ATOMIC} atomic を超えている")]
    OutOfRange(u128),
    /// 文字列が金額として解釈できない。
    #[error("金額として解釈できない: {0}")]
    Malformed(&'static str),
    /// 小数部が {DECIMALS} 桁を超えている。
    #[error("小数部が {DECIMALS} 桁を超えている")]
    TooManyDecimals,
    /// varint の復号に失敗した。
    #[error("金額の復号に失敗した: {0}")]
    VarInt(#[from] VarIntError),
}

/// OAG の金額。内部表現は atomic 単位の `u128`。
///
/// 常に `0 ≤ value ≤ MAX_SUPPLY_ATOMIC` を満たすことが型の不変条件である。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Amount(u128);

impl Amount {
    /// 0 OAG。
    pub const ZERO: Amount = Amount(0);

    /// 総発行量。金額として取りうる最大値。
    pub const MAX: Amount = Amount(MAX_SUPPLY_ATOMIC);

    /// 1 OAG。
    pub const ONE_OAG: Amount = Amount(ATOMIC_PER_OAG);

    /// atomic 単位から生成する。範囲外は拒否する。
    pub const fn from_atomic(value: u128) -> Result<Amount, AmountError> {
        if value > MAX_SUPPLY_ATOMIC {
            return Err(AmountError::OutOfRange(value));
        }
        Ok(Amount(value))
    }

    /// 定数定義用。範囲外の場合はコンパイル時に停止する。
    ///
    /// # Panics
    /// `value` が総発行量を超える場合。const 文脈ではコンパイルエラーとなる。
    pub const fn from_atomic_const(value: u128) -> Amount {
        assert!(value <= MAX_SUPPLY_ATOMIC, "Amount が総発行量を超えている");
        Amount(value)
    }

    /// 整数 OAG から生成する。
    pub const fn from_oag(whole: u128) -> Result<Amount, AmountError> {
        match whole.checked_mul(ATOMIC_PER_OAG) {
            Some(atomic) => Amount::from_atomic(atomic),
            None => Err(AmountError::OutOfRange(u128::MAX)),
        }
    }

    /// atomic 単位の値を返す。
    pub const fn to_atomic(self) -> u128 {
        self.0
    }

    /// 0 かどうか。
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// 検査付き加算。オーバーフローまたは総発行量超過で `None`。
    pub const fn checked_add(self, rhs: Amount) -> Option<Amount> {
        match self.0.checked_add(rhs.0) {
            Some(sum) if sum <= MAX_SUPPLY_ATOMIC => Some(Amount(sum)),
            _ => None,
        }
    }

    /// 検査付き減算。負になる場合は `None`。
    pub const fn checked_sub(self, rhs: Amount) -> Option<Amount> {
        match self.0.checked_sub(rhs.0) {
            Some(diff) => Some(Amount(diff)),
            None => None,
        }
    }

    /// 検査付き乗算。オーバーフローまたは総発行量超過で `None`。
    pub const fn checked_mul(self, k: u64) -> Option<Amount> {
        match self.0.checked_mul(k as u128) {
            Some(product) if product <= MAX_SUPPLY_ATOMIC => Some(Amount(product)),
            _ => None,
        }
    }

    /// 金額の総和。途中で総発行量を超えた場合は `None`。
    ///
    /// トランザクションの入力合計・出力合計の算出に用いる。
    pub fn sum<I: IntoIterator<Item = Amount>>(amounts: I) -> Option<Amount> {
        amounts
            .into_iter()
            .try_fold(Amount::ZERO, |acc, a| acc.checked_add(a))
    }

    /// varint として符号化し `out` に追記する。
    pub fn encode_into(self, out: &mut Vec<u8>) {
        varint::encode_into(self.0, out);
    }

    /// varint として符号化する。
    pub fn encode(self) -> Vec<u8> {
        varint::encode(self.0)
    }

    /// `buf` の先頭から金額を 1 個復号し、値と消費バイト数を返す。
    ///
    /// 範囲外の値は拒否する。
    pub fn decode(buf: &[u8]) -> Result<(Amount, usize), AmountError> {
        let (value, len) = varint::decode(buf)?;
        Ok((Amount::from_atomic(value)?, len))
    }
}

impl fmt::Display for Amount {
    /// `10`, `0.001`, `0.0000000000000001` のように、末尾の 0 を省いて表示する。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / ATOMIC_PER_OAG;
        let frac = self.0 % ATOMIC_PER_OAG;
        if frac == 0 {
            write!(f, "{whole}")
        } else {
            let frac = format!("{frac:0width$}", width = DECIMALS as usize);
            write!(f, "{whole}.{}", frac.trim_end_matches('0'))
        }
    }
}

impl FromStr for Amount {
    type Err = AmountError;

    /// `"10"`, `"0.001"`, `"1.5"` のような十進表記を解釈する。
    ///
    /// 符号、指数表記、桁区切り、空白は受け付けない。
    fn from_str(s: &str) -> Result<Amount, AmountError> {
        if s.is_empty() {
            return Err(AmountError::Malformed("空文字列"));
        }

        let (whole_str, frac_str) = match s.split_once('.') {
            Some((w, f)) => (w, f),
            None => (s, ""),
        };

        if whole_str.is_empty() && frac_str.is_empty() {
            return Err(AmountError::Malformed("数字がない"));
        }
        if frac_str.contains('.') {
            return Err(AmountError::Malformed("小数点が複数ある"));
        }
        if !whole_str.bytes().all(|b| b.is_ascii_digit())
            || !frac_str.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(AmountError::Malformed("十進数字以外を含む"));
        }
        if frac_str.len() > DECIMALS as usize {
            return Err(AmountError::TooManyDecimals);
        }

        let whole: u128 = if whole_str.is_empty() {
            0
        } else {
            whole_str
                .parse()
                .map_err(|_| AmountError::Malformed("整数部が大きすぎる"))?
        };

        let mut frac: u128 = 0;
        if !frac_str.is_empty() {
            frac = frac_str
                .parse()
                .map_err(|_| AmountError::Malformed("小数部が解釈できない"))?;
            let scale = 10u128.pow(DECIMALS - frac_str.len() as u32);
            frac = frac
                .checked_mul(scale)
                .ok_or(AmountError::Malformed("小数部が大きすぎる"))?;
        }

        let atomic = whole
            .checked_mul(ATOMIC_PER_OAG)
            .and_then(|w| w.checked_add(frac))
            .ok_or(AmountError::OutOfRange(u128::MAX))?;

        Amount::from_atomic(atomic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_spec() {
        assert_eq!(ATOMIC_PER_OAG, 10u128.pow(16));
        assert_eq!(MAX_SUPPLY_ATOMIC, 10u128.pow(25));
        // SPEC §3: u128 に対して十分な余裕があること (コンパイル時に検査する)。
        const { assert!(MAX_SUPPLY_ATOMIC < u128::MAX / 1_000_000_000_000) };
    }

    #[test]
    fn block_size_cannot_overflow_output_sum() {
        // SPEC §3: 200,000 バイトのブロックに入る出力数の上限を約 4,700 としても、
        // 全出力が総発行量であっても u128 を溢れない。
        let max_outputs: u128 = 5_000;
        assert!(max_outputs.checked_mul(MAX_SUPPLY_ATOMIC).is_some());
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(Amount::from_atomic(MAX_SUPPLY_ATOMIC).is_ok());
        assert_eq!(
            Amount::from_atomic(MAX_SUPPLY_ATOMIC + 1),
            Err(AmountError::OutOfRange(MAX_SUPPLY_ATOMIC + 1))
        );
        assert!(Amount::from_oag(MAX_SUPPLY_OAG).is_ok());
        assert!(Amount::from_oag(MAX_SUPPLY_OAG + 1).is_err());
    }

    #[test]
    fn checked_add_respects_supply_cap() {
        assert_eq!(Amount::MAX.checked_add(Amount::ONE_OAG), None);
        assert_eq!(
            Amount::ONE_OAG.checked_add(Amount::ONE_OAG),
            Some(Amount::from_oag(2).unwrap())
        );
    }

    #[test]
    fn checked_sub_rejects_negative() {
        assert_eq!(Amount::ZERO.checked_sub(Amount::ONE_OAG), None);
        assert_eq!(
            Amount::ONE_OAG.checked_sub(Amount::ONE_OAG),
            Some(Amount::ZERO)
        );
    }

    #[test]
    fn checked_mul_respects_supply_cap() {
        let ten = Amount::from_oag(10).unwrap();
        assert!(ten.checked_mul(1_000).is_some());
        assert_eq!(Amount::MAX.checked_mul(2), None);
    }

    #[test]
    fn sum_detects_overflow() {
        let half = Amount::from_oag(MAX_SUPPLY_OAG / 2).unwrap();
        assert!(Amount::sum([half, half]).is_some());
        assert_eq!(Amount::sum([half, half, Amount::ONE_OAG]), None);
        assert_eq!(Amount::sum([]), Some(Amount::ZERO));
    }

    #[test]
    fn display_round_trip() {
        let cases = [
            (Amount::ZERO, "0"),
            (Amount::ONE_OAG, "1"),
            (Amount::from_oag(10).unwrap(), "10"),
            (Amount::from_atomic(1).unwrap(), "0.0000000000000001"),
            (Amount::from_atomic(10_000_000_000_000).unwrap(), "0.001"),
            (Amount::MAX, "1000000000"),
        ];
        for (amount, text) in cases {
            assert_eq!(amount.to_string(), text);
            assert_eq!(text.parse::<Amount>().unwrap(), amount);
        }
    }

    #[test]
    fn parses_spec_policy_values() {
        // SPEC §13: 最低中継料率 0.000005 OAG/バイト
        let rate: Amount = "0.000005".parse().unwrap();
        assert_eq!(rate.to_atomic(), 50_000_000_000);
        // SPEC §13: ダスト閾値 0.0015 OAG
        let dust: Amount = "0.0015".parse().unwrap();
        assert_eq!(dust.to_atomic(), 15_000_000_000_000);
    }

    #[test]
    fn rejects_malformed_strings() {
        for s in [
            "", ".", "-1", "+1", "1.2.3", "1e10", "1_000", " 1", "1 ", "abc",
        ] {
            assert!(s.parse::<Amount>().is_err(), "{s} は拒否されるべき");
        }
        // 17 桁の小数部は受け付けない。
        assert_eq!(
            "0.00000000000000001".parse::<Amount>(),
            Err(AmountError::TooManyDecimals)
        );
        // 総発行量を 1 atomic 超える値。
        assert!("1000000000.0000000000000001".parse::<Amount>().is_err());
    }

    #[test]
    fn accepts_leading_and_trailing_dot_forms() {
        assert_eq!(
            ".5".parse::<Amount>().unwrap().to_atomic(),
            ATOMIC_PER_OAG / 2
        );
        assert_eq!(
            "5.".parse::<Amount>().unwrap(),
            Amount::from_oag(5).unwrap()
        );
    }

    #[test]
    fn encode_decode_round_trip() {
        for amount in [Amount::ZERO, Amount::ONE_OAG, Amount::MAX] {
            let bytes = amount.encode();
            let (decoded, len) = Amount::decode(&bytes).unwrap();
            assert_eq!(decoded, amount);
            assert_eq!(len, bytes.len());
        }
    }

    #[test]
    fn decode_rejects_out_of_range_varint() {
        let bytes = varint::encode(MAX_SUPPLY_ATOMIC + 1);
        assert!(matches!(
            Amount::decode(&bytes),
            Err(AmountError::OutOfRange(_))
        ));
    }
}
