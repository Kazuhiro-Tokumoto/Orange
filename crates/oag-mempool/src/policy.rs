//! 中継ポリシー。
//!
//! **ここに書かれた規則はコンセンサスルールではない。** 各ノードが自分の
//! 判断で適用する取捨選択であり、変更にハードフォークを必要としない。
//! マイナーがこれらを無視したトランザクションをブロックに入れることは
//! 妨げられない。
//!
//! この分離により、OAG の価格が変動しても最低手数料をハードフォークなしに
//! 調整できる (SPEC §13.1)。
//!
//! 参照: `docs/SPEC.md` §13, §10.4

use oag_consensus::params;
use oag_primitives::Amount;

/// 中継ポリシーの設定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// 最低中継料率 (atomic / バイト)。
    pub min_relay_fee_rate: Amount,
    /// ダスト閾値。これ未満の出力を含むトランザクションは中継しない。
    pub dust_threshold: Amount,
    /// mempool が保持するトランザクションの合計バイト数の上限。
    pub max_mempool_bytes: usize,
    /// 未知の版数の支払い条件を許すか。
    ///
    /// **既定は false である。** 未知の版数はコンセンサス上 anyone-can-spend
    /// として扱われる (SPEC §10.4)。有効化前にそのようなアドレスへ送金すると
    /// 資金を失うため、ポリシー層で作成も使用も中継しない。
    pub allow_unknown_lock_versions: bool,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            min_relay_fee_rate: params::MIN_RELAY_FEE_RATE_PER_BYTE,
            dust_threshold: params::DUST_THRESHOLD,
            // 200,000 バイトのブロック 300 個分。約 5 時間分の需要にあたる。
            max_mempool_bytes: params::MAX_BLOCK_SIZE * 300,
            allow_unknown_lock_versions: false,
        }
    }
}

impl Policy {
    /// `size` バイトのトランザクションに要求される最低手数料。
    pub fn required_fee(&self, size: usize) -> Option<Amount> {
        self.min_relay_fee_rate
            .checked_mul(u64::try_from(size).ok()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec() {
        let policy = Policy::default();
        assert_eq!(policy.min_relay_fee_rate.to_string(), "0.000005");
        assert_eq!(policy.dust_threshold.to_string(), "0.0015");
        assert!(
            !policy.allow_unknown_lock_versions,
            "未知の版数は既定で中継しない"
        );
    }

    #[test]
    fn the_required_fee_scales_with_size() {
        let policy = Policy::default();
        // SPEC §7.2 の基準トランザクション (195 バイト)。
        assert_eq!(policy.required_fee(195).unwrap().to_string(), "0.000975");
        assert_eq!(policy.required_fee(0).unwrap(), Amount::ZERO);
    }

    #[test]
    fn the_mempool_holds_a_few_hours_of_demand() {
        let policy = Policy::default();
        let blocks = policy.max_mempool_bytes / params::MAX_BLOCK_SIZE;
        let hours = blocks as u64 * params::TARGET_BLOCK_TIME_SECS / 3_600;
        assert_eq!(blocks, 300);
        assert_eq!(hours, 5);
    }
}
