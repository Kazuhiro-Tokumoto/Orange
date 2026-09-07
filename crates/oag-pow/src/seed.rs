//! RandomX のシードエポック。
//!
//! RandomX のデータセットは一定周期で切り替わる。切り替えのたびにマイナーは
//! 2 GB のデータセットを再構築する必要があり (1 回あたり 1〜2 分)、
//! 周期を短くすると実効ハッシュレートが落ちる。
//!
//! 参照: `docs/SPEC.md` §11.3

use oag_consensus::params::{SEED_EPOCH_BLOCKS, SEED_LAG};

/// 指定した高さのブロックが用いるシードのブロック高さ。
///
/// 遅延 [`SEED_LAG`] を設けているのは、浅いリオーグでシードが変わることを
/// 防ぐためである。シードが変わるとデータセットの再構築が必要になる。
pub fn seed_height(height: u64) -> u64 {
    if height < SEED_EPOCH_BLOCKS + SEED_LAG {
        return 0;
    }
    (height - SEED_LAG) / SEED_EPOCH_BLOCKS * SEED_EPOCH_BLOCKS
}

/// 2 つの高さが同じシードを使うか。
pub fn shares_seed(a: u64, b: u64) -> bool {
    seed_height(a) == seed_height(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_blocks_use_the_genesis_seed() {
        for height in [
            0u64,
            1,
            100,
            SEED_EPOCH_BLOCKS,
            SEED_EPOCH_BLOCKS + SEED_LAG - 1,
        ] {
            assert_eq!(seed_height(height), 0, "高さ {height}");
        }
    }

    #[test]
    fn the_first_switch_happens_at_epoch_plus_lag() {
        assert_eq!(seed_height(SEED_EPOCH_BLOCKS + SEED_LAG - 1), 0);
        assert_eq!(seed_height(SEED_EPOCH_BLOCKS + SEED_LAG), SEED_EPOCH_BLOCKS);
        assert_eq!(seed_height(2_112), 2_048);
    }

    #[test]
    fn the_seed_changes_every_epoch() {
        let mut switches = Vec::new();
        let mut previous = seed_height(0);
        for height in 0..(SEED_EPOCH_BLOCKS * 5) {
            let current = seed_height(height);
            if current != previous {
                switches.push(height);
                previous = current;
            }
        }
        assert_eq!(switches, vec![2_112, 4_160, 6_208, 8_256]);
        for pair in switches.windows(2) {
            assert_eq!(pair[1] - pair[0], SEED_EPOCH_BLOCKS);
        }
    }

    #[test]
    fn the_seed_height_is_always_an_epoch_boundary() {
        for height in (0..20_000).step_by(37) {
            let seed = seed_height(height);
            assert_eq!(seed % SEED_EPOCH_BLOCKS, 0, "高さ {height} → シード {seed}");
            assert!(seed + SEED_LAG <= height || seed == 0);
        }
    }

    #[test]
    fn the_lag_keeps_shallow_reorgs_on_the_same_seed() {
        // 切り替え直後の高さから SEED_LAG ブロック巻き戻しても、
        // シードは同じままである。
        let switch = SEED_EPOCH_BLOCKS + SEED_LAG;
        assert!(shares_seed(switch, switch + SEED_LAG));
        assert!(!shares_seed(switch, switch - 1));
    }

    #[test]
    fn epoch_is_about_34_hours() {
        use oag_consensus::params::TARGET_BLOCK_TIME_SECS;
        let hours = SEED_EPOCH_BLOCKS * TARGET_BLOCK_TIME_SECS / 3_600;
        assert_eq!(hours, 34);
    }
}
