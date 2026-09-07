//! メモリ記憶域に対する、チェーンの試験手順。
//!
//! 同じ手順を永続化実装に対しても走らせている
//! (`oag-store/tests/scenarios_redb.rs`)。片方でしか通らない実装を
//! 作らないため。

use oag_chain::scenarios;
use oag_chain::MemoryStore;

macro_rules! scenario {
    ($name:ident) => {
        #[test]
        fn $name() {
            scenarios::$name(MemoryStore::new());
        }
    };
    ($name:ident, two) => {
        #[test]
        fn $name() {
            scenarios::$name(MemoryStore::new(), MemoryStore::new());
        }
    };
}

scenario!(starts_at_genesis);
scenario!(extends_the_tip);
scenario!(rejects_duplicates);
scenario!(rejects_orphans);
scenario!(shorter_branch_stays_a_side_chain);
scenario!(a_heavier_branch_triggers_a_reorg);
scenario!(an_invalid_block_in_a_heavier_branch_is_contained);
scenario!(children_of_an_invalid_block_are_rejected);
scenario!(the_difficulty_is_fixed_until_the_window_is_full);
scenario!(median_time_past_follows_the_chain);
scenario!(a_reorg_matches_a_direct_build, two);
scenario!(a_deep_reorg_stays_consistent, two);
