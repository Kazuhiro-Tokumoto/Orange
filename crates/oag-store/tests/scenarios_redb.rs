//! 永続化記憶域に対する、チェーンの試験手順。
//!
//! `oag-chain` のメモリ実装に対して走らせているのと **同一の手順**を、
//! redb を背後に置いた実装に対して走らせる。リオーグは最もバグりやすい
//! 箇所であり、記憶域ごとに別のテストを書くと片方でしか通らない実装が
//! できてしまう。

use oag_chain::scenarios;
use oag_store::Store;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// テストごとに独立した一時ディレクトリ。作りっぱなしにせず片付ける。
struct TempStore {
    dir: std::path::PathBuf,
}

impl TempStore {
    fn new() -> (TempStore, Store) {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("oag-scn-{}-{n}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(dir.join("chain.redb")).unwrap();
        (TempStore { dir }, store)
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

macro_rules! scenario {
    ($name:ident) => {
        #[test]
        fn $name() {
            let (_guard, store) = TempStore::new();
            scenarios::$name(store);
        }
    };
    ($name:ident, two) => {
        #[test]
        fn $name() {
            let (_a, first) = TempStore::new();
            let (_b, second) = TempStore::new();
            scenarios::$name(first, second);
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

// headers-first 同期
scenario!(headers_alone_do_not_move_the_tip);
scenario!(a_known_header_is_not_added_twice);
scenario!(bodies_arriving_out_of_order_wait_for_their_parents);
scenario!(missing_bodies_are_listed_oldest_first);
scenario!(headers_are_served_from_the_fork_point);
scenario!(a_header_for_an_invalid_block_is_refused);
