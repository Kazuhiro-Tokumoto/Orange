//! チェーン選択の候補探しにかかる費用を測る。
//!
//! 全件走査から漸進的な索引に変えた効果を確かめる。**2 通りの測り方を
//! する。** 端から端まで通した時間だけを見ると、記憶域の書き込みに
//! 埋もれて何も分からないためである。
//!
//! `cargo run --release -p oag-store --example scan_cost`

use oag_chain::index::{BlockIndex, BlockIndexEntry, BlockStatus};
use oag_chain::scenarios;
use oag_consensus::BlockHeader;
use oag_primitives::{hash, Hash};
use oag_store::Store;
use std::time::Instant;

/// 1 本の鎖を模したインデックスと、その先端の作業量を作る。
fn a_chain(len: u64) -> (BlockIndex, Vec<BlockIndexEntry>) {
    let mut index = BlockIndex::new();
    let mut entries = Vec::with_capacity(len as usize + 1);
    let mut prev = Hash::ZERO;
    for height in 0..=len {
        let header = BlockHeader {
            version: 0,
            prev_hash: prev,
            merkle_root: hash::txid(b"merkle"),
            timestamp: 1_800_000_000 + height as i64 * 60,
            difficulty: 1,
            height,
            nonce: height,
        };
        let entry = BlockIndexEntry {
            hash: header.hash(),
            header,
            cumulative_work: u128::from(height) + 1,
            status: BlockStatus::FullyValid,
        };
        prev = entry.hash;
        index.insert(entry.clone());
        entries.push(entry);
    }
    (index, entries)
}

/// 候補探しだけを測る。
fn candidate_search() {
    println!("── 候補探しだけを測る (1 ブロックあたり) ──");
    println!("{:>10}  {:>14}  {:>14}", "ブロック", "全件走査", "索引");
    for len in [1_000u64, 10_000, 100_000, 400_000] {
        let (index, entries) = a_chain(len);
        let tip_work = entries[entries.len() - 2].cumulative_work;
        let rounds = 200;

        // 旧: 全件を見て、作業量が先端を超えるものを集めて並べ替える。
        // Vec の走査は HashMap より速いので、旧実装に有利な見積もりである。
        let started = Instant::now();
        let mut sink = 0usize;
        for _ in 0..rounds {
            let mut found: Vec<(u128, Hash)> = entries
                .iter()
                .filter(|e| e.is_candidate() && e.cumulative_work > tip_work)
                .map(|e| (e.cumulative_work, e.hash))
                .collect();
            found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
            sink += found.len();
        }
        let full = started.elapsed().as_secs_f64() * 1e6 / rounds as f64;

        // 新: 作業量順の集合の末尾から、先端を超える分だけ見る。
        let started = Instant::now();
        for _ in 0..rounds {
            sink += index.candidates_above(tip_work).count();
        }
        let indexed = started.elapsed().as_secs_f64() * 1e6 / rounds as f64;

        assert!(sink > 0);
        println!("{len:>10}  {full:>11.1} μs  {indexed:>11.3} μs");
    }
}

/// 端から端まで通して測る。
fn end_to_end() {
    println!();
    println!("── 記憶域まで通して測る (1 ブロックあたり) ──");
    println!("{:>10}  {:>14}", "ブロック", "μs/ブロック");
    for count in [1_000usize, 4_000, 8_000] {
        let dir = std::env::temp_dir().join(format!("oag-scan-{count}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(dir.join("chain.redb")).expect("記憶域を開ける");

        let mut chain = scenarios::open(store);
        let genesis = chain.tip().unwrap().hash;
        let started = Instant::now();
        scenarios::extend(&mut chain, genesis, count, 1);
        let per = started.elapsed().as_secs_f64() * 1e6 / count as f64;

        println!("{count:>10}  {per:>11.1} μs");
        drop(chain);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

fn main() {
    candidate_search();
    end_to_end();
}
