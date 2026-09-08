//! RandomX のハッシュレートを実機で測る。
//!
//! ```sh
//! cargo run --release -p oag-pow --features randomx --example hashrate
//! ```
//!
//! light モードだけを測るなら `--light`。fast モードはデータセットの
//! 構築に 2 GB と 1 分前後を要する。
//!
//! ここで出た数字は、ジェネシス難易度 (SPEC §14.3) が妥当かを見直す
//! 根拠になる。

use oag_consensus::BlockHeader;
use oag_pow::randomx::{RandomXMiner, RandomXVerifier};
use oag_primitives::hash;
use std::time::Instant;

/// 測る回数。1 ハッシュが数十ミリ秒かかるので、多くすると待たされる。
const ROUNDS: u64 = 300;
/// 暖機の回数。
const WARMUP: u64 = 16;

fn header(nonce: u64) -> BlockHeader {
    BlockHeader {
        version: 0,
        prev_hash: hash::block_hash(b"parent"),
        merkle_root: hash::txid(b"merkle"),
        timestamp: 1_788_220_800,
        difficulty: 1_000,
        height: 10,
        nonce,
    }
}

/// `hash` を ROUNDS 回呼び、1 秒あたりの回数を返す。
fn measure(mut hash: impl FnMut(&BlockHeader)) -> f64 {
    for nonce in 0..WARMUP {
        hash(&header(nonce));
    }
    let started = Instant::now();
    for nonce in 0..ROUNDS {
        hash(&header(nonce));
    }
    ROUNDS as f64 / started.elapsed().as_secs_f64()
}

fn main() {
    let light_only = std::env::args().any(|a| a == "--light");
    let seed = hash::block_hash(b"Orange hashrate measurement");

    println!(
        "RandomX のフラグ: {:?}",
        randomx_rs::RandomXFlag::get_recommended_flags()
    );
    println!();

    let started = Instant::now();
    let light = RandomXVerifier::new(&seed, 0).expect("light を作れる");
    println!(
        "light の初期化 (256 MB): {:.1} 秒",
        started.elapsed().as_secs_f64()
    );
    let light_rate = measure(|h| {
        std::hint::black_box(light.hash_header(h).unwrap());
    });
    println!("light: {light_rate:.0} H/s");

    let fast_rate = if light_only {
        None
    } else {
        println!();
        println!("fast のデータセットを構築する (2 GB、1 分前後かかる)…");
        let started = Instant::now();
        match RandomXMiner::new(&seed, 0) {
            Ok(fast) => {
                println!(
                    "fast の初期化: {:.1} 秒 ({} バイト)",
                    started.elapsed().as_secs_f64(),
                    RandomXMiner::dataset_bytes().unwrap_or(0)
                );
                let rate = measure(|h| {
                    std::hint::black_box(fast.hash_header(h).unwrap());
                });
                println!("fast:  {rate:.0} H/s ({:.1} 倍)", rate / light_rate);
                Some(rate)
            }
            Err(e) => {
                println!("fast を用意できない: {e}");
                None
            }
        }
    };

    let rate = fast_rate.unwrap_or(light_rate);
    println!();
    println!("── 難易度と、この 1 コアでのブロック間隔 ──");
    for difficulty in [1u64, 10, 100, 1_000, 10_000, 100_000] {
        println!(
            "  難易度 {difficulty:>7}: {:>9.1} 秒",
            difficulty as f64 / rate
        );
    }
    println!();
    println!("目標 60 秒に合う難易度 (この 1 コア): {:.0}", rate * 60.0);
    println!("mainnet のジェネシス難易度は 1,000、testnet は 10 である。");
}
