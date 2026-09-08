//! RandomX のハッシュレートを実測する。
//!
//! ジェネシス難易度は「1 コアでおよそ 1,000 H/s」という仮定の上に
//! 置かれている (SPEC §14.3)。**仮定のままにしておくと、公開直後の
//! ブロック間隔が目標の 60 秒から大きく外れる。** 実測して置き換える。
//!
//! `cargo run --release -p oag-pow --example hashrate`

use oag_consensus::BlockHeader;
use oag_pow::randomx::RandomXVerifier;
use oag_primitives::hash;
use std::time::Instant;

fn main() {
    let seed = hash::block_hash(b"Orange hashrate measurement");

    println!(
        "RandomX のフラグ: {:?}",
        randomx_rs::RandomXFlag::get_recommended_flags()
    );

    let started = Instant::now();
    let verifier = RandomXVerifier::new(&seed, 0).expect("検証器を作れる");
    println!(
        "初期化 (light, 256 MB): {:.2} 秒",
        started.elapsed().as_secs_f64()
    );

    let mut header = BlockHeader {
        version: 0,
        prev_hash: seed,
        merkle_root: hash::txid(b"merkle"),
        timestamp: 1_800_000_000,
        difficulty: 1,
        height: 1,
        nonce: 0,
    };

    // 暖機。最初の数回は分岐予測もキャッシュも冷えている。
    for nonce in 0..64 {
        header.nonce = nonce;
        verifier.hash_header(&header).unwrap();
    }

    let rounds = 2_000u64;
    let started = Instant::now();
    for nonce in 0..rounds {
        header.nonce = nonce;
        std::hint::black_box(verifier.hash_header(&header).unwrap());
    }
    let elapsed = started.elapsed().as_secs_f64();
    let rate = rounds as f64 / elapsed;

    println!("1 コア (light モード): {rate:.0} H/s");
    println!();
    println!("── 難易度と、1 コアでのブロック間隔 ──");
    for difficulty in [1u64, 100, 1_000, 10_000, 100_000] {
        println!(
            "  難易度 {difficulty:>7}: {:>10.1} 秒",
            difficulty as f64 / rate
        );
    }
    println!();
    println!("目標 60 秒に合う難易度 (1 コア): {:.0}", rate * 60.0);
}
