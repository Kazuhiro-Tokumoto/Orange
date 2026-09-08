//! light モードと fast モードが同じハッシュを返すことを確かめる。
//!
//! **これが崩れるとチェーンが割れる。** fast モードで掘ったブロックを
//! light モードのノードが撥ねる、あるいはその逆になる。速さのために
//! モードを分けている以上、一致は仕様であって偶然ではない。
//!
//! データセットの構築に 2 GB と 1 分前後を要するため、この試験は重い。
//! それでも既定で走らせる。走らない試験は無いのと同じである。
//!
//! 速さは測らない。機械によって変わる数字を試験に固定しても意味がない。
//! 手元で測るには `cargo run --release -p oag-pow --features randomx
//! --example hashrate` を使う。

#![cfg(feature = "randomx")]

use oag_consensus::block::BlockHeader;
use oag_consensus::codec::Encode;
use oag_pow::randomx::{RandomXMiner, RandomXVerifier};
use oag_primitives::{hash, Hash};
use std::time::Instant;

fn seed() -> Hash {
    hash::block_hash(b"Orange fast mode agreement")
}

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

#[test]
fn the_two_modes_agree_on_every_hash() {
    // **データセットの構築に 1 分前後かかるため、1 個の試験にまとめてある。**
    // 分けると構築が 2 回走る。
    let light = RandomXVerifier::new(&seed(), 0).expect("light を作れる");

    let started = Instant::now();
    let fast = RandomXMiner::new(&seed(), 0).expect("fast を作れる (2 GB 要る)");
    println!(
        "データセットの構築: {:.1} 秒 ({} バイト)",
        started.elapsed().as_secs_f64(),
        RandomXMiner::dataset_bytes().unwrap_or(0)
    );

    assert_eq!(fast.seed(), light.seed());
    assert_eq!(fast.seed_height(), light.seed_height());

    // ── 一致すること ──
    //
    // 任意のバイト列。空は RandomX が受け付けないので入れない。
    for input in [
        &b"orange"[..],
        b"Orange is good",
        &[0u8; 1][..],
        &[0xffu8; 256][..],
        &[0x5au8; 4096][..],
    ] {
        assert_eq!(
            light.hash(input).unwrap(),
            fast.hash(input).unwrap(),
            "入力 {input:?} で食い違った"
        );
    }

    // 実際に採掘で使う形、つまりヘッダの符号化。
    for nonce in 0..32 {
        let h = header(nonce);
        assert_eq!(
            light.hash_header(&h).unwrap(),
            fast.hash_header(&h).unwrap(),
            "nonce {nonce} で食い違った"
        );
        // 採掘器が触るのは符号化されたバイト列である。そちらも一致すること。
        assert_eq!(
            fast.hash_header(&h).unwrap(),
            fast.hash(&h.encode()).unwrap()
        );
    }
}
