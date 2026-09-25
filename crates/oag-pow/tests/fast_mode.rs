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
use oag_pow::randomx::{RandomXMiner, RandomXVerifier, SharedDataset};
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
    let light = RandomXVerifier::new(&seed(), 0).expect("light can be created");

    let started = Instant::now();
    let shared = SharedDataset::new(&seed(), 0).expect("fast can be created (needs 2 GB)");
    println!(
        "building the dataset: {:.1} s ({} bytes, large pages: {})",
        started.elapsed().as_secs_f64(),
        RandomXMiner::dataset_bytes().unwrap_or(0),
        shared.uses_large_pages()
    );
    let fast = shared.miner().expect("a VM can be created on the dataset");
    assert_eq!(fast.uses_large_pages(), shared.uses_large_pages());

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
            "disagreed on input {input:?}"
        );
    }

    // 実際に採掘で使う形、つまりヘッダの符号化。
    for nonce in 0..32 {
        let h = header(nonce);
        assert_eq!(
            light.hash_header(&h).unwrap(),
            fast.hash_header(&h).unwrap(),
            "disagreed at nonce {nonce}"
        );
        // 採掘器が触るのは符号化されたバイト列である。そちらも一致すること。
        assert_eq!(
            fast.hash_header(&h).unwrap(),
            fast.hash(&h.encode()).unwrap()
        );
    }

    // ── 1 本のデータセットを、別々のスレッドから同時に使う ──
    //
    // 採掘はこの形で動く。スレッドごとに VM を建て、データセットは
    // 共有する。どのスレッドも light と同じハッシュを返すこと。
    let want: Vec<_> = (0..16)
        .map(|n| light.hash_header(&header(n)).unwrap())
        .collect();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..3)
            .map(|_| {
                let shared = shared.clone();
                scope.spawn(move || {
                    let miner = shared.miner().expect("each thread builds its own VM");
                    (0..16)
                        .map(|n| miner.hash_header(&header(n)).unwrap())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for worker in workers {
            assert_eq!(
                worker.join().unwrap(),
                want,
                "a thread disagreed with light mode"
            );
        }
    });

    // 呼び出し元の分を先に捨てても、スレッドの側が持っている限り
    // データセットは生きている。最後の 1 つが消えたときに解放される。
    let miner = std::thread::spawn({
        let shared = shared.clone();
        move || shared.miner().map(|m| m.hash(b"orange").unwrap())
    });
    drop(fast);
    drop(shared);
    assert_eq!(
        miner.join().unwrap().unwrap(),
        light.hash(b"orange").unwrap()
    );
}
