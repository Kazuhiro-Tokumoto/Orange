//! RandomX で実際に採掘する試験。
//!
//! feature `randomx` が有効なときにのみ走る。light モードは 1 ハッシュに
//! 数ミリ秒かかるため、難易度は低く抑えてある。

#![cfg(feature = "randomx")]

use oag_consensus::codec::Encode;
use oag_consensus::lock::Lock;
use oag_consensus::utxo::UtxoSet;
use oag_consensus::validate::{validate_block, AcceptAnyPow, BlockContext, HeaderContext};
use oag_mempool::Mempool;
use oag_miner::{build_template, mine, NeverStop, TemplateRequest};
use oag_pow::randomx::RandomXVerifier;
use oag_pow::target::meets_difficulty;
use oag_primitives::{hash, SecretKey};

const HEIGHT: u64 = 10;
const MTP: i64 = 1_800_000_000;
const NOW: i64 = MTP + 3_600;

fn request(difficulty: u64) -> TemplateRequest {
    TemplateRequest {
        prev_hash: hash::block_hash(b"parent"),
        height: HEIGHT,
        difficulty,
        timestamp: NOW,
        payout: Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
        extra_nonce: b"orange".to_vec(),
    }
}

fn verifier() -> RandomXVerifier {
    RandomXVerifier::new(&hash::block_hash(b"orange genesis"), 0).expect("初期化できる")
}

#[test]
fn a_block_mined_with_randomx_passes_validation() {
    // テンプレートを組み、RandomX で掘り、そのまま検証を通す。
    // ここが通れば、採掘から受理までの筋道がひととおり繋がっている。
    let difficulty = 16;
    let template = build_template(&request(difficulty), &Mempool::new()).unwrap();
    let verifier = verifier();

    let outcome = mine(&template, &verifier, 0, 5_000, &NeverStop).unwrap();
    let block = outcome.block().expect("難易度 16 なら見つかるはず");

    // 見つけたブロックが本当に難易度を満たしていること。
    let pow = verifier.hash(&block.header.encode()).unwrap();
    assert!(
        meets_difficulty(&pow, difficulty).unwrap(),
        "難易度を満たしていない"
    );

    // 検証器を通すこと。
    assert!(
        verifier.check(&block.header).unwrap(),
        "RandomXVerifier が自分で掘ったブロックを認めない"
    );

    // コンセンサスの検証も通ること。
    let utxo = UtxoSet::new();
    let ctx = BlockContext {
        header: HeaderContext {
            expected_height: HEIGHT,
            expected_prev_hash: hash::block_hash(b"parent"),
            median_time_past: MTP,
            expected_difficulty: difficulty,
            now: NOW,
        },
        utxo: &utxo,
    };
    validate_block(&block, &ctx, &AcceptAnyPow).expect("組み立てたブロックが検証を通らない");
}

#[test]
fn changing_the_nonce_changes_the_randomx_hash() {
    let template = build_template(&request(1_000_000), &Mempool::new()).unwrap();
    let verifier = verifier();

    let mut a = template.clone();
    a.header.nonce = 1;
    let mut b = template;
    b.header.nonce = 2;

    assert_ne!(
        verifier.hash(&a.hash_input()).unwrap(),
        verifier.hash(&b.hash_input()).unwrap()
    );
}

#[test]
fn an_impossible_difficulty_exhausts_the_range() {
    let template = build_template(&request(u64::MAX), &Mempool::new()).unwrap();
    let verifier = verifier();
    let outcome = mine(&template, &verifier, 0, 20, &NeverStop).unwrap();
    assert!(outcome.block().is_none());
}
