//! 先端の候補が、鎖の長さに比例して増えないこと。
//!
//! `with_body` と `valid_headers` は作業量順の集合であり、入れたものを
//! 捨てないとブロック 1 個につき 48 バイトの鍵を 2 つ積み続ける。60 秒
//! 間隔では年 52 万ブロックなので、常駐量が高さに比例して伸びる
//! (`docs/SPEC.md` §19)。
//!
//! 先端の作業量は決して減らないので、そこを下回るものは二度と候補に
//! ならない。落としてよい。

use oag_chain::chain::HeaderOutcome;
use oag_chain::scenarios::{build_on, extend, genesis, open, NOW};
use oag_chain::store::MemoryStore;
use oag_consensus::validate::AcceptAnyPow;

// ━━━━━━━━ 伸びても増えないこと ━━━━━━━━

#[test]
fn a_straight_chain_keeps_exactly_one_candidate() {
    let mut chain = open(MemoryStore::new());
    let mut tip = genesis().header.hash();

    for expected_height in 1..=200u64 {
        tip = *extend(&mut chain, tip, 1, expected_height).last().unwrap();
        assert_eq!(chain.height().unwrap(), expected_height);
        assert_eq!(
            chain.tip_candidates(),
            2,
            "candidates grew at height {expected_height}"
        );
    }
}

#[test]
fn the_count_does_not_follow_the_height() {
    let mut chain = open(MemoryStore::new());
    let genesis_hash = genesis().header.hash();

    extend(&mut chain, genesis_hash, 10, 1);
    let at_10 = chain.tip_candidates();
    let tip = chain.tip().unwrap().hash;

    extend(&mut chain, tip, 500, 2);
    let at_510 = chain.tip_candidates();

    assert_eq!(chain.height().unwrap(), 510);
    assert_eq!(
        at_10, at_510,
        "the number of candidates changed at 51 times the height"
    );
}

// ━━━━━━━━ 落としても判断が変わらないこと ━━━━━━━━

#[test]
fn a_losing_branch_can_still_overtake_later() {
    let mut chain = open(MemoryStore::new());
    let fork = genesis().header.hash();

    // 先に A を 5 個積む。これが先端になる。
    let a = extend(&mut chain, fork, 5, 1);
    assert_eq!(chain.tip().unwrap().hash, a[4]);

    // B を 3 個積む。作業量で負けるので先端は動かない。
    // **この 3 個は先端を下回るので、候補の集合から落ちる。**
    let b = extend(&mut chain, fork, 3, 2);
    assert_eq!(chain.tip().unwrap().hash, a[4], "A is still the tip");

    // B をさらに伸ばして追い越させる。落としたあとでも追い越せること。
    let b = extend(&mut chain, b[2], 4, 3);
    assert_eq!(chain.tip().unwrap().hash, b[3], "it switches to B");
    assert_eq!(chain.height().unwrap(), 7);
}

#[test]
fn the_best_header_is_unchanged_by_pruning() {
    let mut chain = open(MemoryStore::new());
    let mut parent = genesis().header.hash();

    // 本体を繋ぎながら 50 個。
    parent = *extend(&mut chain, parent, 50, 1).last().unwrap();

    // その先にヘッダだけ 20 個。先端は動かないが、最良ヘッダは進む。
    let mut header_tip = parent;
    for i in 0..20u64 {
        let block = build_on(&chain, header_tip, 900_000 + i);
        header_tip = block.header.hash();
        assert_eq!(
            chain
                .accept_header(&block.header, &AcceptAnyPow, NOW)
                .unwrap(),
            HeaderOutcome::New
        );
    }

    assert_eq!(
        chain.tip().unwrap().height(),
        50,
        "the tip with bodies is 50"
    );
    assert_eq!(
        chain.best_header().unwrap().height(),
        70,
        "headers are at 70"
    );
    assert_eq!(chain.best_header().unwrap().hash, header_tip);
}

#[test]
fn reopening_does_not_bring_the_dropped_keys_back() {
    let store = MemoryStore::new();
    let mut chain = open(store);
    extend(&mut chain, genesis().header.hash(), 100, 1);
    let before = chain.tip_candidates();
    let height = chain.height().unwrap();

    // 記憶域を引き継いで開き直す。全件を読み込むが、そのあと落とす。
    let store = chain.into_store();
    let chain = open(store);

    assert_eq!(chain.height().unwrap(), height);
    assert_eq!(
        chain.tip_candidates(),
        before,
        "it hoards them when reopened"
    );
}
