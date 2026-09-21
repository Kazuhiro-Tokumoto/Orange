//! インデックスの常駐量が、鎖の長さに比例しないこと。
//!
//! `BlockIndex` は以前、知っているブロックを 1 件も捨てずに抱えていた。
//! 1 件あたり 500 バイト前後で、60 秒間隔では年 52 万ブロック積まれる。
//! 10 年で 2.5 GB、20 年で 5 GB になる (`docs/SPEC.md` §19)。
//!
//! いま常駐するのは 2 つだけである。
//!
//! - **先端の候補** — 競合する枝の数で決まる。鎖の長さによらない
//! - **最近引いたものの控え** — 上限で頭打ちになる
//!
//! 実体の正本は記憶域にある。**控えから落ちても、聞き直せば同じ答えが
//! 返る。** ここで確かめるのはその 2 点である。

use oag_chain::chain::Retarget;
use oag_chain::scenarios::{entry_of, extend, genesis, DIFFICULTY};
use oag_chain::store::MemoryStore;
use oag_chain::{BlockStatus, Chain};

/// 控えの上限を小さくして開く。**追い出しを実際に起こすため。**
fn open_small(store: MemoryStore) -> Chain<MemoryStore> {
    Chain::open_with_cache(store, genesis(), DIFFICULTY, Retarget::Enabled, 8)
        .expect("can be opened")
}

const LEN: u64 = 150;

// ━━━━━━━━ 頭打ちになること ━━━━━━━━

#[test]
fn neither_the_candidates_nor_the_cache_follow_the_height() {
    let mut chain = open_small(MemoryStore::new());
    let mut tip = genesis().header.hash();

    for height in 1..=LEN {
        tip = *extend(&mut chain, tip, 1, height).last().unwrap();
        assert_eq!(
            chain.tip_candidates(),
            2,
            "candidates grew at height {height}"
        );
        assert!(
            chain.cached_entries() <= 8,
            "the cache exceeded its bound at height {height} ({} entries)",
            chain.cached_entries()
        );
    }
    assert_eq!(chain.height().unwrap(), LEN);
    // 知っているブロック数は伸びている。伸びていないのは常駐量のほうである。
    assert_eq!(chain.indexed_blocks().unwrap(), LEN + 1);
}

// ━━━━━━━━ 落ちても答えが変わらないこと ━━━━━━━━

#[test]
fn every_ancestor_is_still_reachable_after_eviction() {
    let mut chain = open_small(MemoryStore::new());
    let genesis_hash = genesis().header.hash();
    let blocks = extend(&mut chain, genesis_hash, LEN as usize, 1);
    let tip = *blocks.last().unwrap();

    // 控えは 8 件しかないので、ほとんどは記憶域から引き直すことになる。
    assert!(chain.cached_entries() <= 8);

    assert_eq!(
        chain.ancestor_hash_at(&tip, 0).unwrap(),
        Some(genesis_hash),
        "cannot be traced back to genesis"
    );
    for (i, hash) in blocks.iter().enumerate() {
        let height = i as u64 + 1;
        assert_eq!(
            chain.ancestor_hash_at(&tip, height).unwrap(),
            Some(*hash),
            "the ancestor at height {height} cannot be looked up"
        );
        assert_eq!(entry_of(&chain, hash).height(), height);
        assert_eq!(entry_of(&chain, hash).status, BlockStatus::FullyValid);
    }
}

#[test]
fn a_cold_cache_gives_the_same_answers() {
    let mut chain = open_small(MemoryStore::new());
    let blocks = extend(&mut chain, genesis().header.hash(), LEN as usize, 1);

    let best = chain.best_header().unwrap();
    let headers = chain.headers_after(&[blocks[9]], &oag_primitives::Hash::ZERO, 20);
    let locator: Vec<_> = chain.header_hashes_at(&[0, 50, LEN]).unwrap();

    // 控えを空にして開き直す。答えが変わってはならない。
    let store = chain.into_store();
    let chain = open_small(store);
    assert_eq!(chain.cached_entries(), 0, "holding it right after opening");

    assert_eq!(chain.best_header().unwrap().hash, best.hash);
    assert_eq!(
        chain
            .headers_after(&[blocks[9]], &oag_primitives::Hash::ZERO, 20)
            .unwrap()
            .len(),
        headers.unwrap().len()
    );
    assert_eq!(chain.header_hashes_at(&[0, 50, LEN]).unwrap(), locator);
    assert_eq!(chain.height().unwrap(), LEN);
}

#[test]
fn the_chain_keeps_growing_after_reopening() {
    let mut chain = open_small(MemoryStore::new());
    extend(&mut chain, genesis().header.hash(), LEN as usize, 1);

    let store = chain.into_store();
    let mut chain = open_small(store);
    let tip = chain.tip().unwrap().hash;

    extend(&mut chain, tip, 20, 2);
    assert_eq!(chain.height().unwrap(), LEN + 20);
    assert_eq!(chain.tip_candidates(), 2);
    assert!(chain.cached_entries() <= 8);
}

// ━━━━━━━━ 控えが小さくてもリオーグできること ━━━━━━━━

#[test]
fn a_reorg_works_with_almost_no_cache() {
    let mut chain = Chain::open_with_cache(
        MemoryStore::new(),
        genesis(),
        DIFFICULTY,
        Retarget::Enabled,
        1,
    )
    .expect("can be opened");
    let fork = genesis().header.hash();

    let a = extend(&mut chain, fork, 20, 1);
    assert_eq!(chain.tip().unwrap().hash, *a.last().unwrap());

    // 分岐点から 25 個積んで追い越す。控えは 1 件しか持てない。
    let b = extend(&mut chain, fork, 25, 2);
    assert_eq!(
        chain.tip().unwrap().hash,
        *b.last().unwrap(),
        "it does not switch"
    );
    assert_eq!(chain.height().unwrap(), 25);

    // 負けた枝はアクティブチェーンから外れている。**無効ではない。**
    // 検証は通っているので、印は付かない。
    for (i, hash) in a.iter().enumerate() {
        let height = i as u64 + 1;
        assert_ne!(entry_of(&chain, hash).status, BlockStatus::Invalid);
        assert_ne!(
            chain.hash_at_height(height).unwrap(),
            Some(*hash),
            "the losing branch is still at height {height}"
        );
    }
}
