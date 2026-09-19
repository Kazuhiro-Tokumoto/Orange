//! 本体がまだ 1 つも届いていない時期に、祖先のハッシュを引けること。
//!
//! RandomX のシードは [`seed_height`](oag_pow::seed_height) が示す高さの
//! ブロックハッシュである (`docs/SPEC.md` §11.3)。headers-first の同期では、
//! ヘッダが高さ数千まで届いていても本体が 1 つも繋がっていない時期があり、
//! そのあいだアクティブチェーンの高さは 0 のままである。
//!
//! そこで**アクティブチェーンの高さの索引**を引くと、知っているはずの
//! シードにも `None` が返る。mainnet では最初のエポック境界 (高さ 2112) で
//! 同期が止まった。

use oag_chain::chain::HeaderOutcome;
use oag_chain::scenarios::{build_on, extend, genesis, open, NOW};
use oag_chain::store::MemoryStore;
use oag_consensus::validate::AcceptAnyPow;
use oag_primitives::Hash;

/// ヘッダだけを `count` 個積む。**本体は渡さない。**
fn extend_headers(
    chain: &mut oag_chain::Chain<MemoryStore>,
    mut parent: Hash,
    count: usize,
    salt: u64,
) -> Vec<Hash> {
    let mut hashes = Vec::with_capacity(count);
    for i in 0..count {
        let block = build_on(chain, parent, salt * 1_000_000 + i as u64);
        parent = block.header.hash();
        assert_eq!(
            chain
                .accept_header(&block.header, &AcceptAnyPow, NOW)
                .expect("有効なヘッダ"),
            HeaderOutcome::New
        );
        hashes.push(parent);
    }
    hashes
}

// ━━━━━━━━ 本体が無い時期 ━━━━━━━━

#[test]
fn the_active_index_cannot_answer_while_only_headers_are_known() {
    let mut chain = open(MemoryStore::new());
    let headers = extend_headers(&mut chain, genesis().header.hash(), 100, 1);

    // ヘッダは 100 個入っているが、先端は動いていない。
    assert_eq!(chain.tip().unwrap().height(), 0);
    assert_eq!(chain.indexed_blocks(), 101);

    // アクティブチェーンの索引には、ジェネシスしか入っていない。
    assert_eq!(chain.hash_at_height(64).unwrap(), None);

    // 祖先を辿るほうは引ける。**これが無いとシードを決められない。**
    assert_eq!(
        chain.ancestor_hash_at(&headers[99], 64).unwrap(),
        Some(headers[63])
    );
}

#[test]
fn the_ancestor_of_a_header_is_found_at_every_depth() {
    let mut chain = open(MemoryStore::new());
    let genesis_hash = genesis().header.hash();
    let headers = extend_headers(&mut chain, genesis_hash, 50, 2);

    assert_eq!(
        chain.ancestor_hash_at(&headers[49], 0).unwrap(),
        Some(genesis_hash)
    );
    for (i, hash) in headers.iter().enumerate() {
        let height = i as u64 + 1;
        assert_eq!(
            chain.ancestor_hash_at(&headers[49], height).unwrap(),
            Some(*hash)
        );
    }
}

#[test]
fn asking_above_the_branch_tip_finds_nothing() {
    let mut chain = open(MemoryStore::new());
    let headers = extend_headers(&mut chain, genesis().header.hash(), 10, 3);
    assert_eq!(chain.ancestor_hash_at(&headers[9], 11).unwrap(), None);
    assert_eq!(
        chain
            .ancestor_hash_at(&Hash::from_bytes([9; 32]), 1)
            .unwrap(),
        None
    );
}

// ━━━━━━━━ 枝が分かれているとき ━━━━━━━━

#[test]
fn each_branch_answers_with_its_own_ancestor() {
    let mut chain = open(MemoryStore::new());
    let fork = genesis().header.hash();
    let a = extend_headers(&mut chain, fork, 20, 4);
    let b = extend_headers(&mut chain, fork, 20, 5);

    // 同じ高さで別のブロックである。
    assert_ne!(a[9], b[9]);

    // 高さだけで引くと取り違える。枝を指定すれば取り違えない。
    assert_eq!(chain.ancestor_hash_at(&a[19], 10).unwrap(), Some(a[9]));
    assert_eq!(chain.ancestor_hash_at(&b[19], 10).unwrap(), Some(b[9]));
}

// ━━━━━━━━ 本体が繋がっている時期 ━━━━━━━━

#[test]
fn a_connected_chain_gives_the_same_answer_as_the_active_index() {
    let mut chain = open(MemoryStore::new());
    let blocks = extend(&mut chain, genesis().header.hash(), 30, 6);

    assert_eq!(chain.tip().unwrap().height(), 30);
    for height in 0..=30u64 {
        assert_eq!(
            chain.ancestor_hash_at(&blocks[29], height).unwrap(),
            chain.hash_at_height(height).unwrap(),
            "高さ {height}"
        );
    }
}
