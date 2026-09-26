//! シードのエポックをまたいでブロックをまとめて繋いでも、正しいブロックに
//! 無効の印が付かないこと。
//!
//! # 0.1.1 までに起きたこと
//!
//! ノードは RandomX の検証器を 1 つだけ持ち、**受け取ったブロックの**高さに
//! 合わせて組む。初期同期でブロックの本体が順不同に届くと、欠けていた 1 個が
//! 届いた時点で、待っていた子孫をまとめて繋ぐ。その子孫がシードの次の
//! エポックに入っていると、前のエポックの検証器で PoW を確かめ直すことに
//! なり、必ず落ちる。正しいブロックとその子孫すべてに無効の印が付き、印は
//! 永続化されるので、ノードは二度と正しいチェーンへ戻れなくなった。
//!
//! 本番の VPS で、高さ 2112 を過ぎたところでこれが起きた。
//!
//! ここでは、自分のエポックのヘッダしか通さない検証器 ([`OneEpoch`]) で
//! その状況を再現する。本物の RandomX 検証器も、エポックが合わなければ
//! 「PoW を満たさない」と答える。

use oag_chain::chain::HeaderOutcome;
use oag_chain::scenarios::{build_on, entry_of, open, NOW};
use oag_chain::{AcceptOutcome, BlockStatus, Chain, ChainStore, MemoryStore};
use oag_consensus::params::{SEED_EPOCH_BLOCKS, SEED_LAG};
use oag_consensus::validate::{AcceptAnyPow, PowVerifier};
use oag_consensus::{Block, BlockHeader};
use oag_pow::seed_height;

/// 1 つのエポックのヘッダだけを通す検証器。
///
/// ノードの RandomX 検証器と同じ振る舞いである。組んだときのシードと
/// ヘッダが求めるシードが違えば、PoW は合わない。
struct OneEpoch(u64);

impl PowVerifier for OneEpoch {
    fn verify(&self, header: &BlockHeader) -> bool {
        seed_height(header.height) == self.0
    }
}

/// そのブロック自身のエポックの検証器。ノードが `accept_block` の前に
/// 組むものと同じである。
fn verifier_for(block: &Block) -> OneEpoch {
    OneEpoch(seed_height(block.header.height))
}

/// 最初のシード切り替え (高さ 2112) を越えるまでのブロックを作る。
///
/// 作るには親の難易度が要るので、別のチェーンに積みながら作る。
fn blocks_past_the_first_switch(extra: u64) -> Vec<Block> {
    let last = SEED_EPOCH_BLOCKS + SEED_LAG + extra;
    let mut source = open(MemoryStore::new());
    let mut parent = source.tip().unwrap().hash;
    let mut blocks = Vec::with_capacity(last as usize);
    for height in 1..=last {
        let block = build_on(&source, parent, height);
        parent = block.header.hash();
        source
            .accept_block(block.clone(), &AcceptAnyPow, NOW)
            .expect("a valid block");
        blocks.push(block);
    }
    blocks
}

/// ヘッダを全部渡してから、本体を `order` の順に渡す。検証器は毎回、
/// 渡すブロック自身のエポックのものにする。
fn sync_in_order(
    chain: &mut Chain<MemoryStore>,
    blocks: &[Block],
    order: &[usize],
) -> Vec<AcceptOutcome> {
    for block in blocks {
        assert_eq!(
            chain
                .accept_header(&block.header, &verifier_for(block), NOW)
                .expect("every header passes with its own epoch"),
            HeaderOutcome::New
        );
    }
    order
        .iter()
        .map(|&i| {
            let block = &blocks[i];
            chain
                .accept_block(block.clone(), &verifier_for(block), NOW)
                .unwrap_or_else(|e| {
                    panic!("the body at height {} failed: {e}", block.header.height)
                })
        })
        .collect()
}

#[test]
fn a_batch_that_crosses_the_seed_switch_connects() {
    let blocks = blocks_past_the_first_switch(8);
    let switch = (SEED_EPOCH_BLOCKS + SEED_LAG) as usize; // 高さ 2112
    let last_before = switch - 1; // 高さ 2111。blocks[i] は高さ i + 1

    // 2110 までは順に渡す。2111 だけを遅らせ、先に 2112 以降を渡す。
    // 最後に 2111 が届いた時点で、2111 から先端までをまとめて繋ぐ。
    let mut order: Vec<usize> = (0..last_before - 1).collect();
    order.extend(last_before..blocks.len());
    order.push(last_before - 1);

    let mut chain = open(MemoryStore::new());
    let outcomes = sync_in_order(&mut chain, &blocks, &order);

    // 最後の 1 個で、エポックをまたぐ 10 個がまとめて繋がる。
    match outcomes.last().expect("some bodies were given") {
        AcceptOutcome::Reorganized(reorg) => {
            assert!(reorg.disconnected.is_empty());
            assert_eq!(reorg.connected.len(), blocks.len() - (last_before - 1));
        }
        other => panic!("the last body did not connect the batch: {other:?}"),
    }

    let tip = chain.tip().unwrap();
    assert_eq!(tip.hash, blocks.last().unwrap().header.hash());
    for block in &blocks[last_before..] {
        let entry = entry_of(&chain, &block.header.hash());
        assert_eq!(
            entry.status,
            BlockStatus::FullyValid,
            "the block at height {} was not connected",
            block.header.height
        );
    }
}

#[test]
fn bodies_in_order_across_the_switch_connect() {
    // 対照として、順に届けば 0.1.1 でも通っていたことを確かめる。
    let blocks = blocks_past_the_first_switch(8);
    let order: Vec<usize> = (0..blocks.len()).collect();

    let mut chain = open(MemoryStore::new());
    sync_in_order(&mut chain, &blocks, &order);
    assert_eq!(
        chain.tip().unwrap().hash,
        blocks.last().unwrap().header.hash()
    );
}

// ━━━━━━━━ すでに付いてしまった印 ━━━━━━━━

#[test]
fn reconsidering_clears_marks_left_by_the_old_version() {
    // 0.1.1 で同期して止まったノードの記憶域を作る。正しいブロックの
    // 本体を持ったまま、高さ 4 から先に無効の印が付いている。
    let mut chain = open(MemoryStore::new());
    let genesis = chain.tip().unwrap().hash;
    let mut hashes = Vec::new();
    let mut parent = genesis;
    for salt in 1..=6 {
        let block = build_on(&chain, parent, salt);
        parent = block.header.hash();
        chain.accept_block(block, &AcceptAnyPow, NOW).unwrap();
        hashes.push(parent);
    }
    let store = chain.into_store();
    // 高さ 4〜6 を先端から外し、印を付ける。
    for _ in 0..3 {
        store.disconnect_tip().unwrap();
    }
    for hash in &hashes[3..] {
        let mut entry = store.index_entry(hash).unwrap().unwrap();
        entry.status = BlockStatus::Invalid;
        store.put_index_entry(&entry).unwrap();
    }

    // 新しい版で開き直す。開いただけでは先端は 3 のまま。
    let mut chain = open(store);
    assert_eq!(chain.tip().unwrap().hash, hashes[2]);

    assert_eq!(chain.reconsider_invalid(NOW).unwrap(), 3);
    assert_eq!(chain.tip().unwrap().hash, hashes[5]);
    for hash in &hashes {
        assert_eq!(entry_of(&chain, hash).status, BlockStatus::FullyValid);
    }

    // 印が無ければ何もしない。
    assert_eq!(chain.reconsider_invalid(NOW).unwrap(), 0);
}

#[test]
fn reconsidering_a_truly_invalid_block_marks_it_again() {
    // 本当に無効なブロック (高さに合わない報酬) は、見直しても繋がらず、
    // また印が付く。正しいチェーンの先端は動かない。
    let mut chain = open(MemoryStore::new());
    let genesis = chain.tip().unwrap().hash;
    let good = build_on(&chain, genesis, 1);
    let good_hash = good.header.hash();
    chain.accept_block(good, &AcceptAnyPow, NOW).unwrap();

    let mut bad = build_on(&chain, good_hash, 2);
    bad.transactions[0].outputs[0].amount = bad.transactions[0].outputs[0]
        .amount
        .checked_add(oag_primitives::Amount::from_atomic(1).unwrap())
        .unwrap();
    bad.header.merkle_root =
        oag_primitives::merkle::merkle_root(&[bad.transactions[0].txid()]).unwrap();
    let bad_hash = bad.header.hash();
    // 繋ごうとして落ち、印が付く。結果が誤りか側枝かは問わない。
    let _ = chain.accept_block(bad, &AcceptAnyPow, NOW);
    assert_eq!(entry_of(&chain, &bad_hash).status, BlockStatus::Invalid);

    assert_eq!(chain.reconsider_invalid(NOW).unwrap(), 1);
    assert_eq!(entry_of(&chain, &bad_hash).status, BlockStatus::Invalid);
    assert_eq!(chain.tip().unwrap().hash, good_hash);
}
