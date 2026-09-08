//! 記憶域によらず走らせる試験手順。
//!
//! リオーグは最もバグりやすい箇所であり、記憶域ごとに別のテストを書くと
//! 片方でしか通らない実装ができてしまう。ここに手順を一本化し、
//! メモリ実装と永続化実装の双方に対して同じものを走らせる。
//!

use crate::chain::{AcceptOutcome, Chain, ChainError, HeaderOutcome};
use crate::genesis::GenesisSpec;
use crate::index::BlockStatus;
use crate::store::ChainStore;
use oag_consensus::lock::Lock;
use oag_consensus::tx::{encode_coinbase_signature, OutPoint, TxInput, CURRENT_TX_VERSION};
use oag_consensus::utxo::UtxoView;
use oag_consensus::validate::AcceptAnyPow;
use oag_consensus::{Block, BlockHeader, Transaction, TxOutput};
use oag_primitives::{merkle, Amount, Hash, Network, SecretKey};

/// 試験で用いる「現在時刻」。
pub const NOW: i64 = 3_000_000_000;
/// ジェネシスのタイムスタンプ。
pub const GENESIS_TIME: i64 = 1_800_000_000;
/// 試験で用いる難易度。
pub const DIFFICULTY: u64 = 1;

/// 試験用のジェネシスブロック。
pub fn genesis() -> Block {
    GenesisSpec::without_reward(Network::Regtest, GENESIS_TIME, b"Orange regtest").build(0)
}

/// 記憶域からチェーンを起こす。
pub fn open<S: ChainStore>(store: S) -> Chain<S> {
    Chain::open(store, genesis(), DIFFICULTY).expect("ジェネシスは有効")
}

/// `parent` の上に載る有効なブロックを組み立てる。
///
/// `salt` を変えるとコインベースが変わり、同じ高さの別のブロックになる。
pub fn build_on<S: ChainStore>(chain: &Chain<S>, parent: Hash, salt: u64) -> Block {
    let parent_entry = chain.entry(&parent).expect("親を知っている");
    let height = parent_entry.height() + 1;

    let mut input = TxInput::new(OutPoint::null());
    input.signature = encode_coinbase_signature(height, &salt.to_le_bytes());
    let coinbase = Transaction {
        version: CURRENT_TX_VERSION,
        inputs: vec![input],
        outputs: vec![TxOutput::new(
            oag_consensus::params::block_subsidy(height),
            Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
        )],
        locktime: 0,
    };
    let merkle_root = merkle::merkle_root(&[coinbase.txid()]).unwrap();

    Block {
        header: BlockHeader {
            version: 0,
            prev_hash: parent,
            merkle_root,
            timestamp: GENESIS_TIME + height as i64 * 60,
            difficulty: chain
                .expected_difficulty_for_child_of(&parent)
                .expect("難易度を計算できる"),
            height,
            nonce: salt,
        },
        transactions: vec![coinbase],
    }
}

/// `parent` の上に `count` 個のブロックを積む。
pub fn extend<S: ChainStore>(
    chain: &mut Chain<S>,
    mut parent: Hash,
    count: usize,
    salt: u64,
) -> Vec<Hash> {
    let mut hashes = Vec::with_capacity(count);
    for i in 0..count {
        let block = build_on(chain, parent, salt * 1_000_000 + i as u64);
        parent = block.header.hash();
        chain
            .accept_block(block, &AcceptAnyPow, NOW)
            .expect("有効なブロック");
        hashes.push(parent);
    }
    hashes
}

/// コインベース出力が UTXO セットに存在するか。
fn has_coinbase_output<S: ChainStore>(chain: &Chain<S>, block_hash: &Hash) -> bool {
    let block = chain
        .store()
        .block(block_hash)
        .ok()
        .flatten()
        .expect("本体がある");
    let outpoint = OutPoint::new(block.transactions[0].txid(), 0);
    chain
        .utxo_view()
        .expect("ビューを取れる")
        .get(&outpoint)
        .expect("読める")
        .is_some()
}

// ━━━━━━━━ シナリオ ━━━━━━━━

/// ジェネシスから始まること。
pub fn starts_at_genesis<S: ChainStore>(store: S) {
    let chain = open(store);
    assert_eq!(chain.height().unwrap(), 0);
    assert_eq!(chain.tip().unwrap().hash, genesis().header.hash());
    assert_eq!(chain.tip().unwrap().cumulative_work, u128::from(DIFFICULTY));
    assert_eq!(chain.indexed_blocks(), 1);
    assert_eq!(
        chain.store().utxo_count().unwrap(),
        0,
        "ジェネシスは報酬を放棄している"
    );
}

/// 先端を伸ばせること。
pub fn extends_the_tip<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let tip = chain.tip().unwrap().hash;
    let block = build_on(&chain, tip, 1);
    let hash = block.header.hash();

    assert_eq!(
        chain.accept_block(block, &AcceptAnyPow, NOW).unwrap(),
        AcceptOutcome::ExtendedTip
    );
    assert_eq!(chain.height().unwrap(), 1);
    assert_eq!(chain.tip().unwrap().hash, hash);
    assert_eq!(chain.hash_at_height(1).unwrap(), Some(hash));
    assert_eq!(chain.store().utxo_count().unwrap(), 1);
}

/// 同じブロックを二度受け取っても重複として扱うこと。
pub fn rejects_duplicates<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let tip = chain.tip().unwrap().hash;
    let block = build_on(&chain, tip, 1);
    chain
        .accept_block(block.clone(), &AcceptAnyPow, NOW)
        .unwrap();
    assert_eq!(
        chain.accept_block(block, &AcceptAnyPow, NOW).unwrap(),
        AcceptOutcome::Duplicate
    );
    assert_eq!(chain.height().unwrap(), 1);
}

/// 親を知らないブロックを拒否すること。
pub fn rejects_orphans<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let tip = chain.tip().unwrap().hash;
    let mut block = build_on(&chain, tip, 1);
    block.header.prev_hash = oag_primitives::hash::block_hash(b"unknown");
    assert!(matches!(
        chain.accept_block(block, &AcceptAnyPow, NOW),
        Err(ChainError::UnknownParent(_))
    ));
}

/// 作業量が足りない枝はサイドチェーンにとどまること。
pub fn shorter_branch_stays_a_side_chain<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let fork = chain.tip().unwrap().hash;
    let main = extend(&mut chain, fork, 3, 1);

    let side = build_on(&chain, fork, 999);
    assert_eq!(
        chain.accept_block(side, &AcceptAnyPow, NOW).unwrap(),
        AcceptOutcome::SideChain
    );
    assert_eq!(chain.tip().unwrap().hash, *main.last().unwrap());
    assert_eq!(chain.height().unwrap(), 3);
    assert_eq!(chain.indexed_blocks(), 5, "サイドチェーンも記録される");
}

/// 作業量で上回る枝が現れたらリオーグすること。同点では切り替えないこと。
pub fn a_heavier_branch_triggers_a_reorg<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let fork = chain.tip().unwrap().hash;
    let main = extend(&mut chain, fork, 3, 1);
    assert_eq!(chain.tip().unwrap().hash, *main.last().unwrap());

    let mut parent = fork;
    let mut side = Vec::new();
    for i in 0..4 {
        let block = build_on(&chain, parent, 500 + i);
        parent = block.header.hash();
        side.push(parent);
        let outcome = chain.accept_block(block, &AcceptAnyPow, NOW).unwrap();
        if i < 3 {
            assert_eq!(outcome, AcceptOutcome::SideChain, "{i} 本目で切り替わった");
        } else {
            match outcome {
                AcceptOutcome::Reorganized(reorg) => {
                    assert_eq!(reorg.depth(), 3, "3 ブロック取り消すはず");
                    assert_eq!(reorg.connected.len(), 4);
                }
                other => panic!("リオーグしなかった: {other:?}"),
            }
        }
    }

    assert_eq!(chain.height().unwrap(), 4);
    assert_eq!(chain.tip().unwrap().hash, *side.last().unwrap());
    for (h, hash) in side.iter().enumerate() {
        assert_eq!(chain.hash_at_height(h as u64 + 1).unwrap(), Some(*hash));
    }

    // 取り消された枝のコインベース出力が消えていること。
    for hash in &main {
        assert!(
            !has_coinbase_output(&chain, hash),
            "取り消した枝の出力が残っている"
        );
    }
    for hash in &side {
        assert!(has_coinbase_output(&chain, hash));
    }
}

/// リオーグ後の状態が、その枝を最初から積んだ場合と一致すること。
///
/// これが崩れると、リオーグを経験したノードだけが別の帳簿を持つ。
pub fn a_reorg_matches_a_direct_build<S: ChainStore>(forked_store: S, direct_store: S) {
    let mut forked = open(forked_store);
    let fork = forked.tip().unwrap().hash;
    extend(&mut forked, fork, 2, 1); // 捨てられる枝

    let mut parent = fork;
    let mut winner = Vec::new();
    for i in 0..5 {
        let block = build_on(&forked, parent, 700 + i);
        parent = block.header.hash();
        winner.push(block.clone());
        forked.accept_block(block, &AcceptAnyPow, NOW).unwrap();
    }

    let mut direct = open(direct_store);
    for block in &winner {
        direct
            .accept_block(block.clone(), &AcceptAnyPow, NOW)
            .unwrap();
    }

    assert_eq!(forked.tip().unwrap().hash, direct.tip().unwrap().hash);
    assert_eq!(forked.height().unwrap(), direct.height().unwrap());
    assert_eq!(
        forked.store().utxo_count().unwrap(),
        direct.store().utxo_count().unwrap(),
        "リオーグ後の UTXO 件数が直接構築したものと一致しない"
    );

    let forked_view = forked.utxo_view().unwrap();
    let direct_view = direct.utxo_view().unwrap();
    for block in &winner {
        let outpoint = OutPoint::new(block.transactions[0].txid(), 0);
        assert_eq!(
            forked_view.get(&outpoint).unwrap(),
            direct_view.get(&outpoint).unwrap(),
            "高さ {} の出力が食い違った",
            block.header.height
        );
    }
}

/// リオーグの途中で無効が判明しても、元のチェーンに戻ること。
pub fn an_invalid_block_in_a_heavier_branch_is_contained<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let fork = chain.tip().unwrap().hash;
    let main = extend(&mut chain, fork, 2, 1);
    let good_tip = *main.last().unwrap();
    let good_count = chain.store().utxo_count().unwrap();

    let b1 = build_on(&chain, fork, 800);
    let b1_hash = b1.header.hash();
    chain.accept_block(b1, &AcceptAnyPow, NOW).unwrap();

    // コインベースを過大にする。ヘッダは正しいので接続時に初めて弾かれる。
    let mut b2 = build_on(&chain, b1_hash, 801);
    b2.transactions[0].outputs[0].amount = Amount::from_oag(1_000).unwrap();
    b2.header.merkle_root = merkle::merkle_root(&[b2.transactions[0].txid()]).unwrap();
    let b2_hash = b2.header.hash();
    chain.accept_block(b2, &AcceptAnyPow, NOW).unwrap();

    let b3 = build_on(&chain, b2_hash, 802);
    let b3_hash = b3.header.hash();
    let outcome = chain.accept_block(b3, &AcceptAnyPow, NOW).unwrap();

    assert_eq!(outcome, AcceptOutcome::SideChain);
    assert_eq!(
        chain.tip().unwrap().hash,
        good_tip,
        "元の先端に戻っていない"
    );
    assert_eq!(chain.height().unwrap(), 2);
    assert_eq!(
        chain.store().utxo_count().unwrap(),
        good_count,
        "UTXO が元に戻っていない"
    );
    for hash in &main {
        assert!(
            has_coinbase_output(&chain, hash),
            "元の枝の出力が復元されていない"
        );
    }

    // 実際に失敗した b2 とその子孫にのみ印が付くこと。
    assert_eq!(
        chain.entry(&b1_hash).unwrap().status,
        BlockStatus::FullyValid,
        "巻き添えで無効にされている"
    );
    assert_eq!(chain.entry(&b2_hash).unwrap().status, BlockStatus::Invalid);
    assert_eq!(chain.entry(&b3_hash).unwrap().status, BlockStatus::Invalid);
}

/// 無効な祖先を持つブロックが到着時に拒否されること。
pub fn children_of_an_invalid_block_are_rejected<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let fork = chain.tip().unwrap().hash;
    extend(&mut chain, fork, 3, 1);

    let b1 = build_on(&chain, fork, 900);
    let b1_hash = b1.header.hash();
    chain.accept_block(b1, &AcceptAnyPow, NOW).unwrap();

    let mut b2 = build_on(&chain, b1_hash, 901);
    b2.transactions[0].outputs[0].amount = Amount::from_oag(1_000).unwrap();
    b2.header.merkle_root = merkle::merkle_root(&[b2.transactions[0].txid()]).unwrap();
    let b2_hash = b2.header.hash();
    chain.accept_block(b2, &AcceptAnyPow, NOW).unwrap();

    let b3 = build_on(&chain, b2_hash, 902);
    let b3_hash = b3.header.hash();
    chain.accept_block(b3, &AcceptAnyPow, NOW).unwrap();
    let b4 = build_on(&chain, b3_hash, 903);
    chain.accept_block(b4, &AcceptAnyPow, NOW).unwrap();

    assert_eq!(chain.entry(&b2_hash).unwrap().status, BlockStatus::Invalid);
    let b5 = build_on(&chain, b3_hash, 904);
    assert!(matches!(
        chain.accept_block(b5, &AcceptAnyPow, NOW),
        Err(ChainError::InvalidAncestor(_))
    ));
}

/// 深いリオーグでも状態が一致すること。
pub fn a_deep_reorg_stays_consistent<S: ChainStore>(forked_store: S, direct_store: S) {
    let mut chain = open(forked_store);
    let fork = chain.tip().unwrap().hash;
    extend(&mut chain, fork, 30, 1);
    assert_eq!(chain.height().unwrap(), 30);

    let mut parent = fork;
    let mut winner = Vec::new();
    for i in 0..31 {
        let block = build_on(&chain, parent, 2_000 + i);
        parent = block.header.hash();
        winner.push(block.clone());
        chain.accept_block(block, &AcceptAnyPow, NOW).unwrap();
    }

    assert_eq!(chain.height().unwrap(), 31);
    assert_eq!(
        chain.store().utxo_count().unwrap(),
        31,
        "勝ち枝のコインベースのみ"
    );

    let mut direct = open(direct_store);
    for block in &winner {
        direct
            .accept_block(block.clone(), &AcceptAnyPow, NOW)
            .unwrap();
    }
    assert_eq!(
        chain.store().utxo_count().unwrap(),
        direct.store().utxo_count().unwrap()
    );
    assert_eq!(chain.tip().unwrap().hash, direct.tip().unwrap().hash);
}

/// 難易度が窓幅に達するまで固定であること。
pub fn the_difficulty_is_fixed_until_the_window_is_full<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let tip = chain.tip().unwrap().hash;
    assert_eq!(
        chain.expected_difficulty_for_child_of(&tip).unwrap(),
        DIFFICULTY
    );

    let window = oag_pow::lwma::WINDOW as u64;
    extend(&mut chain, tip, window as usize, 1);
    assert_eq!(chain.height().unwrap(), window);

    let tip = chain.tip().unwrap().hash;
    assert_eq!(
        chain.expected_difficulty_for_child_of(&tip).unwrap(),
        DIFFICULTY,
        "等間隔なら難易度は変わらない"
    );
}

/// Median Time Past がチェーンに追随すること。
pub fn median_time_past_follows_the_chain<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let tip = chain.tip().unwrap().hash;
    assert_eq!(chain.median_time_past_for_child_of(&tip), GENESIS_TIME);

    extend(&mut chain, tip, 20, 1);
    let tip = chain.tip().unwrap().hash;
    // 直近 11 ブロック (高さ 10〜20) の中央値は高さ 15 のもの。
    assert_eq!(
        chain.median_time_past_for_child_of(&tip),
        GENESIS_TIME + 15 * 60
    );
}

// ━━━━━━━━ headers-first 同期 ━━━━━━━━

/// ヘッダだけを受け取っても先端は動かないこと。
///
/// 本体が無いのだから接続できない。ここで先端が動いてしまうと、
/// 中身を検証していないブロックを採用したことになる。
pub fn headers_alone_do_not_move_the_tip<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let genesis = chain.tip().unwrap().hash;

    // 本体は渡さず、ヘッダだけを 5 個受け取る。
    let mut parent = genesis;
    let mut headers = Vec::new();
    for i in 0..5 {
        let block = build_on(&chain, parent, 100 + i);
        parent = block.header.hash();
        assert_eq!(
            chain
                .accept_header(&block.header, &AcceptAnyPow, NOW)
                .unwrap(),
            HeaderOutcome::New
        );
        headers.push(block);
    }

    assert_eq!(chain.tip().unwrap().hash, genesis, "先端は動かないはず");
    assert_eq!(chain.height().unwrap(), 0);
    assert_eq!(chain.best_header().unwrap().height(), 5, "ヘッダは先行する");
    assert_eq!(chain.indexed_blocks(), 6);

    for header in &headers {
        let entry = chain.entry(&header.header.hash()).unwrap();
        assert_eq!(entry.status, BlockStatus::HeaderOnly);
        assert!(!entry.has_body());
    }

    // 本体を古い順に渡すと、そのつど先端が伸びる。
    for (i, block) in headers.into_iter().enumerate() {
        let hash = block.header.hash();
        assert_eq!(
            chain.accept_block(block, &AcceptAnyPow, NOW).unwrap(),
            AcceptOutcome::ExtendedTip
        );
        assert_eq!(chain.tip().unwrap().hash, hash);
        assert_eq!(chain.height().unwrap(), i as u64 + 1);
        assert_eq!(chain.entry(&hash).unwrap().status, BlockStatus::FullyValid);
    }
    assert!(chain.missing_bodies(100).unwrap().is_empty());
}

/// 同じヘッダを二度受け取っても増えないこと。
pub fn a_known_header_is_not_added_twice<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let genesis = chain.tip().unwrap().hash;
    let block = build_on(&chain, genesis, 1);

    assert_eq!(
        chain
            .accept_header(&block.header, &AcceptAnyPow, NOW)
            .unwrap(),
        HeaderOutcome::New
    );
    assert_eq!(
        chain
            .accept_header(&block.header, &AcceptAnyPow, NOW)
            .unwrap(),
        HeaderOutcome::Known
    );
    assert_eq!(chain.indexed_blocks(), 2);

    // 本体を受け取った後は、ヘッダは「既知」のままである。
    chain
        .accept_block(block.clone(), &AcceptAnyPow, NOW)
        .unwrap();
    assert_eq!(
        chain
            .accept_header(&block.header, &AcceptAnyPow, NOW)
            .unwrap(),
        HeaderOutcome::Known
    );
    // 本体も二度目は重複として扱う。
    assert_eq!(
        chain.accept_block(block, &AcceptAnyPow, NOW).unwrap(),
        AcceptOutcome::Duplicate
    );
    assert_eq!(chain.indexed_blocks(), 2);
}

/// 本体が飛び飛びに届いても、そろうまで先端が動かないこと。
///
/// 取り寄せは複数のピアに割り振るため、順序が入れ替わって届きうる。
/// 途中が欠けたまま先へ進むと、検証していないブロックを飛ばして
/// UTXO を更新することになる。
pub fn bodies_arriving_out_of_order_wait_for_their_parents<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let genesis = chain.tip().unwrap().hash;

    let mut parent = genesis;
    let mut blocks = Vec::new();
    for i in 0..4 {
        let block = build_on(&chain, parent, 200 + i);
        parent = block.header.hash();
        chain
            .accept_header(&block.header, &AcceptAnyPow, NOW)
            .unwrap();
        blocks.push(block);
    }

    // 高さ 3 と 4 を先に渡す。親がまだ無いので繋がらない。
    let fourth = blocks.pop().unwrap();
    let third = blocks.pop().unwrap();
    assert_eq!(
        chain.accept_block(fourth, &AcceptAnyPow, NOW).unwrap(),
        AcceptOutcome::SideChain,
        "親の本体が無いうちは切り替えない"
    );
    assert_eq!(chain.height().unwrap(), 0);
    assert_eq!(
        chain.accept_block(third, &AcceptAnyPow, NOW).unwrap(),
        AcceptOutcome::SideChain
    );
    assert_eq!(chain.height().unwrap(), 0);

    // 高さ 2 を渡してもまだ足りない。
    let second = blocks.pop().unwrap();
    assert_eq!(
        chain.accept_block(second, &AcceptAnyPow, NOW).unwrap(),
        AcceptOutcome::SideChain
    );
    assert_eq!(chain.height().unwrap(), 0);

    // 最後の欠けが埋まると、一気に 4 つ繋がる。
    let first = blocks.pop().unwrap();
    let outcome = chain.accept_block(first, &AcceptAnyPow, NOW).unwrap();
    assert!(
        matches!(outcome, AcceptOutcome::Reorganized(_)),
        "4 つまとめて繋がる: {outcome:?}"
    );
    assert_eq!(chain.height().unwrap(), 4);
    assert!(chain.missing_bodies(100).unwrap().is_empty());
}

/// 取り寄せるべき本体が、古い順に挙がること。
pub fn missing_bodies_are_listed_oldest_first<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let genesis = chain.tip().unwrap().hash;

    let mut parent = genesis;
    let mut expected = Vec::new();
    for i in 0..6 {
        let block = build_on(&chain, parent, 300 + i);
        parent = block.header.hash();
        chain
            .accept_header(&block.header, &AcceptAnyPow, NOW)
            .unwrap();
        expected.push(block.header.hash());
    }

    assert_eq!(chain.missing_bodies(100).unwrap(), expected);
    assert_eq!(
        chain.missing_bodies(2).unwrap(),
        expected[..2].to_vec(),
        "上限は古い側から効く"
    );
    assert!(chain.missing_bodies(0).unwrap().is_empty());
}

/// `getheaders` にロケータの分岐点から答えること。
pub fn headers_are_served_from_the_fork_point<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let genesis = chain.tip().unwrap().hash;
    let hashes = extend(&mut chain, genesis, 10, 1);

    // 何も知らない相手 (ジェネシスだけ) には高さ 1 から返す。
    let all = chain.headers_after(&[genesis], &Hash::ZERO, 100).unwrap();
    assert_eq!(all.len(), 10);
    assert_eq!(all[0].height, 1);
    assert_eq!(all[9].height, 10);

    // 高さ 4 まで知っている相手には高さ 5 から返す。
    let after = chain.headers_after(&[hashes[3]], &Hash::ZERO, 100).unwrap();
    assert_eq!(after.len(), 6);
    assert_eq!(after[0].height, 5);

    // 上限が効くこと。
    let capped = chain.headers_after(&[genesis], &Hash::ZERO, 3).unwrap();
    assert_eq!(capped.len(), 3);
    assert_eq!(capped[2].height, 3);

    // stop で打ち切ること (そのヘッダを含む)。
    let stopped = chain.headers_after(&[genesis], &hashes[2], 100).unwrap();
    assert_eq!(stopped.len(), 3);
    assert_eq!(stopped[2].height, 3);

    // 先端まで知っている相手には何も返さない。
    assert!(chain
        .headers_after(&[hashes[9]], &Hash::ZERO, 100)
        .unwrap()
        .is_empty());

    // 知らないハッシュしか無いロケータにはジェネシスの次から返す。
    let unknown = oag_primitives::hash::block_hash(b"unknown block");
    let from_scratch = chain.headers_after(&[unknown], &Hash::ZERO, 100).unwrap();
    assert_eq!(from_scratch.len(), 10);
    assert_eq!(from_scratch[0].height, 1);
}

/// 無効と分かっているブロックのヘッダを受け取っても、蘇らないこと。
pub fn a_header_for_an_invalid_block_is_refused<S: ChainStore>(store: S) {
    let mut chain = open(store);
    let genesis = chain.tip().unwrap().hash;

    // 報酬を取りすぎたブロックを作る。ヘッダは正しいので、接続を試みて
    // 初めて無効と判明する。
    let mut bad = build_on(&chain, genesis, 7);
    bad.transactions[0].outputs[0].amount = Amount::from_oag(1_000).unwrap();
    bad.header.merkle_root = merkle::merkle_root(&[bad.transactions[0].txid()]).unwrap();
    let bad_hash = bad.header.hash();
    let header = bad.header;

    assert_eq!(
        chain.accept_block(bad, &AcceptAnyPow, NOW).unwrap(),
        AcceptOutcome::SideChain,
        "接続に失敗するので先端にはならない"
    );
    assert_eq!(chain.entry(&bad_hash).unwrap().status, BlockStatus::Invalid);
    assert_eq!(chain.tip().unwrap().hash, genesis);

    // 同じヘッダを送り直されても受け付けない。
    assert!(matches!(
        chain.accept_header(&header, &AcceptAnyPow, NOW),
        Err(ChainError::InvalidAncestor(_))
    ));
    assert_eq!(chain.entry(&bad_hash).unwrap().status, BlockStatus::Invalid);
}
