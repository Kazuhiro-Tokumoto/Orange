//! assumevalid の試験 (`docs/SPEC.md` §10.8)。
//!
//! 確かめたいのは 2 つである。
//!
//! 1. **効くこと。** 指定したブロックとその祖先では署名検証が飛ぶ。
//! 2. **効きすぎないこと。** それ以外では飛ばない。こちらが本題であり、
//!    ここが緩むと「攻撃者のチェーンでも署名を検査しない」になる。

use oag_chain::chain::Chain;
use oag_chain::index::BlockStatus;
use oag_chain::scenarios::{self, NOW};
use oag_chain::{ChainStore, MemoryStore};
use oag_consensus::lock::Lock;
use oag_consensus::tx::{
    encode_coinbase_signature, OutPoint, Transaction, TxInput, TxOutput, CURRENT_TX_VERSION,
};
use oag_consensus::validate::AcceptAnyPow;
use oag_consensus::{sighash, Block, BlockHeader, SighashType};
use oag_primitives::{merkle, Amount, Hash, SecretKey};

/// コインベースだけのブロック。報酬は `payout` へ支払う。
fn coinbase_block(chain: &Chain<MemoryStore>, parent: Hash, salt: u64, payout: Lock) -> Block {
    let height = scenarios::entry_of(chain, &parent).height() + 1;

    let mut input = TxInput::new(OutPoint::null());
    input.signature = encode_coinbase_signature(height, &salt.to_le_bytes());
    let coinbase = Transaction {
        version: CURRENT_TX_VERSION,
        inputs: vec![input],
        outputs: vec![TxOutput::new(
            oag_consensus::params::block_subsidy(height),
            payout,
        )],
        locktime: 0,
    };
    block_with(chain, parent, salt, vec![coinbase])
}

/// 与えたトランザクション列でブロックを組む。先頭はコインベースであること。
fn block_with(
    chain: &Chain<MemoryStore>,
    parent: Hash,
    salt: u64,
    transactions: Vec<Transaction>,
) -> Block {
    let height = scenarios::entry_of(chain, &parent).height() + 1;
    let txids: Vec<Hash> = transactions.iter().map(|tx| tx.txid()).collect();
    Block {
        header: BlockHeader {
            version: 0,
            prev_hash: parent,
            merkle_root: merkle::merkle_root(&txids).expect("at least one transaction"),
            timestamp: scenarios::GENESIS_TIME + height as i64 * 60,
            difficulty: chain
                .expected_difficulty_for_child_of(&parent)
                .expect("the difficulty can be computed"),
            height,
            nonce: salt,
        },
        transactions,
    }
}

/// 成熟したコインベースを使う、**署名が合っていない**ブロックを組む。
///
/// 署名そのものは本物である。**別のメッセージに対する本物**なので、
/// 形式の検査はすべて通り、楕円曲線上の検証だけが落ちる。これは
/// 「飛ばしたのは検証 1 回だけである」ことを確かめるためである。
fn block_spending_with_a_wrong_signature(
    chain: &Chain<MemoryStore>,
    parent: Hash,
    salt: u64,
    key: &SecretKey,
    funding: &Transaction,
) -> Block {
    block_spending(chain, parent, salt, key, funding, true)
}

/// 署名の合っている支払いを含むブロック。
fn block_spending_correctly(
    chain: &Chain<MemoryStore>,
    parent: Hash,
    salt: u64,
    key: &SecretKey,
    funding: &Transaction,
) -> Block {
    block_spending(chain, parent, salt, key, funding, false)
}

fn block_spending(
    chain: &Chain<MemoryStore>,
    parent: Hash,
    salt: u64,
    key: &SecretKey,
    funding: &Transaction,
    tamper: bool,
) -> Block {
    let height = scenarios::entry_of(chain, &parent).height() + 1;

    let mut coinbase_input = TxInput::new(OutPoint::null());
    coinbase_input.signature = encode_coinbase_signature(height, &salt.to_le_bytes());
    let coinbase = Transaction {
        version: CURRENT_TX_VERSION,
        inputs: vec![coinbase_input],
        outputs: vec![TxOutput::new(
            oag_consensus::params::block_subsidy(height),
            Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
        )],
        locktime: 0,
    };

    let spent = funding.outputs[0].clone();
    let mut spend = Transaction {
        version: CURRENT_TX_VERSION,
        inputs: vec![TxInput::new(OutPoint::new(funding.txid(), 0))],
        outputs: vec![TxOutput::new(
            spent
                .amount
                .checked_sub(Amount::from_atomic_const(1000))
                .unwrap(),
            Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
        )],
        locktime: 0,
    };

    let mut msg =
        sighash(&spend, &[spent], 0, SighashType::DEFAULT).expect("the sighash is defined");
    if tamper {
        // **わざと別のメッセージに署名する。**
        msg[0] ^= 0x01;
    }
    spend.inputs[0].signature = key.sign(&msg).to_bytes().to_vec();

    block_with(chain, parent, salt, vec![coinbase, spend])
}

/// 高さ 1 のコインベースを自分の鍵で受け取り、成熟するまで伸ばす。
fn matured_chain() -> (Chain<MemoryStore>, SecretKey, Transaction, Hash) {
    let mut chain = scenarios::open(MemoryStore::new());
    let key = SecretKey::generate();
    let genesis = chain.tip().unwrap().hash;

    let first = coinbase_block(&chain, genesis, 1, Lock::pay_to_pubkey(&key.public_key()));
    let funding = first.transactions[0].clone();
    let mut parent = first.header.hash();
    chain
        .accept_block(first, &AcceptAnyPow, NOW)
        .expect("a valid block");

    // 成熟期間 (120) を越えるまで積む。
    for i in 0..oag_consensus::params::COINBASE_MATURITY {
        let block = coinbase_block(
            &chain,
            parent,
            100 + i,
            Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
        );
        parent = block.header.hash();
        chain
            .accept_block(block, &AcceptAnyPow, NOW)
            .expect("a valid block");
    }

    (chain, key, funding, parent)
}

/// ブロックを差し出し、**署名の検査で落ちたこと**を確かめる。
///
/// 本体の検証はチェーンを繋ぎ替えるときに走るため、失敗しても
/// `accept_block` は誤りを返さない。落ちた枝は脇に置かれ、印が付く
/// (`an_invalid_block_in_a_heavier_branch_is_contained` と同じ挙動)。
/// **したがって「誤りが返ったか」ではなく「先端が進んだか」で見る。**
fn assert_rejected(chain: &mut Chain<MemoryStore>, block: Block) {
    let hash = block.header.hash();
    let before = chain.tip().unwrap().hash;
    chain
        .accept_block(block, &AcceptAnyPow, NOW)
        .expect("the header is well formed");
    assert_eq!(
        chain.tip().unwrap().hash,
        before,
        "the tip moved onto a block whose signature does not check out"
    );
    assert_eq!(
        scenarios::entry_of(chain, &hash).status,
        BlockStatus::Invalid,
        "the block was not marked invalid"
    );
}

/// ブロックを差し出し、**通って先端になったこと**を確かめる。
fn assert_accepted(chain: &mut Chain<MemoryStore>, block: Block) {
    let hash = block.header.hash();
    chain
        .accept_block(block, &AcceptAnyPow, NOW)
        .expect("the header is well formed");
    assert_eq!(
        chain.tip().unwrap().hash,
        hash,
        "the block did not become the tip"
    );
}

#[test]
fn without_assumevalid_a_wrong_signature_is_rejected() {
    let (mut chain, key, funding, tip) = matured_chain();
    let bad = block_spending_with_a_wrong_signature(&chain, tip, 900, &key, &funding);

    assert_rejected(&mut chain, bad);
}

#[test]
fn under_assumevalid_the_same_block_is_accepted() {
    // 上の試験と同じブロックが、assumevalid を置くと通る。
    // **これが「効いている」ことの証明である。**
    let (mut chain, key, funding, tip) = matured_chain();
    let bad = block_spending_with_a_wrong_signature(&chain, tip, 900, &key, &funding);
    let bad_hash = bad.header.hash();

    chain.set_assume_valid(Some(bad_hash));
    assert_accepted(&mut chain, bad);
}

#[test]
fn a_block_that_is_not_an_ancestor_is_still_checked() {
    // **本題。** assumevalid を置いても、その祖先でないブロックは従来どおり
    // 検証される。攻撃者が別のチェーンを食わせてきた場合がこれにあたる。
    let (mut chain, key, funding, tip) = matured_chain();

    // 本線を 1 つ伸ばし、その先端を assumevalid に指名する。
    let named = coinbase_block(
        &chain,
        tip,
        7000,
        Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
    );
    let named_hash = named.header.hash();
    assert_accepted(&mut chain, named);
    chain.set_assume_valid(Some(named_hash));

    // 指名したブロックの **兄弟** として、署名の合わないブロックを置く。
    // 高さは同じだが、指名したブロックの祖先ではない。
    let sibling = block_spending_with_a_wrong_signature(&chain, tip, 8000, &key, &funding);
    let sibling_hash = sibling.header.hash();
    assert_ne!(sibling_hash, named_hash);
    chain
        .accept_block(sibling, &AcceptAnyPow, NOW)
        .expect("the header is well formed");

    // 同じ作業量では繋ぎ替えが起きず、検証まで届かない。**枝を重くして
    // 繋ぎ替えを起こす。** ここで初めて兄弟の署名が検査される。
    let heavier = coinbase_block(
        &chain,
        sibling_hash,
        8001,
        Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
    );
    chain
        .accept_block(heavier, &AcceptAnyPow, NOW)
        .expect("the header is well formed");

    assert_eq!(
        chain.tip().unwrap().hash,
        named_hash,
        "the tip moved onto a branch that assumevalid does not cover"
    );
    assert_eq!(
        scenarios::entry_of(&chain, &sibling_hash).status,
        BlockStatus::Invalid,
        "a block that is not an ancestor of the named one must still be checked"
    );
}

#[test]
fn a_block_above_assumevalid_is_still_checked() {
    let (mut chain, key, funding, tip) = matured_chain();

    // 先端を assumevalid に指名する。その **上** は完全検証のままである。
    chain.set_assume_valid(Some(tip));

    let above = block_spending_with_a_wrong_signature(&chain, tip, 9000, &key, &funding);
    assert_rejected(&mut chain, above);
}

#[test]
fn an_unknown_assumevalid_hash_changes_nothing() {
    // 指定したハッシュをまだ受け取っていない間は、何も飛ばさない。
    let (mut chain, key, funding, tip) = matured_chain();
    chain.set_assume_valid(Some(oag_primitives::hash::block_hash(b"not on this chain")));

    let bad = block_spending_with_a_wrong_signature(&chain, tip, 9100, &key, &funding);
    assert_rejected(&mut chain, bad);
}

#[test]
fn turning_it_off_restores_full_checking() {
    let (mut chain, key, funding, tip) = matured_chain();
    let bad = block_spending_with_a_wrong_signature(&chain, tip, 9200, &key, &funding);

    chain.set_assume_valid(Some(bad.header.hash()));
    chain.set_assume_valid(None);
    assert_eq!(chain.assume_valid(), None);

    assert_rejected(&mut chain, bad);
}

#[test]
fn the_ancestors_of_the_named_block_are_skipped_too() {
    // 指名したブロックだけでなく、その祖先も飛ばす。これが初期同期で
    // 効く理由である。
    let (mut chain, key, funding, tip) = matured_chain();
    let bad = block_spending_with_a_wrong_signature(&chain, tip, 9300, &key, &funding);
    let bad_hash = bad.header.hash();

    chain.set_assume_valid(Some(bad_hash));
    assert_accepted(&mut chain, bad);

    // 指名したブロックの **子** を積む。ここは飛ばされない。
    let child = block_spending_with_a_wrong_signature(&chain, bad_hash, 9400, &key, &funding);
    assert_rejected(&mut chain, child);
}

/// 正しいチェーンを 1 本組み、ブロックを順に返す。
///
/// 署名の合った支払いを 1 つ含む。**署名検証が実際に走る**チェーンで
/// なければ、飛ばす／飛ばさないの比較に意味がない。
fn a_valid_chain() -> Vec<Block> {
    let (chain, key, funding, tip) = matured_chain();
    let mut blocks = Vec::new();
    for height in 1..=chain.height().unwrap() {
        let hash = chain.hash_at_height(height).unwrap().expect("on the chain");
        blocks.push(
            chain
                .store()
                .block(&hash)
                .unwrap()
                .expect("the body is kept"),
        );
    }
    blocks.push(block_spending_correctly(&chain, tip, 4242, &key, &funding));
    blocks
}

#[test]
fn assumevalid_does_not_change_what_is_valid() {
    // **「コンセンサスを変えない」ことの試験。**
    //
    // 同じブロック列を、assumevalid を置いた側と置かない側に流す。
    // 1 ブロックごとの結果も、最後の状態も、一致しなければならない。
    // ここがずれると、設定の違うノード同士でチェーンが割れる。
    let blocks = a_valid_chain();
    let last = blocks.last().unwrap().header.hash();

    let mut plain = scenarios::open(MemoryStore::new());
    let mut assumed = scenarios::open(MemoryStore::new());
    assumed.set_assume_valid(Some(last));

    for block in &blocks {
        let without = plain
            .accept_block(block.clone(), &AcceptAnyPow, NOW)
            .expect("a valid block");
        let with = assumed
            .accept_block(block.clone(), &AcceptAnyPow, NOW)
            .expect("a valid block");
        assert_eq!(
            without, with,
            "the two disagreed at height {}",
            block.header.height
        );
    }

    assert_eq!(plain.tip().unwrap().hash, assumed.tip().unwrap().hash);
    assert_eq!(assumed.tip().unwrap().hash, last);
    assert_eq!(plain.height().unwrap(), assumed.height().unwrap());
    assert_eq!(
        plain.store().utxo_count(),
        assumed.store().utxo_count(),
        "the UTXO sets came out different"
    );
}
