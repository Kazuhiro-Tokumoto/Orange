//! 記憶装置が読めなかっただけのブロックに、無効の印を付けないこと。
//!
//! [`UtxoView::get`] が `Result` を返すのは、ディスクの不調を「その UTXO
//! は存在しない」と取り違えないためである。その区別は
//! `UtxoError::Backend` として検証を抜けるまで保たれるが、チェーン側が
//! そこで握り潰すと意味が無くなる。
//!
//! 無効の印は子孫へ広がり、永続化され、再起動しても消えない。一度の
//! 読み取り失敗で付けてしまうと、**そのノードは正しいチェーンへ二度と
//! 戻れなくなる**。判定を下せないときは、下さずに投げ返すのが正しい。

use std::cell::Cell;

use oag_chain::index::BlockIndexEntry;
use oag_chain::scenarios::{build_on, entry_of, open, NOW};
use oag_chain::store::{ChainStore, MemoryStore, MemoryStoreError};
use oag_chain::{BlockStatus, ChainError};
use oag_consensus::lock::Lock;
use oag_consensus::tx::{OutPoint, TxInput, CURRENT_TX_VERSION};
use oag_consensus::utxo::{UndoBlock, UtxoEntry, UtxoError, UtxoSet, UtxoView};
use oag_consensus::validate::AcceptAnyPow;
use oag_consensus::{Block, Transaction, TxOutput};
use oag_primitives::{merkle, Amount, Hash, SecretKey};

/// 読み取りを任意の時点で失敗させられる記憶域。
///
/// 中身は [`MemoryStore`] にそのまま委ねる。違うのは UTXO のビューだけで、
/// `failing` を立てている間は読み取りが `UtxoError::Backend` を返す。
struct FlakyStore {
    inner: MemoryStore,
    failing: Cell<bool>,
}

impl FlakyStore {
    fn new() -> FlakyStore {
        FlakyStore {
            inner: MemoryStore::new(),
            failing: Cell::new(false),
        }
    }

    fn set_failing(&self, failing: bool) {
        self.failing.set(failing);
    }
}

/// 読み取りが失敗するビュー。
struct FlakyView {
    inner: UtxoSet,
    failing: bool,
}

impl UtxoView for FlakyView {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, UtxoError> {
        if self.failing {
            // 「無い」ではなく「読めない」。この違いが本件の全部である。
            return Err(UtxoError::Backend("ディスクを読めない".to_string()));
        }
        self.inner.get(outpoint)
    }
}

impl ChainStore for FlakyStore {
    type Error = MemoryStoreError;
    type View<'a> = FlakyView;

    fn tip(&self) -> Result<Option<Hash>, Self::Error> {
        self.inner.tip()
    }

    fn height(&self) -> Result<Option<u64>, Self::Error> {
        self.inner.height()
    }

    fn hash_at_height(&self, height: u64) -> Result<Option<Hash>, Self::Error> {
        self.inner.hash_at_height(height)
    }

    fn block(&self, hash: &Hash) -> Result<Option<Block>, Self::Error> {
        self.inner.block(hash)
    }

    fn index_entry(&self, hash: &Hash) -> Result<Option<BlockIndexEntry>, Self::Error> {
        self.inner.index_entry(hash)
    }

    fn all_index_entries(&self) -> Result<Vec<BlockIndexEntry>, Self::Error> {
        self.inner.all_index_entries()
    }

    fn index_len(&self) -> Result<u64, Self::Error> {
        self.inner.index_len()
    }

    fn for_each_index_entry(&self, f: &mut dyn FnMut(BlockIndexEntry)) -> Result<(), Self::Error> {
        self.inner.for_each_index_entry(f)
    }

    fn children_of(&self, hash: &Hash) -> Result<Vec<Hash>, Self::Error> {
        self.inner.children_of(hash)
    }

    fn put_block(&self, block: &Block, entry: &BlockIndexEntry) -> Result<(), Self::Error> {
        self.inner.put_block(block, entry)
    }

    fn put_index_entry(&self, entry: &BlockIndexEntry) -> Result<(), Self::Error> {
        self.inner.put_index_entry(entry)
    }

    fn connect_block(&self, block: &Block) -> Result<UndoBlock, Self::Error> {
        self.inner.connect_block(block)
    }

    fn disconnect_tip(&self) -> Result<Hash, Self::Error> {
        self.inner.disconnect_tip()
    }

    fn utxo_view(&self) -> Result<Self::View<'_>, Self::Error> {
        Ok(FlakyView {
            inner: ChainStore::utxo_view(&self.inner)?,
            failing: self.failing.get(),
        })
    }

    fn utxo_count(&self) -> Result<u64, Self::Error> {
        ChainStore::utxo_count(&self.inner)
    }
}

/// 存在しない UTXO を使おうとするトランザクションを 1 件足したブロック。
///
/// 接続の最中に必ず [`UtxoView::get`] を通る。コインベースだけのブロックは
/// ビューを引かないため、この試験には使えない。
fn block_that_reads_the_utxo_set<S: ChainStore>(
    chain: &oag_chain::Chain<S>,
    parent: Hash,
    salt: u64,
) -> Block {
    let mut block = build_on(chain, parent, salt);
    let spend = Transaction {
        version: CURRENT_TX_VERSION,
        // 親のブロックハッシュを txid に見立てる。UTXO セットには無い。
        inputs: vec![TxInput::new(OutPoint::new(parent, 0))],
        outputs: vec![TxOutput::new(
            Amount::from_oag(1).unwrap(),
            Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
        )],
        locktime: 0,
    };
    block.transactions.push(spend);
    let txids: Vec<Hash> = block.transactions.iter().map(|tx| tx.txid()).collect();
    block.header.merkle_root = merkle::merkle_root(&txids).unwrap();
    block
}

#[test]
fn a_storage_failure_does_not_mark_the_block_invalid() {
    let mut chain = open(FlakyStore::new());
    let genesis = chain.tip().unwrap().hash;

    let block = block_that_reads_the_utxo_set(&chain, genesis, 1);
    let hash = block.header.hash();

    // 接続の最中にディスクが読めなくなる。
    chain.store().set_failing(true);
    let err = chain
        .accept_block(block, &AcceptAnyPow, NOW)
        .expect_err("読み取りが失敗した以上、接続は通らない");

    match &err {
        ChainError::Validation(e) => assert!(
            e.is_storage_failure(),
            "記憶装置の失敗として返っていない: {e}"
        ),
        other => panic!("想定しない誤り: {other}"),
    }

    assert_ne!(
        entry_of(&chain, &hash).status,
        BlockStatus::Invalid,
        "読めなかっただけのブロックに無効の印が付いている"
    );
    assert_eq!(chain.tip().unwrap().hash, genesis, "先端が動いている");
}

#[test]
fn the_verdict_is_only_deferred_not_lost() {
    let mut chain = open(FlakyStore::new());
    let genesis = chain.tip().unwrap().hash;

    let block = block_that_reads_the_utxo_set(&chain, genesis, 1);
    let hash = block.header.hash();

    chain.store().set_failing(true);
    chain.accept_block(block, &AcceptAnyPow, NOW).unwrap_err();
    assert_ne!(entry_of(&chain, &hash).status, BlockStatus::Invalid);

    // ディスクが直り、子が届いて接続をやり直す。今度は本当に読めるので、
    // このブロックが不正であることが分かる。
    chain.store().set_failing(false);
    let child = build_on(&chain, hash, 2);
    chain.accept_block(child, &AcceptAnyPow, NOW).unwrap();

    assert_eq!(
        entry_of(&chain, &hash).status,
        BlockStatus::Invalid,
        "読めるようになっても判定が下りていない"
    );
    assert_eq!(chain.tip().unwrap().hash, genesis);
}

#[test]
fn a_readable_disk_still_marks_a_bad_block_invalid() {
    let mut chain = open(FlakyStore::new());
    let genesis = chain.tip().unwrap().hash;

    let block = block_that_reads_the_utxo_set(&chain, genesis, 1);
    let hash = block.header.hash();

    // 一度も失敗させない。存在しない UTXO を使っているので不正である。
    chain.accept_block(block, &AcceptAnyPow, NOW).unwrap();

    assert_eq!(
        entry_of(&chain, &hash).status,
        BlockStatus::Invalid,
        "不正なブロックに印が付いていない"
    );
    assert_eq!(chain.tip().unwrap().hash, genesis);
}
