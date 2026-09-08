//! チェーンの記憶域の抽象。
//!
//! [`Chain`](crate::Chain) はこの trait の上で動く。メモリ上の
//! [`MemoryStore`] と、永続化された実装 (`oag-store` クレート) の双方を
//! 同じコードで扱える。
//!
//! # なぜ抽象化するのか
//!
//! リオーグは最もバグりやすい箇所である。記憶域ごとに別の実装を持つと、
//! 片方だけで通るテストができてしまう。trait を挟むことで、**同一の
//! シナリオをどちらの記憶域に対しても走らせられる**
//! ([`crate::scenarios`] を参照)。

use crate::index::BlockIndexEntry;
use oag_consensus::utxo::{UndoBlock, UtxoSet, UtxoView};
use oag_consensus::Block;
use oag_primitives::Hash;
use std::collections::HashMap;

/// チェーンの状態を保持する記憶域。
///
/// [`connect_block`](ChainStore::connect_block) と
/// [`disconnect_tip`](ChainStore::disconnect_tip) は、UTXO セット・
/// 巻き戻し情報・アクティブチェーン・先端の記録を **不可分に** 更新する
/// MUST。途中で失敗した場合、いずれも変更されていてはならない。
pub trait ChainStore {
    /// この記憶域の誤り。
    type Error: std::error::Error + Send + Sync + 'static;

    /// UTXO の読み取りビュー。取得した時点のスナップショットを見る。
    type View<'a>: UtxoView
    where
        Self: 'a;

    /// アクティブチェーンの先端。
    fn tip(&self) -> Result<Option<Hash>, Self::Error>;

    /// アクティブチェーンの高さ。
    fn height(&self) -> Result<Option<u64>, Self::Error>;

    /// アクティブチェーンの指定した高さのブロックハッシュ。
    fn hash_at_height(&self, height: u64) -> Result<Option<Hash>, Self::Error>;

    /// ブロック本体。
    fn block(&self, hash: &Hash) -> Result<Option<Block>, Self::Error>;

    /// インデックスの 1 件。
    fn index_entry(&self, hash: &Hash) -> Result<Option<BlockIndexEntry>, Self::Error>;

    /// インデックスの全件。起動時にチェーンを組み立てるために用いる。
    fn all_index_entries(&self) -> Result<Vec<BlockIndexEntry>, Self::Error>;

    /// ブロック本体とインデックスを記録する。接続はしない。
    fn put_block(&self, block: &Block, entry: &BlockIndexEntry) -> Result<(), Self::Error>;

    /// インデックスの 1 件を更新する。
    fn put_index_entry(&self, entry: &BlockIndexEntry) -> Result<(), Self::Error>;

    /// ブロックをアクティブチェーンに接続する。検証は呼び出し側の責任である。
    fn connect_block(&self, block: &Block) -> Result<UndoBlock, Self::Error>;

    /// 先端のブロックを取り消す。
    fn disconnect_tip(&self) -> Result<Hash, Self::Error>;

    /// UTXO の読み取りビュー。
    fn utxo_view(&self) -> Result<Self::View<'_>, Self::Error>;

    /// UTXO の件数。記憶域どうしの比較に用いる。
    fn utxo_count(&self) -> Result<u64, Self::Error>;
}

/// メモリ上の記憶域。
///
/// 試験と、永続化を必要としない用途に用いる。プロセスが終われば消える。
///
/// **大きなチェーンには向かない。** [`utxo_view`](MemoryStore::utxo_view)
/// が UTXO セット全体を複製するため、1 ブロック接続するたびに
/// UTXO 件数に比例した費用がかかる。永続化実装は読み取りトランザクション
/// を返すのでこの費用を持たない。
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: std::cell::RefCell<MemoryInner>,
}

#[derive(Debug, Default)]
struct MemoryInner {
    blocks: HashMap<Hash, Block>,
    index: HashMap<Hash, BlockIndexEntry>,
    undo: HashMap<Hash, UndoBlock>,
    active: Vec<Hash>,
    utxo: UtxoSet,
}

/// メモリ記憶域の誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MemoryStoreError {
    /// UTXO セットの操作に失敗した。
    #[error(transparent)]
    Utxo(#[from] oag_consensus::utxo::UtxoError),
    /// 先端が記録されていない。
    #[error("先端が記録されていない")]
    NoTip,
    /// 巻き戻し情報を保持していない。
    #[error("ブロック {0} の巻き戻し情報を保持していない")]
    MissingUndo(Hash),
}

impl MemoryStore {
    /// 空の記憶域を作る。
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }

    /// 保持している UTXO の件数。
    pub fn utxo_count(&self) -> usize {
        self.inner.borrow().utxo.len()
    }

    /// UTXO セットの複製。試験での比較に用いる。
    pub fn utxo_snapshot(&self) -> UtxoSet {
        self.inner.borrow().utxo.clone()
    }
}

impl ChainStore for MemoryStore {
    type Error = MemoryStoreError;
    type View<'a> = UtxoSet;

    fn tip(&self) -> Result<Option<Hash>, Self::Error> {
        Ok(self.inner.borrow().active.last().copied())
    }

    fn height(&self) -> Result<Option<u64>, Self::Error> {
        let inner = self.inner.borrow();
        Ok((!inner.active.is_empty()).then(|| inner.active.len() as u64 - 1))
    }

    fn hash_at_height(&self, height: u64) -> Result<Option<Hash>, Self::Error> {
        let inner = self.inner.borrow();
        Ok(usize::try_from(height)
            .ok()
            .and_then(|i| inner.active.get(i).copied()))
    }

    fn block(&self, hash: &Hash) -> Result<Option<Block>, Self::Error> {
        Ok(self.inner.borrow().blocks.get(hash).cloned())
    }

    fn index_entry(&self, hash: &Hash) -> Result<Option<BlockIndexEntry>, Self::Error> {
        Ok(self.inner.borrow().index.get(hash).cloned())
    }

    fn all_index_entries(&self) -> Result<Vec<BlockIndexEntry>, Self::Error> {
        Ok(self.inner.borrow().index.values().cloned().collect())
    }

    fn put_block(&self, block: &Block, entry: &BlockIndexEntry) -> Result<(), Self::Error> {
        let mut inner = self.inner.borrow_mut();
        inner.blocks.insert(entry.hash, block.clone());
        inner.index.insert(entry.hash, entry.clone());
        Ok(())
    }

    fn put_index_entry(&self, entry: &BlockIndexEntry) -> Result<(), Self::Error> {
        self.inner
            .borrow_mut()
            .index
            .insert(entry.hash, entry.clone());
        Ok(())
    }

    fn connect_block(&self, block: &Block) -> Result<UndoBlock, Self::Error> {
        let mut inner = self.inner.borrow_mut();
        // UtxoSet::apply_block は失敗時に変更を残さない。
        let undo = inner
            .utxo
            .apply_block(&block.transactions, block.header.height)?;
        let hash = block.header.hash();
        inner.undo.insert(hash, undo.clone());
        inner.active.push(hash);
        Ok(undo)
    }

    fn disconnect_tip(&self) -> Result<Hash, Self::Error> {
        let mut inner = self.inner.borrow_mut();
        let hash = *inner.active.last().ok_or(MemoryStoreError::NoTip)?;
        let undo = inner
            .undo
            .get(&hash)
            .cloned()
            .ok_or(MemoryStoreError::MissingUndo(hash))?;
        inner.utxo.undo_block(&undo)?;
        inner.active.pop();
        Ok(hash)
    }

    fn utxo_view(&self) -> Result<Self::View<'_>, Self::Error> {
        Ok(self.inner.borrow().utxo.clone())
    }

    fn utxo_count(&self) -> Result<u64, Self::Error> {
        Ok(self.inner.borrow().utxo.len() as u64)
    }
}
