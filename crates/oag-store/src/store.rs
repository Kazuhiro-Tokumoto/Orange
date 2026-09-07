//! redb を用いた記憶域。

use oag_chain::index::BlockIndexEntry;
use oag_consensus::codec::{CodecError, Decode, Encode};
use oag_consensus::tx::OutPoint;
use oag_consensus::utxo::{
    apply_block_to, undo_block_from, UndoBlock, UtxoEntry, UtxoError, UtxoView, UtxoWrite,
};
use oag_consensus::Block;
use oag_primitives::Hash;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::path::Path;

type Bytes = &'static [u8];

/// ブロック本体。ハッシュ → シリアライズしたブロック。
const BLOCKS: TableDefinition<'static, Bytes, Bytes> = TableDefinition::new("blocks");
/// ブロックインデックス。ハッシュ → インデックスの 1 件。
const INDEX: TableDefinition<'static, Bytes, Bytes> = TableDefinition::new("block_index");
/// 巻き戻し情報。ハッシュ → 巻き戻し情報。
const UNDO: TableDefinition<'static, Bytes, Bytes> = TableDefinition::new("undo");
/// UTXO セット。出力参照 → UTXO の内容。
const UTXO: TableDefinition<'static, Bytes, Bytes> = TableDefinition::new("utxo");
/// アクティブチェーン。高さ → ハッシュ。
const ACTIVE: TableDefinition<'static, u64, Bytes> = TableDefinition::new("active_chain");
/// その他の記録。
const META: TableDefinition<'static, &'static str, Bytes> = TableDefinition::new("meta");

const META_TIP: &str = "tip";

/// 記憶域の操作で起きうる誤り。
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// データベースの操作に失敗した。
    #[error("データベースの操作に失敗した: {0}")]
    Db(String),
    /// 保存されていた値を復号できなかった。データベースの破損を意味する。
    #[error("保存されていた値を復号できない (データベースの破損): {0}")]
    Corrupt(#[from] CodecError),
    /// UTXO セットの操作に失敗した。
    #[error(transparent)]
    Utxo(#[from] UtxoError),
    /// 先端が記録されていない。
    #[error("先端が記録されていない")]
    NoTip,
    /// ブロック本体を保持していない。
    #[error("ブロック {0} の本体を保持していない")]
    MissingBlock(Hash),
    /// 巻き戻し情報を保持していない。
    #[error("ブロック {0} の巻き戻し情報を保持していない")]
    MissingUndo(Hash),
    /// 入出力に失敗した。
    #[error("入出力に失敗した: {0}")]
    Io(String),
}

fn db_err<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Db(e.to_string())
}

/// 書き込みトランザクション内の UTXO テーブルを [`UtxoWrite`] として見せる。
///
/// これにより、適用と巻き戻しのロジックをメモリ実装と共有できる
/// ([`apply_block_to`] / [`undo_block_from`])。二重に実装すると、
/// メモリ版と DB 版で挙動が食い違ったときに帳簿が分裂する。
struct TableUtxo<'a, 'txn> {
    table: &'a mut redb::Table<'txn, Bytes, Bytes>,
}

impl UtxoView for TableUtxo<'_, '_> {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, UtxoError> {
        let key = outpoint.encode();
        match self.table.get(key.as_slice()) {
            Ok(Some(guard)) => UtxoEntry::decode(guard.value())
                .map(Some)
                .map_err(|e| UtxoError::Backend(e.to_string())),
            Ok(None) => Ok(None),
            Err(e) => Err(UtxoError::Backend(e.to_string())),
        }
    }
}

impl UtxoWrite for TableUtxo<'_, '_> {
    fn insert(&mut self, outpoint: OutPoint, entry: UtxoEntry) -> Result<(), UtxoError> {
        if self.get(&outpoint)?.is_some() {
            return Err(UtxoError::DuplicateUtxo(outpoint));
        }
        let key = outpoint.encode();
        let value = entry.encode();
        self.table
            .insert(key.as_slice(), value.as_slice())
            .map(|_| ())
            .map_err(|e| UtxoError::Backend(e.to_string()))
    }

    fn remove(&mut self, outpoint: &OutPoint) -> Result<UtxoEntry, UtxoError> {
        let key = outpoint.encode();
        match self.table.remove(key.as_slice()) {
            Ok(Some(guard)) => {
                UtxoEntry::decode(guard.value()).map_err(|e| UtxoError::Backend(e.to_string()))
            }
            Ok(None) => Err(UtxoError::MissingUtxo(*outpoint)),
            Err(e) => Err(UtxoError::Backend(e.to_string())),
        }
    }
}

/// 読み取り専用の UTXO ビュー。
///
/// 取得した時点のスナップショットを見る。以降の書き込みには影響されない。
pub struct StoreView {
    table: redb::ReadOnlyTable<Bytes, Bytes>,
}

impl UtxoView for StoreView {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, UtxoError> {
        let key = outpoint.encode();
        match self.table.get(key.as_slice()) {
            Ok(Some(guard)) => UtxoEntry::decode(guard.value())
                .map(Some)
                .map_err(|e| UtxoError::Backend(e.to_string())),
            Ok(None) => Ok(None),
            Err(e) => Err(UtxoError::Backend(e.to_string())),
        }
    }
}

/// 永続化された記憶域。
pub struct Store {
    db: Database,
}

impl Store {
    /// データベースを作る、または既存のものを開く。
    pub fn open(path: impl AsRef<Path>) -> Result<Store, StoreError> {
        let db = Database::create(path).map_err(db_err)?;
        // すべてのテーブルを作っておく。読み取り時に存在しないと誤りになるため。
        let txn = db.begin_write().map_err(db_err)?;
        txn.open_table(BLOCKS).map_err(db_err)?;
        txn.open_table(INDEX).map_err(db_err)?;
        txn.open_table(UNDO).map_err(db_err)?;
        txn.open_table(UTXO).map_err(db_err)?;
        txn.open_table(ACTIVE).map_err(db_err)?;
        txn.open_table(META).map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(Store { db })
    }

    /// 読み取り用の UTXO ビューを得る。
    pub fn utxo_view(&self) -> Result<StoreView, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(UTXO).map_err(db_err)?;
        Ok(StoreView { table })
    }

    /// アクティブチェーンの先端。
    pub fn tip(&self) -> Result<Option<Hash>, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let meta = txn.open_table(META).map_err(db_err)?;
        match meta.get(META_TIP).map_err(db_err)? {
            Some(guard) => Ok(Some(
                Hash::from_slice(guard.value()).map_err(|_| StoreError::NoTip)?,
            )),
            None => Ok(None),
        }
    }

    /// ブロック本体を読む。
    pub fn block(&self, hash: &Hash) -> Result<Option<Block>, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(BLOCKS).map_err(db_err)?;
        match table.get(hash.as_bytes().as_slice()).map_err(db_err)? {
            Some(guard) => Ok(Some(Block::decode(guard.value())?)),
            None => Ok(None),
        }
    }

    /// インデックスの 1 件を読む。
    pub fn index_entry(&self, hash: &Hash) -> Result<Option<BlockIndexEntry>, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(INDEX).map_err(db_err)?;
        match table.get(hash.as_bytes().as_slice()).map_err(db_err)? {
            Some(guard) => Ok(Some(BlockIndexEntry::decode(guard.value())?)),
            None => Ok(None),
        }
    }

    /// インデックスの全件を読む。起動時にチェーンを組み立てるために用いる。
    pub fn all_index_entries(&self) -> Result<Vec<BlockIndexEntry>, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(INDEX).map_err(db_err)?;
        let mut out = Vec::new();
        for row in table.iter().map_err(db_err)? {
            let (_, value) = row.map_err(db_err)?;
            out.push(BlockIndexEntry::decode(value.value())?);
        }
        Ok(out)
    }

    /// アクティブチェーンの指定した高さのブロックハッシュ。
    pub fn hash_at_height(&self, height: u64) -> Result<Option<Hash>, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(ACTIVE).map_err(db_err)?;
        match table.get(height).map_err(db_err)? {
            Some(guard) => Ok(Some(
                Hash::from_slice(guard.value()).map_err(|_| StoreError::NoTip)?,
            )),
            None => Ok(None),
        }
    }

    /// アクティブチェーンの高さ。ジェネシスのみなら 0。
    pub fn height(&self) -> Result<Option<u64>, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(ACTIVE).map_err(db_err)?;
        let last = table.last().map_err(db_err)?;
        Ok(last.map(|(k, _)| k.value()))
    }

    /// UTXO の件数。
    pub fn utxo_count(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(UTXO).map_err(db_err)?;
        table.len().map_err(db_err)
    }

    /// ブロック本体とインデックスを記録する。アクティブチェーンには繋がない。
    ///
    /// 受け取ったがまだ接続していないブロック (サイドチェーン) に用いる。
    pub fn put_block(&self, block: &Block, entry: &BlockIndexEntry) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let key = entry.hash.to_bytes();
            let mut blocks = txn.open_table(BLOCKS).map_err(db_err)?;
            blocks
                .insert(key.as_slice(), block.encode().as_slice())
                .map_err(db_err)?;
            let mut index = txn.open_table(INDEX).map_err(db_err)?;
            index
                .insert(key.as_slice(), entry.encode().as_slice())
                .map_err(db_err)?;
        }
        txn.commit().map_err(db_err)
    }

    /// インデックスの 1 件を更新する。
    pub fn put_index_entry(&self, entry: &BlockIndexEntry) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut index = txn.open_table(INDEX).map_err(db_err)?;
            index
                .insert(entry.hash.to_bytes().as_slice(), entry.encode().as_slice())
                .map_err(db_err)?;
        }
        txn.commit().map_err(db_err)
    }

    /// ブロックをアクティブチェーンに接続する。
    ///
    /// UTXO セットの更新、巻き戻し情報の保存、アクティブチェーンへの追加、
    /// 先端の更新を **1 つのトランザクション**で行う。途中で電源が落ちても
    /// すべて反映されるか、まったく反映されないかのどちらかになる。
    ///
    /// 呼び出し側は事前に検証を済ませていなければならない。
    pub fn connect_block(&self, block: &Block) -> Result<UndoBlock, StoreError> {
        let hash = block.header.hash();
        let height = block.header.height;
        let txn = self.db.begin_write().map_err(db_err)?;

        let undo = {
            let mut utxo_table = txn.open_table(UTXO).map_err(db_err)?;
            let mut utxo = TableUtxo {
                table: &mut utxo_table,
            };
            apply_block_to(&mut utxo, &block.transactions, height)?
        };

        {
            let key = hash.to_bytes();
            let mut undo_table = txn.open_table(UNDO).map_err(db_err)?;
            undo_table
                .insert(key.as_slice(), undo.encode().as_slice())
                .map_err(db_err)?;

            let mut active = txn.open_table(ACTIVE).map_err(db_err)?;
            active.insert(height, key.as_slice()).map_err(db_err)?;

            let mut meta = txn.open_table(META).map_err(db_err)?;
            meta.insert(META_TIP, key.as_slice()).map_err(db_err)?;
        }

        txn.commit().map_err(db_err)?;
        Ok(undo)
    }

    /// 先端のブロックを取り消す。
    ///
    /// 接続と同様、すべて 1 つのトランザクションで行う。
    pub fn disconnect_tip(&self) -> Result<Hash, StoreError> {
        let tip = self.tip()?.ok_or(StoreError::NoTip)?;
        let entry = self
            .index_entry(&tip)?
            .ok_or(StoreError::MissingBlock(tip))?;

        let txn = self.db.begin_write().map_err(db_err)?;

        let undo = {
            let undo_table = txn.open_table(UNDO).map_err(db_err)?;
            let guard = undo_table
                .get(tip.to_bytes().as_slice())
                .map_err(db_err)?
                .ok_or(StoreError::MissingUndo(tip))?;
            UndoBlock::decode(guard.value())?
        };

        {
            let mut utxo_table = txn.open_table(UTXO).map_err(db_err)?;
            let mut utxo = TableUtxo {
                table: &mut utxo_table,
            };
            undo_block_from(&mut utxo, &undo)?;
        }

        {
            let mut active = txn.open_table(ACTIVE).map_err(db_err)?;
            active.remove(entry.height()).map_err(db_err)?;

            let mut meta = txn.open_table(META).map_err(db_err)?;
            if entry.height() == 0 {
                meta.remove(META_TIP).map_err(db_err)?;
            } else {
                meta.insert(META_TIP, entry.prev_hash().to_bytes().as_slice())
                    .map_err(db_err)?;
            }
        }

        txn.commit().map_err(db_err)?;
        Ok(tip)
    }

    /// アクティブチェーンのブロックをファイルに書き出す。
    ///
    /// `<dir>/<高さ>/<ブロックハッシュ>.dat` に 1 ブロックずつ置く。
    /// **これは確認用であり、正典ではない。** 高さごとのディレクトリは
    /// 同じ高さに複数のブロックが並ぶ状況を自然に表せるが、1 ブロック
    /// 1 ファイルはディスクと inode を大量に消費するため、
    /// 記憶域そのものには用いない (このクレートの冒頭の説明を参照)。
    ///
    /// 書き出したブロック数を返す。
    pub fn export_blocks(&self, dir: impl AsRef<Path>) -> Result<usize, StoreError> {
        let dir = dir.as_ref();
        let txn = self.db.begin_read().map_err(db_err)?;
        let active = txn.open_table(ACTIVE).map_err(db_err)?;
        let blocks = txn.open_table(BLOCKS).map_err(db_err)?;

        let mut count = 0;
        for row in active.iter().map_err(db_err)? {
            let (height, hash_bytes) = row.map_err(db_err)?;
            let hash = Hash::from_slice(hash_bytes.value()).map_err(|_| StoreError::NoTip)?;
            let body = blocks
                .get(hash_bytes.value())
                .map_err(db_err)?
                .ok_or(StoreError::MissingBlock(hash))?;

            let sub = dir.join(height.value().to_string());
            std::fs::create_dir_all(&sub).map_err(|e| StoreError::Io(e.to_string()))?;
            std::fs::write(sub.join(format!("{hash}.dat")), body.value())
                .map_err(|e| StoreError::Io(e.to_string()))?;
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_chain::index::BlockStatus;
    use oag_consensus::lock::Lock;
    use oag_consensus::tx::{encode_coinbase_signature, TxInput, TxOutput, CURRENT_TX_VERSION};
    use oag_consensus::utxo::UtxoSet;
    use oag_consensus::{BlockHeader, Transaction};
    use oag_primitives::{merkle, Amount, SecretKey};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// テストごとに独立した一時ディレクトリ。
    struct TempDb(std::path::PathBuf);

    impl TempDb {
        fn new() -> TempDb {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir =
                std::env::temp_dir().join(format!("oag-store-{}-{n}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            TempDb(dir)
        }

        fn db_path(&self) -> std::path::PathBuf {
            self.0.join("chain.redb")
        }

        fn open(&self) -> Store {
            Store::open(self.db_path()).unwrap()
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn coinbase(height: u64, salt: u64) -> Transaction {
        let mut input = TxInput::new(OutPoint::null());
        input.signature = encode_coinbase_signature(height, &salt.to_le_bytes());
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: vec![TxOutput::new(
                oag_consensus::params::block_subsidy(height),
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            )],
            locktime: 0,
        }
    }

    fn block_at(height: u64, prev: Hash, salt: u64) -> Block {
        let cb = coinbase(height, salt);
        let merkle_root = merkle::merkle_root(&[cb.txid()]).unwrap();
        Block {
            header: BlockHeader {
                version: 0,
                prev_hash: prev,
                merkle_root,
                timestamp: 1_800_000_000 + height as i64 * 60,
                difficulty: 1,
                height,
                nonce: salt,
            },
            transactions: vec![cb],
        }
    }

    fn entry_for(block: &Block, work: u128) -> BlockIndexEntry {
        BlockIndexEntry {
            hash: block.header.hash(),
            header: block.header,
            cumulative_work: work,
            status: BlockStatus::HeaderValid,
        }
    }

    /// 高さ 0 から `count` 個のブロックを繋いだ状態にする。
    fn build(store: &Store, count: u64) -> Vec<Block> {
        let mut blocks = Vec::new();
        let mut prev = Hash::ZERO;
        for height in 0..count {
            let block = block_at(height, prev, height);
            prev = block.header.hash();
            store
                .put_block(&block, &entry_for(&block, u128::from(height) + 1))
                .unwrap();
            store.connect_block(&block).unwrap();
            blocks.push(block);
        }
        blocks
    }

    #[test]
    fn a_fresh_store_is_empty() {
        let tmp = TempDb::new();
        let store = tmp.open();
        assert_eq!(store.tip().unwrap(), None);
        assert_eq!(store.height().unwrap(), None);
        assert_eq!(store.utxo_count().unwrap(), 0);
        assert!(store.all_index_entries().unwrap().is_empty());
    }

    #[test]
    fn blocks_and_index_entries_round_trip() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let block = block_at(0, Hash::ZERO, 1);
        let entry = entry_for(&block, 1);

        store.put_block(&block, &entry).unwrap();
        assert_eq!(store.block(&entry.hash).unwrap().as_ref(), Some(&block));
        assert_eq!(
            store.index_entry(&entry.hash).unwrap().as_ref(),
            Some(&entry)
        );
        assert_eq!(store.all_index_entries().unwrap(), vec![entry]);
    }

    #[test]
    fn connecting_updates_utxo_tip_and_height() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let blocks = build(&store, 3);

        assert_eq!(store.height().unwrap(), Some(2));
        assert_eq!(store.tip().unwrap(), Some(blocks[2].header.hash()));
        assert_eq!(store.utxo_count().unwrap(), 3);
        for (height, block) in blocks.iter().enumerate() {
            assert_eq!(
                store.hash_at_height(height as u64).unwrap(),
                Some(block.header.hash())
            );
        }
    }

    #[test]
    fn disconnecting_restores_the_previous_state() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let blocks = build(&store, 3);

        let removed = store.disconnect_tip().unwrap();
        assert_eq!(removed, blocks[2].header.hash());
        assert_eq!(store.height().unwrap(), Some(1));
        assert_eq!(store.tip().unwrap(), Some(blocks[1].header.hash()));
        assert_eq!(store.utxo_count().unwrap(), 2);

        // 取り消された分の出力が消えていること。
        let view = store.utxo_view().unwrap();
        let gone = OutPoint::new(blocks[2].transactions[0].txid(), 0);
        assert_eq!(view.get(&gone).unwrap(), None);
    }

    #[test]
    fn the_memory_and_persistent_backends_agree() {
        // 同じ手順を踏んだとき、メモリ実装と DB 実装が同じ UTXO セットに
        // 行き着くこと。食い違えば帳簿が分裂する。
        let tmp = TempDb::new();
        let store = tmp.open();
        let blocks = build(&store, 8);

        let mut memory = UtxoSet::new();
        for block in &blocks {
            memory
                .apply_block(&block.transactions, block.header.height)
                .unwrap();
        }

        assert_eq!(store.utxo_count().unwrap(), memory.len() as u64);
        let view = store.utxo_view().unwrap();
        for block in &blocks {
            let outpoint = OutPoint::new(block.transactions[0].txid(), 0);
            assert_eq!(
                view.get(&outpoint).unwrap(),
                memory.get(&outpoint).unwrap(),
                "高さ {} で食い違った",
                block.header.height
            );
        }

        // 巻き戻しでも一致すること。
        drop(view);
        store.disconnect_tip().unwrap();
        let undo_target = blocks.last().unwrap();
        let mut memory2 = UtxoSet::new();
        for block in &blocks[..blocks.len() - 1] {
            memory2
                .apply_block(&block.transactions, block.header.height)
                .unwrap();
        }
        assert_eq!(store.utxo_count().unwrap(), memory2.len() as u64);
        let view = store.utxo_view().unwrap();
        let gone = OutPoint::new(undo_target.transactions[0].txid(), 0);
        assert_eq!(view.get(&gone).unwrap(), None);
        assert_eq!(memory2.get(&gone).unwrap(), None);
    }

    // ━━━━━━━━ 原子性と永続性 ━━━━━━━━

    #[test]
    fn a_failed_connect_changes_nothing() {
        // 存在しない UTXO を使うブロックを繋ごうとする。
        // トランザクションが commit されないので、何も変わってはならない。
        let tmp = TempDb::new();
        let store = tmp.open();
        let blocks = build(&store, 2);

        let tip_before = store.tip().unwrap();
        let height_before = store.height().unwrap();
        let count_before = store.utxo_count().unwrap();

        let mut bad = block_at(2, blocks[1].header.hash(), 99);
        let ghost = OutPoint::new(oag_primitives::hash::txid(b"ghost"), 0);
        bad.transactions.push(Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput::new(ghost)],
            outputs: vec![TxOutput::new(
                Amount::ONE_OAG,
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            )],
            locktime: 0,
        });

        assert!(store.connect_block(&bad).is_err());
        assert_eq!(store.tip().unwrap(), tip_before, "先端が動いている");
        assert_eq!(store.height().unwrap(), height_before);
        assert_eq!(
            store.utxo_count().unwrap(),
            count_before,
            "コインベース出力だけが書き込まれてしまっている"
        );
    }

    #[test]
    fn the_state_survives_a_reopen() {
        let tmp = TempDb::new();
        let (tip, height, count, first_hash) = {
            let store = tmp.open();
            let blocks = build(&store, 5);
            (
                store.tip().unwrap(),
                store.height().unwrap(),
                store.utxo_count().unwrap(),
                blocks[0].header.hash(),
            )
        };

        // 閉じて開き直す。
        let store = tmp.open();
        assert_eq!(store.tip().unwrap(), tip);
        assert_eq!(store.height().unwrap(), height);
        assert_eq!(store.utxo_count().unwrap(), count);
        assert_eq!(store.all_index_entries().unwrap().len(), 5);
        assert!(store.block(&first_hash).unwrap().is_some());
    }

    #[test]
    fn the_utxo_set_survives_a_reopen() {
        let tmp = TempDb::new();
        let outpoint = {
            let store = tmp.open();
            let blocks = build(&store, 3);
            OutPoint::new(blocks[1].transactions[0].txid(), 0)
        };

        let store = tmp.open();
        let view = store.utxo_view().unwrap();
        let entry = view.get(&outpoint).unwrap().expect("残っている");
        assert_eq!(entry.height, 1);
        assert!(entry.is_coinbase);
        assert_eq!(entry.output.amount, oag_consensus::params::BLOCK_REWARD);
    }

    #[test]
    fn a_read_view_is_a_snapshot() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let blocks = build(&store, 2);
        let outpoint = OutPoint::new(blocks[1].transactions[0].txid(), 0);

        let view = store.utxo_view().unwrap();
        assert!(view.get(&outpoint).unwrap().is_some());

        // ビューを持ったまま先端を取り消しても、ビューは元の状態を見続ける。
        store.disconnect_tip().unwrap();
        assert!(
            view.get(&outpoint).unwrap().is_some(),
            "読み取りビューが書き込みの影響を受けている"
        );

        let fresh = store.utxo_view().unwrap();
        assert!(fresh.get(&outpoint).unwrap().is_none());
    }

    // ━━━━━━━━ エクスポート ━━━━━━━━

    #[test]
    fn export_writes_one_file_per_block_under_its_height() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let blocks = build(&store, 4);

        let out = tmp.0.join("block");
        assert_eq!(store.export_blocks(&out).unwrap(), 4);

        for (height, block) in blocks.iter().enumerate() {
            let hash = block.header.hash();
            let path = out.join(height.to_string()).join(format!("{hash}.dat"));
            assert!(path.exists(), "{} が無い", path.display());
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(
                Block::decode(&bytes).unwrap(),
                *block,
                "書き出した内容が元のブロックと一致しない"
            );
        }
    }
}
