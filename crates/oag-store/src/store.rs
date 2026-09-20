//! redb を用いた記憶域。

use oag_chain::index::BlockIndexEntry;
use oag_consensus::block::BLOCK_HEADER_LEN;
use oag_consensus::codec::{CodecError, Decode, Encode, Reader};
use oag_consensus::lock::Lock;
use oag_consensus::tx::OutPoint;
use oag_consensus::tx::TxOutput;
use oag_consensus::utxo::{
    apply_block_to, undo_block_from, UndoBlock, UtxoEntry, UtxoError, UtxoView, UtxoWrite,
};
use oag_consensus::{Block, BlockHeader, Transaction};
use oag_primitives::hash::HASH_LEN;
use oag_primitives::Hash;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::collections::HashMap;
use std::path::Path;

use crate::txindex::{self, KEY_LEN};

type Bytes = &'static [u8];

/// ブロック本体。ハッシュ → シリアライズしたブロック。
const BLOCKS: TableDefinition<'static, Bytes, Bytes> = TableDefinition::new("blocks");
/// ブロックインデックス。ハッシュ → インデックスの 1 件。
const INDEX: TableDefinition<'static, Bytes, Bytes> = TableDefinition::new("block_index");
/// 親 → 子。親のハッシュ → 子のハッシュを並べたもの (32 バイト区切り)。
///
/// インデックスの `prev_hash` を逆から引いただけの派生物である。
/// **メモリではなくここに置くのは、高さに比例して伸びるためである**
/// (SPEC §19)。引くのは無効の印を子孫へ広げるときだけで、滅多に起きない。
const CHILDREN: TableDefinition<'static, Bytes, Bytes> = TableDefinition::new("block_children");
/// 巻き戻し情報。ハッシュ → 巻き戻し情報。
const UNDO: TableDefinition<'static, Bytes, Bytes> = TableDefinition::new("undo");
/// UTXO セット。出力参照 → UTXO の内容。
const UTXO: TableDefinition<'static, Bytes, Bytes> = TableDefinition::new("utxo");
/// アクティブチェーン。高さ → ハッシュ。
const ACTIVE: TableDefinition<'static, u64, Bytes> = TableDefinition::new("active_chain");
/// その他の記録。
const META: TableDefinition<'static, &'static str, Bytes> = TableDefinition::new("meta");
/// 取引索引。txid の接頭辞 ++ 高さ ++ 位置 → なし。
///
/// **既定では空である。** 運用者が索引を有効にしたときだけ作られる
/// (SPEC §19)。値を持たないのは、鍵そのものが位置を表すためである。
const TX_INDEX: TableDefinition<'static, Bytes, ()> = TableDefinition::new("tx_index");
/// アドレス索引。lock の接頭辞 ++ 高さ ++ 位置 → なし。
///
/// 同じく既定では空である。1 つの取引が同じアドレスへ複数の出力を持つ
/// 場合、鍵は同一になって 1 件に潰れる。**それでよい。** ここが答える
/// のは「どの取引がこのアドレスに触れたか」であって、何回触れたかは
/// 取引そのものを読めば分かる。
const ADDR_INDEX: TableDefinition<'static, Bytes, ()> = TableDefinition::new("addr_index");

const META_TIP: &str = "tip";
/// 索引がどの高さから作られているか。**この鍵が無ければ索引は無い。**
///
/// 値が 0 なら索引はジェネシスから揃っている。0 でない値は「途中から
/// 作られた索引」であり、照会は答えを返してはならない。足りない範囲を
/// 黙って省いた履歴は、無い履歴より悪い。利用者はそれを信じてしまう。
const META_INDEX_FROM: &str = "index_from";

/// 親から子への線を 1 本張る。**同じ子を二重に入れない。**
///
/// ジェネシスは親を持たないので張らない。同じブロックのインデックスは
/// 状態が変わるたびに書き直されるため、二重に入らないことが要る。
fn link_child(
    children: &mut redb::Table<'_, Bytes, Bytes>,
    entry: &BlockIndexEntry,
) -> Result<(), StoreError> {
    if entry.height() == 0 {
        return Ok(());
    }
    let parent = entry.prev_hash().to_bytes();
    let child = entry.hash.to_bytes();
    let mut list = match children.get(parent.as_slice()).map_err(db_err)? {
        Some(guard) => guard.value().to_vec(),
        None => Vec::new(),
    };
    if list.as_chunks::<HASH_LEN>().0.contains(&child) {
        return Ok(());
    }
    list.extend_from_slice(&child);
    children
        .insert(parent.as_slice(), list.as_slice())
        .map_err(db_err)?;
    Ok(())
}

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
    /// 索引を持っていない。
    #[error("索引を持っていない (--index を付けて起動すること)")]
    NoIndex,
    /// 索引が途中からしか無い。
    #[error("索引は高さ {0} からしか無い。組み直しが要る")]
    PartialIndex(u64),
    /// 索引の鍵に収まらない値があった。
    #[error(transparent)]
    Key(#[from] crate::txindex::KeyError),
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

// ━━━━━━━━ 索引 ━━━━━━━━

/// ブロック 1 個分の索引の鍵。`(取引索引, アドレス索引)`。
type IndexKeys = (Vec<[u8; KEY_LEN]>, Vec<[u8; KEY_LEN]>);

/// ブロック 1 個分の索引の鍵。
///
/// `(取引索引の鍵, アドレス索引の鍵)` を返す。接続でも切断でも**同じ関数
/// から作る**。別々に書くと、入れた鍵と消す鍵が食い違ったときに索引へ
/// ごみが残り、それは二度と消えない。
fn index_keys(block: &Block, undo: &UndoBlock, height: u64) -> Result<IndexKeys, StoreError> {
    // 入力は OutPoint しか名乗らない。「誰のコインを使ったか」は消費された
    // 出力を見なければ分からず、その出力は UTXO セットから既に消えている。
    // 巻き戻し情報が唯一の手掛かりである。
    let mut spent: HashMap<([u8; 32], u32), &Lock> = HashMap::new();
    for (outpoint, entry) in undo.spent() {
        spent.insert(
            (outpoint.txid.to_bytes(), outpoint.index),
            &entry.output.lock,
        );
    }

    let mut tx_keys = Vec::with_capacity(block.transactions.len());
    let mut addr_keys = Vec::new();

    for (position, tx) in block.transactions.iter().enumerate() {
        let txid = tx.txid();
        tx_keys.push(txindex::key(txindex::tx_prefix(&txid), height, position)?);

        for output in &tx.outputs {
            addr_keys.push(txindex::key(
                txindex::lock_prefix(&output.lock),
                height,
                position,
            )?);
        }
        for input in &tx.inputs {
            // コインベースの空参照は何も消費していない。巻き戻し情報にも
            // 載らないので、ここで自然に外れる。
            let Some(lock) = spent.get(&(input.prev_out.txid.to_bytes(), input.prev_out.index))
            else {
                continue;
            };
            addr_keys.push(txindex::key(txindex::lock_prefix(lock), height, position)?);
        }
    }

    Ok((tx_keys, addr_keys))
}

/// ブロックを索引に加える。呼び出し側の書き込みトランザクションの中で行う。
fn write_index(
    txn: &redb::WriteTransaction,
    block: &Block,
    undo: &UndoBlock,
    height: u64,
) -> Result<(), StoreError> {
    let (tx_keys, addr_keys) = index_keys(block, undo, height)?;
    let mut tx_table = txn.open_table(TX_INDEX).map_err(db_err)?;
    for key in &tx_keys {
        tx_table.insert(key.as_slice(), ()).map_err(db_err)?;
    }
    let mut addr_table = txn.open_table(ADDR_INDEX).map_err(db_err)?;
    for key in &addr_keys {
        addr_table.insert(key.as_slice(), ()).map_err(db_err)?;
    }
    Ok(())
}

/// ブロックを索引から取り除く。リオーグで用いる。
fn erase_index(
    txn: &redb::WriteTransaction,
    block: &Block,
    undo: &UndoBlock,
    height: u64,
) -> Result<(), StoreError> {
    let (tx_keys, addr_keys) = index_keys(block, undo, height)?;
    let mut tx_table = txn.open_table(TX_INDEX).map_err(db_err)?;
    for key in &tx_keys {
        tx_table.remove(key.as_slice()).map_err(db_err)?;
    }
    let mut addr_table = txn.open_table(ADDR_INDEX).map_err(db_err)?;
    for key in &addr_keys {
        addr_table.remove(key.as_slice()).map_err(db_err)?;
    }
    Ok(())
}

/// META から索引の状態を読む。
fn index_from_in<T: ReadableTable<&'static str, Bytes>>(
    meta: &T,
) -> Result<Option<u64>, StoreError> {
    match meta.get(META_INDEX_FROM).map_err(db_err)? {
        Some(guard) => {
            let bytes: [u8; 8] = guard
                .value()
                .try_into()
                .map_err(|_| StoreError::Db("索引の記録が壊れている".to_string()))?;
            Ok(Some(u64::from_le_bytes(bytes)))
        }
        None => Ok(None),
    }
}

/// 索引が指し示した取引の位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxLocation {
    /// 取引の ID。
    pub txid: Hash,
    /// 入っているブロックの高さ。
    pub height: u64,
    /// ブロック内の並び順。0 はコインベースである。
    pub position: usize,
    /// 入っているブロックのハッシュ。
    pub block: Hash,
}

/// 一覧に並べるための、ブロック 1 個の要約。
///
/// # なぜ本体を返さないのか
///
/// 一覧が要るのは高さ・時刻・難易度・取引数・大きさだけである。ところが
/// 本体を丸ごと復号すると、**表に出さない取引まで全部組み立ててしまう**。
/// 満杯のブロック (200 KB, 約 670 取引) を 25 個並べると、25 行を描く
/// ために 16,000 件あまりの [`Transaction`] を確保して即座に捨てることに
/// なる。
///
/// 上の 3 つはブロックインデックスのヘッダにある。残る 2 つも、保存して
/// あるバイト列から**復号せずに**取れる。大きさは記録の長さそのもので、
/// 取引数はヘッダ直後の varint 1 個である。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSummary {
    /// アクティブチェーン上の高さ。
    pub height: u64,
    /// ブロックハッシュ。
    pub hash: Hash,
    /// ヘッダ。時刻と難易度はここから取る。
    pub header: BlockHeader,
    /// 入っている取引の数。
    pub transactions: usize,
    /// 符号化した大きさ (バイト)。
    pub size: usize,
}

/// 索引を組み直した結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IndexStats {
    /// 索引したブロック数。
    pub blocks: u64,
    /// 索引した取引数。
    pub transactions: u64,
    /// アドレス索引に入れた件数。
    pub addr_entries: u64,
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
        txn.open_table(CHILDREN).map_err(db_err)?;
        txn.open_table(UNDO).map_err(db_err)?;
        txn.open_table(UTXO).map_err(db_err)?;
        txn.open_table(ACTIVE).map_err(db_err)?;
        txn.open_table(META).map_err(db_err)?;
        txn.open_table(TX_INDEX).map_err(db_err)?;
        txn.open_table(ADDR_INDEX).map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        let store = Store { db };
        store.rebuild_children_if_missing()?;
        Ok(store)
    }

    /// 親子の表が無ければ、インデックスから組み直す。
    ///
    /// この表より前に作られた記憶域を開いたときに 1 度だけ走る。
    /// **組み直さないと、無効の印が子孫へ広がらなくなる。**
    fn rebuild_children_if_missing(&self) -> Result<(), StoreError> {
        {
            let txn = self.db.begin_read().map_err(db_err)?;
            let children = txn.open_table(CHILDREN).map_err(db_err)?;
            let index = txn.open_table(INDEX).map_err(db_err)?;
            // ジェネシスしか無いときは、張る線がそもそも無い。
            if !children.is_empty().map_err(db_err)? || index.len().map_err(db_err)? <= 1 {
                return Ok(());
            }
        }
        let entries = self.all_index_entries()?;
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut children = txn.open_table(CHILDREN).map_err(db_err)?;
            for entry in &entries {
                link_child(&mut children, entry)?;
            }
        }
        txn.commit().map_err(db_err)
    }

    /// `hash` を親とするブロック。
    pub fn children_of(&self, hash: &Hash) -> Result<Vec<Hash>, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(CHILDREN).map_err(db_err)?;
        let Some(guard) = table.get(hash.as_bytes().as_slice()).map_err(db_err)? else {
            return Ok(Vec::new());
        };
        // 端数は切り捨てられる。**書くのは 32 バイト単位だけ**なので、
        // 端数が出ている時点で記憶域が壊れている。
        Ok(guard
            .value()
            .as_chunks::<HASH_LEN>()
            .0
            .iter()
            .map(|c| Hash::from_bytes(*c))
            .collect())
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

    /// インデックスに入っている件数。
    pub fn index_len(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(INDEX).map_err(db_err)?;
        table.len().map_err(db_err)
    }

    /// インデックスを 1 件ずつ渡す。**全件を同時にメモリへ載せない。**
    pub fn for_each_index_entry(
        &self,
        f: &mut dyn FnMut(BlockIndexEntry),
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(INDEX).map_err(db_err)?;
        for row in table.iter().map_err(db_err)? {
            let (_, value) = row.map_err(db_err)?;
            f(BlockIndexEntry::decode(value.value())?);
        }
        Ok(())
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

    /// 先端から遡って `max` 件ぶんの要約を、**新しい順に**返す。
    ///
    /// # なぜ 1 つの呼び出しにまとめるのか
    ///
    /// 呼ぶ側 (エクスプローラの一覧) は高さごとにハッシュを引き、次に
    /// ブロックを引く、を繰り返していた。25 行で 50 往復になるうえ、
    /// **1 往復ごとに別の読み取りトランザクションを張る**ので、描いて
    /// いる途中にブロックが届くと上の行と下の行が違う時点を映す。
    ///
    /// ここでまとめると往復は 1 回、断面も 1 つになる。
    ///
    /// 本体は [`Block::decode`] に渡さない。要約に必要な 2 つの数は、
    /// 保存してあるバイト列から直に取れる ([`BlockSummary`])。
    pub fn recent_summaries(&self, max: usize) -> Result<Vec<BlockSummary>, StoreError> {
        if max == 0 {
            return Ok(Vec::new());
        }
        let txn = self.db.begin_read().map_err(db_err)?;
        let active = txn.open_table(ACTIVE).map_err(db_err)?;
        let index = txn.open_table(INDEX).map_err(db_err)?;
        let blocks = txn.open_table(BLOCKS).map_err(db_err)?;

        let mut out = Vec::new();
        for row in active.iter().map_err(db_err)?.rev() {
            if out.len() == max {
                break;
            }
            let (height, hash_bytes) = row.map_err(db_err)?;
            let hash = Hash::from_slice(hash_bytes.value()).map_err(|_| StoreError::NoTip)?;

            let Some(entry) = index.get(hash.as_bytes().as_slice()).map_err(db_err)? else {
                continue;
            };
            let header = BlockIndexEntry::decode(entry.value())?.header;

            let Some(body) = blocks.get(hash.as_bytes().as_slice()).map_err(db_err)? else {
                continue;
            };
            let raw = body.value();
            let size = raw.len();
            // ヘッダの直後に取引数の varint が 1 個。そこまでで読むのをやめる。
            let rest = raw
                .get(BLOCK_HEADER_LEN..)
                .ok_or_else(|| StoreError::Db(format!("ブロック {hash} の記録がヘッダより短い")))?;
            let transactions = Reader::new(rest).read_count::<Transaction>("block.transactions")?;

            out.push(BlockSummary {
                height: height.value(),
                hash,
                header,
                transactions,
                size,
            });
        }
        Ok(out)
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

    /// 支払い条件が一致する UTXO を集める。
    ///
    /// # なぜ全件走査なのか
    ///
    /// 支払い条件から UTXO を引く索引を持っていないためである
    /// (`docs/SPEC.md` の未決事項)。ウォレットが自分の残高を知るには、
    /// **UTXO セットを丸ごと見て自分のものを拾う**しかない。
    /// bitcoind の `scantxoutset` と同じ方式である。
    ///
    /// 索引を持たない代わりに、記憶域はコンセンサスが必要とするものだけで
    /// 済んでいる。走査は UTXO セットの大きさに比例し、その大きさは
    /// チェーンの長さではなく**使われていない出力の数**で決まる。
    ///
    /// `max` 件見つけたところで打ち切る。
    pub fn scan_utxos(
        &self,
        wanted: &[Lock],
        max: usize,
    ) -> Result<Vec<(OutPoint, UtxoEntry)>, StoreError> {
        if wanted.is_empty() || max == 0 {
            return Ok(Vec::new());
        }
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(UTXO).map_err(db_err)?;

        let mut found = Vec::new();
        for row in table.iter().map_err(db_err)? {
            let (key, value) = row.map_err(db_err)?;
            let entry = UtxoEntry::decode(value.value())?;
            if !wanted.contains(&entry.output.lock) {
                continue;
            }
            found.push((OutPoint::decode(key.value())?, entry));
            if found.len() >= max {
                break;
            }
        }
        Ok(found)
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
            let mut children = txn.open_table(CHILDREN).map_err(db_err)?;
            link_child(&mut children, entry)?;
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
            let mut children = txn.open_table(CHILDREN).map_err(db_err)?;
            link_child(&mut children, entry)?;
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

        let indexed = {
            let meta = txn.open_table(META).map_err(db_err)?;
            index_from_in(&meta)?.is_some()
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

        // 索引も同じトランザクションの中で更新する。**別に分けてはならない。**
        // 分けると「UTXO は進んだが索引は古い」状態が存在しうるようになり、
        // 電源が落ちるたびにその食い違いを直す仕掛けが要る。ここに入れて
        // おけば、索引は常に UTXO セットと同じ地点を指している。
        if indexed {
            write_index(&txn, block, &undo, height)?;
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

        let indexed = {
            let meta = txn.open_table(META).map_err(db_err)?;
            index_from_in(&meta)?.is_some()
        };

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

        // 索引からも同じブロックの分を取り除く。接続と同じ関数で鍵を
        // 作っているので、入れたものと消すものは必ず一致する。
        if indexed {
            let block = {
                let blocks = txn.open_table(BLOCKS).map_err(db_err)?;
                let guard = blocks
                    .get(tip.to_bytes().as_slice())
                    .map_err(db_err)?
                    .ok_or(StoreError::MissingBlock(tip))?;
                Block::decode(guard.value())?
            };
            erase_index(&txn, &block, &undo, entry.height())?;
        }

        txn.commit().map_err(db_err)?;
        Ok(tip)
    }

    // ━━━━━━━━ 索引 ━━━━━━━━

    /// 索引がどの高さから作られているか。持っていなければ `None`。
    pub fn index_from(&self) -> Result<Option<u64>, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let meta = txn.open_table(META).map_err(db_err)?;
        index_from_in(&meta)
    }

    /// 索引がジェネシスから揃っているか確かめる。
    ///
    /// 揃っていなければ理由を誤りとして返す。**照会の入口で必ず通す。**
    fn require_index(&self) -> Result<(), StoreError> {
        match self.index_from()? {
            Some(0) => Ok(()),
            Some(from) => Err(StoreError::PartialIndex(from)),
            None => Err(StoreError::NoIndex),
        }
    }

    /// 索引を作る、または組み直す。
    ///
    /// アクティブチェーンをジェネシスから走査して作り直す。既にあるものは
    /// 捨てる。入力側のアドレスは巻き戻し情報から引く。
    ///
    /// # なぜ 1 つのトランザクションで行うのか
    ///
    /// 途中で電源が落ちたときに**半分だけの索引が残るのが最悪である**。
    /// 索引は「無い」なら照会を断れる。しかし「半分ある」ことを知らなければ、
    /// 欠けた履歴を完全なものとして返してしまう。利用者はそれを信じる。
    ///
    /// 1 つにまとめておけば、索引は必ず「完全にある」か「まったく無い」かの
    /// どちらかになる。区別のつく状態しか作らない。
    pub fn build_index(&self) -> Result<IndexStats, StoreError> {
        let txn = self.db.begin_write().map_err(db_err)?;
        let mut stats = IndexStats::default();

        // 作り直しなので、残っているものは捨てる。索引を縮めたときに
        // 古い鍵が居座ると、消えたはずの取引を指し続ける。
        txn.delete_table(TX_INDEX).map_err(db_err)?;
        txn.delete_table(ADDR_INDEX).map_err(db_err)?;

        let chain: Vec<(u64, Hash)> = {
            let active = txn.open_table(ACTIVE).map_err(db_err)?;
            let mut out = Vec::new();
            for row in active.iter().map_err(db_err)? {
                let (height, hash) = row.map_err(db_err)?;
                let hash = Hash::from_slice(hash.value()).map_err(|_| StoreError::NoTip)?;
                out.push((height.value(), hash));
            }
            out
        };

        {
            let mut tx_table = txn.open_table(TX_INDEX).map_err(db_err)?;
            let mut addr_table = txn.open_table(ADDR_INDEX).map_err(db_err)?;

            for (height, hash) in &chain {
                let (block, undo) = {
                    let blocks = txn.open_table(BLOCKS).map_err(db_err)?;
                    let undo_table = txn.open_table(UNDO).map_err(db_err)?;
                    let block = blocks
                        .get(hash.as_bytes().as_slice())
                        .map_err(db_err)?
                        .ok_or(StoreError::MissingBlock(*hash))?;
                    let block = Block::decode(block.value())?;
                    let undo = undo_table
                        .get(hash.as_bytes().as_slice())
                        .map_err(db_err)?
                        .ok_or(StoreError::MissingUndo(*hash))?;
                    let undo = UndoBlock::decode(undo.value())?;
                    (block, undo)
                };

                let (tx_keys, addr_keys) = index_keys(&block, &undo, *height)?;
                stats.blocks += 1;
                stats.transactions += tx_keys.len() as u64;
                stats.addr_entries += addr_keys.len() as u64;

                for key in &tx_keys {
                    tx_table.insert(key.as_slice(), ()).map_err(db_err)?;
                }
                for key in &addr_keys {
                    addr_table.insert(key.as_slice(), ()).map_err(db_err)?;
                }
            }
        }

        {
            let mut meta = txn.open_table(META).map_err(db_err)?;
            meta.insert(META_INDEX_FROM, 0u64.to_le_bytes().as_slice())
                .map_err(db_err)?;
        }

        txn.commit().map_err(db_err)?;
        Ok(stats)
    }

    /// 索引を捨てる。
    pub fn drop_index(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(db_err)?;
        txn.delete_table(TX_INDEX).map_err(db_err)?;
        txn.delete_table(ADDR_INDEX).map_err(db_err)?;
        txn.open_table(TX_INDEX).map_err(db_err)?;
        txn.open_table(ADDR_INDEX).map_err(db_err)?;
        {
            let mut meta = txn.open_table(META).map_err(db_err)?;
            meta.remove(META_INDEX_FROM).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)
    }

    /// アクティブチェーンの指定した位置の取引を読む。
    pub fn transaction_at(
        &self,
        height: u64,
        position: usize,
    ) -> Result<Option<Transaction>, StoreError> {
        let Some(hash) = self.hash_at_height(height)? else {
            return Ok(None);
        };
        let Some(block) = self.block(&hash)? else {
            return Ok(None);
        };
        Ok(block.transactions.get(position).cloned())
    }

    /// txid から取引の位置を引く。
    ///
    /// 索引の鍵は txid の頭 8 バイトしか持たない。**したがって候補を
    /// 完全な txid と突き合わせる。** 一致したものだけを返す。
    pub fn tx_location(&self, txid: &Hash) -> Result<Option<TxLocation>, StoreError> {
        self.require_index()?;
        let candidates =
            self.candidates(TX_INDEX, txindex::tx_prefix(txid), 0, Self::CANDIDATE_SLACK)?;
        for (height, position) in candidates {
            let Some(tx) = self.transaction_at(height, position)? else {
                continue;
            };
            if tx.txid() != *txid {
                // 接頭辞の衝突。捨てる。
                continue;
            }
            let block = self.hash_at_height(height)?.ok_or(StoreError::NoTip)?;
            return Ok(Some(TxLocation {
                txid: *txid,
                height,
                position,
                block,
            }));
        }
        Ok(None)
    }

    /// 支払い条件に触れた取引を、古い順に引く。
    ///
    /// `from` 以降の高さに絞り、`max` 件で打ち切る。こちらも接頭辞の
    /// 衝突がありうるので、取引を読んで**完全な lock と突き合わせる**。
    pub fn address_history(
        &self,
        lock: &Lock,
        from: u64,
        max: usize,
    ) -> Result<Vec<TxLocation>, StoreError> {
        self.require_index()?;
        let candidates = self.candidates(
            ADDR_INDEX,
            txindex::lock_prefix(lock),
            from,
            max.saturating_add(Self::CANDIDATE_SLACK),
        )?;
        let mut out = Vec::new();
        for (height, position) in candidates {
            let Some(tx) = self.transaction_at(height, position)? else {
                continue;
            };
            if !self.touches(&tx, height, lock)? {
                // 接頭辞の衝突。捨てる。
                continue;
            }
            out.push(TxLocation {
                txid: tx.txid(),
                height,
                position,
                block: self.hash_at_height(height)?.ok_or(StoreError::NoTip)?,
            });
            if out.len() >= max {
                break;
            }
        }
        Ok(out)
    }

    /// 取引の各入力が指している出力を引く。
    ///
    /// エクスプローラが「どこから来た金か」を出すために要る。使われた
    /// 出力は UTXO セットに無いので、その取引が入っているブロックの
    /// 巻き戻し情報から引く。
    ///
    /// 入力と同じ並びで返す。引けなかった入力は `None` になる。コインベース
    /// の空参照は常に `None` である。
    pub fn spent_outputs(
        &self,
        height: u64,
        tx: &Transaction,
    ) -> Result<Vec<Option<TxOutput>>, StoreError> {
        if tx.is_coinbase() {
            return Ok(tx.inputs.iter().map(|_| None).collect());
        }
        let Some(hash) = self.hash_at_height(height)? else {
            return Ok(tx.inputs.iter().map(|_| None).collect());
        };
        let undo = self.undo(&hash)?;
        Ok(tx
            .inputs
            .iter()
            .map(|input| {
                undo.spent()
                    .iter()
                    .find(|(outpoint, _)| *outpoint == input.prev_out)
                    .map(|(_, entry)| entry.output.clone())
            })
            .collect())
    }

    /// その取引が本当にこの支払い条件に触れているか。
    ///
    /// 出力はそのまま見れば分かる。入力が指す出力は UTXO セットから消えて
    /// いるので、**その取引が入っているブロックの巻き戻し情報**から引く。
    /// 索引が高さを教えてくれているので、引くのは 1 ブロック分で足りる。
    fn touches(&self, tx: &Transaction, height: u64, lock: &Lock) -> Result<bool, StoreError> {
        if tx.outputs.iter().any(|o| o.lock == *lock) {
            return Ok(true);
        }
        if tx.is_coinbase() {
            return Ok(false);
        }
        let Some(hash) = self.hash_at_height(height)? else {
            return Ok(false);
        };
        let undo = self.undo(&hash)?;
        Ok(undo.spent().iter().any(|(outpoint, entry)| {
            entry.output.lock == *lock && tx.inputs.iter().any(|i| i.prev_out == *outpoint)
        }))
    }

    /// ブロックの巻き戻し情報を読む。
    fn undo(&self, hash: &Hash) -> Result<UndoBlock, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(UNDO).map_err(db_err)?;
        let guard = table
            .get(hash.as_bytes().as_slice())
            .map_err(db_err)?
            .ok_or(StoreError::MissingUndo(*hash))?;
        Ok(UndoBlock::decode(guard.value())?)
    }

    /// 照合で落ちる分の余裕。
    ///
    /// 候補は接頭辞が一致しただけのもので、照合して落ちることがある。
    /// 欲しい件数ちょうどしか集めないと、落ちた分だけ足りなくなる。
    /// 接頭辞の衝突は 3.5 億件で期待値 0.003 件なので、この余裕は
    /// 現実にはまず使われない。
    const CANDIDATE_SLACK: usize = 64;

    /// 接頭辞が一致する索引の項を、古い順に集める。
    ///
    /// 鍵の作りが同じなので表は引数で受け取る。**取り違えると別の索引を
    /// 読むことになる**ので、呼び出し側は接頭辞と表を必ず揃えること。
    ///
    /// `max` で打ち切る。よく使われるアドレスは索引の項が何百万件にもなり
    /// うるので、**50 件欲しいだけのときに全部を集めてはならない**。
    fn candidates(
        &self,
        which: TableDefinition<'static, Bytes, ()>,
        prefix: [u8; txindex::PREFIX_LEN],
        from: u64,
        max: usize,
    ) -> Result<Vec<(u64, usize)>, StoreError> {
        let (lo, hi) = txindex::range(prefix, from);
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(which).map_err(db_err)?;
        let mut out = Vec::new();
        for row in table.range(lo.as_slice()..=hi.as_slice()).map_err(db_err)? {
            let (key, _) = row.map_err(db_err)?;
            if let Some(pair) = txindex::split(key.value()) {
                out.push(pair);
            }
            if out.len() >= max {
                break;
            }
        }
        Ok(out)
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

// ━━━━━━━━ ChainStore の実装 ━━━━━━━━

impl oag_chain::store::ChainStore for Store {
    type Error = StoreError;
    type View<'a> = StoreView;

    fn tip(&self) -> Result<Option<Hash>, StoreError> {
        Store::tip(self)
    }

    fn height(&self) -> Result<Option<u64>, StoreError> {
        Store::height(self)
    }

    fn hash_at_height(&self, height: u64) -> Result<Option<Hash>, StoreError> {
        Store::hash_at_height(self, height)
    }

    fn block(&self, hash: &Hash) -> Result<Option<Block>, StoreError> {
        Store::block(self, hash)
    }

    fn index_entry(&self, hash: &Hash) -> Result<Option<BlockIndexEntry>, StoreError> {
        Store::index_entry(self, hash)
    }

    fn all_index_entries(&self) -> Result<Vec<BlockIndexEntry>, StoreError> {
        Store::all_index_entries(self)
    }

    fn index_len(&self) -> Result<u64, StoreError> {
        Store::index_len(self)
    }

    fn for_each_index_entry(&self, f: &mut dyn FnMut(BlockIndexEntry)) -> Result<(), StoreError> {
        Store::for_each_index_entry(self, f)
    }

    fn children_of(&self, hash: &Hash) -> Result<Vec<Hash>, StoreError> {
        Store::children_of(self, hash)
    }

    fn put_block(&self, block: &Block, entry: &BlockIndexEntry) -> Result<(), StoreError> {
        Store::put_block(self, block, entry)
    }

    fn put_index_entry(&self, entry: &BlockIndexEntry) -> Result<(), StoreError> {
        Store::put_index_entry(self, entry)
    }

    fn connect_block(&self, block: &Block) -> Result<UndoBlock, StoreError> {
        Store::connect_block(self, block)
    }

    fn disconnect_tip(&self) -> Result<Hash, StoreError> {
        Store::disconnect_tip(self)
    }

    fn utxo_view(&self) -> Result<StoreView, StoreError> {
        Store::utxo_view(self)
    }

    fn utxo_count(&self) -> Result<u64, StoreError> {
        Store::utxo_count(self)
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

    // ━━━━━━━━ 親から子 ━━━━━━━━

    #[test]
    fn children_are_recorded_as_blocks_arrive() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let blocks = build(&store, 4);

        for i in 0..3 {
            assert_eq!(
                store.children_of(&blocks[i].header.hash()).unwrap(),
                vec![blocks[i + 1].header.hash()],
                "高さ {i} の子が引けない"
            );
        }
        // 先端に子はいない。
        assert!(store
            .children_of(&blocks[3].header.hash())
            .unwrap()
            .is_empty());
        // ジェネシスは親を持たないので、0 のハッシュに子は付かない。
        assert!(store.children_of(&Hash::ZERO).unwrap().is_empty());
    }

    #[test]
    fn a_fork_gives_the_parent_two_children() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let blocks = build(&store, 3);

        let fork = block_at(2, blocks[1].header.hash(), 999);
        store.put_block(&fork, &entry_for(&fork, 3)).unwrap();

        let mut children = store.children_of(&blocks[1].header.hash()).unwrap();
        children.sort_unstable();
        let mut expected = vec![blocks[2].header.hash(), fork.header.hash()];
        expected.sort_unstable();
        assert_eq!(children, expected);
    }

    #[test]
    fn rewriting_the_status_does_not_duplicate_the_child() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let blocks = build(&store, 2);

        let mut entry = entry_for(&blocks[1], 2);
        for status in [BlockStatus::FullyValid, BlockStatus::Invalid] {
            entry.status = status;
            store.put_index_entry(&entry).unwrap();
        }

        assert_eq!(
            store.children_of(&blocks[0].header.hash()).unwrap().len(),
            1,
            "状態を書き直すたびに子が増えている"
        );
    }

    #[test]
    fn an_old_database_gets_its_children_rebuilt_on_open() {
        let tmp = TempDb::new();
        let blocks = {
            let store = tmp.open();
            let blocks = build(&store, 5);

            // この表が入る前の記憶域を真似る。**中身を消すだけ**にして、
            // インデックスはそのまま残す。
            let txn = store.db.begin_write().unwrap();
            {
                let mut children = txn.open_table(CHILDREN).unwrap();
                children.retain(|_, _| false).unwrap();
            }
            txn.commit().unwrap();
            assert!(store
                .children_of(&blocks[0].header.hash())
                .unwrap()
                .is_empty());
            blocks
        };

        // 開き直すと組み直される。
        let store = tmp.open();
        for i in 0..4 {
            assert_eq!(
                store.children_of(&blocks[i].header.hash()).unwrap(),
                vec![blocks[i + 1].header.hash()],
                "高さ {i} の子が組み直されていない"
            );
        }
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
    fn scanning_finds_only_the_requested_locks() {
        let tmp = TempDb::new();
        let store = tmp.open();

        // 狙いの支払い条件を 1 つ決め、高さ 1 と 3 でそこへ払う。
        let mine = Lock::pay_to_pubkey(&SecretKey::generate().public_key());
        let mut prev = Hash::ZERO;
        for height in 0..5u64 {
            let mut cb = coinbase(height, height);
            if height == 1 || height == 3 {
                cb.outputs[0].lock = mine.clone();
            }
            let merkle_root = merkle::merkle_root(&[cb.txid()]).unwrap();
            let block = Block {
                header: BlockHeader {
                    version: 0,
                    prev_hash: prev,
                    merkle_root,
                    timestamp: 1_800_000_000 + height as i64 * 60,
                    difficulty: 1,
                    height,
                    nonce: height,
                },
                transactions: vec![cb],
            };
            prev = block.header.hash();
            store
                .put_block(&block, &entry_for(&block, u128::from(height) + 1))
                .unwrap();
            store.connect_block(&block).unwrap();
        }
        assert_eq!(store.utxo_count().unwrap(), 5);

        let found = store.scan_utxos(std::slice::from_ref(&mine), 100).unwrap();
        assert_eq!(found.len(), 2, "自分の分だけ拾うべき");
        let mut heights: Vec<u64> = found.iter().map(|(_, e)| e.height).collect();
        heights.sort_unstable();
        assert_eq!(heights, vec![1, 3]);
        for (_, entry) in &found {
            assert_eq!(entry.output.lock, mine);
            assert!(entry.is_coinbase);
        }

        // 上限は効く。
        assert_eq!(
            store
                .scan_utxos(std::slice::from_ref(&mine), 1)
                .unwrap()
                .len(),
            1
        );
        assert!(store.scan_utxos(&[mine], 0).unwrap().is_empty());

        // 知らない支払い条件では何も見つからない。
        let other = Lock::pay_to_pubkey(&SecretKey::generate().public_key());
        assert!(store.scan_utxos(&[other], 100).unwrap().is_empty());
        assert!(store.scan_utxos(&[], 100).unwrap().is_empty());
    }

    #[test]
    fn a_spent_output_is_no_longer_found() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let blocks = build(&store, 3);
        let lock = blocks[1].transactions[0].outputs[0].lock.clone();
        assert_eq!(
            store
                .scan_utxos(std::slice::from_ref(&lock), 100)
                .unwrap()
                .len(),
            1
        );

        // 高さ 1 と 2 を巻き戻すと、高さ 1 の出力は無くなる。
        store.disconnect_tip().unwrap();
        store.disconnect_tip().unwrap();
        assert!(
            store.scan_utxos(&[lock], 100).unwrap().is_empty(),
            "巻き戻したのに見つかる"
        );
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
    // ━━━━━━━━ 索引 ━━━━━━━━

    /// 高さ `h` に、コインベース (受取先 `to`) と、任意の使用取引を置く。
    fn block_with(height: u64, prev: Hash, to: &Lock, extra: Vec<Transaction>) -> Block {
        let mut cb = coinbase(height, height);
        cb.outputs[0].lock = to.clone();
        let mut txs = vec![cb];
        txs.extend(extra);
        let ids: Vec<Hash> = txs.iter().map(|t| t.txid()).collect();
        Block {
            header: BlockHeader {
                version: 0,
                prev_hash: prev,
                merkle_root: merkle::merkle_root(&ids).unwrap(),
                timestamp: 1_800_000_000 + height as i64 * 60,
                difficulty: 1,
                height,
                nonce: height,
            },
            transactions: txs,
        }
    }

    fn spend(prev_out: OutPoint, to: &Lock) -> Transaction {
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput::new(prev_out)],
            outputs: vec![TxOutput::new(Amount::from_atomic(1).unwrap(), to.clone())],
            locktime: 0,
        }
    }

    fn put_and_connect(store: &Store, block: &Block) {
        store.put_block(block, &entry_for(block, 1)).unwrap();
        store.connect_block(block).unwrap();
    }

    #[test]
    fn a_summary_reports_what_the_block_really_holds() {
        // **復号せずに数えている**ので、本物のブロックと突き合わせる。
        // ずれれば、一覧が嘘の取引数や大きさを出していることになる。
        let tmp = TempDb::new();
        let store = tmp.open();
        let to = Lock::pay_to_pubkey(&SecretKey::generate().public_key());
        let mut prev = Hash::ZERO;
        let mut blocks = Vec::new();

        // 高さ 0 はコインベースだけ。1 以降は 0 の出力を使う取引を足す。
        let genesis = block_with(0, prev, &to, Vec::new());
        put_and_connect(&store, &genesis);
        prev = genesis.header.hash();
        blocks.push(genesis.clone());

        let out = OutPoint {
            txid: genesis.transactions[0].txid(),
            index: 0,
        };
        let block = block_with(1, prev, &to, vec![spend(out, &to)]);
        put_and_connect(&store, &block);
        blocks.push(block);

        let summaries = store.recent_summaries(10).unwrap();
        // 新しい順。
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].height, 1);
        assert_eq!(summaries[1].height, 0);

        for summary in &summaries {
            let block = &blocks[summary.height as usize];
            assert_eq!(summary.hash, block.header.hash());
            assert_eq!(summary.header, block.header);
            assert_eq!(
                summary.transactions,
                block.transactions.len(),
                "高さ {} の取引数が本体と合わない",
                summary.height
            );
            assert_eq!(
                summary.size,
                block.size(),
                "高さ {} の大きさが本体と合わない",
                summary.height
            );
        }
        assert_eq!(summaries[0].transactions, 2);
        assert_eq!(summaries[1].transactions, 1);
    }

    #[test]
    fn a_summary_list_stops_at_the_asked_for_count() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let mut prev = Hash::ZERO;
        for height in 0..6u64 {
            let block = block_at(height, prev, height);
            put_and_connect(&store, &block);
            prev = block.header.hash();
        }

        // 先端から数えて 3 件。古い側ではない。
        let summaries = store.recent_summaries(3).unwrap();
        let heights: Vec<u64> = summaries.iter().map(|s| s.height).collect();
        assert_eq!(heights, vec![5, 4, 3]);

        // 0 件を求めたら読みに行かない。
        assert!(store.recent_summaries(0).unwrap().is_empty());
        // 鎖より多く求めても、あるぶんだけ返る。
        assert_eq!(store.recent_summaries(100).unwrap().len(), 6);
    }

    #[test]
    fn without_an_index_a_lookup_is_refused_rather_than_answered_emptily() {
        // 索引が無いときに「見つからない」と答えてはならない。呼び出し側は
        // それを「その取引は存在しない」と受け取る。
        let tmp = TempDb::new();
        let store = tmp.open();
        let block = block_at(0, Hash::ZERO, 0);
        put_and_connect(&store, &block);

        assert_eq!(store.index_from().unwrap(), None);
        let txid = block.transactions[0].txid();
        assert!(matches!(store.tx_location(&txid), Err(StoreError::NoIndex)));
    }

    #[test]
    fn building_the_index_covers_the_chain_that_is_already_there() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let mut prev = Hash::ZERO;
        let mut blocks = Vec::new();
        for height in 0..5u64 {
            let block = block_at(height, prev, height);
            put_and_connect(&store, &block);
            prev = block.header.hash();
            blocks.push(block);
        }

        let stats = store.build_index().unwrap();
        assert_eq!(stats.blocks, 5);
        assert_eq!(stats.transactions, 5);
        assert_eq!(store.index_from().unwrap(), Some(0));

        for (height, block) in blocks.iter().enumerate() {
            let txid = block.transactions[0].txid();
            let found = store.tx_location(&txid).unwrap().unwrap();
            assert_eq!(found.height, height as u64);
            assert_eq!(found.position, 0);
            assert_eq!(found.block, block.header.hash());
        }
    }

    #[test]
    fn a_block_connected_after_the_build_is_indexed_too() {
        // 索引は接続と同じトランザクションで更新される。組み直さなくても
        // 追いつく。
        let tmp = TempDb::new();
        let store = tmp.open();
        let first = block_at(0, Hash::ZERO, 0);
        put_and_connect(&store, &first);
        store.build_index().unwrap();

        let second = block_at(1, first.header.hash(), 1);
        put_and_connect(&store, &second);

        let txid = second.transactions[0].txid();
        assert_eq!(store.tx_location(&txid).unwrap().unwrap().height, 1);
    }

    #[test]
    fn disconnecting_takes_the_block_back_out_of_the_index() {
        // 取り消したブロックを索引が指し続けると、リオーグで消えた取引が
        // 永遠に見つかることになる。
        let tmp = TempDb::new();
        let store = tmp.open();
        let first = block_at(0, Hash::ZERO, 0);
        put_and_connect(&store, &first);
        let second = block_at(1, first.header.hash(), 1);
        put_and_connect(&store, &second);
        store.build_index().unwrap();

        let txid = second.transactions[0].txid();
        assert!(store.tx_location(&txid).unwrap().is_some());

        store.disconnect_tip().unwrap();
        assert_eq!(store.tx_location(&txid).unwrap(), None);
        // 残ったほうは無事である。
        let first_txid = first.transactions[0].txid();
        assert!(store.tx_location(&first_txid).unwrap().is_some());
    }

    #[test]
    fn address_history_covers_both_receiving_and_spending() {
        // 使われた出力は UTXO セットから消えている。入力側を巻き戻し情報
        // から拾えていなければ、ここで高さ 1 が落ちる。
        let tmp = TempDb::new();
        let store = tmp.open();
        let payer = Lock::pay_to_pubkey(&SecretKey::generate().public_key());
        let payee = Lock::pay_to_pubkey(&SecretKey::generate().public_key());
        let other = Lock::pay_to_pubkey(&SecretKey::generate().public_key());

        let first = block_with(0, Hash::ZERO, &payer, Vec::new());
        put_and_connect(&store, &first);

        let spent = OutPoint::new(first.transactions[0].txid(), 0);
        let second = block_with(1, first.header.hash(), &other, vec![spend(spent, &payee)]);
        put_and_connect(&store, &second);

        store.build_index().unwrap();

        let history = store.address_history(&payer, 0, 100).unwrap();
        assert_eq!(history.len(), 2, "受け取りと使用の両方が出るべき");
        assert_eq!((history[0].height, history[0].position), (0, 0));
        assert_eq!((history[1].height, history[1].position), (1, 1));

        // 受け取っただけの相手は 1 件。
        let history = store.address_history(&payee, 0, 100).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].txid, second.transactions[1].txid());
    }

    #[test]
    fn address_history_can_start_partway_and_stop_early() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let mine = Lock::pay_to_pubkey(&SecretKey::generate().public_key());
        let mut prev = Hash::ZERO;
        for height in 0..6u64 {
            let block = block_with(height, prev, &mine, Vec::new());
            put_and_connect(&store, &block);
            prev = block.header.hash();
        }
        store.build_index().unwrap();

        let all = store.address_history(&mine, 0, 100).unwrap();
        assert_eq!(all.len(), 6);
        // 古い順である。
        let heights: Vec<u64> = all.iter().map(|l| l.height).collect();
        assert_eq!(heights, vec![0, 1, 2, 3, 4, 5]);

        let from_three = store.address_history(&mine, 3, 100).unwrap();
        assert_eq!(
            from_three.iter().map(|l| l.height).collect::<Vec<u64>>(),
            vec![3, 4, 5]
        );

        let capped = store.address_history(&mine, 0, 2).unwrap();
        assert_eq!(capped.len(), 2);
    }

    #[test]
    fn dropping_the_index_puts_it_back_to_refusing() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let block = block_at(0, Hash::ZERO, 0);
        put_and_connect(&store, &block);
        store.build_index().unwrap();
        assert_eq!(store.index_from().unwrap(), Some(0));

        store.drop_index().unwrap();
        assert_eq!(store.index_from().unwrap(), None);
        assert!(matches!(
            store.tx_location(&block.transactions[0].txid()),
            Err(StoreError::NoIndex)
        ));
    }

    #[test]
    fn an_unrelated_address_has_no_history() {
        let tmp = TempDb::new();
        let store = tmp.open();
        let mine = Lock::pay_to_pubkey(&SecretKey::generate().public_key());
        let block = block_with(0, Hash::ZERO, &mine, Vec::new());
        put_and_connect(&store, &block);
        store.build_index().unwrap();

        let stranger = Lock::pay_to_pubkey(&SecretKey::generate().public_key());
        assert!(store.address_history(&stranger, 0, 100).unwrap().is_empty());
    }
}
