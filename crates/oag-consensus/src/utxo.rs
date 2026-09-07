//! UTXO セット。
//!
//! 未使用の出力の集合である。すべてのノードが恒久的に保持し、検証のたびに
//! 参照するため、実質的にメモリ常駐となる。極小額の出力を大量に作る攻撃が
//! 全ノードを永続的に汚染するのはこのためであり、ダスト閾値
//! (`params::DUST_THRESHOLD`) がそれを防ぐ。
//!
//! 本モジュールの実装はメモリ上のものである。永続化は後のフェーズで
//! [`UtxoView`] を実装する別の型に差し替える。
//!
//! 参照: `docs/SPEC.md` §10.3, §13.3

use crate::codec::{write_varint, CodecError, Decode, Encode, Reader};
use crate::tx::{OutPoint, Transaction, TxOutput};
use std::collections::HashMap;

/// UTXO 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoEntry {
    /// 出力そのもの。
    pub output: TxOutput,
    /// この出力を生成したブロックの高さ。
    pub height: u64,
    /// コインベース出力か。成熟判定に用いる。
    pub is_coinbase: bool,
}

/// UTXO セットの読み取り。
///
/// 永続化された実装に差し替えられるよう、所有権を返す。
pub trait UtxoView {
    /// 指定した参照先の UTXO を返す。使用済みまたは存在しない場合は `Ok(None)`。
    ///
    /// # なぜ `Result` なのか
    ///
    /// 永続化された実装では読み取り自体が失敗しうる。これを `None`
    /// (= UTXO が存在しない) と区別せずに扱うと、ディスクの不調が
    /// 「そのトランザクションは無効」という判定に化ける。ノードは正当な
    /// ブロックを拒否して静かにチェーンから外れることになる。
    /// 記憶装置の障害と、UTXO が使用済みであることは、別の事実である。
    fn get(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, UtxoError>;

    /// UTXO が存在するか。
    fn contains(&self, outpoint: &OutPoint) -> Result<bool, UtxoError> {
        Ok(self.get(outpoint)?.is_some())
    }
}

/// UTXO セットの変更。
///
/// メモリ上の実装と永続化された実装の双方が実装する。適用と巻き戻しの
/// ロジックは [`apply_block_to`] と [`undo_block_from`] に一本化してあり、
/// **背後の記憶装置によらず同じ手順が走る**。二重に実装すると、メモリ版と
/// DB 版で挙動が食い違ったときに帳簿が分裂する。
pub trait UtxoWrite: UtxoView {
    /// UTXO を追加する。すでに存在する場合は誤りとする。
    fn insert(&mut self, outpoint: OutPoint, entry: UtxoEntry) -> Result<(), UtxoError>;

    /// UTXO を取り除き、その内容を返す。存在しない場合は誤りとする。
    fn remove(&mut self, outpoint: &OutPoint) -> Result<UtxoEntry, UtxoError>;
}

/// ブロックを適用し、巻き戻し情報を返す。
///
/// 呼び出し側は事前に検証を済ませていなければならない。
/// **途中で失敗した場合、`utxo` は中途半端な状態のまま残る。**
/// 呼び出し側が巻き戻すか、書き込みトランザクションを破棄すること。
pub fn apply_block_to(
    utxo: &mut dyn UtxoWrite,
    transactions: &[Transaction],
    height: u64,
) -> Result<UndoBlock, UtxoError> {
    let mut undo = UndoBlock::default();
    for tx in transactions {
        let is_coinbase = tx.is_coinbase();
        if !is_coinbase {
            for input in &tx.inputs {
                let entry = utxo.remove(&input.prev_out)?;
                undo.spent.push((input.prev_out, entry));
            }
        }
        let txid = tx.txid();
        for (index, output) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint::new(txid, index as u32);
            utxo.insert(
                outpoint,
                UtxoEntry {
                    output: output.clone(),
                    height,
                    is_coinbase,
                },
            )?;
            undo.created.push(outpoint);
        }
    }
    Ok(undo)
}

/// ブロックの適用を取り消す。
pub fn undo_block_from(utxo: &mut dyn UtxoWrite, undo: &UndoBlock) -> Result<(), UtxoError> {
    for outpoint in &undo.created {
        utxo.remove(outpoint)?;
    }
    for (outpoint, entry) in &undo.spent {
        if utxo.contains(outpoint)? {
            return Err(UtxoError::UndoMismatch(*outpoint));
        }
        utxo.insert(*outpoint, entry.clone())?;
    }
    Ok(())
}

/// ブロックを適用した際の巻き戻し情報。
///
/// リオーグでブロックを取り消すために必要となる。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UndoBlock {
    /// 消費された UTXO とその内容。復元に用いる。
    pub(crate) spent: Vec<(OutPoint, UtxoEntry)>,
    /// 生成された UTXO の参照。削除に用いる。
    pub(crate) created: Vec<OutPoint>,
}

impl UndoBlock {
    /// 消費された UTXO の件数。
    pub fn spent_count(&self) -> usize {
        self.spent.len()
    }

    /// 生成された UTXO の件数。
    pub fn created_count(&self) -> usize {
        self.created.len()
    }
}

/// UTXO の適用・巻き戻しで起きうる誤り。
///
/// これらは検証を通過したブロックに対しては発生しない。発生した場合は
/// 検証の漏れかセットの破損を意味する。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UtxoError {
    /// 存在しない UTXO を消費しようとした。
    #[error("存在しない UTXO を消費しようとした: {0:?}")]
    MissingUtxo(OutPoint),
    /// すでに存在する UTXO を生成しようとした。
    #[error("すでに存在する UTXO を生成しようとした: {0:?}")]
    DuplicateUtxo(OutPoint),
    /// 巻き戻しで復元しようとした UTXO がすでに存在する。
    #[error("巻き戻しの整合性が取れない: {0:?}")]
    UndoMismatch(OutPoint),
    /// 記憶装置の読み書きに失敗した。
    ///
    /// UTXO が存在しないこととは区別される。
    #[error("記憶装置の操作に失敗した: {0}")]
    Backend(String),
}

/// メモリ上の UTXO セット。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UtxoSet {
    entries: HashMap<OutPoint, UtxoEntry>,
}

impl UtxoSet {
    /// 空のセットを作る。
    pub fn new() -> UtxoSet {
        UtxoSet::default()
    }

    /// 保持している UTXO の件数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// UTXO を追加する。
    pub fn insert(&mut self, outpoint: OutPoint, entry: UtxoEntry) -> Result<(), UtxoError> {
        if self.entries.contains_key(&outpoint) {
            return Err(UtxoError::DuplicateUtxo(outpoint));
        }
        self.entries.insert(outpoint, entry);
        Ok(())
    }

    /// UTXO を取り除き、その内容を返す。
    pub fn remove(&mut self, outpoint: &OutPoint) -> Result<UtxoEntry, UtxoError> {
        self.entries
            .remove(outpoint)
            .ok_or(UtxoError::MissingUtxo(*outpoint))
    }

    /// ブロックを適用し、巻き戻し情報を返す。
    ///
    /// 途中で失敗した場合、セットは変更されないまま返る。作業用の複製に
    /// 対して操作し、成功したときだけ差し替えるため。
    pub fn apply_block(
        &mut self,
        transactions: &[Transaction],
        height: u64,
    ) -> Result<UndoBlock, UtxoError> {
        let mut working = self.clone();
        let undo = apply_block_to(&mut working, transactions, height)?;
        *self = working;
        Ok(undo)
    }

    /// ブロックの適用を取り消す。リオーグで用いる。
    pub fn undo_block(&mut self, undo: &UndoBlock) -> Result<(), UtxoError> {
        let mut working = self.clone();
        undo_block_from(&mut working, undo)?;
        *self = working;
        Ok(())
    }
}

impl UtxoWrite for UtxoSet {
    fn insert(&mut self, outpoint: OutPoint, entry: UtxoEntry) -> Result<(), UtxoError> {
        UtxoSet::insert(self, outpoint, entry)
    }

    fn remove(&mut self, outpoint: &OutPoint) -> Result<UtxoEntry, UtxoError> {
        UtxoSet::remove(self, outpoint)
    }
}

impl UtxoView for UtxoSet {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, UtxoError> {
        Ok(self.entries.get(outpoint).cloned())
    }

    fn contains(&self, outpoint: &OutPoint) -> Result<bool, UtxoError> {
        Ok(self.entries.contains_key(outpoint))
    }
}

/// 検証中のブロック内で生成・消費された UTXO を重ねて見せるビュー。
///
/// 同一ブロック内で、前のトランザクションが生成した出力を後のトランザクションが
/// 使用することを許すために必要となる。
pub struct OverlayView<'a> {
    base: &'a dyn UtxoView,
    created: HashMap<OutPoint, UtxoEntry>,
    spent: std::collections::HashSet<OutPoint>,
}

impl<'a> OverlayView<'a> {
    /// 基底のビューに重ねる。
    pub fn new(base: &'a dyn UtxoView) -> OverlayView<'a> {
        OverlayView {
            base,
            created: HashMap::new(),
            spent: std::collections::HashSet::new(),
        }
    }

    /// 使用済みとして記録する。すでに使用済みなら `false` を返す。
    pub fn mark_spent(&mut self, outpoint: OutPoint) -> bool {
        self.spent.insert(outpoint)
    }

    /// このブロック内で生成された出力を記録する。
    pub fn add_created(&mut self, outpoint: OutPoint, entry: UtxoEntry) {
        self.created.insert(outpoint, entry);
    }
}

impl UtxoView for OverlayView<'_> {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, UtxoError> {
        if self.spent.contains(outpoint) {
            return Ok(None);
        }
        match self.created.get(outpoint) {
            Some(entry) => Ok(Some(entry.clone())),
            None => self.base.get(outpoint),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::Lock;
    use crate::params::BLOCK_REWARD;
    use crate::tx::{encode_coinbase_signature, TxInput, CURRENT_TX_VERSION};
    use oag_primitives::{Amount, SecretKey};

    fn lock() -> Lock {
        Lock::pay_to_pubkey(&SecretKey::generate().public_key())
    }

    fn coinbase(height: u64) -> Transaction {
        let mut input = TxInput::new(OutPoint::null());
        input.signature = encode_coinbase_signature(height, b"");
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: vec![TxOutput::new(BLOCK_REWARD, lock())],
            locktime: 0,
        }
    }

    fn spend(prev: OutPoint, amount: Amount) -> Transaction {
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput::new(prev)],
            outputs: vec![TxOutput::new(amount, lock())],
            locktime: 0,
        }
    }

    #[test]
    fn apply_and_undo_restore_the_original_state() {
        let mut set = UtxoSet::new();
        let cb = coinbase(1);
        let undo1 = set.apply_block(std::slice::from_ref(&cb), 1).unwrap();
        let after_first = set.clone();
        assert_eq!(set.len(), 1);

        let cb_out = OutPoint::new(cb.txid(), 0);
        let tx = spend(cb_out, Amount::from_oag(9).unwrap());
        let undo2 = set.apply_block(&[coinbase(2), tx.clone()], 2).unwrap();
        assert_eq!(
            set.len(),
            2,
            "コインベース 2 件目 + 送金先。元の 1 件は消費された"
        );
        assert!(!set.contains(&cb_out).unwrap());

        set.undo_block(&undo2).unwrap();
        assert_eq!(set.len(), after_first.len());
        assert!(
            set.contains(&cb_out).unwrap(),
            "消費された UTXO が復元される"
        );
        assert_eq!(set.get(&cb_out), after_first.get(&cb_out));

        set.undo_block(&undo1).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn undo_records_both_directions() {
        let mut set = UtxoSet::new();
        let cb = coinbase(1);
        set.apply_block(std::slice::from_ref(&cb), 1).unwrap();

        let undo = set
            .apply_block(
                &[
                    coinbase(2),
                    spend(OutPoint::new(cb.txid(), 0), Amount::from_oag(9).unwrap()),
                ],
                2,
            )
            .unwrap();
        assert_eq!(undo.spent_count(), 1);
        assert_eq!(undo.created_count(), 2);
    }

    #[test]
    fn entries_record_height_and_coinbase_flag() {
        let mut set = UtxoSet::new();
        let cb = coinbase(42);
        set.apply_block(std::slice::from_ref(&cb), 42).unwrap();
        let entry = set.get(&OutPoint::new(cb.txid(), 0)).unwrap().unwrap();
        assert_eq!(entry.height, 42);
        assert!(entry.is_coinbase);
    }

    #[test]
    fn spending_a_missing_utxo_fails_without_mutating() {
        let mut set = UtxoSet::new();
        let ghost = OutPoint::new(oag_primitives::hash::txid(b"ghost"), 0);
        let before = set.len();
        assert_eq!(
            set.apply_block(&[spend(ghost, Amount::ONE_OAG)], 1),
            Err(UtxoError::MissingUtxo(ghost))
        );
        assert_eq!(set.len(), before, "失敗時にセットは変更されない");
    }

    #[test]
    fn a_block_that_fails_midway_leaves_the_set_untouched() {
        let mut set = UtxoSet::new();
        let cb = coinbase(1);
        set.apply_block(std::slice::from_ref(&cb), 1).unwrap();
        let snapshot = set.clone();

        let ghost = OutPoint::new(oag_primitives::hash::txid(b"ghost"), 0);
        let result = set.apply_block(
            &[
                coinbase(2),
                spend(OutPoint::new(cb.txid(), 0), Amount::from_oag(9).unwrap()),
                spend(ghost, Amount::ONE_OAG),
            ],
            2,
        );
        assert!(result.is_err());
        assert_eq!(set.len(), snapshot.len());
        assert!(set.contains(&OutPoint::new(cb.txid(), 0)).unwrap());
    }

    #[test]
    fn overlay_sees_outputs_created_in_the_same_block() {
        let mut set = UtxoSet::new();
        let cb = coinbase(1);
        set.apply_block(std::slice::from_ref(&cb), 1).unwrap();

        let mut overlay = OverlayView::new(&set);
        let base_out = OutPoint::new(cb.txid(), 0);
        assert!(overlay.contains(&base_out).unwrap());

        let fresh = OutPoint::new(oag_primitives::hash::txid(b"new"), 0);
        assert!(!overlay.contains(&fresh).unwrap());
        overlay.add_created(
            fresh,
            UtxoEntry {
                output: TxOutput::new(Amount::ONE_OAG, lock()),
                height: 2,
                is_coinbase: false,
            },
        );
        assert!(
            overlay.contains(&fresh).unwrap(),
            "同一ブロック内の出力が見える"
        );

        assert!(overlay.mark_spent(fresh));
        assert!(!overlay.contains(&fresh).unwrap(), "使用済みは見えなくなる");
        assert!(!overlay.mark_spent(fresh), "二重使用は検出される");

        // 基底のセットは変更されない。
        assert!(set.contains(&base_out).unwrap());
    }
}

// ━━━━━━━━ 永続化のためのシリアライズ ━━━━━━━━

impl Encode for UtxoEntry {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.output.encode_into(out);
        write_varint(u128::from(self.height), out);
        out.push(u8::from(self.is_coinbase));
    }
}

impl Decode for UtxoEntry {
    fn read_from(reader: &mut Reader<'_>) -> Result<UtxoEntry, CodecError> {
        Ok(UtxoEntry {
            output: TxOutput::read_from(reader)?,
            height: reader.read_varint_u64("utxo.height")?,
            is_coinbase: reader.read_u8()? != 0,
        })
    }
}

impl Encode for UndoBlock {
    fn encode_into(&self, out: &mut Vec<u8>) {
        write_varint(self.spent.len() as u128, out);
        for (outpoint, entry) in &self.spent {
            outpoint.encode_into(out);
            entry.encode_into(out);
        }
        write_varint(self.created.len() as u128, out);
        for outpoint in &self.created {
            outpoint.encode_into(out);
        }
    }
}

impl Decode for UndoBlock {
    fn read_from(reader: &mut Reader<'_>) -> Result<UndoBlock, CodecError> {
        let spent_count = reader.read_count("undo.spent")?;
        let mut spent = Vec::with_capacity(spent_count);
        for _ in 0..spent_count {
            let outpoint = OutPoint::read_from(reader)?;
            let entry = UtxoEntry::read_from(reader)?;
            spent.push((outpoint, entry));
        }
        let created_count = reader.read_count("undo.created")?;
        let mut created = Vec::with_capacity(created_count);
        for _ in 0..created_count {
            created.push(OutPoint::read_from(reader)?);
        }
        Ok(UndoBlock { spent, created })
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;
    use crate::lock::Lock;
    use oag_primitives::{Amount, SecretKey};

    fn entry(height: u64, is_coinbase: bool) -> UtxoEntry {
        UtxoEntry {
            output: TxOutput::new(
                Amount::from_oag(7).unwrap(),
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            ),
            height,
            is_coinbase,
        }
    }

    #[test]
    fn utxo_entry_round_trip() {
        for (height, coinbase) in [(0u64, true), (1, false), (u32::MAX as u64, true)] {
            let e = entry(height, coinbase);
            assert_eq!(UtxoEntry::decode(&e.encode()).unwrap(), e);
        }
    }

    #[test]
    fn undo_block_round_trip() {
        let undo = UndoBlock {
            spent: vec![
                (
                    OutPoint::new(oag_primitives::hash::txid(b"a"), 0),
                    entry(1, true),
                ),
                (
                    OutPoint::new(oag_primitives::hash::txid(b"b"), 7),
                    entry(2, false),
                ),
            ],
            created: vec![
                OutPoint::new(oag_primitives::hash::txid(b"c"), 0),
                OutPoint::new(oag_primitives::hash::txid(b"c"), 1),
            ],
        };
        assert_eq!(UndoBlock::decode(&undo.encode()).unwrap(), undo);
    }

    #[test]
    fn an_empty_undo_round_trips() {
        let undo = UndoBlock::default();
        assert_eq!(UndoBlock::decode(&undo.encode()).unwrap(), undo);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = entry(1, true).encode();
        bytes.push(0);
        assert_eq!(UtxoEntry::decode(&bytes), Err(CodecError::TrailingBytes(1)));
    }
}
