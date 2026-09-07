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
    /// 指定した参照先の UTXO を返す。使用済みまたは存在しない場合は `None`。
    fn get(&self, outpoint: &OutPoint) -> Option<UtxoEntry>;

    /// UTXO が存在するか。
    fn contains(&self, outpoint: &OutPoint) -> bool {
        self.get(outpoint).is_some()
    }
}

/// ブロックを適用した際の巻き戻し情報。
///
/// リオーグでブロックを取り消すために必要となる。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UndoBlock {
    /// 消費された UTXO とその内容。復元に用いる。
    spent: Vec<(OutPoint, UtxoEntry)>,
    /// 生成された UTXO の参照。削除に用いる。
    created: Vec<OutPoint>,
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
}

/// メモリ上の UTXO セット。
#[derive(Debug, Clone, Default)]
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

    /// トランザクション 1 件を適用する。
    ///
    /// 呼び出し側は事前に検証を済ませていなければならない。
    fn apply_transaction(
        &mut self,
        tx: &Transaction,
        height: u64,
        undo: &mut UndoBlock,
    ) -> Result<(), UtxoError> {
        if !tx.is_coinbase() {
            for input in &tx.inputs {
                let entry = self.remove(&input.prev_out)?;
                undo.spent.push((input.prev_out, entry));
            }
        }

        let txid = tx.txid();
        let is_coinbase = tx.is_coinbase();
        for (index, output) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint::new(txid, index as u32);
            self.insert(
                outpoint,
                UtxoEntry {
                    output: output.clone(),
                    height,
                    is_coinbase,
                },
            )?;
            undo.created.push(outpoint);
        }
        Ok(())
    }

    /// ブロックを適用し、巻き戻し情報を返す。
    ///
    /// 途中で失敗した場合、セットは変更されないまま返る。
    pub fn apply_block(
        &mut self,
        transactions: &[Transaction],
        height: u64,
    ) -> Result<UndoBlock, UtxoError> {
        let mut working = self.clone();
        let mut undo = UndoBlock::default();
        for tx in transactions {
            working.apply_transaction(tx, height, &mut undo)?;
        }
        *self = working;
        Ok(undo)
    }

    /// ブロックの適用を取り消す。リオーグで用いる。
    pub fn undo_block(&mut self, undo: &UndoBlock) -> Result<(), UtxoError> {
        let mut working = self.clone();

        // 生成された UTXO を消す。
        for outpoint in &undo.created {
            working.remove(outpoint)?;
        }
        // 消費された UTXO を戻す。
        for (outpoint, entry) in &undo.spent {
            if working.entries.contains_key(outpoint) {
                return Err(UtxoError::UndoMismatch(*outpoint));
            }
            working.entries.insert(*outpoint, entry.clone());
        }

        *self = working;
        Ok(())
    }
}

impl UtxoView for UtxoSet {
    fn get(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        self.entries.get(outpoint).cloned()
    }

    fn contains(&self, outpoint: &OutPoint) -> bool {
        self.entries.contains_key(outpoint)
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
    fn get(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        if self.spent.contains(outpoint) {
            return None;
        }
        self.created
            .get(outpoint)
            .cloned()
            .or_else(|| self.base.get(outpoint))
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
        assert!(!set.contains(&cb_out));

        set.undo_block(&undo2).unwrap();
        assert_eq!(set.len(), after_first.len());
        assert!(set.contains(&cb_out), "消費された UTXO が復元される");
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
        let entry = set.get(&OutPoint::new(cb.txid(), 0)).unwrap();
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
        assert!(set.contains(&OutPoint::new(cb.txid(), 0)));
    }

    #[test]
    fn overlay_sees_outputs_created_in_the_same_block() {
        let mut set = UtxoSet::new();
        let cb = coinbase(1);
        set.apply_block(std::slice::from_ref(&cb), 1).unwrap();

        let mut overlay = OverlayView::new(&set);
        let base_out = OutPoint::new(cb.txid(), 0);
        assert!(overlay.contains(&base_out));

        let fresh = OutPoint::new(oag_primitives::hash::txid(b"new"), 0);
        assert!(!overlay.contains(&fresh));
        overlay.add_created(
            fresh,
            UtxoEntry {
                output: TxOutput::new(Amount::ONE_OAG, lock()),
                height: 2,
                is_coinbase: false,
            },
        );
        assert!(overlay.contains(&fresh), "同一ブロック内の出力が見える");

        assert!(overlay.mark_spent(fresh));
        assert!(!overlay.contains(&fresh), "使用済みは見えなくなる");
        assert!(!overlay.mark_spent(fresh), "二重使用は検出される");

        // 基底のセットは変更されない。
        assert!(set.contains(&base_out));
    }
}
