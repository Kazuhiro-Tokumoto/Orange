//! mempool。
//!
//! ブロックに入る前の、検証済みトランザクションの置き場である。
//!
//! # コンセンサスとポリシーの境界
//!
//! mempool に入れるかどうかは **ポリシー**の判断であり、ブロックが有効かを
//! 決める **コンセンサス**とは別である。ここで拒否したトランザクションが
//! ブロックに入っていても、そのブロックは有効でありうる。
//!
//! # 依存関係
//!
//! mempool の中のトランザクションの出力を、別のトランザクションが使うことを
//! 許す。ブロックを組み立てるときは、**親が子より先に来るように**並べる。
//! ブロック内のトランザクションは依存順でなければならないためである
//! (`docs/SPEC.md` §10.2)。

use crate::policy::Policy;
use oag_consensus::params;
use oag_consensus::tx::OutPoint;
use oag_consensus::utxo::{UtxoEntry, UtxoError, UtxoView};
use oag_consensus::validate::{validate_transaction, ValidationError};
use oag_consensus::{Block, Transaction, TxOutput};
use oag_primitives::{Amount, Hash};
use std::collections::{HashMap, HashSet};

/// mempool がトランザクションを受け入れなかった理由。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Reject {
    /// すでに保持している。
    #[error("すでに mempool にある")]
    AlreadyKnown,
    /// コインベースは単独では流通しない。
    #[error("コインベーストランザクションは mempool に入れられない")]
    Coinbase,
    /// 大きすぎる。
    #[error("サイズ {actual} が上限 {max} を超えている")]
    TooLarge {
        /// 実際のサイズ。
        actual: usize,
        /// 上限。
        max: usize,
    },
    /// コンセンサスルールに反している。
    #[error(transparent)]
    Consensus(#[from] ValidationError),
    /// UTXO の読み取りに失敗した。
    #[error(transparent)]
    Utxo(#[from] UtxoError),
    /// 手数料が最低中継料率に満たない。
    #[error("手数料 {paid} が最低要求 {required} に満たない")]
    FeeTooLow {
        /// 支払われた手数料。
        paid: Amount,
        /// 要求される手数料。
        required: Amount,
    },
    /// ダスト閾値未満の出力を含む。
    #[error("出力 {index} の金額 {amount} がダスト閾値 {threshold} 未満")]
    DustOutput {
        /// 出力番号。
        index: usize,
        /// その金額。
        amount: Amount,
        /// 閾値。
        threshold: Amount,
    },
    /// 未知の版数の支払い条件を作ろうとしている。
    #[error("出力 {index} が未知の版数 {version} を使っている (資金を失う恐れがある)")]
    UnknownLockVersionCreated {
        /// 出力番号。
        index: usize,
        /// 版数。
        version: u8,
    },
    /// 未知の版数の支払い条件を使おうとしている。
    #[error("入力 {index} が未知の版数 {version} の出力を使おうとしている")]
    UnknownLockVersionSpent {
        /// 入力番号。
        index: usize,
        /// 版数。
        version: u8,
    },
    /// すでに mempool にあるトランザクションと同じ UTXO を使う。
    ///
    /// 手数料を上げた置き換え (RBF) には対応していない。
    #[error("UTXO {outpoint:?} はすでに {existing} が使っている")]
    Conflict {
        /// 競合する参照先。
        outpoint: OutPoint,
        /// すでに使っているトランザクション。
        existing: Hash,
    },
}

/// mempool の 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MempoolEntry {
    /// トランザクション本体。
    pub tx: Transaction,
    /// トランザクション ID。
    pub txid: Hash,
    /// 支払う手数料。
    pub fee: Amount,
    /// シリアライズサイズ。
    pub size: usize,
    /// 到着順の連番。同じ料率のときの順序づけに用いる (時刻に依存しない)。
    pub arrival: u64,
}

impl MempoolEntry {
    /// 1 バイトあたりの手数料 (atomic)。
    ///
    /// 整数のまま比較できるよう、割り算はせずに交差積で比較する
    /// 内部の比較では丸めずに交差積を用いる。この値は表示と目安のためのものである。
    pub fn fee_rate(&self) -> u128 {
        if self.size == 0 {
            return 0;
        }
        self.fee.to_atomic() / self.size as u128
    }

    /// 料率がもう一方より高いか。丸めずに交差積で比較する。
    fn beats(&self, other: &MempoolEntry) -> bool {
        let left = self.fee.to_atomic() * other.size as u128;
        let right = other.fee.to_atomic() * self.size as u128;
        (left, other.arrival) > (right, self.arrival)
    }
}

/// mempool。
#[derive(Debug)]
pub struct Mempool {
    entries: HashMap<Hash, MempoolEntry>,
    /// 使用中の参照先 → それを使っているトランザクション。
    spent: HashMap<OutPoint, Hash>,
    total_size: usize,
    next_arrival: u64,
    policy: Policy,
}

/// 未確認トランザクションの出力を重ねて見せるビュー。
struct PoolView<'a> {
    base: &'a dyn UtxoView,
    pool: &'a Mempool,
    next_height: u64,
}

impl UtxoView for PoolView<'_> {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, UtxoError> {
        if self.pool.spent.contains_key(outpoint) {
            return Ok(None);
        }
        if let Some(entry) = self.pool.output_at(outpoint, self.next_height) {
            return Ok(Some(entry));
        }
        self.base.get(outpoint)
    }
}

impl Mempool {
    /// 既定のポリシーで作る。
    pub fn new() -> Mempool {
        Mempool::with_policy(Policy::default())
    }

    /// ポリシーを指定して作る。
    pub fn with_policy(policy: Policy) -> Mempool {
        Mempool {
            entries: HashMap::new(),
            spent: HashMap::new(),
            total_size: 0,
            next_arrival: 0,
            policy,
        }
    }

    /// 適用しているポリシー。
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// 保持している件数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 保持しているトランザクションの合計バイト数。
    pub fn total_size(&self) -> usize {
        self.total_size
    }

    /// 指定した ID のトランザクションを保持しているか。
    pub fn contains(&self, txid: &Hash) -> bool {
        self.entries.contains_key(txid)
    }

    /// 1 件を引く。
    pub fn get(&self, txid: &Hash) -> Option<&MempoolEntry> {
        self.entries.get(txid)
    }

    /// 保持しているすべての ID。
    pub fn txids(&self) -> Vec<Hash> {
        self.entries.keys().copied().collect()
    }

    /// mempool の中のトランザクションが作る出力を引く。
    fn output_at(&self, outpoint: &OutPoint, height: u64) -> Option<UtxoEntry> {
        let entry = self.entries.get(&outpoint.txid)?;
        let output = entry
            .tx
            .outputs
            .get(usize::try_from(outpoint.index).ok()?)?;
        Some(UtxoEntry {
            output: output.clone(),
            height,
            is_coinbase: false,
        })
    }

    /// トランザクションを受け入れる。
    ///
    /// `chain_utxo` は確定済みチェーンの UTXO、`next_height` はこの
    /// トランザクションが入りうる最初のブロックの高さ、`median_time_past` は
    /// 現在の先端のものを渡す。
    pub fn accept(
        &mut self,
        tx: Transaction,
        chain_utxo: &dyn UtxoView,
        next_height: u64,
        median_time_past: i64,
    ) -> Result<Hash, Reject> {
        let txid = tx.txid();
        if self.entries.contains_key(&txid) {
            return Err(Reject::AlreadyKnown);
        }
        if tx.is_coinbase() {
            return Err(Reject::Coinbase);
        }

        let size = tx.size();
        if size > params::MAX_TX_SIZE {
            return Err(Reject::TooLarge {
                actual: size,
                max: params::MAX_TX_SIZE,
            });
        }

        // 二重使用。手数料を上げた置き換え (RBF) には対応していない。
        for input in &tx.inputs {
            if let Some(existing) = self.spent.get(&input.prev_out) {
                return Err(Reject::Conflict {
                    outpoint: input.prev_out,
                    existing: *existing,
                });
            }
        }

        let view = PoolView {
            base: chain_utxo,
            pool: self,
            next_height,
        };

        // 使用対象の支払い条件を、コンセンサス検証の前に集めておく。
        let mut spent_outputs: Vec<TxOutput> = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            if let Some(entry) = view.get(&input.prev_out)? {
                spent_outputs.push(entry.output);
            }
        }

        // ここまではポリシー。ここからコンセンサス。
        let summary = validate_transaction(&tx, &view, next_height, median_time_past, 0)?;

        // ── 以降はポリシーの判断 ──
        let required = self.policy.required_fee(size).ok_or(Reject::FeeTooLow {
            paid: summary.fee,
            required: Amount::MAX,
        })?;
        if summary.fee < required {
            return Err(Reject::FeeTooLow {
                paid: summary.fee,
                required,
            });
        }

        for (index, output) in tx.outputs.iter().enumerate() {
            if output.amount < self.policy.dust_threshold {
                return Err(Reject::DustOutput {
                    index,
                    amount: output.amount,
                    threshold: self.policy.dust_threshold,
                });
            }
            if !self.policy.allow_unknown_lock_versions && !output.lock.is_known_version() {
                return Err(Reject::UnknownLockVersionCreated {
                    index,
                    version: output.lock.version(),
                });
            }
        }

        if !self.policy.allow_unknown_lock_versions {
            for (index, spent) in spent_outputs.iter().enumerate() {
                if !spent.lock.is_known_version() {
                    return Err(Reject::UnknownLockVersionSpent {
                        index,
                        version: spent.lock.version(),
                    });
                }
            }
        }

        // 受け入れる。
        let entry = MempoolEntry {
            txid,
            fee: summary.fee,
            size,
            arrival: self.next_arrival,
            tx,
        };
        self.next_arrival += 1;
        for input in &entry.tx.inputs {
            self.spent.insert(input.prev_out, txid);
        }
        self.total_size += size;
        self.entries.insert(txid, entry);

        self.evict_until_within_limit();
        Ok(txid)
    }

    /// 1 件と、その出力に依存する子孫を取り除く。
    ///
    /// 取り除いた ID を返す。
    pub fn remove_recursive(&mut self, txid: &Hash) -> Vec<Hash> {
        let mut removed = Vec::new();
        let mut frontier = vec![*txid];
        while let Some(current) = frontier.pop() {
            let Some(entry) = self.entries.remove(&current) else {
                continue;
            };
            self.total_size -= entry.size;
            for input in &entry.tx.inputs {
                self.spent.remove(&input.prev_out);
            }
            // この ID の出力を使っているものを探す。
            let children: Vec<Hash> = self
                .spent
                .iter()
                .filter(|(outpoint, _)| outpoint.txid == current)
                .map(|(_, child)| *child)
                .collect();
            frontier.extend(children);
            removed.push(current);
        }
        removed
    }

    /// 上限を超えている間、料率の低いものから取り除く。
    fn evict_until_within_limit(&mut self) {
        while self.total_size > self.policy.max_mempool_bytes {
            // 最も料率の低いものを選ぶ。
            let Some(worst) = self
                .entries
                .values()
                .reduce(|acc, e| if e.beats(acc) { acc } else { e })
                .map(|e| e.txid)
            else {
                return;
            };
            self.remove_recursive(&worst);
        }
    }

    /// ブロックが繋がったときの整理。
    ///
    /// ブロックに入ったトランザクションと、そのブロックと同じ UTXO を使う
    /// 競合するトランザクションを取り除く。取り除いた件数を返す。
    pub fn on_block_connected(&mut self, block: &Block) -> usize {
        let mut removed = 0;

        // ブロックに入ったもの。
        for tx in &block.transactions {
            let txid = tx.txid();
            if self.entries.contains_key(&txid) {
                removed += self.remove_recursive(&txid).len();
            }
        }

        // ブロックが使った UTXO を使おうとしているもの (二重使用になった)。
        let mut conflicting = Vec::new();
        for tx in &block.transactions {
            if tx.is_coinbase() {
                continue;
            }
            for input in &tx.inputs {
                if let Some(txid) = self.spent.get(&input.prev_out) {
                    conflicting.push(*txid);
                }
            }
        }
        for txid in conflicting {
            removed += self.remove_recursive(&txid).len();
        }

        removed
    }

    /// ブロックが取り消されたときに、mempool へ戻すべきトランザクション。
    ///
    /// **戻す処理自体は行わない。** 戻すには改めて検証が要り、そのためには
    /// リオーグ後の UTXO の状態が必要だからである。呼び出し側がリオーグを
    /// 終えてから [`Mempool::accept`] を呼ぶ。
    pub fn transactions_to_resubmit(block: &Block) -> Vec<Transaction> {
        block
            .transactions
            .iter()
            .filter(|tx| !tx.is_coinbase())
            .cloned()
            .collect()
    }

    /// ブロックに詰めるトランザクションを選ぶ。
    ///
    /// 料率の高いものから貪欲に選ぶ。ただし **mempool 内の依存関係を守り、
    /// 親を子より先に置く**。ブロック内のトランザクションは依存順でなければ
    /// ならないためである (SPEC §10.2)。
    ///
    /// `available_bytes` はコインベースを除いた、使える領域の大きさ。
    pub fn select_for_block(&self, available_bytes: usize) -> Vec<Transaction> {
        let mut selected: Vec<&MempoolEntry> = Vec::new();
        let mut chosen: HashSet<Hash> = HashSet::new();
        let mut used = 0usize;

        loop {
            // まだ選んでおらず、依存が満たされていて、容量に収まるもののうち
            // 最も料率の高いものを取る。
            let mut best: Option<&MempoolEntry> = None;
            for entry in self.entries.values() {
                if chosen.contains(&entry.txid) || used + entry.size > available_bytes {
                    continue;
                }
                // mempool 内の親がすべて選ばれているか。
                let ready = entry.tx.inputs.iter().all(|input| {
                    !self.entries.contains_key(&input.prev_out.txid)
                        || chosen.contains(&input.prev_out.txid)
                });
                if !ready {
                    continue;
                }
                if best.is_none_or(|b| entry.beats(b)) {
                    best = Some(entry);
                }
            }

            let Some(entry) = best else { break };
            used += entry.size;
            chosen.insert(entry.txid);
            selected.push(entry);
        }

        selected.into_iter().map(|e| e.tx.clone()).collect()
    }
}

impl Default for Mempool {
    fn default() -> Mempool {
        Mempool::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_consensus::lock::Lock;
    use oag_consensus::sighash::{sighash, SighashType};
    use oag_consensus::tx::{TxInput, CURRENT_TX_VERSION};
    use oag_consensus::utxo::UtxoSet;
    use oag_consensus::BlockHeader;
    use oag_primitives::{hash, merkle, SecretKey};

    const HEIGHT: u64 = 500;
    const MTP: i64 = 1_800_000_000;

    /// 使える資金 1 件。
    struct Funds {
        outpoint: OutPoint,
        output: TxOutput,
        key: SecretKey,
    }

    /// 使用可能な UTXO を用意する。コインベースではないので成熟の制約はない。
    fn fund(utxo: &mut UtxoSet, amount: &str, seed: &[u8]) -> Funds {
        let key = SecretKey::generate();
        let output = TxOutput::new(
            amount.parse().unwrap(),
            Lock::pay_to_pubkey(&key.public_key()),
        );
        let outpoint = OutPoint::new(hash::txid(seed), 0);
        utxo.insert(
            outpoint,
            UtxoEntry {
                output: output.clone(),
                height: 1,
                is_coinbase: false,
            },
        )
        .unwrap();
        Funds {
            outpoint,
            output,
            key,
        }
    }

    /// 指定した出力を持つ、署名済みトランザクションを作る。
    fn spend(funds: &[&Funds], outputs: Vec<TxOutput>) -> Transaction {
        let mut tx = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: funds.iter().map(|f| TxInput::new(f.outpoint)).collect(),
            outputs,
            locktime: 0,
        };
        let spent: Vec<TxOutput> = funds.iter().map(|f| f.output.clone()).collect();
        let messages: Vec<[u8; 32]> = (0..tx.inputs.len())
            .map(|i| sighash(&tx, &spent, i, SighashType::DEFAULT).unwrap())
            .collect();
        for ((input, f), msg) in tx.inputs.iter_mut().zip(funds).zip(&messages) {
            input.signature = f.key.sign(msg).to_bytes().to_vec();
        }
        tx
    }

    fn to(amount: &str) -> TxOutput {
        TxOutput::new(
            amount.parse().unwrap(),
            Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
        )
    }

    /// 資金 1 件を使い、手数料を差し引いた 1 出力を作る。
    fn simple_spend(funds: &Funds, fee: &str) -> Transaction {
        let fee: Amount = fee.parse().unwrap();
        let out = funds.output.amount.checked_sub(fee).unwrap();
        spend(&[funds], vec![TxOutput::new(out, to("1").lock)])
    }

    fn setup() -> (Mempool, UtxoSet, Funds) {
        let mut utxo = UtxoSet::new();
        let funds = fund(&mut utxo, "10", b"a");
        (Mempool::new(), utxo, funds)
    }

    // ━━━━━━━━ 受け入れ ━━━━━━━━

    #[test]
    fn accepts_a_valid_transaction() {
        let (mut pool, utxo, funds) = setup();
        let tx = simple_spend(&funds, "0.01");
        let txid = pool.accept(tx.clone(), &utxo, HEIGHT, MTP).unwrap();

        assert_eq!(txid, tx.txid());
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&txid));
        assert_eq!(pool.total_size(), tx.size());
        assert_eq!(pool.get(&txid).unwrap().fee.to_string(), "0.01");
    }

    #[test]
    fn rejects_a_duplicate() {
        let (mut pool, utxo, funds) = setup();
        let tx = simple_spend(&funds, "0.01");
        pool.accept(tx.clone(), &utxo, HEIGHT, MTP).unwrap();
        assert_eq!(
            pool.accept(tx, &utxo, HEIGHT, MTP),
            Err(Reject::AlreadyKnown)
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn rejects_a_coinbase() {
        let (mut pool, utxo, _) = setup();
        let coinbase = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput::new(OutPoint::null())],
            outputs: vec![to("10")],
            locktime: 0,
        };
        assert_eq!(
            pool.accept(coinbase, &utxo, HEIGHT, MTP),
            Err(Reject::Coinbase)
        );
    }

    #[test]
    fn rejects_a_consensus_invalid_transaction() {
        let (mut pool, utxo, funds) = setup();
        // 署名した後に金額を書き換える。
        let mut tx = simple_spend(&funds, "0.01");
        tx.outputs[0].amount = Amount::from_oag(1).unwrap();
        assert!(matches!(
            pool.accept(tx, &utxo, HEIGHT, MTP),
            Err(Reject::Consensus(ValidationError::BadSignature { .. }))
        ));
        assert!(pool.is_empty());
    }

    #[test]
    fn rejects_spending_an_unknown_utxo() {
        let (mut pool, utxo, funds) = setup();
        let mut tx = simple_spend(&funds, "0.01");
        tx.inputs[0].prev_out = OutPoint::new(hash::txid(b"ghost"), 0);
        assert!(matches!(
            pool.accept(tx, &utxo, HEIGHT, MTP),
            Err(Reject::Consensus(ValidationError::MissingUtxo))
        ));
    }

    // ━━━━━━━━ 手数料ポリシー ━━━━━━━━

    #[test]
    fn the_minimum_fee_boundary_is_exact() {
        let (mut pool, utxo, funds) = setup();

        // まず必要額を測る。
        let probe = simple_spend(&funds, "0.001");
        let required = pool.policy().required_fee(probe.size()).unwrap();

        // 1 atomic 足りないと拒否される。
        let short = Amount::from_atomic(required.to_atomic() - 1).unwrap();
        let tx = spend(
            &[&funds],
            vec![TxOutput::new(
                funds.output.amount.checked_sub(short).unwrap(),
                to("1").lock,
            )],
        );
        assert_eq!(tx.size(), probe.size(), "サイズが変わってしまっている");
        assert_eq!(
            pool.accept(tx, &utxo, HEIGHT, MTP),
            Err(Reject::FeeTooLow {
                paid: short,
                required
            })
        );

        // ちょうどなら通る。
        let tx = spend(
            &[&funds],
            vec![TxOutput::new(
                funds.output.amount.checked_sub(required).unwrap(),
                to("1").lock,
            )],
        );
        assert!(pool.accept(tx, &utxo, HEIGHT, MTP).is_ok());
    }

    #[test]
    fn rejects_dust_outputs() {
        let (mut pool, utxo, funds) = setup();
        let threshold = pool.policy().dust_threshold;
        let dust = Amount::from_atomic(threshold.to_atomic() - 1).unwrap();
        let rest = funds
            .output
            .amount
            .checked_sub(dust)
            .unwrap()
            .checked_sub("0.01".parse().unwrap())
            .unwrap();
        let tx = spend(
            &[&funds],
            vec![
                TxOutput::new(rest, to("1").lock),
                TxOutput::new(dust, to("1").lock),
            ],
        );
        assert_eq!(
            pool.accept(tx, &utxo, HEIGHT, MTP),
            Err(Reject::DustOutput {
                index: 1,
                amount: dust,
                threshold
            })
        );
    }

    // ━━━━━━━━ 未知の版数 (SPEC §10.4 のポリシー層) ━━━━━━━━

    #[test]
    fn refuses_to_create_an_unknown_lock_version() {
        // コンセンサス上は有効だが、送金すると資金を失う恐れがあるため中継しない。
        let (mut pool, utxo, funds) = setup();
        let future_lock = Lock::new(7, vec![0xab; 32]).unwrap();
        let tx = spend(
            &[&funds],
            vec![TxOutput::new("9.99".parse().unwrap(), future_lock)],
        );
        assert_eq!(
            pool.accept(tx, &utxo, HEIGHT, MTP),
            Err(Reject::UnknownLockVersionCreated {
                index: 0,
                version: 7
            })
        );
    }

    #[test]
    fn refuses_to_spend_an_unknown_lock_version() {
        let mut utxo = UtxoSet::new();
        let outpoint = OutPoint::new(hash::txid(b"future"), 0);
        utxo.insert(
            outpoint,
            UtxoEntry {
                output: TxOutput::new(
                    Amount::from_oag(10).unwrap(),
                    Lock::new(7, vec![0xcd; 32]).unwrap(),
                ),
                height: 1,
                is_coinbase: false,
            },
        )
        .unwrap();

        // 未知の版数は誰でも使えるので、署名なしでコンセンサス検証は通る。
        let tx = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput::new(outpoint)],
            outputs: vec![to("9.99")],
            locktime: 0,
        };
        let mut pool = Mempool::new();
        assert_eq!(
            pool.accept(tx, &utxo, HEIGHT, MTP),
            Err(Reject::UnknownLockVersionSpent {
                index: 0,
                version: 7
            })
        );
    }

    #[test]
    fn a_permissive_policy_allows_unknown_versions() {
        let mut utxo = UtxoSet::new();
        let funds = fund(&mut utxo, "10", b"a");
        let mut pool = Mempool::with_policy(Policy {
            allow_unknown_lock_versions: true,
            ..Policy::default()
        });

        let tx = spend(
            &[&funds],
            vec![TxOutput::new(
                "9.99".parse().unwrap(),
                Lock::new(7, vec![0xab; 32]).unwrap(),
            )],
        );
        assert!(pool.accept(tx, &utxo, HEIGHT, MTP).is_ok());
    }

    // ━━━━━━━━ 競合と依存 ━━━━━━━━

    #[test]
    fn rejects_a_double_spend() {
        let (mut pool, utxo, funds) = setup();
        let first = simple_spend(&funds, "0.01");
        let first_id = pool.accept(first, &utxo, HEIGHT, MTP).unwrap();

        // 同じ UTXO を使う別のトランザクション。
        let second = spend(&[&funds], vec![to("9.98")]);
        assert_eq!(
            pool.accept(second, &utxo, HEIGHT, MTP),
            Err(Reject::Conflict {
                outpoint: funds.outpoint,
                existing: first_id
            })
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn accepts_a_transaction_that_spends_a_mempool_output() {
        let (mut pool, utxo, funds) = setup();
        let parent_key = SecretKey::generate();
        let parent = spend(
            &[&funds],
            vec![TxOutput::new(
                "9.99".parse().unwrap(),
                Lock::pay_to_pubkey(&parent_key.public_key()),
            )],
        );
        let parent_id = pool.accept(parent.clone(), &utxo, HEIGHT, MTP).unwrap();

        let middle = Funds {
            outpoint: OutPoint::new(parent_id, 0),
            output: parent.outputs[0].clone(),
            key: parent_key,
        };
        let child = simple_spend(&middle, "0.01");
        assert!(
            pool.accept(child, &utxo, HEIGHT, MTP).is_ok(),
            "mempool 内の出力を使えない"
        );
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn removing_a_parent_removes_its_descendants() {
        let (mut pool, utxo, funds) = setup();
        let parent_key = SecretKey::generate();
        let parent = spend(
            &[&funds],
            vec![TxOutput::new(
                "9.99".parse().unwrap(),
                Lock::pay_to_pubkey(&parent_key.public_key()),
            )],
        );
        let parent_id = pool.accept(parent.clone(), &utxo, HEIGHT, MTP).unwrap();
        let middle = Funds {
            outpoint: OutPoint::new(parent_id, 0),
            output: parent.outputs[0].clone(),
            key: parent_key,
        };
        let child = simple_spend(&middle, "0.01");
        let child_id = pool.accept(child, &utxo, HEIGHT, MTP).unwrap();

        let removed = pool.remove_recursive(&parent_id);
        assert_eq!(removed.len(), 2, "子孫も取り除かれるべき");
        assert!(pool.is_empty());
        assert_eq!(pool.total_size(), 0);
        assert!(!pool.contains(&child_id));
    }

    // ━━━━━━━━ ブロックへの選択 ━━━━━━━━

    #[test]
    fn selection_prefers_higher_fee_rates() {
        let mut utxo = UtxoSet::new();
        let cheap = fund(&mut utxo, "10", b"cheap");
        let rich = fund(&mut utxo, "10", b"rich");
        let mut pool = Mempool::new();

        pool.accept(simple_spend(&cheap, "0.01"), &utxo, HEIGHT, MTP)
            .unwrap();
        let rich_tx = simple_spend(&rich, "1");
        let rich_id = pool.accept(rich_tx, &utxo, HEIGHT, MTP).unwrap();

        let selected = pool.select_for_block(params::MAX_BLOCK_SIZE);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].txid(), rich_id, "料率の高い方が先に来るべき");
    }

    #[test]
    fn selection_keeps_parents_before_children() {
        // 子の手数料が高くても、親より先に置いてはならない。
        // ブロック内のトランザクションは依存順である必要がある (SPEC §10.2)。
        let (mut pool, utxo, funds) = setup();
        let parent_key = SecretKey::generate();
        let parent = spend(
            &[&funds],
            vec![TxOutput::new(
                "9.99".parse().unwrap(),
                Lock::pay_to_pubkey(&parent_key.public_key()),
            )],
        );
        let parent_id = pool.accept(parent.clone(), &utxo, HEIGHT, MTP).unwrap();

        let middle = Funds {
            outpoint: OutPoint::new(parent_id, 0),
            output: parent.outputs[0].clone(),
            key: parent_key,
        };
        // 子の手数料をずっと高くする。
        let child = simple_spend(&middle, "5");
        let child_id = pool.accept(child, &utxo, HEIGHT, MTP).unwrap();
        assert!(pool.get(&child_id).unwrap().fee_rate() > pool.get(&parent_id).unwrap().fee_rate());

        let selected = pool.select_for_block(params::MAX_BLOCK_SIZE);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].txid(), parent_id, "親が先に来ていない");
        assert_eq!(selected[1].txid(), child_id);
    }

    #[test]
    fn selection_respects_the_size_limit() {
        let mut utxo = UtxoSet::new();
        let mut pool = Mempool::new();
        let mut sizes = Vec::new();
        for i in 0..5u8 {
            let funds = fund(&mut utxo, "10", &[i]);
            let tx = simple_spend(&funds, "0.01");
            sizes.push(tx.size());
            pool.accept(tx, &utxo, HEIGHT, MTP).unwrap();
        }
        // 2 件分だけの領域を与える。
        let budget = sizes[0] * 2 + 10;
        let selected = pool.select_for_block(budget);
        assert_eq!(selected.len(), 2);
        assert!(selected.iter().map(|t| t.size()).sum::<usize>() <= budget);

        assert!(pool.select_for_block(0).is_empty());
    }

    #[test]
    fn a_child_is_left_out_when_only_the_parent_fits() {
        let (mut pool, utxo, funds) = setup();
        let parent_key = SecretKey::generate();
        let parent = spend(
            &[&funds],
            vec![TxOutput::new(
                "9.99".parse().unwrap(),
                Lock::pay_to_pubkey(&parent_key.public_key()),
            )],
        );
        let parent_id = pool.accept(parent.clone(), &utxo, HEIGHT, MTP).unwrap();
        let middle = Funds {
            outpoint: OutPoint::new(parent_id, 0),
            output: parent.outputs[0].clone(),
            key: parent_key,
        };
        pool.accept(simple_spend(&middle, "0.01"), &utxo, HEIGHT, MTP)
            .unwrap();

        let selected = pool.select_for_block(parent.size());
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].txid(), parent_id);
    }

    // ━━━━━━━━ チェーンの変化への追随 ━━━━━━━━

    fn block_with(transactions: Vec<Transaction>) -> Block {
        let txids: Vec<Hash> = transactions.iter().map(|t| t.txid()).collect();
        Block {
            header: BlockHeader {
                version: 0,
                prev_hash: Hash::ZERO,
                merkle_root: merkle::merkle_root(&txids).unwrap_or(Hash::ZERO),
                timestamp: MTP + 60,
                difficulty: 1,
                height: HEIGHT,
                nonce: 0,
            },
            transactions,
        }
    }

    #[test]
    fn a_connected_block_clears_the_transactions_it_contains() {
        let (mut pool, utxo, funds) = setup();
        let tx = simple_spend(&funds, "0.01");
        pool.accept(tx.clone(), &utxo, HEIGHT, MTP).unwrap();
        assert_eq!(pool.len(), 1);

        assert_eq!(pool.on_block_connected(&block_with(vec![tx])), 1);
        assert!(pool.is_empty());
        assert_eq!(pool.total_size(), 0);
    }

    #[test]
    fn a_connected_block_clears_conflicting_transactions() {
        // ブロックが同じ UTXO を別の形で使った場合、mempool のものは
        // 二重使用になるので取り除かれる。
        let (mut pool, utxo, funds) = setup();
        let mine = simple_spend(&funds, "0.01");
        pool.accept(mine, &utxo, HEIGHT, MTP).unwrap();

        let theirs = spend(&[&funds], vec![to("9.5")]);
        assert_eq!(pool.on_block_connected(&block_with(vec![theirs])), 1);
        assert!(pool.is_empty(), "競合するものが残っている");
    }

    #[test]
    fn a_connected_block_leaves_unrelated_transactions_alone() {
        let mut utxo = UtxoSet::new();
        let mine = fund(&mut utxo, "10", b"mine");
        let other = fund(&mut utxo, "10", b"other");
        let mut pool = Mempool::new();
        pool.accept(simple_spend(&mine, "0.01"), &utxo, HEIGHT, MTP)
            .unwrap();

        let unrelated = simple_spend(&other, "0.01");
        assert_eq!(pool.on_block_connected(&block_with(vec![unrelated])), 0);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn a_disconnected_block_yields_its_non_coinbase_transactions() {
        let (_, utxo, funds) = setup();
        let payment = simple_spend(&funds, "0.01");
        let coinbase = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput::new(OutPoint::null())],
            outputs: vec![to("10")],
            locktime: 0,
        };
        let block = block_with(vec![coinbase, payment.clone()]);

        let resubmit = Mempool::transactions_to_resubmit(&block);
        assert_eq!(resubmit, vec![payment]);
        let _ = utxo;
    }

    // ━━━━━━━━ 追い出し ━━━━━━━━

    #[test]
    fn the_lowest_fee_rate_is_evicted_when_full() {
        let mut utxo = UtxoSet::new();
        let cheap = fund(&mut utxo, "10", b"cheap");
        let rich = fund(&mut utxo, "10", b"rich");

        // 1 件しか入らない大きさにする。
        let probe = simple_spend(&cheap, "0.01");
        let mut pool = Mempool::with_policy(Policy {
            max_mempool_bytes: probe.size(),
            ..Policy::default()
        });

        let cheap_id = pool
            .accept(simple_spend(&cheap, "0.01"), &utxo, HEIGHT, MTP)
            .unwrap();
        assert_eq!(pool.len(), 1);

        let rich_id = pool
            .accept(simple_spend(&rich, "1"), &utxo, HEIGHT, MTP)
            .unwrap();
        assert_eq!(pool.len(), 1, "上限を超えたまま保持している");
        assert!(pool.contains(&rich_id), "料率の高い方が残るべき");
        assert!(!pool.contains(&cheap_id));
        assert!(pool.total_size() <= pool.policy().max_mempool_bytes);
    }

    #[test]
    fn eviction_keeps_the_accounting_consistent() {
        let mut utxo = UtxoSet::new();
        let probe_funds = fund(&mut utxo, "10", b"probe");
        let mut pool = Mempool::with_policy(Policy {
            max_mempool_bytes: simple_spend(&probe_funds, "0.01").size() * 3,
            ..Policy::default()
        });

        for i in 0..10u8 {
            let funds = fund(&mut utxo, "10", &[i, 0xff]);
            let fee = format!("0.{:02}", i + 1);
            pool.accept(simple_spend(&funds, &fee), &utxo, HEIGHT, MTP)
                .unwrap();
        }

        assert!(pool.total_size() <= pool.policy().max_mempool_bytes);
        // 記録されている合計が実際と一致すること。
        let actual: usize = pool
            .txids()
            .iter()
            .map(|id| pool.get(id).unwrap().size)
            .sum();
        assert_eq!(pool.total_size(), actual);
        // 使用中の参照先の数も一致すること。
        let inputs: usize = pool
            .txids()
            .iter()
            .map(|id| pool.get(id).unwrap().tx.inputs.len())
            .sum();
        assert_eq!(pool.spent.len(), inputs, "spent の記録が漏れている");
    }
}
