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
use oag_consensus::validate::{validate_transaction, SignatureChecks, ValidationError};
use oag_consensus::{Block, Transaction, TxOutput};
use oag_primitives::{Amount, Hash};
use std::collections::{HashMap, HashSet};

/// mempool がトランザクションを受け入れなかった理由。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Reject {
    /// すでに保持している。
    #[error("already in the mempool")]
    AlreadyKnown,
    /// コインベースは単独では流通しない。
    #[error("a coinbase transaction cannot enter the mempool")]
    Coinbase,
    /// 大きすぎる。
    #[error("size {actual} exceeds the limit {max}")]
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
    #[error("fee {paid} is below the minimum required {required}")]
    FeeTooLow {
        /// 支払われた手数料。
        paid: Amount,
        /// 要求される手数料。
        required: Amount,
    },
    /// ダスト閾値未満の出力を含む。
    #[error("the amount {amount} of output {index} is below the dust threshold {threshold}")]
    DustOutput {
        /// 出力番号。
        index: usize,
        /// その金額。
        amount: Amount,
        /// 閾値。
        threshold: Amount,
    },
    /// 未知の版数の支払い条件を作ろうとしている。
    #[error("output {index} uses the unknown version {version} (the funds may be lost)")]
    UnknownLockVersionCreated {
        /// 出力番号。
        index: usize,
        /// 版数。
        version: u8,
    },
    /// 未知の版数の支払い条件を使おうとしている。
    #[error("input {index} tries to spend an output of the unknown version {version}")]
    UnknownLockVersionSpent {
        /// 入力番号。
        index: usize,
        /// 版数。
        version: u8,
    },
    /// 置き換えが、追い出す側に無かった未確認の入力を加えている。
    ///
    /// BIP125 規則 2。未確認の入力を足されると、置き換えの可否を決めるのに
    /// 必要な手数料の合計が、まだ確定していない祖先の可否に依存する。
    #[error("the replacement adds a new unconfirmed input {outpoint:?}")]
    ReplacementAddsUnconfirmedInput {
        /// 加えられた参照先。
        outpoint: OutPoint,
    },
    /// 置き換えの手数料が、追い出す分の合計に満たない。
    ///
    /// BIP125 規則 3。
    #[error("the replacement fee {paid} is below the total {replaced} of the {count} it evicts")]
    ReplacementPaysLess {
        /// 置き換えが払う手数料。
        paid: Amount,
        /// 追い出す側の合計手数料。
        replaced: Amount,
        /// 追い出す件数。
        count: usize,
    },
    /// 置き換えが自分自身を運ぶ帯域の代金を払っていない。
    ///
    /// BIP125 規則 4。
    #[error("the fee increment {increment} is below the {required} required for {size} bytes")]
    ReplacementIncrementTooLow {
        /// 追い出す側の合計を超えた分。
        increment: Amount,
        /// 要求される増分。
        required: Amount,
        /// 置き換えのサイズ。
        size: usize,
    },
    /// 1 度の置き換えで追い出す件数が多すぎる。
    ///
    /// BIP125 規則 5。
    #[error("the replacement would evict {count} entries (limit {max})")]
    TooManyReplacements {
        /// 追い出そうとしている件数 (子孫を含む)。
        count: usize,
        /// 上限。
        max: usize,
    },
}

/// [`Mempool::accept_with_replacements`] が受け入れた結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// 受け入れたトランザクションの ID。
    pub txid: Hash,
    /// 置き換えで取り除いた ID (子孫を含む)。置き換えでなければ空。
    pub replaced: Vec<Hash>,
}

/// リオーグの後に mempool を組み直した結果。
///
/// 合計が組み直しに掛けた件数である。ただし上限を超えた分は、この後の
/// 追い出しでさらに減ることがある ([`Policy::max_mempool_bytes`])。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rebuilt {
    /// 取り消された枝から mempool へ戻したもの。
    pub resubmitted: usize,
    /// 元から mempool にあり、検証し直しても通ったもの。
    pub retained: usize,
    /// 検証し直して落ちたもの。新しい枝にすでに入っている、二重使用に
    /// なった、親を失った、成熟や locktime に届かなくなった、のいずれか。
    pub dropped: usize,
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
    /// 置き換えで消える予定のトランザクション。**居ないものとして見る。**
    ///
    /// 置き換えの検証は、追い出す側をまだ取り除かないまま行う。先に取り除くと、
    /// 検証に落ちたときに戻さなければならず、戻し損ねれば手数料の高いほうを
    /// 捨てたうえで低いほうも失う。ここで見えなくするほうが安全である。
    replacing: &'a HashSet<Hash>,
}

impl UtxoView for PoolView<'_> {
    fn get(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, UtxoError> {
        if let Some(spender) = self.pool.spent.get(outpoint) {
            if !self.replacing.contains(spender) {
                return Ok(None);
            }
        }
        if !self.replacing.contains(&outpoint.txid) {
            if let Some(entry) = self.pool.output_at(outpoint, self.next_height) {
                return Ok(Some(entry));
            }
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

    /// 置き換えで消えることになる集合 (直接の競合とその子孫)。
    ///
    /// `cutoff` を超えたところで数え上げをやめる。上限を超えていることが
    /// 分かれば断ると決まるので、それ以上たどる意味がない。**再帰では
    /// 書かない。** 依存の鎖の長さに上限は無く、深さがそのまま
    /// スタックの深さになる。
    fn replacement_set(&self, conflicts: &HashSet<Hash>, cutoff: usize) -> HashSet<Hash> {
        let mut set = conflicts.clone();
        let mut frontier: Vec<Hash> = conflicts.iter().copied().collect();
        while let Some(current) = frontier.pop() {
            if set.len() > cutoff {
                break;
            }
            let children: Vec<Hash> = self
                .spent
                .iter()
                .filter(|(outpoint, _)| outpoint.txid == current)
                .map(|(_, child)| *child)
                .collect();
            for child in children {
                if set.insert(child) {
                    frontier.push(child);
                }
            }
        }
        set
    }

    /// 置き換えとして受け入れてよいかを調べる。
    ///
    /// BIP125 の規則 2 から 5 にあたる。規則 1 (置き換え可能の表明) は
    /// 適用しない。詳しくは [`Mempool::accept_with_replacements`] を参照。
    fn check_replacement(
        &self,
        tx: &Transaction,
        fee: Amount,
        size: usize,
        conflicts: &HashSet<Hash>,
        replacing: &HashSet<Hash>,
    ) -> Result<(), Reject> {
        // 規則 5: 追い出す件数の上限。
        if replacing.len() > self.policy.max_replacement_count {
            return Err(Reject::TooManyReplacements {
                count: replacing.len(),
                max: self.policy.max_replacement_count,
            });
        }

        // 規則 2: 追い出す側に無かった未確認の入力を加えない。
        //
        // 未確認の入力を足されると、この置き換えが割に合うかどうかが、
        // まだ mempool にいる祖先の運命に左右される。追い出す側が既に
        // 使っていた参照先なら、その判断は済んでいる。
        let already_spent_by_originals: HashSet<OutPoint> = conflicts
            .iter()
            .filter_map(|txid| self.entries.get(txid))
            .flat_map(|entry| entry.tx.inputs.iter().map(|input| input.prev_out))
            .collect();
        for input in &tx.inputs {
            let unconfirmed = self.entries.contains_key(&input.prev_out.txid);
            if unconfirmed && !already_spent_by_originals.contains(&input.prev_out) {
                return Err(Reject::ReplacementAddsUnconfirmedInput {
                    outpoint: input.prev_out,
                });
            }
        }

        // 規則 3: 追い出す分の合計手数料を下回らない。
        let replaced_fee = Amount::sum(
            replacing
                .iter()
                .filter_map(|txid| self.entries.get(txid))
                .map(|entry| entry.fee),
        )
        .ok_or(Reject::ReplacementPaysLess {
            paid: fee,
            replaced: Amount::MAX,
            count: replacing.len(),
        })?;
        let Some(increment) = fee.checked_sub(replaced_fee) else {
            return Err(Reject::ReplacementPaysLess {
                paid: fee,
                replaced: replaced_fee,
                count: replacing.len(),
            });
        };

        // 規則 4: 自分自身を運ぶ帯域の代金を、上乗せして払う。
        let required =
            self.policy
                .required_increment(size)
                .ok_or(Reject::ReplacementIncrementTooLow {
                    increment,
                    required: Amount::MAX,
                    size,
                })?;
        if increment < required {
            return Err(Reject::ReplacementIncrementTooLow {
                increment,
                required,
                size,
            });
        }

        Ok(())
    }

    /// トランザクションを受け入れる。受け入れた ID を返す。
    ///
    /// 置き換えで何が消えたかを知りたい場合は
    /// [`Mempool::accept_with_replacements`] を使う。
    pub fn accept(
        &mut self,
        tx: Transaction,
        chain_utxo: &dyn UtxoView,
        next_height: u64,
        median_time_past: i64,
    ) -> Result<Hash, Reject> {
        self.accept_with_replacements(tx, chain_utxo, next_height, median_time_past)
            .map(|accepted| accepted.txid)
    }

    /// トランザクションを受け入れ、置き換えで消えた ID も返す。
    ///
    /// `chain_utxo` は確定済みチェーンの UTXO、`next_height` はこの
    /// トランザクションが入りうる最初のブロックの高さ、`median_time_past` は
    /// 現在の先端のものを渡す。
    ///
    /// # 手数料を上げた置き換え (RBF)
    ///
    /// すでに mempool にあるものと同じ UTXO を使うトランザクションは、
    /// BIP125 の規則 2 から 5 を満たせば、先に来たものを**追い出して**
    /// 入る。子孫も道連れになる。
    ///
    /// **規則 1 (置き換え可能の表明) は適用しない。** Bitcoin が最後に
    /// 落ち着いた形と同じである。`sequence` による表明は、表明していない
    /// トランザクションが 0 承認で安全であるかのような見かけを作るが、
    /// その保証は元々存在しない。採掘者は手数料の高いほうを選べばよく、
    /// 表明を見ないノードが 1 つでも中継すれば置き換えは伝わる。守れない
    /// 約束を掲げるより、置き換えは常に起こりうるものとして扱う。
    ///
    /// **0 承認のトランザクションを支払いとして受け取ってはならない。**
    ///
    /// 規則 3 と 4 が見ているのは**手数料の総額**であって料率ではない。
    /// したがって、大きくて料率の低い置き換えが、小さくて料率の高いものを
    /// 追い出せる。BIP125 が抱えたままの弱点であり、Bitcoin も同じである
    /// (`docs/SPEC.md` §13.3.2)。
    pub fn accept_with_replacements(
        &mut self,
        tx: Transaction,
        chain_utxo: &dyn UtxoView,
        next_height: u64,
        median_time_past: i64,
    ) -> Result<Accepted, Reject> {
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

        // 同じ UTXO を使っているものを集める。空でなければ置き換えである。
        let conflicts: HashSet<Hash> = tx
            .inputs
            .iter()
            .filter_map(|input| self.spent.get(&input.prev_out).copied())
            .collect();
        let replacing = self.replacement_set(&conflicts, self.policy.max_replacement_count);

        let view = PoolView {
            base: chain_utxo,
            pool: self,
            next_height,
            replacing: &replacing,
        };

        // 使用対象の支払い条件を、コンセンサス検証の前に集めておく。
        let mut spent_outputs: Vec<TxOutput> = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            if let Some(entry) = view.get(&input.prev_out)? {
                spent_outputs.push(entry.output);
            }
        }

        // ここまではポリシー。ここからコンセンサス。
        // mempool は常に完全検証である。assumevalid は「深く埋まった過去」に
        // だけ許される緩和であり、未確認トランザクションには適用されない。
        let summary = validate_transaction(
            &tx,
            &view,
            next_height,
            median_time_past,
            0,
            SignatureChecks::Verify,
        )?;

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

        if !replacing.is_empty() {
            self.check_replacement(&tx, summary.fee, size, &conflicts, &replacing)?;
        }

        // ここから先は失敗しない。**追い出すのはこの時点である。**
        let mut replaced = Vec::new();
        for conflict in &conflicts {
            replaced.extend(self.remove_recursive(conflict));
        }
        replaced.sort_unstable();
        replaced.dedup();

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
        Ok(Accepted { txid, replaced })
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
    /// リオーグ後の UTXO の状態が必要だからである。リオーグを終えてから
    /// [`Mempool::rebuild_after_reorg`] にまとめて渡す。
    pub fn transactions_to_resubmit(block: &Block) -> Vec<Transaction> {
        block
            .transactions
            .iter()
            .filter(|tx| !tx.is_coinbase())
            .cloned()
            .collect()
    }

    /// リオーグの後、mempool を組み直す。
    ///
    /// 取り消された枝のトランザクション (`orphaned`、古い順) と、いま持って
    /// いるものを合わせ、**リオーグ後の UTXO で全部検証し直す。**
    ///
    /// 落ちたものだけを選んで外すのでは足りない。リオーグは残ったものの
    /// 前提も崩すからである。
    ///
    /// - 親が取り消された枝にあり、戻せなかった (新しい枝と二重使用になる)
    /// - 高さが戻り、コインベース成熟 ([`params::COINBASE_MATURITY`]) に
    ///   届かなくなった
    /// - 高さが戻り、locktime が再び未来になった
    ///
    /// **崩れたまま残すと、自分で掘ったブロックが自分で弾かれる。**
    /// テンプレートは mempool をそのまま詰めるためである。
    ///
    /// 新しい枝に入ったトランザクションを明示的に外す必要はない。使用済みに
    /// なった UTXO はこのビューから消えており、検証し直す時点で落ちる。
    ///
    /// 費用は mempool の大きさに比例する (署名を検証し直す)。リオーグは稀で
    /// あり、mempool には上限があるので、ここは単純さを取る。
    pub fn rebuild_after_reorg(
        &mut self,
        orphaned: Vec<Transaction>,
        chain_utxo: &dyn UtxoView,
        next_height: u64,
        median_time_past: i64,
    ) -> Rebuilt {
        // 取り消された枝のものを先に置く。いちど確認まで進んでいた側であり、
        // 同じ UTXO を奪い合ったときはこちらを優先する。
        let mut candidates: Vec<(bool, Transaction)> =
            orphaned.into_iter().map(|tx| (true, tx)).collect();

        // いま持っているものを到着順に取り出し、空にする。
        let mut existing: Vec<MempoolEntry> = self.entries.values().cloned().collect();
        existing.sort_by_key(|entry| entry.arrival);
        candidates.extend(existing.into_iter().map(|entry| (false, entry.tx)));

        self.entries.clear();
        self.spent.clear();
        self.total_size = 0;

        let mut report = Rebuilt::default();
        for (from_branch, tx) in dependency_order(candidates) {
            match self.accept(tx, chain_utxo, next_height, median_time_past) {
                Ok(_) if from_branch => report.resubmitted += 1,
                Ok(_) => report.retained += 1,
                Err(_) => report.dropped += 1,
            }
        }
        report
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

/// 親が子より先に来るように並べ替える。
///
/// 組み直しでは親を先に受け入れなければならない。子を先に出すと、その時点
/// では親の出力が存在せず、落ちてしまう。
///
/// 依存先が候補の中に無いもの (親がチェーン側にある、あるいは入力が
/// 見つからない) は元の順序のまま残る。候補の中に循環は作れない。txid は
/// トランザクションの中身のハッシュであり、自分の txid を含む親を指す
/// トランザクションは構成できないからである。それでも印で防いでおく。
fn dependency_order(candidates: Vec<(bool, Transaction)>) -> Vec<(bool, Transaction)> {
    let position: HashMap<Hash, usize> = candidates
        .iter()
        .enumerate()
        .map(|(index, (_, tx))| (tx.txid(), index))
        .collect();

    let mut done = vec![false; candidates.len()];
    let mut open = vec![false; candidates.len()];
    let mut ordered: Vec<usize> = Vec::with_capacity(candidates.len());
    // (候補の番号, 親を積み終えたか)。再帰にしないのは、長い連鎖でも
    // スタックを使い切らないようにするためである。
    let mut stack: Vec<(usize, bool)> = Vec::new();

    for start in 0..candidates.len() {
        if done[start] {
            continue;
        }
        stack.push((start, false));
        while let Some((index, expanded)) = stack.pop() {
            if done[index] || (!expanded && open[index]) {
                continue;
            }
            if expanded {
                done[index] = true;
                open[index] = false;
                ordered.push(index);
                continue;
            }
            open[index] = true;
            stack.push((index, true));
            for input in &candidates[index].1.inputs {
                if let Some(&parent) = position.get(&input.prev_out.txid) {
                    if !done[parent] && !open[parent] {
                        stack.push((parent, false));
                    }
                }
            }
        }
    }

    let mut slots: Vec<Option<(bool, Transaction)>> = candidates.into_iter().map(Some).collect();
    ordered
        .into_iter()
        .filter_map(|index| slots[index].take())
        .collect()
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
        assert_eq!(tx.size(), probe.size(), "the size has changed");
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

    // ━━━━━━━━ 手数料を上げた置き換え (RBF) ━━━━━━━━

    /// mempool にあるトランザクションの出力を、次の資金として扱う。
    fn from_pool(txid: Hash, tx: &Transaction, key: SecretKey) -> Funds {
        Funds {
            outpoint: OutPoint::new(txid, 0),
            output: tx.outputs[0].clone(),
            key,
        }
    }

    /// 親を 1 件、その出力を使う子を 1 件、mempool に入れる。
    fn parent_and_child(pool: &mut Mempool, utxo: &UtxoSet, funds: &Funds) -> (Hash, Hash) {
        let parent_key = SecretKey::generate();
        let parent = spend(
            &[funds],
            vec![TxOutput::new(
                "9.99".parse().unwrap(),
                Lock::pay_to_pubkey(&parent_key.public_key()),
            )],
        );
        let parent_id = pool.accept(parent.clone(), utxo, HEIGHT, MTP).unwrap();
        let child_funds = from_pool(parent_id, &parent, parent_key);
        let child_id = pool
            .accept(simple_spend(&child_funds, "0.01"), utxo, HEIGHT, MTP)
            .unwrap();
        (parent_id, child_id)
    }

    #[test]
    fn a_higher_fee_replaces_the_original() {
        let (mut pool, utxo, funds) = setup();
        let first_id = pool
            .accept(simple_spend(&funds, "0.01"), &utxo, HEIGHT, MTP)
            .unwrap();

        let accepted = pool
            .accept_with_replacements(simple_spend(&funds, "0.02"), &utxo, HEIGHT, MTP)
            .unwrap();

        assert_eq!(accepted.replaced, vec![first_id]);
        assert!(!pool.contains(&first_id), "it was evicted");
        assert!(pool.contains(&accepted.txid));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn a_replacement_that_pays_less_is_refused() {
        let (mut pool, utxo, funds) = setup();
        let first_id = pool
            .accept(simple_spend(&funds, "0.02"), &utxo, HEIGHT, MTP)
            .unwrap();

        let err = pool
            .accept(simple_spend(&funds, "0.01"), &utxo, HEIGHT, MTP)
            .unwrap_err();
        assert!(
            matches!(err, Reject::ReplacementPaysLess { count: 1, .. }),
            "{err}"
        );
        assert!(pool.contains(&first_id), "the original is still there");
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn a_replacement_must_pay_for_its_own_bandwidth() {
        let (mut pool, utxo, funds) = setup();
        pool.accept(simple_spend(&funds, "0.01"), &utxo, HEIGHT, MTP)
            .unwrap();

        // 手数料は上がっているが、上乗せが自分のサイズ分に足りない。
        // これを許すと、1 atomic ずつ上げるだけで同じ資金を何度でも
        // 中継させられる。
        let err = pool
            .accept(simple_spend(&funds, "0.0100001"), &utxo, HEIGHT, MTP)
            .unwrap_err();
        match err {
            Reject::ReplacementIncrementTooLow {
                increment,
                required,
                size,
            } => {
                assert!(increment < required, "{increment} < {required}");
                assert_eq!(
                    required,
                    Policy::default().required_increment(size).unwrap()
                );
            }
            other => panic!("{other}"),
        }
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn a_replacement_takes_the_descendants_with_it() {
        let (mut pool, utxo, funds) = setup();
        let (parent_id, child_id) = parent_and_child(&mut pool, &utxo, &funds);
        assert_eq!(pool.len(), 2);

        // 親を置き換えると、親の出力を使っていた子も行き場を失う。
        let accepted = pool
            .accept_with_replacements(simple_spend(&funds, "0.5"), &utxo, HEIGHT, MTP)
            .unwrap();

        let mut expected = vec![parent_id, child_id];
        expected.sort_unstable();
        assert_eq!(accepted.replaced, expected);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn a_replacement_pays_for_the_descendants_too() {
        let (mut pool, utxo, funds) = setup();
        parent_and_child(&mut pool, &utxo, &funds);

        // 親の手数料 0.01 だけを上回っても足りない。子の 0.01 も含めた
        // 合計を超える必要がある。
        let err = pool
            .accept(simple_spend(&funds, "0.015"), &utxo, HEIGHT, MTP)
            .unwrap_err();
        assert!(
            matches!(err, Reject::ReplacementPaysLess { count: 2, .. }),
            "{err}"
        );
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn a_replacement_may_not_add_an_unconfirmed_input() {
        let mut utxo = UtxoSet::new();
        let a = fund(&mut utxo, "10", b"a");
        let b = fund(&mut utxo, "10", b"b");
        let mut pool = Mempool::new();
        pool.accept(simple_spend(&a, "0.01"), &utxo, HEIGHT, MTP)
            .unwrap();

        let other_key = SecretKey::generate();
        let other = spend(
            &[&b],
            vec![TxOutput::new(
                "9.99".parse().unwrap(),
                Lock::pay_to_pubkey(&other_key.public_key()),
            )],
        );
        let other_id = pool.accept(other.clone(), &utxo, HEIGHT, MTP).unwrap();
        let unconfirmed = from_pool(other_id, &other, other_key);

        // a を置き換えつつ、mempool にしかない出力を新たに使う。手数料は
        // 十分だが、この置き換えが割に合うかどうかが other の運命に
        // 左右されることになる。
        let replacement = spend(&[&a, &unconfirmed], vec![to("19.5")]);
        assert_eq!(
            pool.accept(replacement, &utxo, HEIGHT, MTP),
            Err(Reject::ReplacementAddsUnconfirmedInput {
                outpoint: unconfirmed.outpoint
            })
        );
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn a_replacement_that_would_evict_too_many_is_refused() {
        let mut utxo = UtxoSet::new();
        let funds = fund(&mut utxo, "10", b"a");
        let mut pool = Mempool::with_policy(Policy {
            max_replacement_count: 1,
            ..Policy::default()
        });
        parent_and_child(&mut pool, &utxo, &funds);

        assert_eq!(
            pool.accept(simple_spend(&funds, "0.5"), &utxo, HEIGHT, MTP),
            Err(Reject::TooManyReplacements { count: 2, max: 1 })
        );
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn a_replacement_that_fails_validation_leaves_the_original_alone() {
        let (mut pool, utxo, funds) = setup();
        let first_id = pool
            .accept(simple_spend(&funds, "0.01"), &utxo, HEIGHT, MTP)
            .unwrap();

        // 手数料は申し分ないが、署名が通らない。
        let mut bad = simple_spend(&funds, "0.5");
        bad.inputs[0].signature = vec![0u8; 64];
        assert!(pool.accept(bad, &utxo, HEIGHT, MTP).is_err());

        assert!(
            pool.contains(&first_id),
            "the original must not be dropped for a replacement that failed"
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
            "an output in the mempool cannot be spent"
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
        assert_eq!(removed.len(), 2, "descendants should be removed too");
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
        assert_eq!(
            selected[0].txid(),
            rich_id,
            "the higher rate should come first"
        );
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
        assert_eq!(
            selected[0].txid(),
            parent_id,
            "the parent did not come first"
        );
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
        assert!(pool.is_empty(), "a conflicting entry is still there");
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

    // ━━━━━━━━ リオーグ後の組み直し ━━━━━━━━

    #[test]
    fn a_payment_from_the_undone_branch_comes_back_to_the_mempool() {
        // 取り消された枝に入っていた支払いは、また未確認に戻る。誰の
        // mempool にも無ければ、二度と掘られない。
        let (mut pool, utxo, funds) = setup();
        let payment = simple_spend(&funds, "0.01");
        let txid = payment.txid();

        let report = pool.rebuild_after_reorg(vec![payment], &utxo, HEIGHT, MTP);

        assert_eq!(report.resubmitted, 1);
        assert_eq!(report.dropped, 0);
        assert!(pool.contains(&txid));
    }

    #[test]
    fn a_payment_the_new_branch_already_carries_does_not_come_back() {
        // 新しい枝が同じ UTXO を使っているなら、その出力はもう無い。戻して
        // しまえば二重使用になる。
        let (mut pool, mut utxo, funds) = setup();
        let payment = simple_spend(&funds, "0.01");
        // 新しい枝が使い切ったものとする。
        utxo.remove(&funds.outpoint).unwrap();

        let report = pool.rebuild_after_reorg(vec![payment], &utxo, HEIGHT, MTP);

        assert_eq!(report.resubmitted, 0);
        assert_eq!(report.dropped, 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn an_entry_whose_input_the_new_branch_spent_is_dropped() {
        // 組み直しの要点。**落ちたものを選んで外すのではなく、全部検証し直す。**
        // 残したまま掘ると、自分のブロックが自分で弾かれる。
        let (mut pool, mut utxo, funds) = setup();
        let stale = simple_spend(&funds, "0.01");
        let stale_id = pool.accept(stale, &utxo, HEIGHT, MTP).unwrap();
        assert!(pool.contains(&stale_id));

        // 新しい枝が同じ UTXO を別の形で使った。
        utxo.remove(&funds.outpoint).unwrap();
        let report = pool.rebuild_after_reorg(Vec::new(), &utxo, HEIGHT, MTP);

        assert_eq!(report.retained, 0);
        assert_eq!(report.dropped, 1);
        assert!(
            !pool.contains(&stale_id),
            "an invalidated entry is still there"
        );
    }

    #[test]
    fn an_untouched_entry_survives_the_rebuild() {
        let (mut pool, utxo, funds) = setup();
        let payment = simple_spend(&funds, "0.01");
        let txid = pool.accept(payment, &utxo, HEIGHT, MTP).unwrap();

        let report = pool.rebuild_after_reorg(Vec::new(), &utxo, HEIGHT, MTP);

        assert_eq!(report.retained, 1);
        assert_eq!(report.dropped, 0);
        assert!(pool.contains(&txid));
    }

    #[test]
    fn a_child_is_put_back_after_its_parent() {
        // 取り消された枝では、親と子が別のブロックに入っていることも、
        // 逆順に届くこともある。子を先に受け入れようとすると、その時点では
        // 親の出力が存在せず落ちてしまう。並べ替えてから入れる。
        let (mut pool, utxo, funds) = setup();
        let parent_key = SecretKey::generate();
        let parent = spend(
            &[&funds],
            vec![TxOutput::new(
                "9.99".parse().unwrap(),
                Lock::pay_to_pubkey(&parent_key.public_key()),
            )],
        );
        let parent_id = parent.txid();
        let child = simple_spend(&from_pool(parent_id, &parent, parent_key), "0.01");
        let child_id = child.txid();

        // わざと子を先に渡す。
        let report = pool.rebuild_after_reorg(vec![child, parent], &utxo, HEIGHT, MTP);

        assert_eq!(
            report.resubmitted, 2,
            "both parent and child should come back"
        );
        assert_eq!(report.dropped, 0);
        assert!(pool.contains(&parent_id));
        assert!(pool.contains(&child_id));
    }

    #[test]
    fn a_child_left_without_its_parent_is_dropped() {
        // 親が新しい枝と競合して戻れなければ、子も入れない。
        let (mut pool, mut utxo, funds) = setup();
        let parent_key = SecretKey::generate();
        let parent = spend(
            &[&funds],
            vec![TxOutput::new(
                "9.99".parse().unwrap(),
                Lock::pay_to_pubkey(&parent_key.public_key()),
            )],
        );
        let child = simple_spend(&from_pool(parent.txid(), &parent, parent_key), "0.01");
        let child_id = child.txid();
        // 新しい枝が親の入力を使い切った。親は戻れない。
        utxo.remove(&funds.outpoint).unwrap();

        let report = pool.rebuild_after_reorg(vec![parent, child], &utxo, HEIGHT, MTP);

        assert_eq!(report.resubmitted, 0);
        assert_eq!(report.dropped, 2);
        assert!(!pool.contains(&child_id));
    }

    #[test]
    fn the_undone_branch_wins_a_conflict_against_the_mempool() {
        // 同じ UTXO を、mempool にあるものと取り消された枝のものが奪い合う。
        // いちど確認まで進んでいた側を先に置く。
        let (mut pool, utxo, funds) = setup();
        let in_pool = spend(&[&funds], vec![to("9.99")]);
        let in_pool_id = pool.accept(in_pool, &utxo, HEIGHT, MTP).unwrap();
        let confirmed = spend(&[&funds], vec![to("9.98")]);
        let confirmed_id = confirmed.txid();
        assert_ne!(in_pool_id, confirmed_id);

        let report = pool.rebuild_after_reorg(vec![confirmed], &utxo, HEIGHT, MTP);

        assert_eq!(report.resubmitted, 1);
        assert!(pool.contains(&confirmed_id));
        assert_eq!(report.dropped, 1);
        assert!(!pool.contains(&in_pool_id));
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
        assert_eq!(pool.len(), 1, "holding more than the limit");
        assert!(pool.contains(&rich_id), "the higher rate should remain");
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
        assert_eq!(pool.spent.len(), inputs, "a spent record is missing");
    }
}
