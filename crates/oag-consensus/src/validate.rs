//! コンセンサスルールの検証。
//!
//! 参照: `docs/SPEC.md` §10
//!
//! # 検証の順序
//!
//! RandomX の light モード検証は 1 ハッシュあたり数ミリ秒を要する。
//! 攻撃者が無効なヘッダを大量に送ることでノードの CPU を枯渇させられるため、
//! **PoW の検証は最も安価な検査をすべて通過した後に行う** (SPEC §10.5)。
//! [`validate_block`] はこの順序を守る。

use crate::block::{Block, BlockHeader, VERSION_BIT_AUX_POW};
use crate::lock::Lock;
use crate::params;
use crate::sighash::{sighash, SighashError, SighashType};
use crate::tx::{decode_coinbase_height, Transaction, TxOutput, LOCKTIME_THRESHOLD};
use crate::utxo::{OverlayView, UtxoEntry, UtxoError, UtxoView};
use oag_primitives::address::VERSION_PUBKEY;
use oag_primitives::{Amount, Hash, PublicKey, Signature};
use std::collections::HashSet;

/// PoW の検証を差し込むための抽象。
///
/// RandomX による実装は後のフェーズで与える。
pub trait PowVerifier {
    /// ヘッダの PoW が難易度を満たすか。
    fn verify(&self, header: &BlockHeader) -> bool;
}

/// PoW を検証しない実装。テストと regtest でのみ用いる。
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAnyPow;

impl PowVerifier for AcceptAnyPow {
    fn verify(&self, _header: &BlockHeader) -> bool {
        true
    }
}

/// ヘッダだけを検証するために必要な文脈。
///
/// UTXO の状態を必要としないため、まだチェーンに繋がっていないブロック
/// (サイドチェーン) に対しても適用できる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderContext {
    /// このブロックが取るべき高さ。
    pub expected_height: u64,
    /// 親ブロックのハッシュ。
    pub expected_prev_hash: Hash,
    /// 親までの Median Time Past。
    pub median_time_past: i64,
    /// 難易度調整が定めるこのブロックの難易度。
    pub expected_difficulty: u64,
    /// ノードの現在時刻 (Unix 秒)。
    pub now: i64,
}

/// ブロック全体を検証するために必要な文脈。
pub struct BlockContext<'a> {
    /// ヘッダの検証に必要な文脈。
    pub header: HeaderContext,
    /// 親までを適用した UTXO の状態。
    pub utxo: &'a dyn UtxoView,
}

/// 検証の失敗。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    // ── ブロック ──
    /// ブロックが大きすぎる。
    #[error("ブロックサイズ {actual} が上限 {max} を超えている")]
    BlockTooLarge {
        /// 実際のサイズ。
        actual: usize,
        /// 上限。
        max: usize,
    },
    /// 高さが親 + 1 でない。
    #[error("高さが {actual} だが {expected} であるべき")]
    BadHeight {
        /// ヘッダの値。
        actual: u64,
        /// 期待される値。
        expected: u64,
    },
    /// 親ブロックの指定が誤っている。
    #[error("prev_hash が親ブロックを指していない")]
    BadPrevHash,
    /// タイムスタンプが Median Time Past 以下。
    #[error("タイムスタンプ {actual} が Median Time Past {median} を超えていない")]
    TimestampTooOld {
        /// ヘッダの値。
        actual: i64,
        /// Median Time Past。
        median: i64,
    },
    /// タイムスタンプが未来すぎる。
    #[error("タイムスタンプ {actual} がノードの現在時刻 {now} + {drift} 秒を超えている")]
    TimestampTooFarInFuture {
        /// ヘッダの値。
        actual: i64,
        /// ノードの現在時刻。
        now: i64,
        /// 許容する秒数。
        drift: i64,
    },
    /// 難易度が調整結果と一致しない。
    #[error("難易度が {actual} だが {expected} であるべき")]
    BadDifficulty {
        /// ヘッダの値。
        actual: u64,
        /// 期待される値。
        expected: u64,
    },
    /// v1 では補助 PoW を使えない。
    #[error("補助 PoW (マージマイニング) は現行の版では無効")]
    AuxPowNotEnabled,
    /// PoW が難易度を満たさない。
    #[error("PoW が難易度を満たしていない")]
    BadProofOfWork,
    /// マークルルートが本体と一致しない。
    #[error("マークルルートが本体と一致しない")]
    BadMerkleRoot,
    /// ブロックにトランザクションがない。
    #[error("ブロックが空である")]
    EmptyBlock,
    /// 先頭がコインベースでない。
    #[error("先頭のトランザクションがコインベースでない")]
    MissingCoinbase,
    /// 2 件目以降にコインベースがある。
    #[error("{index} 件目のトランザクションがコインベースである")]
    UnexpectedCoinbase {
        /// 位置。
        index: usize,
    },
    /// コインベースに刻まれた高さが違う。
    #[error("コインベースの高さが {actual:?} だが {expected} であるべき")]
    BadCoinbaseHeight {
        /// 読み取れた値。
        actual: Option<u64>,
        /// 期待される値。
        expected: u64,
    },
    /// コインベースの受け取り額が過大。
    #[error("コインベース出力 {actual} が報酬 + 手数料 {allowed} を超えている")]
    CoinbaseOverpay {
        /// 実際の出力合計。
        actual: Amount,
        /// 許される上限。
        allowed: Amount,
    },
    /// 同一ブロック内で同じ UTXO を二重に使用している。
    #[error("ブロック内で UTXO が二重に使用されている")]
    DoubleSpendInBlock,

    // ── トランザクション ──
    /// 入力が無い。
    #[error("トランザクション {index} に入力がない")]
    NoInputs {
        /// ブロック内の位置。
        index: usize,
    },
    /// 出力が無い。
    #[error("トランザクション {index} に出力がない")]
    NoOutputs {
        /// ブロック内の位置。
        index: usize,
    },
    /// トランザクションが大きすぎる。
    #[error("トランザクションサイズ {actual} が上限 {max} を超えている")]
    TransactionTooLarge {
        /// 実際のサイズ。
        actual: usize,
        /// 上限。
        max: usize,
    },
    /// 使用しようとした UTXO が存在しない。
    #[error("存在しないか使用済みの UTXO を参照している")]
    MissingUtxo,
    /// 同一トランザクション内で同じ UTXO を二重に使用している。
    #[error("トランザクション内で UTXO が二重に使用されている")]
    DuplicateInput,
    /// コインベース出力が成熟していない。
    #[error("コインベース出力が成熟していない (生成 {created}、現在 {current}、必要 {required} ブロック)")]
    ImmatureCoinbase {
        /// 生成された高さ。
        created: u64,
        /// 使用しようとした高さ。
        current: u64,
        /// 必要な経過ブロック数。
        required: u64,
    },
    /// 出力合計が入力合計を超えている。
    #[error("出力合計 {outputs} が入力合計 {inputs} を超えている")]
    OutputsExceedInputs {
        /// 入力合計。
        inputs: Amount,
        /// 出力合計。
        outputs: Amount,
    },
    /// 金額の合計が総発行量を超えた。
    #[error("金額の合計が総発行量を超えている")]
    AmountOverflow,
    /// 署名の長さが不正。
    #[error("署名の長さ {0} が不正 (64 または 65 である必要がある)")]
    BadSignatureLength(usize),
    /// 署名検証に失敗した。
    #[error("入力 {index} の署名が無効")]
    BadSignature {
        /// 入力番号。
        index: usize,
    },
    /// sighash を計算できなかった。
    #[error(transparent)]
    Sighash(#[from] SighashError),
    /// UTXO セットの読み取りに失敗した。
    ///
    /// UTXO が存在しないこと ([`ValidationError::MissingUtxo`]) とは
    /// 区別される。こちらは記憶装置の障害であり、ブロックが不正である
    /// ことを意味しない。
    #[error(transparent)]
    Utxo(#[from] UtxoError),
    /// 支払い条件のペイロードが公開鍵として解釈できない。
    #[error("入力 {index} が参照する出力の公開鍵が不正")]
    BadLockPubkey {
        /// 入力番号。
        index: usize,
    },
    /// locktime の条件を満たしていない。
    #[error("locktime {locktime} が満たされていない (高さ {height}、時刻 {time})")]
    LocktimeNotSatisfied {
        /// トランザクションの locktime。
        locktime: u64,
        /// 現在の高さ。
        height: u64,
        /// Median Time Past。
        time: i64,
    },
}

/// 直近のタイムスタンプ列から Median Time Past を求める。
///
/// 新しい順・古い順のどちらで渡してもよい。末尾から
/// `params::MEDIAN_TIME_SPAN` 件を用いる。
pub fn median_time_past(recent_timestamps: &[i64]) -> Option<i64> {
    if recent_timestamps.is_empty() {
        return None;
    }
    let start = recent_timestamps
        .len()
        .saturating_sub(params::MEDIAN_TIME_SPAN);
    let mut window: Vec<i64> = recent_timestamps[start..].to_vec();
    window.sort_unstable();
    Some(window[window.len() / 2])
}

/// トランザクション検証の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionSummary {
    /// このトランザクションが支払う手数料。
    pub fee: Amount,
}

/// 単一のトランザクションを検証する (SPEC §10.3)。
///
/// `utxo` は、このトランザクションより前の状態を反映したビューでなければ
/// ならない。コインベースは本関数の対象外である。
pub fn validate_transaction(
    tx: &Transaction,
    utxo: &dyn UtxoView,
    height: u64,
    median_time_past: i64,
    index: usize,
) -> Result<TransactionSummary, ValidationError> {
    if tx.inputs.is_empty() {
        return Err(ValidationError::NoInputs { index });
    }
    if tx.outputs.is_empty() {
        return Err(ValidationError::NoOutputs { index });
    }

    let size = tx.size();
    if size > params::MAX_TX_SIZE {
        return Err(ValidationError::TransactionTooLarge {
            actual: size,
            max: params::MAX_TX_SIZE,
        });
    }

    // 同一トランザクション内の二重使用。
    let mut seen = HashSet::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        if !seen.insert(input.prev_out) {
            return Err(ValidationError::DuplicateInput);
        }
    }

    // 参照先の UTXO を集める。
    let mut spent_entries = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        let entry = utxo
            .get(&input.prev_out)?
            .ok_or(ValidationError::MissingUtxo)?;

        if entry.is_coinbase {
            let elapsed = height.saturating_sub(entry.height);
            if elapsed < params::COINBASE_MATURITY {
                return Err(ValidationError::ImmatureCoinbase {
                    created: entry.height,
                    current: height,
                    required: params::COINBASE_MATURITY,
                });
            }
        }
        spent_entries.push(entry);
    }

    // 金額の帳尻。すべて検査付き演算で行う。
    let total_in = Amount::sum(spent_entries.iter().map(|e| e.output.amount))
        .ok_or(ValidationError::AmountOverflow)?;
    let total_out = tx.total_output().ok_or(ValidationError::AmountOverflow)?;
    let fee = total_in
        .checked_sub(total_out)
        .ok_or(ValidationError::OutputsExceedInputs {
            inputs: total_in,
            outputs: total_out,
        })?;

    // locktime。
    if !locktime_is_satisfied(tx, height, median_time_past) {
        return Err(ValidationError::LocktimeNotSatisfied {
            locktime: tx.locktime,
            height,
            time: median_time_past,
        });
    }

    // 署名。
    let spent_outputs: Vec<TxOutput> = spent_entries.iter().map(|e| e.output.clone()).collect();
    for (input_index, spent) in spent_outputs.iter().enumerate() {
        verify_input_signature(tx, &spent_outputs, input_index, &spent.lock)?;
    }

    Ok(TransactionSummary { fee })
}

/// locktime の条件を満たしているか (SPEC §7.4)。
fn locktime_is_satisfied(tx: &Transaction, height: u64, median_time_past: i64) -> bool {
    if tx.locktime == 0 {
        return true;
    }
    if tx.locktime < LOCKTIME_THRESHOLD {
        u128::from(height) >= u128::from(tx.locktime)
    } else {
        i128::from(median_time_past) >= i128::from(tx.locktime)
    }
}

/// 1 入力分の署名を検証する。
///
/// # 未知の版数について
///
/// 支払い条件の版数がこの実装にとって未知の場合、**コンセンサス上は誰でも
/// 使用できる (anyone-can-spend) として扱い、署名を検査しない**。
///
/// これはソフトフォークで新しい版数を導入するための機構である。
/// 未知の版数を無効としてしまうと、版数の追加が必ずハードフォークになり、
/// 出力に長さ接頭辞を設けた意味 (SPEC §7.1) が失われる。
///
/// **この性質のため、未知の版数のアドレスへ送金してはならない。**
/// ウォレットは警告を出し、ノードポリシーは未知の版数を含む
/// トランザクションを中継しない。
fn verify_input_signature(
    tx: &Transaction,
    spent_outputs: &[TxOutput],
    index: usize,
    lock: &Lock,
) -> Result<(), ValidationError> {
    if lock.version() != VERSION_PUBKEY {
        return Ok(());
    }

    let signature_field = &tx.inputs[index].signature;
    let (sig_bytes, hash_type) = match signature_field.len() {
        64 => (&signature_field[..], SighashType::DEFAULT),
        65 => (
            &signature_field[..64],
            SighashType::from_byte(signature_field[64])?,
        ),
        other => return Err(ValidationError::BadSignatureLength(other)),
    };

    let pubkey = PublicKey::from_slice(lock.payload())
        .map_err(|_| ValidationError::BadLockPubkey { index })?;
    let signature =
        Signature::from_slice(sig_bytes).map_err(|_| ValidationError::BadSignature { index })?;
    let msg = sighash(tx, spent_outputs, index, hash_type)?;

    if !pubkey.verify(&msg, &signature) {
        return Err(ValidationError::BadSignature { index });
    }
    Ok(())
}

/// ブロック検証の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockSummary {
    /// ブロック内の手数料合計。
    pub total_fees: Amount,
    /// コインベースが受け取った額。
    pub coinbase_value: Amount,
}

/// ヘッダを検証する (SPEC §10.2 の 2〜8)。
pub fn validate_header(
    header: &BlockHeader,
    ctx: &HeaderContext,
    pow: &dyn PowVerifier,
) -> Result<(), ValidationError> {
    // ── 整数比較のみで済む検査 ──
    if header.height != ctx.expected_height {
        return Err(ValidationError::BadHeight {
            actual: header.height,
            expected: ctx.expected_height,
        });
    }
    if header.prev_hash != ctx.expected_prev_hash {
        return Err(ValidationError::BadPrevHash);
    }
    if header.timestamp <= ctx.median_time_past {
        return Err(ValidationError::TimestampTooOld {
            actual: header.timestamp,
            median: ctx.median_time_past,
        });
    }
    if header.timestamp > ctx.now + params::MAX_FUTURE_TIME_DRIFT_SECS {
        return Err(ValidationError::TimestampTooFarInFuture {
            actual: header.timestamp,
            now: ctx.now,
            drift: params::MAX_FUTURE_TIME_DRIFT_SECS,
        });
    }
    if header.difficulty != ctx.expected_difficulty {
        return Err(ValidationError::BadDifficulty {
            actual: header.difficulty,
            expected: ctx.expected_difficulty,
        });
    }
    if header.version & VERSION_BIT_AUX_POW != 0 {
        return Err(ValidationError::AuxPowNotEnabled);
    }

    // ── PoW。安価な検査をすべて通過した場合のみ行う (SPEC §10.5) ──
    if !pow.verify(header) {
        return Err(ValidationError::BadProofOfWork);
    }
    Ok(())
}

/// ブロックを検証する (SPEC §10.2)。
///
/// 検査は安価なものから順に行い、PoW を最後に置く (SPEC §10.5)。
pub fn validate_block(
    block: &Block,
    ctx: &BlockContext<'_>,
    pow: &dyn PowVerifier,
) -> Result<BlockSummary, ValidationError> {
    let header = &block.header;

    // ── 1. サイズ。ヘッダ検証より前に行う (最も安価であるため) ──
    let size = block.size();
    if size > params::MAX_BLOCK_SIZE {
        return Err(ValidationError::BlockTooLarge {
            actual: size,
            max: params::MAX_BLOCK_SIZE,
        });
    }

    // ── 2〜3. ヘッダの検証と PoW ──
    validate_header(header, &ctx.header, pow)?;

    // ── 4. 本体の構造 ──
    if block.transactions.is_empty() {
        return Err(ValidationError::EmptyBlock);
    }
    if !block.merkle_root_is_valid() {
        return Err(ValidationError::BadMerkleRoot);
    }

    let coinbase = block
        .transactions
        .first()
        .filter(|tx| tx.is_coinbase())
        .ok_or(ValidationError::MissingCoinbase)?;

    for (index, tx) in block.transactions.iter().enumerate().skip(1) {
        if tx.is_coinbase() {
            return Err(ValidationError::UnexpectedCoinbase { index });
        }
    }

    let recorded_height = decode_coinbase_height(&coinbase.inputs[0].signature).ok();
    if recorded_height != Some(header.height) {
        return Err(ValidationError::BadCoinbaseHeight {
            actual: recorded_height,
            expected: header.height,
        });
    }

    // ── 5. 各トランザクションの検証 ──
    //
    // 順序が重要である。あるトランザクションを検証する時点では、
    // そのトランザクションが使用しようとしている UTXO はまだ
    // ビューから消えていてはならない。したがって各トランザクションについて
    //   (a) ブロック全体での二重使用を先に検出し
    //   (b) 使用前の状態のビューで検証し
    //   (c) その後にビューへ反映する
    // という順で処理する。
    //
    // この順序により、後続のトランザクションが生成する出力を先行する
    // トランザクションが使用することはできない (Bitcoin と同じく、
    // ブロック内のトランザクションは依存順に並んでいなければならない)。

    let mut overlay = OverlayView::new(ctx.utxo);

    // コインベースの出力を登録する。成熟期間があるため同一ブロック内では
    // 使用できないが、状態としては存在させる。
    register_outputs(&mut overlay, coinbase, header.height, true);

    let mut block_spent: HashSet<crate::tx::OutPoint> = HashSet::new();
    let mut total_fees = Amount::ZERO;

    for (index, tx) in block.transactions.iter().enumerate().skip(1) {
        // (a) ブロック全体での二重使用。
        for input in &tx.inputs {
            if !block_spent.insert(input.prev_out) {
                return Err(ValidationError::DoubleSpendInBlock);
            }
        }

        // (b) 使用前の状態で検証する。
        let summary = validate_transaction(
            tx,
            &overlay,
            header.height,
            ctx.header.median_time_past,
            index,
        )?;

        // (c) ビューへ反映する。
        for input in &tx.inputs {
            overlay.mark_spent(input.prev_out);
        }
        register_outputs(&mut overlay, tx, header.height, false);

        total_fees = total_fees
            .checked_add(summary.fee)
            .ok_or(ValidationError::AmountOverflow)?;
    }

    // ── 6. コインベースの受け取り額 ──
    if coinbase.outputs.is_empty() {
        return Err(ValidationError::NoOutputs { index: 0 });
    }
    let coinbase_size = coinbase.size();
    if coinbase_size > params::MAX_TX_SIZE {
        return Err(ValidationError::TransactionTooLarge {
            actual: coinbase_size,
            max: params::MAX_TX_SIZE,
        });
    }

    let coinbase_value = coinbase
        .total_output()
        .ok_or(ValidationError::AmountOverflow)?;
    let allowed = params::block_subsidy(header.height)
        .checked_add(total_fees)
        .ok_or(ValidationError::AmountOverflow)?;

    // 不等号であることに注意 (SPEC §4)。マイナーは報酬の一部または全部を
    // 放棄できる。放棄された分は永久に発行されない。
    if coinbase_value > allowed {
        return Err(ValidationError::CoinbaseOverpay {
            actual: coinbase_value,
            allowed,
        });
    }

    Ok(BlockSummary {
        total_fees,
        coinbase_value,
    })
}

fn register_outputs(overlay: &mut OverlayView<'_>, tx: &Transaction, height: u64, coinbase: bool) {
    let txid = tx.txid();
    for (index, output) in tx.outputs.iter().enumerate() {
        overlay.add_created(
            crate::tx::OutPoint::new(txid, index as u32),
            UtxoEntry {
                output: output.clone(),
                height,
                is_coinbase: coinbase,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::CURRENT_BLOCK_VERSION;
    use crate::tx::{encode_coinbase_signature, OutPoint, TxInput, CURRENT_TX_VERSION};
    use crate::utxo::UtxoSet;
    use oag_primitives::{hash, merkle, SecretKey};
    use std::cell::Cell;

    const DIFFICULTY: u64 = 1_000;
    const NOW: i64 = 1_800_000_000;
    const MTP: i64 = NOW - 3_600;
    /// コインベースが成熟する高さ。
    const SPEND_HEIGHT: u64 = 1 + params::COINBASE_MATURITY;

    /// 呼び出し回数を数える PoW 検証。検証順序の確認に用いる。
    #[derive(Default)]
    struct CountingPow {
        calls: Cell<usize>,
        result: bool,
    }

    impl CountingPow {
        fn accepting() -> CountingPow {
            CountingPow {
                calls: Cell::new(0),
                result: true,
            }
        }
        fn rejecting() -> CountingPow {
            CountingPow {
                calls: Cell::new(0),
                result: false,
            }
        }
    }

    impl PowVerifier for CountingPow {
        fn verify(&self, _header: &BlockHeader) -> bool {
            self.calls.set(self.calls.get() + 1);
            self.result
        }
    }

    fn coinbase(height: u64, outputs: Vec<TxOutput>) -> Transaction {
        let mut input = TxInput::new(OutPoint::null());
        input.signature = encode_coinbase_signature(height, b"orange");
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs,
            locktime: 0,
        }
    }

    fn sign(tx: &mut Transaction, spent: &[TxOutput], keys: &[&SecretKey]) {
        let messages: Vec<[u8; 32]> = (0..tx.inputs.len())
            .map(|i| sighash(tx, spent, i, SighashType::DEFAULT).unwrap())
            .collect();
        for ((input, key), msg) in tx.inputs.iter_mut().zip(keys).zip(&messages) {
            input.signature = key.sign(msg).to_bytes().to_vec();
        }
    }

    fn make_block(height: u64, prev: Hash, transactions: Vec<Transaction>) -> Block {
        let txids: Vec<Hash> = transactions.iter().map(|t| t.txid()).collect();
        Block {
            header: BlockHeader {
                version: CURRENT_BLOCK_VERSION,
                prev_hash: prev,
                merkle_root: merkle::merkle_root(&txids).unwrap_or(Hash::ZERO),
                timestamp: NOW,
                difficulty: DIFFICULTY,
                height,
                nonce: 0,
            },
            transactions,
        }
    }

    fn refresh_merkle(block: &mut Block) {
        let txids: Vec<Hash> = block.transactions.iter().map(|t| t.txid()).collect();
        block.header.merkle_root = merkle::merkle_root(&txids).unwrap_or(Hash::ZERO);
    }

    /// 高さ 1 のコインベースを持つ UTXO セットと、その受取鍵を用意する。
    struct Fixture {
        utxo: UtxoSet,
        key: SecretKey,
        funded: OutPoint,
        funded_output: TxOutput,
        tip: Hash,
    }

    fn fixture() -> Fixture {
        let key = SecretKey::generate();
        let output = TxOutput::new(params::BLOCK_REWARD, Lock::pay_to_pubkey(&key.public_key()));
        let cb = coinbase(1, vec![output.clone()]);
        let mut utxo = UtxoSet::new();
        utxo.apply_block(std::slice::from_ref(&cb), 1).unwrap();
        Fixture {
            utxo,
            key,
            funded: OutPoint::new(cb.txid(), 0),
            funded_output: output,
            tip: hash::block_hash(b"tip"),
        }
    }

    impl Fixture {
        fn context(&self) -> BlockContext<'_> {
            BlockContext {
                header: HeaderContext {
                    expected_height: SPEND_HEIGHT,
                    expected_prev_hash: self.tip,
                    median_time_past: MTP,
                    expected_difficulty: DIFFICULTY,
                    now: NOW,
                },
                utxo: &self.utxo,
            }
        }

        /// 資金を使う署名済みトランザクション。手数料は `fee`。
        fn spend(&self, fee: &str) -> Transaction {
            let fee: Amount = fee.parse().unwrap();
            let out = params::BLOCK_REWARD.checked_sub(fee).unwrap();
            let mut tx = Transaction {
                version: CURRENT_TX_VERSION,
                inputs: vec![TxInput::new(self.funded)],
                outputs: vec![TxOutput::new(
                    out,
                    Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
                )],
                locktime: 0,
            };
            sign(
                &mut tx,
                std::slice::from_ref(&self.funded_output),
                &[&self.key],
            );
            tx
        }

        /// 正当なブロック。コインベースは報酬 + 手数料を受け取る。
        fn block(&self, fee: &str) -> Block {
            let spend = self.spend(fee);
            let fee: Amount = fee.parse().unwrap();
            let cb = coinbase(
                SPEND_HEIGHT,
                vec![TxOutput::new(
                    params::block_subsidy(SPEND_HEIGHT)
                        .checked_add(fee)
                        .unwrap(),
                    Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
                )],
            );
            make_block(SPEND_HEIGHT, self.tip, vec![cb, spend])
        }
    }

    // ━━━━━━━━ 正常系 ━━━━━━━━

    #[test]
    fn a_valid_block_passes() {
        let f = fixture();
        let block = f.block("0.001");
        let summary = validate_block(&block, &f.context(), &AcceptAnyPow).unwrap();
        assert_eq!(summary.total_fees.to_string(), "0.001");
        assert_eq!(
            summary.coinbase_value,
            params::BLOCK_REWARD
                .checked_add("0.001".parse().unwrap())
                .unwrap()
        );
    }

    #[test]
    fn a_miner_may_claim_less_than_allowed() {
        // SPEC §4: 不等号である。放棄された分は永久に発行されない。
        let f = fixture();
        let mut block = f.block("0.001");
        block.transactions[0].outputs[0].amount = Amount::ONE_OAG;
        refresh_merkle(&mut block);
        assert!(validate_block(&block, &f.context(), &AcceptAnyPow).is_ok());
    }

    // ━━━━━━━━ §10.5 検証順序 ━━━━━━━━

    #[test]
    fn pow_is_verified_only_after_the_cheap_checks() {
        let f = fixture();

        // 高さが違うブロックは、PoW を計算せずに拒否される。
        let mut bad = f.block("0.001");
        bad.header.height += 1;
        let pow = CountingPow::accepting();
        assert!(validate_block(&bad, &f.context(), &pow).is_err());
        assert_eq!(pow.calls.get(), 0, "PoW を計算してしまっている");

        // 正当なブロックではちょうど 1 回呼ばれる。
        let good = f.block("0.001");
        let pow = CountingPow::accepting();
        assert!(validate_block(&good, &f.context(), &pow).is_ok());
        assert_eq!(pow.calls.get(), 1);
    }

    #[test]
    fn invalid_pow_is_rejected() {
        let f = fixture();
        let pow = CountingPow::rejecting();
        assert_eq!(
            validate_block(&f.block("0.001"), &f.context(), &pow),
            Err(ValidationError::BadProofOfWork)
        );
        assert_eq!(pow.calls.get(), 1);
    }

    // ━━━━━━━━ §10.2 ブロックのルール ━━━━━━━━

    #[test]
    fn rejects_wrong_height() {
        let f = fixture();
        let mut block = f.block("0.001");
        block.header.height = 999;
        assert_eq!(
            validate_block(&block, &f.context(), &AcceptAnyPow),
            Err(ValidationError::BadHeight {
                actual: 999,
                expected: SPEND_HEIGHT
            })
        );
    }

    #[test]
    fn rejects_wrong_prev_hash() {
        let f = fixture();
        let mut block = f.block("0.001");
        block.header.prev_hash = Hash::ZERO;
        assert_eq!(
            validate_block(&block, &f.context(), &AcceptAnyPow),
            Err(ValidationError::BadPrevHash)
        );
    }

    #[test]
    fn rejects_timestamp_at_or_before_median_time_past() {
        let f = fixture();
        let mut block = f.block("0.001");
        block.header.timestamp = MTP;
        assert!(matches!(
            validate_block(&block, &f.context(), &AcceptAnyPow),
            Err(ValidationError::TimestampTooOld { .. })
        ));
        block.header.timestamp = MTP + 1;
        assert!(validate_block(&block, &f.context(), &AcceptAnyPow).is_ok());
    }

    #[test]
    fn rejects_timestamp_too_far_in_the_future() {
        let f = fixture();
        let mut block = f.block("0.001");
        block.header.timestamp = NOW + params::MAX_FUTURE_TIME_DRIFT_SECS + 1;
        assert!(matches!(
            validate_block(&block, &f.context(), &AcceptAnyPow),
            Err(ValidationError::TimestampTooFarInFuture { .. })
        ));
        block.header.timestamp = NOW + params::MAX_FUTURE_TIME_DRIFT_SECS;
        assert!(validate_block(&block, &f.context(), &AcceptAnyPow).is_ok());
    }

    #[test]
    fn rejects_wrong_difficulty() {
        let f = fixture();
        let mut block = f.block("0.001");
        block.header.difficulty = DIFFICULTY + 1;
        assert!(matches!(
            validate_block(&block, &f.context(), &AcceptAnyPow),
            Err(ValidationError::BadDifficulty { .. })
        ));
    }

    #[test]
    fn rejects_aux_pow_bit() {
        // v1 ではマージマイニングは無効 (SPEC §9.5)。
        let f = fixture();
        let mut block = f.block("0.001");
        block.header.version |= VERSION_BIT_AUX_POW;
        assert_eq!(
            validate_block(&block, &f.context(), &AcceptAnyPow),
            Err(ValidationError::AuxPowNotEnabled)
        );
    }

    #[test]
    fn rejects_bad_merkle_root() {
        let f = fixture();
        let mut block = f.block("0.001");
        block.header.merkle_root = Hash::ZERO;
        assert_eq!(
            validate_block(&block, &f.context(), &AcceptAnyPow),
            Err(ValidationError::BadMerkleRoot)
        );
    }

    #[test]
    fn rejects_block_without_coinbase() {
        let f = fixture();
        let mut block = f.block("0.001");
        block.transactions.remove(0);
        refresh_merkle(&mut block);
        assert_eq!(
            validate_block(&block, &f.context(), &AcceptAnyPow),
            Err(ValidationError::MissingCoinbase)
        );
    }

    #[test]
    fn rejects_second_coinbase() {
        let f = fixture();
        let mut block = f.block("0.001");
        block.transactions.push(coinbase(
            SPEND_HEIGHT,
            vec![TxOutput::new(
                Amount::ONE_OAG,
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            )],
        ));
        refresh_merkle(&mut block);
        assert_eq!(
            validate_block(&block, &f.context(), &AcceptAnyPow),
            Err(ValidationError::UnexpectedCoinbase { index: 2 })
        );
    }

    #[test]
    fn rejects_wrong_coinbase_height() {
        let f = fixture();
        let mut block = f.block("0.001");
        block.transactions[0].inputs[0].signature = encode_coinbase_signature(999, b"");
        refresh_merkle(&mut block);
        assert!(matches!(
            validate_block(&block, &f.context(), &AcceptAnyPow),
            Err(ValidationError::BadCoinbaseHeight { .. })
        ));
    }

    #[test]
    fn rejects_coinbase_overpay() {
        let f = fixture();
        let mut block = f.block("0.001");
        let over = block.transactions[0].outputs[0]
            .amount
            .checked_add(Amount::from_atomic(1).unwrap())
            .unwrap();
        block.transactions[0].outputs[0].amount = over;
        refresh_merkle(&mut block);
        assert!(
            matches!(
                validate_block(&block, &f.context(), &AcceptAnyPow),
                Err(ValidationError::CoinbaseOverpay { .. })
            ),
            "1 atomic の超過を見逃している"
        );
    }

    #[test]
    fn rejects_double_spend_within_a_block() {
        let f = fixture();
        let mut block = f.block("0.001");
        let duplicate = block.transactions[1].clone();
        block.transactions.push(duplicate);
        refresh_merkle(&mut block);
        assert_eq!(
            validate_block(&block, &f.context(), &AcceptAnyPow),
            Err(ValidationError::DoubleSpendInBlock)
        );
    }

    #[test]
    fn rejects_oversized_block() {
        let f = fixture();
        let mut block = f.block("0.001");
        // 上限を超えるまで出力を足す。
        let filler = TxOutput::new(
            Amount::from_atomic(1).unwrap(),
            Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
        );
        while block.size() <= params::MAX_BLOCK_SIZE {
            block.transactions[0].outputs.push(filler.clone());
        }
        refresh_merkle(&mut block);
        assert!(matches!(
            validate_block(&block, &f.context(), &AcceptAnyPow),
            Err(ValidationError::BlockTooLarge { .. })
        ));
    }

    // ━━━━━━━━ §10.3 トランザクションのルール ━━━━━━━━

    #[test]
    fn coinbase_maturity_boundary() {
        let f = fixture();
        let tx = f.spend("0.001");

        // 119 ブロック経過では未成熟。
        let too_early = 1 + params::COINBASE_MATURITY - 1;
        assert!(matches!(
            validate_transaction(&tx, &f.utxo, too_early, MTP, 1),
            Err(ValidationError::ImmatureCoinbase { .. })
        ));

        // 120 ブロック経過で使用できる。
        assert!(validate_transaction(&tx, &f.utxo, SPEND_HEIGHT, MTP, 1).is_ok());
    }

    #[test]
    fn rejects_spending_a_missing_utxo() {
        let f = fixture();
        let mut tx = f.spend("0.001");
        tx.inputs[0].prev_out = OutPoint::new(hash::txid(b"ghost"), 0);
        assert_eq!(
            validate_transaction(&tx, &f.utxo, SPEND_HEIGHT, MTP, 1),
            Err(ValidationError::MissingUtxo)
        );
    }

    #[test]
    fn rejects_duplicate_inputs_within_a_transaction() {
        let f = fixture();
        let mut tx = f.spend("0.001");
        let input = tx.inputs[0].clone();
        tx.inputs.push(input);
        assert_eq!(
            validate_transaction(&tx, &f.utxo, SPEND_HEIGHT, MTP, 1),
            Err(ValidationError::DuplicateInput)
        );
    }

    #[test]
    fn rejects_creating_value() {
        let f = fixture();
        let mut tx = f.spend("0.001");
        tx.outputs[0].amount = params::BLOCK_REWARD.checked_add(Amount::ONE_OAG).unwrap();
        sign(&mut tx, std::slice::from_ref(&f.funded_output), &[&f.key]);
        assert!(matches!(
            validate_transaction(&tx, &f.utxo, SPEND_HEIGHT, MTP, 1),
            Err(ValidationError::OutputsExceedInputs { .. })
        ));
    }

    #[test]
    fn rejects_a_transaction_with_no_outputs() {
        let f = fixture();
        let mut tx = f.spend("0.001");
        tx.outputs.clear();
        assert_eq!(
            validate_transaction(&tx, &f.utxo, SPEND_HEIGHT, MTP, 3),
            Err(ValidationError::NoOutputs { index: 3 })
        );
    }

    // ━━━━━━━━ 署名 ━━━━━━━━

    #[test]
    fn rejects_a_tampered_output_after_signing() {
        let f = fixture();
        let mut tx = f.spend("0.001");
        tx.outputs[0].amount = Amount::from_oag(1).unwrap();
        assert_eq!(
            validate_transaction(&tx, &f.utxo, SPEND_HEIGHT, MTP, 1),
            Err(ValidationError::BadSignature { index: 0 })
        );
    }

    #[test]
    fn rejects_a_signature_from_the_wrong_key() {
        let f = fixture();
        let mut tx = f.spend("0.001");
        let other = SecretKey::generate();
        sign(&mut tx, std::slice::from_ref(&f.funded_output), &[&other]);
        assert_eq!(
            validate_transaction(&tx, &f.utxo, SPEND_HEIGHT, MTP, 1),
            Err(ValidationError::BadSignature { index: 0 })
        );
    }

    #[test]
    fn rejects_bad_signature_lengths() {
        let f = fixture();
        for len in [0usize, 63, 66, 100] {
            let mut tx = f.spend("0.001");
            tx.inputs[0].signature = vec![0u8; len];
            assert_eq!(
                validate_transaction(&tx, &f.utxo, SPEND_HEIGHT, MTP, 1),
                Err(ValidationError::BadSignatureLength(len))
            );
        }
    }

    #[test]
    fn accepts_65_byte_signatures_with_an_explicit_hash_type() {
        let f = fixture();
        let mut tx = f.spend("0.001");
        let spent = [f.funded_output.clone()];
        let t = SighashType::new(crate::sighash::SighashBase::All, false);
        let msg = sighash(&tx, &spent, 0, t).unwrap();
        let mut sig = f.key.sign(&msg).to_bytes().to_vec();
        sig.push(t.to_byte());
        tx.inputs[0].signature = sig;
        assert!(validate_transaction(&tx, &f.utxo, SPEND_HEIGHT, MTP, 1).is_ok());
    }

    #[test]
    fn rejects_undefined_hash_type_byte() {
        let f = fixture();
        let mut tx = f.spend("0.001");
        let mut sig = tx.inputs[0].signature.clone();
        sig.push(0x7f);
        tx.inputs[0].signature = sig;
        assert!(matches!(
            validate_transaction(&tx, &f.utxo, SPEND_HEIGHT, MTP, 1),
            Err(ValidationError::Sighash(SighashError::UnknownType(0x7f)))
        ));
    }

    // ━━━━━━━━ 未知の版数 ━━━━━━━━

    #[test]
    fn unknown_lock_versions_are_anyone_can_spend() {
        // ソフトフォークで新しい版数を導入するための機構。
        // 未知の版数を無効にすると版数の追加が必ずハードフォークになる。
        let mut utxo = UtxoSet::new();
        let future_lock = Lock::new(5, vec![0xab; 32]).unwrap();
        let cb = coinbase(1, vec![TxOutput::new(params::BLOCK_REWARD, future_lock)]);
        utxo.apply_block(std::slice::from_ref(&cb), 1).unwrap();

        // 署名を一切付けずに使用できる。
        let tx = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput::new(OutPoint::new(cb.txid(), 0))],
            outputs: vec![TxOutput::new(
                Amount::from_oag(9).unwrap(),
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            )],
            locktime: 0,
        };
        assert!(
            validate_transaction(&tx, &utxo, SPEND_HEIGHT, MTP, 1).is_ok(),
            "未知の版数は誰でも使用できなければならない"
        );
    }

    // ━━━━━━━━ locktime ━━━━━━━━

    #[test]
    fn locktime_by_height() {
        let f = fixture();
        let mut tx = f.spend("0.001");
        tx.locktime = SPEND_HEIGHT + 1;
        sign(&mut tx, std::slice::from_ref(&f.funded_output), &[&f.key]);

        assert!(matches!(
            validate_transaction(&tx, &f.utxo, SPEND_HEIGHT, MTP, 1),
            Err(ValidationError::LocktimeNotSatisfied { .. })
        ));
        // locktime と同じ高さで有効になる。
        assert!(validate_transaction(&tx, &f.utxo, SPEND_HEIGHT + 1, MTP, 1).is_ok());
    }

    #[test]
    fn locktime_by_time() {
        let f = fixture();
        let mut tx = f.spend("0.001");
        tx.locktime = (MTP + 100) as u64;
        sign(&mut tx, std::slice::from_ref(&f.funded_output), &[&f.key]);

        assert!(tx.locktime >= LOCKTIME_THRESHOLD);
        assert!(matches!(
            validate_transaction(&tx, &f.utxo, SPEND_HEIGHT, MTP, 1),
            Err(ValidationError::LocktimeNotSatisfied { .. })
        ));
        assert!(validate_transaction(&tx, &f.utxo, SPEND_HEIGHT, MTP + 100, 1).is_ok());
    }

    // ━━━━━━━━ ブロック内の依存関係 ━━━━━━━━

    #[test]
    fn a_transaction_may_spend_an_earlier_output_in_the_same_block() {
        let f = fixture();

        // first の出力を second が使う。中間の鍵を握っておく必要がある。
        let middle_key = SecretKey::generate();
        let mut first = f.spend("0.001");
        first.outputs[0].lock = Lock::pay_to_pubkey(&middle_key.public_key());
        sign(
            &mut first,
            std::slice::from_ref(&f.funded_output),
            &[&f.key],
        );
        let first_out = TxOutput::new(first.outputs[0].amount, first.outputs[0].lock.clone());

        let mut second = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput::new(OutPoint::new(first.txid(), 0))],
            outputs: vec![TxOutput::new(
                first_out
                    .amount
                    .checked_sub("0.001".parse().unwrap())
                    .unwrap(),
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            )],
            locktime: 0,
        };
        sign(
            &mut second,
            std::slice::from_ref(&first_out),
            &[&middle_key],
        );

        let fees: Amount = "0.002".parse().unwrap();
        let cb = coinbase(
            SPEND_HEIGHT,
            vec![TxOutput::new(
                params::block_subsidy(SPEND_HEIGHT)
                    .checked_add(fees)
                    .unwrap(),
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            )],
        );

        let ordered = make_block(
            SPEND_HEIGHT,
            f.tip,
            vec![cb.clone(), first.clone(), second.clone()],
        );
        let summary = validate_block(&ordered, &f.context(), &AcceptAnyPow).unwrap();
        assert_eq!(summary.total_fees, fees);

        // 順序が逆だと、second が使う出力はまだ存在しない。
        let reversed = make_block(SPEND_HEIGHT, f.tip, vec![cb, second, first]);
        assert_eq!(
            validate_block(&reversed, &f.context(), &AcceptAnyPow),
            Err(ValidationError::MissingUtxo)
        );
    }

    #[test]
    fn the_coinbase_of_the_same_block_cannot_be_spent() {
        let f = fixture();
        let cb = coinbase(
            SPEND_HEIGHT,
            vec![TxOutput::new(
                params::BLOCK_REWARD,
                Lock::pay_to_pubkey(&f.key.public_key()),
            )],
        );
        let tx = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput::new(OutPoint::new(cb.txid(), 0))],
            outputs: vec![TxOutput::new(
                Amount::from_oag(9).unwrap(),
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            )],
            locktime: 0,
        };
        let block = make_block(SPEND_HEIGHT, f.tip, vec![cb, tx]);
        assert!(matches!(
            validate_block(&block, &f.context(), &AcceptAnyPow),
            Err(ValidationError::ImmatureCoinbase { .. })
        ));
    }

    // ━━━━━━━━ Median Time Past ━━━━━━━━

    #[test]
    fn median_time_past_uses_the_middle_of_the_last_eleven() {
        assert_eq!(median_time_past(&[]), None);
        assert_eq!(median_time_past(&[5]), Some(5));
        assert_eq!(median_time_past(&[3, 1, 2]), Some(2));

        // 12 件あるとき、古い 1 件は無視される。
        let timestamps: Vec<i64> = (0..12).collect();
        assert_eq!(median_time_past(&timestamps), Some(6));
        assert_eq!(params::MEDIAN_TIME_SPAN, 11);
    }

    #[test]
    fn median_time_past_tolerates_out_of_order_timestamps() {
        // タイムスタンプの逆転は許容される (LWMA が負の solvetime を扱う)。
        let timestamps = [100, 90, 110, 95, 105];
        assert_eq!(median_time_past(&timestamps), Some(100));
    }
}
