//! 署名対象 (sighash) の計算。
//!
//! BIP341 と同じ方式を採る。**署名はすべての入力が参照する UTXO の金額に
//! コミットする**。
//!
//! Bitcoin の初期の sighash は入力金額にコミットしていなかったため、
//! 悪意ある PC がハードウェアウォレットに偽の金額を伝えて署名させ、
//! 差額を全額マイナー手数料として流出させる攻撃が成立した。
//! 本チェーンは初版からこれを含め、署名装置が単独で手数料を検算できる。
//!
//! 参照: `docs/SPEC.md` §8

use crate::codec::{write_varint, Encode};
use crate::tx::{Transaction, TxOutput};
use oag_primitives::{hash, Hash};

const TAG_SIGHASH: &str = "OAG/sighash";
const TAG_PREVOUTS: &str = "OAG/sighash/prevouts";
const TAG_AMOUNTS: &str = "OAG/sighash/amounts";
const TAG_LOCKS: &str = "OAG/sighash/locks";
const TAG_SEQUENCES: &str = "OAG/sighash/sequences";
const TAG_OUTPUTS: &str = "OAG/sighash/outputs";

/// `ANYONECANPAY` を表すビット。
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// 署名が何にコミットするかの基本種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SighashBase {
    /// 全入力・全出力にコミットする。
    All,
    /// 出力にコミットしない。
    None,
    /// 同じ番号の出力のみにコミットする。
    Single,
}

/// 署名対象の指定。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SighashType {
    /// 基本種別。
    pub base: SighashBase,
    /// 自分の入力のみにコミットするか。
    pub anyone_can_pay: bool,
    /// 既定形式 (`0x00`) か。真なら署名は 64 バイトで済む。
    default_form: bool,
}

/// sighash の指定に関する誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SighashError {
    /// 未定義の sighash バイト。
    #[error("undefined sighash type: {0:#04x}")]
    UnknownType(u8),
    /// 入力番号が範囲外。
    #[error("input index {index} is out of range (there are {count} inputs)")]
    InputIndexOutOfRange {
        /// 指定された番号。
        index: usize,
        /// 実際の入力数。
        count: usize,
    },
    /// 使用対象の出力の個数が入力数と一致しない。
    #[error("{given} spent outputs were given but there are {expected} inputs")]
    SpentOutputCountMismatch {
        /// 与えられた個数。
        given: usize,
        /// 必要な個数。
        expected: usize,
    },
    /// `SINGLE` に対応する出力が存在しない。
    #[error("there is no output {index} for SINGLE (there are {count} outputs)")]
    SingleWithoutMatchingOutput {
        /// 入力番号。
        index: usize,
        /// 出力数。
        count: usize,
    },
}

impl SighashType {
    /// 既定形式。`All` と同じ範囲にコミットするが、署名は 64 バイトで済む。
    pub const DEFAULT: SighashType = SighashType {
        base: SighashBase::All,
        anyone_can_pay: false,
        default_form: true,
    };

    /// 明示的な種別を作る。
    pub const fn new(base: SighashBase, anyone_can_pay: bool) -> SighashType {
        SighashType {
            base,
            anyone_can_pay,
            default_form: false,
        }
    }

    /// 署名の末尾に付くバイト。既定形式では `0x00`。
    pub const fn to_byte(self) -> u8 {
        if self.default_form {
            return 0x00;
        }
        let base = match self.base {
            SighashBase::All => 0x01,
            SighashBase::None => 0x02,
            SighashBase::Single => 0x03,
        };
        if self.anyone_can_pay {
            base | SIGHASH_ANYONECANPAY
        } else {
            base
        }
    }

    /// バイトから種別を復元する。未定義の値は拒否する。
    pub fn from_byte(byte: u8) -> Result<SighashType, SighashError> {
        // 既定形式を先に判定する。0x00 は基本種別のビットを持たないため、
        // 基本種別の判定を先に行うと未定義として弾かれてしまう。
        if byte == 0x00 {
            return Ok(SighashType::DEFAULT);
        }
        let base = match byte & !SIGHASH_ANYONECANPAY {
            0x01 => SighashBase::All,
            0x02 => SighashBase::None,
            0x03 => SighashBase::Single,
            _ => return Err(SighashError::UnknownType(byte)),
        };
        Ok(SighashType::new(base, byte & SIGHASH_ANYONECANPAY != 0))
    }

    /// 既定形式か。
    pub const fn is_default(self) -> bool {
        self.default_form
    }

    /// この種別を用いたときの署名の長さ (バイト)。
    pub const fn signature_len(self) -> usize {
        if self.default_form {
            64
        } else {
            65
        }
    }
}

impl Default for SighashType {
    fn default() -> SighashType {
        SighashType::DEFAULT
    }
}

/// 1 トランザクションぶんの中間ハッシュ。
///
/// # なぜ要るのか
///
/// 署名対象のうち、**入力番号に依存しない部分が 5 つある** (prevouts、
/// amounts、locks、sequences、および `All` のときの outputs)。素朴に
/// 書くと入力ごとにこれを作り直すので、入力 n 個のトランザクションで
/// 同じものを n 回組み立てて n 回ハッシュすることになる。**O(n²) である。**
///
/// 入力 1 個が 4 本のバッファに足す量はおよそ 76 バイトなので、
/// 400 入力なら 12 MB、`MAX_TX_SIZE` いっぱいの 980 入力なら 73 MB を
/// ハッシュする。**必要なのはその 1/n である。**
///
/// # コンセンサスは変わらない
///
/// 控えるのは入力番号の関数ではない値だけである。同じ入力から同じ関数で
/// 同じ値が出るだけなので、[`sighash`] の結果は**ビット単位で同じ**に
/// なる。「同じ判定になること」を示す必要すらない。
///
/// [`sighash`] 自体がこれを 1 個作って使う薄い包みなので、**経路が
/// 分岐していない**。片方だけ直す、ということが起こらない。
pub struct SighashCache<'a> {
    tx: &'a Transaction,
    spent_outputs: &'a [TxOutput],
    prevouts: Hash,
    amounts: Hash,
    locks: Hash,
    sequences: Hash,
    /// `All` のときの出力へのコミット。`Single` は入力ごとに変わるので
    /// ここには入らない。
    all_outputs: Hash,
}

impl<'a> SighashCache<'a> {
    /// 中間ハッシュを 1 度だけ計算する。
    ///
    /// `spent_outputs` は各入力が参照する UTXO を入力と同じ順で並べたもの。
    ///
    /// # 使わない値も計算する
    ///
    /// `ANYONECANPAY` は前の 4 つを使わず、`None` は outputs を使わない。
    /// それでも作るのは、**種別ごとに経路を分けると、どの組み合わせで
    /// 何が計算済みかを呼ぶ側が知っていなければならなくなる**ためである。
    /// 余分は 1 回ぶんであり、n 回ではない。
    pub fn new(
        tx: &'a Transaction,
        spent_outputs: &'a [TxOutput],
    ) -> Result<SighashCache<'a>, SighashError> {
        if spent_outputs.len() != tx.inputs.len() {
            return Err(SighashError::SpentOutputCountMismatch {
                given: spent_outputs.len(),
                expected: tx.inputs.len(),
            });
        }

        let mut prevouts = Vec::new();
        let mut amounts = Vec::new();
        let mut locks = Vec::new();
        let mut sequences = Vec::new();
        for (input, spent) in tx.inputs.iter().zip(spent_outputs) {
            input.prev_out.encode_into(&mut prevouts);
            spent.amount.encode_into(&mut amounts);
            spent.lock.encode_into(&mut locks);
            sequences.extend_from_slice(&input.sequence.to_le_bytes());
        }

        let mut outputs = Vec::new();
        write_varint(tx.outputs.len() as u128, &mut outputs);
        for output in &tx.outputs {
            output.encode_into(&mut outputs);
        }

        Ok(SighashCache {
            tx,
            spent_outputs,
            prevouts: hash::tagged(TAG_PREVOUTS, &prevouts),
            amounts: hash::tagged(TAG_AMOUNTS, &amounts),
            locks: hash::tagged(TAG_LOCKS, &locks),
            sequences: hash::tagged(TAG_SEQUENCES, &sequences),
            all_outputs: hash::tagged(TAG_OUTPUTS, &outputs),
        })
    }

    /// 控えの対象になっているトランザクション。
    pub fn transaction(&self) -> &'a Transaction {
        self.tx
    }

    /// 各入力が参照する UTXO。
    pub fn spent_outputs(&self) -> &'a [TxOutput] {
        self.spent_outputs
    }

    /// `input_index` 番目の入力に対する署名対象。
    pub fn sighash(
        &self,
        input_index: usize,
        hash_type: SighashType,
    ) -> Result<[u8; 32], SighashError> {
        let tx = self.tx;
        if input_index >= tx.inputs.len() {
            return Err(SighashError::InputIndexOutOfRange {
                index: input_index,
                count: tx.inputs.len(),
            });
        }

        let mut msg = Vec::new();

        // エポックと種別。
        msg.push(0x00);
        msg.push(hash_type.to_byte());

        // トランザクション全体に関わる値。
        msg.extend_from_slice(&tx.version.to_le_bytes());
        msg.extend_from_slice(&tx.locktime.to_le_bytes());

        // ANYONECANPAY でなければ、全入力の情報にコミットする。
        if !hash_type.anyone_can_pay {
            msg.extend_from_slice(self.prevouts.as_bytes());
            msg.extend_from_slice(self.amounts.as_bytes());
            msg.extend_from_slice(self.locks.as_bytes());
            msg.extend_from_slice(self.sequences.as_bytes());
        }

        // 出力へのコミット。
        match hash_type.base {
            SighashBase::All => {
                msg.extend_from_slice(self.all_outputs.as_bytes());
            }
            SighashBase::Single => {
                let output = tx.outputs.get(input_index).ok_or(
                    SighashError::SingleWithoutMatchingOutput {
                        index: input_index,
                        count: tx.outputs.len(),
                    },
                )?;
                let mut buf = Vec::new();
                write_varint(1, &mut buf);
                output.encode_into(&mut buf);
                msg.extend_from_slice(hash::tagged(TAG_OUTPUTS, &buf).as_bytes());
            }
            SighashBase::None => {}
        }

        // 署名対象の入力。**切り詰めてはならない。** 切り詰めると別々の入力が
        // 同じ署名対象を持つことになり、片方の署名をもう片方に使い回せる。
        // 入力数は MAX_TX_SIZE が抑えているのでここに来る番号は必ず収まるが、
        // 収まらない場合は範囲外として断る。
        let index = u32::try_from(input_index).map_err(|_| SighashError::InputIndexOutOfRange {
            index: input_index,
            count: tx.inputs.len(),
        })?;
        msg.extend_from_slice(&index.to_le_bytes());

        // ANYONECANPAY なら、自分の入力の情報をここで直接コミットする。
        if hash_type.anyone_can_pay {
            let input = &tx.inputs[input_index];
            let spent = &self.spent_outputs[input_index];
            input.prev_out.encode_into(&mut msg);
            spent.amount.encode_into(&mut msg);
            spent.lock.encode_into(&mut msg);
            msg.extend_from_slice(&input.sequence.to_le_bytes());
        }

        Ok(hash::tagged(TAG_SIGHASH, &msg).to_bytes())
    }

    /// 署名対象を [`struct@Hash`] として返す補助。
    pub fn sighash_as_hash(
        &self,
        input_index: usize,
        hash_type: SighashType,
    ) -> Result<Hash, SighashError> {
        Ok(Hash::from_bytes(self.sighash(input_index, hash_type)?))
    }
}

/// `input_index` 番目の入力に対する署名対象を計算する。
///
/// `spent_outputs` は各入力が参照する UTXO を入力と同じ順で並べたもの。
///
/// # 入力が複数あるなら [`SighashCache`] を使うこと
///
/// これは中間ハッシュを毎回作り直す。1 回きりならそれでよいが、
/// **入力ごとに呼ぶと O(n²) になる。**
pub fn sighash(
    tx: &Transaction,
    spent_outputs: &[TxOutput],
    input_index: usize,
    hash_type: SighashType,
) -> Result<[u8; 32], SighashError> {
    SighashCache::new(tx, spent_outputs)?.sighash(input_index, hash_type)
}

/// 署名対象を [`struct@Hash`] として返す補助。
pub fn sighash_as_hash(
    tx: &Transaction,
    spent_outputs: &[TxOutput],
    input_index: usize,
    hash_type: SighashType,
) -> Result<Hash, SighashError> {
    Ok(Hash::from_bytes(sighash(
        tx,
        spent_outputs,
        input_index,
        hash_type,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **控えを一切使わない、独立の実装。**
    ///
    /// これは試験のためだけにある。[`SighashCache`] が中間ハッシュを
    /// 使い回すようになったので、**使い回さずに定義どおり組み立てたものと
    /// 一致するか**をここで確かめる。
    ///
    /// 一致が崩れるのはコンセンサスが割れるときなので、速い方だけを
    /// 残して片方を消してはならない。
    fn sighash_naive(
        tx: &Transaction,
        spent_outputs: &[TxOutput],
        input_index: usize,
        hash_type: SighashType,
    ) -> Result<[u8; 32], SighashError> {
        if spent_outputs.len() != tx.inputs.len() {
            return Err(SighashError::SpentOutputCountMismatch {
                given: spent_outputs.len(),
                expected: tx.inputs.len(),
            });
        }
        if input_index >= tx.inputs.len() {
            return Err(SighashError::InputIndexOutOfRange {
                index: input_index,
                count: tx.inputs.len(),
            });
        }

        let mut msg = Vec::new();
        msg.push(0x00);
        msg.push(hash_type.to_byte());
        msg.extend_from_slice(&tx.version.to_le_bytes());
        msg.extend_from_slice(&tx.locktime.to_le_bytes());

        if !hash_type.anyone_can_pay {
            let mut prevouts = Vec::new();
            let mut amounts = Vec::new();
            let mut locks = Vec::new();
            let mut sequences = Vec::new();
            for (input, spent) in tx.inputs.iter().zip(spent_outputs) {
                input.prev_out.encode_into(&mut prevouts);
                spent.amount.encode_into(&mut amounts);
                spent.lock.encode_into(&mut locks);
                sequences.extend_from_slice(&input.sequence.to_le_bytes());
            }
            msg.extend_from_slice(hash::tagged(TAG_PREVOUTS, &prevouts).as_bytes());
            msg.extend_from_slice(hash::tagged(TAG_AMOUNTS, &amounts).as_bytes());
            msg.extend_from_slice(hash::tagged(TAG_LOCKS, &locks).as_bytes());
            msg.extend_from_slice(hash::tagged(TAG_SEQUENCES, &sequences).as_bytes());
        }

        match hash_type.base {
            SighashBase::All => {
                let mut outputs = Vec::new();
                write_varint(tx.outputs.len() as u128, &mut outputs);
                for output in &tx.outputs {
                    output.encode_into(&mut outputs);
                }
                msg.extend_from_slice(hash::tagged(TAG_OUTPUTS, &outputs).as_bytes());
            }
            SighashBase::Single => {
                let output = tx.outputs.get(input_index).ok_or(
                    SighashError::SingleWithoutMatchingOutput {
                        index: input_index,
                        count: tx.outputs.len(),
                    },
                )?;
                let mut buf = Vec::new();
                write_varint(1, &mut buf);
                output.encode_into(&mut buf);
                msg.extend_from_slice(hash::tagged(TAG_OUTPUTS, &buf).as_bytes());
            }
            SighashBase::None => {}
        }

        let index = u32::try_from(input_index).map_err(|_| SighashError::InputIndexOutOfRange {
            index: input_index,
            count: tx.inputs.len(),
        })?;
        msg.extend_from_slice(&index.to_le_bytes());

        if hash_type.anyone_can_pay {
            let input = &tx.inputs[input_index];
            let spent = &spent_outputs[input_index];
            input.prev_out.encode_into(&mut msg);
            spent.amount.encode_into(&mut msg);
            spent.lock.encode_into(&mut msg);
            msg.extend_from_slice(&input.sequence.to_le_bytes());
        }

        Ok(hash::tagged(TAG_SIGHASH, &msg).to_bytes())
    }

    /// 入力 `inputs` 個・出力 `outputs` 個の取引を組む。
    fn tx_of(inputs: usize, outputs: usize) -> (Transaction, Vec<TxOutput>) {
        use crate::lock::Lock;
        use crate::tx::{OutPoint, TxInput, CURRENT_TX_VERSION};
        use oag_primitives::{hash as ph, Amount, SecretKey};

        let spent: Vec<TxOutput> = (0..inputs)
            .map(|i| {
                TxOutput::new(
                    Amount::from_atomic_const(1_000_000 + i as u128),
                    Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
                )
            })
            .collect();
        let tx = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: (0..inputs)
                .map(|i| {
                    let mut input =
                        TxInput::new(OutPoint::new(ph::txid(&i.to_le_bytes()), i as u32));
                    input.sequence = 0xFFFF_FFF0 + i as u32;
                    input
                })
                .collect(),
            outputs: (0..outputs)
                .map(|i| {
                    TxOutput::new(
                        Amount::from_atomic_const(10_000 + i as u128),
                        Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
                    )
                })
                .collect(),
            locktime: 12_345,
        };
        (tx, spent)
    }

    fn every_type() -> Vec<SighashType> {
        let mut out = vec![SighashType::DEFAULT];
        for base in [SighashBase::All, SighashBase::None, SighashBase::Single] {
            for anyone_can_pay in [false, true] {
                out.push(SighashType::new(base, anyone_can_pay));
            }
        }
        out
    }

    #[test]
    fn the_cache_gives_the_same_bytes_as_building_it_every_time() {
        // **これが「コンセンサスを変えていない」ことの試験である。**
        //
        // 入力数・出力数・種別をひととおり動かして、控えを使う経路と
        // 使わない経路が 1 ビットも違わないことを確かめる。
        for inputs in 1..=6usize {
            for outputs in 1..=6usize {
                let (tx, spent) = tx_of(inputs, outputs);
                let cache = SighashCache::new(&tx, &spent).expect("the lengths line up");
                for hash_type in every_type() {
                    for index in 0..inputs {
                        let fast = cache.sighash(index, hash_type);
                        let slow = sighash_naive(&tx, &spent, index, hash_type);
                        assert_eq!(
                            fast, slow,
                            "they diverged: {inputs} in, {outputs} out, \
                             {hash_type:?}, input {index}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_one_shot_form_agrees_with_the_cache() {
        let (tx, spent) = tx_of(4, 4);
        let cache = SighashCache::new(&tx, &spent).unwrap();
        for hash_type in every_type() {
            for index in 0..4 {
                assert_eq!(
                    sighash(&tx, &spent, index, hash_type),
                    cache.sighash(index, hash_type)
                );
            }
        }
    }

    #[test]
    fn the_same_errors_come_back() {
        // 誤りの出方も変わっていないこと。SINGLE で対応する出力が無い
        // 場合と、番号が範囲外の場合。
        let (tx, spent) = tx_of(3, 1);
        let single = SighashType::new(SighashBase::Single, false);
        let cache = SighashCache::new(&tx, &spent).unwrap();
        for index in 0..3 {
            assert_eq!(
                cache.sighash(index, single),
                sighash_naive(&tx, &spent, index, single)
            );
        }
        assert_eq!(
            cache.sighash(3, SighashType::DEFAULT),
            sighash_naive(&tx, &spent, 3, SighashType::DEFAULT)
        );

        let (tx, spent) = tx_of(3, 3);
        assert!(matches!(
            SighashCache::new(&tx, &spent[..2]),
            Err(SighashError::SpentOutputCountMismatch {
                given: 2,
                expected: 3
            })
        ));
    }

    #[test]
    fn reusing_a_cache_does_not_drift() {
        // 同じ控えから何度引いても同じ値が出ること。控えが呼ぶたびに
        // 書き換わっていれば、ここで落ちる。
        let (tx, spent) = tx_of(5, 5);
        let cache = SighashCache::new(&tx, &spent).unwrap();
        let first: Vec<_> = (0..5)
            .map(|i| cache.sighash(i, SighashType::DEFAULT).unwrap())
            .collect();
        for _ in 0..3 {
            for (i, expected) in first.iter().enumerate() {
                assert_eq!(&cache.sighash(i, SighashType::DEFAULT).unwrap(), expected);
            }
        }
    }

    use crate::lock::Lock;
    use crate::tx::{OutPoint, TxInput, CURRENT_TX_VERSION};
    use oag_primitives::{hash as ph, Amount, SecretKey};

    fn setup() -> (Transaction, Vec<TxOutput>, Vec<SecretKey>) {
        let keys: Vec<SecretKey> = (0..2).map(|_| SecretKey::generate()).collect();
        let spent: Vec<TxOutput> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                TxOutput::new(
                    Amount::from_oag(10 + i as u128).unwrap(),
                    Lock::pay_to_pubkey(&k.public_key()),
                )
            })
            .collect();
        let tx = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![
                TxInput::new(OutPoint::new(ph::txid(b"a"), 0)),
                TxInput::new(OutPoint::new(ph::txid(b"b"), 1)),
            ],
            outputs: vec![
                TxOutput::new(
                    Amount::from_oag(15).unwrap(),
                    Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
                ),
                TxOutput::new(
                    Amount::from_oag(5).unwrap(),
                    Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
                ),
            ],
            locktime: 0,
        };
        (tx, spent, keys)
    }

    fn h(tx: &Transaction, spent: &[TxOutput], i: usize) -> [u8; 32] {
        sighash(tx, spent, i, SighashType::DEFAULT).unwrap()
    }

    #[test]
    fn commits_to_spent_input_amounts() {
        // これが BIP143 / BIP341 が修正した問題への対処である。
        // 使用する UTXO の金額が変われば sighash も変わらなければならない。
        let (tx, mut spent, _) = setup();
        let original = h(&tx, &spent, 0);

        spent[0].amount = Amount::from_oag(999).unwrap();
        assert_ne!(
            h(&tx, &spent, 0),
            original,
            "it does not commit to input amounts (the fee-drain attack works)"
        );
    }

    #[test]
    fn commits_to_other_inputs_spent_amounts() {
        // 自分以外の入力の金額が変わっても sighash は変わる。
        let (tx, mut spent, _) = setup();
        let original = h(&tx, &spent, 0);
        spent[1].amount = Amount::from_oag(777).unwrap();
        assert_ne!(h(&tx, &spent, 0), original);
    }

    #[test]
    fn commits_to_spent_locks() {
        let (tx, mut spent, _) = setup();
        let original = h(&tx, &spent, 0);
        spent[0].lock = Lock::pay_to_pubkey(&SecretKey::generate().public_key());
        assert_ne!(h(&tx, &spent, 0), original);
    }

    #[test]
    fn commits_to_every_transaction_field() {
        let (base, spent, _) = setup();
        let original = h(&base, &spent, 0);

        let mut tx = base.clone();
        tx.version += 1;
        assert_ne!(h(&tx, &spent, 0), original, "version");

        let mut tx = base.clone();
        tx.locktime = 1;
        assert_ne!(h(&tx, &spent, 0), original, "locktime");

        let mut tx = base.clone();
        tx.inputs[0].sequence = 7;
        assert_ne!(h(&tx, &spent, 0), original, "sequence");

        let mut tx = base.clone();
        tx.inputs[1].sequence = 7;
        assert_ne!(h(&tx, &spent, 0), original, "another input's sequence");

        let mut tx = base.clone();
        tx.inputs[0].prev_out.index = 5;
        assert_ne!(h(&tx, &spent, 0), original, "prev_out");

        let mut tx = base.clone();
        tx.outputs[0].amount = Amount::from_oag(1).unwrap();
        assert_ne!(h(&tx, &spent, 0), original, "output amount");

        let mut tx = base.clone();
        tx.outputs.swap(0, 1);
        assert_ne!(h(&tx, &spent, 0), original, "output order");

        let mut tx = base;
        tx.outputs.pop();
        assert_ne!(h(&tx, &spent, 0), original, "output count");
    }

    #[test]
    fn does_not_commit_to_signatures() {
        // 署名は sighash の対象外。そうでなければ署名できない。
        let (mut tx, spent, _) = setup();
        let original = h(&tx, &spent, 0);
        tx.inputs[0].signature = vec![0xff; 64];
        tx.inputs[1].signature = vec![0xee; 64];
        assert_eq!(h(&tx, &spent, 0), original);
    }

    #[test]
    fn differs_per_input_index() {
        let (tx, spent, _) = setup();
        assert_ne!(h(&tx, &spent, 0), h(&tx, &spent, 1));
    }

    #[test]
    fn differs_per_hash_type() {
        let (tx, spent, _) = setup();
        let types = [
            SighashType::DEFAULT,
            SighashType::new(SighashBase::All, false),
            SighashType::new(SighashBase::None, false),
            SighashType::new(SighashBase::Single, false),
            SighashType::new(SighashBase::All, true),
            SighashType::new(SighashBase::None, true),
            SighashType::new(SighashBase::Single, true),
        ];
        let mut seen = std::collections::HashSet::new();
        for t in types {
            let value = sighash(&tx, &spent, 0, t).unwrap();
            assert!(
                seen.insert(value),
                "{t:?} produced the same sighash as another"
            );
        }
    }

    #[test]
    fn none_ignores_outputs() {
        let (base, spent, _) = setup();
        let t = SighashType::new(SighashBase::None, false);
        let original = sighash(&base, &spent, 0, t).unwrap();

        let mut tx = base;
        tx.outputs[0].amount = Amount::from_oag(1).unwrap();
        assert_eq!(sighash(&tx, &spent, 0, t).unwrap(), original);
    }

    #[test]
    fn anyone_can_pay_ignores_other_inputs() {
        let (base, mut spent, _) = setup();
        let t = SighashType::new(SighashBase::All, true);
        let original = sighash(&base, &spent, 0, t).unwrap();

        // 他の入力を変えても、自分の入力に対する sighash は変わらない。
        let mut tx = base.clone();
        tx.inputs[1].sequence = 99;
        assert_eq!(sighash(&tx, &spent, 0, t).unwrap(), original);

        spent[1].amount = Amount::from_oag(500).unwrap();
        assert_eq!(sighash(&base, &spent, 0, t).unwrap(), original);

        // 自分の入力を変えれば当然変わる。
        let mut tx = base;
        tx.inputs[0].sequence = 99;
        assert_ne!(sighash(&tx, &spent, 0, t).unwrap(), original);
    }

    #[test]
    fn single_requires_matching_output() {
        let (mut tx, spent, _) = setup();
        tx.outputs.pop();
        let t = SighashType::new(SighashBase::Single, false);
        assert!(sighash(&tx, &spent, 0, t).is_ok());
        assert_eq!(
            sighash(&tx, &spent, 1, t),
            Err(SighashError::SingleWithoutMatchingOutput { index: 1, count: 1 })
        );
    }

    #[test]
    fn single_only_commits_to_matching_output() {
        let (base, spent, _) = setup();
        let t = SighashType::new(SighashBase::Single, false);
        let original = sighash(&base, &spent, 0, t).unwrap();

        let mut tx = base.clone();
        tx.outputs[1].amount = Amount::from_oag(1).unwrap();
        assert_eq!(
            sighash(&tx, &spent, 0, t).unwrap(),
            original,
            "the other outputs are irrelevant"
        );

        let mut tx = base;
        tx.outputs[0].amount = Amount::from_oag(1).unwrap();
        assert_ne!(sighash(&tx, &spent, 0, t).unwrap(), original);
    }

    #[test]
    fn rejects_mismatched_spent_outputs() {
        let (tx, spent, _) = setup();
        assert_eq!(
            sighash(&tx, &spent[..1], 0, SighashType::DEFAULT),
            Err(SighashError::SpentOutputCountMismatch {
                given: 1,
                expected: 2
            })
        );
    }

    #[test]
    fn rejects_out_of_range_input() {
        let (tx, spent, _) = setup();
        assert_eq!(
            sighash(&tx, &spent, 2, SighashType::DEFAULT),
            Err(SighashError::InputIndexOutOfRange { index: 2, count: 2 })
        );
    }

    #[test]
    fn hash_type_byte_round_trip() {
        let cases = [
            (SighashType::DEFAULT, 0x00u8, 64usize),
            (SighashType::new(SighashBase::All, false), 0x01, 65),
            (SighashType::new(SighashBase::None, false), 0x02, 65),
            (SighashType::new(SighashBase::Single, false), 0x03, 65),
            (SighashType::new(SighashBase::All, true), 0x81, 65),
            (SighashType::new(SighashBase::None, true), 0x82, 65),
            (SighashType::new(SighashBase::Single, true), 0x83, 65),
        ];
        for (t, byte, len) in cases {
            assert_eq!(t.to_byte(), byte);
            assert_eq!(t.signature_len(), len);
            assert_eq!(SighashType::from_byte(byte).unwrap(), t);
        }
    }

    #[test]
    fn rejects_undefined_hash_type_bytes() {
        // 0x80 (ANYONECANPAY のみ) や 0x04 以降は未定義。
        for byte in [0x04u8, 0x05, 0x80, 0x84, 0xff] {
            assert_eq!(
                SighashType::from_byte(byte),
                Err(SighashError::UnknownType(byte))
            );
        }
    }

    #[test]
    fn sign_and_verify_a_real_transaction() {
        let (mut tx, spent, keys) = setup();

        // 署名は sighash の対象外なので、先に全入力分を計算してよい。
        let messages: Vec<[u8; 32]> = (0..tx.inputs.len())
            .map(|i| sighash(&tx, &spent, i, SighashType::DEFAULT).unwrap())
            .collect();
        for ((input, key), msg) in tx.inputs.iter_mut().zip(&keys).zip(&messages) {
            input.signature = key.sign(msg).to_bytes().to_vec();
        }

        for (i, key) in keys.iter().enumerate() {
            let msg = sighash(&tx, &spent, i, SighashType::DEFAULT).unwrap();
            let sig = oag_primitives::Signature::from_slice(&tx.inputs[i].signature).unwrap();
            assert!(key.public_key().verify(&msg, &sig));
            // 使用対象の UTXO に記録された鍵と一致すること。
            assert_eq!(spent[i].lock.to_pubkey().unwrap(), key.public_key());
        }
    }

    #[test]
    fn tampering_with_amount_after_signing_invalidates() {
        let (mut tx, spent, keys) = setup();
        let msg = sighash(&tx, &spent, 0, SighashType::DEFAULT).unwrap();
        tx.inputs[0].signature = keys[0].sign(&msg).to_bytes().to_vec();

        // 攻撃者が出力金額を書き換える。
        tx.outputs[0].amount = Amount::from_oag(19).unwrap();
        let tampered = sighash(&tx, &spent, 0, SighashType::DEFAULT).unwrap();
        let sig = oag_primitives::Signature::from_slice(&tx.inputs[0].signature).unwrap();
        assert!(!keys[0].public_key().verify(&tampered, &sig));
    }
}
