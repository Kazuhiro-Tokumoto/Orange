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
    #[error("未定義の sighash 種別: {0:#04x}")]
    UnknownType(u8),
    /// 入力番号が範囲外。
    #[error("入力番号 {index} が範囲外 (入力は {count} 個)")]
    InputIndexOutOfRange {
        /// 指定された番号。
        index: usize,
        /// 実際の入力数。
        count: usize,
    },
    /// 使用対象の出力の個数が入力数と一致しない。
    #[error("使用対象の出力が {given} 個だが、入力は {expected} 個ある")]
    SpentOutputCountMismatch {
        /// 与えられた個数。
        given: usize,
        /// 必要な個数。
        expected: usize,
    },
    /// `SINGLE` に対応する出力が存在しない。
    #[error("SINGLE に対応する出力 {index} が存在しない (出力は {count} 個)")]
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

/// `input_index` 番目の入力に対する署名対象を計算する。
///
/// `spent_outputs` は各入力が参照する UTXO を入力と同じ順で並べたもの。
pub fn sighash(
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

    // エポックと種別。
    msg.push(0x00);
    msg.push(hash_type.to_byte());

    // トランザクション全体に関わる値。
    msg.extend_from_slice(&tx.version.to_le_bytes());
    msg.extend_from_slice(&tx.locktime.to_le_bytes());

    // ANYONECANPAY でなければ、全入力の情報にコミットする。
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

    // 出力へのコミット。
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
            let output =
                tx.outputs
                    .get(input_index)
                    .ok_or(SighashError::SingleWithoutMatchingOutput {
                        index: input_index,
                        count: tx.outputs.len(),
                    })?;
            let mut buf = Vec::new();
            write_varint(1, &mut buf);
            output.encode_into(&mut buf);
            msg.extend_from_slice(hash::tagged(TAG_OUTPUTS, &buf).as_bytes());
        }
        SighashBase::None => {}
    }

    // 署名対象の入力。
    msg.extend_from_slice(&(input_index as u32).to_le_bytes());

    // ANYONECANPAY なら、自分の入力の情報をここで直接コミットする。
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
            "入力金額にコミットしていない (手数料流出攻撃が成立する)"
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
        assert_ne!(h(&tx, &spent, 0), original, "他の入力の sequence");

        let mut tx = base.clone();
        tx.inputs[0].prev_out.index = 5;
        assert_ne!(h(&tx, &spent, 0), original, "prev_out");

        let mut tx = base.clone();
        tx.outputs[0].amount = Amount::from_oag(1).unwrap();
        assert_ne!(h(&tx, &spent, 0), original, "出力金額");

        let mut tx = base.clone();
        tx.outputs.swap(0, 1);
        assert_ne!(h(&tx, &spent, 0), original, "出力の順序");

        let mut tx = base;
        tx.outputs.pop();
        assert_ne!(h(&tx, &spent, 0), original, "出力の個数");
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
            assert!(seen.insert(value), "{t:?} が他と同じ sighash を生んだ");
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
            "他の出力は無関係"
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
