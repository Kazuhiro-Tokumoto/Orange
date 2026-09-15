//! 部分署名トランザクション (PST)。Bitcoin の PSBT (BIP174) 相当である。
//!
//! 署名の済んでいないトランザクションを、**署名に必要なものを全部添えて**
//! 持ち運ぶための形式である。鍵を持つ機械とネットワークに繋がる機械を
//! 分けたいとき、あるいは複数の持ち主が順に署名するときに要る。
//!
//! # なぜ生のトランザクションでは足りないのか
//!
//! 署名の対象 (sighash) は、**そのトランザクションが使うすべての出力の
//! 金額と支払い条件**を含む (`docs/SPEC.md` §8.2)。生のトランザクションが
//! 持っているのは参照 (`OutPoint`) だけで、金額も条件も入っていない。
//! したがって署名する側はチェーンを見に行かねばならず、鍵だけを持った
//! 機械では署名できない。この形式はそれらを一緒に運ぶ。
//!
//! # §8.2 が守ってくれること
//!
//! PSBT には「入力の金額を偽って渡し、署名する側に法外な手数料を払わせる」
//! という筋の攻撃がある。本チェーンでは**成立しない**。sighash が全入力の
//! 金額を含むため、偽った金額で作った署名は、本当の金額に対しては通らない。
//! 損をするのではなく、単に無効なトランザクションができる。
//!
//! それでも [`Pst::fee`] を見てから署名すること。無効になると分かるのは
//! 検証の時であり、その前に止められるならそのほうがよい。
//!
//! # 役割
//!
//! BIP174 と同じ分け方である。
//!
//! | 役割 | 手続き |
//! | --- | --- |
//! | 作る | [`Pst::from_draft`] |
//! | 署名する | [`Pst::sign_with`] — **署名できる入力だけ**に入れる |
//! | 束ねる | [`Pst::combine`] — 別々に署名されたものを 1 つにする |
//! | 仕上げる | [`Pst::finalize`] — 全部揃っていれば取引を取り出す |
//!
//! [`crate::build::sign`] との違いは、**一部だけ署名して返してよい**点で
//! ある。あちらは 1 個でも鍵が欠けていれば何もしない。

use oag_consensus::codec::{write_var_bytes, write_varint, CodecError, Decode, Encode, Reader};
use oag_consensus::lock::Lock;
use oag_consensus::params;
use oag_consensus::sighash::{sighash, SighashType};
use oag_consensus::{Transaction, TxOutput};
use oag_primitives::{Amount, Hash, SecretKey, Signature};

use crate::build::Draft;

/// 形式の目印。
pub const MAGIC: [u8; 6] = *b"oagpst";

/// 形式の版数。
pub const VERSION: u8 = 1;

/// BIP340 の署名の長さ。
const SIGNATURE_LEN: usize = 64;

/// PST の扱いでの失敗。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PstError {
    /// 符号化が読めない。
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// 目印が合わない。
    #[error("PST の目印が合わない")]
    BadMagic,
    /// 知らない版数。
    #[error("PST の版数 {0} をこの実装は知らない")]
    UnknownVersion(u8),
    /// 入力・出力の数が本体と食い違う。
    #[error("{field} の数が {declared} だが、取引の側は {actual} である")]
    CountMismatch {
        /// 食い違った箇所。
        field: &'static str,
        /// 添えられていた数。
        declared: usize,
        /// 取引側の数。
        actual: usize,
    },
    /// 「未署名の取引」に署名が入っている。
    #[error("未署名のはずの取引の入力 {index} に署名が入っている")]
    NotUnsigned {
        /// その入力の位置。
        index: usize,
    },
    /// 署名の長さが合わない。
    #[error("入力 {index} の署名が {actual} バイトである ({expected} バイトであること)")]
    BadSignatureLength {
        /// その入力の位置。
        index: usize,
        /// 実際の長さ。
        actual: usize,
        /// あるべき長さ。
        expected: usize,
    },
    /// 署名が検証を通らない。
    #[error("入力 {index} の署名が通らない")]
    BadSignature {
        /// その入力の位置。
        index: usize,
    },
    /// 別の取引のものを束ねようとした。
    #[error("束ねようとした PST は別の取引のものである ({ours} と {theirs})")]
    NotTheSameTransaction {
        /// こちらの txid。
        ours: Hash,
        /// 相手の txid。
        theirs: Hash,
    },
    /// 添えられた UTXO が食い違う。
    #[error("入力 {index} に添えられた出力が食い違っている")]
    ConflictingUtxo {
        /// その入力の位置。
        index: usize,
    },
    /// まだ署名が揃っていない。
    #[error("入力 {index} の署名がまだ無い")]
    Incomplete {
        /// 欠けている入力の位置。
        index: usize,
    },
    /// 出力の合計が入力を超えている。
    #[error("出力の合計 {out} が入力の合計 {in_} を超えている")]
    NegativeFee {
        /// 入力の合計。
        in_: Amount,
        /// 出力の合計。
        out: Amount,
    },
    /// 金額の計算が桁あふれした。
    #[error("金額の計算が桁あふれした")]
    Overflow,
    /// sighash を計算できない。
    #[error("sighash を計算できない: {0}")]
    Sighash(String),
    /// 出来上がりが大きすぎる。
    #[error("取引が大きすぎる ({actual} バイト、上限 {max})")]
    TooLarge {
        /// 実際の大きさ。
        actual: usize,
        /// 上限。
        max: usize,
    },
}

/// 鍵の導出経路の控え。
///
/// `m/44'/<coin_type>'/<account>'/<change>/<index>` のうち、ウォレットが
/// 決める後ろ 3 つを持つ。`purpose` と `coin_type` は仕様で決まっており、
/// 運ぶ意味がない (`docs/SPEC.md` §6.6)。
///
/// **これは目安であって証拠ではない。** 署名する側は、この経路で導いた
/// 鍵が本当にその支払い条件に合うかを必ず確かめること。合わなければ
/// 署名しない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Derivation {
    /// 口座番号 (強化)。
    pub account: u32,
    /// 0 なら受取用、1 ならおつり用。
    pub change: u32,
    /// 通し番号。
    pub index: u32,
}

impl Encode for Derivation {
    fn encode_into(&self, out: &mut Vec<u8>) {
        write_varint(u128::from(self.account), out);
        write_varint(u128::from(self.change), out);
        write_varint(u128::from(self.index), out);
    }
}

impl Decode for Derivation {
    const MIN_ENCODED_LEN: usize = 3;

    fn read_from(reader: &mut Reader<'_>) -> Result<Derivation, CodecError> {
        Ok(Derivation {
            account: reader.read_varint_u32("pst.derivation.account")?,
            change: reader.read_varint_u32("pst.derivation.change")?,
            index: reader.read_varint_u32("pst.derivation.index")?,
        })
    }
}

fn write_option<T: Encode>(value: &Option<T>, out: &mut Vec<u8>) {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            value.encode_into(out);
        }
    }
}

fn read_option<T: Decode>(
    reader: &mut Reader<'_>,
    field: &'static str,
) -> Result<Option<T>, CodecError> {
    if reader.read_bool(field)? {
        Ok(Some(T::read_from(reader)?))
    } else {
        Ok(None)
    }
}

/// 1 つの入力に添える控え。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PstInput {
    /// この入力が使う出力。**金額と支払い条件が署名に要る。**
    pub utxo: TxOutput,
    /// この入力に使う sighash の種類。
    pub sighash: SighashType,
    /// 署名。まだ無ければ `None`。
    pub signature: Option<Vec<u8>>,
    /// 鍵の導出経路の目安。
    pub derivation: Option<Derivation>,
}

impl Encode for PstInput {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.utxo.encode_into(out);
        out.push(self.sighash.to_byte());
        write_var_bytes(self.signature.as_deref().unwrap_or(&[]), out);
        write_option(&self.derivation, out);
    }
}

impl Decode for PstInput {
    // 出力 (金額 1 + 条件 2) + sighash 1 + 署名長 1 + 経路の有無 1。
    const MIN_ENCODED_LEN: usize = 6;

    fn read_from(reader: &mut Reader<'_>) -> Result<PstInput, CodecError> {
        let utxo = TxOutput::read_from(reader)?;
        let byte = reader.read_u8()?;
        let sighash = SighashType::from_byte(byte).map_err(|_| CodecError::ValueOutOfRange {
            field: "pst.input.sighash",
            value: u128::from(byte),
        })?;
        let signature = reader.read_var_bytes("pst.input.signature", SIGNATURE_LEN + 1)?;
        let derivation = read_option(reader, "pst.input.derivation")?;
        Ok(PstInput {
            utxo,
            sighash,
            signature: (!signature.is_empty()).then(|| signature.to_vec()),
            derivation,
        })
    }
}

/// 1 つの出力に添える控え。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PstOutput {
    /// 鍵の導出経路の目安。
    ///
    /// **おつりが本当に自分のものかを、署名する側が確かめるために要る。**
    /// これが無いと、おつりの宛先をすり替えられても気づけない。
    pub derivation: Option<Derivation>,
}

impl Encode for PstOutput {
    fn encode_into(&self, out: &mut Vec<u8>) {
        write_option(&self.derivation, out);
    }
}

impl Decode for PstOutput {
    const MIN_ENCODED_LEN: usize = 1;

    fn read_from(reader: &mut Reader<'_>) -> Result<PstOutput, CodecError> {
        Ok(PstOutput {
            derivation: read_option(reader, "pst.output.derivation")?,
        })
    }
}

/// 部分署名トランザクション。
///
/// # `unsigned` の txid は最終的な txid ではない
///
/// 本チェーンの txid は取引の符号化全体のハッシュであり、**署名を含む**
/// (`docs/SPEC.md` §5.3)。したがって署名が入れば txid は変わる。ここで
/// 持っている `unsigned` の txid は、[`Pst::combine`] が「同じ取引か」を
/// 確かめるための照合用であって、送金先に伝える番号ではない。**最終的な
/// txid が決まるのは [`Pst::finalize`] のあとである。**
///
/// 第三者が書き換えられないことは変わらない。BIP340 の署名は固定長かつ
/// 厳密な符号化を持ち、鍵を持たない者は別の有効な署名を作れない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pst {
    /// 署名の入っていない取引。**入力の `signature` はすべて空である。**
    unsigned: Transaction,
    inputs: Vec<PstInput>,
    outputs: Vec<PstOutput>,
}

impl Pst {
    /// 下書きから作る。
    pub fn from_draft(draft: &Draft) -> Pst {
        let mut unsigned = draft.tx.clone();
        for input in &mut unsigned.inputs {
            input.signature.clear();
        }
        let inputs = draft
            .spent
            .iter()
            .map(|utxo| PstInput {
                utxo: utxo.clone(),
                sighash: SighashType::DEFAULT,
                signature: None,
                derivation: None,
            })
            .collect();
        let outputs = unsigned
            .outputs
            .iter()
            .map(|_| PstOutput { derivation: None })
            .collect();
        Pst {
            unsigned,
            inputs,
            outputs,
        }
    }

    /// 署名の入っていない取引。
    pub fn unsigned(&self) -> &Transaction {
        &self.unsigned
    }

    /// 入力に添えた控え。
    pub fn inputs(&self) -> &[PstInput] {
        &self.inputs
    }

    /// 入力に添えた控え (書き換え可能)。導出経路を入れるために使う。
    pub fn inputs_mut(&mut self) -> &mut [PstInput] {
        &mut self.inputs
    }

    /// 出力に添えた控え。
    pub fn outputs(&self) -> &[PstOutput] {
        &self.outputs
    }

    /// 出力に添えた控え (書き換え可能)。
    pub fn outputs_mut(&mut self) -> &mut [PstOutput] {
        &mut self.outputs
    }

    /// 使う出力の一覧。sighash の計算に渡す形。
    fn spent(&self) -> Vec<TxOutput> {
        self.inputs.iter().map(|i| i.utxo.clone()).collect()
    }

    /// 支払う手数料。
    ///
    /// **署名する前にこれを見ること。** 入力の合計と出力の合計の差であり、
    /// 出来上がる取引が実際に手放す額である。
    pub fn fee(&self) -> Result<Amount, PstError> {
        let in_ =
            Amount::sum(self.inputs.iter().map(|i| i.utxo.amount)).ok_or(PstError::Overflow)?;
        let out = Amount::sum(self.unsigned.outputs.iter().map(|o| o.amount))
            .ok_or(PstError::Overflow)?;
        in_.checked_sub(out)
            .ok_or(PstError::NegativeFee { in_, out })
    }

    /// 署名がすべて揃っているか。
    pub fn is_complete(&self) -> bool {
        self.inputs.iter().all(|i| i.signature.is_some())
    }

    /// 署名の入っていない入力のうち、鍵を引けるものに署名する。
    ///
    /// 入れた署名の数を返す。**1 個も引けなくても失敗ではない。** 自分の
    /// 持ち分だけを入れて次へ回す、という使い方をするための形式である。
    ///
    /// すでに署名の入っている入力には触れない。**他人の署名を上書きしない。**
    pub fn sign_with(
        &mut self,
        key_for: impl Fn(&Lock) -> Option<SecretKey>,
    ) -> Result<usize, PstError> {
        let spent = self.spent();
        let mut added = 0;
        for index in 0..self.inputs.len() {
            if self.inputs[index].signature.is_some() {
                continue;
            }
            let Some(key) = key_for(&self.inputs[index].utxo.lock) else {
                continue;
            };
            let hash_type = self.inputs[index].sighash;
            let msg = sighash(&self.unsigned, &spent, index, hash_type)
                .map_err(|e| PstError::Sighash(e.to_string()))?;
            let mut bytes = key.sign(&msg).to_bytes().to_vec();
            // 既定の種類は 1 バイト省く。SPEC §8.3 の取り決めである。
            if !hash_type.is_default() {
                bytes.push(hash_type.to_byte());
            }
            self.inputs[index].signature = Some(bytes);
            added += 1;
        }
        Ok(added)
    }

    /// 別々に署名された同じ取引を 1 つに束ねる。
    ///
    /// **同じ取引であり、添えられた出力も一致することを確かめてから
    /// 束ねる。** 添えられた金額が違えば sighash も違う。確かめずに
    /// 混ぜると、後から署名する側に別物を署名させられる。
    ///
    /// こちらに無い署名だけを取り込む。**すでにあるものは上書きしない。**
    pub fn combine(&mut self, other: &Pst) -> Result<usize, PstError> {
        let ours = self.unsigned.txid();
        let theirs = other.unsigned.txid();
        if ours != theirs {
            return Err(PstError::NotTheSameTransaction { ours, theirs });
        }
        if self.inputs.len() != other.inputs.len() {
            return Err(PstError::CountMismatch {
                field: "inputs",
                declared: other.inputs.len(),
                actual: self.inputs.len(),
            });
        }
        // 添えた出力は取引の中身ではないので、txid が同じでも食い違いうる。
        // **金額が違えば sighash も違う。** 別に見る。
        for (index, (mine, yours)) in self.inputs.iter().zip(&other.inputs).enumerate() {
            if mine.utxo != yours.utxo {
                return Err(PstError::ConflictingUtxo { index });
            }
        }

        let mut taken = 0;
        for (mine, yours) in self.inputs.iter_mut().zip(&other.inputs) {
            if mine.signature.is_none() {
                if let Some(signature) = &yours.signature {
                    mine.signature = Some(signature.clone());
                    mine.sighash = yours.sighash;
                    taken += 1;
                }
            }
            if mine.derivation.is_none() {
                mine.derivation = yours.derivation;
            }
        }
        for (mine, yours) in self.outputs.iter_mut().zip(&other.outputs) {
            if mine.derivation.is_none() {
                mine.derivation = yours.derivation;
            }
        }
        Ok(taken)
    }

    /// 署名を入れて取引を取り出す。
    ///
    /// **すべての署名を検証してから返す。** 束ねる側が壊れていたり
    /// 悪意があったりして、通らない署名が混ざっていることがある。ここで
    /// 捕まえなければ、送ってから初めて分かることになる。
    pub fn finalize(self) -> Result<Transaction, PstError> {
        let spent = self.spent();
        let mut tx = self.unsigned;
        for (index, input) in self.inputs.iter().enumerate() {
            let signature = input
                .signature
                .as_ref()
                .ok_or(PstError::Incomplete { index })?;
            tx.inputs[index].signature = signature.clone();
        }

        for (index, input) in self.inputs.iter().enumerate() {
            verify_input(&tx, &spent, index, &input.utxo.lock)?;
        }

        let size = tx.encode().len();
        if size > params::MAX_TX_SIZE {
            return Err(PstError::TooLarge {
                actual: size,
                max: params::MAX_TX_SIZE,
            });
        }
        Ok(tx)
    }

    /// バイト列に符号化する。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        self.unsigned.encode_into(&mut out);
        write_varint(self.inputs.len() as u128, &mut out);
        for input in &self.inputs {
            input.encode_into(&mut out);
        }
        write_varint(self.outputs.len() as u128, &mut out);
        for output in &self.outputs {
            output.encode_into(&mut out);
        }
        out
    }

    /// バイト列から復号する。
    ///
    /// 次を確かめる。どれも、通してしまうと**署名する側に見せているものと
    /// 実際に署名されるものが食い違う**。
    ///
    /// - 「未署名の取引」に署名が入っていないこと
    /// - 添えた控えの数が、取引の入力・出力の数と一致すること
    /// - 署名の長さが 64 バイト (または種類を足した 65 バイト) であること
    pub fn decode(bytes: &[u8]) -> Result<Pst, PstError> {
        let mut reader = Reader::new(bytes);
        let magic: [u8; 6] = reader.read_array()?;
        if magic != MAGIC {
            return Err(PstError::BadMagic);
        }
        let version = reader.read_u8()?;
        if version != VERSION {
            return Err(PstError::UnknownVersion(version));
        }
        let unsigned = Transaction::read_from(&mut reader)?;

        let declared = reader.read_count::<PstInput>("pst.inputs")?;
        if declared != unsigned.inputs.len() {
            return Err(PstError::CountMismatch {
                field: "inputs",
                declared,
                actual: unsigned.inputs.len(),
            });
        }
        let mut inputs = Vec::with_capacity(declared);
        for _ in 0..declared {
            inputs.push(PstInput::read_from(&mut reader)?);
        }

        let declared = reader.read_count::<PstOutput>("pst.outputs")?;
        if declared != unsigned.outputs.len() {
            return Err(PstError::CountMismatch {
                field: "outputs",
                declared,
                actual: unsigned.outputs.len(),
            });
        }
        let mut outputs = Vec::with_capacity(declared);
        for _ in 0..declared {
            outputs.push(PstOutput::read_from(&mut reader)?);
        }
        reader.finish()?;

        // 「未署名の取引」に署名が入っていてはならない。入っていると、
        // 見せている取引と署名の対象がずれる。
        for (index, input) in unsigned.inputs.iter().enumerate() {
            if !input.signature.is_empty() {
                return Err(PstError::NotUnsigned { index });
            }
        }
        for (index, input) in inputs.iter().enumerate() {
            if let Some(signature) = &input.signature {
                let expected = input.sighash.signature_len();
                if signature.len() != expected {
                    return Err(PstError::BadSignatureLength {
                        index,
                        actual: signature.len(),
                        expected,
                    });
                }
            }
        }

        Ok(Pst {
            unsigned,
            inputs,
            outputs,
        })
    }
}

/// 1 つの入力の署名を検証する。
fn verify_input(
    tx: &Transaction,
    spent: &[TxOutput],
    index: usize,
    lock: &Lock,
) -> Result<(), PstError> {
    let Some(pubkey) = lock.to_pubkey() else {
        // 公開鍵への支払いでなければ、ここで確かめられることはない。
        // コンセンサス側も同じ扱いをする (SPEC §10.4)。
        return Ok(());
    };
    let field = &tx.inputs[index].signature;
    let (bytes, hash_type) = match field.len() {
        64 => (&field[..], SighashType::DEFAULT),
        65 => (
            &field[..64],
            SighashType::from_byte(field[64]).map_err(|_| PstError::BadSignature { index })?,
        ),
        actual => {
            return Err(PstError::BadSignatureLength {
                index,
                actual,
                expected: SIGNATURE_LEN,
            })
        }
    };
    let signature = Signature::from_slice(bytes).map_err(|_| PstError::BadSignature { index })?;
    let msg = sighash(tx, spent, index, hash_type).map_err(|e| PstError::Sighash(e.to_string()))?;
    if !pubkey.verify(&msg, &signature) {
        return Err(PstError::BadSignature { index });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::{build, Coin, Spend};
    use oag_consensus::tx::OutPoint;

    const HEIGHT: u64 = 500;
    const FEE_RATE: &str = "0.000005";

    fn lock_of(key: &SecretKey) -> Lock {
        Lock::pay_to_pubkey(&key.public_key())
    }

    fn coin(amount: &str, key: &SecretKey, n: u32) -> Coin {
        Coin {
            outpoint: OutPoint {
                txid: oag_primitives::hash::txid(&n.to_le_bytes()),
                index: n,
            },
            output: TxOutput::new(amount.parse::<Amount>().unwrap(), lock_of(key)),
            height: 1,
            is_coinbase: false,
        }
    }

    /// 2 人がそれぞれ 1 件ずつ出し合う支払いを組む。
    fn shared() -> (Pst, SecretKey, SecretKey) {
        let alice = SecretKey::generate();
        let bob = SecretKey::generate();
        let coins = vec![coin("5", &alice, 1), coin("5", &bob, 2)];
        let spend = Spend {
            to: lock_of(&SecretKey::generate()),
            amount: "9".parse().unwrap(),
            change_to: lock_of(&alice),
            next_height: HEIGHT,
            fee_rate: FEE_RATE.parse().unwrap(),
        };
        let draft = build(&coins, &spend).unwrap();
        assert_eq!(draft.spent.len(), 2, "2 件とも使う組み立てになっていない");
        (Pst::from_draft(&draft), alice, bob)
    }

    /// 1 人で完結する支払い。
    fn solo() -> (Pst, SecretKey) {
        let key = SecretKey::generate();
        let coins = vec![coin("10", &key, 1)];
        let spend = Spend {
            to: lock_of(&SecretKey::generate()),
            amount: "1".parse().unwrap(),
            change_to: lock_of(&key),
            next_height: HEIGHT,
            fee_rate: FEE_RATE.parse().unwrap(),
        };
        let draft = build(&coins, &spend).unwrap();
        (Pst::from_draft(&draft), key)
    }

    fn keyring(keys: &[&SecretKey]) -> impl Fn(&Lock) -> Option<SecretKey> {
        let pairs: Vec<(Lock, SecretKey)> =
            keys.iter().map(|k| (lock_of(k), (*k).clone())).collect();
        move |lock: &Lock| {
            pairs
                .iter()
                .find(|(l, _)| l == lock)
                .map(|(_, k)| k.clone())
        }
    }

    // ━━━━━━━━ 署名を集める ━━━━━━━━

    #[test]
    fn a_fresh_pst_carries_no_signatures() {
        let (pst, _) = solo();
        assert!(!pst.is_complete());
        assert!(
            pst.unsigned().inputs.iter().all(|i| i.signature.is_empty()),
            "未署名のはずの取引に署名が残っている"
        );
        // 下書きは大きさを測るために 64 バイトの場所取りを入れている。
        // **それを消さずに運ぶと、署名の入った取引を未署名だと偽ることに
        // なる。**
        assert_eq!(pst.inputs().len(), 1);
    }

    #[test]
    fn each_owner_signs_only_their_own_input() {
        let (mut pst, alice, bob) = shared();

        let added = pst.sign_with(keyring(&[&alice])).unwrap();
        assert_eq!(added, 1, "自分の持ち分だけを署名していない");
        assert!(!pst.is_complete());

        let added = pst.sign_with(keyring(&[&bob])).unwrap();
        assert_eq!(added, 1);
        assert!(pst.is_complete());

        pst.finalize().unwrap();
    }

    #[test]
    fn signing_with_no_matching_key_is_not_an_error() {
        // **持ち分が無くても失敗にしない。** 順に回して集める形式である。
        let (mut pst, _, _) = shared();
        let stranger = SecretKey::generate();
        assert_eq!(pst.sign_with(keyring(&[&stranger])).unwrap(), 0);
        assert!(!pst.is_complete());
    }

    #[test]
    fn signing_twice_does_not_overwrite() {
        let (mut pst, alice, _) = shared();
        pst.sign_with(keyring(&[&alice])).unwrap();
        let first = pst.inputs()[0].signature.clone();
        assert_eq!(pst.sign_with(keyring(&[&alice])).unwrap(), 0);
        assert_eq!(pst.inputs()[0].signature, first, "他人の署名を上書きした");
    }

    #[test]
    fn an_incomplete_pst_does_not_finalize() {
        let (mut pst, alice, _) = shared();
        pst.sign_with(keyring(&[&alice])).unwrap();
        let missing = (0..pst.inputs().len())
            .find(|i| pst.inputs()[*i].signature.is_none())
            .unwrap();
        assert_eq!(pst.finalize(), Err(PstError::Incomplete { index: missing }));
    }

    // ━━━━━━━━ 束ねる ━━━━━━━━

    #[test]
    fn two_separately_signed_copies_combine() {
        let (pst, alice, bob) = shared();
        let mut mine = pst.clone();
        let mut theirs = pst;

        mine.sign_with(keyring(&[&alice])).unwrap();
        theirs.sign_with(keyring(&[&bob])).unwrap();
        assert!(!mine.is_complete() && !theirs.is_complete());

        assert_eq!(mine.combine(&theirs).unwrap(), 1);
        assert!(mine.is_complete());
        mine.finalize().unwrap();
    }

    #[test]
    fn combining_does_not_overwrite_what_we_have() {
        let (pst, alice, bob) = shared();
        let mut mine = pst.clone();
        let mut theirs = pst;
        mine.sign_with(keyring(&[&alice, &bob])).unwrap();
        theirs.sign_with(keyring(&[&alice, &bob])).unwrap();

        let before = mine.inputs().to_vec();
        assert_eq!(mine.combine(&theirs).unwrap(), 0);
        assert_eq!(mine.inputs(), before.as_slice());
    }

    #[test]
    fn a_different_transaction_cannot_be_combined() {
        let (mut mine, _) = solo();
        let (theirs, _) = solo();
        let err = mine.combine(&theirs).unwrap_err();
        assert!(
            matches!(err, PstError::NotTheSameTransaction { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_swapped_utxo_cannot_be_combined() {
        // **添えた金額が違えば sighash も違う。** 確かめずに混ぜると、
        // 後から署名する側に別物を署名させられる。
        let (pst, alice, bob) = shared();
        let mut mine = pst.clone();
        let mut theirs = pst;
        mine.sign_with(keyring(&[&alice])).unwrap();
        theirs.inputs_mut()[1].utxo.amount = "4".parse().unwrap();
        theirs.sign_with(keyring(&[&bob])).unwrap();

        assert_eq!(
            mine.combine(&theirs),
            Err(PstError::ConflictingUtxo { index: 1 })
        );
        assert!(!mine.is_complete(), "食い違う署名を取り込んでいる");
    }

    #[test]
    fn a_bad_signature_is_caught_before_the_transaction_comes_out() {
        // 束ねる側が壊れていることがある。ここで捕まえなければ、
        // 送ってから初めて分かることになる。
        let (mut pst, key) = solo();
        pst.sign_with(keyring(&[&key])).unwrap();
        let signature = pst.inputs_mut()[0].signature.as_mut().unwrap();
        signature[0] ^= 0xff;
        assert_eq!(pst.finalize(), Err(PstError::BadSignature { index: 0 }));
    }

    // ━━━━━━━━ 手数料 ━━━━━━━━

    #[test]
    fn the_fee_is_visible_before_signing() {
        let (pst, _) = solo();
        let in_ = Amount::sum(pst.inputs().iter().map(|i| i.utxo.amount)).unwrap();
        let out = Amount::sum(pst.unsigned().outputs.iter().map(|o| o.amount)).unwrap();
        assert_eq!(pst.fee().unwrap(), in_.checked_sub(out).unwrap());
        // 署名する前に、実際に手放す額が分かること。
        assert!(pst.fee().unwrap() > Amount::ZERO);
        assert!(pst.fee().unwrap() < "0.01".parse().unwrap());
    }

    #[test]
    fn a_lie_about_the_input_amount_does_not_cost_the_signer() {
        // sighash は全入力の金額を含む (SPEC §8.2)。偽った金額で作った
        // 署名は、本当の金額に対しては通らない。**損をするのではなく、
        // 単に無効な取引ができる。**
        let (honest, key) = solo();
        let mut lied = honest.clone();
        lied.inputs_mut()[0].utxo.amount = "1000".parse().unwrap();
        assert!(lied.fee().unwrap() > honest.fee().unwrap());

        lied.sign_with(keyring(&[&key])).unwrap();
        let signature = lied.inputs()[0].signature.clone().unwrap();

        // 本当の金額を添えた側にその署名を移すと、通らない。
        let mut real = honest;
        real.inputs_mut()[0].signature = Some(signature);
        assert_eq!(real.finalize(), Err(PstError::BadSignature { index: 0 }));
    }

    #[test]
    fn outputs_above_inputs_are_refused() {
        let (mut pst, _) = solo();
        pst.inputs_mut()[0].utxo.amount = "0.1".parse().unwrap();
        assert!(matches!(pst.fee(), Err(PstError::NegativeFee { .. })));
    }

    // ━━━━━━━━ 符号化 ━━━━━━━━

    #[test]
    fn it_round_trips() {
        let (mut pst, alice, _) = shared();
        pst.sign_with(keyring(&[&alice])).unwrap();
        pst.inputs_mut()[0].derivation = Some(Derivation {
            account: 0,
            change: 1,
            index: 7,
        });
        pst.outputs_mut()[1].derivation = Some(Derivation {
            account: 0,
            change: 1,
            index: 9,
        });

        let bytes = pst.encode();
        assert_eq!(Pst::decode(&bytes).unwrap(), pst);
    }

    #[test]
    fn a_signed_pst_round_trips_and_finalizes() {
        let (mut pst, alice, bob) = shared();
        pst.sign_with(keyring(&[&alice, &bob])).unwrap();
        let restored = Pst::decode(&pst.encode()).unwrap();
        let from_original = pst.finalize().unwrap();
        assert_eq!(restored.finalize().unwrap(), from_original);
    }

    #[test]
    fn the_magic_is_checked() {
        let (pst, _) = solo();
        let mut bytes = pst.encode();
        bytes[0] = b'x';
        assert_eq!(Pst::decode(&bytes), Err(PstError::BadMagic));
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let (pst, _) = solo();
        let mut bytes = pst.encode();
        bytes[MAGIC.len()] = 99;
        assert_eq!(Pst::decode(&bytes), Err(PstError::UnknownVersion(99)));
    }

    #[test]
    fn a_signature_hidden_in_the_unsigned_transaction_is_refused() {
        // **見せている取引と、署名の対象がずれる。**
        let (pst, key) = solo();
        let mut smuggled = pst.clone();
        smuggled.unsigned.inputs[0].signature = vec![0u8; SIGNATURE_LEN];
        let bytes = smuggled.encode();
        assert_eq!(Pst::decode(&bytes), Err(PstError::NotUnsigned { index: 0 }));
        let _ = key;
    }

    #[test]
    fn a_wrong_length_signature_is_refused() {
        let (mut pst, key) = solo();
        pst.sign_with(keyring(&[&key])).unwrap();
        pst.inputs_mut()[0].signature = Some(vec![0u8; 32]);
        assert_eq!(
            Pst::decode(&pst.encode()),
            Err(PstError::BadSignatureLength {
                index: 0,
                actual: 32,
                expected: SIGNATURE_LEN,
            })
        );
    }

    #[test]
    fn a_wrong_number_of_input_records_is_refused() {
        let (pst, _) = solo();
        let mut broken = pst.clone();
        broken.inputs.push(broken.inputs[0].clone());
        assert_eq!(
            Pst::decode(&broken.encode()),
            Err(PstError::CountMismatch {
                field: "inputs",
                declared: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let (pst, _) = solo();
        let mut bytes = pst.encode();
        bytes.push(0);
        assert!(matches!(
            Pst::decode(&bytes),
            Err(PstError::Codec(CodecError::TrailingBytes(1)))
        ));
    }

    #[test]
    fn any_byte_string_is_refused_without_panicking() {
        // 復号は相手が決めるバイト列を読む。どんな並びでも落ちてはならない。
        let (pst, _) = solo();
        let good = pst.encode();
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for round in 0..2_000 {
            let mut bytes = good.clone();
            for _ in 0..(1 + round % 7) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let at = (state as usize) % bytes.len();
                bytes[at] ^= (state >> 32) as u8;
            }
            if let Ok(decoded) = Pst::decode(&bytes) {
                assert_eq!(decoded.encode(), bytes, "復号できたのに元に戻らない");
            }
        }
    }
}
