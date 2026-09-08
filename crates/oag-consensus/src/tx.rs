//! トランザクション。
//!
//! 参照: `docs/SPEC.md` §7

use crate::codec::{write_varint, CodecError, Decode, Encode, Reader};
use crate::lock::Lock;
use oag_primitives::{hash, Amount, Hash};

/// 入力の署名フィールドの最大長。
///
/// 通常の入力は 64 バイト (既定 sighash) または 65 バイト。
/// コインベースはこのフィールドを高さと追加ノンスの領域として使う (SPEC §7.6)。
pub const MAX_INPUT_SIGNATURE_LEN: usize = 100;

/// コインベース入力が用いる `prev_index`。
pub const COINBASE_PREV_INDEX: u32 = 0xFFFF_FFFF;

/// 使用対象の出力を指す参照。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    /// 対象トランザクションの ID。
    pub txid: Hash,
    /// そのトランザクション内の出力番号。
    pub index: u32,
}

impl OutPoint {
    /// 新しい参照を作る。
    pub fn new(txid: Hash, index: u32) -> OutPoint {
        OutPoint { txid, index }
    }

    /// コインベースが用いる空の参照。
    pub fn null() -> OutPoint {
        OutPoint {
            txid: Hash::ZERO,
            index: COINBASE_PREV_INDEX,
        }
    }

    /// コインベースの空参照か。
    pub fn is_null(&self) -> bool {
        self.txid == Hash::ZERO && self.index == COINBASE_PREV_INDEX
    }
}

impl Encode for OutPoint {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.txid.as_bytes());
        write_varint(u128::from(self.index), out);
    }
}

impl Decode for OutPoint {
    fn read_from(reader: &mut Reader<'_>) -> Result<OutPoint, CodecError> {
        let txid = reader.read_hash()?;
        let index = reader.read_varint_u32("prev_index")?;
        Ok(OutPoint { txid, index })
    }
}

/// トランザクションの入力。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    /// 使用する出力への参照。
    pub prev_out: OutPoint,
    /// BIP340 署名 (64 または 65 バイト)。コインベースでは任意データ。
    pub signature: Vec<u8>,
    /// 相対 locktime の符号化 (SPEC §7.5)。
    pub sequence: u32,
}

/// 相対 locktime を無効にする `sequence` 値。
pub const SEQUENCE_FINAL: u32 = 0xFFFF_FFFF;

impl TxInput {
    /// 署名なしの入力を作る。署名は後から埋める。
    pub fn new(prev_out: OutPoint) -> TxInput {
        TxInput {
            prev_out,
            signature: Vec::new(),
            sequence: SEQUENCE_FINAL,
        }
    }

    /// 相対 locktime が有効か (SPEC §7.5)。
    pub fn has_relative_locktime(&self) -> bool {
        self.sequence & 0x8000_0000 == 0
    }
}

impl Encode for TxInput {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.prev_out.encode_into(out);
        write_varint(self.signature.len() as u128, out);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.sequence.to_le_bytes());
    }
}

impl Decode for TxInput {
    fn read_from(reader: &mut Reader<'_>) -> Result<TxInput, CodecError> {
        let prev_out = OutPoint::read_from(reader)?;
        let signature = reader
            .read_var_bytes("input.signature", MAX_INPUT_SIGNATURE_LEN)?
            .to_vec();
        let sequence = reader.read_u32()?;
        Ok(TxInput {
            prev_out,
            signature,
            sequence,
        })
    }
}

/// トランザクションの出力。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    /// 金額。
    pub amount: Amount,
    /// 支払い条件。
    pub lock: Lock,
}

impl TxOutput {
    /// 新しい出力を作る。
    pub fn new(amount: Amount, lock: Lock) -> TxOutput {
        TxOutput { amount, lock }
    }
}

impl Encode for TxOutput {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.amount.encode_into(out);
        self.lock.encode_into(out);
    }

    fn encoded_len(&self) -> usize {
        self.amount.encode().len() + self.lock.encoded_len()
    }
}

impl Decode for TxOutput {
    fn read_from(reader: &mut Reader<'_>) -> Result<TxOutput, CodecError> {
        let amount = reader.read_amount()?;
        let lock = Lock::read_from(reader)?;
        Ok(TxOutput { amount, lock })
    }
}

/// トランザクション。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// 形式のバージョン。
    pub version: u32,
    /// 入力。
    pub inputs: Vec<TxInput>,
    /// 出力。
    pub outputs: Vec<TxOutput>,
    /// 絶対 locktime (SPEC §7.4)。
    pub locktime: u64,
}

/// `locktime` をブロック高さと Unix 秒のどちらとして解釈するかの境界。
pub const LOCKTIME_THRESHOLD: u64 = 500_000_000;

/// 現在のトランザクション形式のバージョン。
pub const CURRENT_TX_VERSION: u32 = 1;

impl Transaction {
    /// トランザクション ID。
    ///
    /// BIP340 署名は固定長で厳密な符号化を持ち、本チェーンはスクリプトを
    /// 持たないため、**第三者が txid を書き換えることはできない**。
    /// この性質により SegWit 相当の機構なしに事前署名取引が成立する
    /// (SPEC §7.3, §17.2)。
    pub fn txid(&self) -> Hash {
        hash::txid(&self.encode())
    }

    /// コインベーストランザクションか。
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].prev_out.is_null()
    }

    /// `locktime` がブロック高さを表すか (偽なら Unix 秒)。
    pub fn locktime_is_height(&self) -> bool {
        self.locktime < LOCKTIME_THRESHOLD
    }

    /// 出力金額の合計。総発行量を超える場合は `None`。
    pub fn total_output(&self) -> Option<Amount> {
        Amount::sum(self.outputs.iter().map(|o| o.amount))
    }

    /// シリアライズサイズ。
    pub fn size(&self) -> usize {
        self.encoded_len()
    }
}

impl Encode for Transaction {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_le_bytes());
        write_varint(self.inputs.len() as u128, out);
        for input in &self.inputs {
            input.encode_into(out);
        }
        write_varint(self.outputs.len() as u128, out);
        for output in &self.outputs {
            output.encode_into(out);
        }
        write_varint(u128::from(self.locktime), out);
    }
}

impl Decode for Transaction {
    fn read_from(reader: &mut Reader<'_>) -> Result<Transaction, CodecError> {
        let version = reader.read_u32()?;

        let input_count = reader.read_count("tx.inputs")?;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            inputs.push(TxInput::read_from(reader)?);
        }

        let output_count = reader.read_count("tx.outputs")?;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(TxOutput::read_from(reader)?);
        }

        let locktime = reader.read_varint_u64("tx.locktime")?;

        Ok(Transaction {
            version,
            inputs,
            outputs,
            locktime,
        })
    }
}

/// コインベースの署名フィールドに高さを埋め込む。
///
/// 異なる高さのコインベースが同一の txid を持つことを防ぐ (SPEC §7.6)。
pub fn encode_coinbase_signature(height: u64, extra_nonce: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(u128::from(height), &mut out);
    out.extend_from_slice(extra_nonce);
    out
}

/// コインベースの署名フィールドから高さを取り出す。
pub fn decode_coinbase_height(signature: &[u8]) -> Result<u64, CodecError> {
    let mut reader = Reader::new(signature);
    reader.read_varint_u64("coinbase.height")
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_primitives::hash::HASH_LEN;
    use oag_primitives::{Network, SecretKey};

    fn lock() -> Lock {
        Lock::pay_to_pubkey(&SecretKey::generate().public_key())
    }

    fn tx_with(amounts: [&str; 2]) -> Transaction {
        let mut input = TxInput::new(OutPoint::new(hash::txid(b"prev"), 0));
        input.signature = vec![0xab; 64];
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: amounts
                .iter()
                .map(|a| TxOutput::new(a.parse().unwrap(), lock()))
                .collect(),
            locktime: 0,
        }
    }

    /// 仕様書の基準トランザクション。
    ///
    /// 1 入力 2 出力。金額は 9 バイトの varint になる範囲 (7.21〜721 OAG)。
    /// 容量と手数料の見積もりはこの大きさを基準とする。
    fn standard_tx() -> Transaction {
        tx_with(["15", "9.9990"])
    }

    /// 少額の送金。金額が 8 バイトの varint に収まる (7.21 OAG 未満)。
    fn small_payment_tx() -> Transaction {
        tx_with(["3", "1.9990"])
    }

    #[test]
    fn standard_transaction_is_195_bytes() {
        // SPEC §7.2 の基準トランザクション。
        let tx = standard_tx();
        assert_eq!(tx.size(), 195, "内訳: 入力 102 + 出力 43×2 + その他 7");
        assert_eq!(tx.inputs[0].encode().len(), 102, "入力 1 個");
        assert_eq!(tx.outputs[0].encode().len(), 43, "出力 1 個");
        // その他 = version 4 + 入力数 1 + 出力数 1 + locktime 1
        assert_eq!(tx.size() - 102 - 43 * 2, 7);
    }

    #[test]
    fn small_payments_are_two_bytes_smaller() {
        // 小数 16 桁のため、金額の varint 長は額に依存する。
        // 7.2058 OAG (= 2^56 atomic) 未満なら 8 バイト、以上なら 9 バイト。
        let tx = small_payment_tx();
        assert_eq!(tx.size(), 193);
        assert_eq!(tx.outputs[0].encode().len(), 42);
    }

    #[test]
    fn amount_varint_length_boundary_is_two_to_the_56() {
        let below = Amount::from_atomic((1u128 << 56) - 1).unwrap();
        let at = Amount::from_atomic(1u128 << 56).unwrap();
        assert_eq!(below.encode().len(), 8);
        assert_eq!(at.encode().len(), 9);
        // 境界は約 7.2058 OAG。
        assert!(at.to_string().starts_with("7.2057594"));
    }

    #[test]
    fn block_holds_about_1025_standard_transactions() {
        // SPEC §7.2 / 付録 B
        let count = crate::params::MAX_BLOCK_SIZE / standard_tx().size();
        assert_eq!(count, 1_025);
        // スループット 17 件/秒 前後
        let per_second = count as f64 / crate::params::TARGET_BLOCK_TIME_SECS as f64;
        assert!((17.0..17.5).contains(&per_second), "実際には {per_second}");
    }

    #[test]
    fn round_trip() {
        let tx = standard_tx();
        assert_eq!(Transaction::decode(&tx.encode()).unwrap(), tx);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = standard_tx().encode();
        bytes.push(0x00);
        assert_eq!(
            Transaction::decode(&bytes),
            Err(CodecError::TrailingBytes(1))
        );
    }

    #[test]
    fn rejects_every_truncation() {
        // どこで切っても復号は失敗しなければならない。
        let bytes = standard_tx().encode();
        for cut in 0..bytes.len() {
            assert!(
                Transaction::decode(&bytes[..cut]).is_err(),
                "{cut} バイトで切った入力が復号できてしまった"
            );
        }
        assert!(Transaction::decode(&bytes).is_ok());
    }

    #[test]
    fn rejects_absurd_input_count() {
        // 入力数だけ巨大に宣言し、本体は空。
        let mut bytes = CURRENT_TX_VERSION.to_le_bytes().to_vec();
        write_varint(u128::from(u64::MAX), &mut bytes);
        assert!(matches!(
            Transaction::decode(&bytes),
            Err(CodecError::CountTooLarge { .. })
        ));
    }

    #[test]
    fn txid_changes_with_every_field() {
        let base = standard_tx();
        let original = base.txid();

        let mut t = base.clone();
        t.version += 1;
        assert_ne!(t.txid(), original);

        let mut t = base.clone();
        t.locktime = 1;
        assert_ne!(t.txid(), original);

        let mut t = base.clone();
        t.inputs[0].sequence = 0;
        assert_ne!(t.txid(), original);

        let mut t = base.clone();
        t.inputs[0].signature[0] ^= 0xff;
        assert_ne!(t.txid(), original, "署名は txid に含まれる");

        let mut t = base.clone();
        t.outputs[0].amount = Amount::from_oag(4).unwrap();
        assert_ne!(t.txid(), original);

        let mut t = base;
        t.outputs.swap(0, 1);
        assert_ne!(t.txid(), original, "出力の順序も txid に含まれる");
    }

    #[test]
    fn coinbase_detection() {
        let mut coinbase = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput::new(OutPoint::null())],
            outputs: vec![TxOutput::new(crate::params::BLOCK_REWARD, lock())],
            locktime: 0,
        };
        coinbase.inputs[0].signature = encode_coinbase_signature(12_345, b"extra");
        assert!(coinbase.is_coinbase());
        assert_eq!(
            decode_coinbase_height(&coinbase.inputs[0].signature).unwrap(),
            12_345
        );

        assert!(!standard_tx().is_coinbase());
    }

    #[test]
    fn coinbase_height_makes_txid_unique_per_height() {
        let make = |height: u64| {
            let mut input = TxInput::new(OutPoint::null());
            input.signature = encode_coinbase_signature(height, b"");
            Transaction {
                version: CURRENT_TX_VERSION,
                inputs: vec![input],
                outputs: vec![TxOutput::new(crate::params::BLOCK_REWARD, lock())],
                locktime: 0,
            }
        };
        // 出力の鍵が同じなら、高さだけが txid を分ける。
        let a = make(100);
        let mut b = make(101);
        b.outputs = a.outputs.clone();
        assert_ne!(a.txid(), b.txid());
    }

    #[test]
    fn coinbase_signature_length_is_bounded() {
        let mut input = TxInput::new(OutPoint::null());
        input.signature = encode_coinbase_signature(1, &[0u8; 200]);
        let tx = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: vec![TxOutput::new(Amount::ONE_OAG, lock())],
            locktime: 0,
        };
        assert!(matches!(
            Transaction::decode(&tx.encode()),
            Err(CodecError::LengthTooLarge { max: 100, .. })
        ));
    }

    #[test]
    fn total_output_uses_checked_arithmetic() {
        let tx = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput::new(OutPoint::new(Hash::ZERO, 0))],
            outputs: vec![
                TxOutput::new(Amount::MAX, lock()),
                TxOutput::new(Amount::ONE_OAG, lock()),
            ],
            locktime: 0,
        };
        assert_eq!(tx.total_output(), None, "総発行量を超えたら None");
    }

    #[test]
    fn locktime_interpretation() {
        let mut tx = standard_tx();
        tx.locktime = 499_999_999;
        assert!(tx.locktime_is_height());
        tx.locktime = LOCKTIME_THRESHOLD;
        assert!(!tx.locktime_is_height());
    }

    #[test]
    fn relative_locktime_flag() {
        let mut input = TxInput::new(OutPoint::null());
        assert!(!input.has_relative_locktime(), "SEQUENCE_FINAL では無効");
        input.sequence = 10;
        assert!(input.has_relative_locktime());
    }

    #[test]
    fn outputs_are_addressable() {
        let sk = SecretKey::generate();
        let output = TxOutput::new(Amount::ONE_OAG, Lock::pay_to_pubkey(&sk.public_key()));
        let address = output.lock.to_address(Network::Mainnet).unwrap();
        assert!(address.to_string().starts_with("oag1q"));
        assert_eq!(Lock::from_address(&address), output.lock);
    }

    #[test]
    fn outpoint_null_is_only_for_coinbase() {
        assert!(OutPoint::null().is_null());
        assert!(!OutPoint::new(Hash::ZERO, 0).is_null());
        assert!(!OutPoint::new(hash::txid(b"x"), COINBASE_PREV_INDEX).is_null());
    }

    #[test]
    fn hash_len_constant_is_used() {
        assert_eq!(HASH_LEN, 32);
    }
}
