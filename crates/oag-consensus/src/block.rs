//! ブロックとブロックヘッダ。
//!
//! 参照: `docs/SPEC.md` §9

use crate::codec::{write_varint, CodecError, Decode, Encode, Reader};
use crate::tx::Transaction;
use oag_primitives::{hash, merkle, Hash};

/// ブロックヘッダのシリアライズサイズ。固定長である。
pub const BLOCK_HEADER_LEN: usize = 100;

/// `version` のうち、補助 PoW (マージマイニング) の有無を示すビット。
///
/// v1 ではこのビットが立ったブロックは無効である。将来 Monero との
/// マージマイニングを導入する際に用いる (SPEC §9.5)。
pub const VERSION_BIT_AUX_POW: u32 = 0x0000_0001;

/// 現在のブロック形式のバージョン。
pub const CURRENT_BLOCK_VERSION: u32 = 0;

/// ブロックヘッダ。100 バイト固定。
///
/// `nonce` を末尾に置くことで、マイナーは末尾 8 バイトのみを書き換えて
/// 反復できる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    /// 形式のバージョンとフラグ。
    pub version: u32,
    /// 親ブロックのハッシュ。
    pub prev_hash: Hash,
    /// トランザクション列のマークルルート。
    pub merkle_root: Hash,
    /// Unix 秒。
    ///
    /// Bitcoin の `u32` は 2106 年に溢れる。本チェーンの発行完了は
    /// 2216 年頃であり、確実にこれを跨ぐため `i64` を用いる (SPEC §9.2)。
    pub timestamp: i64,
    /// このブロックの難易度。
    pub difficulty: u64,
    /// ブロック高さ。
    pub height: u64,
    /// マイニング用のノンス。
    pub nonce: u64,
}

impl BlockHeader {
    /// ブロックハッシュ。
    pub fn hash(&self) -> Hash {
        hash::block_hash(&self.encode())
    }

    /// 補助 PoW のビットが立っているか。v1 では常に無効。
    pub fn has_aux_pow(&self) -> bool {
        self.version & VERSION_BIT_AUX_POW != 0
    }
}

impl Encode for BlockHeader {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(self.prev_hash.as_bytes());
        out.extend_from_slice(self.merkle_root.as_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.difficulty.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
    }

    fn encoded_len(&self) -> usize {
        BLOCK_HEADER_LEN
    }
}

impl Decode for BlockHeader {
    fn read_from(reader: &mut Reader<'_>) -> Result<BlockHeader, CodecError> {
        Ok(BlockHeader {
            version: reader.read_u32()?,
            prev_hash: reader.read_hash()?,
            merkle_root: reader.read_hash()?,
            timestamp: reader.read_i64()?,
            difficulty: reader.read_u64()?,
            height: reader.read_u64()?,
            nonce: reader.read_u64()?,
        })
    }
}

/// ブロック。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// ヘッダ。
    pub header: BlockHeader,
    /// トランザクション。先頭は必ずコインベースである。
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// 含まれるトランザクションから計算したマークルルート。
    ///
    /// 空のブロックは存在しないため、その場合は `None` を返す。
    pub fn compute_merkle_root(&self) -> Option<Hash> {
        let txids: Vec<Hash> = self.transactions.iter().map(|t| t.txid()).collect();
        merkle::merkle_root(&txids)
    }

    /// ヘッダのマークルルートが本体と一致するか。
    pub fn merkle_root_is_valid(&self) -> bool {
        self.compute_merkle_root() == Some(self.header.merkle_root)
    }

    /// コインベーストランザクション。
    pub fn coinbase(&self) -> Option<&Transaction> {
        let first = self.transactions.first()?;
        first.is_coinbase().then_some(first)
    }

    /// シリアライズサイズ。
    pub fn size(&self) -> usize {
        self.encoded_len()
    }
}

impl Encode for Block {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.header.encode_into(out);
        write_varint(self.transactions.len() as u128, out);
        for tx in &self.transactions {
            tx.encode_into(out);
        }
    }
}

impl Decode for Block {
    fn read_from(reader: &mut Reader<'_>) -> Result<Block, CodecError> {
        let header = BlockHeader::read_from(reader)?;
        let count = reader.read_count("block.transactions")?;
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            transactions.push(Transaction::read_from(reader)?);
        }
        Ok(Block {
            header,
            transactions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::Lock;
    use crate::params::BLOCK_REWARD;
    use crate::tx::{encode_coinbase_signature, OutPoint, TxInput, TxOutput, CURRENT_TX_VERSION};
    use oag_primitives::{Amount, SecretKey};

    fn coinbase(height: u64) -> Transaction {
        let mut input = TxInput::new(OutPoint::null());
        input.signature = encode_coinbase_signature(height, b"orange");
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: vec![TxOutput::new(
                BLOCK_REWARD,
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            )],
            locktime: 0,
        }
    }

    /// SPEC §7.2 の基準トランザクション (1 入力 2 出力、195 バイト)。
    fn payment() -> Transaction {
        let mut input = TxInput::new(OutPoint::new(oag_primitives::hash::txid(b"prev"), 0));
        input.signature = vec![0x11; 64];
        let out = |a: &str| {
            TxOutput::new(
                a.parse().unwrap(),
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            )
        };
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: vec![out("15"), out("9.9990")],
            locktime: 0,
        }
    }

    fn block(height: u64, extra: usize) -> Block {
        let mut transactions = vec![coinbase(height)];
        transactions.extend((0..extra).map(|_| payment()));
        let txids: Vec<Hash> = transactions.iter().map(|t| t.txid()).collect();
        Block {
            header: BlockHeader {
                version: CURRENT_BLOCK_VERSION,
                prev_hash: oag_primitives::hash::block_hash(b"parent"),
                merkle_root: merkle::merkle_root(&txids).unwrap(),
                timestamp: 1_774_000_000,
                difficulty: 100_000,
                height,
                nonce: 42,
            },
            transactions,
        }
    }

    #[test]
    fn header_is_exactly_100_bytes() {
        // SPEC §9.1
        let header = block(1, 0).header;
        assert_eq!(header.encode().len(), BLOCK_HEADER_LEN);
        assert_eq!(header.encoded_len(), BLOCK_HEADER_LEN);
    }

    #[test]
    fn nonce_occupies_the_last_eight_bytes() {
        // マイナーが末尾 8 バイトのみを書き換えて反復できること。
        let mut header = block(1, 0).header;
        let before = header.encode();
        header.nonce = header.nonce.wrapping_add(1);
        let after = header.encode();
        assert_eq!(before[..92], after[..92], "先頭 92 バイトは不変");
        assert_ne!(before[92..], after[92..]);
    }

    #[test]
    fn header_round_trip() {
        let header = block(7, 0).header;
        assert_eq!(BlockHeader::decode(&header.encode()).unwrap(), header);
    }

    #[test]
    fn header_fields_all_affect_the_hash() {
        let base = block(1, 0).header;
        let original = base.hash();

        let mut h = base;
        h.version = 0x1000;
        assert_ne!(h.hash(), original);

        let mut h = base;
        h.prev_hash = Hash::ZERO;
        assert_ne!(h.hash(), original);

        let mut h = base;
        h.merkle_root = Hash::ZERO;
        assert_ne!(h.hash(), original);

        let mut h = base;
        h.timestamp += 1;
        assert_ne!(h.hash(), original);

        let mut h = base;
        h.difficulty += 1;
        assert_ne!(h.hash(), original);

        let mut h = base;
        h.height += 1;
        assert_ne!(h.hash(), original);

        let mut h = base;
        h.nonce += 1;
        assert_ne!(h.hash(), original);
    }

    #[test]
    fn timestamp_survives_year_2106() {
        // Bitcoin の u32 タイムスタンプが溢れる時点を越えられること (SPEC §9.2)。
        let mut header = block(1, 0).header;
        // 2216-01-01 頃 = 発行完了の見込み時期。
        header.timestamp = 7_766_000_000;
        assert!(header.timestamp > i64::from(u32::MAX));
        assert_eq!(
            BlockHeader::decode(&header.encode()).unwrap().timestamp,
            7_766_000_000
        );
    }

    #[test]
    fn timestamp_accepts_negative_values() {
        // i64 であること自体の確認 (ジェネシス以前を表現できる)。
        let mut header = block(1, 0).header;
        header.timestamp = -1;
        assert_eq!(BlockHeader::decode(&header.encode()).unwrap().timestamp, -1);
    }

    #[test]
    fn aux_pow_bit_is_reserved_and_off_by_default() {
        let header = block(1, 0).header;
        assert!(!header.has_aux_pow());
        let mut with_aux = header;
        with_aux.version |= VERSION_BIT_AUX_POW;
        assert!(with_aux.has_aux_pow());
    }

    #[test]
    fn block_round_trip() {
        let b = block(100, 5);
        assert_eq!(Block::decode(&b.encode()).unwrap(), b);
    }

    #[test]
    fn merkle_root_matches_body() {
        let b = block(100, 3);
        assert!(b.merkle_root_is_valid());

        let mut tampered = b.clone();
        tampered.transactions[1].outputs[0].amount = Amount::from_oag(2).unwrap();
        assert!(
            !tampered.merkle_root_is_valid(),
            "本体を書き換えたらマークルルートが合わなくなる"
        );

        let mut reordered = b;
        reordered.transactions.swap(1, 2);
        assert!(
            !reordered.merkle_root_is_valid(),
            "順序の入れ替えも検出する"
        );
    }

    #[test]
    fn coinbase_is_the_first_transaction() {
        let b = block(1, 2);
        assert!(b.coinbase().is_some());
        assert_eq!(b.coinbase().unwrap(), &b.transactions[0]);

        let mut without = b;
        without.transactions.remove(0);
        assert!(without.coinbase().is_none());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = block(1, 1).encode();
        bytes.push(0);
        assert_eq!(Block::decode(&bytes), Err(CodecError::TrailingBytes(1)));
    }

    #[test]
    fn rejects_absurd_transaction_count() {
        let mut bytes = block(1, 0).header.encode();
        write_varint(u128::from(u64::MAX), &mut bytes);
        assert!(matches!(
            Block::decode(&bytes),
            Err(CodecError::CountTooLarge { .. })
        ));
    }

    #[test]
    fn a_full_block_holds_about_1000_standard_transactions() {
        // SPEC §7.2 / 付録 B: 200,000 バイトに約 1,025 件。
        let max = crate::params::MAX_BLOCK_SIZE;
        let mut count = 0;
        let mut filled = block(1, 0);
        while filled.size() + payment().size() <= max {
            filled.transactions.push(payment());
            count += 1;
        }
        assert!(
            filled.size() <= max && filled.size() > max - 200,
            "実際には {} バイト",
            filled.size()
        );
        assert!(
            (1_000..=1_025).contains(&count),
            "収容できたのは {count} 件"
        );
    }
}
