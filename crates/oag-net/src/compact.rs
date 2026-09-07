//! Compact Blocks。
//!
//! ブロックを丸ごと送らず、**相手がすでに持っているものは送らない**。
//!
//! ```text
//! 通常:   block      200,000 バイト
//! 圧縮:   cmpctblock   6,000 バイト程度
//!           ヘッダ 100 + 短縮ID 6 × 取引数 + コインベース
//! ```
//!
//! 受け取った側は mempool から短縮 ID の一致するものを拾い、足りない分だけ
//! `getblocktxn` で番号を指定して求める。
//!
//! # なぜ 60 秒ブロックで重要か
//!
//! 伝播に時間がかかるほど、同じ高さのブロックが並行して掘られる確率
//! (孤児率) が上がる。孤児率が高いと、接続の良い大規模なマイナーが有利に
//! なり中央集権化が進む。200,000 バイトを 60 秒間隔で撒く本チェーンでは、
//! これがないと孤児率が 2〜3 % に達する (`docs/SPEC.md` §7.2)。
//!
//! # 短縮 ID の衝突
//!
//! 短縮 ID は 6 バイトしかないため、mempool の中の無関係な取引と偶然
//! 一致しうる。その場合、組み立てたブロックは**間違ったものになる**。
//! 組み立ての最後に必ずマークルルートを検証し、合わなければ捨てて
//! 通常の `block` を求め直す。[`PartialBlock::into_block`] がこれを行う。
//!
//! 鍵はブロックごとに変わるため、攻撃者があらかじめ衝突する取引を用意して
//! 全ノードを一斉に妨害することはできない。

use oag_consensus::codec::{write_varint, CodecError, Decode, Encode, Reader};
use oag_consensus::{Block, BlockHeader, Transaction};
use oag_primitives::{merkle, Hash};
use std::collections::HashMap;

/// 短縮 ID の長さ。
pub const SHORT_ID_LEN: usize = 6;

/// 短縮した取引 ID。
pub type ShortId = [u8; SHORT_ID_LEN];

/// 1 ブロックに入りうる取引数の上限。
///
/// 最小の取引は約 50 バイトなので、200,000 バイトのブロックには
/// 4,000 件程度までしか入らない。余裕を見て 5,000 を上限とする。
pub const MAX_BLOCK_TRANSACTIONS: usize = 5_000;

/// Compact Blocks の失敗。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompactError {
    /// 取引数が上限を超えている。
    #[error("取引数 {actual} が上限 {max} を超えている")]
    TooManyTransactions {
        /// 実際の数。
        actual: usize,
        /// 上限。
        max: usize,
    },
    /// 先頭に埋め込まれた取引がない。コインベースは必ず埋め込む。
    #[error("コインベースが埋め込まれていない")]
    MissingCoinbase,
    /// 埋め込まれた取引の番号が範囲外、または並びが不正。
    #[error("埋め込み取引の番号が不正")]
    BadPrefilledIndex,
    /// 埋めようとした取引の数が求めた数と合わない。
    #[error("{expected} 件求めたが {given} 件が返された")]
    WrongFillCount {
        /// 求めた数。
        expected: usize,
        /// 返された数。
        given: usize,
    },
    /// まだ埋まっていない場所がある。
    #[error("取引が {0} 件不足している")]
    Incomplete(usize),
    /// 組み立てた結果がヘッダのマークルルートと一致しない。
    ///
    /// 短縮 ID の衝突か、相手が誤ったものを返している。
    #[error("組み立てた本体がマークルルートと一致しない")]
    MerkleMismatch,
}

/// 短縮 ID を作るための鍵。
///
/// ブロックごとに変わるため、攻撃者が衝突する取引をあらかじめ用意して
/// 全ノードを一斉に妨害することはできない。
pub fn short_id_key(header: &BlockHeader, nonce: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"OAG/cmpct/shortid");
    hasher.update(&header.encode());
    hasher.update(&nonce.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// 取引 ID を短縮する。
pub fn short_id(key: &[u8; 32], txid: &Hash) -> ShortId {
    let digest = blake3::keyed_hash(key, txid.as_bytes());
    let mut out = [0u8; SHORT_ID_LEN];
    out.copy_from_slice(&digest.as_bytes()[..SHORT_ID_LEN]);
    out
}

/// そのまま埋め込む取引。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefilledTx {
    /// ブロック内での位置。
    pub index: u32,
    /// 取引本体。
    pub tx: Transaction,
}

/// 圧縮したブロック。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactBlock {
    /// ブロックヘッダ。
    pub header: BlockHeader,
    /// 短縮 ID を作るための乱数。
    pub nonce: u64,
    /// 埋め込まなかった取引の短縮 ID。ブロック内の順に並ぶ。
    pub short_ids: Vec<ShortId>,
    /// そのまま埋め込んだ取引。番号の昇順に並ぶ。
    pub prefilled: Vec<PrefilledTx>,
}

impl CompactBlock {
    /// ブロックから作る。
    ///
    /// コインベースは相手が持っていないので必ず埋め込む。
    pub fn from_block(block: &Block, nonce: u64) -> Result<CompactBlock, CompactError> {
        let total = block.transactions.len();
        if total > MAX_BLOCK_TRANSACTIONS {
            return Err(CompactError::TooManyTransactions {
                actual: total,
                max: MAX_BLOCK_TRANSACTIONS,
            });
        }
        let Some(coinbase) = block.transactions.first() else {
            return Err(CompactError::MissingCoinbase);
        };

        let key = short_id_key(&block.header, nonce);
        let short_ids = block.transactions[1..]
            .iter()
            .map(|tx| short_id(&key, &tx.txid()))
            .collect();

        Ok(CompactBlock {
            header: block.header,
            nonce,
            short_ids,
            prefilled: vec![PrefilledTx {
                index: 0,
                tx: coinbase.clone(),
            }],
        })
    }

    /// ブロックに含まれる取引の総数。
    pub fn transaction_count(&self) -> usize {
        self.short_ids.len() + self.prefilled.len()
    }

    /// この圧縮ブロックの短縮 ID の鍵。
    pub fn key(&self) -> [u8; 32] {
        short_id_key(&self.header, self.nonce)
    }

    /// 手元の取引から組み立てを試みる。
    ///
    /// `lookup` は短縮 ID に対応する取引を返す。mempool を引く想定である。
    pub fn reconstruct<F>(&self, lookup: F) -> Result<PartialBlock, CompactError>
    where
        F: Fn(&ShortId) -> Option<Transaction>,
    {
        let total = self.transaction_count();
        if total > MAX_BLOCK_TRANSACTIONS {
            return Err(CompactError::TooManyTransactions {
                actual: total,
                max: MAX_BLOCK_TRANSACTIONS,
            });
        }

        let mut slots: Vec<Option<Transaction>> = vec![None; total];

        // 埋め込まれた取引を置く。
        let mut prefilled_positions = Vec::with_capacity(self.prefilled.len());
        for entry in &self.prefilled {
            let index =
                usize::try_from(entry.index).map_err(|_| CompactError::BadPrefilledIndex)?;
            if index >= total || slots[index].is_some() {
                return Err(CompactError::BadPrefilledIndex);
            }
            slots[index] = Some(entry.tx.clone());
            prefilled_positions.push(index);
        }
        if !prefilled_positions.contains(&0) {
            return Err(CompactError::MissingCoinbase);
        }

        // 残りを短縮 ID で埋める。
        let mut short_iter = self.short_ids.iter();
        let mut missing = Vec::new();
        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.is_some() {
                continue;
            }
            let Some(id) = short_iter.next() else {
                return Err(CompactError::BadPrefilledIndex);
            };
            match lookup(id) {
                Some(tx) => *slot = Some(tx),
                None => missing.push(index as u32),
            }
        }

        Ok(PartialBlock {
            header: self.header,
            slots,
            missing,
        })
    }
}

/// 組み立て途中のブロック。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialBlock {
    header: BlockHeader,
    slots: Vec<Option<Transaction>>,
    missing: Vec<u32>,
}

impl PartialBlock {
    /// 足りない取引の番号。`getblocktxn` で求める。
    pub fn missing_indices(&self) -> &[u32] {
        &self.missing
    }

    /// すべてそろっているか。
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }

    /// 求めた取引を受け取って埋める。
    ///
    /// 数が合わなければ誤りとする。
    pub fn fill(&mut self, transactions: Vec<Transaction>) -> Result<(), CompactError> {
        if transactions.len() != self.missing.len() {
            return Err(CompactError::WrongFillCount {
                expected: self.missing.len(),
                given: transactions.len(),
            });
        }
        for (index, tx) in self.missing.drain(..).zip(transactions) {
            self.slots[index as usize] = Some(tx);
        }
        Ok(())
    }

    /// ブロックに仕上げる。
    ///
    /// **マークルルートを検証する。** 短縮 ID の衝突や、相手が誤った取引を
    /// 返した場合はここで捕まる。捕まったら通常の `block` を求め直す。
    pub fn into_block(self) -> Result<Block, CompactError> {
        if !self.missing.is_empty() {
            return Err(CompactError::Incomplete(self.missing.len()));
        }
        let mut transactions = Vec::with_capacity(self.slots.len());
        for slot in self.slots {
            transactions.push(slot.ok_or(CompactError::Incomplete(1))?);
        }

        let txids: Vec<Hash> = transactions.iter().map(|tx| tx.txid()).collect();
        if merkle::merkle_root(&txids) != Some(self.header.merkle_root) {
            return Err(CompactError::MerkleMismatch);
        }

        Ok(Block {
            header: self.header,
            transactions,
        })
    }
}

/// 短縮 ID から取引を引くための索引。mempool から作る。
#[derive(Debug, Default)]
pub struct ShortIdIndex {
    map: HashMap<ShortId, Transaction>,
}

impl ShortIdIndex {
    /// 取引の集まりから、この圧縮ブロック用の索引を作る。
    ///
    /// 短縮 ID が衝突した場合は先に入れた方を残す。どちらが正しいかは
    /// マークルルートの検証で分かる。
    pub fn build<'a, I>(key: &[u8; 32], transactions: I) -> ShortIdIndex
    where
        I: IntoIterator<Item = &'a Transaction>,
    {
        let mut map = HashMap::new();
        for tx in transactions {
            map.entry(short_id(key, &tx.txid()))
                .or_insert_with(|| tx.clone());
        }
        ShortIdIndex { map }
    }

    /// 引く。
    pub fn get(&self, id: &ShortId) -> Option<Transaction> {
        self.map.get(id).cloned()
    }

    /// 保持している件数。
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ━━━━━━━━ シリアライズ ━━━━━━━━

impl Encode for CompactBlock {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.header.encode_into(out);
        out.extend_from_slice(&self.nonce.to_le_bytes());

        write_varint(self.short_ids.len() as u128, out);
        for id in &self.short_ids {
            out.extend_from_slice(id);
        }

        write_varint(self.prefilled.len() as u128, out);
        // 番号は差分で書く。昇順に並んでいることを前提とする。
        let mut previous: i64 = -1;
        for entry in &self.prefilled {
            let diff = i64::from(entry.index) - previous - 1;
            write_varint(diff.max(0) as u128, out);
            previous = i64::from(entry.index);
            entry.tx.encode_into(out);
        }
    }
}

impl Decode for CompactBlock {
    fn read_from(reader: &mut Reader<'_>) -> Result<CompactBlock, CodecError> {
        let header = BlockHeader::read_from(reader)?;
        let nonce = reader.read_u64()?;

        let short_count = reader.read_count("cmpct.short_ids")?;
        if short_count > MAX_BLOCK_TRANSACTIONS {
            return Err(CodecError::LengthTooLarge {
                field: "cmpct.short_ids",
                actual: short_count as u128,
                max: MAX_BLOCK_TRANSACTIONS,
            });
        }
        let mut short_ids = Vec::with_capacity(short_count);
        for _ in 0..short_count {
            short_ids.push(reader.read_array::<SHORT_ID_LEN>()?);
        }

        let prefilled_count = reader.read_count("cmpct.prefilled")?;
        if prefilled_count > MAX_BLOCK_TRANSACTIONS {
            return Err(CodecError::LengthTooLarge {
                field: "cmpct.prefilled",
                actual: prefilled_count as u128,
                max: MAX_BLOCK_TRANSACTIONS,
            });
        }
        let mut prefilled = Vec::with_capacity(prefilled_count);
        let mut previous: i64 = -1;
        for _ in 0..prefilled_count {
            let diff = reader.read_varint_u32("cmpct.prefilled.index")?;
            let index = previous
                .checked_add(i64::from(diff))
                .and_then(|v| v.checked_add(1))
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(CodecError::ValueOutOfRange {
                    field: "cmpct.prefilled.index",
                    value: u128::from(diff),
                })?;
            previous = i64::from(index);
            prefilled.push(PrefilledTx {
                index,
                tx: Transaction::read_from(reader)?,
            });
        }

        Ok(CompactBlock {
            header,
            nonce,
            short_ids,
            prefilled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_consensus::lock::Lock;
    use oag_consensus::params;
    use oag_consensus::tx::{
        encode_coinbase_signature, OutPoint, TxInput, TxOutput, CURRENT_TX_VERSION,
    };
    use oag_primitives::{hash, Amount, SecretKey};

    fn coinbase(height: u64) -> Transaction {
        let mut input = TxInput::new(OutPoint::null());
        input.signature = encode_coinbase_signature(height, b"orange");
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: vec![TxOutput::new(
                params::BLOCK_REWARD,
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            )],
            locktime: 0,
        }
    }

    fn payment(seed: u64) -> Transaction {
        let mut input = TxInput::new(OutPoint::new(hash::txid(&seed.to_le_bytes()), 0));
        input.signature = vec![0xab; 64];
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: vec![TxOutput::new(
                Amount::from_oag(1).unwrap(),
                Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            )],
            locktime: 0,
        }
    }

    /// コインベース + `count` 件の送金からなるブロック。
    fn block_with(count: u64) -> Block {
        let mut transactions = vec![coinbase(100)];
        transactions.extend((0..count).map(payment));
        let txids: Vec<Hash> = transactions.iter().map(|t| t.txid()).collect();
        Block {
            header: BlockHeader {
                version: 0,
                prev_hash: hash::block_hash(b"parent"),
                merkle_root: merkle::merkle_root(&txids).unwrap(),
                timestamp: 1_800_000_000,
                difficulty: 1_000,
                height: 100,
                nonce: 7,
            },
            transactions,
        }
    }

    #[test]
    fn a_compact_block_is_far_smaller_than_the_block() {
        // 満杯に近いブロックで、実際にどれだけ縮むかを測る。
        let block = block_with(1_000);
        let compact = CompactBlock::from_block(&block, 42).unwrap();
        let full = block.encode().len();
        let small = compact.encode().len();

        assert!(
            small * 20 < full,
            "圧縮が効いていない: {full} → {small} バイト"
        );
        // 内訳はヘッダ 100 + 短縮ID 6×1000 + コインベース + わずかな枠。
        assert!((6_000..8_000).contains(&small), "実際には {small} バイト");
    }

    #[test]
    fn the_coinbase_is_always_prefilled() {
        let block = block_with(5);
        let compact = CompactBlock::from_block(&block, 1).unwrap();
        assert_eq!(compact.prefilled.len(), 1);
        assert_eq!(compact.prefilled[0].index, 0);
        assert_eq!(compact.prefilled[0].tx, block.transactions[0]);
        assert_eq!(compact.short_ids.len(), 5);
        assert_eq!(compact.transaction_count(), 6);
    }

    #[test]
    fn it_round_trips_through_serialization() {
        let block = block_with(20);
        let compact = CompactBlock::from_block(&block, 0xDEAD_BEEF).unwrap();
        assert_eq!(CompactBlock::decode(&compact.encode()).unwrap(), compact);
    }

    #[test]
    fn a_peer_with_everything_reconstructs_immediately() {
        let block = block_with(10);
        let compact = CompactBlock::from_block(&block, 5).unwrap();

        // 受け手の mempool にはブロック内の送金がすべて入っている。
        let index = ShortIdIndex::build(&compact.key(), &block.transactions[1..]);
        let partial = compact.reconstruct(|id| index.get(id)).unwrap();

        assert!(partial.is_complete(), "何も足りないはずがない");
        assert_eq!(partial.into_block().unwrap(), block);
    }

    #[test]
    fn missing_transactions_are_reported_by_index() {
        let block = block_with(10);
        let compact = CompactBlock::from_block(&block, 5).unwrap();

        // 3 番目と 7 番目だけ持っていない。
        let held: Vec<&Transaction> = block.transactions[1..]
            .iter()
            .enumerate()
            .filter(|(i, _)| *i + 1 != 3 && *i + 1 != 7)
            .map(|(_, tx)| tx)
            .collect();
        let index = ShortIdIndex::build(&compact.key(), held);

        let mut partial = compact.reconstruct(|id| index.get(id)).unwrap();
        assert_eq!(partial.missing_indices(), &[3, 7]);
        assert!(!partial.is_complete());

        // 求めた順に返してもらって埋める。
        partial
            .fill(vec![
                block.transactions[3].clone(),
                block.transactions[7].clone(),
            ])
            .unwrap();
        assert!(partial.is_complete());
        assert_eq!(partial.into_block().unwrap(), block);
    }

    #[test]
    fn an_empty_mempool_needs_everything_but_the_coinbase() {
        let block = block_with(4);
        let compact = CompactBlock::from_block(&block, 1).unwrap();
        let partial = compact.reconstruct(|_| None).unwrap();
        assert_eq!(partial.missing_indices(), &[1, 2, 3, 4]);
    }

    #[test]
    fn an_incomplete_block_cannot_be_finished() {
        let block = block_with(3);
        let compact = CompactBlock::from_block(&block, 1).unwrap();
        let partial = compact.reconstruct(|_| None).unwrap();
        assert_eq!(partial.into_block(), Err(CompactError::Incomplete(3)));
    }

    #[test]
    fn filling_with_the_wrong_count_is_refused() {
        let block = block_with(3);
        let compact = CompactBlock::from_block(&block, 1).unwrap();
        let mut partial = compact.reconstruct(|_| None).unwrap();
        assert_eq!(
            partial.fill(vec![block.transactions[1].clone()]),
            Err(CompactError::WrongFillCount {
                expected: 3,
                given: 1
            })
        );
    }

    // ━━━━━━━━ 短縮 ID の衝突 ━━━━━━━━

    #[test]
    fn a_wrong_transaction_is_caught_by_the_merkle_root() {
        // 短縮 ID が衝突して別の取引を拾ってしまった状況を作る。
        // 組み立ては通るが、マークルルートが合わないので捕まる。
        let block = block_with(5);
        let compact = CompactBlock::from_block(&block, 1).unwrap();
        let key = compact.key();

        let impostor = payment(9_999);
        let lookup = |id: &ShortId| {
            // 2 番目の取引の位置に、まったく別の取引を返す。
            if *id == short_id(&key, &block.transactions[2].txid()) {
                Some(impostor.clone())
            } else {
                block.transactions[1..]
                    .iter()
                    .find(|tx| short_id(&key, &tx.txid()) == *id)
                    .cloned()
            }
        };

        let partial = compact.reconstruct(lookup).unwrap();
        assert!(partial.is_complete(), "すべての場所が埋まってはいる");
        assert_eq!(
            partial.into_block(),
            Err(CompactError::MerkleMismatch),
            "誤った取引で組み立てたブロックが通ってしまった"
        );
    }

    #[test]
    fn a_wrong_fill_is_caught_by_the_merkle_root() {
        let block = block_with(4);
        let compact = CompactBlock::from_block(&block, 1).unwrap();
        let mut partial = compact.reconstruct(|_| None).unwrap();

        // 求めたものと違う取引を返してくる相手。
        let wrong: Vec<Transaction> = (0..4).map(|i| payment(1_000 + i)).collect();
        partial.fill(wrong).unwrap();
        assert_eq!(partial.into_block(), Err(CompactError::MerkleMismatch));
    }

    // ━━━━━━━━ 鍵 ━━━━━━━━

    #[test]
    fn the_key_changes_with_the_nonce() {
        let block = block_with(1);
        let a = CompactBlock::from_block(&block, 1).unwrap();
        let b = CompactBlock::from_block(&block, 2).unwrap();
        assert_ne!(a.key(), b.key());
        assert_ne!(
            a.short_ids, b.short_ids,
            "乱数を変えても短縮 ID が変わらない"
        );
    }

    #[test]
    fn the_key_changes_with_the_header() {
        let mut block = block_with(1);
        let a = CompactBlock::from_block(&block, 1).unwrap();
        block.header.nonce += 1;
        let b = CompactBlock::from_block(&block, 1).unwrap();
        assert_ne!(a.key(), b.key());
    }

    #[test]
    fn short_ids_are_stable_for_the_same_inputs() {
        let block = block_with(3);
        let a = CompactBlock::from_block(&block, 77).unwrap();
        let b = CompactBlock::from_block(&block, 77).unwrap();
        assert_eq!(a.short_ids, b.short_ids);
    }

    #[test]
    fn distinct_transactions_get_distinct_short_ids() {
        let key = [0x11u8; 32];
        let mut seen = std::collections::HashSet::new();
        for i in 0..10_000u64 {
            let id = short_id(&key, &hash::txid(&i.to_le_bytes()));
            assert!(seen.insert(id), "1 万件で衝突した ({i} 件目)");
        }
    }

    // ━━━━━━━━ 不正な入力 ━━━━━━━━

    #[test]
    fn a_compact_block_without_a_coinbase_is_refused() {
        let block = block_with(3);
        let mut compact = CompactBlock::from_block(&block, 1).unwrap();
        // コインベースの位置をずらす。
        compact.prefilled[0].index = 2;
        assert_eq!(
            compact.reconstruct(|_| None),
            Err(CompactError::MissingCoinbase)
        );
    }

    #[test]
    fn an_out_of_range_prefilled_index_is_refused() {
        let block = block_with(3);
        let mut compact = CompactBlock::from_block(&block, 1).unwrap();
        compact.prefilled.push(PrefilledTx {
            index: 99,
            tx: payment(1),
        });
        assert_eq!(
            compact.reconstruct(|_| None),
            Err(CompactError::BadPrefilledIndex)
        );
    }

    #[test]
    fn a_duplicate_prefilled_index_is_refused() {
        let block = block_with(3);
        let mut compact = CompactBlock::from_block(&block, 1).unwrap();
        compact.prefilled.push(PrefilledTx {
            index: 0,
            tx: payment(1),
        });
        assert_eq!(
            compact.reconstruct(|_| None),
            Err(CompactError::BadPrefilledIndex)
        );
    }

    #[test]
    fn too_many_transactions_are_refused() {
        let block = block_with(3);
        let mut compact = CompactBlock::from_block(&block, 1).unwrap();
        compact.short_ids = vec![[0u8; SHORT_ID_LEN]; MAX_BLOCK_TRANSACTIONS + 1];
        assert!(matches!(
            compact.reconstruct(|_| None),
            Err(CompactError::TooManyTransactions { .. })
        ));
    }

    #[test]
    fn the_index_keeps_the_first_of_two_colliding_transactions() {
        let key = [0x22u8; 32];
        let a = payment(1);
        let b = payment(2);
        let index = ShortIdIndex::build(&key, [&a, &b]);
        assert_eq!(index.len(), 2, "衝突していない前提が崩れている");
        assert!(!index.is_empty());
        assert_eq!(index.get(&short_id(&key, &a.txid())), Some(a));
    }
}
