//! ブロックテンプレートの組み立て。
//!
//! コインベースを作り、mempool から取引を詰めて、採掘できる形にする。
//!
//! # コインベースの大きさが先に決まらない問題
//!
//! コインベースが受け取る額は手数料の合計に依存し、手数料の合計は詰めた
//! 取引に依存し、詰められる量はコインベースの大きさに依存する。循環する。
//!
//! 素直に解くために、**コインベースのために一定の領域を先に取り置く**。
//! 取り置いた分は詰め物に使われないだけで、あふれることはない。

use oag_consensus::codec::Encode;
use oag_consensus::lock::Lock;
use oag_consensus::params;
use oag_consensus::tx::{encode_coinbase_signature, OutPoint, TxInput, CURRENT_TX_VERSION};
use oag_consensus::{Block, BlockHeader, Transaction, TxOutput};
use oag_mempool::Mempool;
use oag_primitives::{merkle, Amount, Hash};

/// コインベースのために取り置く領域。
///
/// コインベースは入力 1 個 (高さ + 追加ノンス、最大 100 バイト) と出力
/// 1 個で、通常 200 バイト未満に収まる。余裕をもって取っておく。
pub const COINBASE_RESERVE: usize = 1_000;

/// テンプレート組み立ての失敗。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TemplateError {
    /// 金額の合計が総発行量を超えた。
    #[error("金額の合計が総発行量を超えている")]
    AmountOverflow,
    /// 追加ノンスが長すぎる。
    #[error("追加ノンスの長さ {actual} が上限 {max} を超えている")]
    ExtraNonceTooLong {
        /// 実際の長さ。
        actual: usize,
        /// 上限。
        max: usize,
    },
    /// 組み立てた結果が上限を超えた。
    #[error("ブロックサイズ {actual} が上限 {max} を超えている")]
    BlockTooLarge {
        /// 実際のサイズ。
        actual: usize,
        /// 上限。
        max: usize,
    },
}

/// 採掘する土台。
///
/// [`BlockTemplate::header`] の `nonce` を変えながら [`BlockTemplate::hash_input`]
/// を計算し、難易度を満たすものを探す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTemplate {
    /// ヘッダ。`nonce` 以外は確定している。
    pub header: BlockHeader,
    /// コインベースを先頭とする取引の列。
    pub transactions: Vec<Transaction>,
    /// 詰めた取引の手数料の合計。
    pub total_fees: Amount,
}

impl BlockTemplate {
    /// 現在の `nonce` に対する、PoW ハッシュの入力。
    pub fn hash_input(&self) -> Vec<u8> {
        self.header.encode()
    }

    /// ブロックに仕上げる。
    pub fn into_block(self) -> Block {
        Block {
            header: self.header,
            transactions: self.transactions,
        }
    }

    /// 現在の内容でのブロックの大きさ。
    pub fn size(&self) -> usize {
        Block {
            header: self.header,
            transactions: self.transactions.clone(),
        }
        .size()
    }
}

/// テンプレートを組み立てるための入力。
#[derive(Debug, Clone)]
pub struct TemplateRequest {
    /// 親ブロックのハッシュ。
    pub prev_hash: Hash,
    /// このブロックの高さ。
    pub height: u64,
    /// 難易度調整が定めた難易度。
    pub difficulty: u64,
    /// ブロックのタイムスタンプ。
    pub timestamp: i64,
    /// 報酬の受取先。
    pub payout: Lock,
    /// コインベースに入れる追加のバイト列。
    ///
    /// nonce の 2^64 通りを使い切ったときは、ここを変えるとコインベースの
    /// txid が変わり、マークルルートが変わり、探索空間がまるごと新しくなる。
    pub extra_nonce: Vec<u8>,
}

/// テンプレートを組み立てる。
///
/// mempool から料率の高い順に、依存関係を守って詰める。
pub fn build_template(
    request: &TemplateRequest,
    mempool: &Mempool,
) -> Result<BlockTemplate, TemplateError> {
    // コインベースの入力に入れられる長さの上限を守る。
    let signature = encode_coinbase_signature(request.height, &request.extra_nonce);
    if signature.len() > oag_consensus::tx::MAX_INPUT_SIGNATURE_LEN {
        return Err(TemplateError::ExtraNonceTooLong {
            actual: signature.len(),
            max: oag_consensus::tx::MAX_INPUT_SIGNATURE_LEN,
        });
    }

    // 取引に使える領域。コインベースの分を先に取り置く。
    let available = params::MAX_BLOCK_SIZE
        .saturating_sub(oag_consensus::block::BLOCK_HEADER_LEN)
        .saturating_sub(COINBASE_RESERVE);

    let selected = mempool.select_for_block(available);
    let total_fees = selected
        .iter()
        .filter_map(|tx| mempool.get(&tx.txid()).map(|e| e.fee))
        .try_fold(Amount::ZERO, |acc, fee| acc.checked_add(fee))
        .ok_or(TemplateError::AmountOverflow)?;

    let reward = params::block_subsidy(request.height)
        .checked_add(total_fees)
        .ok_or(TemplateError::AmountOverflow)?;

    let mut coinbase_input = TxInput::new(OutPoint::null());
    coinbase_input.signature = signature;
    let coinbase = Transaction {
        version: CURRENT_TX_VERSION,
        inputs: vec![coinbase_input],
        outputs: vec![TxOutput::new(reward, request.payout.clone())],
        locktime: 0,
    };

    let mut transactions = Vec::with_capacity(selected.len() + 1);
    transactions.push(coinbase);
    transactions.extend(selected);

    let txids: Vec<Hash> = transactions.iter().map(|tx| tx.txid()).collect();
    let merkle_root = merkle::merkle_root(&txids).expect("コインベースが必ずある");

    let template = BlockTemplate {
        header: BlockHeader {
            version: oag_consensus::block::CURRENT_BLOCK_VERSION,
            prev_hash: request.prev_hash,
            merkle_root,
            timestamp: request.timestamp,
            difficulty: request.difficulty,
            height: request.height,
            nonce: 0,
        },
        transactions,
        total_fees,
    };

    let size = template.size();
    if size > params::MAX_BLOCK_SIZE {
        return Err(TemplateError::BlockTooLarge {
            actual: size,
            max: params::MAX_BLOCK_SIZE,
        });
    }
    Ok(template)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_consensus::sighash::{sighash, SighashType};
    use oag_consensus::tx::{TxInput as Input, MAX_INPUT_SIGNATURE_LEN};
    use oag_consensus::utxo::{UtxoEntry, UtxoSet};
    use oag_consensus::validate::{validate_block, AcceptAnyPow, BlockContext, HeaderContext};
    use oag_primitives::{hash, Network, SecretKey};

    const HEIGHT: u64 = 500;
    const MTP: i64 = 1_800_000_000;
    const NOW: i64 = MTP + 3_600;
    const DIFFICULTY: u64 = 1_000;

    fn lock() -> Lock {
        Lock::pay_to_pubkey(&SecretKey::generate().public_key())
    }

    struct Funds {
        outpoint: OutPoint,
        output: TxOutput,
        key: SecretKey,
    }

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

    fn spend(funds: &Funds, fee: &str) -> Transaction {
        let fee: Amount = fee.parse().unwrap();
        let out = funds.output.amount.checked_sub(fee).unwrap();
        let mut tx = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![Input::new(funds.outpoint)],
            outputs: vec![TxOutput::new(out, lock())],
            locktime: 0,
        };
        let spent = [funds.output.clone()];
        let msg = sighash(&tx, &spent, 0, SighashType::DEFAULT).unwrap();
        tx.inputs[0].signature = funds.key.sign(&msg).to_bytes().to_vec();
        tx
    }

    fn request() -> TemplateRequest {
        TemplateRequest {
            prev_hash: hash::block_hash(b"parent"),
            height: HEIGHT,
            difficulty: DIFFICULTY,
            timestamp: NOW,
            payout: lock(),
            extra_nonce: b"orange".to_vec(),
        }
    }

    #[test]
    fn an_empty_mempool_gives_a_coinbase_only_block() {
        let template = build_template(&request(), &Mempool::new()).unwrap();
        assert_eq!(template.transactions.len(), 1);
        assert!(template.transactions[0].is_coinbase());
        assert_eq!(template.total_fees, Amount::ZERO);
        assert_eq!(
            template.transactions[0].outputs[0].amount,
            params::block_subsidy(HEIGHT)
        );
    }

    #[test]
    fn the_coinbase_claims_exactly_the_subsidy_plus_fees() {
        let mut utxo = UtxoSet::new();
        let mut mempool = Mempool::new();
        let mut expected = Amount::ZERO;
        for i in 0..5u8 {
            let funds = fund(&mut utxo, "10", &[i]);
            let fee = format!("0.0{}", i + 1);
            mempool
                .accept(spend(&funds, &fee), &utxo, HEIGHT, MTP)
                .unwrap();
            expected = expected.checked_add(fee.parse().unwrap()).unwrap();
        }

        let template = build_template(&request(), &mempool).unwrap();
        assert_eq!(template.transactions.len(), 6);
        assert_eq!(template.total_fees, expected);
        assert_eq!(
            template.transactions[0].outputs[0].amount,
            params::block_subsidy(HEIGHT).checked_add(expected).unwrap(),
            "コインベースの受取額が報酬 + 手数料と一致しない"
        );
    }

    #[test]
    fn the_template_passes_consensus_validation() {
        // 組み立てたブロックが、そのまま検証を通ること。
        // ここが通らなければ、掘っても無駄になる。
        let mut utxo = UtxoSet::new();
        let mut mempool = Mempool::new();
        for i in 0..4u8 {
            let funds = fund(&mut utxo, "10", &[i, 0xaa]);
            mempool
                .accept(spend(&funds, "0.05"), &utxo, HEIGHT, MTP)
                .unwrap();
        }

        let template = build_template(&request(), &mempool).unwrap();
        let block = template.into_block();

        let ctx = BlockContext {
            header: HeaderContext {
                expected_height: HEIGHT,
                expected_prev_hash: hash::block_hash(b"parent"),
                median_time_past: MTP,
                expected_difficulty: DIFFICULTY,
                now: NOW,
            },
            utxo: &utxo,
        };
        let summary = validate_block(&block, &ctx, &AcceptAnyPow)
            .expect("組み立てたブロックが検証を通らない");
        assert_eq!(summary.total_fees.to_string(), "0.2");
    }

    #[test]
    fn the_coinbase_records_the_height() {
        let template = build_template(&request(), &Mempool::new()).unwrap();
        let signature = &template.transactions[0].inputs[0].signature;
        assert_eq!(
            oag_consensus::tx::decode_coinbase_height(signature).unwrap(),
            HEIGHT
        );
    }

    #[test]
    fn the_merkle_root_matches_the_body() {
        let template = build_template(&request(), &Mempool::new()).unwrap();
        assert!(template.clone().into_block().merkle_root_is_valid());
    }

    #[test]
    fn the_extra_nonce_opens_a_new_search_space() {
        // nonce の 2^64 通りを使い切ったときの逃げ道。
        let mut a = request();
        a.extra_nonce = b"aaaa".to_vec();
        let mut b = request();
        b.extra_nonce = b"bbbb".to_vec();

        let ta = build_template(&a, &Mempool::new()).unwrap();
        let tb = build_template(&b, &Mempool::new()).unwrap();

        assert_ne!(
            ta.header.merkle_root, tb.header.merkle_root,
            "追加ノンスを変えてもマークルルートが変わらない"
        );
        assert_ne!(ta.hash_input(), tb.hash_input());
    }

    #[test]
    fn an_overlong_extra_nonce_is_refused() {
        let mut req = request();
        req.extra_nonce = vec![0u8; MAX_INPUT_SIGNATURE_LEN];
        assert!(matches!(
            build_template(&req, &Mempool::new()),
            Err(TemplateError::ExtraNonceTooLong { max, .. }) if max == MAX_INPUT_SIGNATURE_LEN
        ));
    }

    #[test]
    fn the_template_stays_within_the_block_size_limit() {
        // 上限が実際に効く数を入れる。
        // 使える領域は 200,000 − ヘッダ 100 − 取り置き 1,000 = 198,900 バイト。
        // 1 件約 152 バイトなので 1,300 件強で埋まる。
        let mut utxo = UtxoSet::new();
        let mut mempool = Mempool::new();
        for i in 0..1_600u32 {
            let funds = fund(&mut utxo, "10", &i.to_le_bytes());
            mempool
                .accept(spend(&funds, "0.01"), &utxo, HEIGHT, MTP)
                .unwrap();
        }
        assert_eq!(mempool.len(), 1_600, "試験の前提が崩れている");

        let template = build_template(&request(), &mempool).unwrap();
        assert!(
            template.size() <= params::MAX_BLOCK_SIZE,
            "実際には {} バイト",
            template.size()
        );
        // 取り置いた分を除いてほぼ埋まっていること。1 件分の隙間しか残らない。
        let one_more = template.transactions[1].size();
        assert!(
            template.size() + one_more > params::MAX_BLOCK_SIZE - COINBASE_RESERVE,
            "詰め込みが緩すぎる: {} バイト",
            template.size()
        );
        assert!(
            template.transactions.len() < mempool.len(),
            "全部入ってしまっている。上限が効いていない ({} 件)",
            template.transactions.len()
        );
    }

    #[test]
    fn the_payout_goes_where_it_is_told() {
        let payout = lock();
        let mut req = request();
        req.payout = payout.clone();
        let template = build_template(&req, &Mempool::new()).unwrap();
        assert_eq!(template.transactions[0].outputs[0].lock, payout);
        assert!(payout.to_address(Network::Regtest).is_ok());
    }

    #[test]
    fn the_subsidy_stops_after_the_emission_ends() {
        let mut req = request();
        req.height = params::EMISSION_END_HEIGHT;
        let template = build_template(&req, &Mempool::new()).unwrap();
        assert_eq!(
            template.transactions[0].outputs[0].amount,
            Amount::ZERO,
            "発行終了後も報酬を受け取っている"
        );
    }
}
