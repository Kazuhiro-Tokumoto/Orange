//! 壊れたバイト列を復号器に浴びせる。
//!
//! ネットワークから来るバイト列は相手が自由に決められる。単体試験は
//! 「こういう壊れ方をしたら拒む」ことしか示さない。**思いつかなかった
//! 壊れ方**は、当てずっぽうに大量を投げるほうが見つかる。
//!
//! 本試験が主張するのは 2 つである。
//!
//! 1. **どんなバイト列でも `panic` しない。** `Ok` か `Err` を返す。
//!    復号器が落ちるなら、誰でもノードを落とせる
//! 2. **`Ok` を返したなら、その値を符号化し直すと元のバイト列に戻る。**
//!    戻らないなら、同じ値を表すバイト列が 2 通りあることになる。
//!    コンセンサスの符号化でそれが起きると、内容が同じで ID の違う
//!    トランザクションが作れてしまう (展性)
//!
//! 乱数は種を固定した自前の生成器で作る。**失敗したら同じ入力を再現
//! できなければ直せない。** 外部の生成器に頼ると版が上がって並びが
//! 変わりうる。
//!
//! これは本物のファジング (`cargo-fuzz`) の代わりにはならない。網羅の
//! 仕方が素朴であり、詰まった経路を掘り下げる働きもない。**CI で毎回
//! 走る下限**として置く。

use oag_consensus::block::Block;
use oag_consensus::codec::{Decode, Encode};
use oag_consensus::lock::Lock;
use oag_consensus::params::BLOCK_REWARD;
use oag_consensus::tx::{
    encode_coinbase_signature, OutPoint, Transaction, TxInput, TxOutput, CURRENT_TX_VERSION,
};
use oag_consensus::utxo::{UndoBlock, UtxoSet};
use oag_primitives::{merkle, Hash, SecretKey};

/// xorshift64*。種を固定できて、並びが版に依らない。
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        (self.next() % 256) as u8
    }
}

fn lock() -> Lock {
    Lock::pay_to_pubkey(&SecretKey::generate().public_key())
}

fn coinbase(height: u64) -> Transaction {
    let mut input = TxInput::new(OutPoint::null());
    input.signature = encode_coinbase_signature(height, b"orange");
    Transaction {
        version: CURRENT_TX_VERSION,
        inputs: vec![input],
        outputs: vec![TxOutput::new(BLOCK_REWARD, lock())],
        locktime: 0,
    }
}

fn payment(seed: u64) -> Transaction {
    let mut input = TxInput::new(OutPoint::new(
        oag_primitives::hash::txid(&seed.to_le_bytes()),
        (seed % 4) as u32,
    ));
    input.signature = vec![0x11; 64];
    Transaction {
        version: CURRENT_TX_VERSION,
        inputs: vec![input],
        outputs: vec![
            TxOutput::new("15".parse().unwrap(), lock()),
            TxOutput::new("9.999".parse().unwrap(), lock()),
        ],
        locktime: seed % 1_000,
    }
}

fn block(extra: usize) -> Block {
    let transactions: Vec<Transaction> = std::iter::once(coinbase(7))
        .chain((0..extra).map(|i| payment(i as u64)))
        .collect();
    let txids: Vec<Hash> = transactions.iter().map(|t| t.txid()).collect();
    Block {
        header: oag_consensus::BlockHeader {
            version: 0,
            prev_hash: oag_primitives::hash::block_hash(b"parent"),
            merkle_root: merkle::merkle_root(&txids).unwrap(),
            timestamp: 1_774_000_000,
            difficulty: 100_000,
            height: 7,
            nonce: 42,
        },
        transactions,
    }
}

/// 元のバイト列を適当に壊す。
fn corrupt(rng: &mut Rng, original: &[u8]) -> Vec<u8> {
    let mut bytes = original.to_vec();
    match rng.next() % 6 {
        // ビットを 1 つ反転する。
        0 => {
            if !bytes.is_empty() {
                let at = rng.below(bytes.len());
                bytes[at] ^= 1 << (rng.next() % 8);
            }
        }
        // 1 バイトを丸ごと書き換える。個数フィールドを壊しやすい。
        1 => {
            if !bytes.is_empty() {
                let at = rng.below(bytes.len());
                bytes[at] = rng.byte();
            }
        }
        // 途中で切る。
        2 => {
            let keep = rng.below(bytes.len() + 1);
            bytes.truncate(keep);
        }
        // 後ろに継ぎ足す。
        3 => {
            let extra = rng.below(40);
            for _ in 0..extra {
                let b = rng.byte();
                bytes.push(b);
            }
        }
        // 途中に割り込ませる。以降の並びがすべてずれる。
        4 => {
            let at = rng.below(bytes.len() + 1);
            let b = rng.byte();
            bytes.insert(at, b);
        }
        // まるごと出鱈目。
        _ => {
            let len = rng.below(200);
            bytes = (0..len).map(|_| rng.byte()).collect();
        }
    }
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 復号できたなら、符号化し直して元に戻ること。
///
/// `panic` しないことは、この関数が戻ってくること自体が示す。
fn round_trips<T: Decode + Encode>(bytes: &[u8], what: &str) {
    if let Ok(value) = T::decode(bytes) {
        let again = value.encode();
        assert_eq!(
            again,
            bytes,
            "{what}: 復号できたのに符号化し直すと別のバイト列になる\n  元: {}\n  再: {}",
            hex(bytes),
            hex(&again)
        );
    }
}

#[test]
fn a_corrupted_block_never_panics_and_never_decodes_two_ways() {
    let original = block(4).encode();
    let mut rng = Rng::new(0x0A6E_0001);
    for _ in 0..20_000 {
        let bytes = corrupt(&mut rng, &original);
        round_trips::<Block>(&bytes, "block");
    }
}

#[test]
fn a_corrupted_transaction_never_panics_and_never_decodes_two_ways() {
    let original = payment(3).encode();
    let mut rng = Rng::new(0x0A6E_0002);
    for _ in 0..20_000 {
        let bytes = corrupt(&mut rng, &original);
        round_trips::<Transaction>(&bytes, "tx");
    }
}

#[test]
fn a_corrupted_coinbase_never_panics_and_never_decodes_two_ways() {
    // コインベースは署名フィールドの使い方が普通の入力と違う。
    let original = coinbase(1_000_000).encode();
    let mut rng = Rng::new(0x0A6E_0003);
    for _ in 0..20_000 {
        let bytes = corrupt(&mut rng, &original);
        round_trips::<Transaction>(&bytes, "coinbase");
    }
}

#[test]
fn a_corrupted_undo_record_never_panics_and_never_decodes_two_ways() {
    // 記憶域から読み戻す形式。ディスクの壊れ方も相手にする。
    // 使用分と作成分の両方が入った巻き戻し情報を、実際に組み立てて得る。
    let mut utxo = UtxoSet::new();
    let cb = coinbase(1);
    utxo.apply_block(std::slice::from_ref(&cb), 1).unwrap();

    let mut spend = payment(9);
    spend.inputs[0].prev_out = OutPoint::new(cb.txid(), 0);
    let undo = utxo.apply_block(&[coinbase(2), spend], 2).unwrap();
    assert!(undo.spent_count() > 0 && undo.created_count() > 0);
    let original = undo.encode();
    let mut rng = Rng::new(0x0A6E_0004);
    for _ in 0..20_000 {
        let bytes = corrupt(&mut rng, &original);
        round_trips::<UndoBlock>(&bytes, "undo");
    }
}

#[test]
fn pure_noise_never_panics() {
    // 元のバイト列に寄りかからない、完全な出鱈目。
    let mut rng = Rng::new(0x0A6E_0005);
    for _ in 0..20_000 {
        let len = rng.below(300);
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        round_trips::<Block>(&bytes, "noise/block");
        round_trips::<Transaction>(&bytes, "noise/tx");
        round_trips::<UndoBlock>(&bytes, "noise/undo");
    }
}

#[test]
fn a_declared_count_never_outruns_the_input() {
    // 個数フィールドだけを狙う。通ってしまう個数があるなら、それは
    // 入力の長さで説明のつく件数でなければならない。
    let mut rng = Rng::new(0x0A6E_0006);
    for _ in 0..5_000 {
        let mut bytes = block(0).header.encode();
        // 取引数の varint を出鱈目に置く。
        let declared = rng.next() % 1_000_000;
        oag_consensus::codec::write_varint(u128::from(declared), &mut bytes);
        let tail = rng.below(500);
        for _ in 0..tail {
            let b = rng.byte();
            bytes.push(b);
        }

        if let Ok(decoded) = Block::decode(&bytes) {
            assert!(
                decoded.transactions.len() * Transaction::MIN_ENCODED_LEN <= bytes.len(),
                "入力 {} バイトに対して取引 {} 件が通った",
                bytes.len(),
                decoded.transactions.len()
            );
        }
    }
}
