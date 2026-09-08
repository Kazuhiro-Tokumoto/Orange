//! ジェネシスブロックの構築。
//!
//! ジェネシスはチェーンの定義そのものであり、一度確定させたら変更できない。
//! ハッシュが変われば別のチェーンになる。
//!
//! # ここにあるのは構築の手段だけである
//!
//! 各ネットワークに実際に刻む値は
//! [`oag_node::genesis`](../../oag_node/genesis/index.html) が持つ
//! (SPEC §14.4)。確定済みであり、変更できない。

use oag_consensus::codec::Encode;
use oag_consensus::lock::Lock;
use oag_consensus::tx::{encode_coinbase_signature, OutPoint, TxInput, CURRENT_TX_VERSION};
use oag_consensus::{Block, BlockHeader, Transaction, TxOutput};
use oag_primitives::{merkle, Amount, Hash, Network};

/// ジェネシスブロックの素材。
#[derive(Debug, Clone)]
pub struct GenesisSpec {
    /// 対象ネットワーク。難易度の既定値を決める。
    pub network: Network,
    /// ブロックのタイムスタンプ (Unix 秒)。
    pub timestamp: i64,
    /// コインベースに刻むメッセージ。
    ///
    /// 恒久的に公開される。Bitcoin が新聞の見出しを刻んだのと同じ位置づけで、
    /// 「この時点より前に採掘されていないこと」の証拠にもなる。
    pub message: Vec<u8>,
    /// コインベースの出力。
    ///
    /// 空にすればブロック 0 の報酬を放棄することになる。
    pub outputs: Vec<TxOutput>,
}

impl GenesisSpec {
    /// 報酬を放棄したジェネシスを定義する。
    ///
    /// 出力が無いためブロック 0 の 10 OAG は発行されない。プレマインが
    /// 無いことを最も明確に示す構成である。
    pub fn without_reward(network: Network, timestamp: i64, message: &[u8]) -> GenesisSpec {
        GenesisSpec {
            network,
            timestamp,
            message: message.to_vec(),
            outputs: Vec::new(),
        }
    }

    /// ブロック報酬を**焼却する**ジェネシスを定義する。
    ///
    /// 10 OAG は発行されるが、誰にも使えない支払い条件
    /// ([`Lock::unspendable`]) に結び付けられる。受け取らない
    /// ([`GenesisSpec::without_reward`]) との違いは、**発行された事実が
    /// 台帳に残る**ことである。UTXO セットに 1 件残り、エクスプローラでは
    /// 焼却先アドレス (`oag1qqqq…`) に 10 OAG が置かれたまま見える。
    ///
    /// 発行総量の 0.000001 % にすぎないが、「誰も取っていない」ことが
    /// 見える形で示される。
    pub fn with_burned_reward(network: Network, timestamp: i64, message: &[u8]) -> GenesisSpec {
        GenesisSpec {
            network,
            timestamp,
            message: message.to_vec(),
            outputs: vec![TxOutput::new(
                oag_consensus::params::BLOCK_REWARD,
                Lock::unspendable(),
            )],
        }
    }

    /// 通常どおりブロック報酬を受け取るジェネシスを定義する。
    pub fn with_reward(
        network: Network,
        timestamp: i64,
        message: &[u8],
        lock: Lock,
    ) -> GenesisSpec {
        GenesisSpec {
            network,
            timestamp,
            message: message.to_vec(),
            outputs: vec![TxOutput::new(oag_consensus::params::BLOCK_REWARD, lock)],
        }
    }

    /// コインベーストランザクション。
    pub fn coinbase(&self) -> Transaction {
        let mut input = TxInput::new(OutPoint::null());
        input.signature = encode_coinbase_signature(0, &self.message);
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: self.outputs.clone(),
            locktime: 0,
        }
    }

    /// 指定した nonce のジェネシスブロックを組み立てる。
    pub fn build(&self, nonce: u64) -> Block {
        let coinbase = self.coinbase();
        let merkle_root = merkle::merkle_root(&[coinbase.txid()]).expect("1 件はある");
        Block {
            header: BlockHeader {
                version: oag_consensus::block::CURRENT_BLOCK_VERSION,
                prev_hash: Hash::ZERO,
                merkle_root,
                timestamp: self.timestamp,
                difficulty: self.network.genesis_difficulty(),
                height: 0,
                nonce,
            },
            transactions: vec![coinbase],
        }
    }

    /// コインベースの出力合計。
    pub fn total_output(&self) -> Option<Amount> {
        Amount::sum(self.outputs.iter().map(|o| o.amount))
    }
}

/// ジェネシスの候補を nonce を変えながら探す。
///
/// `accepts` が真を返す nonce を見つけたらそのブロックを返す。実際の採掘では
/// RandomX による PoW 判定を渡す。テストでは常に真を返す判定でよい。
pub fn search<F>(spec: &GenesisSpec, max_attempts: u64, accepts: F) -> Option<Block>
where
    F: Fn(&Block) -> bool,
{
    (0..max_attempts)
        .map(|nonce| spec.build(nonce))
        .find(accepts)
}

/// ジェネシスブロックのシリアライズ表現 (16 進)。
///
/// 確定させたジェネシスを仕様書やテストに埋め込むために用いる。
pub fn serialize_hex(block: &Block) -> String {
    block.encode().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_consensus::Decode;

    fn spec() -> GenesisSpec {
        GenesisSpec::without_reward(Network::Regtest, 1_800_000_000, b"Orange genesis")
    }

    #[test]
    fn the_genesis_has_no_parent_and_height_zero() {
        let block = spec().build(0);
        assert_eq!(block.header.height, 0);
        assert_eq!(block.header.prev_hash, Hash::ZERO);
        assert!(block.coinbase().is_some());
        assert!(block.merkle_root_is_valid());
    }

    #[test]
    fn forgoing_the_reward_issues_nothing() {
        let s = spec();
        assert_eq!(s.total_output(), Some(Amount::ZERO));
        assert!(s.coinbase().outputs.is_empty());
    }

    #[test]
    fn the_message_is_embedded_in_the_coinbase() {
        let s = spec();
        let signature = &s.coinbase().inputs[0].signature;
        // 先頭は高さ 0 の varint、その後がメッセージ。
        assert_eq!(signature[0], 0);
        assert_eq!(&signature[1..], b"Orange genesis");
    }

    #[test]
    fn the_message_changes_the_genesis_hash() {
        let a = spec().build(0).header.hash();
        let b = GenesisSpec::without_reward(Network::Regtest, 1_800_000_000, b"different")
            .build(0)
            .header
            .hash();
        assert_ne!(a, b, "刻んだ内容が違えば別のチェーンになる");
    }

    #[test]
    fn each_network_gets_its_own_genesis() {
        let mut hashes = Vec::new();
        for network in Network::ALL {
            let block = GenesisSpec::without_reward(network, 1_800_000_000, b"Orange").build(0);
            assert_eq!(block.header.difficulty, network.genesis_difficulty());
            hashes.push(block.header.hash());
        }
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(hashes.len(), 3, "ネットワークごとに異なるジェネシスになる");
    }

    #[test]
    fn round_trips_through_serialization() {
        let block = spec().build(12_345);
        let hex = serialize_hex(&block);
        let bytes = hex::decode(&hex).unwrap();
        assert_eq!(Block::decode(&bytes).unwrap(), block);
    }

    #[test]
    fn search_finds_a_nonce() {
        let s = spec();
        // 先頭バイトが 0 になるハッシュを探す (確率 1/256)。
        let found =
            search(&s, 10_000, |b| b.header.hash().as_bytes()[0] == 0).expect("見つかるはず");
        assert_eq!(found.header.hash().as_bytes()[0], 0);
    }
}
