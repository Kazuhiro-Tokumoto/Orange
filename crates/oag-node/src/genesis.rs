//! ネットワークごとのジェネシスブロック。
//!
//! ジェネシスはチェーンの定義そのものであり、**一度確定させたら変更でき
//! ない**。ハッシュが変われば別のチェーンになり、既存のデータベースは
//! 使えなくなり、同期していた相手とも繋がらなくなる。
//!
//! 3 つのネットワークすべてで確定済みである (SPEC §14.4)。
//!
//! # ジェネシスに PoW は無い
//!
//! ジェネシスの PoW は検証しない。RandomX のシードは
//! [`seed_height`](oag_pow::seed_height) が示す高さのブロックハッシュで
//! あり、高さ 0 ではそれがジェネシス自身のハッシュになる。**自分のハッシュ
//! を材料に自分のハッシュを求めることはできない。** したがってジェネシスの
//! nonce は 0 に置き、意味を持たせない。
//!
//! ブロック 1 以降は、ジェネシスのハッシュをシードとして通常どおり検証
//! される。

use oag_chain::genesis::GenesisSpec;
use oag_consensus::Block;
use oag_primitives::Network;

/// mainnet と testnet のジェネシスのタイムスタンプ
/// (2026-09-01T00:00:00Z)。
///
/// 過去でなければならない。ジェネシスより後のタイムスタンプしかブロックに
/// 付けられないため、未来の値を置くとその時刻が来るまで採掘できない。
const TIMESTAMP: i64 = 1_788_220_800;

/// コインベースに刻む内容。
///
/// 恒久的に公開される。Bitcoin が新聞の見出しを刻んだのと同じ位置づけで
/// ある。
const MESSAGE: &[u8] = b"Orange is good";

/// regtest のジェネシスのタイムスタンプ (2026-01-01T00:00:00Z)。
///
/// mainnet より前に確定させたため、別の値である。regtest は各自の手元で
/// 作り直せるチェーンだが、揃える理由も無いのでそのままにする。
const REGTEST_TIMESTAMP: i64 = 1_767_225_600;

/// regtest のジェネシスに刻む内容。
const REGTEST_MESSAGE: &[u8] = b"Orange regtest";

/// そのネットワークのジェネシスブロック。
///
/// mainnet と testnet は**ブロック報酬を焼却する**。10 OAG は発行される
/// が、誰にも使えない支払い条件に結び付けられており、動かせない。
/// regtest は報酬を受け取らない (出力が無い)。
pub fn genesis_for(network: Network) -> Block {
    match network {
        Network::Regtest => {
            GenesisSpec::without_reward(Network::Regtest, REGTEST_TIMESTAMP, REGTEST_MESSAGE)
                .build(0)
        }
        other => GenesisSpec::with_burned_reward(other, TIMESTAMP, MESSAGE).build(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_consensus::codec::Encode;
    use oag_consensus::lock::Lock;

    #[test]
    fn every_network_has_a_genesis() {
        for network in Network::ALL {
            let genesis = genesis_for(network);
            assert_eq!(genesis.header.height, 0);
            assert_eq!(genesis.header.prev_hash, oag_primitives::Hash::ZERO);
            assert_eq!(genesis.header.difficulty, network.genesis_difficulty());
            assert!(genesis.coinbase().is_some(), "{network}");
            assert!(genesis.merkle_root_is_valid(), "{network}");
        }
    }

    /// **この値が変わったら別のチェーンである。**
    ///
    /// 落ちたときに直すのは、ここの期待値ではなく、変えてしまった側である。
    #[test]
    fn the_genesis_of_every_network_is_fixed() {
        let expected = [
            (
                Network::Mainnet,
                "7511b77a9fb2aac8d7ba4655ed372c6fc3fbf800e1872a5c907bb64a775f0c40",
                208usize,
            ),
            (
                Network::Testnet,
                "0862309e4cf48d928fad77bbb1ba799835d627e1fd79592395ea284529664bfa",
                208,
            ),
            (
                Network::Regtest,
                "c38b0b105c8557912d3be1eeb6a3c0aedfdefd2882200a8ef1484dd9cad874ba",
                165,
            ),
        ];
        for (network, hash, len) in expected {
            let genesis = genesis_for(network);
            assert_eq!(
                genesis.header.hash().to_string(),
                hash,
                "{network} のジェネシスが変わっている"
            );
            assert_eq!(genesis.encode().len(), len, "{network}");
        }
    }

    /// mainnet と testnet はコインベースが同一であり、ヘッダの難易度だけが
    /// 違う。マークルルートが一致することを固定しておく。
    #[test]
    fn mainnet_and_testnet_share_one_coinbase() {
        let mainnet = genesis_for(Network::Mainnet);
        let testnet = genesis_for(Network::Testnet);
        assert_eq!(mainnet.transactions, testnet.transactions);
        assert_eq!(
            mainnet.header.merkle_root.to_string(),
            "0dfcbab210f8f5997ccad4c2c3fea4af9a783692bd5e35f6f83eba0b41456fb2"
        );
        assert_eq!(
            mainnet.transactions[0].txid().to_string(),
            "016a04257821869f1704bd1ab084a1d14af360a901f1b5930ca21f306b6f0871"
        );
        // 難易度だけが違うのだから、ハッシュは違わなければならない。
        assert_ne!(mainnet.header.hash(), testnet.header.hash());
    }

    #[test]
    fn mainnet_and_testnet_burn_the_block_zero_reward() {
        for network in [Network::Mainnet, Network::Testnet] {
            let coinbase = genesis_for(network).transactions[0].clone();
            assert_eq!(coinbase.outputs.len(), 1, "{network}");
            assert_eq!(
                coinbase.outputs[0].amount,
                oag_consensus::params::BLOCK_REWARD,
                "{network}"
            );
            assert_eq!(
                coinbase.outputs[0].lock,
                Lock::unspendable(),
                "{network} の報酬が焼却先になっていない"
            );
            // 使えないことは oag-consensus の
            // an_output_locked_to_the_zero_key_cannot_be_spent で確かめている。
            assert_eq!(coinbase.outputs[0].lock.to_pubkey(), None, "{network}");
        }
    }

    #[test]
    fn the_regtest_genesis_issues_nothing() {
        assert!(
            genesis_for(Network::Regtest).transactions[0]
                .outputs
                .is_empty(),
            "regtest のジェネシスが報酬を受け取っている"
        );
    }

    #[test]
    fn the_message_is_embedded_in_the_coinbase() {
        let coinbase = genesis_for(Network::Mainnet).transactions[0].clone();
        let signature = &coinbase.inputs[0].signature;
        // 先頭は高さ 0 の varint、その後がメッセージ。
        assert_eq!(signature[0], 0);
        assert_eq!(&signature[1..], MESSAGE);
    }

    #[test]
    fn the_timestamp_is_in_the_past() {
        // 未来の値を置くと、その時刻が来るまで 1 つも掘れない。
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("1970 年より後")
            .as_secs() as i64;
        for network in Network::ALL {
            assert!(
                genesis_for(network).header.timestamp < now,
                "{network} のジェネシスが未来にある"
            );
        }
    }

    #[test]
    fn each_network_gets_a_different_genesis() {
        let mut hashes: Vec<_> = Network::ALL
            .into_iter()
            .map(|n| genesis_for(n).header.hash())
            .collect();
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(hashes.len(), 3, "ネットワーク間でジェネシスが衝突している");
    }
}
