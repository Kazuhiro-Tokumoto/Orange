//! ネットワークごとのジェネシスブロック。
//!
//! ジェネシスはチェーンの定義そのものであり、一度確定させたら変更できない。
//! ハッシュが変われば別のチェーンになる。
//!
//! # mainnet と testnet は未確定である
//!
//! 刻む内容が決まっていないため、これらのネットワークでは起動を断る。
//! その場しのぎのジェネシスで立ち上げてしまうと、後から差し替えたときに
//! 既存のデータベースが使えなくなり、同期していた相手とも繋がらなくなる。
//!
//! 決めるべきこと (`docs/SPEC.md` の未決事項):
//!
//! - タイムスタンプ
//! - コインベースに刻むメッセージ
//! - ブロック 0 の報酬を受け取るか放棄するか

use oag_chain::genesis::GenesisSpec;
use oag_consensus::Block;
use oag_primitives::Network;

/// regtest のジェネシスのタイムスタンプ (2026-01-01T00:00:00Z)。
///
/// 過去でなければならない。ジェネシスより後のタイムスタンプしかブロックに
/// 付けられないため、未来の値を置くとその時刻が来るまで採掘できない。
const REGTEST_TIMESTAMP: i64 = 1_767_225_600;

/// regtest のジェネシスに刻む内容。
const REGTEST_MESSAGE: &[u8] = b"Orange regtest";

/// ジェネシスがまだ決まっていない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "{0} のジェネシスブロックはまだ確定していない。\n\
     タイムスタンプ、コインベースに刻むメッセージ、ブロック 0 の報酬の\n\
     扱いを決める必要がある (docs/SPEC.md の未決事項を参照)。\n\
     現在起動できるのは regtest のみである。"
)]
pub struct GenesisUndecided(pub Network);

/// そのネットワークのジェネシスブロック。
pub fn genesis_for(network: Network) -> Result<Block, GenesisUndecided> {
    match network {
        Network::Regtest => {
            Ok(
                GenesisSpec::without_reward(Network::Regtest, REGTEST_TIMESTAMP, REGTEST_MESSAGE)
                    .build(0),
            )
        }
        other => Err(GenesisUndecided(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_consensus::codec::Encode;

    #[test]
    fn regtest_has_a_genesis() {
        let genesis = genesis_for(Network::Regtest).unwrap();
        assert_eq!(genesis.header.height, 0);
        assert_eq!(
            genesis.header.difficulty,
            Network::Regtest.genesis_difficulty()
        );
        assert!(genesis.coinbase().is_some());
        assert!(genesis.merkle_root_is_valid());
    }

    #[test]
    fn the_regtest_genesis_is_fixed() {
        // 変えたら別のチェーンになる。値を固定しておく。
        let genesis = genesis_for(Network::Regtest).unwrap();
        assert_eq!(
            genesis.header.hash().to_string(),
            "c38b0b105c8557912d3be1eeb6a3c0aedfdefd2882200a8ef1484dd9cad874ba",
            "regtest のジェネシスが変わっている"
        );
        assert_eq!(genesis.encode().len(), 165);
    }

    #[test]
    fn mainnet_and_testnet_refuse_to_start() {
        for network in [Network::Mainnet, Network::Testnet] {
            assert_eq!(
                genesis_for(network),
                Err(GenesisUndecided(network)),
                "{network} が起動できてしまう"
            );
        }
    }

    #[test]
    fn the_genesis_issues_nothing() {
        let genesis = genesis_for(Network::Regtest).unwrap();
        assert!(
            genesis.transactions[0].outputs.is_empty(),
            "ジェネシスが報酬を受け取っている"
        );
    }
}
