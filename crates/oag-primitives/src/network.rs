//! ネットワーク種別と、それに紐づく既定値。
//!
//! 参照: `docs/SPEC.md` §6.2, §14

use core::fmt;
use core::net::{IpAddr, Ipv4Addr};
use core::str::FromStr;

/// ネットワーク種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// 本番ネットワーク。
    Mainnet,
    /// 公開テストネットワーク。
    Testnet,
    /// ローカル開発用ネットワーク。
    Regtest,
}

/// 既知のネットワーク名に一致しなかったことを表す。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("ネットワーク名として解釈できない: {0}")]
pub struct UnknownNetwork(
    /// 与えられた名前。
    pub String,
);

impl Network {
    /// すべてのネットワーク。
    pub const ALL: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Regtest];

    /// bech32m アドレスの HRP (Human Readable Part)。
    pub const fn hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "oag",
            Network::Testnet => "toag",
            Network::Regtest => "roag",
        }
    }

    /// HRP からネットワークを引く。
    pub fn from_hrp(hrp: &str) -> Option<Network> {
        match hrp {
            "oag" => Some(Network::Mainnet),
            "toag" => Some(Network::Testnet),
            "roag" => Some(Network::Regtest),
            _ => None,
        }
    }

    /// P2P ポート。
    ///
    /// Bitcoin の 8333 は採用しない (SPEC §14.1)。
    /// Bitcoin regtest が 18444 を用いるため、testnet は 19444 とする。
    pub const fn p2p_port(self) -> u16 {
        match self {
            Network::Mainnet => 9444,
            Network::Testnet => 19444,
            Network::Regtest => 29444,
        }
    }

    /// RPC ポート。
    pub const fn rpc_port(self) -> u16 {
        self.p2p_port() + 1
    }

    /// マイニング用インタフェースのポート。
    ///
    /// RPC と分離されている。マイナーの接続を許可するために RPC を
    /// 外部公開せざるを得ない状況を構造的に避けるため。
    pub const fn mining_port(self) -> u16 {
        self.p2p_port() + 2
    }

    /// P2P の既定バインドアドレス。外部からの接続受け入れが前提。
    pub const fn p2p_bind_default(self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }

    /// 難易度を調整するか。
    ///
    /// **regtest だけ調整しない。** 調整すると、ブロックを速く積むほど
    /// 難易度が上がり、コインベースの成熟を待つだけで現実的でない時間が
    /// かかる。試験用のネットワークとして使い物にならなくなる。
    /// Bitcoin の regtest も同じ扱いである (SPEC §12.4)。
    pub const fn retargets(self) -> bool {
        !matches!(self, Network::Regtest)
    }

    /// RPC の既定バインドアドレス。**ループバックのみ**。
    ///
    /// RPC を外部公開した結果として資金を喪失する事故は複数のプロジェクトで
    /// 発生している。既定値でこれを防ぐ (SPEC §14.1)。
    pub const fn rpc_bind_default(self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    /// マイニング用インタフェースの既定バインドアドレス。**ループバックのみ**。
    pub const fn mining_bind_default(self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    /// ジェネシスブロックの難易度 (暫定値)。
    ///
    /// RandomX の実測に基づいて調整する (SPEC §14.3)。
    pub const fn genesis_difficulty(self) -> u64 {
        match self {
            Network::Mainnet => 100_000,
            Network::Testnet => 1_000,
            Network::Regtest => 1,
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "regtest",
        })
    }
}

impl FromStr for Network {
    type Err = UnknownNetwork;

    fn from_str(s: &str) -> Result<Network, UnknownNetwork> {
        match s {
            "mainnet" => Ok(Network::Mainnet),
            "testnet" => Ok(Network::Testnet),
            "regtest" => Ok(Network::Regtest),
            other => Err(UnknownNetwork(other.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_match_spec() {
        assert_eq!(
            (
                Network::Mainnet.p2p_port(),
                Network::Mainnet.rpc_port(),
                Network::Mainnet.mining_port()
            ),
            (9444, 9445, 9446)
        );
        assert_eq!(
            (
                Network::Testnet.p2p_port(),
                Network::Testnet.rpc_port(),
                Network::Testnet.mining_port()
            ),
            (19444, 19445, 19446)
        );
        assert_eq!(
            (
                Network::Regtest.p2p_port(),
                Network::Regtest.rpc_port(),
                Network::Regtest.mining_port()
            ),
            (29444, 29445, 29446)
        );
    }

    #[test]
    fn avoids_known_chain_ports() {
        // SPEC §14.1: 既存の主要チェーンが占有するポートを使わない。
        let taken = [
            8332u16, 8333, // Bitcoin
            8444, // Chia
            8232, 8233, // Zcash
            9332, 9333, // Litecoin
            9999, // Dash
            18080, 18081, // Monero
            18333, // Bitcoin testnet
            18444, // Bitcoin regtest
            22556, // Dogecoin
            30303, // Ethereum
        ];
        for network in Network::ALL {
            for port in [
                network.p2p_port(),
                network.rpc_port(),
                network.mining_port(),
            ] {
                assert!(!taken.contains(&port), "{port} は既存チェーンと衝突する");
            }
        }
    }

    #[test]
    fn rpc_and_mining_bind_to_loopback() {
        for network in Network::ALL {
            assert!(
                network.rpc_bind_default().is_loopback(),
                "RPC は既定でループバックのみ"
            );
            assert!(
                network.mining_bind_default().is_loopback(),
                "マイニング用は既定でループバックのみ"
            );
            assert!(
                !network.p2p_bind_default().is_loopback(),
                "P2P は外部接続を受け入れる"
            );
        }
    }

    #[test]
    fn only_regtest_skips_the_difficulty_adjustment() {
        // 本番のチェーンで調整を止めたら、ハッシュレートの変動に
        // まったく追随できなくなる。
        assert!(Network::Mainnet.retargets());
        assert!(Network::Testnet.retargets());
        assert!(!Network::Regtest.retargets());
    }

    #[test]
    fn hrp_round_trip() {
        for network in Network::ALL {
            assert_eq!(Network::from_hrp(network.hrp()), Some(network));
        }
        assert_eq!(Network::from_hrp("bc"), None);
        assert_eq!(Network::from_hrp("OAG"), None);
    }

    #[test]
    fn name_round_trip() {
        for network in Network::ALL {
            assert_eq!(network.to_string().parse::<Network>().unwrap(), network);
        }
        assert!("signet".parse::<Network>().is_err());
    }
}
