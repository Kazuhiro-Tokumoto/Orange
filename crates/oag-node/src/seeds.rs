//! シードノード。**最初の 1 回だけ使う。**
//!
//! 住所帳が空のノードは、繋ぎ先を 1 つも知らない。誰かの IP を人づてに
//! 聞いて打ち込む以外に始めようがない。それを避けるために、ホスト名を
//! 実行ファイルに焼き込んでおく。
//!
//! # DNS シード
//!
//! ホスト名を引くと、稼働中のノードの IP が A / AAAA レコードで返る。
//! そこに繋いだあとは、ノード同士が `addr` で住所を教え合うので、
//! **シードはもう要らない**。住所帳に候補がある限り引きに行かない。
//!
//! したがって、シードが落ちても既存のネットワークは死なない。困るのは
//! **新しく入ろうとするノードだけ**である。
//!
//! # 信用していない
//!
//! DNS の答えは平文で運ばれ、経路上で書き換えられる。シードの運用者が
//! 悪意を持つこともある。だから**シードから得た住所も、他のピアから
//! 聞いた住所と同じ扱いにする** — 住所帳に入れ、[`crate::addrbook`] の
//! 上限と括りの規則に従わせる。特別扱いはしない。
//!
//! シードが返す住所しか知らない状態は日蝕攻撃に弱い。住所帳が育つまでの
//! 間はそういう状態である、と認めておく。
//!
//! # regtest にシードは無い
//!
//! 手元で試すためのものであり、公開ネットワークではない。`--connect` で
//! 相手を明示する。

use oag_primitives::Network;
use std::net::SocketAddr;

/// mainnet のシード。
pub const MAINNET_SEEDS: &[&str] = &["seed.manh2309.org"];

/// testnet のシード。
///
/// mainnet と分ける。同じホスト名にすると、testnet のノードが mainnet の
/// ノードに繋ぎに行く。マジックバイトで弾かれるので実害は無いが、
/// 無駄な接続を撒くことになる。
pub const TESTNET_SEEDS: &[&str] = &["testnet-seed.manh2309.org"];

/// そのネットワークのシードのホスト名。
pub fn seeds_for(network: Network) -> &'static [&'static str] {
    match network {
        Network::Mainnet => MAINNET_SEEDS,
        Network::Testnet => TESTNET_SEEDS,
        // 手元で試すためのものなので、繋ぎ先は明示してもらう。
        Network::Regtest => &[],
    }
}

/// シードを引き、得られた住所を返す。
///
/// 引けなかったホスト名は黙って飛ばす。**1 つでも引ければ始められる。**
/// 全部引けなければ空を返す。呼び出し側が「シードから何も得られなかった」
/// と告げる。
///
/// ポートはそのネットワークの既定値を使う。DNS の A レコードにポートは
/// 書けないためである。
pub async fn resolve(network: Network) -> Vec<SocketAddr> {
    let port = network.p2p_port();
    let mut found = Vec::new();
    for host in seeds_for(network) {
        match tokio::net::lookup_host((*host, port)).await {
            Ok(addrs) => {
                let mut count = 0;
                for addr in addrs {
                    if !found.contains(&addr) {
                        found.push(addr);
                        count += 1;
                    }
                }
                println!("シード {host} から {count} 件");
            }
            Err(e) => eprintln!("シード {host} を引けない: {e}"),
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_public_network_has_a_seed() {
        // 無ければ、新しいノードは人づてに IP を聞くしかない。
        for network in [Network::Mainnet, Network::Testnet] {
            assert!(!seeds_for(network).is_empty(), "{network} にシードが無い");
        }
    }

    #[test]
    fn regtest_has_no_seed() {
        // 手元のネットワークが外に繋ぎに行ってはならない。
        assert!(seeds_for(Network::Regtest).is_empty());
    }

    #[test]
    fn the_networks_do_not_share_a_hostname() {
        for main in MAINNET_SEEDS {
            assert!(
                !TESTNET_SEEDS.contains(main),
                "{main} が mainnet と testnet の両方にある"
            );
        }
    }

    #[tokio::test]
    async fn regtest_resolves_to_nothing_without_touching_dns() {
        assert!(resolve(Network::Regtest).await.is_empty());
    }
}
