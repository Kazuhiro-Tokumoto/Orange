//! ネットワーク識別子 (マジックバイト)。
//!
//! すべてのメッセージの先頭に置く 4 バイトである。**ネットワーク間の分離を
//! 担う実質的な機構はこれであり、ポート番号ではない** (SPEC §14.2)。
//! 異なるネットワークのノードが接続してきても、最初の 4 バイトで弾かれる。
//!
//! # 値の決め方
//!
//! 恣意的に選ぶのではなく、ネットワーク名から決定的に導出する。
//!
//! ```text
//! magic = BLAKE3("Orange/network/<ネットワーク名>")[0..4]
//! ```
//!
//! こうすることで、値の出どころが説明でき、再現もできる。
//! 導出が正しいことは本モジュールの試験で確認している。

use oag_primitives::Network;

/// マジックバイトの長さ。
pub const MAGIC_LEN: usize = 4;

/// mainnet の識別子。
pub const MAGIC_MAINNET: [u8; MAGIC_LEN] = [0x33, 0x97, 0x55, 0x03];
/// testnet の識別子。
pub const MAGIC_TESTNET: [u8; MAGIC_LEN] = [0x7F, 0x88, 0xA0, 0xC1];
/// regtest の識別子。
pub const MAGIC_REGTEST: [u8; MAGIC_LEN] = [0x18, 0x2C, 0x9C, 0x5E];

/// ネットワークの識別子。
pub const fn magic_for(network: Network) -> [u8; MAGIC_LEN] {
    match network {
        Network::Mainnet => MAGIC_MAINNET,
        Network::Testnet => MAGIC_TESTNET,
        Network::Regtest => MAGIC_REGTEST,
    }
}

/// 識別子からネットワークを引く。
pub fn network_for(magic: &[u8; MAGIC_LEN]) -> Option<Network> {
    Network::ALL.into_iter().find(|n| &magic_for(*n) == magic)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 定数が説明どおりの導出になっていること。
    fn derive(network: Network) -> [u8; MAGIC_LEN] {
        let tag = format!("Orange/network/{network}");
        let digest = blake3::hash(tag.as_bytes());
        let mut out = [0u8; MAGIC_LEN];
        out.copy_from_slice(&digest.as_bytes()[..MAGIC_LEN]);
        out
    }

    #[test]
    fn the_constants_match_the_documented_derivation() {
        for network in Network::ALL {
            assert_eq!(
                magic_for(network),
                derive(network),
                "{network} の識別子が導出と一致しない"
            );
        }
    }

    #[test]
    fn every_network_has_a_distinct_magic() {
        let mut seen: Vec<[u8; MAGIC_LEN]> = Network::ALL.iter().map(|n| magic_for(*n)).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn round_trips_through_lookup() {
        for network in Network::ALL {
            assert_eq!(network_for(&magic_for(network)), Some(network));
        }
        assert_eq!(network_for(&[0, 0, 0, 0]), None);
        // Bitcoin の識別子と衝突しないこと。
        assert_eq!(network_for(&[0xF9, 0xBE, 0xB4, 0xD9]), None);
    }

    #[test]
    fn the_magic_is_not_plain_ascii() {
        // 平文の流れの中に偶然現れにくいこと。
        for network in Network::ALL {
            let magic = magic_for(network);
            assert!(
                !magic.iter().all(|b| b.is_ascii_graphic()),
                "{network} の識別子がすべて印字可能な ASCII になっている"
            );
        }
    }
}
