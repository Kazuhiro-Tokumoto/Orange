//! bech32m アドレス。
//!
//! Bitcoin は SegWit v0 に bech32、v1 以降に bech32m を用いるが、
//! これは bech32 に見つかった欠陥を後から修正した歴史的経緯によるものである。
//! 本チェーンは新規であるため、**全バージョンで bech32m に統一する**。
//!
//! 参照: `docs/SPEC.md` §6

use crate::keys::PublicKey;
use crate::network::Network;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
use bech32::{Bech32m, Fe32, Hrp};
use core::fmt;
use core::str::FromStr;

/// Schnorr x-only 公開鍵への支払いを表すアドレス版数。
pub const VERSION_PUBKEY: u8 = 0;

/// アドレス版数の最大値 (bech32m の 1 文字で表せる範囲)。
pub const MAX_VERSION: u8 = 31;

/// 版数 0 のペイロード長 (x-only 公開鍵)。
pub const PUBKEY_PAYLOAD_LEN: usize = 32;

/// ペイロード長の下限。
pub const MIN_PAYLOAD_LEN: usize = 2;

/// ペイロード長の上限。
pub const MAX_PAYLOAD_LEN: usize = 40;

/// アドレスの生成・解釈で起きうる誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    /// bech32m として不正 (チェックサム誤り、大文字小文字の混在など)。
    #[error("bech32m として解釈できない: {0}")]
    Bech32(
        /// bech32 クレートが返した説明。
        String,
    ),
    /// 本チェーンのどのネットワークにも対応しない HRP。
    #[error("既知のネットワークに対応しない HRP: {0}")]
    UnknownHrp(
        /// 与えられた HRP。
        String,
    ),
    /// 期待したネットワークと異なるアドレス。
    #[error("{expected} のアドレスを期待したが {actual} のアドレスだった")]
    NetworkMismatch {
        /// 期待したネットワーク。
        expected: Network,
        /// 実際のネットワーク。
        actual: Network,
    },
    /// データ部が空で版数を取り出せない。
    #[error("アドレス版数が含まれていない")]
    MissingVersion,
    /// 版数が 5 ビットに収まらない。
    #[error("アドレス版数 {0} は範囲外 (0-31)")]
    VersionOutOfRange(
        /// 与えられた版数。
        u8,
    ),
    /// その版数に定められた長さとペイロードが一致しない。
    #[error("版数 {version} のペイロード長 {actual} が不正 ({expected} である必要がある)")]
    BadPayloadLength {
        /// 対象の版数。
        version: u8,
        /// その版数が要求する長さ。
        expected: usize,
        /// 実際に与えられた長さ。
        actual: usize,
    },
    /// ペイロード長が全版数共通の範囲を外れている。
    #[error("ペイロード長 {0} が範囲外 (2-40)")]
    PayloadLengthOutOfRange(
        /// 実際に与えられた長さ。
        usize,
    ),
    /// 同じ内容に対する非正準な文字列表現。
    #[error("正準でないアドレス表現")]
    NonCanonical,
}

/// OAG のアドレス。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    network: Network,
    version: u8,
    payload: Vec<u8>,
}

impl Address {
    /// 構成要素からアドレスを作る。
    pub fn new(network: Network, version: u8, payload: Vec<u8>) -> Result<Address, AddressError> {
        if version > MAX_VERSION {
            return Err(AddressError::VersionOutOfRange(version));
        }
        if !(MIN_PAYLOAD_LEN..=MAX_PAYLOAD_LEN).contains(&payload.len()) {
            return Err(AddressError::PayloadLengthOutOfRange(payload.len()));
        }
        if version == VERSION_PUBKEY && payload.len() != PUBKEY_PAYLOAD_LEN {
            return Err(AddressError::BadPayloadLength {
                version,
                expected: PUBKEY_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        Ok(Address {
            network,
            version,
            payload,
        })
    }

    /// x-only 公開鍵から版数 0 のアドレスを作る。
    pub fn from_pubkey(network: Network, pubkey: &PublicKey) -> Address {
        Address {
            network,
            version: VERSION_PUBKEY,
            payload: pubkey.to_bytes().to_vec(),
        }
    }

    /// このアドレスのネットワーク。
    pub fn network(&self) -> Network {
        self.network
    }

    /// このアドレスの版数。
    pub fn version(&self) -> u8 {
        self.version
    }

    /// このアドレスのペイロード。
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// この実装が意味を理解している版数か。
    ///
    /// 未知の版数のアドレスへの送金は、警告を表示した上で許可する
    /// (前方互換性。SPEC §6.3)。
    pub fn is_known_version(&self) -> bool {
        self.version == VERSION_PUBKEY
    }

    /// 版数 0 のアドレスから公開鍵を取り出す。
    pub fn to_pubkey(&self) -> Option<PublicKey> {
        if self.version != VERSION_PUBKEY {
            return None;
        }
        PublicKey::from_slice(&self.payload).ok()
    }

    /// bech32m 文字列に符号化する。
    pub fn encode(&self) -> String {
        let hrp = Hrp::parse_unchecked(self.network.hrp());
        let version = Fe32::try_from(self.version).expect("版数は 31 以下であることが不変条件");
        self.payload
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version)
            .chars()
            .collect()
    }

    /// bech32m 文字列を復号する。ネットワークは HRP から判定する。
    pub fn decode(s: &str) -> Result<Address, AddressError> {
        let mut parsed =
            CheckedHrpstring::new::<Bech32m>(s).map_err(|e| AddressError::Bech32(e.to_string()))?;

        let hrp = parsed.hrp();
        let network = Network::from_hrp(&hrp.as_str().to_ascii_lowercase())
            .ok_or_else(|| AddressError::UnknownHrp(hrp.to_string()))?;

        let version = parsed
            .remove_witness_version()
            .ok_or(AddressError::MissingVersion)?
            .to_u8();

        let payload: Vec<u8> = parsed.byte_iter().collect();
        let address = Address::new(network, version, payload)?;

        // 5 ビット境界の余りビットの扱いによって、同じアドレスに対して
        // 複数の文字列表現が生じうる。再符号化して一致しない入力は拒否する。
        if address.encode() != s.to_ascii_lowercase() {
            return Err(AddressError::NonCanonical);
        }

        Ok(address)
    }

    /// 指定したネットワークのアドレスとして復号する。
    ///
    /// 異なるネットワークのアドレスは拒否する。誤送金を防ぐため、
    /// ウォレットは常にこちらを用いるべきである。
    pub fn decode_on(network: Network, s: &str) -> Result<Address, AddressError> {
        let address = Address::decode(s)?;
        if address.network != network {
            return Err(AddressError::NetworkMismatch {
                expected: network,
                actual: address.network,
            });
        }
        Ok(address)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Address, AddressError> {
        Address::decode(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SecretKey;

    /// SPEC §6.5 のテストベクタ。
    const VECTORS: [(&str, &str, &str, &str); 3] = [
        (
            "3bea301b132570f53a193a6542940305ac1e6b343249425433febf3c01d3f8f8",
            "0830053b6ac7f7b10243a8058fb5d9bc3ccdec622deadaa9da7f885f16dedc2e",
            "oag1qpqcq2wm2clmmzqjr4qzcldwehs7vmmrz9h4d42w607y979k7mshq9ve7jv",
            "toag1qpqcq2wm2clmmzqjr4qzcldwehs7vmmrz9h4d42w607y979k7mshqwraqde",
        ),
        (
            "5487aaeb0f711bf0dee2cf7b97ea24f28037617dc5ff2f45d095a14ebf231f22",
            "5b528dd539132944eee4387dbf81aee1c65699d1154993a55d1c181c76b3e53e",
            "oag1qtdfgm4fezv55fmhy8p7mlqdwu8r9dxw3z4ye8f2arsvpca4nu5lq34qtxp",
            "toag1qtdfgm4fezv55fmhy8p7mlqdwu8r9dxw3z4ye8f2arsvpca4nu5lq66y4e5",
        ),
        (
            "01119d84272af17d8d957f160f3117bbcc769c2a95e9f8398c546ca24c6a52d8",
            "1ed0a9a1dc8ab784f5f38a869d8479f0ce476eea093883f0e718c566cabe823e",
            "oag1qrmg2ngwu32mcfa0n32rfmpre7r8ywmh2pyug8u88rrzkdj47sglqc68mtx",
            "toag1qrmg2ngwu32mcfa0n32rfmpre7r8ywmh2pyug8u88rrzkdj47sglqn4r95n",
        ),
    ];

    #[test]
    fn spec_vectors_secret_to_public() {
        for (secret_hex, pubkey_hex, _, _) in VECTORS {
            let secret: [u8; 32] = hex::decode(secret_hex).unwrap().try_into().unwrap();
            let sk = SecretKey::from_bytes(secret).unwrap();
            assert_eq!(hex::encode(sk.public_key().to_bytes()), pubkey_hex);
        }
    }

    #[test]
    fn spec_vectors_encode() {
        for (_, pubkey_hex, mainnet, testnet) in VECTORS {
            let pk = pubkey_hex.parse::<PublicKey>().unwrap();
            assert_eq!(
                Address::from_pubkey(Network::Mainnet, &pk).encode(),
                mainnet
            );
            assert_eq!(
                Address::from_pubkey(Network::Testnet, &pk).encode(),
                testnet
            );
        }
    }

    #[test]
    fn spec_vectors_decode() {
        for (_, pubkey_hex, mainnet, testnet) in VECTORS {
            for (text, network) in [(mainnet, Network::Mainnet), (testnet, Network::Testnet)] {
                let address = Address::decode(text).unwrap();
                assert_eq!(address.network(), network);
                assert_eq!(address.version(), VERSION_PUBKEY);
                assert_eq!(hex::encode(address.payload()), pubkey_hex);
                assert_eq!(address.to_pubkey().unwrap().to_string(), pubkey_hex);
            }
        }
    }

    #[test]
    fn address_lengths_match_spec() {
        let pk = VECTORS[0].1.parse::<PublicKey>().unwrap();
        assert_eq!(
            Address::from_pubkey(Network::Mainnet, &pk).encode().len(),
            63
        );
        assert_eq!(
            Address::from_pubkey(Network::Testnet, &pk).encode().len(),
            64
        );
        assert_eq!(
            Address::from_pubkey(Network::Regtest, &pk).encode().len(),
            64
        );
    }

    #[test]
    fn version_zero_renders_as_q() {
        let pk = VECTORS[0].1.parse::<PublicKey>().unwrap();
        for network in Network::ALL {
            let text = Address::from_pubkey(network, &pk).encode();
            let after_separator = &text[network.hrp().len() + 1..];
            assert!(after_separator.starts_with('q'), "版数 0 は 'q' で始まる");
        }
    }

    #[test]
    fn round_trip_for_all_networks() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        for network in Network::ALL {
            let address = Address::from_pubkey(network, &pk);
            let text = address.encode();
            assert_eq!(Address::decode(&text).unwrap(), address);
            assert_eq!(text.parse::<Address>().unwrap(), address);
        }
    }

    #[test]
    fn cross_network_addresses_are_rejected() {
        let pk = VECTORS[0].1.parse::<PublicKey>().unwrap();
        let mainnet = Address::from_pubkey(Network::Mainnet, &pk).encode();

        assert_eq!(
            Address::decode_on(Network::Testnet, &mainnet).unwrap_err(),
            AddressError::NetworkMismatch {
                expected: Network::Testnet,
                actual: Network::Mainnet,
            }
        );
        assert!(Address::decode_on(Network::Mainnet, &mainnet).is_ok());
    }

    #[test]
    fn rejects_foreign_hrp() {
        // Bitcoin の Taproot アドレス。
        let bitcoin = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
        assert!(matches!(
            Address::decode(bitcoin),
            Err(AddressError::UnknownHrp(_))
        ));
    }

    #[test]
    fn rejects_corrupted_checksum() {
        let mut text = VECTORS[0].2.to_owned();
        // 末尾のチェックサム文字を 1 つ変える。
        text.pop();
        text.push('q');
        assert!(matches!(
            Address::decode(&text),
            Err(AddressError::Bech32(_))
        ));
    }

    #[test]
    fn rejects_single_character_errors() {
        // bech32m は 4 文字以内の誤りを 100 % 検出する (SPEC §6.4)。
        let original = VECTORS[0].2;
        let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let mut checked = 0;
        for i in original.find('1').unwrap() + 1..original.len() {
            for replacement in charset.chars() {
                let mut bytes: Vec<char> = original.chars().collect();
                if bytes[i] == replacement {
                    continue;
                }
                bytes[i] = replacement;
                let corrupted: String = bytes.into_iter().collect();
                assert!(
                    Address::decode(&corrupted).is_err(),
                    "{corrupted} は検出されるべき"
                );
                checked += 1;
            }
        }
        assert!(checked > 1_000, "十分な数の変異を検査していない");
    }

    #[test]
    fn rejects_mixed_case() {
        let text = VECTORS[0].2;
        let mixed = format!("{}{}", text[..10].to_uppercase(), &text[10..]);
        assert!(Address::decode(&mixed).is_err());
    }

    #[test]
    fn rejects_bad_payload_length_for_version_zero() {
        assert!(matches!(
            Address::new(Network::Mainnet, VERSION_PUBKEY, vec![0u8; 20]),
            Err(AddressError::BadPayloadLength { .. })
        ));
    }

    #[test]
    fn rejects_out_of_range_version() {
        assert_eq!(
            Address::new(Network::Mainnet, 32, vec![0u8; 32]).unwrap_err(),
            AddressError::VersionOutOfRange(32)
        );
    }

    #[test]
    fn future_versions_decode_but_are_not_known() {
        // SPEC §6.3: 未知の版数もデコードはできる (前方互換性)。
        let address = Address::new(Network::Mainnet, 1, vec![0xab; 32]).unwrap();
        let text = address.encode();
        let after_separator = &text["oag".len() + 1..];
        assert!(after_separator.starts_with('p'), "版数 1 は 'p' で始まる");

        let decoded = Address::decode(&text).unwrap();
        assert_eq!(decoded, address);
        assert!(!decoded.is_known_version());
        assert_eq!(decoded.to_pubkey(), None);
    }
}
