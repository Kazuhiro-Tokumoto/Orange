//! 出力の支払い条件。
//!
//! 本チェーンはスクリプト言語を持たない。出力は「版数 + ペイロード」の組で
//! 支払い条件を表す。版数 0 は Schnorr x-only 公開鍵への支払いを意味する。
//!
//! ペイロードは**長さ接頭辞つき**で符号化する。これにより、将来新しい版数を
//! 追加しても、その版数を知らないノードが出力を読み飛ばせる。自己記述的で
//! なければ版数の追加はハードフォークになってしまう。
//!
//! 参照: `docs/SPEC.md` §6.3, §7.1

use crate::codec::{write_var_bytes, CodecError, Decode, Encode, Reader};
use oag_primitives::address::{
    AddressError, MAX_PAYLOAD_LEN, MAX_VERSION, MIN_PAYLOAD_LEN, PUBKEY_PAYLOAD_LEN, VERSION_PUBKEY,
};
use oag_primitives::{Address, Network, PublicKey};

/// 出力の支払い条件。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Lock {
    version: u8,
    payload: Vec<u8>,
}

impl Lock {
    /// 構成要素から作る。
    ///
    /// 版数とペイロード長の整合はアドレスと同じ規則に従う。
    pub fn new(version: u8, payload: Vec<u8>) -> Result<Lock, AddressError> {
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
        Ok(Lock { version, payload })
    }

    /// Schnorr 公開鍵への支払い (版数 0)。
    pub fn pay_to_pubkey(pubkey: &PublicKey) -> Lock {
        Lock {
            version: VERSION_PUBKEY,
            payload: pubkey.to_bytes().to_vec(),
        }
    }

    /// **誰にも使えない**支払い条件 (版数 0、ペイロードは 32 バイトの 0)。
    ///
    /// 資金を焼却するために用いる。ジェネシスのブロック報酬がこれである
    /// (SPEC §14.4)。
    ///
    /// # なぜ使えないのか
    ///
    /// 32 バイトすべて 0 は secp256k1 の x-only 公開鍵として無効である
    /// (x = 0 に対応する曲線上の点が無い)。使おうとすると署名の検証手前で
    /// `PublicKey::from_slice` が失敗し、[`ValidationError::BadLockPubkey`]
    /// で断られる。
    ///
    /// **未知の版数として扱われるわけではない。** 未知の版数は誰でも使える
    /// (SPEC §10.4) ので、そちらに落ちていたら焼却にならない。版数 0 で
    /// あることが重要である。試験
    /// `an_output_locked_to_the_zero_key_cannot_be_spent` で確かめている。
    ///
    /// [`ValidationError::BadLockPubkey`]: crate::validate::ValidationError::BadLockPubkey
    pub fn unspendable() -> Lock {
        Lock {
            version: VERSION_PUBKEY,
            payload: vec![0u8; PUBKEY_PAYLOAD_LEN],
        }
    }

    /// アドレスから作る。
    pub fn from_address(address: &Address) -> Lock {
        Lock {
            version: address.version(),
            payload: address.payload().to_vec(),
        }
    }

    /// 指定したネットワークのアドレスとして表示する。
    pub fn to_address(&self, network: Network) -> Result<Address, AddressError> {
        Address::new(network, self.version, self.payload.clone())
    }

    /// 版数。
    pub fn version(&self) -> u8 {
        self.version
    }

    /// ペイロード。
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// この実装が意味を理解している版数か。
    pub fn is_known_version(&self) -> bool {
        self.version == VERSION_PUBKEY
    }

    /// 版数 0 の場合に公開鍵を取り出す。
    pub fn to_pubkey(&self) -> Option<PublicKey> {
        if self.version != VERSION_PUBKEY {
            return None;
        }
        PublicKey::from_slice(&self.payload).ok()
    }
}

impl Encode for Lock {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.version);
        write_var_bytes(&self.payload, out);
    }

    fn encoded_len(&self) -> usize {
        // 版数 1 バイト + 長さ接頭辞 1 バイト (ペイロードは 40 バイト以下) + 本体
        1 + 1 + self.payload.len()
    }
}

impl Decode for Lock {
    fn read_from(reader: &mut Reader<'_>) -> Result<Lock, CodecError> {
        let version = reader.read_u8()?;
        let payload = reader.read_var_bytes("lock.payload", MAX_PAYLOAD_LEN)?;
        Lock::new(version, payload.to_vec()).map_err(|e| match e {
            AddressError::VersionOutOfRange(v) => CodecError::ValueOutOfRange {
                field: "lock.version",
                value: u128::from(v),
            },
            _ => CodecError::LengthTooLarge {
                field: "lock.payload",
                actual: payload.len() as u128,
                max: MAX_PAYLOAD_LEN,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_primitives::SecretKey;

    fn pubkey() -> PublicKey {
        "0830053b6ac7f7b10243a8058fb5d9bc3ccdec622deadaa9da7f885f16dedc2e"
            .parse()
            .unwrap()
    }

    #[test]
    fn pay_to_pubkey_round_trip() {
        let lock = Lock::pay_to_pubkey(&pubkey());
        let bytes = lock.encode();
        assert_eq!(bytes.len(), 34, "版数 1 + 長さ 1 + 公開鍵 32");
        assert_eq!(lock.encoded_len(), bytes.len());
        assert_eq!(Lock::decode(&bytes).unwrap(), lock);
        assert_eq!(lock.to_pubkey(), Some(pubkey()));
    }

    #[test]
    fn address_round_trip() {
        let lock = Lock::pay_to_pubkey(&SecretKey::generate().public_key());
        for network in Network::ALL {
            let address = lock.to_address(network).unwrap();
            assert_eq!(Lock::from_address(&address), lock);
        }
    }

    #[test]
    fn unknown_version_is_decodable_but_not_known() {
        // 前方互換性: 版数を知らなくても読み飛ばせる (SPEC §6.3)。
        let lock = Lock::new(7, vec![0xab; 20]).unwrap();
        let decoded = Lock::decode(&lock.encode()).unwrap();
        assert_eq!(decoded, lock);
        assert!(!decoded.is_known_version());
        assert_eq!(decoded.to_pubkey(), None);
    }

    #[test]
    fn length_prefix_makes_outputs_skippable() {
        // 未知の版数の後ろにデータが続いていても、正しく境界を判定できる。
        let unknown = Lock::new(9, vec![0xcd; 40]).unwrap();
        let mut buf = unknown.encode();
        buf.extend_from_slice(b"following data");
        let mut reader = Reader::new(&buf);
        assert_eq!(Lock::read_from(&mut reader).unwrap(), unknown);
        assert_eq!(reader.remaining(), b"following data".len());
    }

    #[test]
    fn version_zero_requires_32_byte_payload() {
        assert!(matches!(
            Lock::new(VERSION_PUBKEY, vec![0u8; 20]),
            Err(AddressError::BadPayloadLength { .. })
        ));
        let mut bad = vec![VERSION_PUBKEY, 20];
        bad.extend_from_slice(&[0u8; 20]);
        assert!(Lock::decode(&bad).is_err());
    }

    #[test]
    fn rejects_oversized_payload() {
        let mut bad = vec![9u8];
        crate::codec::write_var_bytes(&[0xff; 41], &mut bad);
        assert!(matches!(
            Lock::decode(&bad),
            Err(CodecError::LengthTooLarge { max: 40, .. })
        ));
    }
}
