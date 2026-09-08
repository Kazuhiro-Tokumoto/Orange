//! 種と、そこからの鍵の導出。
//!
//! # なぜ種を持つのか
//!
//! 鍵を 1 個ずつ作って並べる方式では、**アドレスを増やすたびに控えが
//! 古くなる**。増やしたあとに控えから復元すると、新しいアドレスの資金が
//! 見えない。種から導けば、控えは 1 つで済み、あとから何個増やしても
//! 同じ控えで復元できる。
//!
//! # 経路
//!
//! BIP44 に従う ([`docs/SPEC.md`] の §6.6)。
//!
//! ```text
//! m / 44' / <coin_type>' / 0' / 0 / <index>
//! ```
//!
//! 控えは BIP39 の 12 語であり、そこから BIP39 の 64 バイトの種を作り、
//! BIP32 でこの経路をたどる。
//!
//! [`docs/SPEC.md`]: https://github.com/Kazuhiro-Tokumoto/Orange/blob/main/docs/SPEC.md

use crate::bip32::{Bip32Error, ExtendedKey, HARDENED};
use crate::bip39::Mnemonic;
use oag_primitives::{Network, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// BIP39 の種の長さ。
pub const SEED_LEN: usize = crate::bip39::SEED_LEN;

/// BIP44 の用途番号。
const PURPOSE: u32 = 44;

/// テストネット用のコインタイプ番号。
///
/// SLIP-0044 が**全コインのテストネット用に予約している**番号である。
/// 登録は要らない。regtest もこれを用いる。
const COIN_TYPE_TESTNET: u32 = 1;

/// 使う口座番号。いまは 1 つだけ。
const ACCOUNT: u32 = 0;

/// 受取用の枝。1 はお釣り用だが、いまは使っていない。
const CHANGE_RECEIVE: u32 = 0;

/// ウォレットの種。BIP39 の 64 バイト。
///
/// 落ちるときに中身を消す。`Debug` でも中身を出さない。
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; SEED_LEN]);

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(<伏せ字>)")
    }
}

/// 種の扱いで起きる失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SeedError {
    /// mainnet のコインタイプ番号がまだ決まっていない。
    #[error(
        "mainnet のコインタイプ番号は SLIP-0044 に未登録であり、導出経路を確定できない。\n\
         暫定の番号で運用すると、登録された番号へ移した時点で同じ控えから導かれる鍵が\n\
         変わる。それは資金が消えたのと区別がつかない。\n\
         testnet または regtest を使うこと (--network testnet)。"
    )]
    CoinTypeUnregistered,
    /// 鍵を導出できなかった。
    #[error("{index} 番目の鍵を導出できない")]
    Underivable {
        /// 導出しようとした番号。
        index: u32,
    },
}

impl From<Bip32Error> for SeedError {
    fn from(e: Bip32Error) -> SeedError {
        match e {
            Bip32Error::Underivable { index } => SeedError::Underivable { index },
            // 種の長さは常に 64 バイトであり、ここへは来ない。
            Bip32Error::BadSeedLength { .. } => SeedError::Underivable { index: 0 },
        }
    }
}

/// ネットワークのコインタイプ番号。
///
/// mainnet は未登録である。**暫定の番号を返さない。**
pub fn coin_type(network: Network) -> Result<u32, SeedError> {
    match network {
        Network::Testnet | Network::Regtest => Ok(COIN_TYPE_TESTNET),
        Network::Mainnet => Err(SeedError::CoinTypeUnregistered),
    }
}

impl Seed {
    /// ニーモニックと追加パスフレーズから作る。
    pub fn from_mnemonic(mnemonic: &Mnemonic, passphrase: &str) -> Seed {
        Seed(*mnemonic.to_seed(passphrase))
    }

    /// バイト列から作る。保存したものを読み戻すために用いる。
    pub fn from_bytes(bytes: [u8; SEED_LEN]) -> Seed {
        Seed(bytes)
    }

    /// バイト列。暗号化して保存するために用いる。
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }

    /// `index` 番目の鍵を導出する。
    pub fn derive(&self, network: Network, index: u32) -> Result<SecretKey, SeedError> {
        let path = [
            PURPOSE | HARDENED,
            coin_type(network)? | HARDENED,
            ACCOUNT | HARDENED,
            CHANGE_RECEIVE,
            index,
        ];
        let node = ExtendedKey::master(&self.0)?.derive_path(&path)?;
        Ok(node.secret_key().clone())
    }

    /// 先頭から `count` 個の鍵を導出する。
    pub fn derive_many(&self, network: Network, count: u32) -> Result<Vec<SecretKey>, SeedError> {
        // 経路の途中までは共通である。1 個ずつ主鍵から辿ると、鍵の数だけ
        // HMAC を繰り返すことになる。
        let branch = [
            PURPOSE | HARDENED,
            coin_type(network)? | HARDENED,
            ACCOUNT | HARDENED,
            CHANGE_RECEIVE,
        ];
        let node = ExtendedKey::master(&self.0)?.derive_path(&branch)?;
        (0..count)
            .map(|i| Ok(node.derive_child(i)?.secret_key().clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39::Mnemonic;

    fn seed() -> Seed {
        let mnemonic = Mnemonic::from_entropy(&[7u8; 16]).unwrap();
        Seed::from_mnemonic(&mnemonic, "")
    }

    #[test]
    fn mainnet_has_no_coin_type_yet() {
        // **暫定の番号を返してはならない。** 返してしまうと、登録された
        // 番号へ移した時点で同じ控えから別の鍵が出る。
        assert_eq!(
            coin_type(Network::Mainnet).unwrap_err(),
            SeedError::CoinTypeUnregistered
        );
        assert_eq!(
            seed().derive(Network::Mainnet, 0).unwrap_err(),
            SeedError::CoinTypeUnregistered
        );
        assert_eq!(
            seed().derive_many(Network::Mainnet, 3).unwrap_err(),
            SeedError::CoinTypeUnregistered
        );
    }

    #[test]
    fn the_test_networks_use_the_reserved_number() {
        // SLIP-0044 が全コインのテストネット用に 1 を予約している。
        assert_eq!(coin_type(Network::Testnet).unwrap(), COIN_TYPE_TESTNET);
        assert_eq!(coin_type(Network::Regtest).unwrap(), COIN_TYPE_TESTNET);
    }

    #[test]
    fn the_same_seed_derives_the_same_keys() {
        // ここが揺らぐと、控えから復元しても資金が見えない。
        let a = seed().derive_many(Network::Testnet, 5).unwrap();
        let b = seed().derive_many(Network::Testnet, 5).unwrap();
        for (x, y) in a.iter().zip(&b) {
            assert_eq!(x.to_bytes(), y.to_bytes());
        }
    }

    #[test]
    fn deriving_many_agrees_with_deriving_one() {
        // derive_many は経路の途中までを使い回す近道である。**近道が
        // 本道と食い違えば、アドレスの一覧と実際の鍵がずれる。**
        let seed = seed();
        let many = seed.derive_many(Network::Testnet, 4).unwrap();
        for (i, key) in many.iter().enumerate() {
            let one = seed.derive(Network::Testnet, i as u32).unwrap();
            assert_eq!(key.to_bytes(), one.to_bytes(), "{i} 番目");
        }
    }

    #[test]
    fn the_path_is_the_one_bip44_defines() {
        // 経路を手で組み立てたものと突き合わせる。定数を書き換えたら
        // ここで落ちる。
        let seed = seed();
        let expected = ExtendedKey::master(seed.as_bytes())
            .unwrap()
            .derive_path(&[44 | HARDENED, 1 | HARDENED, HARDENED, 0, 3])
            .unwrap();
        assert_eq!(
            seed.derive(Network::Testnet, 3).unwrap().to_bytes(),
            expected.secret_key().to_bytes()
        );
    }

    #[test]
    fn different_indices_give_different_keys() {
        let seed = seed();
        let keys: Vec<[u8; 32]> = (0..8)
            .map(|i| seed.derive(Network::Testnet, i).unwrap().to_bytes())
            .collect();
        for (i, a) in keys.iter().enumerate() {
            for (j, b) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "{i} 番と {j} 番が同じ");
                }
            }
        }
    }

    #[test]
    fn the_bip39_passphrase_changes_every_key() {
        let mnemonic = Mnemonic::from_entropy(&[7u8; 16]).unwrap();
        let plain = Seed::from_mnemonic(&mnemonic, "");
        let salted = Seed::from_mnemonic(&mnemonic, "x");
        assert_ne!(
            plain.derive(Network::Testnet, 0).unwrap().to_bytes(),
            salted.derive(Network::Testnet, 0).unwrap().to_bytes()
        );
    }

    #[test]
    fn the_seed_is_not_printed() {
        assert_eq!(format!("{:?}", seed()), "Seed(<伏せ字>)");
    }
}
