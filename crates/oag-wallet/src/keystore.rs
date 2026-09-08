//! 鍵の保管。
//!
//! # 平文で保管している
//!
//! **このファイルを読めた者は資金を動かせる。** 暗号化していないため、
//! ファイルの権限だけが守りである。所有者だけが読める権限で作り、
//! 読むときも権限を確かめる。
//!
//! パスフレーズによる暗号化は未実装である
//! (`docs/SPEC.md` の未決事項)。中途半端な暗号化は、守られているという
//! 誤解を与える分だけ、平文より危険になりうる。**守りが権限だけである
//! ことを、隠さずに言う**方を選んだ。
//!
//! # 形式
//!
//! ```json
//! {
//!   "version": 1,
//!   "network": "regtest",
//!   "keys": ["<秘密鍵 32 バイトの 16 進>", ...]
//! }
//! ```
//!
//! 鍵は作った順に並ぶ。最初の 1 個が既定の受取先である。

use oag_consensus::lock::Lock;
use oag_primitives::{Address, Network, SecretKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// この実装が書き出す形式の版数。
pub const FORMAT_VERSION: u32 = 1;

/// 鍵の保管で起きる失敗。
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// ファイルを読み書きできない。
    #[error("{path} を扱えない: {source}")]
    Io {
        /// 対象のファイル。
        path: PathBuf,
        /// 元の誤り。
        source: std::io::Error,
    },
    /// 中身が読めない。
    #[error("{path} を読めない: {message}")]
    Malformed {
        /// 対象のファイル。
        path: PathBuf,
        /// 理由。
        message: String,
    },
    /// 知らない形式の版数。
    #[error("{path} は版数 {found} である。この実装が読めるのは {FORMAT_VERSION} まで")]
    UnknownVersion {
        /// 対象のファイル。
        path: PathBuf,
        /// ファイルに書かれていた版数。
        found: u32,
    },
    /// ネットワークが食い違う。
    #[error("このウォレットは {stored} のものである ({asked} として開こうとした)")]
    WrongNetwork {
        /// ファイルに書かれていたネットワーク。
        stored: Network,
        /// 開こうとしたネットワーク。
        asked: Network,
    },
    /// 権限が緩い。
    #[error("{path} を所有者以外が読める ({mode:o})。chmod 600 で直すこと")]
    TooPermissive {
        /// 対象のファイル。
        path: PathBuf,
        /// 実際の権限。
        mode: u32,
    },
    /// すでに存在する。
    #[error("{0} はすでにある。消すか、別の名前を指定すること")]
    AlreadyExists(PathBuf),
    /// 鍵が 1 個も無い。
    #[error("鍵が 1 個も無い")]
    Empty,
}

/// ファイルに書き出す形。
#[derive(Serialize, Deserialize)]
struct Stored {
    version: u32,
    network: String,
    keys: Vec<String>,
}

/// 鍵の束。
///
/// `Debug` では鍵の中身を伏せる。
pub struct Keystore {
    path: PathBuf,
    network: Network,
    keys: Vec<SecretKey>,
}

impl std::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keystore")
            .field("path", &self.path)
            .field("network", &self.network)
            .field("keys", &format!("{} 個 (中身は伏せる)", self.keys.len()))
            .finish()
    }
}

impl Keystore {
    /// 鍵を 1 個持つウォレットを新しく作る。
    ///
    /// すでにファイルがあれば断る。**黙って上書きすると、そこにあった鍵で
    /// 守られていた資金を永久に失う。**
    pub fn create(path: &Path, network: Network) -> Result<Keystore, KeystoreError> {
        if path.exists() {
            return Err(KeystoreError::AlreadyExists(path.to_path_buf()));
        }
        let store = Keystore {
            path: path.to_path_buf(),
            network,
            keys: vec![SecretKey::generate()],
        };
        store.save()?;
        Ok(store)
    }

    /// 既存のウォレットを開く。
    pub fn open(path: &Path, network: Network) -> Result<Keystore, KeystoreError> {
        check_permissions(path)?;
        let text = std::fs::read_to_string(path).map_err(|source| KeystoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let stored: Stored = serde_json::from_str(&text).map_err(|e| KeystoreError::Malformed {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;

        if stored.version > FORMAT_VERSION {
            return Err(KeystoreError::UnknownVersion {
                path: path.to_path_buf(),
                found: stored.version,
            });
        }
        let stored_network: Network =
            stored
                .network
                .parse()
                .map_err(|_| KeystoreError::Malformed {
                    path: path.to_path_buf(),
                    message: format!("知らないネットワーク: {}", stored.network),
                })?;
        // ネットワークを取り違えると、別のチェーンのアドレスへ送りかねない。
        if stored_network != network {
            return Err(KeystoreError::WrongNetwork {
                stored: stored_network,
                asked: network,
            });
        }

        let mut keys = Vec::with_capacity(stored.keys.len());
        for (n, hex) in stored.keys.iter().enumerate() {
            keys.push(parse_key(hex).ok_or_else(|| KeystoreError::Malformed {
                path: path.to_path_buf(),
                message: format!("{n} 番目の鍵が読めない"),
            })?);
        }
        if keys.is_empty() {
            return Err(KeystoreError::Empty);
        }

        Ok(Keystore {
            path: path.to_path_buf(),
            network,
            keys,
        })
    }

    /// 鍵を 1 個増やし、そのアドレスを返す。
    pub fn add_key(&mut self) -> Result<Address, KeystoreError> {
        let key = SecretKey::generate();
        let address = Address::from_pubkey(self.network, &key.public_key());
        self.keys.push(key);
        self.save()?;
        Ok(address)
    }

    /// ネットワーク。
    pub fn network(&self) -> Network {
        self.network
    }

    /// 鍵の数。
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// 鍵が無いか。開けたウォレットでは常に偽である。
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// すべてのアドレス。
    pub fn addresses(&self) -> Vec<Address> {
        self.keys
            .iter()
            .map(|k| Address::from_pubkey(self.network, &k.public_key()))
            .collect()
    }

    /// 既定の受取先。最初に作った鍵のもの。
    pub fn default_address(&self) -> Address {
        Address::from_pubkey(self.network, &self.keys[0].public_key())
    }

    /// すべての支払い条件。
    pub fn locks(&self) -> Vec<Lock> {
        self.keys
            .iter()
            .map(|k| Lock::pay_to_pubkey(&k.public_key()))
            .collect()
    }

    /// 支払い条件に対応する秘密鍵。
    pub fn key_for(&self, lock: &Lock) -> Option<SecretKey> {
        self.keys
            .iter()
            .find(|k| Lock::pay_to_pubkey(&k.public_key()) == *lock)
            .cloned()
    }

    /// ファイルに書き出す。所有者だけが読める権限で作る。
    fn save(&self) -> Result<(), KeystoreError> {
        let stored = Stored {
            version: FORMAT_VERSION,
            network: self.network.to_string(),
            keys: self
                .keys
                .iter()
                .map(|k| k.to_bytes().iter().map(|b| format!("{b:02x}")).collect())
                .collect(),
        };
        let text = serde_json::to_string_pretty(&stored).expect("必ず JSON になる");

        let io = |source| KeystoreError::Io {
            path: self.path.clone(),
            source,
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            // 権限は**作るときに**指定する。作ってから絞るのでは、その
            // 隙に他の利用者に読まれうる。
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.path).map_err(io)?;
        use std::io::Write;
        file.write_all(text.as_bytes()).map_err(io)?;
        file.flush().map_err(io)?;
        Ok(())
    }
}

/// 所有者以外が読めるなら断る。
fn check_permissions(path: &Path) -> Result<(), KeystoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path).map_err(|source| KeystoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(KeystoreError::TooPermissive {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn parse_key(hex: &str) -> Option<SecretKey> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    SecretKey::from_bytes(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("oag-ks-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("wallet.json")
    }

    #[test]
    fn a_new_wallet_has_one_key_and_reopens() {
        let path = temp("new");
        let store = Keystore::create(&path, Network::Regtest).unwrap();
        assert_eq!(store.len(), 1);
        let address = store.default_address();

        let reopened = Keystore::open(&path, Network::Regtest).unwrap();
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.default_address().to_string(), address.to_string());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn adding_a_key_persists() {
        let path = temp("add");
        let mut store = Keystore::create(&path, Network::Regtest).unwrap();
        let second = store.add_key().unwrap();
        assert_eq!(store.len(), 2);

        let reopened = Keystore::open(&path, Network::Regtest).unwrap();
        assert_eq!(reopened.len(), 2);
        assert!(reopened
            .addresses()
            .iter()
            .any(|a| a.to_string() == second.to_string()));
        // 既定の受取先は変わらない。増やすたびに変わると、以前に配った
        // アドレスが「既定」でなくなり、案内が食い違う。
        assert_eq!(
            reopened.default_address().to_string(),
            store.default_address().to_string()
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn creating_over_an_existing_wallet_is_refused() {
        // 黙って上書きすると、そこにあった鍵で守られていた資金を失う。
        let path = temp("exists");
        Keystore::create(&path, Network::Regtest).unwrap();
        assert!(matches!(
            Keystore::create(&path, Network::Regtest),
            Err(KeystoreError::AlreadyExists(_))
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn opening_with_the_wrong_network_is_refused() {
        let path = temp("network");
        Keystore::create(&path, Network::Regtest).unwrap();
        assert!(matches!(
            Keystore::open(&path, Network::Testnet),
            Err(KeystoreError::WrongNetwork { .. })
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_wallet_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp("perm");
        Keystore::create(&path, Network::Regtest).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "作ったときの権限が緩い");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Keystore::open(&path, Network::Regtest),
            Err(KeystoreError::TooPermissive { .. })
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_future_format_version_is_refused() {
        // 読めない形式を読めたことにすると、鍵を取りこぼしたまま
        // 「残高 0」と表示しかねない。
        let path = temp("version");
        Keystore::create(&path, Network::Regtest).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"version\": 1", "\"version\": 99")).unwrap();
        assert!(matches!(
            Keystore::open(&path, Network::Regtest),
            Err(KeystoreError::UnknownVersion { found: 99, .. })
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_key_for_a_lock_is_found() {
        let path = temp("lookup");
        let mut store = Keystore::create(&path, Network::Regtest).unwrap();
        store.add_key().unwrap();

        for lock in store.locks() {
            let key = store.key_for(&lock).expect("自分の条件の鍵は引ける");
            assert_eq!(Lock::pay_to_pubkey(&key.public_key()), lock);
        }
        let stranger = Lock::pay_to_pubkey(&SecretKey::generate().public_key());
        assert!(store.key_for(&stranger).is_none());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_keys_are_not_printed() {
        let path = temp("debug");
        let store = Keystore::create(&path, Network::Regtest).unwrap();
        let text = format!("{store:?}");
        for key in &store.keys {
            let hex: String = key.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
            assert!(!text.contains(&hex), "秘密鍵が漏れている: {text}");
        }
        std::fs::remove_file(&path).unwrap();
    }
}
