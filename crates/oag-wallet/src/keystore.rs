//! 鍵の保管。
//!
//! 種 ([`crate::seed`]) を**パスフレーズで暗号化して**保管する。鍵は種から
//! 導くため、ファイルに入っているのは種 1 つだけである。
//!
//! # 守り方
//!
//! | 手立て | 何から守るか |
//! | --- | --- |
//! | Argon2id でパスフレーズを伸ばす | 総当たり。専用機を用いても割に合わなくする |
//! | ChaCha20-Poly1305 で暗号化 | 中身を読まれること。改竄も検知する |
//! | ファイルの権限 0600 | 同じ機械の他の利用者 |
//! | 落ちるときに中身を消す | メモリやスワップに残ること |
//!
//! **控えは種 1 つで足りる。** アドレスをあとから何個増やしても、同じ
//! 控えで復元できる。
//!
//! # 何から守れないか
//!
//! - **パスフレーズが弱ければ守れない。** Argon2id は総当たりの費用を
//!   上げるだけであり、当てられる程度の合言葉を強くはしない
//! - 動作中のプロセスのメモリを読める相手からは守れない。復号した種は
//!   使っている間そこにある
//! - `secp256k1` が内部に持つ鍵の複製までは消せない。消せる範囲は
//!   こちらが持っているものに限られる
//!
//! # 形式
//!
//! ```json
//! {
//!   "version": 3,
//!   "network": "regtest",
//!   "kdf": { "algorithm": "argon2id", "salt": "<16 進>",
//!            "m_cost": 65536, "t_cost": 3, "p_cost": 1 },
//!   "cipher": { "algorithm": "chacha20poly1305", "nonce": "<16 進>" },
//!   "ciphertext": "<16 進>",
//!   "accounts": 1
//! }
//! ```
//!
//! 暗号文の中身は `エントロピーの長さ (1 バイト) ‖ エントロピー ‖ 種 (64)`
//! である。エントロピーを残すのは、控えの語をあとから表示し直すためである。
//! 種だけでは語に戻せない (BIP39 の種は PBKDF2 の出力である)。
//!
//! **版数 1 (平文で鍵を並べたもの) と版数 2 (独自導出の 32 バイトの種) は
//! 読めない。** BIP39 / BIP32 へ移す際、移行経路は用意しないと決めた
//! ([`docs/SPEC.md`] の §16.3)。移行前のウォレットは、秘密鍵を書き出して
//! 新しいウォレットへ送金し直すこと。テストネット公開前であり、
//! 守るべき資金が存在しない間に済ませる。
//!
//! [`docs/SPEC.md`]: https://github.com/Kazuhiro-Tokumoto/Orange/blob/main/docs/SPEC.md

use crate::bip39::{Bip39Error, Mnemonic};
use crate::seed::{Seed, SeedError, SEED_LEN};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use oag_consensus::lock::Lock;
use oag_primitives::{fill_random, Address, Network, SecretKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// この実装が読み書きする形式の版数。
pub const FORMAT_VERSION: u32 = 3;

/// ソルトの長さ。
const SALT_LEN: usize = 16;
/// ChaCha20-Poly1305 の nonce の長さ。
const NONCE_LEN: usize = 12;

/// Argon2id の使用メモリ (KiB)。64 MiB。
///
/// **総当たりの費用はここで決まる。** 大きいほど専用機で並列に試しにくい。
/// 手元の機械で 1 回あたり 0.1 秒程度に収まる範囲で選んである。
const ARGON_M_COST: u32 = 65_536;
/// Argon2id の反復回数。
const ARGON_T_COST: u32 = 3;
/// Argon2id の並列度。
const ARGON_P_COST: u32 = 1;

/// パスフレーズの最短の長さ。
///
/// 短いものを黙って受け入れると、暗号化しているのに守られていない状態に
/// なる。**守れないものは断る。**
pub const MIN_PASSPHRASE_LEN: usize = 8;

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
    #[error(
        "{path} は版数 {found} である。この実装が読めるのは {FORMAT_VERSION} のみ。\n\
         版数 1 (鍵を平文で並べたもの) と版数 2 (独自導出の種) は読めない。\n\
         BIP39 / BIP32 へ移す際に移行経路は用意しないと決めている。\n\
         古いウォレットの資金は、そちらの実装で送り出してから作り直すこと。"
    )]
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
    /// パスフレーズが違う、またはファイルが改竄されている。
    ///
    /// **どちらであるかは区別しない。** 区別できると、改竄したものを
    /// 投げ込んで反応を見る手掛かりになる。
    #[error("復号できない。パスフレーズが違うか、ファイルが壊れている")]
    CannotDecrypt,
    /// パスフレーズが短すぎる。
    #[error("パスフレーズは {MIN_PASSPHRASE_LEN} 文字以上であること")]
    WeakPassphrase,
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
    /// 鍵を導出できない。
    #[error(transparent)]
    Seed(#[from] SeedError),
    /// 控えの語を読めない。
    #[error(transparent)]
    Mnemonic(#[from] Bip39Error),
    /// 鍵の導出に失敗した。
    #[error("パスフレーズから鍵を導出できない: {0}")]
    Kdf(String),
}

/// 版数だけを読むための形。
#[derive(Deserialize)]
struct Versioned {
    version: u32,
}

/// ファイルに書き出す形。
#[derive(Serialize, Deserialize)]
struct Stored {
    version: u32,
    network: String,
    kdf: KdfParams,
    cipher: CipherParams,
    ciphertext: String,
    accounts: u32,
}

#[derive(Serialize, Deserialize)]
struct KdfParams {
    algorithm: String,
    salt: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Serialize, Deserialize)]
struct CipherParams {
    algorithm: String,
    nonce: String,
}

/// 開いたウォレット。
///
/// 種を復号した状態で保持する。落ちるときに消える。
pub struct Keystore {
    path: PathBuf,
    network: Network,
    /// 控えの語。**表示し直すためだけに持つ。**
    mnemonic: Mnemonic,
    seed: Seed,
    /// 導出済みの鍵の数。
    accounts: u32,
    /// 保存し直すために、暗号化のやり直しに要るもの。
    passphrase: Passphrase,
}

/// パスフレーズ。落ちるときに消す。
#[derive(Clone)]
struct Passphrase(Vec<u8>);

impl Drop for Passphrase {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keystore")
            .field("path", &self.path)
            .field("network", &self.network)
            .field("accounts", &self.accounts)
            .field("seed", &"<伏せ字>")
            .finish()
    }
}

impl Keystore {
    /// 新しいウォレットを作る。
    ///
    /// すでにファイルがあれば断る。**黙って上書きすると、そこにあった種で
    /// 守られていた資金を永久に失う。**
    ///
    /// 作った控えの語を返す。呼び出し側はこれを控えとして示すこと。
    ///
    /// `mnemonic_passphrase` は BIP39 の任意パスフレーズである。既定は
    /// 空文字列。**打ち間違えても失敗として現れない。**
    pub fn create(
        path: &Path,
        network: Network,
        passphrase: &[u8],
        mnemonic_passphrase: &str,
    ) -> Result<(Keystore, Mnemonic), KeystoreError> {
        let mnemonic = Mnemonic::generate();
        let store = Keystore::restore(path, network, passphrase, &mnemonic, mnemonic_passphrase)?;
        Ok((store, mnemonic))
    }

    /// 控えの語からウォレットを復元する。
    pub fn restore(
        path: &Path,
        network: Network,
        passphrase: &[u8],
        mnemonic: &Mnemonic,
        mnemonic_passphrase: &str,
    ) -> Result<Keystore, KeystoreError> {
        if path.exists() {
            return Err(KeystoreError::AlreadyExists(path.to_path_buf()));
        }
        check_passphrase(passphrase)?;

        let store = Keystore {
            path: path.to_path_buf(),
            network,
            seed: Seed::from_mnemonic(mnemonic, mnemonic_passphrase),
            mnemonic: mnemonic.clone(),
            accounts: 1,
            passphrase: Passphrase(passphrase.to_vec()),
        };
        // 経路が確定しないネットワークでは、鍵を 1 本も導けない。
        // **ファイルを作る前に断る。** 作ってしまうと、開くたびに失敗する
        // ウォレットが残る。
        store.seed.derive(network, 0)?;
        store.save()?;
        Ok(store)
    }

    /// 既存のウォレットを開く。
    pub fn open(
        path: &Path,
        network: Network,
        passphrase: &[u8],
    ) -> Result<Keystore, KeystoreError> {
        check_permissions(path)?;
        let mut text = std::fs::read_to_string(path).map_err(|source| KeystoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        // **版数を先に読む。** 中身の形は版数ごとに違うため、丸ごと読んで
        // から確かめると、古いファイルに対して「kdf が無い」といった
        // 的外れな説明を返すことになる。
        let probe: Versioned =
            serde_json::from_str(&text).map_err(|e| KeystoreError::Malformed {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;
        if probe.version != FORMAT_VERSION {
            text.zeroize();
            return Err(KeystoreError::UnknownVersion {
                path: path.to_path_buf(),
                found: probe.version,
            });
        }

        let stored: Stored = serde_json::from_str(&text).map_err(|e| KeystoreError::Malformed {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        text.zeroize();
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

        let malformed = |what: &str| KeystoreError::Malformed {
            path: path.to_path_buf(),
            message: what.to_string(),
        };
        if stored.kdf.algorithm != "argon2id" {
            return Err(malformed("知らない鍵導出方式"));
        }
        if stored.cipher.algorithm != "chacha20poly1305" {
            return Err(malformed("知らない暗号方式"));
        }
        let salt = from_hex(&stored.kdf.salt).ok_or_else(|| malformed("ソルトが読めない"))?;
        let nonce = from_hex(&stored.cipher.nonce).ok_or_else(|| malformed("nonce が読めない"))?;
        if nonce.len() != NONCE_LEN {
            return Err(malformed("nonce の長さが違う"));
        }
        let ciphertext =
            from_hex(&stored.ciphertext).ok_or_else(|| malformed("暗号文が読めない"))?;

        // **保存されたパラメータで導出する。** 現在の既定値で導出すると、
        // 古いファイルを開けなくなる。
        let mut key = derive_key(
            passphrase,
            &salt,
            stored.kdf.m_cost,
            stored.kdf.t_cost,
            stored.kdf.p_cost,
        )?;
        let aad = associated_data(&stored.network, stored.accounts);
        let plaintext = decrypt(&key, &nonce, &ciphertext, &aad);
        key.zeroize();

        let mut plaintext = plaintext.ok_or(KeystoreError::CannotDecrypt)?;
        let unpacked = unpack(&plaintext);
        plaintext.zeroize();
        let (mnemonic, seed) = unpacked?;

        Ok(Keystore {
            path: path.to_path_buf(),
            network,
            mnemonic,
            seed,
            accounts: stored.accounts.max(1),
            passphrase: Passphrase(passphrase.to_vec()),
        })
    }

    /// 鍵を 1 個増やし、そのアドレスを返す。
    ///
    /// 種は変わらない。**控えを取り直す必要はない。**
    pub fn add_key(&mut self) -> Result<Address, KeystoreError> {
        let index = self.accounts;
        let key = self.seed.derive(self.network, index)?;
        self.accounts += 1;
        self.save()?;
        Ok(Address::from_pubkey(self.network, &key.public_key()))
    }

    /// ネットワーク。
    pub fn network(&self) -> Network {
        self.network
    }

    /// 導出済みの鍵の数。
    pub fn len(&self) -> usize {
        self.accounts as usize
    }

    /// 鍵が無いか。開けたウォレットでは常に偽である。
    pub fn is_empty(&self) -> bool {
        self.accounts == 0
    }

    /// すべての秘密鍵。
    fn keys(&self) -> Result<Vec<SecretKey>, KeystoreError> {
        Ok(self.seed.derive_many(self.network, self.accounts)?)
    }

    /// すべてのアドレス。
    pub fn addresses(&self) -> Result<Vec<Address>, KeystoreError> {
        Ok(self
            .keys()?
            .iter()
            .map(|k| Address::from_pubkey(self.network, &k.public_key()))
            .collect())
    }

    /// 既定の受取先。最初の鍵のもの。
    pub fn default_address(&self) -> Result<Address, KeystoreError> {
        let key = self.seed.derive(self.network, 0)?;
        Ok(Address::from_pubkey(self.network, &key.public_key()))
    }

    /// すべての支払い条件。
    pub fn locks(&self) -> Result<Vec<Lock>, KeystoreError> {
        Ok(self
            .keys()?
            .iter()
            .map(|k| Lock::pay_to_pubkey(&k.public_key()))
            .collect())
    }

    /// 支払い条件に対応する秘密鍵。
    pub fn key_for(&self, lock: &Lock) -> Option<SecretKey> {
        self.keys()
            .ok()?
            .into_iter()
            .find(|k| Lock::pay_to_pubkey(&k.public_key()) == *lock)
    }

    /// 控えの語。**表示する以外に使ってはならない。**
    pub fn mnemonic(&self) -> &Mnemonic {
        &self.mnemonic
    }

    /// 暗号化して書き出す。
    ///
    /// ソルトと nonce は**保存のたびに作り直す**。同じ鍵と nonce で
    /// 2 度暗号化すると、ChaCha20 の鍵流が再利用され、平文の差分が漏れる。
    fn save(&self) -> Result<(), KeystoreError> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut salt);
        fill_random(&mut nonce);

        let mut key = derive_key(
            &self.passphrase.0,
            &salt,
            ARGON_M_COST,
            ARGON_T_COST,
            ARGON_P_COST,
        )?;
        let aad = associated_data(&self.network.to_string(), self.accounts);
        let mut payload = pack(&self.mnemonic, &self.seed);
        let ciphertext = encrypt(&key, &nonce, &payload, &aad);
        payload.zeroize();
        key.zeroize();
        let ciphertext = ciphertext?;

        let stored = Stored {
            version: FORMAT_VERSION,
            network: self.network.to_string(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: to_hex(&salt),
                m_cost: ARGON_M_COST,
                t_cost: ARGON_T_COST,
                p_cost: ARGON_P_COST,
            },
            cipher: CipherParams {
                algorithm: "chacha20poly1305".to_string(),
                nonce: to_hex(&nonce),
            },
            ciphertext: to_hex(&ciphertext),
            accounts: self.accounts,
        };
        let text = serde_json::to_string_pretty(&stored).expect("必ず JSON になる");

        write_atomically(&self.path, &text)
    }
}

/// 暗号文に収める平文を組み立てる。
///
/// `エントロピーの長さ (1 バイト) ‖ エントロピー ‖ 種 (64 バイト)`。
///
/// **エントロピーも収める。** 種だけでは控えの語に戻せない。BIP39 の種は
/// PBKDF2 の出力であり、一方向である。
fn pack(mnemonic: &Mnemonic, seed: &Seed) -> Vec<u8> {
    let entropy = mnemonic.entropy();
    let mut out = Vec::with_capacity(1 + entropy.len() + SEED_LEN);
    out.push(entropy.len() as u8);
    out.extend_from_slice(entropy);
    out.extend_from_slice(seed.as_bytes());
    out
}

/// [`pack`] の逆。
fn unpack(plaintext: &[u8]) -> Result<(Mnemonic, Seed), KeystoreError> {
    let bad = |what: &str| KeystoreError::Malformed {
        path: PathBuf::new(),
        message: what.to_string(),
    };
    let (&len, rest) = plaintext.split_first().ok_or_else(|| bad("暗号文が空"))?;
    let len = usize::from(len);
    if rest.len() != len + SEED_LEN {
        return Err(bad("復号した中身の長さが違う"));
    }
    let (entropy, seed) = rest.split_at(len);
    let mnemonic = Mnemonic::from_entropy(entropy)?;
    let mut bytes = [0u8; SEED_LEN];
    bytes.copy_from_slice(seed);
    let seed = Seed::from_bytes(bytes);
    // `bytes` は Copy なので、渡したあとも手元に残る。消す。
    bytes.zeroize();
    Ok((mnemonic, seed))
}

/// ファイルを**丸ごと置き換える**。途中で終わらない。
///
/// # なぜ上書きではいけないか
///
/// 上書きは「切り詰めてから書く」である。**切り詰めた直後に電源が落ちると、
/// 中身が空のウォレットが残る。** 種を失えば資金は取り戻せない。
///
/// 別名で書き切り、ディスクに届いたことを確かめてから、名前を付け替える。
/// 名前の付け替えは不可分であり、どちらかの中身が必ず残る。
fn write_atomically(path: &Path, text: &str) -> Result<(), KeystoreError> {
    let temp = path.with_extension(format!("tmp{}", std::process::id()));
    let io = |p: &Path| {
        let p = p.to_path_buf();
        move |source| KeystoreError::Io {
            path: p.clone(),
            source,
        }
    };

    let mut options = std::fs::OpenOptions::new();
    // **すでにあるものは使わない。** 他人が用意した名前に書かされると、
    // その中身を上書きさせられる。
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        // 権限は**作るときに**指定する。作ってから絞るのでは、その隙に
        // 他の利用者に読まれうる。
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    {
        let mut file = options.open(&temp).map_err(io(&temp))?;
        use std::io::Write;
        file.write_all(text.as_bytes()).map_err(io(&temp))?;
        // 名前を付け替える前に、中身がディスクに届いていること。
        file.sync_all().map_err(io(&temp))?;
    }

    match std::fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // 付け替えられなかったら、書きかけを残さない。
            let _ = std::fs::remove_file(&temp);
            Err(KeystoreError::Io {
                path: path.to_path_buf(),
                source: e,
            })
        }
    }
}

/// パスフレーズが短すぎないか。
fn check_passphrase(passphrase: &[u8]) -> Result<(), KeystoreError> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(KeystoreError::WeakPassphrase);
    }
    Ok(())
}

/// パスフレーズから 32 バイトの鍵を導出する。
fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], KeystoreError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    Ok(key)
}

/// 暗号文の外に置く項目を、認証の対象に含めるための文字列。
///
/// # なぜ要るのか
///
/// ネットワークとアドレスの数は暗号文の外にある。**書き換えられても
/// 復号は通ってしまう。** 数を減らされれば、持っているはずのアドレスが
/// 出てこなくなり、資金を失ったように見える。認証付きデータに含めれば、
/// 書き換えた時点で復号が失敗する。
fn associated_data(network: &str, accounts: u32) -> Vec<u8> {
    format!("oag-wallet-v{FORMAT_VERSION}\n{network}\n{accounts}\n").into_bytes()
}

fn encrypt(
    key: &[u8; 32],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
    let (cipher, nonce) = init(key, nonce)
        .ok_or_else(|| KeystoreError::Kdf("鍵または nonce の長さが違う".to_string()))?;
    cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| KeystoreError::Kdf("暗号化に失敗した".to_string()))
}

/// 鍵と nonce から暗号を用意する。長さが違えば `None`。
fn init(key: &[u8; 32], nonce: &[u8]) -> Option<(ChaCha20Poly1305, Nonce)> {
    let key = Key::try_from(&key[..]).ok()?;
    let nonce = Nonce::try_from(nonce).ok()?;
    Some((ChaCha20Poly1305::new(&key), nonce))
}

/// 復号する。**失敗の理由は返さない。**
///
/// パスフレーズ違いと改竄を区別できると、改竄したものを投げ込んで
/// 反応を見る手掛かりになる。
fn decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let (cipher, nonce) = init(key, nonce)?;
    cipher
        .decrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
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

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &[u8] = b"correct horse battery staple";

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
    fn a_new_wallet_reopens_with_the_passphrase() {
        let path = temp("new");
        let (store, _) = Keystore::create(&path, Network::Regtest, PASS, "").unwrap();
        let address = store.default_address().unwrap();

        let reopened = Keystore::open(&path, Network::Regtest, PASS).unwrap();
        assert_eq!(
            reopened.default_address().unwrap().to_string(),
            address.to_string()
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_wrong_passphrase_is_refused() {
        let path = temp("wrong");
        Keystore::create(&path, Network::Regtest, PASS, "").unwrap();
        assert!(matches!(
            Keystore::open(&path, Network::Regtest, b"wrong passphrase"),
            Err(KeystoreError::CannotDecrypt)
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_seed_is_not_in_the_file() {
        // **これが漏れていたら、暗号化した意味がない。**
        let path = temp("leak");
        let (_, mnemonic) = Keystore::create(&path, Network::Regtest, PASS, "").unwrap();
        let seed = Seed::from_mnemonic(&mnemonic, "");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(&*mnemonic.phrase()),
            "控えの語が平文で入っている"
        );

        // 導出される鍵も入っていないこと。
        for i in 0..3 {
            let key = seed.derive(Network::Regtest, i).unwrap();
            let hex: String = key.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
            assert!(!text.contains(&hex), "{i} 番目の鍵が平文で入っている");
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_tampered_file_is_refused() {
        // 認証付き暗号なので、1 バイト書き換えただけで復号に失敗する。
        let path = temp("tamper");
        Keystore::create(&path, Network::Regtest, PASS, "").unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let stored: serde_json::Value = serde_json::from_str(&text).unwrap();
        let mut ciphertext = stored["ciphertext"].as_str().unwrap().to_string();
        // 先頭の 1 文字を別のものに変える。
        let first = if ciphertext.starts_with('0') {
            '1'
        } else {
            '0'
        };
        ciphertext.replace_range(0..1, &first.to_string());

        let tampered = text.replace(stored["ciphertext"].as_str().unwrap(), &ciphertext);
        std::fs::write(&path, tampered).unwrap();

        assert!(matches!(
            Keystore::open(&path, Network::Regtest, PASS),
            Err(KeystoreError::CannotDecrypt)
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn saving_twice_uses_a_new_salt_and_nonce() {
        // 同じ鍵と nonce で 2 度暗号化すると、鍵流が再利用され平文の
        // 差分が漏れる。
        let path = temp("nonce");
        let (mut store, _) = Keystore::create(&path, Network::Regtest, PASS, "").unwrap();
        let first: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

        store.add_key().unwrap();
        let second: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

        assert_ne!(first["kdf"]["salt"], second["kdf"]["salt"], "ソルトが同じ");
        assert_ne!(
            first["cipher"]["nonce"], second["cipher"]["nonce"],
            "nonce が同じ"
        );
        assert_ne!(
            first["ciphertext"], second["ciphertext"],
            "同じ種なのに暗号文まで同じ"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_restored_seed_gives_back_the_same_addresses() {
        // **控えが効くことの確認である。** ここが通らなければ控えの意味がない。
        let path = temp("restore-a");
        let (mut store, mnemonic) = Keystore::create(&path, Network::Regtest, PASS, "").unwrap();
        store.add_key().unwrap();
        store.add_key().unwrap();
        let expected: Vec<String> = store
            .addresses()
            .unwrap()
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(expected.len(), 3);

        // 控えの語だけから復元する。ファイルは持っていない。
        let other = temp("restore-b");
        let mut restored =
            Keystore::restore(&other, Network::Regtest, PASS, &mnemonic, "").unwrap();
        // アドレスを増やした分は、増やし直せば同じものが出る。
        restored.add_key().unwrap();
        restored.add_key().unwrap();

        let got: Vec<String> = restored
            .addresses()
            .unwrap()
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(got, expected, "控えから復元したアドレスが違う");

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&other).unwrap();
    }

    #[test]
    fn adding_a_key_does_not_change_the_seed() {
        // 種が変わるなら、控えを取り直さなければならなくなる。
        let path = temp("stable");
        let (mut store, mnemonic) = Keystore::create(&path, Network::Regtest, PASS, "").unwrap();
        store.add_key().unwrap();
        assert_eq!(store.mnemonic().phrase(), mnemonic.phrase());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_mainnet_wallet_cannot_be_made_yet() {
        // mainnet のコインタイプ番号は SLIP-0044 に未登録であり、
        // 導出経路が確定しない (SPEC §6.6)。**ファイルを作る前に断る。**
        // 作ってしまうと、開くたびに失敗するウォレットが残る。
        let path = temp("mainnet");
        let err = Keystore::create(&path, Network::Mainnet, PASS, "").unwrap_err();
        assert!(
            matches!(err, KeystoreError::Seed(SeedError::CoinTypeUnregistered)),
            "{err:?}"
        );
        assert!(!path.exists(), "断ったのにファイルが残っている");
    }

    #[test]
    fn a_short_passphrase_is_refused() {
        // 守れないものを黙って受け入れると、暗号化しているのに
        // 守られていない状態になる。
        let path = temp("weak");
        assert!(matches!(
            Keystore::create(&path, Network::Regtest, b"short", ""),
            Err(KeystoreError::WeakPassphrase)
        ));
        assert!(!path.exists(), "断ったのにファイルができている");
    }

    #[test]
    fn creating_over_an_existing_wallet_is_refused() {
        let path = temp("exists");
        Keystore::create(&path, Network::Regtest, PASS, "").unwrap();
        assert!(matches!(
            Keystore::create(&path, Network::Regtest, PASS, ""),
            Err(KeystoreError::AlreadyExists(_))
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn opening_with_the_wrong_network_is_refused() {
        let path = temp("network");
        Keystore::create(&path, Network::Regtest, PASS, "").unwrap();
        assert!(matches!(
            Keystore::open(&path, Network::Testnet, PASS),
            Err(KeystoreError::WrongNetwork { .. })
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_wallet_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp("perm");
        Keystore::create(&path, Network::Regtest, PASS, "").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "作ったときの権限が緩い");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Keystore::open(&path, Network::Regtest, PASS),
            Err(KeystoreError::TooPermissive { .. })
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_plaintext_format_is_refused() {
        // 版数 1 は鍵を平文で並べていた。読めるようにしておくと、
        // 平文のまま使い続けられてしまう。
        let path = temp("v1");
        std::fs::write(&path, r#"{"version":1,"network":"regtest","keys":["00"]}"#).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            Keystore::open(&path, Network::Regtest, PASS),
            Err(KeystoreError::UnknownVersion { found: 1, .. })
        ));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn changing_the_account_count_is_detected() {
        // アドレスの数は暗号文の外にある。認証の対象に含めていなければ、
        // 書き換えられても復号が通ってしまう。数を減らされると、
        // 持っているはずのアドレスが出てこなくなる。
        let path = temp("aad-accounts");
        let (mut store, _) = Keystore::create(&path, Network::Regtest, PASS, "").unwrap();
        store.add_key().unwrap();
        store.add_key().unwrap();
        assert_eq!(store.len(), 3);

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"accounts\": 3", "\"accounts\": 1")).unwrap();

        assert!(
            matches!(
                Keystore::open(&path, Network::Regtest, PASS),
                Err(KeystoreError::CannotDecrypt)
            ),
            "アドレスの数を書き換えられても開けてしまう"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn changing_the_network_is_detected() {
        // ネットワークも暗号文の外にある。
        let path = temp("aad-network");
        Keystore::create(&path, Network::Regtest, PASS, "").unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"regtest\"", "\"testnet\"")).unwrap();

        // ネットワークの食い違いとしてまず断られる。
        assert!(matches!(
            Keystore::open(&path, Network::Regtest, PASS),
            Err(KeystoreError::WrongNetwork { .. })
        ));
        // 書き換えた側で開こうとしても、復号が通らない。
        assert!(
            matches!(
                Keystore::open(&path, Network::Testnet, PASS),
                Err(KeystoreError::CannotDecrypt)
            ),
            "ネットワークを書き換えられても開けてしまう"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_failed_save_leaves_the_old_wallet_intact() {
        // 書き換えは別名で書き切ってから名前を付け替える。途中で
        // 終わっても、元の中身か新しい中身のどちらかが必ず残る。
        let path = temp("atomic");
        let (mut store, mnemonic) = Keystore::create(&path, Network::Regtest, PASS, "").unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        store.add_key().unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert_ne!(before, after, "書き換わっていない");

        // 書きかけのファイルが残っていないこと。
        let dir = path.parent().unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "書きかけが残っている: {leftovers:?}");

        // 種は変わらず、開き直せる。
        let reopened = Keystore::open(&path, Network::Regtest, PASS).unwrap();
        assert_eq!(reopened.mnemonic().phrase(), mnemonic.phrase());
        assert_eq!(reopened.len(), 2);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn two_wallets_do_not_share_a_seed() {
        // 乱数源が壊れていれば、ここで気づく。
        let a = temp("rand-a");
        let b = temp("rand-b");
        let (_, sa) = Keystore::create(&a, Network::Regtest, PASS, "").unwrap();
        let (_, sb) = Keystore::create(&b, Network::Regtest, PASS, "").unwrap();
        assert_ne!(
            sa.phrase(),
            sb.phrase(),
            "違うウォレットが同じ種を持っている"
        );
        std::fs::remove_file(&a).unwrap();
        std::fs::remove_file(&b).unwrap();
    }

    #[test]
    fn the_seed_is_not_printed() {
        let path = temp("debug");
        let (store, mnemonic) = Keystore::create(&path, Network::Regtest, PASS, "").unwrap();
        let text = format!("{store:?}");
        assert!(
            !text.contains(&*mnemonic.phrase()),
            "控えの語が漏れている: {text}"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_key_for_a_lock_is_found() {
        let path = temp("lookup");
        let (mut store, _) = Keystore::create(&path, Network::Regtest, PASS, "").unwrap();
        store.add_key().unwrap();

        for lock in store.locks().unwrap() {
            let key = store.key_for(&lock).expect("自分の条件の鍵は引ける");
            assert_eq!(Lock::pay_to_pubkey(&key.public_key()), lock);
        }
        let stranger = Lock::pay_to_pubkey(&SecretKey::generate().public_key());
        assert!(store.key_for(&stranger).is_none());
        std::fs::remove_file(&path).unwrap();
    }
}
