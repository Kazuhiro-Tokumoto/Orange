//! RPC の合言葉。
//!
//! bitcoind と同じ考え方を採る。ノードは起動のたびに使い捨ての合言葉を
//! 作り、データディレクトリの `.cookie` に書く。同じ機械の同じ利用者だけが
//! それを読めるため、設定ファイルにパスワードを書かせずに済む。
//!
//! # なぜ設定ファイルに書かせないのか
//!
//! 書かせると、そのファイルが複製され、履歴に残り、共有される。
//! 使い捨てにすれば、漏れても次の起動で無効になる。
//!
//! # 権限
//!
//! ファイルは**所有者だけが読める**権限で作る。同じ機械の別の利用者から
//! 守るためである。作ってから権限を絞るのでは、その隙に読まれうる。

use std::io::Write;
use std::path::{Path, PathBuf};

/// 合言葉を書き出すファイルの名前。
pub const COOKIE_FILE: &str = ".cookie";

/// 合言葉の利用者名。bitcoind に倣う。
pub const COOKIE_USER: &str = "__cookie__";

/// 合言葉の扱いで起きる失敗。
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// ファイルを読み書きできない。
    #[error("{path} を扱えない: {source}")]
    Io {
        /// 対象のファイル。
        path: PathBuf,
        /// 元の誤り。
        source: std::io::Error,
    },
    /// ファイルの中身が合言葉の形をしていない。
    #[error("{0} の中身が合言葉の形をしていない")]
    Malformed(PathBuf),
}

/// RPC の合言葉。
///
/// `Debug` では中身を伏せる。取り違えて記録に残すと、それを見た者が
/// ノードを操作できてしまう。
#[derive(Clone, PartialEq, Eq)]
pub struct Credential(String);

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential(<伏せ字>)")
    }
}

impl Credential {
    /// `利用者名:合言葉` の形から作る。
    pub fn from_userpass(userpass: &str) -> Credential {
        Credential(format!("Basic {}", base64(userpass.as_bytes())))
    }

    /// 使い捨ての合言葉を作る。
    ///
    /// 乱数は鍵と同じ源から取る。推測できると、ノードを操作されうる。
    pub fn generate(random_bytes: [u8; 32]) -> Credential {
        let hex: String = random_bytes.iter().map(|b| format!("{b:02x}")).collect();
        Credential::from_userpass(&format!("{COOKIE_USER}:{hex}"))
    }

    /// `Authorization` ヘッダに入れる文字列。
    pub fn header_value(&self) -> &str {
        &self.0
    }
}

/// 合言葉をファイルに書き出す。
///
/// 所有者だけが読める権限で作る。すでにあれば上書きする。
pub fn write_cookie(dir: &Path, userpass: &str) -> Result<PathBuf, AuthError> {
    let path = dir.join(COOKIE_FILE);
    let io = |source| AuthError::Io {
        path: path.clone(),
        source,
    };

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        // 権限は**作るときに**指定する。作ってから絞るのでは、その隙に
        // 他の利用者に読まれうる。
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&path).map_err(io)?;
    file.write_all(userpass.as_bytes()).map_err(io)?;
    file.flush().map_err(io)?;
    Ok(path)
}

/// 書き出された合言葉を読む。
pub fn read_cookie(dir: &Path) -> Result<Credential, AuthError> {
    let path = dir.join(COOKIE_FILE);
    let text = std::fs::read_to_string(&path).map_err(|source| AuthError::Io {
        path: path.clone(),
        source,
    })?;
    let text = text.trim();
    if !text.contains(':') || text.is_empty() {
        return Err(AuthError::Malformed(path));
    }
    Ok(Credential::from_userpass(text))
}

/// base64 (RFC 4648 の標準表)。
///
/// HTTP Basic 認証のためだけに要る。この一箇所のために依存を増やす
/// 必要はない。
fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(TABLE[(triple >> 18) as usize & 0x3F] as char);
        out.push(TABLE[(triple >> 12) as usize & 0x3F] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(triple >> 6) as usize & 0x3F] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[triple as usize & 0x3F] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_vectors() {
        // RFC 4648 §10。
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn the_header_is_http_basic() {
        // RFC 7617 の例。
        let credential = Credential::from_userpass("Aladdin:open sesame");
        assert_eq!(
            credential.header_value(),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn the_credential_is_not_printed() {
        let credential = Credential::from_userpass("user:hunter2");
        let text = format!("{credential:?}");
        assert!(!text.contains("hunter2"), "合言葉が漏れている: {text}");
        assert!(!text.contains("dXNlcjpodW50ZXIy"), "符号化しても漏れている");
    }

    #[test]
    fn a_generated_credential_depends_on_the_random_bytes() {
        let a = Credential::generate([1u8; 32]);
        let b = Credential::generate([2u8; 32]);
        assert_ne!(a, b);
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("oag-auth-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_written_cookie_reads_back() {
        let dir = temp_dir("round");
        let userpass = format!("{COOKIE_USER}:0123456789abcdef");
        write_cookie(&dir, &userpass).unwrap();
        assert_eq!(
            read_cookie(&dir).unwrap(),
            Credential::from_userpass(&userpass)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_cookie_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perm");
        let path = write_cookie(&dir, "__cookie__:secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "権限が緩い: {:o}", mode & 0o777);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_cookie_without_a_colon_is_refused() {
        let dir = temp_dir("bad");
        write_cookie(&dir, "合言葉の形をしていない").unwrap();
        assert!(matches!(read_cookie(&dir), Err(AuthError::Malformed(_))));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
