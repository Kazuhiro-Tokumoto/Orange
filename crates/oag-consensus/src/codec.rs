//! 正準シリアライズ。
//!
//! コンセンサスに関わる符号化では、**同一の値が複数のバイト列で表現できては
//! ならない**。そのような曖昧さは、内容が同じでありながら異なる txid を持つ
//! トランザクション (展性) を生み、事前署名した取引を無効化できる。
//!
//! 本モジュールは以下を強制する。
//!
//! - varint は最短形のみ (`oag_primitives::varint` が保証する)
//! - 復号後に余剰バイトがあれば拒否する
//! - 個数フィールドは残りバイト数を超えられない (割り当て量の爆発を防ぐ)
//!
//! 参照: `docs/SPEC.md` §2, §7

use oag_primitives::amount::AmountError;
use oag_primitives::hash::HASH_LEN;
use oag_primitives::varint::{self, VarIntError};
use oag_primitives::{Amount, Hash};

/// 符号化・復号で起きうる誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// 入力が途中で終端した。
    #[error("入力が不足している: {needed} バイト必要だが {remaining} バイトしかない")]
    UnexpectedEof {
        /// 必要なバイト数。
        needed: usize,
        /// 残っているバイト数。
        remaining: usize,
    },
    /// 復号後にバイトが残っている。
    #[error("復号後に {0} バイトが余っている")]
    TrailingBytes(usize),
    /// varint が不正。
    #[error(transparent)]
    VarInt(#[from] VarIntError),
    /// 金額が不正。
    #[error(transparent)]
    Amount(#[from] AmountError),
    /// 個数フィールドが残りバイト数を超えている。
    #[error("{field} の個数 {declared} が残り {remaining} バイトに対して大きすぎる")]
    CountTooLarge {
        /// フィールド名。
        field: &'static str,
        /// 宣言された個数。
        declared: u128,
        /// 残っているバイト数。
        remaining: usize,
    },
    /// 値がフィールドの表現範囲を超えている。
    #[error("{field} の値 {value} が範囲外")]
    ValueOutOfRange {
        /// フィールド名。
        field: &'static str,
        /// 実際の値。
        value: u128,
    },
    /// 可変長フィールドが上限を超えている。
    #[error("{field} の長さ {actual} が上限 {max} を超えている")]
    LengthTooLarge {
        /// フィールド名。
        field: &'static str,
        /// 実際の長さ。
        actual: u128,
        /// 許される上限。
        max: usize,
    },
}

/// バイト列を先頭から読み進める。
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// 新しい読み取り器を作る。
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    /// 残りバイト数。
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// 消費済みバイト数。
    pub fn position(&self) -> usize {
        self.pos
    }

    /// すべて読み切ったことを確認する。余剰があれば誤りとする。
    pub fn finish(self) -> Result<(), CodecError> {
        match self.remaining() {
            0 => Ok(()),
            n => Err(CodecError::TrailingBytes(n)),
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.remaining() < n {
            return Err(CodecError::UnexpectedEof {
                needed: n,
                remaining: self.remaining(),
            });
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// 固定長バイト列を読む。
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        Ok(self.take(N)?.try_into().expect("長さは take が保証する"))
    }

    /// `n` バイト読む。
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        self.take(n)
    }

    /// 1 バイト読む。
    pub fn read_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    /// リトルエンディアンの `u32` を読む。
    pub fn read_u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    /// リトルエンディアンの `u64` を読む。
    pub fn read_u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    /// リトルエンディアンの `i64` を読む。
    pub fn read_i64(&mut self) -> Result<i64, CodecError> {
        Ok(i64::from_le_bytes(self.read_array()?))
    }

    /// 32 バイトのハッシュを読む。
    pub fn read_hash(&mut self) -> Result<Hash, CodecError> {
        Ok(Hash::from_bytes(self.read_array::<HASH_LEN>()?))
    }

    /// varint を読む。
    pub fn read_varint(&mut self) -> Result<u128, CodecError> {
        let (value, len) = varint::decode(&self.buf[self.pos..])?;
        self.pos += len;
        Ok(value)
    }

    /// varint を読み、`u32` に収まることを確認する。
    pub fn read_varint_u32(&mut self, field: &'static str) -> Result<u32, CodecError> {
        let value = self.read_varint()?;
        u32::try_from(value).map_err(|_| CodecError::ValueOutOfRange { field, value })
    }

    /// varint を読み、`u64` に収まることを確認する。
    pub fn read_varint_u64(&mut self, field: &'static str) -> Result<u64, CodecError> {
        let value = self.read_varint()?;
        u64::try_from(value).map_err(|_| CodecError::ValueOutOfRange { field, value })
    }

    /// varint の金額を読む。範囲検査を伴う。
    pub fn read_amount(&mut self) -> Result<Amount, CodecError> {
        let (amount, len) = Amount::decode(&self.buf[self.pos..])?;
        self.pos += len;
        Ok(amount)
    }

    /// 要素数を読む。
    ///
    /// 各要素は最低 1 バイトを占めるため、残りバイト数を超える個数は
    /// その時点で不正である。この検査により、巨大な個数を宣言して
    /// メモリ割り当てを誘発する攻撃を防ぐ。
    pub fn read_count(&mut self, field: &'static str) -> Result<usize, CodecError> {
        let declared = self.read_varint()?;
        let remaining = self.remaining();
        if declared > remaining as u128 {
            return Err(CodecError::CountTooLarge {
                field,
                declared,
                remaining,
            });
        }
        Ok(declared as usize)
    }

    /// 長さ接頭辞つきのバイト列を読む。長さは `max` 以下でなければならない。
    pub fn read_var_bytes(
        &mut self,
        field: &'static str,
        max: usize,
    ) -> Result<&'a [u8], CodecError> {
        let actual = self.read_varint()?;
        if actual > max as u128 {
            return Err(CodecError::LengthTooLarge { field, actual, max });
        }
        self.take(actual as usize)
    }
}

/// バイト列に符号化できる型。
pub trait Encode {
    /// `out` に追記する。
    fn encode_into(&self, out: &mut Vec<u8>);

    /// 新しい `Vec` に符号化する。
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// 符号化したときのバイト数。
    fn encoded_len(&self) -> usize {
        self.encode().len()
    }
}

/// バイト列から復号できる型。
pub trait Decode: Sized {
    /// 読み取り器から 1 個復号する。
    fn read_from(reader: &mut Reader<'_>) -> Result<Self, CodecError>;

    /// バイト列全体をちょうど 1 個の値として復号する。
    ///
    /// 余剰バイトがあれば拒否する。
    fn decode(buf: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(buf);
        let value = Self::read_from(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }
}

/// varint を書き出す補助。
pub fn write_varint(value: u128, out: &mut Vec<u8>) {
    varint::encode_into(value, out);
}

/// 長さ接頭辞つきでバイト列を書き出す補助。
pub fn write_var_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    write_varint(bytes.len() as u128, out);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fixed_width_little_endian() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(r.read_u32().unwrap(), 0x0403_0201);
        assert!(r.finish().is_ok());
    }

    #[test]
    fn detects_trailing_bytes() {
        let r = Reader::new(&[0x00]);
        assert_eq!(r.finish(), Err(CodecError::TrailingBytes(1)));
    }

    #[test]
    fn detects_eof() {
        let mut r = Reader::new(&[0x01]);
        assert_eq!(
            r.read_u32(),
            Err(CodecError::UnexpectedEof {
                needed: 4,
                remaining: 1
            })
        );
    }

    #[test]
    fn count_cannot_exceed_remaining_bytes() {
        // 「要素が 1000 個ある」と宣言しつつ、実データは 0 バイト。
        let mut buf = Vec::new();
        write_varint(1_000, &mut buf);
        let mut r = Reader::new(&buf);
        assert!(matches!(
            r.read_count("inputs"),
            Err(CodecError::CountTooLarge { .. })
        ));
    }

    #[test]
    fn var_bytes_respects_max() {
        let mut buf = Vec::new();
        write_var_bytes(&[0xab; 50], &mut buf);
        let mut r = Reader::new(&buf);
        assert!(matches!(
            r.read_var_bytes("payload", 40),
            Err(CodecError::LengthTooLarge {
                actual: 50,
                max: 40,
                ..
            })
        ));
    }

    #[test]
    fn rejects_non_canonical_varint() {
        // 0 を 2 バイトで表した非正準符号化。
        let mut r = Reader::new(&[0x80, 0x00]);
        assert!(matches!(r.read_varint(), Err(CodecError::VarInt(_))));
    }

    #[test]
    fn varint_u32_range_is_checked() {
        let mut buf = Vec::new();
        write_varint(u128::from(u32::MAX) + 1, &mut buf);
        let mut r = Reader::new(&buf);
        assert!(matches!(
            r.read_varint_u32("prev_index"),
            Err(CodecError::ValueOutOfRange { .. })
        ));
    }
}
