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
//! - 個数フィールドは、その個数を符号化するのに足るバイト数が残っていなければ
//!   ならない (割り当て量の爆発を防ぐ)
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
    /// 個数フィールドが、残りバイト数に収まらない個数を宣言している。
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

    /// 真偽値を 1 バイトとして読む。
    ///
    /// **0 と 1 以外は拒否する。** `!= 0` で受けると、真を表すバイトが
    /// 255 通りになる。同じ値が複数のバイト列で表現できる状態であり、
    /// 本モジュールが禁じているもの (展性) そのものである。符号化側は
    /// 常に 0 か 1 を書くのだから、それ以外は壊れたバイト列である。
    pub fn read_bool(&mut self, field: &'static str) -> Result<bool, CodecError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(CodecError::ValueOutOfRange {
                field,
                value: u128::from(other),
            }),
        }
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

    /// 要素数を読む。要素の最小符号化長は型から取る。
    ///
    /// 復号する型が [`Decode::MIN_ENCODED_LEN`] を持つ場合はこちらを使う。
    pub fn read_count<T: Decode>(&mut self, field: &'static str) -> Result<usize, CodecError> {
        self.read_count_of(field, T::MIN_ENCODED_LEN)
    }

    /// 要素数を読む。`min_item_len` は 1 要素が占める最小バイト数。
    ///
    /// **宣言された個数がそのバイト数だけ残っていなければ、その場で拒否
    /// する。** 個数は攻撃者が決められるうえ、読み出し側はそれを見て
    /// `Vec::with_capacity` を呼ぶ。残りバイト数とだけ比べると、1 要素が
    /// 実際には数十バイトを要する型でも 1 バイト分の個数まで通ってしまい、
    /// **復号が 1 要素目で失敗するより前に、受け取ったバイト列の数十倍の
    /// メモリを確保してしまう**。最小符号化長を掛けて比べれば、確保量は
    /// 受け取ったバイト列と同じ桁に収まる。
    ///
    /// 型に対応する [`Decode`] がある場合は [`Reader::read_count`] を使う。
    /// こちらは varint の並びのように `Decode` を持たない要素のためにある。
    pub fn read_count_of(
        &mut self,
        field: &'static str,
        min_item_len: usize,
    ) -> Result<usize, CodecError> {
        let declared = self.read_varint()?;
        let remaining = self.remaining();
        // 0 は「いくらでも入る」ことになってしまう。どの要素も 1 バイトは占める。
        let min_item_len = min_item_len.max(1) as u128;
        if declared.saturating_mul(min_item_len) > remaining as u128 {
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
    /// この型を符号化したときに最低限占めるバイト数。
    ///
    /// 列の個数フィールドを検査するために使う ([`Reader::read_count`])。
    /// **実際の下限より大きい値を入れてはならない。** 正当なバイト列を
    /// 拒否することになる。既定の 1 はどの型でも成り立つ下限であり、
    /// 安全ではあるが、確保量を抑える効き目は小さい。
    const MIN_ENCODED_LEN: usize = 1;

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
            r.read_count_of("inputs", 1),
            Err(CodecError::CountTooLarge { .. })
        ));
    }

    #[test]
    fn count_accounts_for_how_big_one_item_is() {
        // 100 バイトの残りに「40 バイトの要素が 10 個」は入らない。
        // 個数 (10) 自体は残り (100) より小さいので、残りバイト数とだけ
        // 比べる検査はこれを通してしまう。
        let mut buf = Vec::new();
        write_varint(10, &mut buf);
        buf.extend_from_slice(&[0u8; 100]);

        let mut r = Reader::new(&buf);
        assert_eq!(r.read_count_of("items", 10).unwrap(), 10, "10x10 は入る");

        let mut r = Reader::new(&buf);
        assert!(
            matches!(
                r.read_count_of("items", 40),
                Err(CodecError::CountTooLarge { .. })
            ),
            "1 要素 40 バイトなら 10 個は入らない"
        );
    }

    #[test]
    fn an_absurd_count_does_not_overflow_the_check() {
        // 個数 × 最小長 が u128 を溢れても、検査は拒否側に倒れること。
        let mut buf = Vec::new();
        write_varint(u128::MAX, &mut buf);
        buf.extend_from_slice(&[0u8; 64]);
        let mut r = Reader::new(&buf);
        assert!(matches!(
            r.read_count_of("items", 1_000),
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
