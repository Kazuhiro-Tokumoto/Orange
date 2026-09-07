//! LEB128 可変長整数。
//!
//! コンセンサスに関わる符号化において、同一の値が複数の表現を持つことは
//! トランザクションの展性 (同じ内容でありながら異なる txid を持つ) を生む。
//! したがって本実装は **最短形以外の符号化を拒否する**。
//!
//! 参照: `docs/SPEC.md` §2, §7.1

/// `u128` を符号化した際の最大バイト数 (`ceil(128 / 7)`)。
pub const MAX_LEN_U128: usize = 19;

/// varint の復号で起きうる誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VarIntError {
    /// 継続ビットが立ったまま入力が終端した。
    #[error("varint が途中で終端した")]
    UnexpectedEof,
    /// 値が 128 ビットに収まらない。
    #[error("varint が 128 ビットに収まらない")]
    Overflow,
    /// 最短形ではない符号化 (末尾に不要な 0 バイトが付いている)。
    #[error("varint が最短形ではない (非正準符号化)")]
    NonCanonical,
}

/// `v` を LEB128 で符号化し `out` に追記する。
pub fn encode_into(mut v: u128, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// `v` を LEB128 で符号化した新しい `Vec` を返す。
pub fn encode(v: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_LEN_U128);
    encode_into(v, &mut out);
    out
}

/// `buf` の先頭から LEB128 を 1 個読み、値と消費バイト数を返す。
///
/// 最短形でない符号化は [`VarIntError::NonCanonical`] として拒否する。
pub fn decode(buf: &[u8]) -> Result<(u128, usize), VarIntError> {
    let mut value: u128 = 0;
    let mut shift: u32 = 0;

    for (i, &byte) in buf.iter().enumerate() {
        if i >= MAX_LEN_U128 {
            return Err(VarIntError::Overflow);
        }
        let payload = u128::from(byte & 0x7f);

        // payload が shift 後も失われないことを確認する。
        if payload << shift >> shift != payload {
            return Err(VarIntError::Overflow);
        }
        value |= payload << shift;

        if byte & 0x80 == 0 {
            // 最終バイトが 0 であるのは、値全体が 1 バイトの場合のみ正準。
            if byte == 0 && i != 0 {
                return Err(VarIntError::NonCanonical);
            }
            return Ok((value, i + 1));
        }
        shift += 7;
    }

    Err(VarIntError::UnexpectedEof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for v in [
            0u128,
            1,
            127,
            128,
            255,
            10_000_000_000_000_000,  // 1 OAG
            100_000_000_000_000_000, // 10 OAG (ブロック報酬)
            10u128.pow(25),          // 総発行量
            u128::MAX,
        ] {
            let bytes = encode(v);
            let (decoded, len) = decode(&bytes).expect("復号できる");
            assert_eq!(decoded, v);
            assert_eq!(len, bytes.len());
        }
    }

    #[test]
    fn block_reward_is_nine_bytes() {
        // SPEC §7.2 の出力サイズ見積もり (金額 9 バイト) の根拠。
        assert_eq!(encode(100_000_000_000_000_000).len(), 9);
    }

    #[test]
    fn u128_max_uses_max_len() {
        assert_eq!(encode(u128::MAX).len(), MAX_LEN_U128);
    }

    #[test]
    fn rejects_non_canonical() {
        // 0 を 2 バイトで表した非正準符号化。
        assert_eq!(decode(&[0x80, 0x00]), Err(VarIntError::NonCanonical));
        // 1 を 3 バイトで表した非正準符号化。
        assert_eq!(decode(&[0x81, 0x80, 0x00]), Err(VarIntError::NonCanonical));
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(decode(&[0x80]), Err(VarIntError::UnexpectedEof));
        assert_eq!(decode(&[]), Err(VarIntError::UnexpectedEof));
    }

    #[test]
    fn rejects_overflow() {
        // 20 バイトすべてに継続ビットが立っている。
        let too_long = [0xff; 20];
        assert_eq!(decode(&too_long), Err(VarIntError::Overflow));
        // 19 バイト目に 128 ビットを超える値が入っている。
        let mut overflowing = vec![0xffu8; 18];
        overflowing.push(0x7f);
        assert_eq!(decode(&overflowing), Err(VarIntError::Overflow));
    }

    #[test]
    fn decode_stops_at_boundary() {
        let mut bytes = encode(300);
        bytes.extend_from_slice(b"trailing");
        let (v, len) = decode(&bytes).expect("復号できる");
        assert_eq!(v, 300);
        assert_eq!(len, 2);
    }
}
