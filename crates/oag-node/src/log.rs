//! ノードの記録。
//!
//! # なぜ印を付けるのか
//!
//! **「運んでいる」と「確かめた」は別の話である。** 混ぜて出すと、
//! 止まったときにどちらで止まったのかが読めない。相手が寄越さないのか、
//! こちらが捌けていないのかは、対処が正反対になる。
//!
//! 行の先頭に何の話かを置く。目で追えるし、`grep '\[sync\]'` で片方だけ
//! 取り出せる。
//!
//! ```text
//! [peer] connected to 203.0.113.9:9444 (/oag-node:0.1.0/, height 2126)
//! [sync] headers +2000 (2000 of them)  known up to height 2000
//! [sync] bodies 1204/2126 (57%)  12.4 blk/s  922 to go
//! [sync] caught up  height 2126
//! [check] connected height 2127  1 tx  203 B  mempool 0
//! [tx] received 3f2a1b9c  fee 0.0001 OAG  186 B  mempool 1
//! ```
//!
//! # 出し先
//!
//! 進んでいることの記録は標準出力、警告は標準エラーに出す。`2>` で
//! 分ければ、困ったことだけを別に残せる。

use oag_primitives::Hash;

/// ハッシュの頭 8 桁。
///
/// 64 桁を毎行並べると、肝心の数字が画面の外へ出る。取り違えの心配が
/// ある場面 (掘れたブロックなど) では全部出す。
pub fn short(hash: &Hash) -> String {
    let full = hash.to_string();
    full.chars().take(8).collect()
}

/// 大きさの表記。
pub fn bytes(n: usize) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    match n {
        n if n < 1024 => format!("{n} B"),
        n if (n as f64) < MIB => format!("{:.1} KiB", n as f64 / KIB),
        n => format!("{:.1} MiB", n as f64 / MIB),
    }
}

/// 同期 — 相手から運んでくる話。
///
/// ヘッダと本体がどこまで来たか。**中身が正しいかはここでは言わない。**
#[macro_export]
macro_rules! log_sync {
    ($($arg:tt)*) => { println!("[sync] {}", format_args!($($arg)*)) };
}

/// 検証 — 運んできたものを自分で確かめた話。
///
/// 接続できた、リオーグした。**自分が納得したことだけをここに出す。**
#[macro_export]
macro_rules! log_verify {
    ($($arg:tt)*) => { println!("[check] {}", format_args!($($arg)*)) };
}

/// 取引 — mempool の出入り。
#[macro_export]
macro_rules! log_tx {
    ($($arg:tt)*) => { println!("[tx] {}", format_args!($($arg)*)) };
}

/// ピア — 接続の出入り。
#[macro_export]
macro_rules! log_peer {
    ($($arg:tt)*) => { println!("[peer] {}", format_args!($($arg)*)) };
}

/// 採掘。
#[macro_export]
macro_rules! log_mine {
    ($($arg:tt)*) => { println!("[mining] {}", format_args!($($arg)*)) };
}

/// 警告。標準エラーへ出す。
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { eprintln!("[warn] {}", format_args!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_hash_is_eight_digits() {
        assert_eq!(short(&Hash::ZERO).len(), 8);
        assert_eq!(short(&Hash::ZERO), "00000000");
    }

    #[test]
    fn sizes_change_unit_at_the_boundary() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        assert_eq!(bytes(1024 * 1024), "1.0 MiB");
    }
}
