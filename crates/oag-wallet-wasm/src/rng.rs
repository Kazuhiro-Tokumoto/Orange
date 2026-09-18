//! ブラウザ側から種を貰う乱数。
//!
//! # なぜ自前で用意するのか
//!
//! wasm32 には乱数源が無い。`getrandom` の既定の裏側は
//! `crypto.getRandomValues` を `wasm-bindgen` 経由で呼ぶが、それを選ぶと
//! **組み立てに `wasm-bindgen` の外部道具が要る**ようになる。道具の版数が
//! crate の版数と一致していないと動かず、`cargo build` だけでは作れない
//! ものになってしまう。
//!
//! そこで `getrandom` の「自前の裏側」を使い、**種は起動時に JS から
//! 貰う**ことにした。JS 側が `crypto.getRandomValues` で 32 バイトを取り、
//! [`seed`] に渡す。以後はそれを鍵にした BLAKE3 の XOF から取り出す。
//!
//! # 種を貰う前
//!
//! **失敗させる。** 0 で埋めて進むと、ソルトも nonce も予測できるものに
//! なる。ここで止まる方が、静かに弱い記録を作るより良い。

use core::cell::RefCell;

/// 種の長さ。
pub const SEED_LEN: usize = 32;

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

struct State {
    key: [u8; SEED_LEN],
    counter: u64,
}

/// 種を入れる。既に入っていれば混ぜ直す。
pub fn seed(bytes: &[u8; SEED_LEN]) {
    STATE.with(|cell| {
        let mut slot = cell.borrow_mut();
        let key = match slot.as_ref() {
            // **捨てずに混ぜる。** 二度目の種が弱くても、一度目より
            // 悪くはならない。
            Some(old) => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&old.key);
                hasher.update(bytes);
                *hasher.finalize().as_bytes()
            }
            None => *bytes,
        };
        *slot = Some(State { key, counter: 0 });
    });
}

/// 取り出す。種が無ければ偽を返し、`dest` には触らない。
pub fn fill(dest: &mut [u8]) -> bool {
    STATE.with(|cell| {
        let mut slot = cell.borrow_mut();
        let Some(state) = slot.as_mut() else {
            return false;
        };
        let mut hasher = blake3::Hasher::new_keyed(&state.key);
        hasher.update(&state.counter.to_le_bytes());
        state.counter += 1;
        hasher.finalize_xof().fill(dest);
        true
    })
}

/// 決まった長さを取り出す。
pub fn bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut out = [0u8; N];
    if !fill(&mut out) {
        return Err("乱数の種がまだ入っていない".to_string());
    }
    Ok(out)
}

/// `getrandom` 0.3 の裏側。
///
/// # Safety
///
/// `dest` は `len` バイト書ける領域を指していること。`getrandom` が
/// 呼び出し時にそれを保証する。
#[cfg(target_arch = "wasm32")]
#[no_mangle]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom_03::Error> {
    let slice = unsafe { core::slice::from_raw_parts_mut(dest, len) };
    if fill(slice) {
        Ok(())
    } else {
        Err(getrandom_03::Error::UNSUPPORTED)
    }
}
