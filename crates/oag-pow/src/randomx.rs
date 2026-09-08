//! RandomX への FFI。
//!
//! 実装は C++ の [tevador/RandomX](https://github.com/tevador/RandomX) であり、
//! [`randomx-rs`](https://crates.io/crates/randomx-rs) 経由で利用する。
//! Rust にも Go にも実用に耐えるネイティブ実装は存在しないため、いずれの
//! 言語を選んでも C++ を呼ぶことになる。
//!
//! # 動作モード
//!
//! | モード | メモリ | 型 | 用途 |
//! | --- | ---: | --- | --- |
//! | light | 256 MB | [`RandomXVerifier`] | ノードの検証 |
//! | fast | 2 GB + 256 MB | [`RandomXMiner`] | 採掘 |
//!
//! フルノードは light モードで動作できなければならない。すなわちノードの
//! 運用に 2 GB のデータセットは要求しない (SPEC §11.2)。**採掘するかどうか
//! と、検証できるかどうかは別である。**
//!
//! **どちらのモードも同じハッシュを返す。** 違うのは速さと必要なメモリ
//! だけである。ここが崩れると、fast モードで掘ったブロックを light モード
//! のノードが撥ねることになる。試験
//! `the_two_modes_agree_on_every_hash` で確かめている。
//!
//! # スレッド安全性
//!
//! `RandomXVM` は内部に生ポインタとスクラッチパッドを持ち、`Send` でも
//! `Sync` でもない。**1 スレッドにつき 1 個の VM を持つこと。**
//! 採掘や並列検証を行う際は、スレッドごとに [`RandomXVerifier`] または
//! [`RandomXMiner`] を作る。
//!
//! データセット自体は読み取り専用で共有できる。[`RandomXDataset`] は
//! 内部が `Arc` であり、複製しても 2 GB が増えることはない。複数スレッドで
//! 採掘する場合、データセットは 1 個で足りる
//! ([`RandomXMiner::sharing_dataset_with`])。
//!
//! 参照: `docs/SPEC.md` §11

use crate::target::meets_difficulty;
use oag_consensus::block::BlockHeader;
use oag_consensus::codec::Encode;
use oag_consensus::validate::PowVerifier;
use oag_primitives::Hash;
use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};

/// RandomX の初期化・計算で起きうる誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RandomXPowError {
    /// キャッシュまたは VM の初期化に失敗した。
    #[error("RandomX の初期化に失敗した: {0}")]
    Init(String),
    /// ハッシュの計算に失敗した。
    #[error("RandomX のハッシュ計算に失敗した: {0}")]
    Hash(String),
    /// 返されたハッシュの長さが 32 バイトでない。
    #[error("RandomX が {0} バイトを返した (32 バイトであるべき)")]
    BadHashLength(usize),
    /// 難易度が 0。
    #[error("難易度は 1 以上でなければならない")]
    ZeroDifficulty,
}

/// light モードの RandomX 検証器。
///
/// 1 つのシードエポックに対応する。エポックが変わったら作り直す。
pub struct RandomXVerifier {
    seed_height: u64,
    seed: Hash,
    vm: RandomXVM,
}

impl RandomXVerifier {
    /// シードを指定して検証器を作る。
    ///
    /// `seed` は [`crate::seed::seed_height`] が示す高さのブロックハッシュ、
    /// `seed_height` はその高さである。
    ///
    /// 256 MB のキャッシュを確保するため、初期化には時間がかかる。
    pub fn new(seed: &Hash, seed_height: u64) -> Result<RandomXVerifier, RandomXPowError> {
        // get_recommended_flags は FLAG_FULL_MEM を含まないため light モードになる。
        let flags = RandomXFlag::get_recommended_flags();
        let cache = RandomXCache::new(flags, seed.as_bytes())
            .map_err(|e| RandomXPowError::Init(e.to_string()))?;
        let vm = RandomXVM::new(flags, Some(cache), None)
            .map_err(|e| RandomXPowError::Init(e.to_string()))?;
        Ok(RandomXVerifier {
            seed_height,
            seed: *seed,
            vm,
        })
    }

    /// この検証器が対応するシードのブロック高さ。
    pub fn seed_height(&self) -> u64 {
        self.seed_height
    }

    /// この検証器が用いているシード。
    pub fn seed(&self) -> Hash {
        self.seed
    }

    /// 任意のバイト列の RandomX ハッシュ。
    pub fn hash(&self, data: &[u8]) -> Result<Hash, RandomXPowError> {
        let bytes = self
            .vm
            .calculate_hash(data)
            .map_err(|e| RandomXPowError::Hash(e.to_string()))?;
        Hash::from_slice(&bytes).map_err(|_| RandomXPowError::BadHashLength(bytes.len()))
    }

    /// ブロックヘッダの PoW ハッシュ。
    pub fn hash_header(&self, header: &BlockHeader) -> Result<Hash, RandomXPowError> {
        self.hash(&header.encode())
    }

    /// ヘッダの PoW が難易度を満たすかを、誤りを区別して判定する。
    ///
    /// [`PowVerifier::verify`] は `bool` しか返さないため、初期化やエポックの
    /// 不整合といった呼び出し側の誤りを区別したい場合はこちらを使う。
    pub fn check(&self, header: &BlockHeader) -> Result<bool, RandomXPowError> {
        if crate::seed::seed_height(header.height) != self.seed_height {
            // 検証器のエポックが合っていない。呼び出し側の誤りである。
            return Err(RandomXPowError::Init(format!(
                "検証器はシード高さ {} 用だが、ヘッダの高さ {} は {} を要求する",
                self.seed_height,
                header.height,
                crate::seed::seed_height(header.height)
            )));
        }
        let hash = self.hash_header(header)?;
        meets_difficulty(&hash, header.difficulty).map_err(|_| RandomXPowError::ZeroDifficulty)
    }
}

impl PowVerifier for RandomXVerifier {
    /// 誤りはすべて「PoW を満たさない」として扱う。
    ///
    /// 誤りの内訳が必要な場合は [`RandomXVerifier::check`] を使う。
    fn verify(&self, header: &BlockHeader) -> bool {
        self.check(header).unwrap_or(false)
    }
}

// ━━━━━━━━ fast モード ━━━━━━━━

/// データセットの大きさの目安 (バイト)。
///
/// RandomX の仕様上の値である。実際の確保量は
/// [`RandomXMiner::dataset_bytes`] が返す。
pub const DATASET_BYTES: u64 = 2_181_038_080;

/// fast モードの RandomX 採掘器。
///
/// 2 GB のデータセットを構築して用いる。light モード
/// ([`RandomXVerifier`]) のおよそ 10 倍速い。
///
/// # 構築に時間がかかる
///
/// データセットの初期化は 2 GB を埋める作業であり、**1 分前後かかる**。
/// シードエポックが変わるたびに作り直す必要がある (2048 ブロック =
/// 約 34 時間ごと)。使い捨てにせず、エポックの間は持ち続けること。
///
/// なお本ラッパは初期化を複数スレッドに分割できない (`randomx-rs` の
/// `RandomXDataset::new` が常に自前のデータセットを確保するため)。
/// 構築は 1 スレッドで行われる。
///
/// # メモリ
///
/// データセット 2 GB に加えて、構築の材料であるキャッシュ 256 MB を
/// 抱えたままになる (`RandomXDataset` がキャッシュを保持する)。
/// **確保できなければ [`RandomXPowError::Init`] を返す。** 落ちはしない
/// ので、呼び出し側で light モードに退避できる。
pub struct RandomXMiner {
    seed_height: u64,
    seed: Hash,
    dataset: RandomXDataset,
    vm: RandomXVM,
}

impl RandomXMiner {
    /// シードを指定して採掘器を作る。データセットを構築する。
    ///
    /// 引数の意味は [`RandomXVerifier::new`] と同じである。
    pub fn new(seed: &Hash, seed_height: u64) -> Result<RandomXMiner, RandomXPowError> {
        let cache = RandomXCache::new(cache_flags(), seed.as_bytes())
            .map_err(|e| RandomXPowError::Init(format!("キャッシュを確保できない: {e}")))?;
        // start は 0 でなければならない。0 以外を渡すと、先頭が未初期化の
        // ままのデータセットができ、他の実装と食い違うハッシュを黙って返す。
        let dataset = RandomXDataset::new(RandomXFlag::FLAG_DEFAULT, cache, 0)
            .map_err(|e| RandomXPowError::Init(format!("データセットを確保できない: {e}")))?;
        RandomXMiner::sharing_dataset_with(seed, seed_height, dataset)
    }

    /// すでにあるデータセットを共有して、もう 1 個の採掘器を作る。
    ///
    /// 複数スレッドで採掘するために用いる。**VM はスレッドごとに要るが、
    /// データセットは 1 個でよい。** 2 GB が人数分増えることはない。
    ///
    /// `seed` と `seed_height` は、そのデータセットを作ったときと同じ値を
    /// 渡すこと。食い違わせると、[`RandomXMiner::seed`] が嘘をつく。
    pub fn sharing_dataset_with(
        seed: &Hash,
        seed_height: u64,
        dataset: RandomXDataset,
    ) -> Result<RandomXMiner, RandomXPowError> {
        let vm = RandomXVM::new(vm_flags(), None, Some(dataset.clone()))
            .map_err(|e| RandomXPowError::Init(format!("VM を作れない: {e}")))?;
        Ok(RandomXMiner {
            seed_height,
            seed: *seed,
            dataset,
            vm,
        })
    }

    /// この採掘器のデータセット。別スレッドの採掘器と共有するために取る。
    pub fn dataset(&self) -> RandomXDataset {
        self.dataset.clone()
    }

    /// この採掘器が対応するシードのブロック高さ。
    pub fn seed_height(&self) -> u64 {
        self.seed_height
    }

    /// この採掘器が用いているシード。
    pub fn seed(&self) -> Hash {
        self.seed
    }

    /// 実際に確保されたデータセットの大きさ (バイト)。
    pub fn dataset_bytes() -> Option<u64> {
        RandomXDataset::count()
            .ok()
            .map(|items| u64::from(items) * 64)
    }

    /// 任意のバイト列の RandomX ハッシュ。
    ///
    /// [`RandomXVerifier::hash`] と**同じ値を返す**。
    pub fn hash(&self, data: &[u8]) -> Result<Hash, RandomXPowError> {
        let bytes = self
            .vm
            .calculate_hash(data)
            .map_err(|e| RandomXPowError::Hash(e.to_string()))?;
        Hash::from_slice(&bytes).map_err(|_| RandomXPowError::BadHashLength(bytes.len()))
    }

    /// ブロックヘッダの PoW ハッシュ。
    pub fn hash_header(&self, header: &BlockHeader) -> Result<Hash, RandomXPowError> {
        self.hash(&header.encode())
    }
}

/// キャッシュの確保に使うフラグ。
///
/// `FLAG_LARGE_PAGES` と、Argon2 の命令セット指定だけが意味を持つ。
fn cache_flags() -> RandomXFlag {
    RandomXFlag::get_recommended_flags()
}

/// fast モードの VM に使うフラグ。
///
/// **`FLAG_FULL_MEM` を足すことが fast モードの定義である。**
/// `get_recommended_flags` はこれを含まない。
fn vm_flags() -> RandomXFlag {
    RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_primitives::hash;

    fn verifier() -> RandomXVerifier {
        RandomXVerifier::new(&hash::block_hash(b"orange genesis"), 0).expect("初期化できる")
    }

    fn header(nonce: u64, difficulty: u64) -> BlockHeader {
        BlockHeader {
            version: 0,
            prev_hash: hash::block_hash(b"parent"),
            merkle_root: hash::txid(b"merkle"),
            timestamp: 1_800_000_000,
            difficulty,
            height: 10,
            nonce,
        }
    }

    #[test]
    fn hashing_is_deterministic() {
        let v = verifier();
        let a = v.hash(b"orange").unwrap();
        let b = v.hash(b"orange").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, v.hash(b"orangf").unwrap());
    }

    #[test]
    fn different_seeds_give_different_hashes() {
        let a = RandomXVerifier::new(&hash::block_hash(b"seed a"), 0).unwrap();
        let b = RandomXVerifier::new(&hash::block_hash(b"seed b"), 0).unwrap();
        assert_ne!(a.hash(b"orange").unwrap(), b.hash(b"orange").unwrap());
    }

    #[test]
    fn the_nonce_changes_the_hash() {
        let v = verifier();
        assert_ne!(
            v.hash_header(&header(0, 1)).unwrap(),
            v.hash_header(&header(1, 1)).unwrap()
        );
    }

    #[test]
    fn difficulty_one_always_passes() {
        let v = verifier();
        assert!(v.verify(&header(0, 1)));
        assert!(v.check(&header(0, 1)).unwrap());
    }

    #[test]
    fn an_impossible_difficulty_never_passes() {
        let v = verifier();
        assert!(!v.verify(&header(0, u64::MAX)));
    }

    #[test]
    fn zero_difficulty_is_an_error_not_a_pass() {
        let v = verifier();
        assert_eq!(v.check(&header(0, 0)), Err(RandomXPowError::ZeroDifficulty));
        assert!(!v.verify(&header(0, 0)));
    }

    #[test]
    fn a_verifier_for_the_wrong_epoch_is_an_error() {
        // シード高さ 0 用の検証器に、別エポックのヘッダを渡す。
        let v = verifier();
        let mut h = header(0, 1);
        h.height = 5_000; // シード高さは 4096 になる
        assert_ne!(crate::seed::seed_height(h.height), 0);
        assert!(v.check(&h).is_err());
        assert!(!v.verify(&h), "エポック不整合は PoW 不成立として扱う");
    }

    #[test]
    fn mining_finds_a_nonce_that_meets_the_difficulty() {
        // 実際に採掘してみる。light モードは遅いので難易度は低くしておく。
        let v = verifier();
        let difficulty = 32u64;
        let mut found = None;
        for nonce in 0..2_000u64 {
            let h = header(nonce, difficulty);
            if v.verify(&h) {
                found = Some((nonce, v.hash_header(&h).unwrap()));
                break;
            }
        }
        let (nonce, pow_hash) = found.expect("難易度 32 なら見つかるはず");

        // 見つけた nonce が実際に条件を満たしていること。
        let target = crate::target::target_from_difficulty(difficulty).unwrap();
        assert!(crate::target::meets_target(&pow_hash, &target));

        // 1 ビットでも変えれば別のハッシュになる。
        let mut other = header(nonce, difficulty);
        other.timestamp += 1;
        assert_ne!(v.hash_header(&other).unwrap(), pow_hash);
    }
}
