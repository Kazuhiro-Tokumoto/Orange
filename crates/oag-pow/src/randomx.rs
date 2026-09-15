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
//! # ここは crate の中で唯一 `unsafe` に接している場所である
//!
//! 全 crate に `#![forbid(unsafe_code)]` を置いてあるが、それが縛るのは
//! **自分が書いたコードだけ**である。`randomx-rs` の中の `unsafe` も、その
//! 先の C++ も縛らない。したがってメモリ安全は、この境界で相手に何を渡し、
//! 相手から何を受け取るかで決まる。以下は `randomx-rs` 1.6.0 を読んだうえで
//! 本モジュールが引き受けている事柄である。
//!
//! ## VM が NULL で返ってくることがある
//!
//! C++ の `randomx_create_vm` は、VM の確保 (`vm->allocate()`) が例外を
//! 投げると `nullptr` を返す。スクラッチパッド 2 MB を取れないとき、JIT が
//! 実行可能メモリを地図に載せられないときに起きる。**`randomx-rs` 1.6.0 は
//! この NULL を検査せず `Ok` に包む。** 受け取った側が `calculate_hash` を
//! 呼べば NULL 参照であり、処理が落ちる。ノードが誤りを返して退く
//! 代わりに、検証の最中に死ぬ。
//!
//! 本モジュールは VM を作るたびに NULL を確かめ、NULL なら誤りにする
//! ([`RandomXPowError::NoUsableConfiguration`])。
//!
//! ## 環境が JIT を拒むことがある
//!
//! `RandomXFlag::get_recommended_flags` は `FLAG_JIT` を含む。JIT は
//! 実行可能なメモリを要求するので、SELinux の `deny_execmem`、PaX の
//! MPROTECT、W^X を強制する容器などでは確保が失敗する。そのまま諦めると、
//! **そういう環境ではブロックを 1 つも検証できないノードになる。**
//!
//! RandomX にはインタプリタの経路 (`FLAG_DEFAULT`) があり、実行可能メモリ
//! を要求しない。10 倍ほど遅いが、動く。本モジュールはフラグを
//! 「推奨 → JIT を外したもの → `FLAG_DEFAULT`」の順に試し、通ったものを
//! 使う。どれで動いているかは [`RandomXVerifier::flags`] で分かる。
//!
//! # スレッド安全性
//!
//! `RandomXVM` は内部に生ポインタとスクラッチパッドを持つ。`calculate_hash`
//! は `&self` を取るが、**その中でスクラッチパッドを書き換える。** 同じ VM を
//! 2 つのスレッドから触れば競合であり、未定義動作である。
//!
//! 今は `randomx-rs` の型がいずれも `Send` でも `Sync` でもないため、
//! コンパイラが止めてくれる。将来 `randomx-rs` が `unsafe impl Send` を
//! 足せば、この守りは黙って消える。**`forbid(unsafe_code)` は他所の crate の
//! `unsafe impl` を止めない。** そこで、`Send` でも `Sync` でもないことを
//! コンパイル時に確かめている (このファイル末尾の `const _`)。消えたときは
//! ビルドが失敗する。
//!
//! **1 スレッドにつき 1 個の VM を持つこと。**
//!
//! ## データセットはスレッドをまたげない
//!
//! [`RandomXDataset`] も生ポインタを持つため `Send` ではない。つまり
//! 「2 GB のデータセットを 1 個だけ建てて、複数のスレッドで使い回す」ことは
//! **安全な Rust では書けない**。`unsafe` を禁じている以上、当面できない。
//!
//! [`RandomXMiner::sharing_dataset_with`] が役に立つのは、**同じスレッドの
//! 中で** VM をもう 1 個作るときだけである。複数スレッドで掘るなら今のところ
//! スレッドごとに 2 GB を建てることになる。実用上は 1 スレッドの fast 採掘か
//! light モードで足りるので、課題として残してある (SPEC §19)。
//!
//! 参照: `docs/SPEC.md` §11

use crate::target::meets_difficulty;
use oag_consensus::block::BlockHeader;
use oag_consensus::codec::Encode;
use oag_consensus::validate::PowVerifier;
use oag_primitives::Hash;
use randomx_rs::{RandomXCache, RandomXVM};

// どちらも公開 API の一部である。RandomXDataset は
// `RandomXMiner::sharing_dataset_with` の引数、RandomXFlag は
// `RandomXVerifier::flags` の戻り値に現れる。
pub use randomx_rs::{RandomXDataset, RandomXFlag};

/// RandomX の初期化・計算で起きうる誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RandomXPowError {
    /// キャッシュまたは VM の初期化に失敗した。
    #[error("RandomX の初期化に失敗した: {0}")]
    Init(String),
    /// どのフラグの組み合わせでも RandomX を初期化できなかった。
    ///
    /// 実行可能メモリも大きな確保もできない環境である。ここまで来たら
    /// このホストでは RandomX を動かせない。
    #[error("RandomX を初期化できない (試したフラグ: {tried})。最後の誤り: {last}")]
    NoUsableConfiguration {
        /// 試したフラグの一覧。
        tried: String,
        /// 最後に起きた誤り。
        last: String,
    },
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

// ━━━━━━━━ FFI の境界を守る ━━━━━━━━

/// 試すフラグを、速い順に並べて返す。
///
/// 1. 推奨 (`get_recommended_flags`)。JIT・ハードウェア AES・Argon2 の
///    命令セット指定を含む。
/// 2. 推奨から `FLAG_JIT` を外したもの。実行可能メモリを要求しない。
///    ハードウェア AES は残るので、3 番よりは速い。
/// 3. `FLAG_DEFAULT`。インタプリタとソフトウェア AES。どこでも動く。
///
/// `full_mem` が真なら全部に `FLAG_FULL_MEM` を足す (fast モード)。
///
/// 推奨に JIT が元から入っていない環境では 1 と 2 が同じになるので、
/// 隣り合う重複を落とす。
fn flag_ladder(full_mem: bool) -> Vec<RandomXFlag> {
    let recommended = RandomXFlag::get_recommended_flags();
    let mut steps = vec![
        recommended,
        recommended - RandomXFlag::FLAG_JIT,
        RandomXFlag::FLAG_DEFAULT,
    ];
    steps.dedup();
    if full_mem {
        for flags in &mut steps {
            *flags |= RandomXFlag::FLAG_FULL_MEM;
        }
    }
    steps
}

/// `randomx_create_vm` が返したポインタが NULL かどうか。
///
/// 判定できなかったときは `None` を返す。
///
/// # なぜこんな見方をするのか
///
/// C++ の `randomx_create_vm` は、VM の確保が例外を投げると `nullptr` を
/// 返す。**`randomx-rs` 1.6.0 はそれを検査せず `Ok` に包む。** そのまま
/// `calculate_hash` を呼べば NULL 参照であり、処理が落ちる。
///
/// `randomx-rs` は VM のポインタを公開していない。安全なコードから覗ける
/// のは `Debug` 出力だけである。`*mut T` の `Debug` は 16 進で書かれるので、
/// `vm:` のフィールドを読んで、それが全部 0 かどうかを見る。
///
/// **見た目で判定している。** 気持ちのよいものではないが、代わりの手は
/// 2 つしかない。自分で `unsafe` を書くか (全 crate で禁じている)、落ちるに
/// 任せるかである。
///
/// `randomx-rs` が `Debug` の形を変えれば `None` になり、この検査は素通しに
/// なる。**今と同じ状態に戻るだけで、悪くはならない。** それでも気づける
/// ように、正しく作れた VM に対して `Some(false)` が返ることを試験
/// `the_null_vm_check_still_reads_the_debug_output` で確かめている。
fn vm_pointer_is_null(vm: &RandomXVM) -> Option<bool> {
    // 派生 Debug はフィールドを宣言順に書く。`vm` は 2 番目であり、
    // 入れ子の RandomXCache / RandomXDataset にこの名前のフィールドは
    // ないので、最初に見つかる "vm: 0x" が目当てのものである。
    let text = format!("{vm:?}");
    let after = text.split_once("vm: 0x")?.1;
    let digits = after
        .split(|c: char| !c.is_ascii_hexdigit())
        .next()
        .filter(|d| !d.is_empty())?;
    Some(digits.bytes().all(|b| b == b'0'))
}

/// VM を 1 つ作る。NULL で返ってきたら誤りにする。
///
/// `randomx-rs` が `Ok(NULL)` を返しうるので、`RandomXVM::new` を直に
/// 呼んではならない。**VM を作る道はここだけにしてある。**
///
/// # NULL だったものを落とさない
///
/// NULL の `RandomXVM` を捨てると `randomx_destroy_vm(nullptr)` が走る。
/// C++ 側はそこで `assert(machine != nullptr)` している。`NDEBUG` が
/// 立っていれば消える行だが、**`cargo test` の既定のプロファイルでは
/// 立たない。** `cmake` crate が Rust の profile をそのまま持ち込むため、
/// dev ビルドの RandomX は `CMAKE_BUILD_TYPE=Debug` で建つ。つまり
/// アサーションが生きており、捨てた瞬間に `abort` する。
///
/// そこで [`std::mem::forget`] で落とさずに手放す。NULL なのだから
/// 解放すべき VM は無い。ただし `RandomXVM` が抱えているキャッシュ
/// (256 MB) やデータセット (2 GB) の参照も道連れになり、**それらは二度と
/// 解放されない。**
///
/// 割に合う取引だと考えている。ここに来るのは確保が失敗したときであり、
/// すなわち既にメモリが尽きかけている場面である。そこで漏らすのは確かに
/// 痛いが、**ノードが落ちるよりはましである。** 呼び出し側は誤りを受け
/// 取って、軽いフラグで作り直すか、light モードへ退くことができる。
fn create_vm(
    flags: RandomXFlag,
    cache: Option<RandomXCache>,
    dataset: Option<RandomXDataset>,
) -> Result<RandomXVM, String> {
    let vm = RandomXVM::new(flags, cache, dataset).map_err(|e| e.to_string())?;
    if vm_pointer_is_null(&vm) == Some(true) {
        std::mem::forget(vm);
        return Err("randomx_create_vm が NULL を返した (確保できなかった)".to_string());
    }
    Ok(vm)
}

/// フラグの候補を順に試し、最初に通ったものを返す。
///
/// 全部だめなら [`RandomXPowError::NoUsableConfiguration`] を返す。
/// **このホストでは RandomX を動かせない**という意味である。
fn try_each<T>(
    steps: &[RandomXFlag],
    mut attempt: impl FnMut(RandomXFlag) -> Result<T, String>,
) -> Result<(RandomXFlag, T), RandomXPowError> {
    let mut last = String::from("(試していない)");
    for &flags in steps {
        match attempt(flags) {
            Ok(value) => return Ok((flags, value)),
            Err(e) => last = e,
        }
    }
    Err(RandomXPowError::NoUsableConfiguration {
        tried: steps
            .iter()
            .map(|f| format!("{f:?}"))
            .collect::<Vec<_>>()
            .join(", "),
        last,
    })
}

/// light モードの RandomX 検証器。
///
/// 1 つのシードエポックに対応する。エポックが変わったら作り直す。
pub struct RandomXVerifier {
    seed_height: u64,
    seed: Hash,
    flags: RandomXFlag,
    vm: RandomXVM,
}

impl RandomXVerifier {
    /// シードを指定して検証器を作る。
    ///
    /// `seed` は [`crate::seed::seed_height`] が示す高さのブロックハッシュ、
    /// `seed_height` はその高さである。
    ///
    /// 256 MB のキャッシュを確保するため、初期化には時間がかかる。
    ///
    /// フラグは「推奨 → JIT を外したもの → `FLAG_DEFAULT`」の順に試す。
    /// JIT を拒む環境ではインタプリタまで退く。**遅くなるが、動く。**
    /// どれになったかは
    /// [`RandomXVerifier::flags`] と [`RandomXVerifier::uses_jit`] で分かる。
    pub fn new(seed: &Hash, seed_height: u64) -> Result<RandomXVerifier, RandomXPowError> {
        // FLAG_FULL_MEM を足さないので light モードになる。
        let steps = flag_ladder(false);
        // 候補ごとにキャッシュから作り直す。キャッシュと VM のフラグが必ず
        // 揃うので、組み合わせを考えなくてよい。作り直すのは前の候補が
        // 失敗したときだけなので、通常の経路では 1 回しか通らない。
        let (flags, vm) = try_each(&steps, |flags| {
            let cache = RandomXCache::new(flags, seed.as_bytes())
                .map_err(|e| format!("キャッシュを確保できない: {e}"))?;
            create_vm(flags, Some(cache), None)
        })?;
        Ok(RandomXVerifier {
            seed_height,
            seed: *seed,
            flags,
            vm,
        })
    }

    /// この検証器が実際に用いているフラグ。
    ///
    /// 環境によっては JIT を落として作られる。速さが 10 倍ほど違うので、
    /// 運用者に見せる価値がある。
    pub fn flags(&self) -> RandomXFlag {
        self.flags
    }

    /// JIT で動いているか。偽ならインタプリタであり、**かなり遅い**。
    pub fn uses_jit(&self) -> bool {
        self.flags.contains(RandomXFlag::FLAG_JIT)
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
    ///
    /// `data` が空なら誤りを返す (`randomx-rs` が空の入力を拒む)。ヘッダは
    /// 常に 100 バイトなので、[`RandomXVerifier::hash_header`] では起きない。
    ///
    /// なお `randomx-rs` は、返ってきた 32 バイトが全部 0 のときを「計算に
    /// 失敗した」と読む。本物のハッシュが全部 0 になる確率は 2^-256 であり、
    /// 起きたとしてもこちらは誤りとして受け取る。**当たりを 1 つ取り逃がす
    /// だけで、誤ったブロックを通すことはない。**
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
/// ([`RandomXVerifier`]) より速い。
///
/// # 何倍速いかは書かない
///
/// 機械ごとに違うためである。データセットがどの階層に載るか、メモリの
/// 帯域がどれだけあるか、大きなページを使えるかで変わる。**固定した数字を
/// 書けば、どの機械でも当たらない数字になる。** 手元の値は次で測れる。
/// light と fast を両方測り、その比をそのまま表示する。
///
/// ```sh
/// cargo run --release -p oag-pow --features randomx --example hashrate
/// ```
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
/// **確保できなければ誤りを返す。** 落ちはしないので、呼び出し側で light
/// モードに退避できる。
pub struct RandomXMiner {
    seed_height: u64,
    seed: Hash,
    flags: RandomXFlag,
    dataset: RandomXDataset,
    vm: RandomXVM,
}

impl RandomXMiner {
    /// シードを指定して採掘器を作る。データセットを構築する。
    ///
    /// 引数の意味は [`RandomXVerifier::new`] と同じである。
    pub fn new(seed: &Hash, seed_height: u64) -> Result<RandomXMiner, RandomXPowError> {
        // キャッシュのフラグで意味を持つのは FLAG_JIT・FLAG_LARGE_PAGES と
        // Argon2 の実装選択だけである。いずれも速さの指定であって、でき
        // あがるキャッシュの中身は変わらない。JIT を拒む環境では最初の
        // 候補がすぐ失敗するので、ここを順に試すのは安い。
        let (_, cache) = try_each(&flag_ladder(false), |flags| {
            RandomXCache::new(flags, seed.as_bytes())
                .map_err(|e| format!("キャッシュを確保できない: {e}"))
        })?;
        // データセットのフラグで意味を持つのは FLAG_LARGE_PAGES だけである。
        // 用いないので FLAG_DEFAULT でよい。
        //
        // start は 0 でなければならない。0 以外を渡すと、先頭が未初期化の
        // ままのデータセットができ、他の実装と食い違うハッシュを黙って返す。
        let dataset = RandomXDataset::new(RandomXFlag::FLAG_DEFAULT, cache, 0)
            .map_err(|e| RandomXPowError::Init(format!("データセットを確保できない: {e}")))?;
        RandomXMiner::sharing_dataset_with(seed, seed_height, dataset)
    }

    /// すでにあるデータセットを使って、もう 1 個の採掘器を作る。
    ///
    /// **同じスレッドの中でしか使えない。** [`RandomXDataset`] は `Send`
    /// ではないので、別のスレッドへ渡すことはできない (モジュールの説明を
    /// 参照)。2 GB を建て直さずに VM をもう 1 個持ちたいときに使う。
    ///
    /// `seed` と `seed_height` は、そのデータセットを作ったときと同じ値を
    /// 渡すこと。食い違わせると、[`RandomXMiner::seed`] が嘘をつく。
    ///
    /// データセットは作り直さないので、ここで試すのは VM のフラグだけで
    /// ある。データセットの中身はシードだけで決まり、フラグには依らない。
    pub fn sharing_dataset_with(
        seed: &Hash,
        seed_height: u64,
        dataset: RandomXDataset,
    ) -> Result<RandomXMiner, RandomXPowError> {
        let steps = flag_ladder(true);
        let (flags, vm) = try_each(&steps, |flags| {
            create_vm(flags, None, Some(dataset.clone()))
        })?;
        Ok(RandomXMiner {
            seed_height,
            seed: *seed,
            flags,
            dataset,
            vm,
        })
    }

    /// この採掘器が実際に用いているフラグ。
    ///
    /// [`RandomXVerifier::flags`] と同じ理由で見せている。
    pub fn flags(&self) -> RandomXFlag {
        self.flags
    }

    /// JIT で動いているか。偽ならインタプリタであり、**かなり遅い**。
    pub fn uses_jit(&self) -> bool {
        self.flags.contains(RandomXFlag::FLAG_JIT)
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
    /// [`RandomXVerifier::hash`] と**同じ値を返す**。空の入力と全 0 の
    /// 扱いも同じである。
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

// ━━━━━━━━ Send でも Sync でもないことを、コンパイル時に確かめる ━━━━━━━━

/// ある型が `Send` / `Sync` かどうかを、コンパイルを止めずに調べる仕掛け。
///
/// Rust には「`T: !Send` を要求する」書き方がない。そこで、どの型にも
/// 当てはまるトレイト実装 (偽) と、`T: Send` のときだけ存在する固有実装
/// (真) を用意し、固有実装が優先される規則を使って真偽を取り出す。
/// `static_assertions` crate の `assert_not_impl_any!` と同じ手口である。
mod trait_probe {
    use std::marker::PhantomData;

    /// 調べたい型を包むだけの型。
    pub struct Probe<T>(PhantomData<T>);

    /// どの型にも当てはまる既定値。固有実装が無いときはこちらが使われる。
    pub trait Fallback {
        /// `T: Send` か。
        const IS_SEND: bool = false;
        /// `T: Sync` か。
        const IS_SYNC: bool = false;
    }

    impl<T> Fallback for Probe<T> {}

    impl<T: Send> Probe<T> {
        /// `T: Send` のときだけ存在する。トレイトの既定値より優先される。
        pub const IS_SEND: bool = true;
    }

    impl<T: Sync> Probe<T> {
        /// `T: Sync` のときだけ存在する。
        pub const IS_SYNC: bool = true;
    }
}

/// `RandomXVM` は `calculate_hash(&self)` の中でスクラッチパッドを書き換える。
///
/// したがって `Send` でも `Sync` でもあってはならない。今はどちらでもない
/// ため、同じ VM を 2 つのスレッドから触るコードはコンパイルが通らない。
///
/// **この守りは `randomx-rs` の都合であって、こちらが宣言したものではない。**
/// 向こうが `unsafe impl Send` を足せば黙って消える。`forbid(unsafe_code)`
/// は他所の crate の `unsafe impl` を止めない。だからここで固定する。
/// 消えたらビルドが失敗し、こちらで包み直す (`Mutex` なり、スレッドごとに
/// 作り直すなり) 判断を迫られる。
const _: () = {
    // トレイトを見えるようにする。`Probe::<T>::IS_SEND` は、固有実装が
    // 当てはまればそちら (真)、当てはまらなければトレイトの既定値 (偽) に
    // 解決される。**`<Probe<T> as Fallback>::IS_SEND` と書いてはならない。**
    // それでは常にトレイト側、すなわち常に偽になり、検査が素通しになる。
    use trait_probe::{Fallback as _, Probe};

    // まず仕掛けそのものが効いていることを確かめる。u64 は Send かつ Sync
    // なので、ここが偽なら下の検査は全部当てにならない。
    assert!(
        Probe::<u64>::IS_SEND && Probe::<u64>::IS_SYNC,
        "Send/Sync を調べる仕掛けが壊れている。下の検査は意味を成さない。"
    );

    assert!(
        !Probe::<RandomXVM>::IS_SEND,
        "randomx-rs が RandomXVM を Send にした。VM はスクラッチパッドを \
         書き換えるので、スレッドをまたいで渡せるようになると危ない。\
         このモジュールの前提を見直すこと。"
    );
    assert!(
        !Probe::<RandomXVM>::IS_SYNC,
        "randomx-rs が RandomXVM を Sync にした。calculate_hash は &self を \
         取るので、Sync になると 2 つのスレッドから同時に呼べてしまう。\
         スクラッチパッドの競合であり、未定義動作である。"
    );
    assert!(
        !Probe::<RandomXDataset>::IS_SEND,
        "randomx-rs が RandomXDataset を Send にした。モジュールの説明に \
         『データセットはスレッドをまたげない』と書いてあるので、直すこと。\
         複数スレッドの fast 採掘ができるようになる。"
    );

    // 上から自動で従うが、本モジュールが公開しているのはこちらなので
    // 直接も確かめておく。
    assert!(
        !Probe::<RandomXVerifier>::IS_SEND && !Probe::<RandomXVerifier>::IS_SYNC,
        "RandomXVerifier がスレッドをまたげるようになった"
    );
    assert!(
        !Probe::<RandomXMiner>::IS_SEND && !Probe::<RandomXMiner>::IS_SYNC,
        "RandomXMiner がスレッドをまたげるようになった"
    );
};

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

    // ━━━━━━━━ FFI の境界 ━━━━━━━━

    #[test]
    fn the_flag_ladder_ends_somewhere_that_always_works() {
        let light = flag_ladder(false);
        let fast = flag_ladder(true);

        // 最後は必ずインタプリタである。実行可能メモリも大きなページも
        // 要求しないので、どんな環境でも作れる。
        assert_eq!(*light.last().unwrap(), RandomXFlag::FLAG_DEFAULT);
        assert_eq!(*fast.last().unwrap(), RandomXFlag::FLAG_FULL_MEM);

        // light に FLAG_FULL_MEM が混ざってはならない。256 MB で動く
        // ことがフルノードの条件である (SPEC §11.2)。
        for flags in &light {
            assert!(
                !flags.contains(RandomXFlag::FLAG_FULL_MEM),
                "light モードの候補に FLAG_FULL_MEM が入っている: {flags:?}"
            );
        }
        // fast は全部 FLAG_FULL_MEM を持つ。これが fast の定義である。
        for flags in &fast {
            assert!(
                flags.contains(RandomXFlag::FLAG_FULL_MEM),
                "fast モードの候補に FLAG_FULL_MEM が無い: {flags:?}"
            );
        }

        // 候補は速い順、すなわち JIT のあるものが先。
        let first_without_jit = light
            .iter()
            .position(|f| !f.contains(RandomXFlag::FLAG_JIT));
        if let Some(i) = first_without_jit {
            assert!(
                light[i..]
                    .iter()
                    .all(|f| !f.contains(RandomXFlag::FLAG_JIT)),
                "JIT 無しのあとに JIT 付きが来ている: {light:?}"
            );
        }

        // 同じ候補を 2 度試さない。
        let mut seen = light.clone();
        seen.sort_by_key(|f| f.bits());
        seen.dedup();
        assert_eq!(seen.len(), light.len(), "候補が重複している: {light:?}");
    }

    #[test]
    fn the_null_vm_check_still_reads_the_debug_output() {
        // 正しく作れた VM は NULL ではない。**Some(false) でなければ
        // ならない。** None が返るなら randomx-rs の Debug の形が変わった
        // ということであり、NULL 検査が素通しになっている。
        let v = verifier();
        assert_eq!(
            vm_pointer_is_null(&v.vm),
            Some(false),
            "randomx-rs の Debug 出力から VM のポインタを読めなくなった。\n             NULL 検査が効かなくなっているので、vm_pointer_is_null を\n             書き直すこと。実際の出力: {:?}",
            format!("{:?}", v.vm)
        );
    }

    #[test]
    fn a_verifier_reports_which_flags_it_got() {
        let v = verifier();
        // JIT を使えたなら uses_jit は真。使えなかったなら偽。どちらでも
        // よいが、フラグと食い違ってはならない。
        assert_eq!(v.uses_jit(), v.flags().contains(RandomXFlag::FLAG_JIT));
        // light モードの検証器がデータセットを要求してはならない。
        assert!(!v.flags().contains(RandomXFlag::FLAG_FULL_MEM));
    }

    #[test]
    fn every_flag_in_the_ladder_actually_produces_a_working_vm() {
        // 退避先が本当に動くことを確かめる。ここが動かなければ、JIT を
        // 拒む環境で「退避したつもりで落ちる」ことになる。
        //
        // どの候補も同じハッシュを返さなければならない。フラグは速さの
        // 指定であって、計算するものは 1 つである。ここが崩れると、JIT の
        // 有無でノードの合意が割れる。
        let seed = hash::block_hash(b"orange genesis");
        let mut expected: Option<Hash> = None;
        for flags in flag_ladder(false) {
            let cache = RandomXCache::new(flags, seed.as_bytes())
                .unwrap_or_else(|e| panic!("{flags:?} でキャッシュを作れない: {e}"));
            let vm = create_vm(flags, Some(cache), None)
                .unwrap_or_else(|e| panic!("{flags:?} で VM を作れない: {e}"));
            assert_eq!(vm_pointer_is_null(&vm), Some(false), "{flags:?} が NULL");

            let v = RandomXVerifier {
                seed_height: 0,
                seed,
                flags,
                vm,
            };
            let got = v.hash(b"orange").expect("ハッシュを計算できる");
            match expected {
                None => expected = Some(got),
                Some(want) => assert_eq!(got, want, "{flags:?} だけ違うハッシュを返す"),
            }
        }
    }

    #[test]
    fn an_empty_input_is_an_error_not_a_panic() {
        // randomx-rs は空の入力を拒む。落ちずに誤りで返ること。
        let v = verifier();
        assert!(v.hash(b"").is_err());
        // ヘッダは常に 100 バイトなので、hash_header では起きない。
        assert!(v.hash_header(&header(0, 1)).is_ok());
    }
}
