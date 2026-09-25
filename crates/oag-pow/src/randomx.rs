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
//! この crate は `#![deny(unsafe_code)]`、他の crate は全部
//! `#![forbid(unsafe_code)]` である。自分で書いた `unsafe` は
//! [`SharedDataset`] の `unsafe impl` 2 行だけである。ただしそれらが縛るのは
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
//! ## データセットは共有する
//!
//! [`RandomXDataset`] も生ポインタを持つため `Send` ではない。そのままでは
//! 「2 GB のデータセットを 1 個だけ建てて、複数のスレッドで使い回す」ことが
//! 安全な Rust では書けない。
//!
//! 以前はそれを避けて、スレッドごとにデータセットを 1 本ずつ建てていた。
//! **6 スレッドなら 12 GB である。** 構築も 6 回走り、大きなページも
//! 現実的でなくなる。Monero も XMRig も 1 本を全スレッドで共有している。
//!
//! そこで [`SharedDataset`] に `unsafe impl Send / Sync` を 2 行だけ書いた。
//! この crate で `unsafe` と書いてあるのはそこだけである。引き受けている
//! 事柄は [`SharedDataset`] に書いてある。要点は、**データセットは初期化が
//! 済めば読むだけのものであり、RandomX 自身が複数の VM での共有を想定して
//! いる**ことである。
//!
//! VM は相変わらず共有しない。スクラッチパッドを書き換えるからである。
//! 各作業スレッドは [`SharedDataset::miner`] で自分の VM を建てる。
//! スレッド境界を越えるのは [`SharedDataset`] だけで、[`RandomXMiner`] も
//! [`RandomXVerifier`] もそれぞれのスレッドの上で建ち、そこから動かない。
//!
//! ## 大きなページ
//!
//! データセットとキャッシュは、まず大きなページ (Linux の hugetlb、
//! Windows の large pages) で確保を試みる。データセットへの読み出しは
//! 2 GB の中を飛び回るので、4 KB のページでは TLB が足りない。大きな
//! ページで確保できれば、その分速くなる。
//!
//! **確保できなければ、黙って普通のページに退く。** 何もしていない機械
//! ではまず確保できない。OS 側で用意が要る (Linux は `vm.nr_hugepages`、
//! Windows は「メモリ内のページのロック」の権限)。どちらになったかは
//! [`SharedDataset::uses_large_pages`] で分かる。
//!
//! VM のスクラッチパッド (2 MB) には大きなページを使わない。VM の確保に
//! 失敗すると、NULL の VM と一緒にデータセットの参照を手放せなくなる
//! (`create_vm` を見よ)。失敗しうる試みを VM の側に増やさないためである。
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
    #[error("RandomX initialisation failed: {0}")]
    Init(String),
    /// どのフラグの組み合わせでも RandomX を初期化できなかった。
    ///
    /// 実行可能メモリも大きな確保もできない環境である。ここまで来たら
    /// このホストでは RandomX を動かせない。
    #[error("cannot initialise RandomX (flags tried: {tried}). Last error: {last}")]
    NoUsableConfiguration {
        /// 試したフラグの一覧。
        tried: String,
        /// 最後に起きた誤り。
        last: String,
    },
    /// ハッシュの計算に失敗した。
    #[error("the RandomX hash computation failed: {0}")]
    Hash(String),
    /// 返されたハッシュの長さが 32 バイトでない。
    #[error("RandomX returned {0} bytes (should be 32)")]
    BadHashLength(usize),
    /// 難易度が 0。
    #[error("difficulty must be 1 or more")]
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
        return Err("randomx_create_vm returned NULL (allocation failed)".to_string());
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
    let mut last = String::from("(not tried)");
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
                .map_err(|e| format!("cannot allocate the cache: {e}"))?;
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
                "the verifier is for seed height {} but the header at height {} requires {}",
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

/// 確保の候補それぞれの前に、大きなページを付けたものを差し込む。
///
/// `[a, b]` は `[a | 大きなページ, a, b | 大きなページ, b]` になる。
/// 速い順は崩れない。大きなページが取れない機械では、付けた方の候補が
/// その場で失敗して次に進むだけである (`mmap` や `VirtualAlloc` が
/// 断るだけなので、試すのは安い)。
///
/// **キャッシュとデータセットにだけ使う。** VM には使わない
/// (モジュールの説明の「大きなページ」を見よ)。
fn with_large_pages(steps: &[RandomXFlag]) -> Vec<RandomXFlag> {
    let mut out = Vec::with_capacity(steps.len() * 2);
    for &flags in steps {
        out.push(flags | RandomXFlag::FLAG_LARGE_PAGES);
        out.push(flags);
    }
    out.dedup();
    out
}

/// 採掘スレッドの間で共有できる、fast モードのデータセット。
///
/// 1 つのシードエポックに対応する。**2 GB を 1 本だけ建て、何本の
/// スレッドからでも使う。** 各スレッドは [`SharedDataset::miner`] で
/// 自分の VM を建てる。
///
/// 安く複製できる (中身は参照の数を数えているだけである)。最後の
/// 複製が消えたときにデータセットが解放される。
///
/// # `unsafe impl Send / Sync` が引き受けていること
///
/// この crate で `unsafe` と書いてあるのはこの 2 行だけである。
/// 以下は `randomx-rs` 1.6.0 と、その中の tevador/RandomX を読んだうえで
/// 言えることである。
///
/// 1. **初期化が済めば、データセットは読むだけである。**
///    `RandomXDataset::new` は確保と初期化 (`randomx_init_dataset`) を
///    終えてから値を返す。その後に書き換える API は `randomx-rs` に無い。
///    VM はデータセットをポインタで受け取って読むだけである
///    (`randomx_create_vm` / `randomx_calculate_hash`)。読むだけのメモリを
///    複数のスレッドから同時に読むのは競合ではない。
/// 2. **RandomX 自身がこの使い方をしている。** 同梱のベンチマーク
///    (`src/tests/benchmark.cpp`) は、データセットを 1 つだけ確保し、
///    スレッドごとに建てた VM へ同じものを渡して並行に回している。
///    README も fast モードの 2080 MiB を「共有メモリ」と書いている。
///    Monero も XMRig もそうしている。
/// 3. **解放は 1 回だけ、どのスレッドで起きてもよい。** `RandomXDataset`
///    は中身を `Arc` で持つ。数えるのは不可分操作であり、最後の 1 つが
///    消えたときに `randomx_release_dataset` が 1 回だけ走る。解放は
///    `free` / `munmap` / `VirtualFree` であって、確保したスレッドを
///    問わない。データセットが抱えているキャッシュも同じである。
/// 4. **VM は越えさせない。** ここで `Send` にしているのはデータセット
///    だけである。スクラッチパッドを書き換える [`RandomXMiner`] は
///    `Send` でも `Sync` でもないままであり、このファイル末尾の `const _`
///    がそれを固定している。
///
/// `randomx-rs` が `RandomXDataset` に `Send` / `Sync` を足せば、この
/// 2 行は要らなくなる。末尾の `const _` がそのときにビルドを落として
/// 知らせる。
#[derive(Clone)]
pub struct SharedDataset {
    seed_height: u64,
    seed: Hash,
    /// VM を建てるときのフラグ。建てる前に 1 度だけ確かめておく。
    vm_flags: RandomXFlag,
    /// データセットを大きなページで確保できたか。
    large_pages: bool,
    dataset: RandomXDataset,
}

// 上の説明の 1〜4 を引き受けている。
#[allow(unsafe_code)]
unsafe impl Send for SharedDataset {}
#[allow(unsafe_code)]
unsafe impl Sync for SharedDataset {}

impl SharedDataset {
    /// データセットを構築する。**1 分前後かかる。**
    ///
    /// 引数の意味は [`RandomXVerifier::new`] と同じである。
    ///
    /// 2 GB を確保できなければ誤りを返す。落ちはしないので、呼び出し側で
    /// light モードに退避できる。
    pub fn new(seed: &Hash, seed_height: u64) -> Result<SharedDataset, RandomXPowError> {
        // キャッシュのフラグで意味を持つのは FLAG_JIT・FLAG_LARGE_PAGES と
        // Argon2 の実装選択だけである。いずれも速さの指定であって、でき
        // あがるキャッシュの中身は変わらない。JIT を拒む環境や大きなページ
        // が無い環境では、その候補がすぐ失敗するので、順に試すのは安い。
        let (_, cache) = try_each(&with_large_pages(&flag_ladder(false)), |flags| {
            RandomXCache::new(flags, seed.as_bytes())
                .map_err(|e| format!("cannot allocate the cache: {e}"))
        })?;

        // VM のフラグをここで 1 度だけ決める。
        //
        // 作業スレッドの上で候補を順に試すと、失敗した候補ごとに
        // データセットの参照を 1 つ手放せなくなる (`create_vm` を見よ)。
        // すなわち 2 GB が二度と解放されない。そこでキャッシュを使った
        // light の VM で先に試す。JIT とハードウェア AES が使えるかは、
        // light と fast で変わらない。失敗しても手放せなくなるのは
        // キャッシュの参照だけであり、それはどのみちデータセットが
        // 抱えている。
        let (probed, probe) = try_each(&flag_ladder(false), |flags| {
            create_vm(flags, Some(cache.clone()), None)
        })?;
        drop(probe);
        let vm_flags = probed | RandomXFlag::FLAG_FULL_MEM;

        // データセットのフラグで意味を持つのは FLAG_LARGE_PAGES だけである。
        //
        // start は 0 でなければならない。0 以外を渡すと、先頭が未初期化の
        // ままのデータセットができ、他の実装と食い違うハッシュを黙って返す。
        let dataset_steps = [RandomXFlag::FLAG_LARGE_PAGES, RandomXFlag::FLAG_DEFAULT];
        let (dataset_flags, dataset) = try_each(&dataset_steps, |flags| {
            RandomXDataset::new(flags, cache.clone(), 0)
                .map_err(|e| format!("cannot allocate the dataset: {e}"))
        })?;

        Ok(SharedDataset {
            seed_height,
            seed: *seed,
            vm_flags,
            large_pages: dataset_flags.contains(RandomXFlag::FLAG_LARGE_PAGES),
            dataset,
        })
    }

    /// このデータセットを使う採掘器を 1 つ建てる。
    ///
    /// **呼んだスレッドの上で建ち、そこから動かない。** 採掘スレッドの
    /// それぞれが自分の分を呼ぶ。データセットは建て直さない。
    pub fn miner(&self) -> Result<RandomXMiner, RandomXPowError> {
        let vm = create_vm(self.vm_flags, None, Some(self.dataset.clone()))
            .map_err(|e| RandomXPowError::Init(format!("cannot create a fast-mode VM: {e}")))?;
        Ok(RandomXMiner {
            seed_height: self.seed_height,
            seed: self.seed,
            flags: self.vm_flags,
            large_pages: self.large_pages,
            vm,
        })
    }

    /// データセットを大きなページで確保できたか。
    ///
    /// 偽でも動く。大きなページの分だけ速さを取り逃がしている。
    pub fn uses_large_pages(&self) -> bool {
        self.large_pages
    }

    /// このデータセットが対応するシードのブロック高さ。
    pub fn seed_height(&self) -> u64 {
        self.seed_height
    }

    /// このデータセットが用いているシード。
    pub fn seed(&self) -> Hash {
        self.seed
    }
}

impl std::fmt::Debug for SharedDataset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedDataset")
            .field("seed_height", &self.seed_height)
            .field("vm_flags", &self.vm_flags)
            .field("large_pages", &self.large_pages)
            .finish()
    }
}

/// fast モードの RandomX 採掘器。
///
/// 2 GB のデータセットを用いる。light モード ([`RandomXVerifier`]) より
/// 速い。複数のスレッドで掘るときは [`SharedDataset`] を 1 つ建てて、
/// スレッドごとに [`SharedDataset::miner`] を呼ぶ。
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
/// **スレッドが何本でもこの 1 組で済む。** スレッドごとに増えるのは
/// VM のスクラッチパッド 2 MB だけである。
pub struct RandomXMiner {
    seed_height: u64,
    seed: Hash,
    flags: RandomXFlag,
    large_pages: bool,
    /// データセットへの参照は VM が持っている。VM が生きている間は
    /// データセットも解放されない。
    vm: RandomXVM,
}

impl RandomXMiner {
    /// シードを指定して採掘器を 1 つ作る。データセットを構築する。
    ///
    /// 引数の意味は [`RandomXVerifier::new`] と同じである。1 スレッドで
    /// 掘るとき、あるいは試験のためのものである。複数のスレッドで掘る
    /// なら [`SharedDataset`] を使うこと。これを本数だけ呼ぶと、
    /// データセットも本数だけ建つ。
    pub fn new(seed: &Hash, seed_height: u64) -> Result<RandomXMiner, RandomXPowError> {
        SharedDataset::new(seed, seed_height)?.miner()
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

    /// データセットを大きなページで確保できたか。
    pub fn uses_large_pages(&self) -> bool {
        self.large_pages
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
        "the mechanism that checks Send/Sync is broken. The check below is meaningless."
    );

    assert!(
        !Probe::<RandomXVM>::IS_SEND,
        "randomx-rs has made RandomXVM Send. A VM rewrites its scratchpad, so \
         being able to pass it across threads is dangerous. Revisit the \
         assumptions of this module."
    );
    assert!(
        !Probe::<RandomXVM>::IS_SYNC,
        "randomx-rs has made RandomXVM Sync. calculate_hash takes &self, so \
         once it is Sync two threads can call it at the same time. That races \
         on the scratchpad, which is undefined behaviour."
    );
    assert!(
        !Probe::<RandomXDataset>::IS_SEND && !Probe::<RandomXDataset>::IS_SYNC,
        "randomx-rs has made RandomXDataset Send or Sync. The two \
         `unsafe impl` lines on SharedDataset are no longer needed: remove \
         them and go back to #![forbid(unsafe_code)] in lib.rs."
    );
    // 採掘スレッドへ渡すのはこれである。渡せなくなったら採掘が組めない。
    assert!(
        Probe::<SharedDataset>::IS_SEND && Probe::<SharedDataset>::IS_SYNC,
        "SharedDataset can no longer cross threads"
    );

    // 上から自動で従うが、本モジュールが公開しているのはこちらなので
    // 直接も確かめておく。
    assert!(
        !Probe::<RandomXVerifier>::IS_SEND && !Probe::<RandomXVerifier>::IS_SYNC,
        "RandomXVerifier has become able to cross threads"
    );
    assert!(
        !Probe::<RandomXMiner>::IS_SEND && !Probe::<RandomXMiner>::IS_SYNC,
        "RandomXMiner has become able to cross threads"
    );
};

#[cfg(test)]
mod tests {
    use super::*;
    use oag_primitives::hash;

    fn verifier() -> RandomXVerifier {
        RandomXVerifier::new(&hash::block_hash(b"orange genesis"), 0).expect("can be initialised")
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
        assert!(
            !v.verify(&h),
            "an epoch mismatch is treated as a PoW failure"
        );
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
        let (nonce, pow_hash) = found.expect("it should be found at difficulty 32");

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
                "FLAG_FULL_MEM is among the light-mode candidates: {flags:?}"
            );
        }
        // fast は全部 FLAG_FULL_MEM を持つ。これが fast の定義である。
        for flags in &fast {
            assert!(
                flags.contains(RandomXFlag::FLAG_FULL_MEM),
                "FLAG_FULL_MEM is missing from the fast-mode candidates: {flags:?}"
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
                "a JIT-enabled candidate comes after a JIT-less one: {light:?}"
            );
        }

        // 同じ候補を 2 度試さない。
        let mut seen = light.clone();
        seen.sort_by_key(|f| f.bits());
        seen.dedup();
        assert_eq!(
            seen.len(),
            light.len(),
            "the candidates contain duplicates: {light:?}"
        );
    }

    #[test]
    fn large_pages_are_tried_first_and_given_up_on_quietly() {
        let base = flag_ladder(false);
        let steps = with_large_pages(&base);
        // 大きなページを付けたものが先、付けないものが後。
        assert_eq!(steps.len(), base.len() * 2);
        for (pair, &flags) in steps.chunks(2).zip(&base) {
            assert_eq!(pair[0], flags | RandomXFlag::FLAG_LARGE_PAGES);
            assert_eq!(pair[1], flags);
        }
        // 最後は必ず大きなページを要求しない。取れない機械でも止まらない。
        assert_eq!(*steps.last().unwrap(), RandomXFlag::FLAG_DEFAULT);
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
            "the VM pointer can no longer be read from randomx-rs's Debug output.\n             The NULL check has stopped working, so vm_pointer_is_null must be\n             rewritten. Actual output: {:?}",
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
                .unwrap_or_else(|e| panic!("cannot create a cache with {flags:?}: {e}"));
            let vm = create_vm(flags, Some(cache), None)
                .unwrap_or_else(|e| panic!("cannot create a VM with {flags:?}: {e}"));
            assert_eq!(vm_pointer_is_null(&vm), Some(false), "{flags:?} gave NULL");

            let v = RandomXVerifier {
                seed_height: 0,
                seed,
                flags,
                vm,
            };
            let got = v.hash(b"orange").expect("a hash can be computed");
            match expected {
                None => expected = Some(got),
                Some(want) => assert_eq!(got, want, "only {flags:?} returns a different hash"),
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
