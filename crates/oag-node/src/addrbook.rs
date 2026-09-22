//! ピアの住所帳。Bitcoin の `addrman` と同じ二表構造である。
//!
//! 一度知った相手を覚えておき、次に起動したときに繋ぎ直せるようにする。
//! これが無いと、繋ぐたびに人づてに IP を聞くことになる。
//!
//! # 何から守るのか
//!
//! 住所帳は**相手が中身を決める記憶域**である。`addr` メッセージで送られて
//! きた住所をそのまま溜めるので、攻撃者は好きな住所をいくらでも送り込める。
//! 狙いは日蝕攻撃 (eclipse attack) である。住所帳を自分の手下で埋め尽くし、
//! 被害者が正直なノードに繋がらないようにする。そうなれば、被害者に見せる
//! チェーンを攻撃者が選べる。
//!
//! # 二つの表
//!
//! | 表 | 中身 | 大きさ |
//! | --- | --- | ---: |
//! | `new` | **聞いただけ**の住所 | [`NEW_BUCKET_COUNT`] × [`BUCKET_SIZE`] |
//! | `tried` | **実際に繋がった**住所 | [`TRIED_BUCKET_COUNT`] × [`BUCKET_SIZE`] |
//!
//! `new` から `tried` への昇格には、**接続が成功したという事実**を要求する。
//! これが要である。`addr` を送りつけるだけでは `tried` に入れない。
//!
//! 外向きの接続先を選ぶとき、`new` と `tried` を**半々**で引く
//! ([`AddressBook::candidates`])。したがって `new` が丸ごと攻撃者のもので
//! あっても、外向きの接続の半分は実績のある相手に向かう。**埋め尽くしが
//! 効かなくなるのはこの一点による。**
//!
//! # どのバケットに入るかは当てられない
//!
//! バケットは住所そのものではなく、**ノードごとの秘密の鍵と一緒に**
//! ハッシュして決める。鍵を知らなければ、
//! 狙ったバケットに入る住所を作れない。鍵は住所帳と一緒に保存する。
//! 起動のたびに変えると、その都度すべての住所が別のバケットへ散り、
//! 表の中身が意味を失う。
//!
//! 攻撃者が占められる枠には、構造そのものが上限を与える。
//!
//! - `new`: **1 つの出どころ**から届いた住所は
//!   [`NEW_BUCKETS_PER_SOURCE_GROUP`] 個のバケットにしか入らない。
//!   1,024 個のうちの 64 個、すなわち `new` 全体の 6.25 % である
//! - `tried`: **同じ /16** に属する住所は [`TRIED_BUCKETS_PER_GROUP`] 個の
//!   バケットにしか入らない。256 個のうちの 8 個、3.1 % である
//!
//! 住所を大量に用意することより、**別々のネットワークを大量に用意する
//! ことのほうがずっと高くつく**、という前提に立っている。
//!
//! # 繋がらない相手を延々と試さない
//!
//! 失敗した住所は、失敗の回数に応じて間を空けてから再試行する
//! ([`backoff`])。落ちたノードに毎秒繋ぎに行っても迷惑なだけである。
//! 見込みが尽きた住所は [`Entry::is_terrible`] が真になり、バケットの枠が
//! 要るときに真っ先に譲る。

use oag_net::message::NetAddress;
use oag_primitives::{hash, Network};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// `new` 表のバケット数。
pub const NEW_BUCKET_COUNT: usize = 1_024;

/// `tried` 表のバケット数。
pub const TRIED_BUCKET_COUNT: usize = 256;

/// 1 つのバケットに入る住所の数。
pub const BUCKET_SIZE: usize = 64;

/// 1 つの出どころ (/16) から届いた住所が入りうる `new` バケットの数。
///
/// **日蝕攻撃への主たる対策である。** 1 つのネットワークから何万件
/// 送られても、触れるバケットはこの数で頭打ちになる。
pub const NEW_BUCKETS_PER_SOURCE_GROUP: usize = 64;

/// 同じ /16 に属する住所が入りうる `tried` バケットの数。
pub const TRIED_BUCKETS_PER_GROUP: usize = 8;

/// 1 つの住所が `new` 表で占めうる枠の数。
///
/// 別々の出どころから聞いた住所は、その数だけ枠を取る。多くのピアが
/// 知っている住所ほど選ばれやすくなる、という重み付けである。
pub const NEW_BUCKETS_PER_ADDRESS: usize = 8;

/// 覚えておける住所の上限。二つの表の枠の合計である。
pub const MAX_ENTRIES: usize = NEW_BUCKET_COUNT * BUCKET_SIZE + TRIED_BUCKET_COUNT * BUCKET_SIZE;

/// 1 回の `addr` で受け取る住所の上限。
///
/// プロトコル上の上限 ([`oag_net::message::MAX_ADDRESSES`]) より小さく
/// 取る。1 通で `new` の 1 バケット分を超えて書き換えられるのは多すぎる。
pub const MAX_PER_MESSAGE: usize = 256;

/// `getaddr` に対して返す住所の上限。
pub const MAX_TO_SHARE: usize = 256;

/// 失敗の回数に対する再試行までの間隔の下限 (秒)。
const BACKOFF_BASE_SECS: i64 = 60;

/// 再試行までの間隔の上限 (秒)。
const BACKOFF_MAX_SECS: i64 = 6 * 60 * 60;

/// これより古い住所は覚えない・配らない (秒)。
const STALE_SECS: i64 = 30 * 24 * 60 * 60;

/// 未来の時刻を名乗られたときに許す幅 (秒)。
///
/// **これが無いと、未来の `last_seen` を名乗るだけで居座れる。**
const MAX_FUTURE_SECS: i64 = 10 * 60;

/// 一度も繋がらないまま見限るまでの失敗回数。
const GIVE_UP_UNPROVEN: u32 = 3;

/// 一度は繋がった住所を見限るまでの失敗回数。
const GIVE_UP_PROVEN: u32 = 10;

/// 「一度は繋がった」を実績として数えなくなるまでの期間 (秒)。
const SUCCESS_STALE_SECS: i64 = 7 * 24 * 60 * 60;

/// いま試している最中とみなす幅 (秒)。
const IN_FLIGHT_SECS: i64 = 60;

/// 住所帳の 1 件。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// 最後に見かけた時刻 (Unix 秒)。
    pub last_seen: i64,
    /// 最後に繋ぎに行った時刻。まだなら `None`。
    pub last_try: Option<i64>,
    /// 最後に繋がった時刻。まだなら `None`。
    pub last_success: Option<i64>,
    /// 繋がってから連続して失敗した回数。
    pub failures: u32,
    /// 相手が名乗った提供機能。**まだ聞いていなければ 0。**
    ///
    /// 自分でハンドシェイクして確かめた値だけを入れる。他のピアから
    /// 伝え聞いた値は入れない — 第三者について嘘をつけるからである。
    ///
    /// 欄の無い古い `peers.json` からは 0 として読み込まれる
    /// (`serde(default)`)。「書いてなかった」と「まだ聞いていない」は
    /// どちらも「知らない」であり、同じ 0 で構わない。次に繋いだときに
    /// 本当の値が入る。
    #[serde(default)]
    pub services: u64,
}

impl Entry {
    fn new(last_seen: i64) -> Entry {
        Entry {
            last_seen,
            last_try: None,
            last_success: None,
            failures: 0,
            services: 0,
        }
    }

    /// 一度でも繋がったことがあるか。
    pub fn is_proven(&self) -> bool {
        self.last_success.is_some()
    }

    /// 見込みが尽きているか。
    ///
    /// 真なら、バケットの枠が要るときに真っ先に譲る。Bitcoin の
    /// `IsTerrible` と同じ判定である。
    pub fn is_terrible(&self, now: i64) -> bool {
        // いま試している最中なら、結果が出るまで判断しない。
        if self.last_try.is_some_and(|t| now - t < IN_FLIGHT_SECS) {
            return false;
        }
        if self.last_seen > now + MAX_FUTURE_SECS {
            return true;
        }
        if now - self.last_seen > STALE_SECS {
            return true;
        }
        if !self.is_proven() && self.failures >= GIVE_UP_UNPROVEN {
            return true;
        }
        if self
            .last_success
            .is_some_and(|s| now - s > SUCCESS_STALE_SECS)
            && self.failures >= GIVE_UP_PROVEN
        {
            return true;
        }
        false
    }

    /// いま繋ぎに行ってよいか (再試行の間隔を満たしているか)。
    fn is_ready(&self, now: i64) -> bool {
        match self.last_try {
            None => true,
            Some(tried) => now >= tried.saturating_add(backoff(self.failures)),
        }
    }
}

/// 失敗が `failures` 回続いた住所を、次に試すまで空ける秒数。
///
/// 1 分から始めて倍々にし、6 時間で頭打ちにする。
pub fn backoff(failures: u32) -> i64 {
    if failures == 0 {
        return 0;
    }
    BACKOFF_BASE_SECS
        .saturating_mul(1i64 << failures.min(20))
        .min(BACKOFF_MAX_SECS)
}

/// 住所の属するネットワークの括り。
///
/// IPv4 は /16、IPv6 は /32 で括る。バケットの決定と、外向きの接続先を
/// 散らすことの両方に用いる。
fn group_of(addr: &SocketAddr) -> [u8; 4] {
    match addr.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            [0, 0, o[0], o[1]]
        }
        IpAddr::V6(v6) => {
            // IPv4 射影は IPv4 として括る。括りを二重に持つと、
            // 同じ相手が 2 つの枠を取れてしまう。
            if let Some(v4) = v6.to_ipv4_mapped() {
                let o = v4.octets();
                return [0, 0, o[0], o[1]];
            }
            let o = v6.octets();
            [o[0], o[1], o[2], o[3]]
        }
    }
}

/// 住所を正準な 18 バイトにする (IPv6 形式 16 バイト + ポート 2 バイト)。
///
/// IPv4 射影は元の IPv4 と同じ並びになる。**でなければ、同じ相手が
/// 二つの別々の枠を取れてしまう。**
fn addr_bytes(addr: &SocketAddr) -> [u8; 18] {
    let octets = match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_ipv6_mapped().octets(),
            None => v6.octets(),
        },
    };
    let mut out = [0u8; 18];
    out[..16].copy_from_slice(&octets);
    out[16..].copy_from_slice(&addr.port().to_le_bytes());
    out
}

/// そのネットワークで覚えてよい住所か。
///
/// 公開ネットワークでは、外から到達できない住所を覚えない。ループバック
/// や private の住所を配ると、受け取った側が自分自身や無関係な機器に
/// 繋ぎに行くことになる。**regtest は手元で試すためのものなので許す。**
pub fn is_storable(network: Network, addr: &SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    if network == Network::Regtest {
        return true;
    }
    match addr.ip() {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // 100.64.0.0/10 (CGNAT)。is_shared は安定化されていない。
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_storable(network, &SocketAddr::new(IpAddr::V4(v4), addr.port()));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 (ULA) と fe80::/10 (リンクローカル)。
                || (v6.octets()[0] & 0xfe) == 0xfc
                || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xc0) == 0x80))
        }
    }
}

/// 覚えている 1 件と、その置き場所。
#[derive(Debug, Clone)]
struct Info {
    entry: Entry,
    /// 誰から聞いたかの括り。`new` のバケットを決めるのに使う。
    source_group: [u8; 4],
    /// `tried` 表に居るか。真なら `new_slots` は空である。
    in_tried: bool,
    /// `new` 表で占めている枠 (バケット番号, 位置)。
    new_slots: Vec<(u16, u8)>,
}

/// 小さな擬似乱数。接続先の選択にだけ使う。
///
/// **暗号用途ではない。** 種だけを OS から取り、以後は xorshift で回す。
/// 1 回の選択で数百回引くため、その都度 OS を呼ぶ必要はない。
struct Rng(u64);

impl Rng {
    fn new() -> Rng {
        let mut seed = [0u8; 8];
        oag_primitives::fill_random(&mut seed);
        Rng(u64::from_le_bytes(seed) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next() % n as u64) as usize
    }
}

/// バケットの表。`new` と `tried` で同じ形を使う。
///
/// 埋まっている枠の一覧を別に持つ。**持たないと、疎な表から 1 件引くのに
/// 表を舐めることになる。** 起動直後は 65,536 枠に数件しか入っていない。
#[derive(Debug)]
struct Table {
    /// `slots[バケット][位置]` = (住所, `filled` の何番目か)。
    slots: Vec<Vec<Option<(SocketAddr, u32)>>>,
    /// 埋まっている枠の一覧。
    ///
    /// **枠ごとに 1 つ載る。** 複数の枠を持つ住所は、その数だけ
    /// 選ばれやすくなる。多くのピアが知っている住所を重く見る、という
    /// 重み付けがこれで働く。
    filled: Vec<(u16, u8)>,
}

impl Table {
    fn new(buckets: usize) -> Table {
        Table {
            slots: vec![vec![None; BUCKET_SIZE]; buckets],
            filled: Vec::new(),
        }
    }

    /// 埋まっている枠の数。
    fn len(&self) -> usize {
        self.filled.len()
    }

    fn get(&self, bucket: usize, slot: usize) -> Option<SocketAddr> {
        self.slots[bucket][slot].map(|(addr, _)| addr)
    }

    /// 空いている枠に入れる。埋まっていれば何もしない。
    fn set(&mut self, bucket: usize, slot: usize, addr: SocketAddr) {
        if self.slots[bucket][slot].is_some() {
            return;
        }
        let index = self.filled.len() as u32;
        self.filled.push((bucket as u16, slot as u8));
        self.slots[bucket][slot] = Some((addr, index));
    }

    /// 枠を空ける。`filled` の穴は末尾を詰めて埋める。
    fn clear(&mut self, bucket: usize, slot: usize) -> Option<SocketAddr> {
        let (addr, index) = self.slots[bucket][slot].take()?;
        let last = self.filled.len() - 1;
        self.filled.swap_remove(index as usize);
        // 末尾から移ってきた枠の、自分の番号を書き直す。
        if (index as usize) < last {
            let (b, s) = self.filled[index as usize];
            if let Some((_, moved)) = &mut self.slots[b as usize][s as usize] {
                *moved = index;
            }
        }
        Some(addr)
    }

    /// 埋まっている枠から 1 つを無作為に引く。
    fn draw(&self, rng: &mut Rng) -> Option<SocketAddr> {
        if self.filled.is_empty() {
            return None;
        }
        let (bucket, slot) = self.filled[rng.below(self.filled.len())];
        self.get(bucket as usize, slot as usize)
    }
}

/// 住所帳。
pub struct AddressBook {
    network: Network,
    /// バケットを決めるための秘密の鍵。
    ///
    /// **これが漏れると、狙ったバケットを埋める住所を作られる。**
    key: [u8; 32],
    entries: HashMap<SocketAddr, Info>,
    /// 聞いただけの住所の表。
    new_table: Table,
    /// 繋がったことのある住所の表。1 住所につき 1 枠である。
    tried_table: Table,
    /// 自分自身の住所。覚えない。
    own: Vec<SocketAddr>,
    /// 保存先。`None` なら保存しない (試験用)。
    path: Option<PathBuf>,
    /// 保存していない変更があるか。
    dirty: bool,
}

impl std::fmt::Debug for AddressBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // **鍵は出さない。** 出てしまえば、狙ったバケットを埋められる。
        f.debug_struct("AddressBook")
            .field("network", &self.network)
            .field("entries", &self.entries.len())
            .field("tried", &self.tried_table.len())
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// ファイルに書き出す 1 件。
#[derive(Debug, Serialize, Deserialize)]
struct StoredEntry {
    addr: SocketAddr,
    entry: Entry,
    source_group: [u8; 4],
    in_tried: bool,
}

/// ファイルに書き出す形。
#[derive(Debug, Serialize, Deserialize)]
struct Stored {
    version: u32,
    network: String,
    /// バケットの鍵。**これが変わると、全住所が別のバケットへ散る。**
    key: [u8; 32],
    entries: Vec<StoredEntry>,
}

/// 保存の形式の版数。
///
/// 1 は一つの表だけを持っていた頃のもの。二表構造では読まない。
const FORMAT_VERSION: u32 = 2;

const TAG_NEW_INDEX: &str = "OAG/addrbook/new-index";
const TAG_NEW_BUCKET: &str = "OAG/addrbook/new-bucket";
const TAG_TRIED_INDEX: &str = "OAG/addrbook/tried-index";
const TAG_TRIED_BUCKET: &str = "OAG/addrbook/tried-bucket";
const TAG_SLOT: &str = "OAG/addrbook/slot";

impl AddressBook {
    /// 空の住所帳。保存しない。
    pub fn in_memory(network: Network) -> AddressBook {
        let mut key = [0u8; 32];
        oag_primitives::fill_random(&mut key);
        AddressBook {
            network,
            key,
            entries: HashMap::new(),
            new_table: Table::new(NEW_BUCKET_COUNT),
            tried_table: Table::new(TRIED_BUCKET_COUNT),
            own: Vec::new(),
            path: None,
            dirty: false,
        }
    }

    /// ファイルから読み込む。無ければ空で始める。
    ///
    /// **壊れていても起動を止めない。** 住所帳はいつでも作り直せる。
    /// 読めなければ捨てて空から始め、その旨を告げる。
    pub fn open(network: Network, path: &Path) -> AddressBook {
        let mut book = AddressBook::in_memory(network);
        book.path = Some(path.to_path_buf());

        let Ok(text) = std::fs::read_to_string(path) else {
            return book;
        };
        match serde_json::from_str::<Stored>(&text) {
            Ok(stored)
                if stored.version == FORMAT_VERSION && stored.network == network.to_string() =>
            {
                // **鍵を先に戻す。** でなければ、バケットの割り当てが
                // 起動のたびに変わり、表の意味が失われる。
                book.key = stored.key;
                // tried を先に戻す。new から戻すと、tried に居るはずの
                // 住所が new の枠を取ってしまう。
                for stored in stored
                    .entries
                    .iter()
                    .filter(|s| s.in_tried)
                    .chain(stored.entries.iter().filter(|s| !s.in_tried))
                {
                    if !is_storable(network, &stored.addr) {
                        continue;
                    }
                    book.restore(stored);
                }
                book.dirty = false;
            }
            Ok(stored) => {
                crate::log_warn!(
                    "{} is from version {} / {} and does not match the current {network}. Starting empty.",
                    path.display(),
                    stored.version,
                    stored.network
                );
            }
            Err(e) => {
                crate::log_warn!("{} cannot be read ({e}). Starting empty.", path.display());
            }
        }
        book
    }

    /// 保存された 1 件を表へ戻す。
    fn restore(&mut self, stored: &StoredEntry) {
        if stored.in_tried {
            let bucket = self.tried_bucket(&stored.addr);
            let slot = self.slot(true, bucket, &stored.addr);
            if self.tried_table.get(bucket, slot).is_some() {
                return;
            }
            self.entries.insert(
                stored.addr,
                Info {
                    entry: stored.entry,
                    source_group: stored.source_group,
                    in_tried: true,
                    new_slots: Vec::new(),
                },
            );
            self.tried_table.set(bucket, slot, stored.addr);
            return;
        }
        let bucket = self.new_bucket(&stored.addr, &stored.source_group);
        let slot = self.slot(false, bucket, &stored.addr);
        if self.new_table.get(bucket, slot).is_some() {
            return;
        }
        self.entries.insert(
            stored.addr,
            Info {
                entry: stored.entry,
                source_group: stored.source_group,
                in_tried: false,
                new_slots: vec![(bucket as u16, slot as u8)],
            },
        );
        self.new_table.set(bucket, slot, stored.addr);
    }

    /// 自分自身の住所を登録する。以後、この住所は覚えない。
    pub fn set_own(&mut self, addrs: Vec<SocketAddr>) {
        self.own = addrs;
    }

    /// 覚えている件数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 1 件も覚えていないか。
    ///
    /// **真ならシードに頼るしかない。**
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `tried` 表に居る件数 (実際に繋がったことのある住所の数)。
    pub fn tried_len(&self) -> usize {
        self.tried_table.len()
    }

    /// `new` 表に居る件数 (聞いただけの住所の数)。
    ///
    /// 枠の数ではなく**住所の数**である。1 つの住所が複数の枠を占める
    /// ことがある。
    pub fn new_len(&self) -> usize {
        self.entries.len() - self.tried_table.len()
    }

    /// 1 件を引く。
    pub fn get(&self, addr: &SocketAddr) -> Option<&Entry> {
        self.entries.get(addr).map(|info| &info.entry)
    }

    // ── バケットの決め方 ──

    fn digest(&self, tag: &str, parts: &[&[u8]]) -> u64 {
        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(&self.key);
        for part in parts {
            data.extend_from_slice(part);
        }
        let digest = hash::tagged(tag, &data);
        u64::from_le_bytes(
            digest.as_bytes()[..8]
                .try_into()
                .expect("there are 32 bytes"),
        )
    }

    /// `new` 表のどのバケットに入るか。
    ///
    /// **出どころの括りが効く。** 1 つの出どころから届いた住所は、
    /// [`NEW_BUCKETS_PER_SOURCE_GROUP`] 個のバケットにしか散らない。
    fn new_bucket(&self, addr: &SocketAddr, source_group: &[u8; 4]) -> usize {
        let group = group_of(addr);
        let index = self.digest(TAG_NEW_INDEX, &[&group, source_group])
            % NEW_BUCKETS_PER_SOURCE_GROUP as u64;
        (self.digest(TAG_NEW_BUCKET, &[source_group, &index.to_le_bytes()])
            % NEW_BUCKET_COUNT as u64) as usize
    }

    /// `tried` 表のどのバケットに入るか。
    ///
    /// **住所自身の括りが効く。** 同じ /16 の住所は
    /// [`TRIED_BUCKETS_PER_GROUP`] 個のバケットにしか散らない。
    fn tried_bucket(&self, addr: &SocketAddr) -> usize {
        let group = group_of(addr);
        let index =
            self.digest(TAG_TRIED_INDEX, &[&addr_bytes(addr)]) % TRIED_BUCKETS_PER_GROUP as u64;
        (self.digest(TAG_TRIED_BUCKET, &[&group, &index.to_le_bytes()]) % TRIED_BUCKET_COUNT as u64)
            as usize
    }

    /// バケットの中のどの位置に入るか。
    fn slot(&self, tried: bool, bucket: usize, addr: &SocketAddr) -> usize {
        (self.digest(
            TAG_SLOT,
            &[
                &[u8::from(tried)],
                &(bucket as u32).to_le_bytes(),
                &addr_bytes(addr),
            ],
        ) % BUCKET_SIZE as u64) as usize
    }

    // ── 覚える ──

    /// 住所を覚える。出どころは住所自身とみなす。
    ///
    /// シードや `--connect` で名指しされた相手のように、人づてでない
    /// 経路で知った住所に用いる。
    pub fn add(&mut self, addr: SocketAddr, last_seen: i64, now: i64) -> bool {
        self.add_from(addr, None, last_seen, now)
    }

    /// 住所を覚える。`source` は教えてくれた相手。
    ///
    /// 覚えたら真を返す。すでに知っていれば `last_seen` を進めて真を返す。
    pub fn add_from(
        &mut self,
        addr: SocketAddr,
        source: Option<SocketAddr>,
        last_seen: i64,
        now: i64,
    ) -> bool {
        if !is_storable(self.network, &addr) || self.own.contains(&addr) {
            return false;
        }
        // 未来を名乗られても、いまより先には進めない。
        let last_seen = last_seen.min(now + MAX_FUTURE_SECS).min(now);
        if last_seen < now - STALE_SECS {
            return false;
        }
        let source_group = source.as_ref().map_or_else(|| group_of(&addr), group_of);
        let bucket = self.new_bucket(&addr, &source_group);
        let slot = self.slot(false, bucket, &addr);

        if let Some(info) = self.entries.get_mut(&addr) {
            info.entry.last_seen = info.entry.last_seen.max(last_seen);
            self.dirty = true;
            if info.in_tried
                || info.new_slots.len() >= NEW_BUCKETS_PER_ADDRESS
                || info.new_slots.iter().any(|(b, _)| *b as usize == bucket)
            {
                return true;
            }
            // 別の出どころからも聞いた。もう 1 枠取る。
            if self.claim_new_slot(bucket, slot, now) {
                self.new_table.set(bucket, slot, addr);
                if let Some(info) = self.entries.get_mut(&addr) {
                    info.new_slots.push((bucket as u16, slot as u8));
                }
            }
            return true;
        }

        if !self.claim_new_slot(bucket, slot, now) {
            return false;
        }
        self.new_table.set(bucket, slot, addr);
        self.entries.insert(
            addr,
            Info {
                entry: Entry::new(last_seen),
                source_group,
                in_tried: false,
                new_slots: vec![(bucket as u16, slot as u8)],
            },
        );
        self.dirty = true;
        true
    }

    /// `new` の 1 枠を空ける。空けられたら真。
    ///
    /// 先客が居る場合、**見込みが尽きている先客だけ**を押しのける。
    /// 元気な先客は動かさない。動かせるようにすると、攻撃者は繋がる
    /// 住所を並べるだけで表を入れ替えられる。
    fn claim_new_slot(&mut self, bucket: usize, slot: usize, now: i64) -> bool {
        let Some(occupant) = self.new_table.get(bucket, slot) else {
            return true;
        };
        let terrible = self
            .entries
            .get(&occupant)
            .is_some_and(|info| info.entry.is_terrible(now));
        if !terrible {
            return false;
        }
        self.release_new_slot(&occupant, bucket, slot);
        true
    }

    /// `new` の 1 枠から住所を外す。最後の枠なら住所ごと忘れる。
    fn release_new_slot(&mut self, addr: &SocketAddr, bucket: usize, slot: usize) {
        self.new_table.clear(bucket, slot);
        let Some(info) = self.entries.get_mut(addr) else {
            return;
        };
        info.new_slots
            .retain(|(b, s)| (*b as usize, *s as usize) != (bucket, slot));
        if info.new_slots.is_empty() && !info.in_tried {
            self.entries.remove(addr);
        }
    }

    /// `addr` メッセージで受け取った住所をまとめて覚える。
    ///
    /// 覚えた件数を返す。1 通で受け取る数は [`MAX_PER_MESSAGE`] までに
    /// 切り詰める。
    pub fn add_many(
        &mut self,
        addrs: &[NetAddress],
        source: Option<SocketAddr>,
        now: i64,
    ) -> usize {
        addrs
            .iter()
            .take(MAX_PER_MESSAGE)
            .filter(|net| self.add_from(net.to_socket(), source, net.last_seen, now))
            .count()
    }

    // ── 結果を記録する ──

    /// 繋ぎに行ったことを記録する。
    pub fn mark_attempt(&mut self, addr: &SocketAddr, now: i64) {
        if let Some(info) = self.entries.get_mut(addr) {
            info.entry.last_try = Some(now);
            self.dirty = true;
        }
    }

    /// 相手が名乗った提供機能を覚える。ハンドシェイクが成立した直後に呼ぶ。
    ///
    /// **知らない住所には何もしない。** 先に [`AddressBook::mark_success`]
    /// を呼んで住所帳に載せてから呼ぶこと。名乗りだけで住所帳を太らせると、
    /// 繋がりもしない住所が枠を取る。
    ///
    /// `services` は [`oag_net::effective_services`] を通した後の値を渡す。
    /// 版数 1 の相手はフルノードとして記録される。
    pub fn set_services(&mut self, addr: &SocketAddr, services: u64) {
        let Some(info) = self.entries.get_mut(addr) else {
            return;
        };
        if info.entry.services == services {
            return;
        }
        info.entry.services = services;
        self.dirty = true;
    }

    /// 繋がったことを記録し、`tried` 表へ昇格させる。
    ///
    /// **まだ覚えていない住所なら、ここで覚える。** 実際に繋がった住所は
    /// 到達できることの最も強い証拠であり、`--connect` で名指しされた
    /// 相手やシードから得た相手はこの経路で住所帳に入る。**`new` に枠が
    /// 取れなくても諦めない。** その場合は直接 `tried` へ迎える。
    ///
    /// `tried` の行き先が塞がっている場合、**先客が見込みを失っていな
    /// ければ昇格しない**。新参が繋がったという理由だけで実績のある住所を
    /// 追い出せるようにすると、攻撃者は繋がるノードを並べるだけで
    /// `tried` を入れ替えられる。
    pub fn mark_success(&mut self, addr: &SocketAddr, now: i64) {
        if !self.entries.contains_key(addr) && !self.add(*addr, now, now) && !self.adopt(*addr, now)
        {
            return;
        }
        let Some(info) = self.entries.get_mut(addr) else {
            return;
        };
        info.entry.last_try = Some(now);
        info.entry.last_success = Some(now);
        info.entry.last_seen = info.entry.last_seen.max(now);
        info.entry.failures = 0;
        self.dirty = true;
        if info.in_tried {
            return;
        }

        let bucket = self.tried_bucket(addr);
        let slot = self.slot(true, bucket, addr);
        if let Some(occupant) = self.tried_table.get(bucket, slot) {
            if occupant == *addr {
                return;
            }
            let terrible = self
                .entries
                .get(&occupant)
                .is_some_and(|info| info.entry.is_terrible(now));
            if !terrible {
                // 先客は元気である。この住所は new に留め置く。
                return;
            }
            self.demote(&occupant, bucket, slot, now);
        }

        // new の枠をすべて返してから tried へ移す。
        let slots = self
            .entries
            .get(addr)
            .map(|info| info.new_slots.clone())
            .unwrap_or_default();
        for (b, s) in slots {
            self.new_table.clear(b as usize, s as usize);
        }
        if let Some(info) = self.entries.get_mut(addr) {
            info.new_slots.clear();
            info.in_tried = true;
        }
        self.tried_table.set(bucket, slot, *addr);
    }

    /// `new` に枠が取れなかった住所を、直接 `tried` に迎える。迎えたら真。
    ///
    /// # なぜ `new` の枠を要求しないのか
    ///
    /// `new` は**まだ試していない住所**を溜める場所である。実際に繋がった
    /// 相手がそこの枠を取り合う理由はない。それでも要求していたため、
    /// [`AddressBook::add`] が枠を取れないと成功の記録ごと落ちていた。
    ///
    /// **落ちると、聞かせた住所で `new` を埋めるだけで、正直な相手が
    /// `tried` に入るのを塞げる。** 2 つの表を分けてあるのは、繋がった
    /// 実績のある相手を、聞いただけの住所と別勘定にしておくためである。
    /// 片方を埋めてもう片方への道を塞げるなら、分けた意味がない。
    ///
    /// ただし `tried` の先客は守る。行き先が塞がっていて先客が見込みを
    /// 失っていなければ迎えない。ここを緩めると、繋がるノードを並べる
    /// だけで `tried` を入れ替えられる。
    ///
    /// 迎えると決まってから登録する。先に登録してから断ると、どちらの
    /// 表にも居ない項目が `entries` に残る。
    fn adopt(&mut self, addr: SocketAddr, now: i64) -> bool {
        if !is_storable(self.network, &addr) || self.own.contains(&addr) {
            return false;
        }
        let bucket = self.tried_bucket(&addr);
        let slot = self.slot(true, bucket, &addr);
        if let Some(occupant) = self.tried_table.get(bucket, slot) {
            let terrible = self
                .entries
                .get(&occupant)
                .is_some_and(|info| info.entry.is_terrible(now));
            if !terrible {
                return false;
            }
        }
        self.entries.insert(
            addr,
            Info {
                entry: Entry::new(now),
                source_group: group_of(&addr),
                in_tried: false,
                new_slots: Vec::new(),
            },
        );
        true
    }

    /// `tried` から降ろす。行き先の `new` が塞がっていれば忘れる。
    fn demote(&mut self, addr: &SocketAddr, bucket: usize, slot: usize, now: i64) {
        self.tried_table.clear(bucket, slot);
        let Some(info) = self.entries.get_mut(addr) else {
            return;
        };
        info.in_tried = false;
        let source_group = info.source_group;
        let new_bucket = self.new_bucket(addr, &source_group);
        let new_slot = self.slot(false, new_bucket, addr);
        if self.claim_new_slot(new_bucket, new_slot, now) {
            self.new_table.set(new_bucket, new_slot, *addr);
            if let Some(info) = self.entries.get_mut(addr) {
                info.new_slots = vec![(new_bucket as u16, new_slot as u8)];
            }
        } else {
            self.entries.remove(addr);
        }
    }

    /// 繋がらなかったことを記録する。
    pub fn mark_failure(&mut self, addr: &SocketAddr, now: i64) {
        if let Some(info) = self.entries.get_mut(addr) {
            info.entry.last_try = Some(now);
            info.entry.failures = info.entry.failures.saturating_add(1);
            self.dirty = true;
        }
    }

    // ── 選ぶ ──

    /// いま繋ぎに行ってよい住所を、最大 `want` 件返す。
    ///
    /// `busy` に入っている住所は返さない (すでに繋がっている、または
    /// 繋ぎに行っている最中)。
    ///
    /// **`tried` と `new` を半々で引く。** `new` が丸ごと攻撃者のもので
    /// あっても、外向きの接続の半分は実績のある相手に向かう。ここが
    /// 日蝕攻撃に対する要である。
    ///
    /// **同じ /16 からは 1 件しか返さない。** 選んだ先が偏ると、
    /// 1 つのネットワークが落ちただけで孤立する。
    ///
    /// 選ぶ順は乱数で決める。順序が読めると、狙って先頭に居座られる。
    pub fn candidates(&self, now: i64, want: usize, busy: &[SocketAddr]) -> Vec<SocketAddr> {
        if want == 0 || self.entries.is_empty() {
            return Vec::new();
        }
        let mut rng = Rng::new();
        let mut out: Vec<SocketAddr> = Vec::with_capacity(want);
        let mut groups: Vec<[u8; 4]> = Vec::with_capacity(want);

        // 引き当たらないまま回り続けないよう、試行回数に上限を置く。
        let budget = (want + 1) * 256;
        for _ in 0..budget {
            if out.len() >= want {
                break;
            }
            let from_tried = match (self.tried_table.len(), self.new_table.len()) {
                (0, 0) => break,
                (0, _) => false,
                (_, 0) => true,
                _ => rng.next().is_multiple_of(2),
            };
            let table = if from_tried {
                &self.tried_table
            } else {
                &self.new_table
            };
            let Some(addr) = table.draw(&mut rng) else {
                continue;
            };
            if out.contains(&addr) || busy.contains(&addr) {
                continue;
            }
            let Some(info) = self.entries.get(&addr) else {
                continue;
            };
            if !info.entry.is_ready(now) || info.entry.is_terrible(now) {
                continue;
            }
            let group = group_of(&addr);
            if groups.contains(&group) {
                continue;
            }
            groups.push(group);
            out.push(addr);
        }
        out
    }

    /// `getaddr` に返す住所を選ぶ。
    ///
    /// **`tried` 表からしか配らない。** 聞いただけの住所を配れば、
    /// 受け取った側がそこに繋ぎに行って無駄足を踏む。攻撃者から聞いた
    /// だけの住所を、こちらが裏書きして広めることにもなる。
    ///
    /// Bitcoin は `new` からも配るが、本実装は配らない。その分、まだ
    /// 誰も繋いだことのない新しいノードの住所は 1 ホップで止まる。
    /// **止まったままにはならない。** 聞いた側は `new` からも半分の
    /// 割合で繋ぎに行くので、繋がった時点で `tried` に上がり、そこから
    /// 配られ始める。
    pub fn to_share(&self, now: i64, want: usize) -> Vec<NetAddress> {
        let mut proven: Vec<(&SocketAddr, &Entry)> = self
            .entries
            .iter()
            .filter(|(_, info)| info.in_tried && !info.entry.is_terrible(now))
            .map(|(addr, info)| (addr, &info.entry))
            .collect();
        proven.sort_by_key(|(_, e)| -e.last_seen);
        proven
            .into_iter()
            .take(want.min(MAX_TO_SHARE))
            .map(|(addr, entry)| NetAddress::from_socket(*addr, entry.services, entry.last_seen))
            .collect()
    }

    // ── 保存 ──

    /// ファイルに書き出す。保存先が無ければ何もしない。
    ///
    /// **別名に書き切ってから置き換える。** 途中で電源が落ちても、
    /// 中途半端な住所帳が残らない。
    ///
    /// バケットの割り当ては書かない。鍵と出どころの括りがあれば計算し
    /// 直せる。読み込みの順が違う分だけ枠の取り合いの結果は変わりうるが、
    /// **どちらの表に居るかは保たれる。** そこが要である。
    pub fn save(&mut self) -> std::io::Result<()> {
        let Some(path) = self.path.clone() else {
            return Ok(());
        };
        let stored = Stored {
            version: FORMAT_VERSION,
            network: self.network.to_string(),
            key: self.key,
            entries: self
                .entries
                .iter()
                .map(|(addr, info)| StoredEntry {
                    addr: *addr,
                    entry: info.entry,
                    source_group: info.source_group,
                    in_tried: info.in_tried,
                })
                .collect(),
        };
        let text = serde_json::to_string(&stored).map_err(|e| {
            std::io::Error::other(format!("cannot write out the address book: {e}"))
        })?;

        let temp = path.with_extension(format!("tmp{}", std::process::id()));
        let result = (|| -> std::io::Result<()> {
            std::fs::write(&temp, text.as_bytes())?;
            std::fs::rename(&temp, &path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        if result.is_ok() {
            self.dirty = false;
        }
        result
    }

    /// 保存していない変更があるか。
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const NOW: i64 = 1_800_000_000;
    const NET: Network = Network::Mainnet;

    fn addr(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        format!("{a}.{b}.{c}.{d}:9444").parse().unwrap()
    }

    fn book() -> AddressBook {
        AddressBook::in_memory(NET)
    }

    /// 1 つの出どころから、別々の /16 の住所を大量に流し込む。
    fn flood(b: &mut AddressBook, source: SocketAddr, first: u8, last: u8, now: i64) -> usize {
        let mut taken = 0;
        for hi in first..=last {
            for lo in 0..=250u8 {
                if b.add_from(addr(hi, lo, 1, 1), Some(source), now, now) {
                    taken += 1;
                }
            }
        }
        taken
    }

    /// `new` 表で使われているバケットの一覧。
    fn new_buckets(b: &AddressBook) -> HashSet<u16> {
        b.new_table
            .filled
            .iter()
            .map(|(bucket, _)| *bucket)
            .collect()
    }

    // ━━━━━━━━ 二つの表 ━━━━━━━━

    #[test]
    fn a_known_address_comes_back() {
        let mut b = book();
        assert!(b.is_empty());
        assert!(b.add(addr(1, 2, 3, 4), NOW, NOW));
        assert_eq!(b.len(), 1);
        assert_eq!(b.candidates(NOW, 10, &[]), vec![addr(1, 2, 3, 4)]);
    }

    #[test]
    fn a_heard_address_starts_in_new_and_a_connection_promotes_it() {
        // **ここが二表構造の要である。** `addr` を送りつけるだけでは
        // tried に入れない。入るには実際に繋がる必要がある。
        let mut b = book();
        let a = addr(93, 184, 216, 1);
        assert!(b.add(a, NOW, NOW));
        assert_eq!((b.new_len(), b.tried_len()), (1, 0));
        assert!(!b.get(&a).unwrap().is_proven());

        b.mark_success(&a, NOW);
        assert_eq!((b.new_len(), b.tried_len()), (0, 1));
        assert!(b.get(&a).unwrap().is_proven());
    }

    #[test]
    fn one_source_can_only_reach_a_few_new_buckets() {
        // 日蝕攻撃への主たる対策である。**ここが効かないと、1 つの相手が
        // new 表を丸ごと埋められる。**
        let mut b = book();
        let attacker = addr(93, 184, 216, 34);
        flood(&mut b, attacker, 11, 90, NOW);

        let touched = new_buckets(&b);
        assert!(
            touched.len() <= NEW_BUCKETS_PER_SOURCE_GROUP,
            "one source reached {} buckets (limit {})",
            touched.len(),
            NEW_BUCKETS_PER_SOURCE_GROUP
        );
        assert!(
            b.len() <= NEW_BUCKETS_PER_SOURCE_GROUP * BUCKET_SIZE,
            "one source occupies {} entries",
            b.len()
        );
        // new 表の 6 % ほどしか触れていない。残りは他の出どころのもの。
        assert!(touched.len() * 8 < NEW_BUCKET_COUNT);
    }

    #[test]
    fn a_flood_from_one_source_does_not_shut_out_another() {
        let mut b = book();
        flood(&mut b, addr(93, 184, 216, 34), 11, 90, NOW);
        // 別の相手が教えてくれた住所は、別のバケット群に入る。
        let honest = addr(104, 16, 0, 7);
        let mut accepted = 0;
        for lo in 0..=200u8 {
            if b.add_from(addr(198, lo, 5, 5), Some(honest), NOW, NOW) {
                accepted += 1;
            }
        }
        // 取りこぼす分はある。1 つの出どころが触れるのは 1,024 個中
        // 64 個のバケットなので、二つの出どころのバケットは平均 4 個
        // (64 × 64 ÷ 1,024) 重なる。重なった先は攻撃者が埋めている。
        // 加えて 201 件どうしの枠の衝突が数件。合わせて 1 割強である。
        // **8 割が通れば、埋め尽くしは効いていない。**
        assert!(
            accepted * 4 >= 201 * 3,
            "flooding kept honest addresses out ({accepted}/201)"
        );
    }

    #[test]
    fn one_group_can_only_reach_a_few_tried_buckets() {
        let mut b = book();
        for lo in 0..=255u8 {
            for x in 1..=8u8 {
                let a = addr(93, 184, lo, x);
                b.add(a, NOW, NOW);
                b.mark_success(&a, NOW);
            }
        }
        let buckets: HashSet<usize> = b
            .entries
            .iter()
            .filter(|(_, info)| info.in_tried)
            .map(|(addr, _)| b.tried_bucket(addr))
            .collect();
        assert!(
            buckets.len() <= TRIED_BUCKETS_PER_GROUP,
            "the same /16 reached {} tried buckets (limit {})",
            buckets.len(),
            TRIED_BUCKETS_PER_GROUP
        );
    }

    #[test]
    fn a_healthy_tried_address_is_not_displaced() {
        // 繋がるノードを並べるだけで tried を入れ替えられてはならない。
        let mut b = book();
        for lo in 0..=255u8 {
            for x in 1..=8u8 {
                let a = addr(93, 184, lo, x);
                b.add(a, NOW, NOW);
                b.mark_success(&a, NOW);
            }
        }
        let before: HashSet<SocketAddr> = b
            .entries
            .iter()
            .filter(|(_, info)| info.in_tried)
            .map(|(addr, _)| *addr)
            .collect();
        assert!(
            before.len() < 2_048,
            "no collision occurred, so the test is meaningless"
        );

        for lo in 0..=255u8 {
            for x in 9..=16u8 {
                let a = addr(93, 184, lo, x);
                b.add(a, NOW + 1, NOW + 1);
                b.mark_success(&a, NOW + 1);
            }
        }
        let after: HashSet<SocketAddr> = b
            .entries
            .iter()
            .filter(|(_, info)| info.in_tried)
            .map(|(addr, _)| *addr)
            .collect();
        assert!(
            before.is_subset(&after),
            "a healthy address in tried was evicted by a newcomer"
        );
    }

    #[test]
    fn a_hopeless_address_gives_up_its_slot() {
        let mut b = book();
        let source = addr(93, 184, 216, 34);
        flood(&mut b, source, 11, 90, NOW);
        let filled = b.len();
        assert!(filled > 0);

        // どれも繋がらなかった。見限る回数まで失敗させる。
        let known: Vec<SocketAddr> = b.entries.keys().copied().collect();
        for a in &known {
            for _ in 0..GIVE_UP_UNPROVEN {
                b.mark_failure(a, NOW);
            }
        }
        // 試している最中とみなされる幅を過ぎてから。
        let later = NOW + IN_FLIGHT_SECS + 1;
        let taken = flood(&mut b, source, 91, 170, later);
        assert!(
            taken > 0,
            "an address with no prospects will not yield its slot"
        );
        assert!(b.len() <= NEW_BUCKETS_PER_SOURCE_GROUP * BUCKET_SIZE);
    }

    #[test]
    fn hearing_from_several_sources_takes_several_slots() {
        // 多くのピアが知っている住所ほど選ばれやすくする。
        let mut b = book();
        let a = addr(93, 184, 216, 1);
        for i in 1..=4u8 {
            b.add_from(a, Some(addr(10 * i, 0, 0, 1)), NOW, NOW);
        }
        let slots = b.entries[&a].new_slots.len();
        assert!((2..=4).contains(&slots), "there are only {slots} slots");

        // 同じ出どころからもう一度聞いても増えない。
        b.add_from(a, Some(addr(10, 0, 0, 1)), NOW, NOW);
        assert_eq!(b.entries[&a].new_slots.len(), slots);
    }

    #[test]
    fn one_address_cannot_take_unlimited_slots() {
        let mut b = book();
        let a = addr(93, 184, 216, 1);
        for i in 1..=30u8 {
            b.add_from(a, Some(addr(3 * i, 7, 0, 1)), NOW, NOW);
        }
        assert!(b.entries[&a].new_slots.len() <= NEW_BUCKETS_PER_ADDRESS);
    }

    #[test]
    fn a_peer_that_answered_reaches_tried_even_with_its_new_slot_taken() {
        // **聞かせた住所で new を埋めて、正直な相手が tried に入るのを
        // 塞げてはならない。** 2 つの表を分けてあるのは、繋がった実績の
        // ある相手を聞いただけの住所と別勘定にするためである。
        let mut b = book();
        let honest = addr(104, 16, 1, 1);

        // honest の new の行き先を、見込みのある別の住所で塞ぐ。
        let bucket = b.new_bucket(&honest, &group_of(&honest));
        let slot = b.slot(false, bucket, &honest);
        let blocker = addr(93, 184, 216, 7);
        assert!(b.add(blocker, NOW, NOW));
        b.new_table.set(bucket, slot, blocker);

        // 前提: この状態では new に入れない。
        assert!(
            !b.add(honest, NOW, NOW),
            "a slot is free; the test's premise differs"
        );
        assert!(b.get(&honest).is_none());

        // それでも、実際に繋がったのなら tried に載る。
        b.mark_success(&honest, NOW);
        assert_eq!(b.tried_len(), 1, "connected but not in tried");
        assert!(
            b.get(&honest).is_some_and(|e| e.is_proven()),
            "the success was not recorded"
        );
        // 塞いでいた住所は追い出していない。
        assert!(b.get(&blocker).is_some());
    }

    #[test]
    fn a_live_occupant_of_tried_is_not_pushed_out_by_an_unknown_peer() {
        // new を迂回できるようにしても、tried の先客は守る。ここを緩めると
        // 繋がるノードを並べるだけで tried を入れ替えられる。
        let mut b = book();
        let honest = addr(104, 16, 1, 1);

        // honest が入るはずの tried の枠を、元気な住所で埋める。
        let bucket = b.tried_bucket(&honest);
        let slot = b.slot(true, bucket, &honest);
        let occupant = addr(93, 184, 216, 9);
        assert!(b.add(occupant, NOW, NOW));
        b.mark_success(&occupant, NOW);
        b.tried_table.set(bucket, slot, occupant);

        // honest の new も塞ぐ。どちらにも行き場がない。
        let nb = b.new_bucket(&honest, &group_of(&honest));
        let ns = b.slot(false, nb, &honest);
        b.new_table.set(nb, ns, occupant);
        assert!(
            !b.add(honest, NOW, NOW),
            "a slot is free; the test's premise differs"
        );

        b.mark_success(&honest, NOW);

        // 迎えなかった。**そしてどちらの表にも居ない項目を残していない。**
        assert!(
            b.get(&honest).is_none(),
            "an entry belonging nowhere is left behind"
        );
        assert!(b.get(&occupant).is_some_and(|e| e.is_proven()));
    }

    #[test]
    fn candidates_come_from_both_tables() {
        // **new が丸ごと攻撃者のものでも、半分は実績のある相手に向かう。**
        let mut b = book();
        let attacker = addr(93, 184, 216, 34);
        flood(&mut b, attacker, 11, 90, NOW);
        let honest = addr(104, 16, 1, 1);
        b.add(honest, NOW, NOW);
        b.mark_success(&honest, NOW);
        assert_eq!(b.tried_len(), 1);

        let rounds = 400;
        let hits = (0..rounds)
            .filter(|_| b.candidates(NOW, 1, &[]) == vec![honest])
            .count();
        assert!(
            (rounds / 4..=rounds * 3 / 4).contains(&hits),
            "the share from tried is {hits}/{rounds}, which is not half and half"
        );
    }

    #[test]
    fn candidates_do_not_repeat_a_network() {
        // 選んだ先が偏ると、1 つのネットワークが落ちただけで孤立する。
        let mut b = book();
        for i in 1..=32u8 {
            b.add(addr(93, 184, 216, i), NOW, NOW);
        }
        b.add(addr(104, 16, 1, 1), NOW, NOW);
        let picked = b.candidates(NOW, 8, &[]);
        assert_eq!(
            picked.len(),
            2,
            "picked two or more from the same /16: {picked:?}"
        );
    }

    #[test]
    fn a_hopeless_address_is_not_offered() {
        let mut b = book();
        let a = addr(93, 184, 216, 1);
        b.add(a, NOW, NOW);
        for _ in 0..GIVE_UP_UNPROVEN {
            b.mark_failure(&a, NOW);
        }
        let later = NOW + BACKOFF_MAX_SECS;
        assert!(
            b.candidates(later, 10, &[]).is_empty(),
            "an address we gave up on is being offered as a destination"
        );
    }

    // ━━━━━━━━ 住所の取捨 ━━━━━━━━

    #[test]
    fn an_unroutable_address_is_refused_on_mainnet() {
        let mut b = book();
        for text in [
            "127.0.0.1:9444",
            "10.0.0.1:9444",
            "192.168.1.1:9444",
            "172.16.0.1:9444",
            "169.254.1.1:9444",
            "0.0.0.0:9444",
            "100.64.0.1:9444",
            "224.0.0.1:9444",
            "[::1]:9444",
            "[fc00::1]:9444",
            "[fe80::1]:9444",
            "1.2.3.4:0",
        ] {
            let a: SocketAddr = text.parse().unwrap();
            assert!(!b.add(a, NOW, NOW), "{text} was remembered");
        }
        assert!(b.is_empty());
    }

    #[test]
    fn regtest_allows_loopback() {
        // 手元で 2 台繋ぐために要る。
        let mut b = AddressBook::in_memory(Network::Regtest);
        assert!(b.add("127.0.0.1:29444".parse().unwrap(), NOW, NOW));
    }

    #[test]
    fn an_ipv4_mapped_address_is_judged_as_ipv4() {
        // 射影を通せば private が通る、という抜け道を塞ぐ。
        let mut b = book();
        assert!(!b.add("[::ffff:10.0.0.1]:9444".parse().unwrap(), NOW, NOW));
        assert!(b.add("[::ffff:93.184.216.1]:9444".parse().unwrap(), NOW, NOW));
    }

    #[test]
    fn a_mapped_address_lands_in_the_same_slot_as_its_ipv4() {
        // 括りを二重に持つと、同じ相手が 2 つの枠を取れてしまう。
        let b = book();
        let plain = addr(93, 184, 216, 9);
        let mapped: SocketAddr = "[::ffff:93.184.216.9]:9444".parse().unwrap();
        assert_eq!(addr_bytes(&plain), addr_bytes(&mapped));
        assert_eq!(group_of(&plain), group_of(&mapped));
        assert_eq!(b.tried_bucket(&plain), b.tried_bucket(&mapped));
    }

    #[test]
    fn a_future_timestamp_cannot_buy_a_permanent_slot() {
        // 未来を名乗る住所を許すと、古いものから捨てる規則が効かなくなる。
        let mut b = book();
        b.add(addr(93, 184, 216, 1), NOW + 10 * 365 * 86_400, NOW);
        assert!(b.get(&addr(93, 184, 216, 1)).unwrap().last_seen <= NOW);
    }

    #[test]
    fn a_very_old_address_is_refused() {
        let mut b = book();
        assert!(!b.add(addr(93, 184, 216, 1), NOW - STALE_SECS - 1, NOW));
    }

    #[test]
    fn our_own_address_is_not_remembered() {
        let mut b = book();
        b.set_own(vec![addr(93, 184, 216, 1)]);
        assert!(!b.add(addr(93, 184, 216, 1), NOW, NOW));
        assert!(b.add(addr(93, 184, 216, 2), NOW, NOW));
    }

    #[test]
    fn one_message_cannot_deliver_more_than_the_cap() {
        let mut b = book();
        let flood: Vec<NetAddress> = (0..1_000u32)
            .map(|i| {
                let a = addr(
                    (1 + i / 60_000) as u8,
                    (1 + (i / 250) % 240) as u8,
                    (i % 250) as u8,
                    1,
                );
                NetAddress::from_socket(a, 0, NOW)
            })
            .collect();
        assert!(b.add_many(&flood, Some(addr(104, 16, 1, 1)), NOW) <= MAX_PER_MESSAGE);
    }

    // ━━━━━━━━ 再試行 ━━━━━━━━

    #[test]
    fn a_failing_address_is_not_retried_immediately() {
        let mut b = book();
        b.add(addr(93, 184, 216, 1), NOW, NOW);
        b.mark_failure(&addr(93, 184, 216, 1), NOW);

        assert!(
            b.candidates(NOW, 10, &[]).is_empty(),
            "retrying immediately"
        );
        assert!(b.candidates(NOW + backoff(1) - 1, 10, &[]).is_empty());
        assert_eq!(b.candidates(NOW + backoff(1), 10, &[]).len(), 1);
    }

    #[test]
    fn the_backoff_grows_and_is_capped() {
        assert_eq!(backoff(0), 0);
        assert_eq!(backoff(1), BACKOFF_BASE_SECS * 2);
        assert!(backoff(2) > backoff(1));
        assert_eq!(
            backoff(64),
            BACKOFF_MAX_SECS,
            "it does not cap at the limit"
        );
        // あふれて負や 0 にならないこと。
        for f in 0..64 {
            assert!((0..=BACKOFF_MAX_SECS).contains(&backoff(f)), "failures={f}");
        }
    }

    #[test]
    fn success_clears_the_backoff() {
        let mut b = book();
        let a = addr(93, 184, 216, 1);
        b.add(a, NOW, NOW);
        for _ in 0..5 {
            b.mark_failure(&a, NOW);
        }
        assert_eq!(b.get(&a).unwrap().failures, 5);
        b.mark_success(&a, NOW);
        assert_eq!(b.get(&a).unwrap().failures, 0);
        assert!(b.get(&a).unwrap().is_proven());
        assert_eq!(b.candidates(NOW, 10, &[]).len(), 1);
    }

    #[test]
    fn a_busy_address_is_not_offered() {
        let mut b = book();
        b.add(addr(93, 184, 216, 1), NOW, NOW);
        assert!(b.candidates(NOW, 10, &[addr(93, 184, 216, 1)]).is_empty());
    }

    #[test]
    fn being_tried_right_now_is_not_hopeless() {
        // 結果が出る前に見限ると、繋ぎに行った先が即座に捨てられる。
        let mut e = Entry::new(NOW);
        e.last_try = Some(NOW);
        e.failures = GIVE_UP_UNPROVEN;
        assert!(!e.is_terrible(NOW));
        assert!(e.is_terrible(NOW + IN_FLIGHT_SECS));
    }

    // ━━━━━━━━ 配る ━━━━━━━━

    #[test]
    fn only_proven_addresses_are_shared() {
        // 聞いただけの住所を配ると、こちらが裏書きして広めることになる。
        let mut b = book();
        b.add(addr(104, 16, 1, 1), NOW, NOW);
        b.add(addr(93, 184, 216, 1), NOW, NOW);
        assert!(
            b.to_share(NOW, 10).is_empty(),
            "handing out addresses with no track record"
        );

        b.mark_success(&addr(93, 184, 216, 1), NOW);
        let shared = b.to_share(NOW, 10);
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].to_socket(), addr(93, 184, 216, 1));
    }

    #[test]
    fn a_long_dead_address_is_not_shared() {
        let mut b = book();
        let a = addr(93, 184, 216, 1);
        b.add(a, NOW, NOW);
        b.mark_success(&a, NOW);
        assert_eq!(b.to_share(NOW, 10).len(), 1);
        assert!(
            b.to_share(NOW + STALE_SECS + 1, 10).is_empty(),
            "handing out addresses that vanished long ago"
        );
    }

    // ━━━━━━━━ 保存 ━━━━━━━━

    #[test]
    fn it_round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("oag-addr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.json");

        let mut b = AddressBook::open(NET, &path);
        assert!(b.is_empty());
        b.add(addr(93, 184, 216, 1), NOW, NOW);
        b.mark_success(&addr(93, 184, 216, 1), NOW);
        b.add(addr(104, 16, 1, 1), NOW, NOW);
        assert!(b.is_dirty());
        b.save().unwrap();
        assert!(!b.is_dirty());

        let restored = AddressBook::open(NET, &path);
        assert_eq!(restored.len(), 2);
        assert_eq!((restored.new_len(), restored.tried_len()), (1, 1));
        assert!(restored.get(&addr(93, 184, 216, 1)).unwrap().is_proven());
        assert!(!restored.get(&addr(104, 16, 1, 1)).unwrap().is_proven());
        // **鍵が変わると、全住所が別のバケットへ散る。**
        assert_eq!(restored.key, b.key, "the bucket key was not preserved");
        assert!(!restored.is_dirty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn services_survive_a_round_trip() {
        let dir = std::env::temp_dir().join(format!("oag-addr-svc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.json");
        let a = addr(93, 184, 216, 1);

        let mut b = AddressBook::open(NET, &path);
        b.add(a, NOW, NOW);
        b.mark_success(&a, NOW);
        b.set_services(&a, oag_net::SERVICE_FULL_NODE);
        b.save().unwrap();

        let restored = AddressBook::open(NET, &path);
        assert_eq!(
            restored.get(&a).unwrap().services,
            oag_net::SERVICE_FULL_NODE
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_address_book_without_the_services_field_still_loads() {
        // **版を上げていない。** services の無い古い peers.json を捨てると、
        // 上げた瞬間に全ノードの住所帳が飛び、シード 1 台に全員がぶら下がる。
        let dir = std::env::temp_dir().join(format!("oag-addr-old-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.json");
        let a = addr(93, 184, 216, 1);

        let mut b = AddressBook::open(NET, &path);
        b.add(a, NOW, NOW);
        b.mark_success(&a, NOW);
        b.set_services(&a, oag_net::SERVICE_FULL_NODE);
        b.save().unwrap();

        // 欄ごと削って、この変更より前に書かれたファイルに戻す。
        let text = std::fs::read_to_string(&path).unwrap();
        let old = text.replace(&format!(",\"services\":{}", oag_net::SERVICE_FULL_NODE), "");
        assert!(!old.contains("services"), "the field was not removed");
        std::fs::write(&path, &old).unwrap();

        let restored = AddressBook::open(NET, &path);
        assert_eq!(restored.len(), 1, "an old address book was discarded");
        assert!(restored.get(&a).unwrap().is_proven());
        // 「書いてなかった」も「まだ聞いていない」も、同じ 0 でよい。
        assert_eq!(restored.get(&a).unwrap().services, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shared_addresses_carry_what_we_were_told() {
        let mut b = book();
        let a = addr(93, 184, 216, 1);
        b.add(a, NOW, NOW);
        b.mark_success(&a, NOW);
        assert_eq!(b.to_share(NOW, 10)[0].services, 0, "before the handshake");

        b.set_services(&a, oag_net::SERVICE_FULL_NODE);
        assert_eq!(b.to_share(NOW, 10)[0].services, oag_net::SERVICE_FULL_NODE);
    }

    #[test]
    fn services_are_not_recorded_for_an_unknown_address() {
        let mut b = book();
        b.set_services(&addr(93, 184, 216, 9), oag_net::SERVICE_FULL_NODE);
        assert!(b.is_empty(), "a bare claim put an address in the book");
    }

    #[test]
    fn a_book_from_another_network_is_not_used() {
        // regtest の住所帳を mainnet で読むと、ループバックに繋ぎに行く。
        let dir = std::env::temp_dir().join(format!("oag-addr-x-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.json");

        let mut reg = AddressBook::open(Network::Regtest, &path);
        reg.add("127.0.0.1:29444".parse().unwrap(), NOW, NOW);
        reg.save().unwrap();

        let main = AddressBook::open(Network::Mainnet, &path);
        assert!(main.is_empty(), "loading another network's address book");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_file_does_not_stop_startup() {
        let dir = std::env::temp_dir().join(format!("oag-addr-c-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.json");
        std::fs::write(&path, b"{ not json").unwrap();

        let b = AddressBook::open(NET, &path);
        assert!(b.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod table_accounting {
    use super::*;

    /// 表の索引が実体とずれていないこと。
    ///
    /// ずれると、無作為に引いたときに空の枠や消えた住所が返る。
    /// **日蝕攻撃への対策が静かに無効になる**ので、ここで捕まえる。
    #[test]
    fn the_index_matches_the_slots() {
        let mut b = AddressBook::in_memory(Network::Mainnet);
        let now = 1_800_000_000;
        let source: SocketAddr = "93.184.216.34:9444".parse().unwrap();
        for hi in 11..=60u8 {
            for lo in 0..=250u8 {
                let addr: SocketAddr = format!("{hi}.{lo}.1.1:9444").parse().unwrap();
                b.add_from(addr, Some(source), now, now);
            }
        }
        // 半分を昇格させ、new から tried へ枠を移す。
        let known: Vec<SocketAddr> = b.entries.keys().copied().take(500).collect();
        for addr in &known {
            b.mark_success(addr, now);
        }
        // 残りを見限らせ、枠の譲り合いを起こす。
        let rest: Vec<SocketAddr> = b
            .entries
            .iter()
            .filter(|(_, info)| !info.in_tried)
            .map(|(addr, _)| *addr)
            .collect();
        for addr in &rest {
            for _ in 0..GIVE_UP_UNPROVEN {
                b.mark_failure(addr, now);
            }
        }
        let later = now + IN_FLIGHT_SECS + 1;
        for hi in 61..=110u8 {
            for lo in 0..=250u8 {
                let addr: SocketAddr = format!("{hi}.{lo}.2.2:9444").parse().unwrap();
                b.add_from(addr, Some(source), later, later);
            }
        }

        for (name, table) in [("new", &b.new_table), ("tried", &b.tried_table)] {
            // filled が指す枠は、すべて埋まっていて自分を指し返すこと。
            for (index, (bucket, slot)) in table.filled.iter().enumerate() {
                let cell = table.slots[*bucket as usize][*slot as usize];
                let (addr, back) =
                    cell.unwrap_or_else(|| panic!("{name}: points at an empty slot"));
                assert_eq!(back as usize, index, "{name}: the index disagrees");
                assert!(
                    b.entries.contains_key(&addr),
                    "{name}: a removed address is still there"
                );
            }
            // 埋まっている枠は、すべて filled に載っていること。
            let occupied = table
                .slots
                .iter()
                .flatten()
                .filter(|cell| cell.is_some())
                .count();
            assert_eq!(
                occupied,
                table.filled.len(),
                "{name}: the slot count does not add up"
            );
        }

        // 住所が持つ枠の記録と、表の中身が一致すること。
        let mut from_entries = 0;
        for (addr, info) in &b.entries {
            if info.in_tried {
                assert!(info.new_slots.is_empty(), "in tried yet holding a new slot");
                continue;
            }
            assert!(!info.new_slots.is_empty(), "in new yet holding no slot");
            for (bucket, slot) in &info.new_slots {
                assert_eq!(
                    b.new_table.get(*bucket as usize, *slot as usize),
                    Some(*addr),
                    "another entry occupies the slot this address holds"
                );
                from_entries += 1;
            }
        }
        assert_eq!(from_entries, b.new_table.len());
        assert_eq!(b.tried_len() + b.new_len(), b.len());
    }
}
