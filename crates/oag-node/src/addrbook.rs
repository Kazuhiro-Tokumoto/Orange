//! ピアの住所帳。
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
//! 対策は 2 つ置いてある。
//!
//! 1. **/16 ごとの上限** ([`GROUP_LIMIT`])。同じ IPv4 の /16 (IPv6 は /32)
//!    に属する住所は決まった数までしか覚えない。攻撃者が 1 つの
//!    ネットワークから何万件送ってきても、占める枠はその数で頭打ちになる。
//!    住所を大量に用意することより、**別々のネットワークを大量に用意する
//!    ことのほうがずっと高くつく**、という前提に立っている
//! 2. **全体の上限** ([`MAX_ENTRIES`])。溢れたら、最後に見かけたのが古い
//!    ものから捨てる
//!
//! これで防ぎ切れるわけではない。ボットネットのように多数の /16 を持つ
//! 相手には効かない。Bitcoin の `addrman` はこれに加えて、
//! 「試したことのある住所」と「聞いただけの住所」を分けて持ち、後者から
//! 前者への昇格に接続の成功を要求する。**本実装はそこまで作っていない。**
//!
//! # 繋がらない相手を延々と試さない
//!
//! 失敗した住所は、失敗の回数に応じて間を空けてから再試行する
//! ([`backoff`])。落ちたノードに毎秒繋ぎに行っても迷惑なだけである。

use oag_net::message::NetAddress;
use oag_primitives::Network;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// 覚えておく住所の上限。
pub const MAX_ENTRIES: usize = 4_096;

/// 同じ /16 (IPv6 は /32) から覚える住所の上限。
///
/// 日蝕攻撃への主たる対策である。上げると偏りやすく、下げると正直な
/// ノードが多い地域から覚えられる数が減る。
pub const GROUP_LIMIT: usize = 32;

/// 1 回の `addr` で受け取る住所の上限。
///
/// プロトコル上の上限 ([`oag_net::message::MAX_ADDRESSES`]) より小さく
/// 取る。1 通で住所帳の 1/4 を書き換えられるのは多すぎる。
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
/// **これが無いと、未来の `last_seen` を名乗るだけで住所帳の先頭に
/// 居座れる。** 溢れたときに捨てられるのは古いものからなので、
/// 未来を名乗る住所は永久に残る。
const MAX_FUTURE_SECS: i64 = 10 * 60;

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
}

impl Entry {
    fn new(last_seen: i64) -> Entry {
        Entry {
            last_seen,
            last_try: None,
            last_success: None,
            failures: 0,
        }
    }

    /// 一度でも繋がったことがあるか。
    pub fn is_proven(&self) -> bool {
        self.last_success.is_some()
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
/// IPv4 は /16、IPv6 は /32 で括る。同じ括りから覚える数を
/// [`GROUP_LIMIT`] に抑えるために用いる。
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

/// 住所帳。
#[derive(Debug)]
pub struct AddressBook {
    network: Network,
    entries: HashMap<SocketAddr, Entry>,
    /// 括りごとの件数。[`GROUP_LIMIT`] の判定に使う。
    ///
    /// 毎回全件を走査すると、住所を 1 件足すたびに O(n) かかる。
    /// 溢れるまで足すと O(n²) である。件数を持って増減させる。
    groups: HashMap<[u8; 4], usize>,
    /// 自分自身の住所。覚えない。
    own: Vec<SocketAddr>,
    /// 保存先。`None` なら保存しない (試験用)。
    path: Option<PathBuf>,
    /// 保存していない変更があるか。
    dirty: bool,
}

/// ファイルに書き出す形。
#[derive(Debug, Serialize, Deserialize)]
struct Stored {
    version: u32,
    network: String,
    entries: Vec<(SocketAddr, Entry)>,
}

/// 保存の形式の版数。
const FORMAT_VERSION: u32 = 1;

impl AddressBook {
    /// 空の住所帳。保存しない。
    pub fn in_memory(network: Network) -> AddressBook {
        AddressBook {
            network,
            entries: HashMap::new(),
            groups: HashMap::new(),
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
                for (addr, entry) in stored.entries {
                    if is_storable(network, &addr) {
                        book.insert(addr, entry);
                    }
                }
            }
            Ok(stored) => {
                eprintln!(
                    "{} は版数 {} / {} のもので、いまの {network} と合わない。空から始める。",
                    path.display(),
                    stored.version,
                    stored.network
                );
            }
            Err(e) => {
                eprintln!("{} を読めない ({e})。空から始める。", path.display());
            }
        }
        book
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

    /// 1 件を引く。
    pub fn get(&self, addr: &SocketAddr) -> Option<&Entry> {
        self.entries.get(addr)
    }

    /// 住所を覚える。すでに知っていれば `last_seen` を進めるだけ。
    ///
    /// 覚えたら真を返す。
    pub fn add(&mut self, addr: SocketAddr, last_seen: i64, now: i64) -> bool {
        if !is_storable(self.network, &addr) || self.own.contains(&addr) {
            return false;
        }
        // 未来を名乗られても、いまより先には進めない。
        let last_seen = last_seen.min(now + MAX_FUTURE_SECS).min(now);
        if last_seen < now - STALE_SECS {
            return false;
        }

        if let Some(entry) = self.entries.get_mut(&addr) {
            entry.last_seen = entry.last_seen.max(last_seen);
            self.dirty = true;
            return true;
        }
        if self.group_count(&addr) >= GROUP_LIMIT {
            return false;
        }
        if self.entries.len() >= MAX_ENTRIES && !self.evict_oldest() {
            return false;
        }
        self.insert(addr, Entry::new(last_seen));
        self.dirty = true;
        true
    }

    /// 1 件入れ、括りの件数を進める。**入れる口はここ 1 つに絞る。**
    fn insert(&mut self, addr: SocketAddr, entry: Entry) {
        if self.entries.insert(addr, entry).is_none() {
            *self.groups.entry(group_of(&addr)).or_insert(0) += 1;
        }
    }

    /// 1 件外し、括りの件数を戻す。
    fn remove(&mut self, addr: &SocketAddr) {
        if self.entries.remove(addr).is_some() {
            let group = group_of(addr);
            if let Some(count) = self.groups.get_mut(&group) {
                *count -= 1;
                if *count == 0 {
                    self.groups.remove(&group);
                }
            }
        }
    }

    /// `addr` メッセージで受け取った住所をまとめて覚える。
    ///
    /// 覚えた件数を返す。1 通で受け取る数は [`MAX_PER_MESSAGE`] までに
    /// 切り詰める。
    pub fn add_many(&mut self, addrs: &[NetAddress], now: i64) -> usize {
        addrs
            .iter()
            .take(MAX_PER_MESSAGE)
            .filter(|net| self.add(net.to_socket(), net.last_seen, now))
            .count()
    }

    /// 繋ぎに行ったことを記録する。
    pub fn mark_attempt(&mut self, addr: &SocketAddr, now: i64) {
        if let Some(entry) = self.entries.get_mut(addr) {
            entry.last_try = Some(now);
            self.dirty = true;
        }
    }

    /// 繋がったことを記録する。失敗の回数は 0 に戻す。
    ///
    /// **まだ覚えていない住所なら、ここで覚える。** 実際に繋がった住所は
    /// 到達できることの最も強い証拠であり、`--connect` で名指しされた
    /// 相手やシードから得た相手はこの経路で住所帳に入る。
    ///
    /// ただし [`add`](AddressBook::add) の規則には従う。/16 の枠が
    /// 埋まっていれば覚えない。**繋がったからといって上限を緩めない。**
    /// 緩めれば、攻撃者は繋がせるだけで枠を破れる。
    pub fn mark_success(&mut self, addr: &SocketAddr, now: i64) {
        if !self.entries.contains_key(addr) {
            self.add(*addr, now, now);
        }
        if let Some(entry) = self.entries.get_mut(addr) {
            entry.last_try = Some(now);
            entry.last_success = Some(now);
            entry.last_seen = entry.last_seen.max(now);
            entry.failures = 0;
            self.dirty = true;
        }
    }

    /// 繋がらなかったことを記録する。
    pub fn mark_failure(&mut self, addr: &SocketAddr, now: i64) {
        if let Some(entry) = self.entries.get_mut(addr) {
            entry.last_try = Some(now);
            entry.failures = entry.failures.saturating_add(1);
            self.dirty = true;
        }
    }

    /// いま繋ぎに行ってよい住所を、最大 `want` 件返す。
    ///
    /// `busy` に入っている住所は返さない (すでに繋がっている、または
    /// 繋ぎに行っている最中)。
    ///
    /// **同じ /16 からは 1 件しか返さない。** 選んだ先が偏ると、
    /// 1 つのネットワークが落ちただけで孤立する。
    pub fn candidates(&self, now: i64, want: usize, busy: &[SocketAddr]) -> Vec<SocketAddr> {
        if want == 0 {
            return Vec::new();
        }
        let mut ready: Vec<(&SocketAddr, &Entry)> = self
            .entries
            .iter()
            .filter(|(addr, entry)| {
                if busy.contains(addr) {
                    return false;
                }
                match entry.last_try {
                    None => true,
                    Some(tried) => now >= tried.saturating_add(backoff(entry.failures)),
                }
            })
            .collect();

        // 一度繋がった相手を先に、その中では最近見かけた順に。
        // 同点は乱数で崩す。順序が読めると、狙って先頭に居座られる。
        let mut noise = [0u8; 8];
        oag_primitives::fill_random(&mut noise);
        let seed = u64::from_le_bytes(noise);
        ready.sort_by_key(|(addr, entry)| {
            let jitter = {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                use std::hash::{Hash, Hasher};
                seed.hash(&mut h);
                addr.hash(&mut h);
                h.finish()
            };
            (!entry.is_proven(), -entry.last_seen, jitter)
        });

        let mut out = Vec::with_capacity(want);
        let mut groups = Vec::with_capacity(want);
        for (addr, _) in ready {
            let group = group_of(addr);
            if groups.contains(&group) {
                continue;
            }
            groups.push(group);
            out.push(*addr);
            if out.len() >= want {
                break;
            }
        }
        out
    }

    /// `getaddr` に返す住所を選ぶ。
    ///
    /// **古い住所と、一度も繋がったことのない住所は配らない。** 配れば
    /// 受け取った側がそこに繋ぎに行って無駄足を踏む。攻撃者から聞いた
    /// だけの住所を、こちらが裏書きして広めることにもなる。
    pub fn to_share(&self, now: i64, want: usize) -> Vec<NetAddress> {
        let mut proven: Vec<(&SocketAddr, &Entry)> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_proven() && e.last_seen >= now - STALE_SECS)
            .collect();
        proven.sort_by_key(|(_, e)| -e.last_seen);
        proven
            .into_iter()
            .take(want.min(MAX_TO_SHARE))
            .map(|(addr, entry)| NetAddress::from_socket(*addr, 0, entry.last_seen))
            .collect()
    }

    /// ファイルに書き出す。保存先が無ければ何もしない。
    ///
    /// **別名に書き切ってから置き換える。** 途中で電源が落ちても、
    /// 中途半端な住所帳が残らない。
    pub fn save(&mut self) -> std::io::Result<()> {
        let Some(path) = self.path.clone() else {
            return Ok(());
        };
        let stored = Stored {
            version: FORMAT_VERSION,
            network: self.network.to_string(),
            entries: self.entries.iter().map(|(a, e)| (*a, *e)).collect(),
        };
        let text = serde_json::to_string(&stored)
            .map_err(|e| std::io::Error::other(format!("住所帳を書き出せない: {e}")))?;

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

    fn group_count(&self, addr: &SocketAddr) -> usize {
        self.groups.get(&group_of(addr)).copied().unwrap_or(0)
    }

    /// 最後に見かけたのが最も古い、一度も繋がったことのない住所を捨てる。
    ///
    /// 捨てられるものが無ければ偽を返す。**繋がった実績のある住所は
    /// 捨てない。** 実績のあるものを捨てて、聞いただけのものを入れるのは
    /// 日蝕攻撃に手を貸すことになる。
    ///
    /// 全件を走査する。溢れている間は 1 件入れるごとに走るので、
    /// [`MAX_ENTRIES`] に比例した費用がかかる。4,096 件では 1 通の
    /// `addr` (最大 [`MAX_PER_MESSAGE`] 件) あたり 1 ミリ秒程度であり、
    /// 手を入れるほどではない。上限を桁で上げるなら考え直すこと。
    fn evict_oldest(&mut self) -> bool {
        let victim = self
            .entries
            .iter()
            .filter(|(_, e)| !e.is_proven())
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(addr, _)| *addr);
        match victim {
            Some(addr) => {
                self.remove(&addr);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const NET: Network = Network::Mainnet;

    fn addr(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        format!("{a}.{b}.{c}.{d}:9444").parse().unwrap()
    }

    fn book() -> AddressBook {
        AddressBook::in_memory(NET)
    }

    #[test]
    fn a_known_address_comes_back() {
        let mut b = book();
        assert!(b.is_empty());
        assert!(b.add(addr(1, 2, 3, 4), NOW, NOW));
        assert_eq!(b.len(), 1);
        assert_eq!(b.candidates(NOW, 10, &[]), vec![addr(1, 2, 3, 4)]);
    }

    #[test]
    fn one_network_cannot_fill_the_book() {
        // 日蝕攻撃への主たる対策である。**ここが効かないと、住所帳を
        // 1 つのネットワークで埋め尽くされる。**
        let mut b = book();
        for i in 0..1_000u32 {
            b.add(addr(93, 184, (i / 256) as u8, (i % 256) as u8), NOW, NOW);
        }
        assert_eq!(
            b.len(),
            GROUP_LIMIT,
            "同じ /16 から {} 件を超えて覚えている",
            GROUP_LIMIT
        );

        // 別の /16 なら別枠である。
        b.add(addr(104, 16, 1, 1), NOW, NOW);
        assert_eq!(b.len(), GROUP_LIMIT + 1);
    }

    #[test]
    fn candidates_do_not_repeat_a_network() {
        // 選んだ先が偏ると、1 つのネットワークが落ちただけで孤立する。
        let mut b = book();
        for i in 0..GROUP_LIMIT as u8 {
            b.add(addr(93, 184, 216, i + 1), NOW, NOW);
        }
        b.add(addr(104, 16, 1, 1), NOW, NOW);
        let picked = b.candidates(NOW, 8, &[]);
        assert_eq!(
            picked.len(),
            2,
            "同じ /16 から 2 件以上選んでいる: {picked:?}"
        );
    }

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
            assert!(!b.add(a, NOW, NOW), "{text} を覚えてしまった");
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
    fn a_mapped_address_shares_the_group_of_its_ipv4() {
        // 括りを二重に持つと、同じ相手が /16 の枠を 2 つ取れてしまう。
        let mut b = book();
        for i in 0..GROUP_LIMIT as u8 {
            b.add(addr(93, 184, 216, i + 1), NOW, NOW);
        }
        assert!(
            !b.add("[::ffff:93.184.217.9]:9444".parse().unwrap(), NOW, NOW),
            "射影で /16 の枠を回避できてしまった"
        );
    }

    #[test]
    fn a_future_timestamp_cannot_buy_a_permanent_slot() {
        // 溢れたときに捨てられるのは古いものからである。未来を名乗る
        // 住所を許すと、それが永久に残る。
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
    fn a_failing_address_is_not_retried_immediately() {
        let mut b = book();
        b.add(addr(93, 184, 216, 1), NOW, NOW);
        b.mark_failure(&addr(93, 184, 216, 1), NOW);

        assert!(
            b.candidates(NOW, 10, &[]).is_empty(),
            "すぐに再試行している"
        );
        assert!(b.candidates(NOW + backoff(1) - 1, 10, &[]).is_empty());
        assert_eq!(b.candidates(NOW + backoff(1), 10, &[]).len(), 1);
    }

    #[test]
    fn the_backoff_grows_and_is_capped() {
        assert_eq!(backoff(0), 0);
        assert_eq!(backoff(1), BACKOFF_BASE_SECS * 2);
        assert!(backoff(2) > backoff(1));
        assert_eq!(backoff(64), BACKOFF_MAX_SECS, "上限で頭打ちにならない");
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
    fn proven_addresses_are_offered_first() {
        let mut b = book();
        b.add(addr(104, 16, 1, 1), NOW, NOW);
        b.add(addr(93, 184, 216, 1), NOW, NOW);
        b.mark_success(&addr(93, 184, 216, 1), NOW);
        assert_eq!(b.candidates(NOW, 1, &[]), vec![addr(93, 184, 216, 1)]);
    }

    #[test]
    fn only_proven_addresses_are_shared() {
        // 聞いただけの住所を配ると、こちらが裏書きして広めることになる。
        let mut b = book();
        b.add(addr(104, 16, 1, 1), NOW, NOW);
        b.add(addr(93, 184, 216, 1), NOW, NOW);
        assert!(b.to_share(NOW, 10).is_empty(), "実績の無い住所を配っている");

        b.mark_success(&addr(93, 184, 216, 1), NOW);
        let shared = b.to_share(NOW, 10);
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].to_socket(), addr(93, 184, 216, 1));
    }

    #[test]
    fn the_book_is_bounded() {
        let mut b = book();
        // /16 を変えながら、上限を超えるまで入れる。
        let mut added = 0;
        for hi in 1..=200u8 {
            for lo in 1..=30u8 {
                if b.add(addr(hi, lo, 1, 1), NOW, NOW) {
                    added += 1;
                }
            }
        }
        assert!(added > MAX_ENTRIES);
        assert_eq!(b.len(), MAX_ENTRIES, "上限を超えて覚えている");
    }

    #[test]
    fn a_proven_address_survives_eviction() {
        // 実績のあるものを捨てて聞いただけのものを入れるのは、
        // 日蝕攻撃に手を貸すことになる。
        let mut b = book();
        let precious = addr(93, 184, 216, 1);
        b.add(precious, NOW - 1_000, NOW);
        b.mark_success(&precious, NOW - 1_000);

        for hi in 1..=200u8 {
            for lo in 1..=30u8 {
                b.add(addr(hi, lo, 2, 2), NOW, NOW);
            }
        }
        assert_eq!(b.len(), MAX_ENTRIES);
        assert!(b.get(&precious).is_some(), "実績のある住所が捨てられた");
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
        assert!(b.add_many(&flood, NOW) <= MAX_PER_MESSAGE);
    }

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
        assert!(restored.get(&addr(93, 184, 216, 1)).unwrap().is_proven());
        assert!(!restored.get(&addr(104, 16, 1, 1)).unwrap().is_proven());

        let _ = std::fs::remove_dir_all(&dir);
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
        assert!(main.is_empty(), "別のネットワークの住所帳を読み込んでいる");

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
mod group_accounting {
    use super::*;

    /// 括りの件数が実体とずれていないこと。
    ///
    /// ずれると /16 の上限が効かなくなる。**日蝕攻撃への対策が
    /// 静かに無効になる**ので、数え方を変えたらここで捕まえる。
    #[test]
    fn the_group_counts_match_the_entries() {
        let mut b = AddressBook::in_memory(Network::Mainnet);
        for hi in 1..=200u8 {
            for lo in 1..=30u8 {
                b.add(
                    format!("{hi}.{lo}.7.7:9444").parse().unwrap(),
                    1_800_000_000,
                    1_800_000_000,
                );
            }
        }
        let mut recomputed: HashMap<[u8; 4], usize> = HashMap::new();
        for addr in b.entries.keys() {
            *recomputed.entry(group_of(addr)).or_insert(0) += 1;
        }
        assert_eq!(b.groups, recomputed, "括りの件数が実体とずれている");
        assert_eq!(b.entries.len(), MAX_ENTRIES);
    }
}
