//! ブロックの取り寄せ。
//!
//! headers-first 方式を採る。まずヘッダだけを集めてチェーンの形を確かめ、
//! そのうえで本体を取り寄せる。
//!
//! ```text
//! getheaders ──▶            ヘッダだけ先に集める
//!            ◀── headers    (1 件 100 バイト。安い)
//!
//! getdata ────▶             形が確かめられた分だけ本体を求める
//!         ◀──── block       (1 件 最大 200,000 バイト。高い)
//! ```
//!
//! # なぜヘッダを先に集めるのか
//!
//! ヘッダは本体の 1/2000 の大きさで、PoW と繋がりを検証できる。先にこれを
//! 集めてしまえば、**どのブロックが本当に必要かが分かってから本体を求める**
//! ことになる。順に本体を要求していく方式では、悪意あるピアに無関係な
//! ブロックを延々と送りつけられる。
//!
//! # 本モジュールが決めること
//!
//! - どのブロックを、どのピアに、いくつまで同時に頼むか
//! - 返ってこなかったものをいつ諦めて他のピアに頼み直すか
//!
//! 実際の送受信は行わない。

use oag_primitives::Hash;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// 1 つのピアに同時に頼むブロック数の上限。
///
/// 多すぎると 1 つのピアに依存し、少なすぎると往復待ちで遅くなる。
pub const MAX_IN_FLIGHT_PER_PEER: usize = 16;

/// 応答を待つ秒数。これを過ぎたら他のピアに頼み直す。
///
/// 目標ブロック間隔と同じにしてある。これより長く待つ理由がない。
pub const REQUEST_TIMEOUT_SECS: i64 = 60;

/// ピアの識別子。
pub type PeerId = u64;

/// 依頼中の 1 件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InFlight {
    peer: PeerId,
    requested_at: i64,
}

/// ブロック取り寄せの割り振り。
///
/// 同じブロックを複数のピアに重ねて頼まないようにしつつ、返ってこないものは
/// 諦めて別のピアに回す。
///
/// # 並びを保つこと
///
/// 待ち行列は**チェーン上の並び**を保つ。取りこぼしたブロックを頼み直す
/// ときも、元の位置に戻す。ブロックは親から順に繋いでいくため、途中が
/// 欠けたままでは後続をいくら集めても繋げられないからである。
///
/// このため待ち行列は通し番号で並べた木で持つ。ハッシュ表の反復順に頼ると
/// 並びが崩れる。
#[derive(Debug, Default)]
pub struct BlockDownload {
    /// 通し番号 → ハッシュ。番号はチェーン上の並びに対応する。
    wanted: BTreeMap<u64, Hash>,
    /// ハッシュ → 通し番号。取り寄せ終わるまで保持する。
    order_of: HashMap<Hash, u64>,
    /// 依頼中のもの。
    in_flight: HashMap<Hash, InFlight>,
    next_order: u64,
}

impl BlockDownload {
    /// 空の状態を作る。
    pub fn new() -> BlockDownload {
        BlockDownload::default()
    }

    /// 待ち行列の長さ。
    pub fn queued_len(&self) -> usize {
        self.wanted.len()
    }

    /// 依頼中の件数。
    pub fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    /// まだ取り寄せるべきものが残っているか。
    pub fn is_idle(&self) -> bool {
        self.wanted.is_empty() && self.in_flight.is_empty()
    }

    /// そのブロックを取り寄せ対象として知っているか。
    pub fn is_tracked(&self, hash: &Hash) -> bool {
        self.order_of.contains_key(hash)
    }

    /// 本体が欲しいブロックを、古い順に加える。
    ///
    /// すでに待ち行列にあるものや依頼中のものは重ねて加えない。
    /// 実際に加えた件数を返す。
    pub fn want(&mut self, hashes: impl IntoIterator<Item = Hash>) -> usize {
        let mut added = 0;
        for hash in hashes {
            if self.is_tracked(&hash) {
                continue;
            }
            let order = self.next_order;
            self.next_order += 1;
            self.order_of.insert(hash, order);
            self.wanted.insert(order, hash);
            added += 1;
        }
        added
    }

    /// このピアに次に頼むブロックを選ぶ。
    ///
    /// そのピアが今抱えている件数が上限に達していれば空を返す。
    /// 選ばれるのは常にチェーン上で最も古いものからである。
    pub fn assign(&mut self, peer: PeerId, now: i64) -> Vec<Hash> {
        let current = self.in_flight.values().filter(|f| f.peer == peer).count();
        let room = MAX_IN_FLIGHT_PER_PEER.saturating_sub(current);

        let mut assigned = Vec::with_capacity(room.min(self.wanted.len()));
        for _ in 0..room {
            let Some((_, hash)) = self.wanted.pop_first() else {
                break;
            };
            self.in_flight.insert(
                hash,
                InFlight {
                    peer,
                    requested_at: now,
                },
            );
            assigned.push(hash);
        }
        assigned
    }

    /// ブロックが届いた。
    ///
    /// 依頼していたものであれば真を返す。頼んでいないブロックが届いた場合は
    /// 偽であり、呼び出し側はそれを咎めてよい。
    pub fn received(&mut self, hash: &Hash) -> bool {
        if self.in_flight.remove(hash).is_some() {
            self.order_of.remove(hash);
            true
        } else {
            false
        }
    }

    /// 依頼中のものを待ち行列に戻す。元の通し番号に戻すため、並びは保たれる。
    fn requeue(&mut self, hash: Hash) {
        self.in_flight.remove(&hash);
        if let Some(order) = self.order_of.get(&hash) {
            self.wanted.insert(*order, hash);
        }
    }

    /// 頼んだ相手が「持っていない」と答えた。待ち行列に戻す。
    ///
    /// **戻さなければ、返事は来ているのに [`REQUEST_TIMEOUT_SECS`] だけ
    /// 待つことになる。** ブロックは親から順にしか繋げないので、その間は
    /// 後続をいくら集めても繋げられない。
    ///
    /// 持っていない相手に頼んでしまうのは避けようがない。先端を知らせて
    /// くれた相手と、本体を頼む相手は同じとは限らないためである。**避け
    /// られないなら、断られたときに直ちに回し直せなければならない。**
    ///
    /// 頼んだ相手からの答えでなければ何もしない。誰の `notfound` でも
    /// 効くようにすると、無関係なピアが他人への依頼を剥がせてしまう。
    /// 戻したときだけ真を返す。
    pub fn not_found(&mut self, hash: &Hash, peer: PeerId) -> bool {
        if self.in_flight.get(hash).is_none_or(|f| f.peer != peer) {
            return false;
        }
        self.requeue(*hash);
        true
    }

    /// 応答が返らなかったものを待ち行列に戻す。
    ///
    /// 戻したブロックを返す。
    pub fn expire(&mut self, now: i64) -> Vec<Hash> {
        let expired: Vec<Hash> = self
            .in_flight
            .iter()
            .filter(|(_, f)| now - f.requested_at >= REQUEST_TIMEOUT_SECS)
            .map(|(hash, _)| *hash)
            .collect();

        for hash in &expired {
            self.requeue(*hash);
        }
        expired
    }

    /// ピアが切れた。そのピアに頼んでいたものを待ち行列に戻す。
    ///
    /// 戻した件数を返す。
    pub fn peer_disconnected(&mut self, peer: PeerId) -> usize {
        let orphaned: Vec<Hash> = self
            .in_flight
            .iter()
            .filter(|(_, f)| f.peer == peer)
            .map(|(hash, _)| *hash)
            .collect();

        for hash in &orphaned {
            self.requeue(*hash);
        }
        orphaned.len()
    }

    /// もう要らなくなったものを取り除く (別の枝が勝った場合など)。
    pub fn forget(&mut self, hash: &Hash) {
        self.in_flight.remove(hash);
        if let Some(order) = self.order_of.remove(hash) {
            self.wanted.remove(&order);
        }
    }
}

// ━━━━━━━━ トランザクションの取り寄せ ━━━━━━━━

/// 1 つのピアに同時に頼むトランザクション数の上限。
pub const MAX_TX_IN_FLIGHT_PER_PEER: usize = 32;

/// 取り寄せ待ちに溜めておくトランザクションの上限。
///
/// `inv` は 1 通で [`crate::message::MAX_INV_ITEMS`] 件を運べる。上限が
/// 無ければ、繋がっただけのピアがこちらの記憶を好きなだけ埋められる。
pub const MAX_QUEUED_TX: usize = 5_000;

/// トランザクションの応答を待つ秒数。
///
/// 過ぎたら**忘れる**。頼み直さない ([`TxRequests`] の説明を参照)。
pub const TX_REQUEST_TIMEOUT_SECS: i64 = 60;

/// トランザクション取り寄せの割り振り。
///
/// [`BlockDownload`] と似ているが、2 点で意図的に違う。
///
/// # 並びを持たない
///
/// ブロックは親から順に繋ぐ必要があるので待ち行列の並びが要る。
/// トランザクションにその制約はない。到着順に頼めばよい。
///
/// # 取りこぼしても頼み直さない
///
/// ブロックは 1 つ欠けると以降が全部繋がらないので、返ってこなければ
/// 別のピアに頼み直す。トランザクションは違う。1 つ取り逃しても、
/// 誰かが次のブロックに入れるか、誰かがまた `inv` してくる。
///
/// **頼み直さないことが、ここでは安全側である。** 存在しない txid を
/// 大量に `inv` されたとき、頼み直す作りだと、こちらがピアを次々に
/// 変えながら同じ嘘を追い続けることになる。1 度で諦めれば、嘘 1 件の
/// 代償は往復 1 回で終わる。
///
/// # 頼んでいないものは受け取らない
///
/// [`TxRequests::was_requested_from`] が、この構造体の主な役目である。
/// 頼んだ覚えのないトランザクションを検証すると、署名の検証という重い
/// 計算を、相手が好きなだけこちらに行わせられる。**頼んだ相手から、
/// 頼んだものが来たときだけ検証する。**
#[derive(Debug, Default)]
pub struct TxRequests {
    /// まだ誰にも頼んでいないもの。到着順。
    wanted: VecDeque<Hash>,
    /// `wanted` に入っているものの集合。重複を弾くために持つ。
    queued: HashSet<Hash>,
    /// 依頼中のもの。
    in_flight: HashMap<Hash, InFlight>,
}

impl TxRequests {
    /// 空の状態を作る。
    pub fn new() -> TxRequests {
        TxRequests::default()
    }

    /// 取り寄せ待ちの数。
    pub fn queued_len(&self) -> usize {
        self.wanted.len()
    }

    /// 依頼中の数。
    pub fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    /// すでに待ち行列にあるか、依頼中か。
    pub fn is_tracked(&self, txid: &Hash) -> bool {
        self.queued.contains(txid) || self.in_flight.contains_key(txid)
    }

    /// 取り寄せたいものとして積む。積めた数を返す。
    ///
    /// すでに追っているものと、上限を超える分は捨てる。
    pub fn want(&mut self, txids: impl IntoIterator<Item = Hash>) -> usize {
        let mut added = 0;
        for txid in txids {
            if self.wanted.len() >= MAX_QUEUED_TX {
                break;
            }
            if self.is_tracked(&txid) {
                continue;
            }
            self.queued.insert(txid);
            self.wanted.push_back(txid);
            added += 1;
        }
        added
    }

    /// このピアに頼むものを取り出す。
    ///
    /// 1 つのピアへの同時依頼は [`MAX_TX_IN_FLIGHT_PER_PEER`] 件まで。
    pub fn assign(&mut self, peer: PeerId, now: i64) -> Vec<Hash> {
        let current = self.in_flight.values().filter(|f| f.peer == peer).count();
        let room = MAX_TX_IN_FLIGHT_PER_PEER.saturating_sub(current);
        let mut picked = Vec::new();
        while picked.len() < room {
            let Some(txid) = self.wanted.pop_front() else {
                break;
            };
            self.queued.remove(&txid);
            self.in_flight.insert(
                txid,
                InFlight {
                    peer,
                    requested_at: now,
                },
            );
            picked.push(txid);
        }
        picked
    }

    /// このピアに、このトランザクションを頼んであるか。
    ///
    /// **検証する前にこれを通すこと。** 偽ならそのトランザクションには
    /// 触らない。頼んでいないものを検証するのは、相手に計算を命じられて
    /// いるのと同じである。
    pub fn was_requested_from(&self, peer: PeerId, txid: &Hash) -> bool {
        self.in_flight.get(txid).is_some_and(|f| f.peer == peer)
    }

    /// 受け取った (または諦めた) 印をつける。依頼中だったなら真。
    pub fn received(&mut self, txid: &Hash) -> bool {
        self.in_flight.remove(txid).is_some()
    }

    /// 時間切れのものを忘れる。忘れた数を返す。
    ///
    /// **頼み直さない。** 理由は型の説明にある。
    pub fn expire(&mut self, now: i64) -> usize {
        let before = self.in_flight.len();
        self.in_flight
            .retain(|_, f| now - f.requested_at < TX_REQUEST_TIMEOUT_SECS);
        before - self.in_flight.len()
    }

    /// 切れたピアに頼んでいたものを忘れる。忘れた数を返す。
    ///
    /// こちらも頼み直さない。
    pub fn peer_disconnected(&mut self, peer: PeerId) -> usize {
        let before = self.in_flight.len();
        self.in_flight.retain(|_, f| f.peer != peer);
        before - self.in_flight.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_primitives::hash;
    use std::collections::HashSet;

    fn block_hash(n: u64) -> Hash {
        hash::block_hash(&n.to_le_bytes())
    }

    fn hashes(range: std::ops::Range<u64>) -> Vec<Hash> {
        range.map(block_hash).collect()
    }

    #[test]
    fn a_fresh_tracker_is_idle() {
        let download = BlockDownload::new();
        assert!(download.is_idle());
        assert_eq!(download.queued_len(), 0);
        assert_eq!(download.in_flight_len(), 0);
    }

    #[test]
    fn wanted_blocks_are_assigned_in_order() {
        let mut download = BlockDownload::new();
        assert_eq!(download.want(hashes(0..5)), 5);

        let assigned = download.assign(1, 0);
        assert_eq!(
            assigned,
            hashes(0..5),
            "they should be assigned oldest first"
        );
        assert_eq!(download.queued_len(), 0);
        assert_eq!(download.in_flight_len(), 5);
    }

    #[test]
    fn the_same_block_is_not_requested_twice() {
        let mut download = BlockDownload::new();
        download.want(hashes(0..3));
        assert_eq!(download.want(hashes(0..3)), 0, "added twice");

        download.assign(1, 0);
        assert_eq!(
            download.want(hashes(0..3)),
            0,
            "an in-flight request was added again"
        );
    }

    #[test]
    fn one_peer_is_not_asked_beyond_the_limit() {
        let mut download = BlockDownload::new();
        let total = MAX_IN_FLIGHT_PER_PEER * 3;
        download.want(hashes(0..total as u64));

        let first = download.assign(1, 0);
        assert_eq!(first.len(), MAX_IN_FLIGHT_PER_PEER);
        assert!(
            download.assign(1, 0).is_empty(),
            "requesting beyond the limit"
        );

        // 別のピアには頼める。
        let second = download.assign(2, 0);
        assert_eq!(second.len(), MAX_IN_FLIGHT_PER_PEER);
        assert!(
            first.iter().all(|h| !second.contains(h)),
            "requesting duplicates"
        );
    }

    #[test]
    fn room_opens_up_as_blocks_arrive() {
        let mut download = BlockDownload::new();
        download.want(hashes(0..(MAX_IN_FLIGHT_PER_PEER as u64 + 5)));
        let assigned = download.assign(1, 0);
        assert!(download.assign(1, 0).is_empty());

        // 3 件届けば 3 件分の空きができる。
        for hash in assigned.iter().take(3) {
            assert!(download.received(hash));
        }
        assert_eq!(download.assign(1, 0).len(), 3);
    }

    #[test]
    fn an_unrequested_block_is_reported() {
        let mut download = BlockDownload::new();
        download.want(hashes(0..1));
        download.assign(1, 0);

        assert!(download.received(&block_hash(0)));
        assert!(
            !download.received(&block_hash(0)),
            "the same block counts as received twice"
        );
        assert!(
            !download.received(&block_hash(99)),
            "an unrequested block was accepted"
        );
    }

    #[test]
    fn timed_out_requests_go_back_to_the_queue() {
        let mut download = BlockDownload::new();
        download.want(hashes(0..3));
        download.assign(1, 0);
        assert_eq!(download.in_flight_len(), 3);

        // まだ期限内。
        assert!(download.expire(REQUEST_TIMEOUT_SECS - 1).is_empty());
        assert_eq!(download.in_flight_len(), 3);

        let expired = download.expire(REQUEST_TIMEOUT_SECS);
        assert_eq!(expired.len(), 3);
        assert_eq!(download.in_flight_len(), 0);
        assert_eq!(download.queued_len(), 3);

        // 別のピアに頼み直せる。
        assert_eq!(download.assign(2, REQUEST_TIMEOUT_SECS).len(), 3);
    }

    #[test]
    fn a_peer_that_does_not_have_it_gives_it_up_at_once() {
        // **時間切れを待ってはならない。** 返事は来ているのだから、
        // 60 秒後ではなく直ちに別のピアへ回せなければならない。
        let mut download = BlockDownload::new();
        download.want(hashes(0..1));
        assert_eq!(download.assign(1, 0), hashes(0..1));
        assert!(
            download.assign(2, 0).is_empty(),
            "an in-flight request was handed out twice"
        );

        assert!(download.not_found(&block_hash(0), 1));
        assert_eq!(download.in_flight_len(), 0);
        assert_eq!(
            download.assign(2, 0),
            hashes(0..1),
            "not reassigned to another peer immediately after the refusal"
        );
    }

    #[test]
    fn only_the_peer_we_asked_can_give_it_up() {
        // 誰の notfound でも効くなら、無関係なピアが他人への依頼を
        // 剥がして横取りできる。
        let mut download = BlockDownload::new();
        download.want(hashes(0..1));
        download.assign(1, 0);

        assert!(!download.not_found(&block_hash(0), 2));
        assert_eq!(download.in_flight_len(), 1);
        assert!(download.assign(3, 0).is_empty());
    }

    #[test]
    fn giving_up_something_we_never_asked_for_changes_nothing() {
        let mut download = BlockDownload::new();
        download.want(hashes(0..2));
        download.assign(1, 0);

        assert!(!download.not_found(&block_hash(99), 1));
        assert_eq!(download.in_flight_len(), 2);
        assert_eq!(download.queued_len(), 0);
    }

    #[test]
    fn a_block_given_up_keeps_its_place_in_the_chain() {
        // 戻す先は元の位置である。後ろに回すと、チェーンの頭が埋まらない
        // まま後続だけが溜まる。
        let mut download = BlockDownload::new();
        download.want(hashes(0..3));
        download.assign(1, 0);
        download.not_found(&block_hash(0), 1);

        assert_eq!(
            download.assign(2, 0),
            hashes(0..1),
            "the requeued one was put behind"
        );
    }

    #[test]
    fn a_disconnect_returns_that_peers_requests() {
        let mut download = BlockDownload::new();
        download.want(hashes(0..6));
        let first = download.assign(1, 0);
        let second = download.assign(2, 0);
        assert_eq!(first.len() + second.len(), 6);

        assert_eq!(download.peer_disconnected(1), first.len());
        assert_eq!(download.queued_len(), first.len());
        assert_eq!(
            download.in_flight_len(),
            second.len(),
            "another peer's requests were requeued too"
        );
    }

    #[test]
    fn a_disconnect_of_an_unknown_peer_changes_nothing() {
        let mut download = BlockDownload::new();
        download.want(hashes(0..3));
        download.assign(1, 0);
        assert_eq!(download.peer_disconnected(99), 0);
        assert_eq!(download.in_flight_len(), 3);
    }

    #[test]
    fn requeued_blocks_keep_their_place_at_the_front() {
        // 取りこぼしたものを後回しにすると、チェーンの先頭が埋まらず
        // いつまでも繋げられない。先に頼み直す。
        let mut download = BlockDownload::new();
        download.want(hashes(0..3));
        download.assign(1, 0);
        download.want(hashes(3..6));

        download.expire(REQUEST_TIMEOUT_SECS);
        let assigned = download.assign(2, REQUEST_TIMEOUT_SECS);
        assert_eq!(
            &assigned[..3],
            &hashes(0..3)[..],
            "the older missed one was put behind"
        );
    }

    #[test]
    fn forgetting_removes_it_from_both_places() {
        let mut download = BlockDownload::new();
        download.want(hashes(0..4));
        download.assign(1, 0);
        download.want(hashes(4..8));

        // 依頼中のもの。
        download.forget(&block_hash(0));
        assert!(!download.is_tracked(&block_hash(0)));
        assert_eq!(download.in_flight_len(), 3);

        // 待ち行列のもの。
        download.forget(&block_hash(5));
        assert!(!download.is_tracked(&block_hash(5)));
        assert_eq!(download.queued_len(), 3);
        assert!(!download.assign(1, 0).contains(&block_hash(5)));
    }

    #[test]
    fn everything_is_eventually_delivered_across_peer_failures() {
        // ピアが落ちても時間切れになっても、最後には全部そろうこと。
        let mut download = BlockDownload::new();
        let total = 40u64;
        download.want(hashes(0..total));

        let mut received: HashSet<Hash> = HashSet::new();
        let mut now = 0i64;
        let mut peer: PeerId = 1;

        for round in 0..20 {
            download.expire(now);
            let assigned = download.assign(peer, now);
            // 半分だけ届き、残りは放置される。
            for hash in assigned.iter().step_by(2) {
                download.received(hash);
                received.insert(*hash);
            }
            if round % 3 == 2 {
                download.peer_disconnected(peer);
                peer += 1;
            }
            now += REQUEST_TIMEOUT_SECS;
            if download.is_idle() {
                break;
            }
        }

        assert_eq!(
            received.len() as u64,
            total,
            "some were missed (only {} arrived)",
            received.len()
        );
        assert!(download.is_idle());
    }
    // ━━━━━━━━ トランザクションの取り寄せ ━━━━━━━━

    fn txid(n: u64) -> Hash {
        oag_primitives::hash::txid(&n.to_le_bytes())
    }

    #[test]
    fn a_transaction_is_only_accepted_from_the_peer_it_was_asked_of() {
        // これがこの型の主な役目である。頼んだ覚えのないものを検証すると、
        // 署名の検証という重い計算を相手に命じられることになる。
        let mut reqs = TxRequests::new();
        reqs.want([txid(1)]);
        let asked = reqs.assign(7, 0);
        assert_eq!(asked, vec![txid(1)]);

        assert!(
            reqs.was_requested_from(7, &txid(1)),
            "it passes from the peer it was requested from"
        );
        assert!(
            !reqs.was_requested_from(8, &txid(1)),
            "another peer cutting in must not be accepted"
        );
        assert!(
            !reqs.was_requested_from(7, &txid(2)),
            "what was not requested must not be accepted"
        );
    }

    #[test]
    fn the_same_transaction_is_not_asked_for_twice() {
        let mut reqs = TxRequests::new();
        assert_eq!(
            reqs.want([txid(1), txid(1), txid(2)]),
            2,
            "duplicates fold into one"
        );
        assert_eq!(reqs.assign(1, 0).len(), 2);
        // 依頼中のものをもう一度積もうとしても増えない。
        assert_eq!(reqs.want([txid(1)]), 0);
    }

    #[test]
    fn one_peer_cannot_be_asked_for_more_than_the_limit() {
        let mut reqs = TxRequests::new();
        let many: Vec<Hash> = (0..MAX_TX_IN_FLIGHT_PER_PEER as u64 * 3)
            .map(txid)
            .collect();
        reqs.want(many);
        assert_eq!(reqs.assign(1, 0).len(), MAX_TX_IN_FLIGHT_PER_PEER);
        // 同じピアには、返すまで追加で頼まない。
        assert!(reqs.assign(1, 0).is_empty());
        // 別のピアには頼める。
        assert_eq!(reqs.assign(2, 0).len(), MAX_TX_IN_FLIGHT_PER_PEER);
    }

    #[test]
    fn the_queue_is_bounded() {
        // 上限が無ければ、繋がっただけのピアがこちらの記憶を好きなだけ
        // 埋められる。inv は 1 通で 5,000 件を運べる。
        let mut reqs = TxRequests::new();
        let flood: Vec<Hash> = (0..MAX_QUEUED_TX as u64 + 1_000).map(txid).collect();
        reqs.want(flood);
        assert_eq!(reqs.queued_len(), MAX_QUEUED_TX);
    }

    #[test]
    fn a_request_that_times_out_is_forgotten_rather_than_retried() {
        // ブロックとは違い、頼み直さない。存在しない txid を大量に
        // 知らされたとき、頼み直す作りだと、ピアを変えながら同じ嘘を
        // 追い続けることになる。
        let mut reqs = TxRequests::new();
        reqs.want([txid(1)]);
        reqs.assign(1, 0);
        assert_eq!(reqs.in_flight_len(), 1);

        assert_eq!(reqs.expire(TX_REQUEST_TIMEOUT_SECS), 1);
        assert_eq!(reqs.in_flight_len(), 0);
        assert_eq!(reqs.queued_len(), 0, "it must not be put back in the queue");
        assert!(!reqs.is_tracked(&txid(1)));
    }

    #[test]
    fn a_request_still_inside_the_timeout_is_kept() {
        let mut reqs = TxRequests::new();
        reqs.want([txid(1)]);
        reqs.assign(1, 0);
        assert_eq!(reqs.expire(TX_REQUEST_TIMEOUT_SECS - 1), 0);
        assert!(reqs.was_requested_from(1, &txid(1)));
    }

    #[test]
    fn requests_to_a_peer_that_left_are_forgotten() {
        let mut reqs = TxRequests::new();
        reqs.want([txid(1), txid(2)]);
        reqs.assign(1, 0);
        assert_eq!(reqs.peer_disconnected(1), 2);
        assert_eq!(reqs.in_flight_len(), 0);
        assert_eq!(reqs.queued_len(), 0, "we do not re-request it either");
    }

    #[test]
    fn receiving_clears_the_request() {
        let mut reqs = TxRequests::new();
        reqs.want([txid(1)]);
        reqs.assign(1, 0);
        assert!(reqs.received(&txid(1)));
        // 使い切り。同じ相手がもう一度送ってきても通らない。
        assert!(!reqs.was_requested_from(1, &txid(1)));
        assert!(!reqs.received(&txid(1)));
    }
}
