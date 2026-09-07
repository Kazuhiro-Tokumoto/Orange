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
use std::collections::{BTreeMap, HashMap};

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
        assert_eq!(assigned, hashes(0..5), "古い順に割り振られるべき");
        assert_eq!(download.queued_len(), 0);
        assert_eq!(download.in_flight_len(), 5);
    }

    #[test]
    fn the_same_block_is_not_requested_twice() {
        let mut download = BlockDownload::new();
        download.want(hashes(0..3));
        assert_eq!(download.want(hashes(0..3)), 0, "重ねて加えられている");

        download.assign(1, 0);
        assert_eq!(
            download.want(hashes(0..3)),
            0,
            "依頼中のものが再び加えられている"
        );
    }

    #[test]
    fn one_peer_is_not_asked_beyond_the_limit() {
        let mut download = BlockDownload::new();
        let total = MAX_IN_FLIGHT_PER_PEER * 3;
        download.want(hashes(0..total as u64));

        let first = download.assign(1, 0);
        assert_eq!(first.len(), MAX_IN_FLIGHT_PER_PEER);
        assert!(download.assign(1, 0).is_empty(), "上限を超えて頼んでいる");

        // 別のピアには頼める。
        let second = download.assign(2, 0);
        assert_eq!(second.len(), MAX_IN_FLIGHT_PER_PEER);
        assert!(
            first.iter().all(|h| !second.contains(h)),
            "重複して頼んでいる"
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
            "同じブロックを二度受け取ったことになっている"
        );
        assert!(
            !download.received(&block_hash(99)),
            "頼んでいないブロックが受理されている"
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
            "他のピアの依頼まで戻されている"
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
            "取りこぼした古い方が後回しになっている"
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
            "取りこぼしがある ({} 件しか届いていない)",
            received.len()
        );
        assert!(download.is_idle());
    }
}
