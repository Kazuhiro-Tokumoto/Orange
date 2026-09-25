//! 外向きの接続を保つ。
//!
//! 住所帳から繋ぎ先を選び、決まった本数の接続を維持する。切れたら補充
//! する。**これが無いと、住所帳に何件覚えていても誰にも繋がらない。**
//!
//! # 繋ぎ先が 1 件も無いとき
//!
//! シード ([`crate::seeds`]) を引く。**住所帳に候補がある限り引かない。**
//! シードは新しく入るときの取っ掛かりであって、常用するものではない。
//!
//! # 何本繋ぐか
//!
//! [`TARGET_OUTBOUND`] 本。少ないと、繋いだ相手が全員が悪意を持っていた
//! 場合に偽のチェーンを掴まされる (日蝕攻撃)。多いと帯域と相手の負担が
//! 増える。住所帳が同じ /16 から 1 件しか候補を返さない
//! ([`crate::addrbook::AddressBook::candidates`]) ので、この本数は
//! そのまま**別々のネットワークの数**になる。
//!
//! # 先端が止まったとき
//!
//! 住所帳に候補があるとシードは引かない。すると、**繋いでいる相手が揃って
//! 止まっていても (相手自身が孤立している、など)、同じ相手とだけ繋がり
//! 続ける。** 1 分に 1 個のはずのブロックが `STALE_TIP_SECS` 来なければ、
//! シードを引き直して候補を足す。
//!
//! ネットワーク全体で本当に誰も掘っていないときもここに来る。そのときは
//! 引き直しても何も変わらないが、害も無い。30 分に 1 回、名前を引くだけで
//! ある。
//!
//! 死んだ接続そのものは [`crate::peer`] の `ping` が見つけて切る。こちらは
//! 生きているが止まっている相手のためのものである。
//!
//! # 相手から繋がれた接続は数えない
//!
//! 攻撃者は好きなだけ繋いでこられる。それを本数に数えると、繋いでくる
//! だけで**こちらが外に繋ぎに行くのを止められる**。数えるのは自分から
//! 繋いだ本数だけである。

use crate::peer::{self, Direction};
use crate::service::{DialOutcome, NodeHandle};
use oag_net::magic::magic_for;
use oag_net::transport::Connection;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 保ちたい外向きの接続の本数。
pub const TARGET_OUTBOUND: usize = 8;

/// 繋ぎ先を見直す間隔。
const REVIEW: Duration = Duration::from_secs(5);

/// 住所帳を書き出す間隔。
const SAVE: Duration = Duration::from_secs(300);

/// 1 回の見直しで新しく繋ぎに行く上限。
///
/// 一度に全部を張りに行かない。**シードを引いた直後は候補が一斉に
/// 入る**ので、それを丸ごと同時に叩くと相手にも自分にも優しくない。
const DIALS_PER_REVIEW: usize = 2;

/// 繋ぐ試みの待ち時間。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 先端がこの秒数だけ動かなければ、シードを引き直す。目標間隔の 30 倍。
const STALE_TIP_SECS: i64 = 30 * 60;

/// いま繋いでいる・繋ぎに行っている外向きの住所。
#[derive(Debug, Clone, Default)]
pub struct Outbound(Arc<Mutex<HashSet<SocketAddr>>>);

impl Outbound {
    /// 空の一覧。
    pub fn new() -> Outbound {
        Outbound::default()
    }

    /// 本数。
    pub fn len(&self) -> usize {
        self.0.lock().map(|set| set.len()).unwrap_or(0)
    }

    /// 1 本も無いか。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 一覧。
    pub fn addrs(&self) -> Vec<SocketAddr> {
        self.0
            .lock()
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// 入れる。すでにあれば偽を返す。
    fn insert(&self, addr: SocketAddr) -> bool {
        self.0
            .lock()
            .map(|mut set| set.insert(addr))
            .unwrap_or(false)
    }

    fn remove(&self, addr: &SocketAddr) {
        if let Ok(mut set) = self.0.lock() {
            set.remove(addr);
        }
    }
}

/// 外向きの接続を保ち続ける。**戻らない。**
///
/// `fixed` は `--connect` で明示された相手。住所帳とは別に、常に繋ぎ
/// 直す。運用者が名指しした相手を勝手に諦めない。
pub async fn maintain(handle: NodeHandle, outbound: Outbound, fixed: Vec<SocketAddr>) {
    for addr in &fixed {
        spawn_dial(handle.clone(), outbound.clone(), *addr);
    }

    let mut review = tokio::time::interval(REVIEW);
    review.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut save = tokio::time::interval(SAVE);
    save.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // interval の 1 回目は即座に来る。書き出しは今すぐでなくてよい。
    save.tick().await;

    let mut events = handle.subscribe();
    let mut stale = StaleTip::new(now());

    loop {
        tokio::select! {
            _ = review.tick() => {
                // --connect で名指しされた相手は、切れていたら繋ぎ直す。
                for addr in &fixed {
                    if !outbound.addrs().contains(addr) {
                        spawn_dial(handle.clone(), outbound.clone(), *addr);
                    }
                }
                if let Some(quiet) = stale.due(now()) {
                    crate::log_warn!(
                        "no new block for {} minutes with {} outbound peers, \
                         so asking the seed for more",
                        quiet / 60,
                        outbound.len()
                    );
                    if let Err(e) = pull_seeds(&handle).await {
                        crate::log_warn!("cannot add the seed's addresses: {e}");
                        return;
                    }
                }
                if let Err(e) = top_up(&handle, &outbound).await {
                    crate::log_warn!("cannot choose a destination: {e}");
                    return;
                }
            }
            event = events.recv() => {
                match event {
                    Ok(crate::service::NodeEvent::NewTip { .. }) => stale.moved(now()),
                    Ok(_) => {}
                    // 取り落とした中に先端の報せがあったかもしれない。
                    // 動いたものとして扱う。引き直しが 30 分遅れるだけである。
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => stale.moved(now()),
                    // ノードが止まった。
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
            _ = save.tick() => {
                if let Err(e) = handle.save_addresses().await {
                    crate::log_warn!("cannot write out the address book: {e}");
                    return;
                }
            }
        }
    }
}

/// 足りない分を繋ぎに行く。
async fn top_up(handle: &NodeHandle, outbound: &Outbound) -> Result<(), String> {
    let busy = outbound.addrs();
    if busy.len() >= TARGET_OUTBOUND {
        return Ok(());
    }
    let want = (TARGET_OUTBOUND - busy.len()).min(DIALS_PER_REVIEW);

    let mut picked = handle.address_candidates(want, busy.clone()).await?;
    if picked.is_empty() && busy.is_empty() {
        // 住所帳に当てが無く、1 本も繋がっていない。ここで初めてシードを
        // 引く。**繋がっている間は引かない。**
        if !pull_seeds(handle).await? {
            return Ok(());
        }
        picked = handle.address_candidates(want, busy).await?;
    }

    for addr in picked {
        spawn_dial(handle.clone(), outbound.clone(), addr);
    }
    Ok(())
}

/// シードを引き、答えを住所帳に足す。1 件でも得られたら真。
async fn pull_seeds(handle: &NodeHandle) -> Result<bool, String> {
    let seeded = crate::seeds::resolve(handle.network()).await;
    if seeded.is_empty() {
        return Ok(false);
    }
    let at = now();
    let addrs = seeded
        .iter()
        .map(|a| oag_net::message::NetAddress::from_socket(*a, 0, at))
        .collect();
    // 出どころは指定しない。シードが答えた住所は、それぞれ自分の
    // 括りでバケットが決まる。**シードを 1 つの出どころとして扱うと、
    // 答え全体が 64 バケットに押し込まれる。**
    handle.add_addresses(addrs, None).await?;
    Ok(true)
}

/// 先端が止まっていないかの見張り。
///
/// 時刻は壁時計 (秒) である。
#[derive(Debug)]
struct StaleTip {
    /// 最後に先端が動いた時刻。
    moved_at: i64,
    /// 最後にシードを引き直した時刻。
    pulled_at: i64,
}

impl StaleTip {
    fn new(now: i64) -> StaleTip {
        StaleTip {
            moved_at: now,
            pulled_at: now,
        }
    }

    /// 先端が動いた。
    fn moved(&mut self, now: i64) {
        self.moved_at = now;
    }

    /// シードを引き直す時なら、止まっている秒数を返す。引き直したものと
    /// して覚える。
    ///
    /// 止まっている間も [`STALE_TIP_SECS`] に 1 回だけ引く。
    fn due(&mut self, now: i64) -> Option<i64> {
        let quiet = now - self.moved_at;
        if quiet < STALE_TIP_SECS || now - self.pulled_at < STALE_TIP_SECS {
            return None;
        }
        self.pulled_at = now;
        Some(quiet)
    }
}

/// 1 本繋ぎに行き、切れるまで面倒を見る。
fn spawn_dial(handle: NodeHandle, outbound: Outbound, addr: SocketAddr) {
    if !outbound.insert(addr) {
        // すでに繋いでいる、または繋ぎに行っている最中。
        return;
    }
    tokio::spawn(async move {
        let network = handle.network();
        let connected = tokio::time::timeout(
            CONNECT_TIMEOUT,
            Connection::connect(magic_for(network), addr),
        )
        .await;

        match connected {
            Ok(Ok(conn)) => {
                let _ = handle.address_outcome(addr, DialOutcome::Connected).await;
                if let Err(e) = peer::run_as(handle.clone(), conn, Direction::Outbound).await {
                    crate::log_warn!("dropped the exchange with {addr}: {e}");
                }
            }
            Ok(Err(e)) => {
                crate::log_warn!("cannot connect to {addr}: {e}");
                let _ = handle.address_outcome(addr, DialOutcome::Failed).await;
            }
            Err(_) => {
                crate::log_warn!("no connection to {addr} (gave up after {CONNECT_TIMEOUT:?})");
                let _ = handle.address_outcome(addr, DialOutcome::Failed).await;
            }
        }
        outbound.remove(&addr);
    });
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> SocketAddr {
        format!("93.184.216.{n}:9444").parse().unwrap()
    }

    #[test]
    fn an_address_is_only_held_once() {
        let out = Outbound::new();
        assert!(out.is_empty());
        assert!(out.insert(addr(1)));
        assert!(!out.insert(addr(1)), "dialling the same address twice");
        assert_eq!(out.len(), 1);

        out.remove(&addr(1));
        assert!(out.is_empty());
        assert!(out.insert(addr(1)));
    }

    const T0: i64 = 1_800_000_000;

    #[test]
    fn a_moving_tip_never_pulls_the_seed() {
        let mut stale = StaleTip::new(T0);
        for minute in 1..=120 {
            let now = T0 + minute * 60;
            stale.moved(now);
            assert_eq!(stale.due(now), None, "pulled at minute {minute}");
        }
    }

    #[test]
    fn a_stuck_tip_pulls_the_seed_once_per_period() {
        let mut stale = StaleTip::new(T0);
        assert_eq!(stale.due(T0 + STALE_TIP_SECS - 1), None);
        assert_eq!(stale.due(T0 + STALE_TIP_SECS), Some(STALE_TIP_SECS));
        // 止まったままでも、次は 1 周期あとまで引かない。
        assert_eq!(stale.due(T0 + STALE_TIP_SECS + 5), None);
        assert_eq!(stale.due(T0 + 2 * STALE_TIP_SECS - 1), None);
        assert_eq!(stale.due(T0 + 2 * STALE_TIP_SECS), Some(2 * STALE_TIP_SECS));
    }

    #[test]
    fn a_tip_that_moves_again_resets_the_wait() {
        let mut stale = StaleTip::new(T0);
        assert_eq!(stale.due(T0 + STALE_TIP_SECS), Some(STALE_TIP_SECS));
        let moved = T0 + STALE_TIP_SECS + 60;
        stale.moved(moved);
        assert_eq!(stale.due(moved + STALE_TIP_SECS - 1), None);
        assert_eq!(stale.due(moved + STALE_TIP_SECS), Some(STALE_TIP_SECS));
    }

    #[test]
    fn removing_something_absent_is_harmless() {
        let out = Outbound::new();
        out.remove(&addr(9));
        assert!(out.is_empty());
    }
}
