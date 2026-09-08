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

    loop {
        tokio::select! {
            _ = review.tick() => {
                // --connect で名指しされた相手は、切れていたら繋ぎ直す。
                for addr in &fixed {
                    if !outbound.addrs().contains(addr) {
                        spawn_dial(handle.clone(), outbound.clone(), *addr);
                    }
                }
                if let Err(e) = top_up(&handle, &outbound).await {
                    eprintln!("繋ぎ先を選べない: {e}");
                    return;
                }
            }
            _ = save.tick() => {
                if let Err(e) = handle.save_addresses().await {
                    eprintln!("住所帳を書き出せない: {e}");
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
        let seeded = crate::seeds::resolve(handle.network()).await;
        if seeded.is_empty() {
            return Ok(());
        }
        let at = now();
        let addrs = seeded
            .iter()
            .map(|a| oag_net::message::NetAddress::from_socket(*a, 0, at))
            .collect();
        handle.add_addresses(addrs).await?;
        picked = handle.address_candidates(want, busy).await?;
    }

    for addr in picked {
        spawn_dial(handle.clone(), outbound.clone(), addr);
    }
    Ok(())
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
                    eprintln!("{addr} とのやり取りを打ち切った: {e}");
                }
            }
            Ok(Err(e)) => {
                eprintln!("{addr} に繋げない: {e}");
                let _ = handle.address_outcome(addr, DialOutcome::Failed).await;
            }
            Err(_) => {
                eprintln!("{addr} に繋がらない ({CONNECT_TIMEOUT:?} で諦めた)");
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
        assert!(!out.insert(addr(1)), "同じ住所を二重に繋ぎに行っている");
        assert_eq!(out.len(), 1);

        out.remove(&addr(1));
        assert!(out.is_empty());
        assert!(out.insert(addr(1)));
    }

    #[test]
    fn removing_something_absent_is_harmless() {
        let out = Outbound::new();
        out.remove(&addr(9));
        assert!(out.is_empty());
    }
}
