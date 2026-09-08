//! ピア発見を、実際に 3 台繋いで確かめる。
//!
//! **試すのは「教えていない相手に繋がるか」である。** 住所帳の単体試験は
//! 中身の規則しか示さない。C が A から B の住所を聞いて、B に繋ぎに行き、
//! B のチェーンに追いつく — ここまで通って初めてピア発見と言える。
//!
//! ```text
//!   B ──(掘る)          A ──(--connect で B を知っている)
//!                        │
//!                        └── C は A にだけ繋ぐ。B のことは知らない
//! ```
//!
//! C が B に届けば、`getaddr` / `addr` と接続の維持が噛み合っている。

use oag_consensus::lock::Lock;
use oag_net::magic::magic_for;
use oag_net::transport::Listener;
use oag_node::connect::Outbound;
use oag_node::service::{NodeHandle, NodeService};
use oag_node::{accept_loop, connect};
use oag_primitives::{Address, Network, SecretKey};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const NETWORK: Network = Network::Regtest;

/// 待つ上限。RandomX の検証を含むので短くしすぎない。
const TIMEOUT: Duration = Duration::from_secs(90);

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("oag-disc-{tag}-{}-{n}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn payout() -> Lock {
    Lock::from_address(&Address::from_pubkey(
        NETWORK,
        &SecretKey::generate().public_key(),
    ))
}

fn start(tag: &str) -> (TempDir, NodeService) {
    let dir = TempDir::new(tag);
    let service = NodeService::start(NETWORK, &dir.0).expect("ノードを起こせる");
    (dir, service)
}

async fn listen(handle: NodeHandle) -> SocketAddr {
    let listener = Listener::bind(magic_for(NETWORK), "127.0.0.1:0".parse().unwrap())
        .await
        .expect("待ち受けられる");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(accept_loop(handle, listener));
    addr
}

async fn wait_until(what: &str, mut ready: impl AsyncCheck) {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if ready.check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{what}: 期限までに起きなかった");
}

/// 待ち合わせの条件。async クロージャを安定版で書けないので trait にする。
trait AsyncCheck {
    fn check(&mut self) -> impl std::future::Future<Output = bool>;
}

impl<F, Fut> AsyncCheck for F
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    fn check(&mut self) -> impl std::future::Future<Output = bool> {
        self()
    }
}

/// 教えていない相手に、聞いて繋ぎに行くこと。
#[test]
fn a_node_reaches_a_peer_it_was_never_told_about() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (_dir_a, service_a) = start("hub");
    let (_dir_b, service_b) = start("src");
    let (_dir_c, service_c) = start("new");
    let a = service_a.handle();
    let b = service_b.handle();
    let c = service_c.handle();

    runtime.block_on(async {
        let a_addr = listen(a.clone()).await;
        let b_addr = listen(b.clone()).await;

        // B がチェーンを積む。**C には B のことを一切教えない。**
        b.start_mining(payout(), Some(3), false).await.unwrap();

        // A と B は自分の待ち受け住所を名乗る。これが無いと、A は B の
        // 住所を知っていても「実績のある住所」にならず、C に配らない。
        a.set_own_addresses(vec![a_addr]).await.unwrap();
        b.set_own_addresses(vec![b_addr]).await.unwrap();

        // A は B を名指しで知っている。
        let a_out = Outbound::new();
        tokio::spawn(connect::maintain(a.clone(), a_out, vec![b_addr]));

        // C は A しか知らない。
        let c_out = Outbound::new();
        tokio::spawn(connect::maintain(c.clone(), c_out.clone(), vec![a_addr]));

        // ── C が B の住所を知ること ──
        {
            let c = c.clone();
            wait_until("C が B の住所を覚える", move || {
                let c = c.clone();
                async move {
                    c.status()
                        .await
                        .map(|s| s.known_addresses > 0)
                        .unwrap_or(false)
                }
            })
            .await;
        }

        // ── C が B に繋ぎに行き、チェーンに追いつくこと ──
        //
        // A は掘っていないので、C が高さ 3 になったなら B から得ている。
        {
            let c = c.clone();
            wait_until("C が B のチェーンに追いつく", move || {
                let c = c.clone();
                async move { c.status().await.map(|s| s.height >= 3).unwrap_or(false) }
            })
            .await;
        }

        let sb = b.status().await.unwrap();
        let sc = c.status().await.unwrap();
        assert_eq!(sc.tip, sb.tip, "先端が食い違っている");
        assert_eq!(sc.height, 3);

        // C は B に自分から繋ぎに行ったはずである。
        assert!(
            c_out.addrs().contains(&b_addr),
            "C が B に繋ぎに行っていない: {:?}",
            c_out.addrs()
        );
    });
}

/// 住所帳がファイルに残り、次の起動で読まれること。
///
/// **残らなければ、起動のたびにシードを引くことになる。**
#[test]
fn what_a_node_learns_survives_a_restart() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let dir = TempDir::new("restart");
    let (_dir_b, service_b) = start("restart-peer");
    let b = service_b.handle();

    let learned = runtime.block_on(async {
        let b_addr = listen(b.clone()).await;
        b.set_own_addresses(vec![b_addr]).await.unwrap();

        let service_a = NodeService::start(NETWORK, &dir.0).expect("ノードを起こせる");
        let a = service_a.handle();
        let out = Outbound::new();
        tokio::spawn(connect::maintain(a.clone(), out, vec![b_addr]));

        {
            let a = a.clone();
            wait_until("A が B に繋がる", move || {
                let a = a.clone();
                async move {
                    a.status()
                        .await
                        .map(|s| s.known_addresses > 0)
                        .unwrap_or(false)
                }
            })
            .await;
        }
        a.save_addresses().await.unwrap();
        drop(service_a);
        b_addr
    });

    // 同じデータディレクトリで起こし直す。
    let service_a2 = NodeService::start(NETWORK, &dir.0).expect("ノードを起こし直せる");
    let a2 = service_a2.handle();
    runtime.block_on(async {
        let status = a2.status().await.unwrap();
        assert!(
            status.known_addresses > 0,
            "起動し直したら住所帳が空になっている"
        );
        let picked = a2.address_candidates(4, Vec::new()).await.unwrap();
        assert!(
            picked.contains(&learned),
            "覚えたはずの {learned} が候補に出てこない: {picked:?}"
        );
    });
}
