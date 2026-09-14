//! 2 台のノードを実際に TCP で繋ぎ、同期することを確かめる。
//!
//! 単体試験はそれぞれの部品が仕様どおりに動くことしか示さない。
//! **繋いだときに実際にブロックが渡るか**は、繋いでみないと分からない。
//!
//! regtest を用いる。難易度 1 なので RandomX の計算はすぐ終わる。
//! それでも検証器の初期化に 256 MB の確保が伴うため、この試験は
//! 他の試験より重い。

use oag_consensus::lock::Lock;
use oag_net::magic::magic_for;
use oag_net::transport::Listener;
use oag_node::service::{NodeHandle, NodeService};
use oag_node::{accept_loop, dial};
use oag_primitives::{Address, Network, SecretKey};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const NETWORK: Network = Network::Regtest;

/// 同期を待つ上限。RandomX の検証を含むため短くしすぎない。
const SYNC_TIMEOUT: Duration = Duration::from_secs(60);

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// 試験ごとに独立した一時ディレクトリ。作りっぱなしにせず片付ける。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("oag-p2p-{tag}-{}-{n}-{nanos}", std::process::id()));
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
    let secret = SecretKey::generate();
    Lock::from_address(&Address::from_pubkey(NETWORK, &secret.public_key()))
}

/// ノードを 1 台起こす。
fn start(tag: &str) -> (TempDir, NodeService) {
    let dir = TempDir::new(tag);
    let service = NodeService::start(NETWORK, &dir.0).expect("ノードを起こせる");
    (dir, service)
}

/// 待ち受けを始め、受け入れ作業を走らせる。実際に開いた住所を返す。
async fn listen(handle: NodeHandle) -> SocketAddr {
    // ポート 0 を指定すると空いているポートが選ばれる。試験を並行して
    // 走らせても衝突しない。
    let listener = Listener::bind(magic_for(NETWORK), "127.0.0.1:0".parse().unwrap())
        .await
        .expect("待ち受けられる");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(accept_loop(handle, listener));
    addr
}

/// 高さがその値になるまで待つ。
async fn wait_for_height(handle: &NodeHandle, wanted: u64, what: &str) {
    let deadline = Instant::now() + SYNC_TIMEOUT;
    let mut last = 0;
    while Instant::now() < deadline {
        let status = handle.status().await.expect("状態を引ける");
        last = status.height;
        if status.height >= wanted {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{what}: 高さ {wanted} に届かなかった (今は {last})");
}

/// 掘り終えるまで待つ。
async fn wait_for_mining(handle: &NodeHandle, wanted: u64) {
    wait_for_height(handle, wanted, "採掘").await;
}

/// 追いついたノードが、追いつかれた側と同じ先端を持つこと。
async fn assert_same_tip(a: &NodeHandle, b: &NodeHandle) {
    let sa = a.status().await.unwrap();
    let sb = b.status().await.unwrap();
    assert_eq!(sa.tip, sb.tip, "先端が食い違っている");
    assert_eq!(sa.height, sb.height, "高さが食い違っている");
    assert_eq!(sa.utxo_count, sb.utxo_count, "UTXO の数が食い違っている");
    assert_eq!(
        sa.cumulative_work, sb.cumulative_work,
        "累積作業量が食い違っている"
    );
}

/// 先に積まれたチェーンに、後から繋いだノードが追いつくこと。
#[test]
fn a_new_node_catches_up_with_an_existing_chain() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (_dir_a, service_a) = start("a-src");
    let (_dir_b, service_b) = start("a-dst");
    let a = service_a.handle();
    let b = service_b.handle();

    runtime.block_on(async {
        // A に 5 ブロック積む。この時点で B は繋がっていない。
        a.start_mining(payout(), Some(5), false).await.unwrap();
        wait_for_mining(&a, 5).await;
        assert_eq!(b.status().await.unwrap().height, 0, "B はまだ空のはず");

        // B を A に繋ぐ。
        let addr = listen(a.clone()).await;
        tokio::spawn(dial(b.clone(), addr));

        wait_for_height(&b, 5, "追いつき").await;
        assert_same_tip(&a, &b).await;
    });
}

/// 繋がっている間に掘られたブロックが、相手に伝わること。
///
/// 追いつきとは別の道である。追いつきは `getheaders` から始まるが、
/// こちらは掘った側が `inv` で知らせるところから始まる。
#[test]
fn a_block_mined_while_connected_reaches_the_peer() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (_dir_a, service_a) = start("b-src");
    let (_dir_b, service_b) = start("b-dst");
    let a = service_a.handle();
    let b = service_b.handle();

    runtime.block_on(async {
        // 先に繋いでから掘る。
        let addr = listen(a.clone()).await;
        tokio::spawn(dial(b.clone(), addr));

        // ハンドシェイクが済むのを待つ。両方とも高さ 0 のままである。
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(a.status().await.unwrap().height, 0);
        assert_eq!(b.status().await.unwrap().height, 0);

        a.start_mining(payout(), Some(3), false).await.unwrap();
        wait_for_mining(&a, 3).await;

        wait_for_height(&b, 3, "中継").await;
        assert_same_tip(&a, &b).await;
    });
}

/// 同期しても、相手の言い分をそのまま信じてはいないこと。
///
/// 受け取ったブロックは自分で検証している。検証を通ったのだから、
/// **UTXO セットは自分で組み立てた結果**である。同じ高さで同じ
/// UTXO 件数になることがその証拠になる。
#[test]
fn a_synced_node_rebuilds_the_utxo_set_itself() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (_dir_a, service_a) = start("c-src");
    let (_dir_b, service_b) = start("c-dst");
    let a = service_a.handle();
    let b = service_b.handle();

    runtime.block_on(async {
        a.start_mining(payout(), Some(4), false).await.unwrap();
        wait_for_mining(&a, 4).await;

        let addr = listen(a.clone()).await;
        tokio::spawn(dial(b.clone(), addr));
        wait_for_height(&b, 4, "追いつき").await;

        let sb = b.status().await.unwrap();
        // ジェネシスは報酬を受け取らないため、高さ 4 なら UTXO は 4 件。
        assert_eq!(sb.utxo_count, 4, "コインベース 4 件が UTXO になる");
        assert_eq!(sb.indexed_blocks, 5, "ジェネシスを含めて 5 個");
        assert_same_tip(&a, &b).await;
    });
}

/// 先端が一致するまで待つ。
async fn wait_for_same_tip(a: &NodeHandle, b: &NodeHandle, what: &str) {
    let deadline = Instant::now() + SYNC_TIMEOUT;
    while Instant::now() < deadline {
        let sa = a.status().await.expect("状態を引ける");
        let sb = b.status().await.expect("状態を引ける");
        if sa.tip == sb.tip {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let sa = a.status().await.unwrap();
    let sb = b.status().await.unwrap();
    panic!(
        "{what}: 先端が揃わなかった (A は高さ {} の {}、B は高さ {} の {})",
        sa.height, sa.tip, sb.height, sb.tip
    );
}

/// 別々に掘った 2 本のチェーンが繋がったとき、作業量の多い方に揃うこと。
///
/// **これがブロックチェーンの根幹である。** 離れている間に別々のブロックを
/// 掘った 2 台は、繋がった時点で異なる帳簿を持っている。どちらが正しいかは
/// 多数決でも先着順でもなく、**積み上げた作業量**で決まる。負けた側は
/// 自分のブロックを取り消し、相手の枝を自分で検証して繋ぎ直す。
///
/// 単なる追いつき ([`a_new_node_catches_up_with_an_existing_chain`]) との
/// 違いは、**負ける側にも捨てるべきブロックがある**ことである。取り消しは
/// UTXO セットを巻き戻す操作を伴い、追いつきでは一度も走らない。
#[test]
fn two_chains_that_disagree_converge_on_the_heavier_one() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (_dir_a, service_a) = start("d-light");
    let (_dir_b, service_b) = start("d-heavy");
    let a = service_a.handle();
    let b = service_b.handle();

    runtime.block_on(async {
        // 繋がずにそれぞれ掘る。報酬の宛先が違うのでコインベースが違い、
        // 同じ高さでも別のブロックになる。
        a.start_mining(payout(), Some(3), false).await.unwrap();
        b.start_mining(payout(), Some(6), false).await.unwrap();
        wait_for_mining(&a, 3).await;
        wait_for_mining(&b, 6).await;

        let light = a.status().await.unwrap();
        let heavy = b.status().await.unwrap();
        assert_ne!(light.tip, heavy.tip, "同じチェーンを掘ってしまっている");
        assert!(light.cumulative_work < heavy.cumulative_work);
        let abandoned = light.tip;

        // ここで繋ぐ。A は自分の 3 ブロックを捨てて B の 6 ブロックに乗る。
        let addr = listen(b.clone()).await;
        tokio::spawn(dial(a.clone(), addr));

        wait_for_height(&a, 6, "リオーグ").await;
        wait_for_same_tip(&a, &b, "リオーグ").await;
        assert_same_tip(&a, &b).await;

        let after = a.status().await.unwrap();
        assert_ne!(after.tip, abandoned, "自分の枝を持ったままである");
        // 捨てた枝のコインベースは UTXO から消えていなければならない。
        // 残っていれば、存在しないはずの金が使える。
        assert_eq!(
            after.utxo_count, 6,
            "取り消した 3 ブロックのコインベースが残っている"
        );
    });
}

/// 作業量が同じ 2 本は、次の 1 ブロックが決めること。
///
/// 同点では切り替えない。切り替えると、繋ぎ直しただけで帳簿が入れ替わる
/// ことになり、決着がつかない。**先に見ていた方を保つ。** 決着は次の
/// ブロックが積まれたときに、そちらが重くなることでつく。
///
/// このとき負ける側のリオーグは分岐点まで遡るため、**チェーン全体と同じ
/// 深さ**になる。浅いリオーグより厳しい経路である。
#[test]
fn an_even_race_is_settled_by_the_next_block() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (_dir_a, service_a) = start("e-a");
    let (_dir_b, service_b) = start("e-b");
    let a = service_a.handle();
    let b = service_b.handle();

    runtime.block_on(async {
        // 同じ高さまで、別々に掘る。
        a.start_mining(payout(), Some(4), false).await.unwrap();
        b.start_mining(payout(), Some(4), false).await.unwrap();
        wait_for_mining(&a, 4).await;
        wait_for_mining(&b, 4).await;

        let before_a = a.status().await.unwrap();
        let before_b = b.status().await.unwrap();
        assert_ne!(before_a.tip, before_b.tip);
        assert_eq!(before_a.cumulative_work, before_b.cumulative_work);

        let addr = listen(b.clone()).await;
        tokio::spawn(dial(a.clone(), addr));

        // 繋がっても、同点のうちはどちらも動かない。
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(
            a.status().await.unwrap().tip,
            before_a.tip,
            "同点で先端を明け渡している"
        );
        assert_eq!(
            b.status().await.unwrap().tip,
            before_b.tip,
            "同点で先端を明け渡している"
        );

        // B が 1 つ積む。これで B の方が重くなる。
        b.start_mining(payout(), Some(1), false).await.unwrap();
        wait_for_mining(&b, 5).await;

        // A は 4 ブロックすべてを取り消して B の枝に乗り換える。
        wait_for_height(&a, 5, "同点の決着").await;
        wait_for_same_tip(&a, &b, "同点の決着").await;
        assert_same_tip(&a, &b).await;
        assert_eq!(
            a.status().await.unwrap().utxo_count,
            5,
            "取り消した枝のコインベースが残っている"
        );
    });
}
