//! 2 台のノードを実際に TCP で繋ぎ、同期することを確かめる。
//!
//! 単体試験はそれぞれの部品が仕様どおりに動くことしか示さない。
//! **繋いだときに実際にブロックが渡るか**は、繋いでみないと分からない。
//!
//! regtest を用いる。難易度 1 なので RandomX の計算はすぐ終わる。
//! それでも検証器の初期化に 256 MB の確保が伴うため、この試験は
//! 他の試験より重い。

use oag_consensus::lock::Lock;
use oag_consensus::params;
use oag_consensus::sighash::{sighash, SighashType};
use oag_consensus::tx::{TxInput, CURRENT_TX_VERSION, SEQUENCE_FINAL};
use oag_consensus::{Transaction, TxOutput};
use oag_net::magic::magic_for;
use oag_net::transport::Listener;
use oag_node::service::{MiningMode, NodeHandle, NodeService};
use oag_node::{accept_loop, dial};
use oag_primitives::{Address, Amount, Network, SecretKey};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const NETWORK: Network = Network::Regtest;

/// 同期を待つ上限。RandomX の検証を含むため短くしすぎない。
const SYNC_TIMEOUT: Duration = Duration::from_secs(60);

/// コインベースの成熟まで掘る試験の上限。130 ブロックを掘って、
/// さらにもう 1 台が検証する。
const MATURITY_TIMEOUT: Duration = Duration::from_secs(240);

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
    let service = NodeService::start(NETWORK, &dir.0).expect("a node can be started");
    (dir, service)
}

/// 待ち受けを始め、受け入れ作業を走らせる。実際に開いた住所を返す。
async fn listen(handle: NodeHandle) -> SocketAddr {
    // ポート 0 を指定すると空いているポートが選ばれる。試験を並行して
    // 走らせても衝突しない。
    let listener = Listener::bind(magic_for(NETWORK), "127.0.0.1:0".parse().unwrap())
        .await
        .expect("it can listen");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(accept_loop(handle, listener));
    addr
}

/// 高さがその値になるまで待つ。
async fn wait_for_height(handle: &NodeHandle, wanted: u64, what: &str) {
    wait_for_height_within(handle, wanted, what, SYNC_TIMEOUT).await
}

/// 高さがその値になるまで、上限を指定して待つ。
async fn wait_for_height_within(handle: &NodeHandle, wanted: u64, what: &str, limit: Duration) {
    let deadline = Instant::now() + limit;
    let mut last = 0;
    while Instant::now() < deadline {
        let status = handle.status().await.expect("the state can be read");
        last = status.height;
        if status.height >= wanted {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{what}: did not reach height {wanted} (now {last})");
}

/// 掘り終えるまで待つ。
async fn wait_for_mining(handle: &NodeHandle, wanted: u64) {
    wait_for_height(handle, wanted, "mined").await;
}

/// 追いついたノードが、追いつかれた側と同じ先端を持つこと。
async fn assert_same_tip(a: &NodeHandle, b: &NodeHandle) {
    let sa = a.status().await.unwrap();
    let sb = b.status().await.unwrap();
    assert_eq!(sa.tip, sb.tip, "the tips disagree");
    assert_eq!(sa.height, sb.height, "the heights disagree");
    assert_eq!(sa.utxo_count, sb.utxo_count, "the UTXO counts disagree");
    assert_eq!(
        sa.cumulative_work, sb.cumulative_work,
        "the cumulative work disagrees"
    );
}

/// 持っていないと言われたブロックを、時間切れを待たずに別の相手へ回すこと。
///
/// 先端を知らせてくれた相手と、本体を頼む相手は同じとは限らない。**持って
/// いない相手に当たること自体は避けられない。** 避けられないなら、断られた
/// ときに直ちに回し直せなければならない。返事を無視して時間切れ (60 秒) を
/// 待つ作りだと、その間チェーンは 1 個も伸びない。ブロックは親から順にしか
/// 繋げないので、止まるのはその 1 個では済まない。
#[test]
fn a_block_the_peer_does_not_have_goes_back_to_the_queue() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (_dir_a, service_a) = start("notfound-src");
    let (_dir_b, service_b) = start("notfound-dst");
    let a = service_a.handle();
    let b = service_b.handle();

    runtime.block_on(async {
        // A で 1 個掘り、**ヘッダだけ**を B に渡す。B は本体を欲しがる。
        a.start_mining(payout(), Some(1), MiningMode::light())
            .await
            .unwrap();
        wait_for_mining(&a, 1).await;
        let tip = a.status().await.unwrap().tip;
        let block = a.block(tip).await.unwrap().expect("there is a mined block");
        let accepted = b.accept_headers(vec![block.header]).await.unwrap();
        assert_eq!(accepted.new, 1, "the header is not present");

        // 持っていないピア (7) に割り振られてしまった状況を作る。時刻は
        // 固定してよい。ここで見たいのは時間切れ**ではない**経路である。
        assert_eq!(
            b.assign_downloads(7, 0).await.unwrap(),
            vec![tip],
            "a block whose body is needed is not assigned"
        );
        assert!(
            b.assign_downloads(8, 0).await.unwrap().is_empty(),
            "an in-flight request was handed out twice"
        );

        // 7 が「持っていない」と答える。
        b.blocks_not_found(7, vec![tip]).await.unwrap();

        assert_eq!(
            b.assign_downloads(8, 0).await.unwrap(),
            vec![tip],
            "refused, yet not reassigned to another peer before the timeout"
        );
    });
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
        a.start_mining(payout(), Some(5), MiningMode::light())
            .await
            .unwrap();
        wait_for_mining(&a, 5).await;
        assert_eq!(
            b.status().await.unwrap().height,
            0,
            "B should still be empty"
        );

        // B を A に繋ぐ。
        let addr = listen(a.clone()).await;
        tokio::spawn(dial(b.clone(), addr));

        wait_for_height(&b, 5, "catch-up").await;
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

        a.start_mining(payout(), Some(3), MiningMode::light())
            .await
            .unwrap();
        wait_for_mining(&a, 3).await;

        wait_for_height(&b, 3, "relay").await;
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
        a.start_mining(payout(), Some(4), MiningMode::light())
            .await
            .unwrap();
        wait_for_mining(&a, 4).await;

        let addr = listen(a.clone()).await;
        tokio::spawn(dial(b.clone(), addr));
        wait_for_height(&b, 4, "catch-up").await;

        let sb = b.status().await.unwrap();
        // ジェネシスは報酬を受け取らないため、高さ 4 なら UTXO は 4 件。
        assert_eq!(sb.utxo_count, 4, "four coinbases become UTXOs");
        assert_eq!(sb.indexed_blocks, 5, "five including genesis");
        assert_same_tip(&a, &b).await;
    });
}

/// 先端が一致するまで待つ。
async fn wait_for_same_tip(a: &NodeHandle, b: &NodeHandle, what: &str) {
    let deadline = Instant::now() + SYNC_TIMEOUT;
    while Instant::now() < deadline {
        let sa = a.status().await.expect("the state can be read");
        let sb = b.status().await.expect("the state can be read");
        if sa.tip == sb.tip {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let sa = a.status().await.unwrap();
    let sb = b.status().await.unwrap();
    panic!(
        "{what}: the tips did not converge (A is {} at height {}, B is {} at height {})",
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
        a.start_mining(payout(), Some(3), MiningMode::light())
            .await
            .unwrap();
        b.start_mining(payout(), Some(6), MiningMode::light())
            .await
            .unwrap();
        wait_for_mining(&a, 3).await;
        wait_for_mining(&b, 6).await;

        let light = a.status().await.unwrap();
        let heavy = b.status().await.unwrap();
        assert_ne!(light.tip, heavy.tip, "they ended up mining the same chain");
        assert!(light.cumulative_work < heavy.cumulative_work);
        let abandoned = light.tip;

        // ここで繋ぐ。A は自分の 3 ブロックを捨てて B の 6 ブロックに乗る。
        let addr = listen(b.clone()).await;
        tokio::spawn(dial(a.clone(), addr));

        wait_for_height(&a, 6, "reorg").await;
        wait_for_same_tip(&a, &b, "reorg").await;
        assert_same_tip(&a, &b).await;

        let after = a.status().await.unwrap();
        assert_ne!(after.tip, abandoned, "it still holds its own branch");
        // 捨てた枝のコインベースは UTXO から消えていなければならない。
        // 残っていれば、存在しないはずの金が使える。
        assert_eq!(
            after.utxo_count, 6,
            "the coinbases of the three undone blocks are still there"
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
        a.start_mining(payout(), Some(4), MiningMode::light())
            .await
            .unwrap();
        b.start_mining(payout(), Some(4), MiningMode::light())
            .await
            .unwrap();
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
            "it gave up the tip on a tie"
        );
        assert_eq!(
            b.status().await.unwrap().tip,
            before_b.tip,
            "it gave up the tip on a tie"
        );

        // B が 1 つ積む。これで B の方が重くなる。
        b.start_mining(payout(), Some(1), MiningMode::light())
            .await
            .unwrap();
        wait_for_mining(&b, 5).await;

        // A は 4 ブロックすべてを取り消して B の枝に乗り換える。
        wait_for_height(&a, 5, "settling a tie").await;
        wait_for_same_tip(&a, &b, "settling a tie").await;
        assert_same_tip(&a, &b).await;
        assert_eq!(
            a.status().await.unwrap().utxo_count,
            5,
            "the coinbase of the undone branch is still there"
        );
    });
}

/// 送金が、繋がっている相手の mempool まで届くこと。
///
/// ブロックの中継とは別の道である。ブロックは `inv` → `getheaders` →
/// `getdata` と辿るが、トランザクションは `inv` → `getdata` → `tx` で
/// 済む。**頼んだものだけを受け取る**規則が、この道を塞いでいないことを
/// 実際に確かめる。
///
/// # なぜ 130 ブロック掘るのか
///
/// コインベースは 120 ブロック経つまで使えない。使える残高を作るには
/// それを超えて掘るしかない。regtest は難易度調整をしないので、現実的な
/// 時間で終わる。
#[test]
fn a_transaction_reaches_the_peers_mempool() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (_dir_a, service_a) = start("tx-src");
    let (_dir_b, service_b) = start("tx-dst");
    let a = service_a.handle();
    let b = service_b.handle();

    // 受け取り先の鍵は手元に残す。UTXO を引くのに要る。
    let secret = SecretKey::generate();
    let lock = Lock::from_address(&Address::from_pubkey(NETWORK, &secret.public_key()));
    let mine_to = params::COINBASE_MATURITY + 10;

    runtime.block_on(async {
        // A に成熟したコインベースができるまで掘る。B はまだ居ない。
        a.start_mining(lock.clone(), Some(mine_to), MiningMode::light())
            .await
            .unwrap();
        wait_for_height_within(&a, mine_to, "mined", MATURITY_TIMEOUT).await;

        // B を繋いで追いつかせる。
        let addr = listen(a.clone()).await;
        tokio::spawn(dial(b.clone(), addr));
        wait_for_height_within(&b, mine_to, "catch-up", MATURITY_TIMEOUT).await;

        // 使えるコインベースを 1 つ選ぶ。
        let coins = a.scan_utxos(vec![lock.clone()], 500).await.unwrap();
        let spendable = coins
            .into_iter()
            .find(|c| c.entry.height + params::COINBASE_MATURITY <= mine_to)
            .expect("there should be a mature coinbase");

        // 1 入力 1 出力。差額はそのまま手数料になる。
        let value = spendable.entry.output.amount;
        let send = Amount::from_atomic(value.to_atomic() / 2).unwrap();
        let mut tx = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput {
                prev_out: spendable.outpoint,
                signature: Vec::new(),
                sequence: SEQUENCE_FINAL,
            }],
            outputs: vec![TxOutput {
                amount: send,
                lock: lock.clone(),
            }],
            locktime: 0,
        };
        let spent = vec![spendable.entry.output.clone()];
        let msg = sighash(&tx, &spent, 0, SighashType::DEFAULT).unwrap();
        tx.inputs[0].signature = secret.sign(&msg).to_bytes().to_vec();
        let txid = tx.txid();

        // A に入れる。ここを通った時点で検証は済んでいる。
        let accepted = a.submit_tx(tx).await.expect("A accepts it");
        assert_eq!(accepted, txid);

        // B の mempool に届くまで待つ。
        let deadline = Instant::now() + SYNC_TIMEOUT;
        loop {
            if b.mempool_txids().await.unwrap().contains(&txid) {
                break;
            }
            assert!(Instant::now() < deadline, "it did not reach B's mempool");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // B は中身も持っている。ハッシュだけ知らされて終わりではない。
        let got = b
            .mempool_tx(txid)
            .await
            .unwrap()
            .expect("B holds the object");
        assert_eq!(got.txid(), txid);
        // A も手放していない。
        assert!(a.mempool_txids().await.unwrap().contains(&txid));
    });
}

/// 頼んでいないトランザクションは、検証せずに断ること。
///
/// 署名の検証は高い計算である。**頼んだ覚えのないものを検証するのは、
/// 相手に計算を命じられているのと変わらない。** ここが開いていると、
/// 繋がっただけの相手が、こちらの CPU を好きなだけ使える。
///
/// 中身が正しいかどうかは関係ない。**頼んでいないという一点で断る。**
#[test]
fn an_unrequested_transaction_is_refused_without_being_verified() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (_dir, service) = start("tx-unsolicited");
    let node = service.handle();

    runtime.block_on(async {
        // 中身は何でもよい。どうせ検証まで行かない。
        let tx = Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput {
                prev_out: oag_consensus::tx::OutPoint::new(oag_primitives::Hash::ZERO, 0),
                signature: vec![0u8; 64],
                sequence: SEQUENCE_FINAL,
            }],
            outputs: vec![TxOutput {
                amount: Amount::from_oag(1).unwrap(),
                lock: Lock::from_address(&Address::from_pubkey(
                    NETWORK,
                    &SecretKey::generate().public_key(),
                )),
            }],
            locktime: 0,
        };

        // ピアから来たことにする。誰もこれを頼んでいない。
        let refused = node.submit_tx_from(tx.clone(), Some(1)).await;
        assert!(refused.is_err(), "something unrequested was accepted");

        // 自分で出したものは、この規則の対象外である。財布からの送金が
        // 塞がれては困る。こちらは中身が駄目なので別の理由で落ちる。
        let own = node.submit_tx(tx).await;
        assert!(own.is_err(), "these contents should fail validation");
        assert_ne!(
            own.unwrap_err(),
            refused.unwrap_err(),
            "if the reason for refusing is the same, it is no proof that validation was skipped"
        );
    });
}

/// 受け取ったブロックを、**くれた相手以外へ中継すること**。
///
/// 2 台の試験では、掘った側が自分の相手へ知らせるところまでしか見ていない。
/// **繋がっていない相手へ届くかどうかは、間に 1 台挟まないと分からない。**
/// ここが動いていなければ、ネットワークは直接繋がった組でしか揃わない。
///
/// ```text
/// A ── B ── C        A と C は互いを知らない
/// ```
///
/// A が掘り、C が持てば中継が働いている。
#[test]
fn a_block_travels_to_a_node_that_is_not_directly_connected() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let (_dir_a, service_a) = start("relay-miner");
    let (_dir_b, service_b) = start("relay-middle");
    let (_dir_c, service_c) = start("relay-far");
    let a = service_a.handle();
    let b = service_b.handle();
    let c = service_c.handle();

    runtime.block_on(async {
        // B だけが待ち受ける。A と C は B にしか繋がない。互いの住所を
        // 教えていないうえ、外向きの接続を回す仕掛けも動かしていないので、
        // A と C が直接繋がることはない。
        let b_addr = listen(b.clone()).await;
        tokio::spawn(dial(a.clone(), b_addr));
        tokio::spawn(dial(c.clone(), b_addr));

        // まず 1 個掘って、3 台が繋がって揃うのを待つ。ここを踏まずに
        // 掘ると、C が後から繋いで初期同期で追いついただけでも通って
        // しまい、中継を見たことにならない。
        a.start_mining(payout(), Some(1), MiningMode::light())
            .await
            .unwrap();
        wait_for_mining(&a, 1).await;
        wait_for_height(&c, 1, "initial sync").await;

        // ここから先が中継である。C はすでに繋がっていて揃っており、
        // 取りに行く理由がない。**B が知らせなければ届かない。**
        a.start_mining(payout(), Some(2), MiningMode::light())
            .await
            .unwrap();
        wait_for_mining(&a, 3).await;
        wait_for_height(&c, 3, "relay").await;

        assert_same_tip(&a, &c).await;
        assert_same_tip(&b, &c).await;
    });
}
