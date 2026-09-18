//! Orange (OAG) のノード。

#![forbid(unsafe_code)]
#![warn(clippy::all)]

use clap::{Parser, Subcommand};
use oag_consensus::lock::Lock;
use oag_net::magic::magic_for;
use oag_net::transport::Listener;
use oag_node::node::{self, Node};
use oag_node::service::{MiningMode, NodeEvent, NodeHandle, NodeService};
use oag_node::{accept_loop, dial};
use oag_primitives::{Address, Network, SecretKey};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "oag-node", about = "Orange (OAG) のノード", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

// `Run` は旗の入れ物であり、他の枝より大きい。**起動時に 1 個しか
// 作らない**ので、箱に入れて間接参照を増やす意味が無い。
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    /// ノードを動かす。
    Run {
        #[command(flatten)]
        common: Common,
        /// 採掘する。`--payout` が必要。
        ///
        /// **既定では掘らない。** これを付けなければ、ブロックを検証して
        /// 中継するだけのノードとして動く。検証は light モード (256 MB)
        /// だけで済むので、2 GB を積んでいない機械でも構わない。
        #[arg(long)]
        mine: bool,
        /// 採掘に fast モード (2 GB) を使う。light モードより速い。
        ///
        /// データセットの構築に 1 分前後かかる。2 GB を確保できなければ
        /// light モードで続ける。**検証は常に light モードで行う。**
        ///
        /// 何倍速いかは機械による。手元で測るには
        /// `cargo run --release -p oag-pow --features randomx --example hashrate`
        #[arg(long)]
        fast: bool,
        /// 何スレッドで掘るか。既定は 1。`0` なら機械のコア数に合わせる。
        ///
        /// **スレッドを増やすと memory も増える。** RandomX の採掘器は
        /// スレッドをまたげないので、1 本ごとに自分の分を建てる。light
        /// モードで 1 本 256 MB、fast モードで 1 本 2 GB である。
        ///
        /// `0` を渡しても fast モードでは 1 本のままにする。積んでいる
        /// memory が分からないのに 2 GB ずつ確保しにいかないためである。
        #[arg(long, default_value_t = 1)]
        mining_threads: usize,
        /// 報酬の受取先アドレス。
        #[arg(long)]
        payout: Option<String>,
        /// この数だけ掘ったら止める。省略すると止まらない。
        #[arg(long)]
        blocks: Option<u64>,
        /// 待ち受ける住所。既定はネットワークごとの P2P ポート。
        #[arg(long)]
        listen: Option<SocketAddr>,
        /// 待ち受けない。
        #[arg(long)]
        no_listen: bool,
        /// 接続しにいく相手。複数指定してよい。
        ///
        /// ここで名指しした相手は、切れていれば繋ぎ直す。住所帳から
        /// 選ばれる相手とは別枠である。
        #[arg(long, value_name = "住所")]
        connect: Vec<SocketAddr>,
        /// ピアに名乗る自分の住所 (外から見える `ホスト:ポート`)。
        ///
        /// **これを渡さないと、こちらの住所は誰にも伝わらない。** 外から
        /// 繋いでもらいたいノード (シードに載せるノードなど) では渡す。
        /// 自分の外向きの住所を自分で確かめる手立ては無いので、運用者が
        /// 明示する。
        #[arg(long, value_name = "住所")]
        external_addr: Vec<SocketAddr>,
        /// 住所帳とシードによる繋ぎ先の自動探索を行わない。
        ///
        /// `--connect` で名指しした相手だけに繋ぐ。
        #[arg(long)]
        no_discovery: bool,
        /// RPC を待ち受ける住所。既定はループバックの RPC ポート。
        #[arg(long)]
        rpc: Option<SocketAddr>,
        /// RPC を待ち受けない。
        #[arg(long)]
        no_rpc: bool,
        /// 取引索引とアドレス索引を作る。
        ///
        /// **既定では作らない。** コンセンサスはこれを必要とせず
        /// (`docs/SPEC.md` §19)、満杯のブロックが続けば年 37 GB を要する。
        /// 作ると `getrawtransaction` が確定した取引も引けるようになり、
        /// `getaddresshistory` とエクスプローラが使えるようになる。
        ///
        /// 初回は鎖全体を走査する。索引は以後、ブロックの接続と同じ
        /// トランザクションの中で更新されるので、組み直す必要はない。
        #[arg(long)]
        index: bool,
        /// 索引を捨てる。`--index` と同時には指定できない。
        #[arg(long, conflicts_with = "index")]
        drop_index: bool,
        /// エクスプローラを待ち受ける住所。既定は `127.0.0.1:8080`。
        ///
        /// **読むだけの口である。** 送金も設定変更もできない。索引が要る
        /// ので、渡すと `--index` も指定したものとして扱う。
        ///
        /// ループバック以外を指定すると外から見えるようになる。中身は
        /// 公開情報だが、自分のノードが動いていること自体を晒すことになる。
        #[arg(long, value_name = "住所", num_args = 0..=1,
              default_missing_value = "127.0.0.1:8080")]
        explorer: Option<SocketAddr>,
        /// ブラウザのウォレットを待ち受ける住所。既定は `127.0.0.1:25565`。
        ///
        /// **署名はブラウザの中で終わる。** 種も秘密鍵もノードへは渡らず、
        /// この口が受け取るのは署名済みのトランザクションだけである。
        /// 索引が要るので、渡すと `--index` も指定したものとして扱う。
        ///
        /// エクスプローラとは**別の口にしてある**。ブラウザの保存領域は
        /// ポートごとに仕切られるため、片方に穴があってももう片方の
        /// 記録は読めない。
        ///
        /// ループバック以外を指定するには、`--tls-cert` と `--tls-key` で
        /// 証明書を渡すこと。**平文で配った画面は差し替えられる。**
        /// 差し替えられた画面は鍵をそのまま抜き取れる。
        #[arg(long, value_name = "住所", num_args = 0..=1,
              default_missing_value = "127.0.0.1:25565")]
        wallet: Option<SocketAddr>,
        /// ウォレットの口に使う証明書 (PEM)。`--tls-key` と対で渡す。
        ///
        /// 証明書は公開してよいものであり、秘密なのは鍵の方である。
        /// **中身は起動時に一度だけ読む。** 更新したら再起動すること。
        #[arg(long, value_name = "経路", requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// ウォレットの口に使う秘密鍵 (PEM)。`--tls-cert` と対で渡す。
        #[arg(long, value_name = "経路", requires = "tls_cert")]
        tls_key: Option<PathBuf>,
        /// 採掘も接続も終わったら、この秒数で終了する。
        ///
        /// 試験のためのもの。省略すると終了しない。
        #[arg(long)]
        exit_after: Option<u64>,
    },
    /// 現在の様子を表示する。
    Info {
        #[command(flatten)]
        common: Common,
    },
    /// 鍵を作り、アドレスを表示する。
    Keygen {
        /// 対象ネットワーク。
        #[arg(long, default_value = "regtest")]
        network: String,
        /// 秘密鍵の書き出し先。
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// アクティブチェーンのブロックをファイルに書き出す。
    ExportBlocks {
        #[command(flatten)]
        common: Common,
        /// 書き出し先のディレクトリ。
        #[arg(long, default_value = "./block")]
        out: PathBuf,
    },
}

#[derive(clap::Args)]
struct Common {
    /// 対象ネットワーク。mainnet / testnet / regtest。
    #[arg(long, default_value = "regtest")]
    network: String,
    /// データを置くディレクトリ。
    #[arg(long, default_value = "./oag-data")]
    datadir: PathBuf,
}

impl Common {
    fn network(&self) -> Result<Network, String> {
        self.network
            .parse()
            .map_err(|_| format!("知らないネットワーク: {}", self.network))
    }
}

fn main() {
    if let Err(message) = run() {
        eprintln!("エラー: {message}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::Run {
            common,
            mine,
            fast,
            mining_threads,
            external_addr,
            no_discovery,
            payout,
            blocks,
            listen,
            no_listen,
            connect,
            rpc,
            no_rpc,
            index,
            drop_index,
            explorer,
            wallet,
            tls_cert,
            tls_key,
            exit_after,
        } => {
            let network = common.network()?;
            // 受取先は、記憶域を開く前に確かめる。開いてから断るのは無駄である。
            let payout = match (mine, payout) {
                (true, Some(text)) => Some(Lock::from_address(
                    &Address::decode_on(network, &text)
                        .map_err(|e| format!("受取先アドレスが不正: {e}"))?,
                )),
                (true, None) => return Err("--mine には --payout が必要である".to_string()),
                (false, _) => None,
            };

            let service =
                NodeService::start(network, &common.datadir).map_err(|e| e.to_string())?;
            let handle = service.handle();

            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("tokio を起こせない: {e}"))?;

            runtime.block_on(async {
                let status = handle.status().await?;
                println!(
                    "{} を {} で開いた (高さ {}、次の難易度 {})",
                    common.datadir.display(),
                    network,
                    status.height,
                    status.next_difficulty
                );

                if !no_listen {
                    let addr = listen.unwrap_or_else(|| {
                        SocketAddr::new(network.p2p_bind_default(), network.p2p_port())
                    });
                    let listener = Listener::bind(magic_for(network), addr)
                        .await
                        .map_err(|e| format!("{addr} で待ち受けられない: {e}"))?;
                    let bound = listener.local_addr().map_err(|e| e.to_string())?;
                    println!("{bound} で待ち受ける");
                    tokio::spawn(accept_loop(handle.clone(), listener));
                }

                if drop_index {
                    handle.drop_index().await?;
                    println!("索引を捨てた");
                }

                // エクスプローラは索引に頼る。無いまま開いても取引と
                // アドレスが引けないので、暗黙に作る。
                if index || explorer.is_some() || wallet.is_some() {
                    match handle.index_from().await? {
                        Some(0) => println!("索引は既にある"),
                        _ => {
                            println!("索引を作る (鎖全体を走査する)");
                            let stats = handle.build_index().await?;
                            println!(
                                "索引を作った: ブロック {} 件、取引 {} 件、アドレス項目 {} 件",
                                stats.blocks, stats.transactions, stats.addr_entries
                            );
                        }
                    }
                }

                if !no_rpc {
                    let addr = rpc.unwrap_or_else(|| {
                        SocketAddr::new(network.rpc_bind_default(), network.rpc_port())
                    });
                    oag_node::start_rpc(handle.clone(), addr, &common.datadir).await?;
                }

                if let Some(addr) = explorer {
                    let bound = oag_node::explorer::start_explorer(handle.clone(), addr).await?;
                    println!("エクスプローラを http://{bound}/ で開いた");
                }

                if let Some(addr) = wallet {
                    let tls = match (&tls_cert, &tls_key) {
                        (Some(cert), Some(key)) => Some(oag_node::wallet::load_tls(cert, key)?),
                        // clap の `requires` が片方だけを弾く。
                        _ => None,
                    };
                    // **平文のまま外へ出させない。** 通信路は署名が守るが、
                    // 画面を配る線は何も守らない。差し替えられた画面は
                    // 本物と見分けが付かないまま鍵を抜き取れる。
                    if tls.is_none() && !addr.ip().is_loopback() {
                        return Err(format!(
                            "{addr} は手元の機械の外から届く。ウォレットの画面を\n\
                             平文で配ると、途中で差し替えられても利用者には分からない。\n\
                             差し替えられた画面は種をそのまま持ち出せる。\n\
                             外に出すなら --tls-cert と --tls-key を渡すこと。\n\
                             手元で試すだけなら --wallet 127.0.0.1:{} で足りる。",
                            addr.port()
                        ));
                    }
                    let scheme = if tls.is_some() { "https" } else { "http" };
                    let bound = oag_node::wallet::start_wallet(handle.clone(), addr, tls).await?;
                    println!("ウォレットを {scheme}://{bound}/ で開いた");
                }

                if !external_addr.is_empty() {
                    for addr in &external_addr {
                        println!("自分の住所として {addr} を名乗る");
                    }
                    handle.set_own_addresses(external_addr).await?;
                }

                if no_discovery {
                    // 名指しされた相手だけに繋ぐ。住所帳もシードも使わない。
                    for addr in connect {
                        tokio::spawn(dial(handle.clone(), addr));
                    }
                } else {
                    let outbound = oag_node::connect::Outbound::new();
                    tokio::spawn(oag_node::connect::maintain(
                        handle.clone(),
                        outbound,
                        connect,
                    ));
                }

                if let Some(lock) = payout {
                    println!("採掘を開始する (Ctrl-C で中断してよい)");
                    let mode = MiningMode {
                        fast,
                        threads: mining_threads,
                    };
                    handle.start_mining(lock, blocks, mode).await?;
                }

                wait_for_shutdown(&handle, blocks.is_some(), exit_after).await;
                // 覚えた住所を残す。次の起動でシードを引かずに済む。
                if let Err(e) = handle.save_addresses().await {
                    eprintln!("住所帳を書き出せない: {e}");
                }
                print_status(&handle).await
            })?;
            Ok(())
        }
        Command::Info { common } => {
            let network = common.network()?;
            let node = Node::open(network, &common.datadir).map_err(|e| e.to_string())?;
            print_node_status(&node)
        }
        Command::Keygen { network, out } => {
            let network: Network = network
                .parse()
                .map_err(|_| format!("知らないネットワーク: {network}"))?;
            let secret = SecretKey::generate();
            let address = Address::from_pubkey(network, &secret.public_key());
            println!("{address}");
            if let Some(path) = out {
                let hex: String = secret
                    .to_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                std::fs::write(&path, format!("{hex}\n"))
                    .map_err(|e| format!("{} に書けない: {e}", path.display()))?;
                println!("秘密鍵を {} に書き出した", path.display());
                println!("このファイルを失うと資金は取り戻せない。");
            } else {
                println!("(--out を付けると秘密鍵をファイルに書き出す)");
            }
            Ok(())
        }
        Command::ExportBlocks { common, out } => {
            let network = common.network()?;
            let node = Node::open(network, &common.datadir).map_err(|e| e.to_string())?;
            let count = node.export_blocks(&out).map_err(|e| e.to_string())?;
            println!("{count} 個のブロックを {} に書き出した", out.display());
            Ok(())
        }
    }
}

/// 終わるまで待つ。
///
/// Ctrl-C で終わる。採掘に上限があるなら、掘り終えたときにも終わる。
/// `exit_after` を指定した場合は、そこからさらにその秒数だけ待つ
/// (掘ったものを相手に配る猶予である)。
async fn wait_for_shutdown(handle: &NodeHandle, mining_limited: bool, exit_after: Option<u64>) {
    let mut events = handle.subscribe();
    let mining_done = async {
        if !mining_limited {
            // 採掘に上限が無いなら、この道では終わらない。
            std::future::pending::<()>().await;
        }
        loop {
            match events.recv().await {
                Ok(NodeEvent::MiningStopped) => return,
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => println!("中断を受け取った"),
        _ = mining_done => println!("指定した数だけ掘り終えた"),
    }

    if let Some(secs) = exit_after {
        println!("{secs} 秒待ってから終了する");
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
    }
}

async fn print_status(handle: &NodeHandle) -> Result<(), String> {
    let s = handle.status().await?;
    print_status_lines(&s);
    Ok(())
}

fn print_node_status(node: &Node) -> Result<(), String> {
    let s = node.status().map_err(|e| e.to_string())?;
    print_status_lines(&s);
    Ok(())
}

fn print_status_lines(s: &node::NodeStatus) {
    println!("  ネットワーク    {}", s.network);
    println!("  高さ            {}", s.height);
    println!("  先端            {}", s.tip);
    println!("  累積作業量      {}", s.cumulative_work);
    println!("  次の難易度      {}", s.next_difficulty);
    println!("  UTXO 件数       {}", s.utxo_count);
    println!("  知っているブロック {}", s.indexed_blocks);
    println!("  mempool         {}", s.mempool_len);
    println!("  知っているピア  {}", s.known_addresses);
}
