//! Orange (OAG) のノード。

#![forbid(unsafe_code)]
#![warn(clippy::all)]

use clap::{Parser, Subcommand};
use oag_consensus::lock::Lock;
use oag_net::magic::magic_for;
use oag_net::transport::Listener;
use oag_node::node::{self, Node};
use oag_node::service::{NodeEvent, NodeHandle, NodeService};
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

#[derive(Subcommand)]
enum Command {
    /// ノードを動かす。
    Run {
        #[command(flatten)]
        common: Common,
        /// 採掘する。`--payout` が必要。
        #[arg(long)]
        mine: bool,
        /// 採掘に fast モード (2 GB) を使う。light モードのおよそ 6 倍速い。
        ///
        /// データセットの構築に 1 分前後かかる。2 GB を確保できなければ
        /// light モードで続ける。**検証は常に light モードで行う。**
        #[arg(long)]
        fast: bool,
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
            external_addr,
            no_discovery,
            payout,
            blocks,
            listen,
            no_listen,
            connect,
            rpc,
            no_rpc,
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

                if !no_rpc {
                    let addr = rpc.unwrap_or_else(|| {
                        SocketAddr::new(network.rpc_bind_default(), network.rpc_port())
                    });
                    oag_node::start_rpc(handle.clone(), addr, &common.datadir).await?;
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
                    handle.start_mining(lock, blocks, fast).await?;
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
