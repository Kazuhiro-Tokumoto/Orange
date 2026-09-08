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
        #[arg(long, value_name = "住所")]
        connect: Vec<SocketAddr>,
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
    /// 対象ネットワーク。現在起動できるのは regtest のみ。
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
            payout,
            blocks,
            listen,
            no_listen,
            connect,
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
                NodeService::start(network, &common.datadir, blocks).map_err(|e| e.to_string())?;
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

                for addr in connect {
                    tokio::spawn(dial(handle.clone(), addr));
                }

                if let Some(lock) = payout {
                    println!("採掘を開始する (Ctrl-C で中断してよい)");
                    handle.start_mining(lock).await?;
                }

                wait_for_shutdown(&handle, blocks.is_some(), exit_after).await;
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
}
