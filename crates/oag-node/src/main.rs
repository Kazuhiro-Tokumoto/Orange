//! Orange (OAG) のノード。

#![forbid(unsafe_code)]
#![warn(clippy::all)]

mod genesis;
mod node;

use clap::{Parser, Subcommand};
use node::{MinedBlock, Node};
use oag_consensus::lock::Lock;
use oag_primitives::{Address, Network, SecretKey};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
        } => {
            let network = common.network()?;
            let mut node = Node::open(network, &common.datadir).map_err(|e| e.to_string())?;
            let status = node.status().map_err(|e| e.to_string())?;
            println!(
                "{} を {} で開いた (高さ {}、次の難易度 {})",
                common.datadir.display(),
                network,
                status.height,
                status.next_difficulty
            );

            if !mine {
                println!("採掘は無効。--mine を付けると掘る。");
                print_status(&node)?;
                return Ok(());
            }

            let text = payout.ok_or("--mine には --payout が必要である")?;
            let address = Address::decode_on(network, &text)
                .map_err(|e| format!("受取先アドレスが不正: {e}"))?;
            let lock = Lock::from_address(&address);
            println!("報酬の受取先: {address}");
            println!("採掘を開始する (Ctrl-C で中断してよい)");

            let mut mined = 0u64;
            loop {
                match node
                    .mine_next(&lock, now(), 200_000)
                    .map_err(|e| e.to_string())?
                {
                    MinedBlock::Accepted {
                        hash,
                        height,
                        attempts,
                    } => {
                        mined += 1;
                        println!("高さ {height}  {hash}  ({attempts} 回)");
                        if blocks.is_some_and(|limit| mined >= limit) {
                            break;
                        }
                    }
                    MinedBlock::NotFound { attempts } => {
                        println!("{attempts} 回試したが見つからず。続ける。");
                    }
                }
            }
            print_status(&node)?;
            Ok(())
        }
        Command::Info { common } => {
            let network = common.network()?;
            let node = Node::open(network, &common.datadir).map_err(|e| e.to_string())?;
            print_status(&node)
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

fn print_status(node: &Node) -> Result<(), String> {
    let s = node.status().map_err(|e| e.to_string())?;
    println!("  ネットワーク    {}", s.network);
    println!("  高さ            {}", s.height);
    println!("  先端            {}", s.tip);
    println!("  累積作業量      {}", s.cumulative_work);
    println!("  次の難易度      {}", s.next_difficulty);
    println!("  UTXO 件数       {}", s.utxo_count);
    println!("  知っているブロック {}", s.indexed_blocks);
    println!("  mempool         {}", s.mempool_len);
    Ok(())
}
