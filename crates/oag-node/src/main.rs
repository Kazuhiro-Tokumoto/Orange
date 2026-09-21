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
#[command(name = "oag-node", about = "the Orange (OAG) node", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

// `Run` は旗の入れ物であり、他の枝より大きい。**起動時に 1 個しか
// 作らない**ので、箱に入れて間接参照を増やす意味が無い。
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    /// Run the node.
    Run {
        #[command(flatten)]
        common: Common,
        /// Mine. Requires `--payout`.
        ///
        /// **Off by default.** Without it, the node simply validates and relays
        /// blocks. Validation only needs light mode (256 MB), so a machine
        /// without 2 GB to spare is fine.
        #[arg(long)]
        mine: bool,
        /// Mine in fast mode (2 GB). Faster than light mode.
        ///
        /// Building the dataset takes about a minute. If 2 GB cannot be
        /// allocated, it continues in light mode. **Validation is always light.**
        ///
        /// How much faster depends on the machine. To measure locally:
        /// `cargo run --release -p oag-pow --features randomx --example hashrate`
        #[arg(long)]
        fast: bool,
        /// How many threads to mine with. Default 1. `0` matches the core count.
        ///
        /// **More threads means more memory.** A RandomX miner cannot cross
        /// threads, so each builds its own: 256 MB per thread in light mode and
        /// 2 GB per thread in fast mode.
        ///
        /// Passing `0` still gives one thread in fast mode, so it does not go
        /// allocating 2 GB per core without knowing how much memory there is.
        #[arg(long, default_value_t = 1)]
        mining_threads: usize,
        /// The address the reward is paid to.
        #[arg(long)]
        payout: Option<String>,
        /// Stop after mining this many. Without it, it does not stop.
        #[arg(long)]
        blocks: Option<u64>,
        /// The address to listen on. Defaults to the network's P2P port.
        #[arg(long)]
        listen: Option<SocketAddr>,
        /// Do not listen.
        #[arg(long)]
        no_listen: bool,
        /// Peers to dial. May be given more than once.
        ///
        /// Peers named here are redialled whenever the connection drops. They are
        /// counted separately from peers chosen out of the address book.
        #[arg(long, value_name = "address")]
        connect: Vec<SocketAddr>,
        /// The address to announce to peers (the externally visible `host:port`).
        ///
        /// **Without this, our address reaches nobody.** Pass it on a node that
        /// wants inbound connections (a seed node, for instance). There is no way
        /// for a node to determine its own external address reliably, so the
        /// operator states it.
        #[arg(long, value_name = "address")]
        external_addr: Vec<SocketAddr>,
        /// Do not discover peers automatically from the address book or the seed.
        ///
        /// Connect only to the peers named with `--connect`.
        #[arg(long)]
        no_discovery: bool,
        /// The address to serve RPC on. Defaults to the loopback RPC port.
        #[arg(long)]
        rpc: Option<SocketAddr>,
        /// Do not serve RPC.
        #[arg(long)]
        no_rpc: bool,
        /// Build the transaction index and the address index.
        ///
        /// **Off by default.** Consensus does not need it (`docs/SPEC.md` §19), and
        /// a year of full blocks would need 37 GB.
        /// With it, `getrawtransaction` can look up confirmed transactions, and
        /// `getaddresshistory` and the explorer become available.
        ///
        /// The first run scans the whole chain. After that the index updates inside
        /// the same transaction as connecting a block, so it never needs a rebuild.
        #[arg(long)]
        index: bool,
        /// Drop the index. Cannot be combined with `--index`.
        #[arg(long, conflicts_with = "index")]
        drop_index: bool,
        /// The address to serve the explorer on. Defaults to `127.0.0.1:8080`.
        ///
        /// **It is read-only.** It cannot send coins or change settings. It needs
        /// the index, so passing it implies `--index`.
        ///
        /// Binding to anything but loopback makes it visible externally. The
        /// contents are public, but it does reveal that your node is running.
        #[arg(long, value_name = "address", num_args = 0..=1,
              default_missing_value = "127.0.0.1:8080")]
        explorer: Option<SocketAddr>,
        /// The address to serve the browser wallet on. Default `127.0.0.1:25565`.
        ///
        /// **Signing finishes inside the browser.** Neither the seed nor any private
        /// key reaches the node; this interface accepts only signed transactions.
        /// It needs the index, so passing it implies `--index`.
        ///
        /// It is deliberately **a different interface from the explorer**. Browser
        /// storage is partitioned per port, so a hole in one cannot read the
        /// other's records.
        ///
        /// To bind to anything but loopback, supply a certificate with `--tls-cert`
        /// and `--tls-key`. **A page served in plaintext can be swapped out**, and
        /// a swapped page lifts the keys as they are.
        #[arg(long, value_name = "address", num_args = 0..=1,
              default_missing_value = "127.0.0.1:25565")]
        wallet: Option<SocketAddr>,
        /// The certificate (PEM) for the wallet interface. Pass with `--tls-key`.
        ///
        /// A certificate is public; the key is the secret one.
        /// **It is read once at startup.** Restart after renewing it.
        #[arg(long, value_name = "path", requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// The private key (PEM) for the wallet interface. Pass with `--tls-cert`.
        #[arg(long, value_name = "path", requires = "tls_cert")]
        tls_key: Option<PathBuf>,
        /// Exit this many seconds after mining and connections have finished.
        ///
        /// For testing. Without it, it does not exit.
        #[arg(long)]
        exit_after: Option<u64>,
    },
    /// Show the current state.
    Info {
        #[command(flatten)]
        common: Common,
    },
    /// Create a key and print the address.
    Keygen {
        /// The target network.
        #[arg(long, default_value = "regtest")]
        network: String,
        /// Where to write the private key.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Write the active chain's blocks out to files.
    ExportBlocks {
        #[command(flatten)]
        common: Common,
        /// The directory to write into.
        #[arg(long, default_value = "./block")]
        out: PathBuf,
    },
}

#[derive(clap::Args)]
struct Common {
    /// The target network: mainnet / testnet / regtest.
    #[arg(long, default_value = "regtest")]
    network: String,
    /// The directory the data lives in.
    #[arg(long, default_value = "./oag-data")]
    datadir: PathBuf,
}

impl Common {
    fn network(&self) -> Result<Network, String> {
        self.network
            .parse()
            .map_err(|_| format!("unknown network: {}", self.network))
    }
}

fn main() {
    if let Err(message) = run() {
        eprintln!("error: {message}");
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
                        .map_err(|e| format!("the payout address is invalid: {e}"))?,
                )),
                (true, None) => return Err("--mine requires --payout".to_string()),
                (false, _) => None,
            };

            let service =
                NodeService::start(network, &common.datadir).map_err(|e| e.to_string())?;
            let handle = service.handle();

            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("cannot start tokio: {e}"))?;

            runtime.block_on(async {
                let status = handle.status().await?;
                println!(
                    "opened {} on {} (height {}, next difficulty {})",
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
                        .map_err(|e| format!("cannot listen on {addr}: {e}"))?;
                    let bound = listener.local_addr().map_err(|e| e.to_string())?;
                    println!("listening on {bound}");
                    tokio::spawn(accept_loop(handle.clone(), listener));
                }

                if drop_index {
                    handle.drop_index().await?;
                    println!("dropped the index");
                }

                // エクスプローラは索引に頼る。無いまま開いても取引と
                // アドレスが引けないので、暗黙に作る。
                if index || explorer.is_some() || wallet.is_some() {
                    match handle.index_from().await? {
                        Some(0) => println!("the index already exists"),
                        _ => {
                            println!("building the index (scanning the whole chain)");
                            let stats = handle.build_index().await?;
                            println!(
                                "built the index: {} blocks, {} transactions, {} address entries",
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
                    println!("explorer open at http://{bound}/");
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
                            "{addr} is reachable from outside this machine. Serving the wallet\n\
                             page in plaintext means a user cannot tell when it has been\n\
                             swapped out in transit, and a swapped page lifts the seed as it is.\n\
                             To expose it, pass --tls-cert and --tls-key.\n\
                             For local experimentation, --wallet 127.0.0.1:{} is enough.",
                            addr.port()
                        ));
                    }
                    let scheme = if tls.is_some() { "https" } else { "http" };
                    let bound = oag_node::wallet::start_wallet(handle.clone(), addr, tls).await?;
                    println!("wallet open at {scheme}://{bound}/");
                }

                if !external_addr.is_empty() {
                    for addr in &external_addr {
                        println!("announcing {addr} as our own address");
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
                    println!("starting to mine (Ctrl-C to interrupt)");
                    let mode = MiningMode {
                        fast,
                        threads: mining_threads,
                    };
                    handle.start_mining(lock, blocks, mode).await?;
                }

                wait_for_shutdown(&handle, blocks.is_some(), exit_after).await;
                // 覚えた住所を残す。次の起動でシードを引かずに済む。
                if let Err(e) = handle.save_addresses().await {
                    eprintln!("cannot write out the address book: {e}");
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
                .map_err(|_| format!("unknown network: {network}"))?;
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
                    .map_err(|e| format!("cannot write to {}: {e}", path.display()))?;
                println!("wrote the private key to {}", path.display());
                println!("losing this file means the funds cannot be recovered.");
            } else {
                println!("(pass --out to write the private key to a file)");
            }
            Ok(())
        }
        Command::ExportBlocks { common, out } => {
            let network = common.network()?;
            let node = Node::open(network, &common.datadir).map_err(|e| e.to_string())?;
            let count = node.export_blocks(&out).map_err(|e| e.to_string())?;
            println!("wrote {count} blocks to {}", out.display());
            Ok(())
        }
    }
}

/// Wait until it finishes.
///
/// Ctrl-C ends it. With a mining limit, it also ends when that is reached.
/// With `exit_after`, it then waits that many more seconds (the grace
/// period for handing what was mined to peers).
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
        _ = tokio::signal::ctrl_c() => println!("interrupt received"),
        _ = mining_done => println!("mined the requested number of blocks"),
    }

    if let Some(secs) = exit_after {
        println!("exiting after {secs} seconds");
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
    println!("  network          {}", s.network);
    println!("  height           {}", s.height);
    println!("  tip              {}", s.tip);
    println!("  cumulative work  {}", s.cumulative_work);
    println!("  next difficulty  {}", s.next_difficulty);
    println!("  UTXO count       {}", s.utxo_count);
    println!("  blocks known     {}", s.indexed_blocks);
    println!("  mempool         {}", s.mempool_len);
    println!("  peers known      {}", s.known_addresses);
}
