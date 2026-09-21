//! Orange (OAG) のウォレット。
//!
//! ノードとは JSON-RPC でしか話さない。**秘密鍵はノードに渡らない。**
//! 署名はここで済ませ、出来上がったものだけを `sendrawtransaction` で
//! 投げる。

#![forbid(unsafe_code)]
#![warn(clippy::all)]

use clap::{Parser, Subcommand};
use oag_consensus::codec::{Decode, Encode};
use oag_consensus::lock::Lock;
use oag_consensus::params;
use oag_consensus::{Transaction, TxOutput};
use oag_primitives::{Address, Amount, Hash, Network};
use oag_rpc::auth::read_cookie;
use oag_rpc::client::Client;
use oag_wallet::bip39::Mnemonic;
use oag_wallet::build::{build, consolidate, sign, Coin, Consolidate, Spend};
use oag_wallet::keystore::{Keystore, MIN_PASSPHRASE_LEN};
use oag_wallet::pst::Pst;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

#[derive(Parser)]
#[command(name = "oag-wallet", about = "the Orange (OAG) wallet", version)]
struct Cli {
    #[command(flatten)]
    common: Common,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct Common {
    /// The target network.
    #[arg(long, global = true, default_value = "regtest")]
    network: String,
    /// The wallet file.
    #[arg(long, global = true, default_value = "./wallet.json")]
    wallet: PathBuf,
    /// The node's data directory. The RPC cookie is read from here.
    #[arg(long, global = true, default_value = "./oag-data")]
    datadir: PathBuf,
    /// The node's RPC address. Defaults to the loopback RPC port.
    #[arg(long, global = true)]
    rpc: Option<SocketAddr>,
    /// A file holding the passphrase.
    ///
    /// Without it, you are asked in the terminal. **It cannot be passed on the
    /// command line**, because arguments are visible to other users via the process list.
    #[arg(long, global = true, value_name = "path")]
    passphrase_file: Option<PathBuf>,
}

/// How to obtain the BIP39 optional passphrase.
///
/// **The default is the empty string.** Not using one is normal; only
/// those who decide to use one state it.
#[derive(clap::Args)]
struct MnemonicPassphrase {
    /// Ask for the BIP39 optional passphrase in the terminal.
    #[arg(long)]
    mnemonic_passphrase: bool,
    /// A file holding the BIP39 optional passphrase.
    #[arg(long, value_name = "path", conflicts_with = "mnemonic_passphrase")]
    mnemonic_passphrase_file: Option<PathBuf>,
}

impl MnemonicPassphrase {
    /// Obtain the optional passphrase.
    ///
    /// With `confirm` true it asks twice and compares. **A typo does not surface
    /// as a failure**, so it is always confirmed when creating.
    fn get(&self, confirm: bool) -> Result<Zeroizing<String>, String> {
        if let Some(path) = &self.mnemonic_passphrase_file {
            let mut text = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let value = Zeroizing::new(text.trim_end_matches(['\n', '\r']).to_string());
            text.zeroize();
            return Ok(value);
        }
        if !self.mnemonic_passphrase {
            return Ok(Zeroizing::new(String::new()));
        }
        let first =
            Zeroizing::new(read_secret("BIP39 optional passphrase: ").map_err(|e| e.to_string())?);
        if confirm {
            let second = Zeroizing::new(read_secret("again: ").map_err(|e| e.to_string())?);
            if *first != *second {
                return Err("the optional passphrases do not match".to_string());
            }
        }
        Ok(first)
    }
}

#[derive(Subcommand)]
enum Command {
    /// Create a new wallet.
    New {
        #[command(flatten)]
        mnemonic_passphrase: MnemonicPassphrase,
    },
    /// Restore a wallet from a recovery phrase.
    Restore {
        /// A file holding the recovery phrase. Without it, you are asked.
        #[arg(long, value_name = "path")]
        mnemonic_file: Option<PathBuf>,
        #[command(flatten)]
        mnemonic_passphrase: MnemonicPassphrase,
    },
    /// Show the recovery phrase.
    Seed,
    /// Show the receiving address.
    Address {
        /// Add one new address and show it.
        #[arg(long)]
        new: bool,
        /// Show every address.
        #[arg(long)]
        all: bool,
    },
    /// Show the balance.
    Balance {
        /// Show the UTXOs one by one.
        #[arg(long)]
        verbose: bool,
    },
    /// Send coins.
    Send {
        /// The destination address.
        to: String,
        /// The amount to send (OAG).
        amount: String,
        /// Build it but do not send.
        #[arg(long)]
        dry_run: bool,
    },
    /// Fold small UTXOs into one.
    ///
    /// Mining adds one UTXO per block. Too many, and you hit the `scanutxos`
    /// bound, at which point **neither balance nor send works**. This folds
    /// them up before that.
    ///
    /// `MAX_TX_SIZE` bounds how many inputs fit in one transaction, so when
    /// there are many, call it repeatedly. Each run says how many are left.
    Consolidate {
        /// Where to fold into. Defaults to the usual receiving address.
        #[arg(long)]
        to: Option<String>,
        /// The maximum inputs in one transaction. Without it, as many as fit.
        #[arg(long)]
        max_inputs: Option<usize>,
        /// Build it but do not send.
        #[arg(long)]
        dry_run: bool,
    },
    /// Work with partially signed transactions (the PSBT equivalent).
    ///
    /// Use it when the machine holding the keys should be separate from the one
    /// talking to a node, or when several owners sign in turn.
    Pst {
        #[command(subcommand)]
        action: PstCommand,
    },
    /// Show the node's state.
    Info,
}

#[derive(Subcommand)]
enum PstCommand {
    /// Build a payment and write out a PST. **It does not sign.**
    Create {
        /// The destination address.
        to: String,
        /// The amount to send (OAG).
        amount: String,
        /// Where to write it. Without it, to standard output.
        #[arg(long, value_name = "path")]
        out: Option<PathBuf>,
    },
    /// Add our own share's signature to a PST.
    ///
    /// **No node connection is needed.** Everything signing requires is carried in the PST.
    Sign {
        /// The PST to read.
        file: PathBuf,
        /// Where to write it. Without it, back to the original file.
        #[arg(long, value_name = "path")]
        out: Option<PathBuf>,
    },
    /// Combine separately signed PSTs into one.
    Combine {
        /// The PSTs to combine. Two or more.
        #[arg(required = true, num_args = 2..)]
        files: Vec<PathBuf>,
        /// Where to write it. Without it, to standard output.
        #[arg(long, value_name = "path")]
        out: Option<PathBuf>,
    },
    /// Show the contents of a PST.
    Show {
        /// The PST to read.
        file: PathBuf,
    },
    /// Finalize a PST and send it.
    Send {
        /// The PST to read.
        file: PathBuf,
        /// Finalize it but do not send.
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("error: cannot start tokio: {e}");
            std::process::exit(1);
        }
    };
    if let Err(message) = runtime.block_on(run()) {
        eprintln!("error: {message}");
        std::process::exit(1);
    }
}

/// Obtain the passphrase.
///
/// Reads from the file if one is given, otherwise asks in the terminal.
/// **It is never taken from a command-line argument.** Arguments are visible
/// to other users on the machine via the process list and persist in shell history.
/// A passphrase. Zeroed on drop.
///
/// Carried around as a raw `Vec<u8>` it would stay in memory after use.
struct Secret(Vec<u8>);

impl Drop for Secret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl std::ops::Deref for Secret {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

fn passphrase(file: &Option<PathBuf>, prompt: &str) -> Result<Secret, String> {
    if let Some(path) = file {
        let mut text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        // 末尾の改行は入力の一部ではない。
        let secret = Secret(text.trim_end_matches(['\n', '\r']).as_bytes().to_vec());
        use zeroize::Zeroize;
        text.zeroize();
        return Ok(secret);
    }
    Ok(Secret(
        read_secret(prompt)
            .map_err(|e| format!("cannot read the passphrase: {e}"))?
            .into_bytes(),
    ))
}

/// Read one line of secret.
///
/// On a terminal it asks with echo off. Otherwise it reads one line from stdin.
/// **The latter is needed not only for trying things by hand but for automated
/// testing.** Anything that needs a terminal rots untested.
///
/// # Why the prompt is written by hand
///
/// `rpassword::prompt_password` is not used. It writes the prompt to the
/// terminal device (`CONOUT$` on Windows, `/dev/tty` on Unix) **as raw bytes**.
/// A Windows console interprets what is written as the current output code
/// page (CP932 by default in a Japanese environment), so UTF-8 Japanese
/// arriving as-is comes out garbled. That is why a prompt reading
/// "パスフレーズ:" turns into "繝代せ繝輔Ξ繝ｼ繧ｺ:".
///
/// Standard error goes through Rust's standard library. On Windows it checks
/// whether the destination is a console and, if so, converts to UTF-16 and
/// writes with `WriteConsoleW`, so the code page does not garble it.
/// **Hence the prompt goes to stderr and only the reading is left to rpassword.**
///
/// stderr rather than stdout, because the prompt is not part of the output.
/// It must not mix in when you write `oag-wallet ... | something`.
fn read_secret(prompt: &str) -> std::io::Result<String> {
    use std::io::{BufRead, IsTerminal, Write};
    use zeroize::Zeroize;

    if !std::io::stdin().is_terminal() {
        // 端末がないなら標準入力から読む。`rpassword::read_password` は
        // 端末の装置そのものを開くので、端末のない場所では開けずに失敗する。
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let secret = line.trim_end_matches(['\n', '\r']).to_string();
        line.zeroize();
        return Ok(secret);
    }

    let mut err = std::io::stderr();
    err.write_all(prompt.as_bytes())?;
    err.flush()?;
    rpassword::read_password()
}

/// Ask for a new passphrase, with confirmation.
fn new_passphrase(file: &Option<PathBuf>) -> Result<Secret, String> {
    if file.is_some() {
        return passphrase(file, "");
    }
    let first = passphrase(&None, "passphrase: ")?;
    let second = passphrase(&None, "again: ")?;
    if *first != *second {
        return Err("the passphrases do not match".to_string());
    }
    if first.len() < MIN_PASSPHRASE_LEN {
        return Err(format!(
            "the passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
        ));
    }
    Ok(first)
}

/// Explain how to keep the backup.
fn print_backup(mnemonic: &Mnemonic, used_passphrase: bool) {
    let words = mnemonic.words();
    println!();
    println!("recovery phrase (this alone restores every address):");
    println!();
    // 番号を付けて 4 語ずつ並べる。書き写す先の紙でも順序を保てる。
    for (row, line) in words.chunks(4).enumerate() {
        let cells: Vec<String> = line
            .iter()
            .enumerate()
            .map(|(col, word)| format!("{:2}. {word:<10}", row * 4 + col + 1))
            .collect();
        println!("    {}", cells.join(" "));
    }
    println!();
    println!("**Copy it onto paper and keep it somewhere safe.**");
    println!("Anyone who knows these words can move the funds. Lose them and the funds are gone.");
    println!("However many addresses you add later, this same phrase is enough.");
    if used_passphrase {
        println!();
        println!("**The optional passphrase is needed too.** The words alone will not restore it.");
        println!("And a typo does not surface as a failure. A different passphrase");
        println!(
            "simply creates another wallet with a zero balance, and nothing reports an error."
        );
    }
}

impl Common {
    fn network(&self) -> Result<Network, String> {
        self.network
            .parse()
            .map_err(|_| format!("unknown network: {}", self.network))
    }

    /// The call interface to the node. The cookie is read from the data directory.
    fn client(&self, network: Network) -> Result<Client, String> {
        let credential = read_cookie(&self.datadir).map_err(|e| {
            format!("{e}\nCheck that the node is running and that --datadir is correct")
        })?;
        let addr = self
            .rpc
            .unwrap_or_else(|| SocketAddr::new(network.rpc_bind_default(), network.rpc_port()));
        Ok(Client::new(addr, credential))
    }
}

async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let network = cli.common.network()?;

    match cli.command {
        Command::New {
            mnemonic_passphrase,
        } => {
            let extra = mnemonic_passphrase.get(true)?;
            let pass = new_passphrase(&cli.common.passphrase_file)?;
            let (store, mnemonic) = Keystore::create(&cli.common.wallet, network, &pass, &extra)
                .map_err(|e| e.to_string())?;
            println!("created a new wallet at {}", cli.common.wallet.display());
            println!(
                "receiving address: {}",
                store.default_address().map_err(|e| e.to_string())?
            );
            print_backup(&mnemonic, !extra.is_empty());
            Ok(())
        }

        Command::Restore {
            mnemonic_file,
            mnemonic_passphrase,
        } => {
            let mut text = match &mnemonic_file {
                Some(path) => std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?,
                None => read_secret("recovery phrase (space separated): ")
                    .map_err(|e| format!("cannot read the recovery phrase: {e}"))?,
            };
            let mnemonic = Mnemonic::parse(&text);
            text.zeroize();
            let mnemonic = mnemonic.map_err(|e| e.to_string())?;
            let extra = mnemonic_passphrase.get(false)?;
            let pass = new_passphrase(&cli.common.passphrase_file)?;

            let store = Keystore::restore(&cli.common.wallet, network, &pass, &mnemonic, &extra)
                .map_err(|e| e.to_string())?;
            println!("restored to {}", cli.common.wallet.display());
            println!(
                "receiving address: {}",
                store.default_address().map_err(|e| e.to_string())?
            );
            println!();
            println!("If two or more addresses were in use, running `address --new`");
            println!("that many times brings back the same ones.");
            Ok(())
        }

        Command::Seed => {
            let pass = passphrase(&cli.common.passphrase_file, "passphrase: ")?;
            let store =
                Keystore::open(&cli.common.wallet, network, &pass).map_err(|e| e.to_string())?;
            print_backup(store.mnemonic(), false);
            Ok(())
        }

        Command::Address { new, all } => {
            let pass = passphrase(&cli.common.passphrase_file, "passphrase: ")?;
            let mut store =
                Keystore::open(&cli.common.wallet, network, &pass).map_err(|e| e.to_string())?;
            if new {
                let address = store.add_key().map_err(|e| e.to_string())?;
                println!("{address}");
            } else if all {
                for address in store.addresses().map_err(|e| e.to_string())? {
                    println!("{address}");
                }
            } else {
                println!("{}", store.default_address().map_err(|e| e.to_string())?);
            }
            Ok(())
        }

        Command::Balance { verbose } => {
            let pass = passphrase(&cli.common.passphrase_file, "passphrase: ")?;
            let store =
                Keystore::open(&cli.common.wallet, network, &pass).map_err(|e| e.to_string())?;
            let client = cli.common.client(network)?;
            let height = block_count(&client).await?;
            let scan = scan(&client, &store).await?;

            let mut spendable = Amount::ZERO;
            let mut immature = Amount::ZERO;
            // 使えるが、まだ目安の確認数に届いていない分。
            let mut shallow = Amount::ZERO;
            for coin in &scan {
                // 使えるかどうかは、次に入るブロックの高さで決まる。
                if coin.is_spendable_at(height + 1) {
                    spendable = spendable
                        .checked_add(coin.output.amount)
                        .ok_or("overflow")?;
                    if confirmations(coin.height, height) < params::RECOMMENDED_CONFIRMATIONS {
                        shallow = shallow.checked_add(coin.output.amount).ok_or("overflow")?;
                    }
                } else {
                    immature = immature.checked_add(coin.output.amount).ok_or("overflow")?;
                }
            }

            println!("  spendable      {spendable} OAG");
            if shallow.to_atomic() > 0 {
                println!(
                    "  of which shallow {shallow} OAG (below the guideline of {} confirmations)",
                    params::RECOMMENDED_CONFIRMATIONS
                );
            }
            if immature.to_atomic() > 0 {
                println!(
                    "  immature       {immature} OAG (a coinbase is spendable after {} blocks)",
                    params::COINBASE_MATURITY
                );
            }
            println!("  UTXOs          {}", scan.len());
            println!("  addresses      {}", store.len());
            println!("  node height    {height}");

            if verbose {
                println!();
                for coin in &scan {
                    let confirmations = confirmations(coin.height, height);
                    let mark = if !coin.is_spendable_at(height + 1) {
                        "*"
                    } else if confirmations < params::RECOMMENDED_CONFIRMATIONS {
                        "!"
                    } else {
                        " "
                    };
                    println!(
                        "  {mark} {} OAG  height {}  confirmations {}  {}:{}",
                        coin.output.amount,
                        coin.height,
                        confirmations,
                        coin.outpoint.txid,
                        coin.outpoint.index
                    );
                }
                if immature.to_atomic() > 0 {
                    println!("  (* is immature)");
                }
                if shallow.to_atomic() > 0 {
                    println!(
                        "  (! is below {} confirmations; wait before accepting it as payment)",
                        params::RECOMMENDED_CONFIRMATIONS
                    );
                }
            }
            Ok(())
        }

        Command::Send {
            to,
            amount,
            dry_run,
        } => {
            let pass = passphrase(&cli.common.passphrase_file, "passphrase: ")?;
            let store =
                Keystore::open(&cli.common.wallet, network, &pass).map_err(|e| e.to_string())?;
            let to_address = Address::decode_on(network, &to)
                .map_err(|e| format!("the destination address is invalid: {e}"))?;
            let amount = amount
                .parse::<Amount>()
                .map_err(|e| format!("the amount is invalid: {e}"))?;

            let client = cli.common.client(network)?;
            let height = block_count(&client).await?;
            let coins = scan(&client, &store).await?;

            let spend = Spend {
                to: Lock::from_address(&to_address),
                amount,
                // おつりは既定の受取先へ戻す。
                change_to: Lock::from_address(&store.default_address().map_err(|e| e.to_string())?),
                next_height: height + 1,
                fee_rate: params::MIN_RELAY_FEE_RATE_PER_BYTE,
            };

            let draft = build(&coins, &spend).map_err(|e| e.to_string())?;
            let signed = sign(&draft, |lock| store.key_for(lock)).map_err(|e| e.to_string())?;
            let raw = signed.encode();

            println!("  to             {to_address}");
            println!("  amount         {amount} OAG");
            println!("  fee            {} OAG", draft.fee);
            println!("  change         {} OAG", draft.change);
            println!("  inputs         {}", draft.spent.len());
            println!("  size           {} bytes", raw.len());
            println!("  txid          {}", signed.txid());

            if dry_run {
                println!();
                println!("--dry-run, so nothing is sent. Raw transaction:");
                println!("{}", to_hex(&raw));
                return Ok(());
            }

            let txid = client
                .call("sendrawtransaction", json!([to_hex(&raw)]))
                .await
                .map_err(|e| format!("the send was refused: {e}"))?;
            println!();
            println!("sent: {}", as_str(&txid, "txid")?);
            Ok(())
        }

        Command::Consolidate {
            to,
            max_inputs,
            dry_run,
        } => {
            let pass = passphrase(&cli.common.passphrase_file, "passphrase: ")?;
            let store =
                Keystore::open(&cli.common.wallet, network, &pass).map_err(|e| e.to_string())?;

            let target = match &to {
                Some(text) => Address::decode_on(network, text)
                    .map_err(|e| format!("the consolidation target address is invalid: {e}"))?,
                None => store.default_address().map_err(|e| e.to_string())?,
            };
            // **まとめ先が自分のものか確かめる。**
            //
            // まとめは額を指定しない。宛先を間違えると、集めた全部を
            // 一度に手放す。`send` の打ち間違いより高くつくので、自分の
            // アドレスでないときは黙って進めない。
            let mine = store.addresses().map_err(|e| e.to_string())?;
            let to_myself = mine.contains(&target);

            let client = cli.common.client(network)?;
            let height = block_count(&client).await?;
            // **打ち切られていても進む。** 上限に当たっている状態こそ
            // まとめが要る場面であり、そこで断ると抜け出す道具が、
            // 抜け出すべき状態でだけ使えないことになる。畳むのに手持ちの
            // 全部は要らない。
            let (mut coins, truncated) = scan_partial(&client, &store).await?;
            let next_height = height + 1;
            if truncated {
                println!(
                    "  the scan was truncated at its limit; holdings exceed the numbers below."
                );
            }

            // **mempool で使用中の出力を外す。**
            //
            // `scanutxos` は UTXO セットを見るので、送信済みで未確定の
            // 取引が使っている出力もまだ手持ちに見える。外さずに組むと、
            // 1 つ前のまとめと同じ出力を使う取引ができる。それは置き換え
            // の申し出として扱われ、「手数料の増分が足りない」と断られる。
            // **金は減らないが、二度押しの理由が読み取れない。**
            let pending = pending_spends(&client).await?;
            let before = coins.len();
            coins.retain(|c| !pending.contains(&(c.outpoint.txid.to_string(), c.outpoint.index)));
            let held = coins.len();
            if before != held {
                println!(
                    "  {} in use by unconfirmed transactions (excluded)",
                    before - held
                );
            }
            let usable = coins
                .iter()
                .filter(|c| c.is_spendable_at(next_height))
                .count();
            println!("  UTXOs held     {held}");
            println!("  foldable now   {usable} (the rest are waiting for coinbase maturity)");

            // **1 件以下なら何もしない。** 二度押しでも手数料は減らない。
            if usable < 2 {
                println!();
                println!("nothing to consolidate. Nothing was done.");
                if truncated {
                    // 打ち切られた 50 件がたまたま全部成熟待ちだった場合が
                    // ある。**並びは決まっているので、すぐ引き直しても同じ
                    // 顔ぶれが返る。** 待つしかない。
                    println!("The scan was truncated, though. This is what happens when everything that came");
                    println!("back is waiting to mature. Advance a few blocks and try again.");
                }
                return Ok(());
            }

            let order = Consolidate {
                to: Lock::from_address(&target),
                next_height,
                fee_rate: params::MIN_RELAY_FEE_RATE_PER_BYTE,
                max_inputs,
            };
            let draft = consolidate(&coins, &order).map_err(|e| e.to_string())?;
            let signed = sign(&draft, |lock| store.key_for(lock)).map_err(|e| e.to_string())?;
            let raw = signed.encode();

            let taken = draft.spent.len();
            let out = draft.tx.outputs[0].amount;
            // この 1 本を送ったあと、手持ちは「残り + まとめた 1 つ」になる。
            let after = held - taken + 1;
            // 畳み残しは 2 種類ある。**混ぜて報せない。** 片方は確定後に
            // もう一度実行すれば片付き、もう片方は待つしかない。
            let left_over = usable - taken;
            let immature = held - usable;

            println!();
            println!("  target         {target}");
            if !to_myself {
                println!();
                println!("**The target is not an address of this wallet.**");
                println!(
                    "Running this gives away {out} OAG. Make sure that is the intended recipient."
                );
            }
            println!("  inputs folded  {taken}");
            println!("  output         {out} OAG");
            println!("  fee            {} OAG", draft.fee);
            println!("  size           {} bytes", raw.len());
            println!("  txid          {}", signed.txid());
            if truncated {
                println!("  UTXOs after    {after} or more");
            } else {
                println!("  UTXOs after    {after}");
            }
            println!();
            if truncated {
                // 走査が打ち切られている以上、「全部畳んだ」とは言えない。
                // 見えていない手持ちがまだある。
                println!("The scan was truncated, so this is not the end.");
                println!("Run it again once this confirms. Repeat until you are under the limit.");
            } else if left_over > 0 {
                println!("They did not all fit in one transaction. The remaining {left_over} can be folded");
                println!("by running this again once this transaction confirms.");
            } else {
                println!("Everything spendable has been folded.");
            }
            if immature > 0 {
                println!("Another {immature} are waiting for coinbase maturity. Those need time.");
            }

            if dry_run {
                println!();
                println!("--dry-run, so nothing is sent. Raw transaction:");
                println!("{}", to_hex(&raw));
                return Ok(());
            }

            let txid = client
                .call("sendrawtransaction", json!([to_hex(&raw)]))
                .await
                .map_err(|e| format!("the send was refused: {e}"))?;
            println!();
            println!("sent: {}", as_str(&txid, "txid")?);
            Ok(())
        }

        Command::Pst { action } => pst(&cli.common, network, action).await,

        Command::Info => {
            let client = cli.common.client(network)?;
            let info = client
                .call("getinfo", json!([]))
                .await
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&info).unwrap_or_default()
            );
            Ok(())
        }
    }
}

/// Collect the outputs used by transactions in the mempool.
///
/// `scanutxos` looks only at the UTXO set, so outputs used by an unconfirmed
/// transaction still answer "present". Counting those as holdings produces a
/// transaction that conflicts with our own unconfirmed one.
async fn pending_spends(client: &Client) -> Result<HashSet<(String, u32)>, String> {
    let list = client
        .call("getmempool", json!([]))
        .await
        .map_err(|e| e.to_string())?;
    let Some(txids) = list.as_array() else {
        return Ok(HashSet::new());
    };

    let mut spent = HashSet::new();
    for id in txids {
        let Some(text) = id.as_str() else { continue };
        // 1 件ずつ引く。引いている間に確定して mempool から消えることが
        // あるので、引けなかったものは飛ばす。
        let Ok(raw) = client.call("getrawtransaction", json!([text])).await else {
            continue;
        };
        // **JSON ではなく生のバイト列で受け取って自分で解く。** 表示用の
        // JSON の形に依存すると、そちらを直したときに黙って壊れる。
        let Some(hex) = raw.as_str() else { continue };
        let Ok(bytes) = from_hex(hex) else { continue };
        let Ok(tx) = Transaction::decode(&bytes) else {
            continue;
        };
        for input in &tx.inputs {
            spent.insert((input.prev_out.txid.to_string(), input.prev_out.index));
        }
    }
    Ok(spent)
}

/// Read a PST. It travels as hexadecimal text.
fn read_pst(path: &std::path::Path) -> Result<Pst, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let bytes = from_hex(text.trim())?;
    Pst::decode(&bytes).map_err(|e| format!("cannot read {} as a PST: {e}", path.display()))
}

/// Write a PST. To standard output when no destination is given.
fn write_pst(pst: &Pst, out: &Option<PathBuf>) -> Result<(), String> {
    let text = to_hex(&pst.encode());
    match out {
        Some(path) => {
            std::fs::write(path, format!("{text}\n"))
                .map_err(|e| format!("cannot write to {}: {e}", path.display()))?;
            println!("written to {}", path.display());
        }
        None => println!("{text}"),
    }
    Ok(())
}

/// Show the contents of a PST.
fn show_pst(pst: &Pst, network: Network) -> Result<(), String> {
    let tx = pst.unsigned();
    println!("  inputs         {}", pst.inputs().len());
    for (index, input) in pst.inputs().iter().enumerate() {
        let where_ = input
            .utxo
            .lock
            .to_address(network)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "(a condition this implementation does not know)".to_string());
        let state = if input.signature.is_some() {
            "signed"
        } else {
            "**unsigned**"
        };
        println!("    [{index}] {} OAG  {where_}  {state}", input.utxo.amount);
    }
    println!("  outputs        {}", tx.outputs.len());
    for (index, output) in tx.outputs.iter().enumerate() {
        let where_ = output
            .lock
            .to_address(network)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "(a condition this implementation does not know)".to_string());
        println!("    [{index}] {} OAG  {where_}", output.amount);
    }
    // **署名する前にこれを見ること。** 出来上がる取引が手放す額である。
    println!(
        "  fee            {} OAG",
        pst.fee().map_err(|e| e.to_string())?
    );
    println!(
        "  signatures     {}",
        if pst.is_complete() {
            "complete".to_string()
        } else {
            format!(
                "{} / {}",
                pst.inputs()
                    .iter()
                    .filter(|i| i.signature.is_some())
                    .count(),
                pst.inputs().len()
            )
        }
    );
    Ok(())
}

async fn pst(common: &Common, network: Network, action: PstCommand) -> Result<(), String> {
    match action {
        PstCommand::Create { to, amount, out } => {
            let pass = passphrase(&common.passphrase_file, "passphrase: ")?;
            let store =
                Keystore::open(&common.wallet, network, &pass).map_err(|e| e.to_string())?;
            let to_address = Address::decode_on(network, &to)
                .map_err(|e| format!("the destination address is invalid: {e}"))?;
            let amount = amount
                .parse::<Amount>()
                .map_err(|e| format!("the amount is invalid: {e}"))?;

            let client = common.client(network)?;
            let height = block_count(&client).await?;
            let coins = scan(&client, &store).await?;

            let spend = Spend {
                to: Lock::from_address(&to_address),
                amount,
                change_to: Lock::from_address(&store.default_address().map_err(|e| e.to_string())?),
                next_height: height + 1,
                fee_rate: params::MIN_RELAY_FEE_RATE_PER_BYTE,
            };
            let draft = build(&coins, &spend).map_err(|e| e.to_string())?;
            let pst = Pst::from_draft(&draft);
            show_pst(&pst, network)?;
            println!();
            write_pst(&pst, &out)
        }

        PstCommand::Sign { file, out } => {
            let pass = passphrase(&common.passphrase_file, "passphrase: ")?;
            let store =
                Keystore::open(&common.wallet, network, &pass).map_err(|e| e.to_string())?;
            let mut pst = read_pst(&file)?;

            // **署名する前に中身を見せる。** 何に署名するのかを知らずに
            // 署名させてはならない。
            show_pst(&pst, network)?;
            let added = pst
                .sign_with(|lock| store.key_for(lock))
                .map_err(|e| e.to_string())?;
            println!();
            println!("signed {added} inputs");
            if !pst.is_complete() {
                println!("Not complete yet. Pass it to the remaining owners.");
            }
            write_pst(&pst, &Some(out.unwrap_or(file)))
        }

        PstCommand::Combine { files, out } => {
            let mut parts = files.iter();
            let first = parts.next().expect("clap guarantees there are two or more");
            let mut combined = read_pst(first)?;
            let mut taken = 0;
            for path in parts {
                taken += combined
                    .combine(&read_pst(path)?)
                    .map_err(|e| format!("cannot combine {}: {e}", path.display()))?;
            }
            println!("took in {taken} signatures");
            show_pst(&combined, network)?;
            println!();
            write_pst(&combined, &out)
        }

        PstCommand::Show { file } => show_pst(&read_pst(&file)?, network),

        PstCommand::Send { file, dry_run } => {
            let pst = read_pst(&file)?;
            show_pst(&pst, network)?;
            // **すべての署名を検証してから取り出す。**
            let tx = pst.finalize().map_err(|e| e.to_string())?;
            let raw = tx.encode();
            println!("  size           {} bytes", raw.len());
            println!("  txid          {}", tx.txid());

            if dry_run {
                println!();
                println!("--dry-run, so nothing is sent. Raw transaction:");
                println!("{}", to_hex(&raw));
                return Ok(());
            }
            let client = common.client(network)?;
            let txid = client
                .call("sendrawtransaction", json!([to_hex(&raw)]))
                .await
                .map_err(|e| format!("the send was refused: {e}"))?;
            println!();
            println!("sent: {}", as_str(&txid, "txid")?);
            Ok(())
        }
    }
}

/// Turn hexadecimal text into bytes.
fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("the hex has an odd number of digits".to_string());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| format!("invalid hex: {e}")))
        .collect()
}

async fn block_count(client: &Client) -> Result<u64, String> {
    let value = client
        .call("getblockcount", json!([]))
        .await
        .map_err(|e| e.to_string())?;
    value
        .as_u64()
        .ok_or_else(|| "getblockcount did not return a number".to_string())
}

/// Confirmations, seen from tip `tip`, of an output in the block at height `coin`.
///
/// **An output in the tip itself is 1.** Zero confirmations means not yet in
/// any block. The wallet looks only at the chain's UTXO set, so anything
/// appearing here is always 1 or more
/// (`docs/SPEC.md` §10.7)。
fn confirmations(coin: u64, tip: u64) -> u64 {
    tip.saturating_sub(coin).saturating_add(1)
}

/// Have the node count our UTXOs.
///
/// There is no index from spending condition to UTXO, so the node scans the
/// whole UTXO set. If the response was truncated, it refuses, so as not to
/// understate the balance.
///
/// Operations that tolerate truncation use [`scan_partial`].
async fn scan(client: &Client, store: &Keystore) -> Result<Vec<Coin>, String> {
    let (coins, truncated) = scan_partial(client, store).await?;
    if truncated {
        return Err(
            "too many UTXOs, so the scan was truncated. Continuing would understate \
             the balance. Fold them up with `consolidate`"
                .to_string(),
        );
    }
    Ok(coins)
}

/// Scan. Reports whether it was truncated and **returns the contents either way**.
///
/// # Why it does not refuse
///
/// A balance cannot be stated without seeing everything. It comes out short by
/// whatever was missed, so claiming a balance from a truncated scan is a lie.
///
/// **Consolidation is different.** Folding does not need everything. If some of
/// the holdings come back, they can be made into one. Indeed, hitting the bound
/// is exactly when folding is needed, and refusing there would make **the tool
/// for getting out unusable precisely in the state you need to get out of**.
///
/// The set that comes back is not "the most recent N". A UTXO's key is
/// `txid ++ output index`, and a txid is a hash, so the order is effectively
/// arbitrary. It is **an arbitrary N of the holdings**, which is enough to fold.
async fn scan_partial(client: &Client, store: &Keystore) -> Result<(Vec<Coin>, bool), String> {
    let addresses: Vec<String> = store
        .addresses()
        .map_err(|e| e.to_string())?
        .iter()
        .map(|a| a.to_string())
        .collect();
    let result = client
        .call("scanutxos", json!([addresses]))
        .await
        .map_err(|e| e.to_string())?;

    let truncated = result.get("truncated").and_then(Value::as_bool) == Some(true);

    let utxos = result
        .get("utxos")
        .and_then(Value::as_array)
        .ok_or("the scanutxos response has no utxos")?;

    // 自分の支払い条件だけを引き当てる。引き当てられないものは、
    // 署名できないのだから手持ちに数えない。
    let known: Vec<(String, Lock)> = store
        .addresses()
        .map_err(|e| e.to_string())?
        .iter()
        .map(|a| (a.to_string(), Lock::from_address(a)))
        .collect();

    let mut coins = Vec::with_capacity(utxos.len());
    for utxo in utxos {
        let address = as_str(utxo.get("address").unwrap_or(&Value::Null), "address")?;
        let Some((_, lock)) = known.iter().find(|(text, _)| *text == address) else {
            continue;
        };
        let amount = as_atomic(utxo.get("amount").unwrap_or(&Value::Null))?;
        coins.push(Coin {
            outpoint: oag_consensus::tx::OutPoint {
                txid: as_hash(utxo.get("txid").unwrap_or(&Value::Null))?,
                index: u32::try_from(
                    utxo.get("index")
                        .and_then(Value::as_u64)
                        .ok_or("utxo.index is missing")?,
                )
                .map_err(|_| "utxo.index is too large")?,
            },
            output: TxOutput::new(amount, lock.clone()),
            height: utxo
                .get("height")
                .and_then(Value::as_u64)
                .ok_or("utxo.height is missing")?,
            is_coinbase: utxo
                .get("coinbase")
                .and_then(Value::as_bool)
                .ok_or("utxo.coinbase is missing")?,
        });
    }
    Ok((coins, truncated))
}

fn as_str(value: &Value, name: &str) -> Result<String, String> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{name} is not a string"))
}

fn as_hash(value: &Value) -> Result<Hash, String> {
    as_str(value, "txid")?
        .parse()
        .map_err(|_| "the txid cannot be read".to_string())
}

/// Turn a decimal string in atomic units into an amount.
///
/// A JSON number cannot express 10^25, so these travel as strings.
fn as_atomic(value: &Value) -> Result<Amount, String> {
    let text = as_str(value, "amount")?;
    let atomic: u128 = text
        .parse()
        .map_err(|_| format!("the amount cannot be read: {text}"))?;
    Amount::from_atomic(atomic).map_err(|e| e.to_string())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_coin_in_the_tip_block_has_one_confirmation() {
        assert_eq!(confirmations(100, 100), 1);
        assert_eq!(confirmations(100, 109), 10);
        assert_eq!(confirmations(0, 0), 1);
    }

    #[test]
    fn the_recommended_depth_is_reached_ten_blocks_later() {
        // 高さ 100 で受け取った出力は、先端が 109 になった時点で目安を満たす。
        let received_at = 100;
        let enough = received_at + params::RECOMMENDED_CONFIRMATIONS - 1;
        assert!(confirmations(received_at, enough - 1) < params::RECOMMENDED_CONFIRMATIONS);
        assert_eq!(
            confirmations(received_at, enough),
            params::RECOMMENDED_CONFIRMATIONS
        );
    }

    #[test]
    fn a_coin_from_the_future_does_not_wrap_around() {
        // 先端より高い出力は起こらないが、起きたときに「深い」と
        // 誤らせるより 1 承認と見せるほうが安全である。
        assert_eq!(confirmations(200, 100), 1);
    }
}
