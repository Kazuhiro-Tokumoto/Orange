//! Orange (OAG) のウォレット。
//!
//! ノードとは JSON-RPC でしか話さない。**秘密鍵はノードに渡らない。**
//! 署名はここで済ませ、出来上がったものだけを `sendrawtransaction` で
//! 投げる。

#![forbid(unsafe_code)]
#![warn(clippy::all)]

use clap::{Parser, Subcommand};
use oag_consensus::codec::Encode;
use oag_consensus::lock::Lock;
use oag_consensus::params;
use oag_consensus::TxOutput;
use oag_primitives::{Address, Amount, Hash, Network};
use oag_rpc::auth::read_cookie;
use oag_rpc::client::Client;
use oag_wallet::bip39::Mnemonic;
use oag_wallet::build::{build, sign, Coin, Spend};
use oag_wallet::keystore::{Keystore, MIN_PASSPHRASE_LEN};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

#[derive(Parser)]
#[command(name = "oag-wallet", about = "Orange (OAG) のウォレット", version)]
struct Cli {
    #[command(flatten)]
    common: Common,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct Common {
    /// 対象ネットワーク。
    #[arg(long, global = true, default_value = "regtest")]
    network: String,
    /// ウォレットファイル。
    #[arg(long, global = true, default_value = "./wallet.json")]
    wallet: PathBuf,
    /// ノードのデータディレクトリ。RPC の合言葉をここから読む。
    #[arg(long, global = true, default_value = "./oag-data")]
    datadir: PathBuf,
    /// ノードの RPC の住所。既定はループバックの RPC ポート。
    #[arg(long, global = true)]
    rpc: Option<SocketAddr>,
    /// パスフレーズを収めたファイル。
    ///
    /// 省略すると端末で尋ねる。**コマンドラインには渡せない。**
    /// 引数はプロセス一覧から他の利用者に見えるためである。
    #[arg(long, global = true, value_name = "パス")]
    passphrase_file: Option<PathBuf>,
}

/// BIP39 の追加パスフレーズの受け取り方。
///
/// **既定は空文字列である。** 使わないのが普通であり、使うと決めた者だけが
/// 明示する。
#[derive(clap::Args)]
struct MnemonicPassphrase {
    /// BIP39 の追加パスフレーズを端末で尋ねる。
    #[arg(long)]
    mnemonic_passphrase: bool,
    /// BIP39 の追加パスフレーズを収めたファイル。
    #[arg(long, value_name = "パス", conflicts_with = "mnemonic_passphrase")]
    mnemonic_passphrase_file: Option<PathBuf>,
}

impl MnemonicPassphrase {
    /// 追加パスフレーズを得る。
    ///
    /// `confirm` が真なら 2 度尋ねて突き合わせる。**打ち間違えても失敗
    /// として現れない**ため、作るときは必ず確かめる。
    fn get(&self, confirm: bool) -> Result<Zeroizing<String>, String> {
        if let Some(path) = &self.mnemonic_passphrase_file {
            let mut text = std::fs::read_to_string(path)
                .map_err(|e| format!("{} を読めない: {e}", path.display()))?;
            let value = Zeroizing::new(text.trim_end_matches(['\n', '\r']).to_string());
            text.zeroize();
            return Ok(value);
        }
        if !self.mnemonic_passphrase {
            return Ok(Zeroizing::new(String::new()));
        }
        let first =
            Zeroizing::new(read_secret("BIP39 の追加パスフレーズ: ").map_err(|e| e.to_string())?);
        if confirm {
            let second = Zeroizing::new(read_secret("もう一度: ").map_err(|e| e.to_string())?);
            if *first != *second {
                return Err("追加パスフレーズが一致しない".to_string());
            }
        }
        Ok(first)
    }
}

#[derive(Subcommand)]
enum Command {
    /// 新しいウォレットを作る。
    New {
        #[command(flatten)]
        mnemonic_passphrase: MnemonicPassphrase,
    },
    /// 控えの語からウォレットを復元する。
    Restore {
        /// 控えの語を収めたファイル。省略すると尋ねる。
        #[arg(long, value_name = "パス")]
        mnemonic_file: Option<PathBuf>,
        #[command(flatten)]
        mnemonic_passphrase: MnemonicPassphrase,
    },
    /// 控えの語を表示する。
    Seed,
    /// 受取先アドレスを表示する。
    Address {
        /// 新しいアドレスを 1 つ増やして表示する。
        #[arg(long)]
        new: bool,
        /// すべてのアドレスを表示する。
        #[arg(long)]
        all: bool,
    },
    /// 残高を表示する。
    Balance {
        /// UTXO を 1 件ずつ表示する。
        #[arg(long)]
        verbose: bool,
    },
    /// 送金する。
    Send {
        /// 宛先アドレス。
        to: String,
        /// 送る額 (OAG)。
        amount: String,
        /// 組み立てるだけで送らない。
        #[arg(long)]
        dry_run: bool,
    },
    /// ノードの状態を表示する。
    Info,
}

fn main() {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("エラー: tokio を起こせない: {e}");
            std::process::exit(1);
        }
    };
    if let Err(message) = runtime.block_on(run()) {
        eprintln!("エラー: {message}");
        std::process::exit(1);
    }
}

/// パスフレーズを得る。
///
/// ファイルが指定されていればそこから読み、なければ端末で尋ねる。
/// **コマンドラインの引数からは受け取らない。** 引数はプロセス一覧から
/// 同じ機械の他の利用者に見えるうえ、シェルの履歴にも残る。
/// パスフレーズ。落ちるときに消す。
///
/// 生の `Vec<u8>` のまま持ち回すと、使い終わったあともメモリに残る。
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
            .map_err(|e| format!("{} を読めない: {e}", path.display()))?;
        // 末尾の改行は入力の一部ではない。
        let secret = Secret(text.trim_end_matches(['\n', '\r']).as_bytes().to_vec());
        use zeroize::Zeroize;
        text.zeroize();
        return Ok(secret);
    }
    Ok(Secret(
        read_secret(prompt)
            .map_err(|e| format!("パスフレーズを読めない: {e}"))?
            .into_bytes(),
    ))
}

/// 秘密を 1 行読む。
///
/// 端末なら伏せ字で尋ねる。端末でなければ標準入力から 1 行読む。
/// **後者が要るのは、手で試すためだけでなく、自動で試験するためでもある。**
/// 端末がないと動かないものは、試験されないまま腐る。
///
/// # 促しを自分で書く理由
///
/// `rpassword::prompt_password` を使わない。あれは促しを端末の装置
/// (Windows なら `CONOUT$`、Unix なら `/dev/tty`) へ**生のバイト列のまま**
/// 書き出す。Windows のコンソールは書き込まれたバイト列を現在の出力
/// コードページ (日本語環境の既定は CP932) として解釈するので、UTF-8 の
/// 日本語がそのまま届くと化ける。「パスフレーズ:」が
/// 「繝代せ繝輔Ξ繝ｼ繧ｺ:」になるのはこれである。
///
/// 標準エラー出力なら Rust の標準ライブラリが噛む。Windows では相手が
/// コンソールかどうかを見て、コンソールなら UTF-16 に直して
/// `WriteConsoleW` で書くため、コードページに関わらず化けない。
/// **だから促しは標準エラー出力へ書き、読むところだけ rpassword に任せる。**
///
/// 標準出力ではなく標準エラー出力なのは、促しが出力の一部ではないからだ。
/// `oag-wallet ... | something` としたときに促しが混ざってはいけない。
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

/// 新しく決めるパスフレーズを、確認付きで尋ねる。
fn new_passphrase(file: &Option<PathBuf>) -> Result<Secret, String> {
    if file.is_some() {
        return passphrase(file, "");
    }
    let first = passphrase(&None, "パスフレーズ: ")?;
    let second = passphrase(&None, "もう一度: ")?;
    if *first != *second {
        return Err("パスフレーズが一致しない".to_string());
    }
    if first.len() < MIN_PASSPHRASE_LEN {
        return Err(format!(
            "パスフレーズは {MIN_PASSPHRASE_LEN} 文字以上であること"
        ));
    }
    Ok(first)
}

/// 控えの取り方を伝える。
fn print_backup(mnemonic: &Mnemonic, used_passphrase: bool) {
    let words = mnemonic.words();
    println!();
    println!("控えの語 (これだけですべてのアドレスを復元できる):");
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
    println!("**紙に書き写して安全な場所に保管すること。**");
    println!("この語を知る者は資金を動かせる。失えば資金は取り戻せない。");
    println!("アドレスをあとから増やしても、この控えのままでよい。");
    if used_passphrase {
        println!();
        println!("**追加パスフレーズも要る。** 語だけでは復元できない。");
        println!("そして打ち間違えても失敗としては現れない。別のパスフレーズは");
        println!("残高 0 の別のウォレットを作るだけで、どこにも誤りは出ない。");
    }
}

impl Common {
    fn network(&self) -> Result<Network, String> {
        self.network
            .parse()
            .map_err(|_| format!("知らないネットワーク: {}", self.network))
    }

    /// ノードへの呼び出し口。合言葉はデータディレクトリから読む。
    fn client(&self, network: Network) -> Result<Client, String> {
        let credential = read_cookie(&self.datadir).map_err(|e| {
            format!("{e}\nノードが動いていて、--datadir が合っているか確かめること")
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
            println!("{} に新しいウォレットを作った", cli.common.wallet.display());
            println!(
                "受取先: {}",
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
                    .map_err(|e| format!("{} を読めない: {e}", path.display()))?,
                None => read_secret("控えの語 (空白区切り): ")
                    .map_err(|e| format!("控えの語を読めない: {e}"))?,
            };
            let mnemonic = Mnemonic::parse(&text);
            text.zeroize();
            let mnemonic = mnemonic.map_err(|e| e.to_string())?;
            let extra = mnemonic_passphrase.get(false)?;
            let pass = new_passphrase(&cli.common.passphrase_file)?;

            let store = Keystore::restore(&cli.common.wallet, network, &pass, &mnemonic, &extra)
                .map_err(|e| e.to_string())?;
            println!("{} に復元した", cli.common.wallet.display());
            println!(
                "受取先: {}",
                store.default_address().map_err(|e| e.to_string())?
            );
            println!();
            println!("アドレスを 2 個以上使っていた場合は、`address --new` を");
            println!("その数だけ繰り返すと同じものが出る。");
            Ok(())
        }

        Command::Seed => {
            let pass = passphrase(&cli.common.passphrase_file, "パスフレーズ: ")?;
            let store =
                Keystore::open(&cli.common.wallet, network, &pass).map_err(|e| e.to_string())?;
            print_backup(store.mnemonic(), false);
            Ok(())
        }

        Command::Address { new, all } => {
            let pass = passphrase(&cli.common.passphrase_file, "パスフレーズ: ")?;
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
            let pass = passphrase(&cli.common.passphrase_file, "パスフレーズ: ")?;
            let store =
                Keystore::open(&cli.common.wallet, network, &pass).map_err(|e| e.to_string())?;
            let client = cli.common.client(network)?;
            let height = block_count(&client).await?;
            let scan = scan(&client, &store).await?;

            let mut spendable = Amount::ZERO;
            let mut immature = Amount::ZERO;
            for coin in &scan {
                // 使えるかどうかは、次に入るブロックの高さで決まる。
                if coin.is_spendable_at(height + 1) {
                    spendable = spendable
                        .checked_add(coin.output.amount)
                        .ok_or("桁あふれ")?;
                } else {
                    immature = immature.checked_add(coin.output.amount).ok_or("桁あふれ")?;
                }
            }

            println!("  使える残高    {spendable} OAG");
            if immature.to_atomic() > 0 {
                println!(
                    "  未成熟        {immature} OAG (コインベースは {} ブロック後に使える)",
                    params::COINBASE_MATURITY
                );
            }
            println!("  UTXO          {} 件", scan.len());
            println!("  アドレス      {} 個", store.len());
            println!("  ノードの高さ  {height}");

            if verbose {
                println!();
                for coin in &scan {
                    let mark = if coin.is_spendable_at(height + 1) {
                        " "
                    } else {
                        "*"
                    };
                    println!(
                        "  {mark} {} OAG  高さ {}  {}:{}",
                        coin.output.amount, coin.height, coin.outpoint.txid, coin.outpoint.index
                    );
                }
                if immature.to_atomic() > 0 {
                    println!("  (* は未成熟)");
                }
            }
            Ok(())
        }

        Command::Send {
            to,
            amount,
            dry_run,
        } => {
            let pass = passphrase(&cli.common.passphrase_file, "パスフレーズ: ")?;
            let store =
                Keystore::open(&cli.common.wallet, network, &pass).map_err(|e| e.to_string())?;
            let to_address =
                Address::decode_on(network, &to).map_err(|e| format!("宛先アドレスが不正: {e}"))?;
            let amount = amount
                .parse::<Amount>()
                .map_err(|e| format!("額が不正: {e}"))?;

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

            println!("  宛先          {to_address}");
            println!("  送る額        {amount} OAG");
            println!("  手数料        {} OAG", draft.fee);
            println!("  おつり        {} OAG", draft.change);
            println!("  入力          {} 件", draft.spent.len());
            println!("  大きさ        {} バイト", raw.len());
            println!("  txid          {}", signed.txid());

            if dry_run {
                println!();
                println!("--dry-run のため送らない。生の取引:");
                println!("{}", to_hex(&raw));
                return Ok(());
            }

            let txid = client
                .call("sendrawtransaction", json!([to_hex(&raw)]))
                .await
                .map_err(|e| format!("送信を断られた: {e}"))?;
            println!();
            println!("送信した: {}", as_str(&txid, "txid")?);
            Ok(())
        }

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

async fn block_count(client: &Client) -> Result<u64, String> {
    let value = client
        .call("getblockcount", json!([]))
        .await
        .map_err(|e| e.to_string())?;
    value
        .as_u64()
        .ok_or_else(|| "getblockcount が数値を返さない".to_string())
}

/// 自分の UTXO をノードに数えてもらう。
///
/// 支払い条件から UTXO を引く索引が無いため、ノードは UTXO セットを
/// 丸ごと走査する。応答が打ち切られていたら、残高を過少に見せない
/// ように断る。
async fn scan(client: &Client, store: &Keystore) -> Result<Vec<Coin>, String> {
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

    if result.get("truncated").and_then(Value::as_bool) == Some(true) {
        return Err(
            "UTXO が多すぎて走査が打ち切られた。このまま続けると残高を実際より\
             少なく見積もる。アドレスを分けて調べること"
                .to_string(),
        );
    }

    let utxos = result
        .get("utxos")
        .and_then(Value::as_array)
        .ok_or("scanutxos の応答に utxos が無い")?;

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
                        .ok_or("utxo.index が無い")?,
                )
                .map_err(|_| "utxo.index が大きすぎる")?,
            },
            output: TxOutput::new(amount, lock.clone()),
            height: utxo
                .get("height")
                .and_then(Value::as_u64)
                .ok_or("utxo.height が無い")?,
            is_coinbase: utxo
                .get("coinbase")
                .and_then(Value::as_bool)
                .ok_or("utxo.coinbase が無い")?,
        });
    }
    Ok(coins)
}

fn as_str(value: &Value, name: &str) -> Result<String, String> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{name} が文字列でない"))
}

fn as_hash(value: &Value) -> Result<Hash, String> {
    as_str(value, "txid")?
        .parse()
        .map_err(|_| "txid が読めない".to_string())
}

/// atomic 単位の 10 進文字列を額に直す。
///
/// JSON の数値では 10^25 を表しきれないため、文字列でやり取りしている。
fn as_atomic(value: &Value) -> Result<Amount, String> {
    let text = as_str(value, "amount")?;
    let atomic: u128 = text.parse().map_err(|_| format!("額が読めない: {text}"))?;
    Amount::from_atomic(atomic).map_err(|e| e.to_string())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
