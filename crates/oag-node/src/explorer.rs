//! ブロックエクスプローラ。
//!
//! ブラウザで鎖の中身を見るための、読むだけの HTTP である。既定では
//! `127.0.0.1:8080` で待ち受ける。
//!
//! # なぜ RPC の HTTP を使い回さないのか
//!
//! [`oag_rpc::http`] は「`POST /` に JSON を 1 個、合言葉つき」だけを
//! 受け付ける。**その狭さがあの層の安全性そのもの**であり (SPEC §14.1)、
//! `GET` と任意のパスを通すために広げると、資金を動かせる入口の作りを
//! 弱めることになる。
//!
//! こちらは読むだけで、状態を変える経路を一切持たない。別の口として
//! 分けておけば、片方を緩めてももう片方は緩まない。
//!
//! # 何ができないか
//!
//! - **書き込みは無い。** 送金も採掘操作もここからはできない。
//! - **索引が要る。** 取引とアドレスの照会は `--index` で作った索引に
//!   頼る。無ければその旨を表示して、ブロックの閲覧だけを提供する。
//! - 待ち受けは既定でループバックのみである。外に出すなら住所を明示する。
//!
//! # 表示の向き
//!
//! アドレスの履歴は**古い順**に出す。索引の鍵が高さ順に並んでいるため、
//! その順に読むのが最も安く、続きから読むだけで頁送りになるからである。
//! 新しい順に並べ替えるには全件を数える必要があり、それは「途中で
//! 打ち切った」ことを利用者に隠したまま行うには危うい。

use crate::service::{NodeHandle, TxRecord};
use oag_consensus::lock::Lock;
use oag_consensus::{Block, Transaction};
use oag_primitives::{Address, Amount, Hash, Network};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 要求の頭の上限。
const MAX_REQUEST: usize = 8 * 1024;
/// 要求が来ないまま接続を保つ上限。
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// 一覧に出す最近のブロックの数。
const RECENT_BLOCKS: usize = 25;
/// 履歴 1 頁の件数。
const PAGE: usize = 50;
/// アドレス頁に出す UTXO の上限。
const MAX_UTXOS: usize = 500;

/// 待ち受けを始める。実際に結びついた住所を返す。
pub async fn start_explorer(handle: NodeHandle, addr: SocketAddr) -> Result<SocketAddr, String> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot listen for the explorer on {addr}: {e}"))?;
    let bound = listener
        .local_addr()
        .map_err(|e| format!("cannot determine the address: {e}"))?;

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    crate::log_warn!("cannot accept an explorer connection: {e}");
                    return;
                }
            };
            let handle = handle.clone();
            tokio::spawn(async move {
                let _ = serve_connection(stream, handle).await;
            });
        }
    });
    Ok(bound)
}

/// 応答 1 個。
struct Response {
    status: &'static str,
    body: String,
}

async fn serve_connection(mut stream: TcpStream, handle: NodeHandle) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let mut buffer = Vec::with_capacity(1024);

    // 1 要求 1 接続とする。使い回しに応じないぶん、扱いが単純になる。
    let target = match read_target(&mut stream, &mut buffer).await {
        Some(target) => target,
        None => {
            let body = page("400", "<h1>cannot read the request</h1>");
            return write_response(
                &mut stream,
                &Response {
                    status: "400 Bad Request",
                    body,
                },
            )
            .await;
        }
    };

    let response = route(&handle, &target).await;
    write_response(&mut stream, &response).await
}

/// 要求行から要求先を取り出す。`GET` 以外は `None`。
async fn read_target(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<String> {
    let mut chunk = [0u8; 1024];
    loop {
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > MAX_REQUEST {
            return None;
        }
        let read = tokio::time::timeout(IDLE_TIMEOUT, stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }

    let text = String::from_utf8_lossy(buffer);
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    // 読むだけの口なので、読む動詞しか受けない。
    if method != "GET" && method != "HEAD" {
        return None;
    }
    Some(target.to_string())
}

async fn write_response(stream: &mut TcpStream, response: &Response) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         X-Robots-Tag: noindex, nofollow\r\n\
         Connection: close\r\n\r\n",
        response.status,
        response.body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(response.body.as_bytes()).await?;
    stream.flush().await
}

// ━━━━━━━━ 経路 ━━━━━━━━

async fn route(handle: &NodeHandle, target: &str) -> Response {
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    };
    let path = percent_decode(path);
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();

    match segments.as_slice() {
        [""] => overview(handle).await,
        ["search"] => search(handle, query).await,
        ["block", rest @ ..] => block_page(handle, &rest.join("/"), query).await,
        ["tx", rest @ ..] => tx_page(handle, &rest.join("/")).await,
        ["address", rest @ ..] => address_page(handle, &rest.join("/"), query).await,
        ["mempool"] => mempool_page(handle).await,
        _ => not_found("no such page"),
    }
}

async fn overview(handle: &NodeHandle) -> Response {
    let status = match handle.status().await {
        Ok(status) => status,
        Err(e) => return error_page(&e),
    };
    let indexed = handle.index_from().await.unwrap_or(None);
    let mempool = handle.mempool_txids().await.unwrap_or_default();

    let mut body = String::new();
    body.push_str(&search_box(""));

    body.push_str("<div class=\"grid\">");
    stat(&mut body, "network", &esc(&status.network.to_string()));
    stat(&mut body, "height", &status.height.to_string());
    stat(&mut body, "next difficulty", &group(status.next_difficulty));
    stat(&mut body, "UTXO", &group(status.utxo_count));
    stat(&mut body, "mempool", &mempool.len().to_string());
    stat(
        &mut body,
        "index",
        match indexed {
            Some(_) => "<span class=\"ok\">yes</span>",
            None => "<span class=\"warn\">no</span>",
        },
    );
    body.push_str("</div>");

    if indexed.is_none() {
        body.push_str(
            "<p class=\"note\">no index is held, so transaction IDs and addresses cannot be \
             looked up. Start the node with <code>--index</code> to enable them.</p>",
        );
    }

    body.push_str("<h2>tip</h2>");
    body.push_str(&format!(
        "<p class=\"mono break\">{}</p>",
        esc(&status.tip.to_string())
    ));

    // 最近のブロック。
    body.push_str("<h2>recent blocks</h2><div class=\"wrap\"><table class=\"list\">");
    body.push_str("<tr class=\"head\"><th>height</th><th>time (UTC)</th><th>txs</th><th>size</th><th>difficulty</th><th>hash</th></tr>");
    // **本体は引かない。** 高さごとに 2 往復して 25 個のブロックを丸ごと
    // 復号すると、満杯の鎖では 5 MB を読んで 16,000 件あまりの取引を組み
    // 立てることになる。表に出すのは 1 行 5 項目だけである。
    for summary in handle
        .recent_blocks(RECENT_BLOCKS)
        .await
        .unwrap_or_default()
    {
        let hash = summary.hash.to_string();
        let _ = write!(
            body,
            "<tr><td data-label=\"height\"><a href=\"/block/{h}\">{h}</a></td>\
             <td data-label=\"time (UTC)\" class=\"mono\">{t}</td>\
             <td data-label=\"txs\">{n}</td><td data-label=\"size\" class=\"wide\">{s} B</td>\
             <td data-label=\"difficulty\" class=\"wide\">{d}</td>\
             <td data-label=\"hash\" class=\"mono trunc wide\"><a href=\"/block/{hash}\">{short}</a></td></tr>",
            h = summary.height,
            t = utc(summary.header.timestamp),
            n = summary.transactions,
            s = group(summary.size as u64),
            d = group(summary.header.difficulty),
            hash = esc(&hash),
            short = esc(&shorten(&hash)),
        );
    }
    body.push_str("</table></div>");

    if !mempool.is_empty() {
        body.push_str(&format!(
            "<h2>mempool</h2><p><a href=\"/mempool\">{} unconfirmed transactions</a></p>",
            mempool.len()
        ));
    }

    ok(page("Orange explorer", &body))
}

async fn search(handle: &NodeHandle, query: &str) -> Response {
    let q = query_value(query, "q").unwrap_or_default();
    let q = q.trim().to_string();
    if q.is_empty() {
        return not_found("nothing was entered");
    }

    // 数字だけなら高さ。
    if q.chars().all(|c| c.is_ascii_digit()) {
        return block_page(handle, &q, "").await;
    }
    // 64 文字の 16 進はブロックか取引。ブロックを先に見る。
    if q.len() == 64 && q.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(hash) = q.parse::<Hash>() {
            if matches!(handle.entry(hash).await, Ok(Some(_))) {
                return block_page(handle, &q, "").await;
            }
        }
        return tx_page(handle, &q).await;
    }
    address_page(handle, &q, "").await
}

async fn block_page(handle: &NodeHandle, key: &str, query: &str) -> Response {
    let hash = if key.chars().all(|c| c.is_ascii_digit()) {
        let Ok(height) = key.parse::<u64>() else {
            return not_found(&format!("{key} cannot be read as a height"));
        };
        match handle.hash_at_height(height).await {
            Ok(Some(hash)) => hash,
            Ok(None) => return not_found(&format!("there is no block at height {height}")),
            Err(e) => return error_page(&e),
        }
    } else {
        match key.parse::<Hash>() {
            Ok(hash) => hash,
            Err(_) => return not_found(&format!("{key} cannot be read as a block hash")),
        }
    };

    let block = match handle.block(hash).await {
        Ok(Some(block)) => block,
        Ok(None) => return not_found("the body of that block is not held"),
        Err(e) => return error_page(&e),
    };

    let mut body = String::new();
    body.push_str(&search_box(""));
    let _ = write!(body, "<h1>block {}</h1>", block.header.height);
    body.push_str(&format!(
        "<p class=\"mono break\">{}</p>",
        esc(&hash.to_string())
    ));

    body.push_str("<div class=\"wrap\"><table class=\"kv\">");
    row(&mut body, "height", &block.header.height.to_string());
    row(&mut body, "time (UTC)", &utc(block.header.timestamp));
    row(
        &mut body,
        "unix seconds",
        &block.header.timestamp.to_string(),
    );
    row(&mut body, "difficulty", &group(block.header.difficulty));
    row(&mut body, "nonce", &group(block.header.nonce));
    row(&mut body, "version", &block.header.version.to_string());
    row(
        &mut body,
        "size",
        &format!("{} B", group(block.size() as u64)),
    );
    row(
        &mut body,
        "transactions",
        &block.transactions.len().to_string(),
    );
    row_raw(
        &mut body,
        "merkle root",
        &format!(
            "<span class=\"mono break\">{}</span>",
            esc(&block.header.merkle_root.to_string())
        ),
    );
    let prev = block.header.prev_hash;
    if block.header.height > 0 {
        row_raw(
            &mut body,
            "parent",
            &format!(
                "<a class=\"mono break\" href=\"/block/{p}\">{p}</a>",
                p = esc(&prev.to_string())
            ),
        );
    }
    body.push_str("</table></div>");

    // 満杯のブロックは約 670 取引を持ちうる。全部を 1 枚に吐くと
    // 130 KB の表になるので、アドレス履歴と同じ幅で区切る。
    let from: usize = query_value(query, "from")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .min(block.transactions.len());
    let upto = (from + PAGE).min(block.transactions.len());

    body.push_str("<h2>transactions</h2>");
    if block.transactions.len() > PAGE && upto > from {
        let _ = write!(
            body,
            "<p class=\"note\">{} to {} of {}</p>",
            group(block.transactions.len() as u64),
            from + 1,
            upto
        );
    }
    body.push_str(&tx_table(&block, handle.network(), from, upto));

    body.push_str(&tx_pager(&hash, from, upto, block.transactions.len()));

    let mut nav = String::new();
    if block.header.height > 0 {
        let _ = write!(
            nav,
            "<a href=\"/block/{}\">&larr; previous</a> ",
            block.header.height - 1
        );
    }
    let _ = write!(
        nav,
        "<a href=\"/block/{}\">next &rarr;</a>",
        block.header.height + 1
    );
    let _ = write!(body, "<p class=\"nav\">{nav}</p>");

    ok(page(&format!("block {}", block.header.height), &body))
}

async fn tx_page(handle: &NodeHandle, key: &str) -> Response {
    let Ok(txid) = key.parse::<Hash>() else {
        return not_found(&format!("{key} cannot be read as a transaction ID"));
    };
    let network = handle.network();

    let indexed = handle.index_from().await.unwrap_or(None).is_some();
    let record = if indexed {
        handle.tx_record(txid).await.unwrap_or(None)
    } else {
        None
    };

    let mut body = String::new();
    body.push_str(&search_box(""));
    body.push_str("<h1>transaction</h1>");
    body.push_str(&format!(
        "<p class=\"mono break\">{}</p>",
        esc(&txid.to_string())
    ));

    if let Some(record) = record {
        body.push_str(&record_detail(&record, network));
        return ok(page("transaction", &body));
    }

    // 索引に無ければ mempool を見る。
    match handle.mempool_tx(txid).await {
        Ok(Some(tx)) => {
            body.push_str("<p class=\"warn\">unconfirmed (in the mempool)</p>");
            body.push_str(&tx_detail(&tx, &[], network));
            ok(page("transaction", &body))
        }
        Ok(None) if !indexed => not_found(
            "without an index, a confirmed transaction cannot be looked up by ID; start the node with --index",
        ),
        Ok(None) => not_found("there is no such transaction"),
        Err(e) => error_page(&e),
    }
}

async fn address_page(handle: &NodeHandle, key: &str, query: &str) -> Response {
    let network = handle.network();
    let address = match Address::decode_on(network, key) {
        Ok(address) => address,
        Err(e) => return not_found(&format!("{key} cannot be read as an address: {e}")),
    };
    let lock = Lock::from_address(&address);
    let from: u64 = query_value(query, "from")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let mut body = String::new();
    body.push_str(&search_box(key));
    body.push_str("<h1>address</h1>");
    body.push_str(&format!("<p class=\"mono break\">{}</p>", esc(key)));

    // 残高は索引に頼らない。UTXO セットを丸ごと見て拾う。
    let utxos = handle
        .scan_utxos(vec![lock.clone()], MAX_UTXOS)
        .await
        .unwrap_or_default();
    let balance = Amount::sum(utxos.iter().map(|u| u.entry.output.amount));

    body.push_str("<div class=\"grid\">");
    stat(
        &mut body,
        "balance",
        &match balance {
            Some(amount) => format!("{} OAG", esc(&amount.to_string())),
            None => "cannot be computed".to_string(),
        },
    );
    stat(&mut body, "UTXO", &utxos.len().to_string());
    body.push_str("</div>");
    if utxos.len() >= MAX_UTXOS {
        body.push_str(
            "<p class=\"warn\">the UTXO scan hit its limit, so this balance is lower than the real one.</p>",
        );
    }

    // 履歴は索引に頼る。
    match handle.index_from().await {
        Ok(Some(_)) => {
            let history = handle
                .address_history(lock.clone(), from, PAGE + 1)
                .await
                .unwrap_or_default();
            let more = history.len() > PAGE;
            let shown = &history[..history.len().min(PAGE)];

            body.push_str("<h2>history <span class=\"note\">(oldest first)</span></h2>");
            if shown.is_empty() {
                body.push_str("<p class=\"note\">no transactions in this range.</p>");
            } else {
                body.push_str(&history_table(shown, &lock, network));
            }
            if more {
                let next = shown.last().map(|r| r.location.height + 1).unwrap_or(from);
                let _ = write!(
                    body,
                    "<p class=\"nav\"><a href=\"/address/{}?from={}\">more &rarr;</a></p>",
                    esc(key),
                    next
                );
            }
            if from > 0 {
                let _ = write!(
                    body,
                    "<p class=\"nav\"><a href=\"/address/{}\">&larr; back to start</a></p>",
                    esc(key)
                );
            }
        }
        _ => body.push_str(
            "<h2>history</h2><p class=\"warn\">no index is held, so history cannot be shown. \
             Start the node with <code>--index</code>.</p>",
        ),
    }

    // 保有中の UTXO。
    if !utxos.is_empty() {
        body.push_str("<h2>unspent outputs</h2><div class=\"wrap\"><table class=\"list\">");
        body.push_str("<tr class=\"head\"><th>transaction</th><th>index</th><th>amount</th><th>height</th><th>kind</th></tr>");
        for utxo in &utxos {
            let _ = write!(
                body,
                "<tr><td data-label=\"transaction\" class=\"mono trunc\"><a href=\"/tx/{full}\">{short}</a></td>\
                 <td data-label=\"index\" class=\"wide\">{i}</td><td data-label=\"amount\" class=\"num\">{a} OAG</td>\
                 <td data-label=\"height\">{h}</td><td data-label=\"kind\" class=\"wide\">{c}</td></tr>",
                full = esc(&utxo.outpoint.txid.to_string()),
                short = esc(&shorten(&utxo.outpoint.txid.to_string())),
                i = utxo.outpoint.index,
                a = esc(&utxo.entry.output.amount.to_string()),
                h = utxo.entry.height,
                c = if utxo.entry.is_coinbase {
                    "mined"
                } else {
                    "ordinary"
                },
            );
        }
        body.push_str("</table></div>");
    }

    ok(page("address", &body))
}

async fn mempool_page(handle: &NodeHandle) -> Response {
    let txids = match handle.mempool_txids().await {
        Ok(txids) => txids,
        Err(e) => return error_page(&e),
    };
    let mut body = String::new();
    body.push_str(&search_box(""));
    let _ = write!(body, "<h1>mempool ({} entries)</h1>", txids.len());
    if txids.is_empty() {
        body.push_str("<p class=\"note\">there are no unconfirmed transactions.</p>");
    } else {
        body.push_str("<div class=\"wrap\"><table class=\"list\"><tr class=\"head\"><th>transaction ID</th></tr>");
        for txid in &txids {
            let _ = write!(
                body,
                "<tr><td class=\"mono trunc\"><a href=\"/tx/{full}\">{full}</a></td></tr>",
                full = esc(&txid.to_string())
            );
        }
        body.push_str("</table></div>");
    }
    ok(page("mempool", &body))
}

// ━━━━━━━━ 部品 ━━━━━━━━

/// ブロック内の取引表の頁送り。区切る必要が無ければ空文字列を返す。
///
/// # なぜ高さではなくハッシュで繋ぐのか
///
/// 高さで繋ぐと、**サイドチェーンのブロックを開いているときに、続きが
/// アクティブチェーンの同じ高さの別のブロックへ飛ぶ。** ハッシュなら
/// 開いている当のブロックを指す。
fn tx_pager(hash: &Hash, from: usize, upto: usize, total: usize) -> String {
    let here = esc(&hash.to_string());
    let mut pager = String::new();
    if from > 0 {
        let _ = write!(
            pager,
            "<a href=\"/block/{here}?from={f}\">&larr; previous {p}</a> ",
            f = from.saturating_sub(PAGE),
            p = PAGE
        );
    }
    if upto < total {
        let _ = write!(
            pager,
            "<a href=\"/block/{here}?from={f}\">next {p} &rarr;</a>",
            f = upto,
            p = PAGE
        );
    }
    if pager.is_empty() {
        return String::new();
    }
    format!("<p class=\"nav\">{pager}</p>")
}

/// ブロック内の取引を `from` 番目から `upto` 番目の手前まで並べる。
///
/// 位置の番号は**ブロック内の通し番号**であり、頁の中の番号ではない。
/// 0 は必ずコインベースである。
fn tx_table(block: &Block, network: Network, from: usize, upto: usize) -> String {
    let mut out = String::from("<div class=\"wrap\"><table class=\"list\">");
    out.push_str("<tr class=\"head\"><th>#</th><th>transaction ID</th><th>in</th><th>out</th><th>total</th></tr>");
    for (position, tx) in block.transactions[from..upto].iter().enumerate() {
        let position = from + position;
        let total = Amount::sum(tx.outputs.iter().map(|o| o.amount));
        let _ = write!(
            out,
            "<tr><td data-label=\"#\">{p}{cb}</td>\
             <td data-label=\"transaction ID\" class=\"mono trunc\"><a href=\"/tx/{full}\">{short}</a></td>\
             <td data-label=\"in\">{i}</td><td data-label=\"out\">{o}</td>\
             <td data-label=\"total\" class=\"num\">{t} OAG</td></tr>",
            p = position,
            cb = if tx.is_coinbase() {
                " <span class=\"tag\">mined</span>"
            } else {
                ""
            },
            full = esc(&tx.txid().to_string()),
            short = esc(&shorten(&tx.txid().to_string())),
            i = tx.inputs.len(),
            o = tx.outputs.len(),
            t = total
                .map(|a| esc(&a.to_string()))
                .unwrap_or_else(|| "?".to_string()),
        );
    }
    let _ = network;
    out.push_str("</table></div>");
    out
}

fn history_table(records: &[TxRecord], lock: &Lock, network: Network) -> String {
    let mut out = String::from("<div class=\"wrap\"><table class=\"list\">");
    out.push_str("<tr class=\"head\"><th>height</th><th>transaction ID</th><th>change</th></tr>");
    for record in records {
        // このアドレスから見た増減を出す。受け取った出力の合計から、
        // 使った入力の合計を引く。
        let received: u128 = record
            .tx
            .outputs
            .iter()
            .filter(|o| o.lock == *lock)
            .map(|o| o.amount.to_atomic())
            .sum();
        let sent: u128 = record
            .spent
            .iter()
            .flatten()
            .filter(|o| o.lock == *lock)
            .map(|o| o.amount.to_atomic())
            .sum();
        let delta = received as i128 - sent as i128;
        let class = if delta >= 0 { "plus" } else { "minus" };
        let _ = write!(
            out,
            "<tr><td data-label=\"height\"><a href=\"/block/{h}\">{h}</a></td>\
             <td data-label=\"transaction ID\" class=\"mono trunc\"><a href=\"/tx/{full}\">{short}</a></td>\
             <td data-label=\"change\" class=\"num {class}\">{sign}{amount} OAG</td></tr>",
            h = record.location.height,
            full = esc(&record.txid_text()),
            short = esc(&shorten(&record.txid_text())),
            class = class,
            sign = if delta >= 0 { "+" } else { "−" },
            amount = esc(&atomic_to_oag(delta.unsigned_abs())),
        );
    }
    let _ = network;
    out.push_str("</table></div>");
    out
}

fn record_detail(record: &TxRecord, network: Network) -> String {
    let mut out = String::new();
    out.push_str("<div class=\"wrap\"><table class=\"kv\">");
    row_raw(&mut out, "status", "<span class=\"ok\">confirmed</span>");
    row_raw(
        &mut out,
        "block",
        &format!("<a href=\"/block/{h}\">{h}</a>", h = record.location.height),
    );
    row_raw(
        &mut out,
        "block hash",
        &format!(
            "<a class=\"mono break\" href=\"/block/{b}\">{b}</a>",
            b = esc(&record.location.block.to_string())
        ),
    );
    row(
        &mut out,
        "index within the block",
        &record.location.position.to_string(),
    );
    out.push_str("</table></div>");
    out.push_str(&tx_detail(&record.tx, &record.spent, network));
    out
}

fn tx_detail(
    tx: &Transaction,
    spent: &[Option<oag_consensus::tx::TxOutput>],
    network: Network,
) -> String {
    let mut out = String::new();

    out.push_str("<div class=\"wrap\"><table class=\"kv\">");
    row(&mut out, "version", &tx.version.to_string());
    row(&mut out, "size", &format!("{} B", group(tx.size() as u64)));
    row(&mut out, "locktime", &tx.locktime.to_string());
    row(
        &mut out,
        "kind",
        if tx.is_coinbase() {
            "mined (coinbase)"
        } else {
            "ordinary"
        },
    );

    let out_total: u128 = tx.outputs.iter().map(|o| o.amount.to_atomic()).sum();
    // 入力側が全部引けているときだけ手数料を出す。1 つでも欠けていれば
    // 出さない。引けなかった分を 0 として足すと、手数料を多く見せる。
    let in_known =
        !tx.is_coinbase() && spent.len() == tx.inputs.len() && spent.iter().all(|s| s.is_some());
    if in_known {
        let in_total: u128 = spent.iter().flatten().map(|o| o.amount.to_atomic()).sum();
        row(
            &mut out,
            "fee",
            &format!("{} OAG", atomic_to_oag(in_total.saturating_sub(out_total))),
        );
    }
    row(
        &mut out,
        "total out",
        &format!("{} OAG", atomic_to_oag(out_total)),
    );
    out.push_str("</table></div>");

    // 入力。
    out.push_str("<h2>inputs</h2><div class=\"wrap\"><table class=\"list\">");
    if tx.is_coinbase() {
        out.push_str(
            "<tr><td class=\"note\">newly issued by mining. no outputs were spent.</td></tr>",
        );
    } else {
        out.push_str(
            "<tr class=\"head\"><th>source transaction</th><th>index</th><th>address</th><th>amount</th></tr>",
        );
        for (n, input) in tx.inputs.iter().enumerate() {
            let prev = spent.get(n).and_then(|s| s.as_ref());
            let (addr, amount) = match prev {
                Some(prev) => (
                    prev.lock
                        .to_address(network)
                        .ok()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| format!("version {}", prev.lock.version())),
                    format!("{} OAG", prev.amount),
                ),
                // 索引が無い、あるいは未確定の取引では引けない。
                None => ("unknown".to_string(), "unknown".to_string()),
            };
            let _ = write!(
                out,
                "<tr><td data-label=\"source transaction\" class=\"mono trunc\"><a href=\"/tx/{full}\">{short}</a></td>\
                 <td data-label=\"index\">{i}</td>\
                 <td data-label=\"address\" class=\"mono trunc\"><a href=\"/address/{a}\">{a_short}</a></td>\
                 <td data-label=\"amount\" class=\"num\">{amount}</td></tr>",
                full = esc(&input.prev_out.txid.to_string()),
                short = esc(&shorten(&input.prev_out.txid.to_string())),
                i = input.prev_out.index,
                a = esc(&addr),
                a_short = esc(&shorten(&addr)),
                amount = esc(&amount),
            );
        }
    }
    out.push_str("</table></div>");

    // 出力。
    out.push_str("<h2>outputs</h2><div class=\"wrap\"><table class=\"list\">");
    out.push_str("<tr class=\"head\"><th>#</th><th>address</th><th>amount</th></tr>");
    for (n, output) in tx.outputs.iter().enumerate() {
        let addr = output
            .lock
            .to_address(network)
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_else(|| format!("version {} (unknown)", output.lock.version()));
        let _ = write!(
            out,
            "<tr><td data-label=\"#\">{n}</td>\
             <td data-label=\"address\" class=\"mono trunc\"><a href=\"/address/{a}\">{a_short}</a></td>\
             <td data-label=\"amount\" class=\"num\">{amount} OAG</td></tr>",
            n = n,
            a = esc(&addr),
            a_short = esc(&shorten(&addr)),
            amount = esc(&output.amount.to_string()),
        );
    }
    out.push_str("</table></div>");
    out
}

fn search_box(value: &str) -> String {
    format!(
        "<form class=\"search\" action=\"/search\" method=\"get\">\
         <input name=\"q\" value=\"{}\" placeholder=\"height, block, transaction ID or address\" \
         autocapitalize=\"off\" autocomplete=\"off\" spellcheck=\"false\">\
         <button type=\"submit\">search</button></form>",
        esc(value)
    )
}

fn stat(out: &mut String, label: &str, value: &str) {
    let _ = write!(
        out,
        "<div class=\"stat\"><div class=\"label\">{}</div><div class=\"value\">{}</div></div>",
        esc(label),
        value
    );
}

fn row(out: &mut String, label: &str, value: &str) {
    let _ = write!(
        out,
        "<tr><th>{}</th><td>{}</td></tr>",
        esc(label),
        esc(value)
    );
}

fn row_raw(out: &mut String, label: &str, value: &str) {
    let _ = write!(out, "<tr><th>{}</th><td>{}</td></tr>", esc(label), value);
}

fn ok(body: String) -> Response {
    Response {
        status: "200 OK",
        body,
    }
}

fn not_found(message: &str) -> Response {
    Response {
        status: "404 Not Found",
        body: page(
            "not found",
            &format!(
                "{}<h1>not found</h1><p>{}</p>",
                search_box(""),
                esc(message)
            ),
        ),
    }
}

fn error_page(message: &str) -> Response {
    Response {
        status: "500 Internal Server Error",
        body: page(
            "error",
            &format!("{}<h1>error</h1><p>{}</p>", search_box(""), esc(message)),
        ),
    }
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"ja\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex, nofollow\">\
         <title>{title} · Orange</title><style>{css}</style></head>\
         <body><header><a class=\"brand\" href=\"/\">Orange <span>OAG</span></a>\
         <nav><a href=\"/\">overview</a> <a href=\"/mempool\">mempool</a></nav></header>\
         <main>{body}</main>\
         <footer>A local, read-only explorer. It cannot send coins or change settings.</footer>\
         </body></html>",
        title = esc(title),
        css = CSS,
        body = body,
    )
}

pub(crate) const CSS: &str = "\
:root{--bg:#fff;--fg:#1a1a1a;--dim:#666;--line:#e3e3e3;--accent:#e8720c;--card:#faf9f7;}\
@media (prefers-color-scheme:dark){:root{--bg:#16150f;--fg:#ececec;--dim:#9a9a9a;--line:#333;--accent:#ff9f45;--card:#1f1e18;}}\
*{box-sizing:border-box}\
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 system-ui,-apple-system,'Hiragino Sans','Noto Sans JP',sans-serif;}\
header{display:flex;flex-wrap:wrap;gap:12px;align-items:baseline;justify-content:space-between;\
padding:14px 16px;border-bottom:1px solid var(--line);}\
.brand{font-weight:700;font-size:18px;color:var(--accent);text-decoration:none}\
.brand span{color:var(--dim);font-weight:400;font-size:13px}\
nav a{color:var(--dim);text-decoration:none;margin-left:12px}\
nav a:hover{color:var(--accent)}\
main{max-width:960px;margin:0 auto;padding:16px;}\
footer{max-width:960px;margin:0 auto;padding:24px 16px;color:var(--dim);font-size:12px}\
h1{font-size:20px;margin:16px 0 4px}h2{font-size:16px;margin:28px 0 8px}\
a{color:var(--accent)}\
.search{display:flex;gap:8px;margin:8px 0 20px}\
.search input{flex:1;min-width:0;padding:10px 12px;border:1px solid var(--line);border-radius:8px;\
background:var(--card);color:var(--fg);font-size:16px}\
.search button{padding:10px 16px;border:0;border-radius:8px;background:var(--accent);color:#fff;font-size:15px;cursor:pointer}\
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:12px 0}\
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}\
.stat .label{color:var(--dim);font-size:12px}\
.stat .value{font-size:18px;font-variant-numeric:tabular-nums;margin-top:2px}\
.wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border:1px solid var(--line);border-radius:10px}\
table{border-collapse:collapse;width:100%;min-width:480px}\
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}\
tr:last-child th,tr:last-child td{border-bottom:0}\
th{color:var(--dim);font-weight:500;font-size:13px}\
.num{text-align:right;font-variant-numeric:tabular-nums}\
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}\
.break{word-break:break-all;white-space:normal}\
.trunc{max-width:22ch;overflow:hidden;text-overflow:ellipsis}\
table.kv{min-width:0}.kv th{width:1%}.kv td{white-space:normal;overflow-wrap:anywhere}\
@media (max-width:600px){\
table.list{min-width:0}.list,.list tbody,.list tr,.list td{display:block}.list tr.head{display:none}\
.list tr{padding:8px 12px;border-bottom:1px solid var(--line)}.list tr:last-child{border-bottom:0}\
.list td{display:flow-root;padding:2px 0;border:0;white-space:normal;text-align:right;overflow-wrap:anywhere}\
.list td.trunc{max-width:none;overflow:visible}.list td:not([data-label]){text-align:left}.list td.wide{display:none}\
.list td[data-label]::before{content:attr(data-label);float:left;margin-right:12px;color:var(--dim);\
font-family:system-ui,-apple-system,sans-serif;font-size:13px;line-height:24px}}\
.note{color:var(--dim);font-size:13px}\
.warn{color:#d97706}.ok{color:#16a34a}\
.plus{color:#16a34a}.minus{color:#dc2626}\
.tag{background:var(--card);border:1px solid var(--line);border-radius:4px;padding:0 4px;font-size:11px;color:var(--dim)}\
.nav{margin:16px 0}\
code{background:var(--card);border:1px solid var(--line);border-radius:4px;padding:1px 5px;font-size:13px}\
";

// ━━━━━━━━ 変換 ━━━━━━━━

/// HTML に埋め込むための逃がし。
///
/// **経路もクエリも利用者が決める文字列である。** そのまま埋めると、
/// 局所の頁とはいえ任意の script を仕込める。すべての埋め込みはここを通す。
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// 長い識別子を頭と尻だけにする。
fn shorten(s: &str) -> String {
    if s.chars().count() <= 20 {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let head: String = chars[..10].iter().collect();
    let tail: String = chars[chars.len() - 6..].iter().collect();
    format!("{head}…{tail}")
}

/// 3 桁ごとに区切る。
fn group(n: u64) -> String {
    let text = n.to_string();
    let mut out = String::with_capacity(text.len() + text.len() / 3);
    for (i, c) in text.chars().enumerate() {
        if i > 0 && (text.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// 最小単位を OAG の表記にする。
fn atomic_to_oag(atomic: u128) -> String {
    match Amount::from_atomic(atomic) {
        Ok(amount) => amount.to_string(),
        Err(_) => atomic.to_string(),
    }
}

/// Unix 秒を UTC の表記にする。
///
/// 暦の変換は Howard Hinnant の `civil_from_days` による。外部の暦を
/// 引き込むほどの用途ではない。
fn utc(timestamp: i64) -> String {
    let days = timestamp.div_euclid(86_400);
    let secs = timestamp.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// パーセント符号化を戻す。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// クエリ文字列から 1 つ取り出す。
fn query_value(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=')?;
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}

impl TxRecord {
    fn txid_text(&self) -> String {
        self.location.txid.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_that_goes_into_a_page_is_escaped() {
        assert_eq!(esc("<script>"), "&lt;script&gt;");
        assert_eq!(esc("a&b"), "a&amp;b");
        assert_eq!(esc("\"><svg"), "&quot;&gt;&lt;svg");
        assert_eq!(esc("it's"), "it&#39;s");
        // 日本語はそのまま通る。
        assert_eq!(esc("height"), "height");
    }

    #[test]
    fn percent_encoding_is_undone() {
        assert_eq!(percent_decode("/address/%3Cscript%3E"), "/address/<script>");
        assert_eq!(percent_decode("a+b"), "a b");
        // 半端な % はそのまま残す。落とすと別の文字列になる。
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn a_query_value_is_picked_out_by_name() {
        assert_eq!(query_value("q=abc&from=5", "q").as_deref(), Some("abc"));
        assert_eq!(query_value("q=abc&from=5", "from").as_deref(), Some("5"));
        assert_eq!(query_value("q=abc", "missing"), None);
        assert_eq!(query_value("", "q"), None);
    }

    #[test]
    fn timestamps_are_shown_as_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00:00");
        assert_eq!(utc(1_700_000_000), "2023-11-14 22:13:20");
        // 閏年の 2 月 29 日を跨ぐところ。
        assert_eq!(utc(1_709_164_800), "2024-02-29 00:00:00");
        // 1970 より前も崩れない。
        assert_eq!(utc(-1), "1969-12-31 23:59:59");
    }

    #[test]
    fn long_identifiers_are_shortened_in_the_middle() {
        let hash = "0".repeat(64);
        let short = shorten(&hash);
        assert!(short.contains('…'));
        assert!(short.len() < hash.len());
        // 短いものはそのまま。
        assert_eq!(shorten("abc"), "abc");
    }

    /// 取引を `count` 件持つブロック。0 番目はコインベースにする。
    fn block_of(count: usize) -> Block {
        use oag_consensus::tx::{OutPoint, TxInput, TxOutput, CURRENT_TX_VERSION};
        use oag_consensus::BlockHeader;
        use oag_primitives::{hash, SecretKey};

        let lock = Lock::pay_to_pubkey(&SecretKey::generate().public_key());
        let transactions = (0..count)
            .map(|i| Transaction {
                version: CURRENT_TX_VERSION,
                inputs: vec![if i == 0 {
                    TxInput::new(OutPoint::null())
                } else {
                    TxInput::new(OutPoint::new(hash::txid(&[i as u8]), 0))
                }],
                outputs: vec![TxOutput::new(
                    Amount::from_atomic(i as u128 + 1).unwrap(),
                    lock.clone(),
                )],
                locktime: 0,
            })
            .collect();
        Block {
            header: BlockHeader {
                version: 0,
                prev_hash: Hash::ZERO,
                merkle_root: Hash::ZERO,
                timestamp: 1_800_000_000,
                difficulty: 1,
                height: 7,
                nonce: 0,
            },
            transactions,
        }
    }

    #[test]
    fn a_page_of_transactions_keeps_the_numbering_of_the_whole_block() {
        // **頁の中の番号ではなく、ブロック内の通し番号を出す。** ここが
        // ずれると、表の `#` が索引の位置と食い違い、`/tx/` の照合結果と
        // 説明がつかなくなる。
        let block = block_of(5);
        let table = tx_table(&block, Network::Mainnet, 2, 5);

        assert!(
            table.contains("<td data-label=\"#\">2</td>"),
            "it does not start from the second"
        );
        assert!(
            table.contains("<td data-label=\"#\">4</td>"),
            "the last, fourth one is missing"
        );
        assert!(
            !table.contains("<td data-label=\"#\">0</td>"),
            "the zeroth, outside the page, is shown"
        );
        assert!(
            !table.contains("<td data-label=\"#\">5</td>"),
            "a fifth that does not exist is shown"
        );

        // 採掘の印は 0 番目だけのもの。2 件目以降の頁には出ない。
        assert!(
            !table.contains("mined"),
            "shown as mined although it is not a coinbase"
        );

        // 先頭の頁には出る。
        let first = tx_table(&block, Network::Mainnet, 0, 2);
        assert!(first.contains("mined"));
    }

    #[test]
    fn the_pager_points_at_the_block_being_read_not_at_a_height() {
        // **高さで繋ぐと、サイドチェーンのブロックを開いているとき、
        // 続きがアクティブチェーンの別のブロックへ飛ぶ。**
        let hash = block_of(1).header.hash();
        let here = hash.to_string();

        // 真ん中の頁。前にも次にも行ける。
        let mid = tx_pager(&hash, PAGE, PAGE * 2, PAGE * 3);
        assert!(mid.contains(&format!("/block/{here}?from=0")), "{mid}");
        assert!(
            mid.contains(&format!("/block/{here}?from={}", PAGE * 2)),
            "{mid}"
        );

        // 先頭の頁に「前」は無い。
        let first = tx_pager(&hash, 0, PAGE, PAGE * 2);
        assert!(!first.contains("previous "));
        assert!(first.contains("next "));

        // 末尾の頁に「次」は無い。
        let last = tx_pager(&hash, PAGE, PAGE * 2, PAGE * 2);
        assert!(last.contains("previous "));
        assert!(!last.contains("next "));

        // 区切る必要が無ければ何も出さない。
        assert_eq!(tx_pager(&hash, 0, 3, 3), "");
    }

    #[test]
    fn an_empty_range_renders_a_table_with_no_rows() {
        // 高さの末尾を越えて `from` を指定されても落ちない。
        let block = block_of(3);
        let table = tx_table(&block, Network::Mainnet, 3, 3);
        assert!(table.contains("<th>#</th>"));
        assert!(!table.contains("/tx/"));
    }

    #[test]
    fn numbers_are_grouped_in_threes() {
        assert_eq!(group(0), "0");
        assert_eq!(group(999), "999");
        assert_eq!(group(1_000), "1,000");
        assert_eq!(group(24_850), "24,850");
        assert_eq!(group(1_234_567), "1,234,567");
    }
}
