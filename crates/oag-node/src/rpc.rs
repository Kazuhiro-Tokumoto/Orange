//! ノードが提供する JSON-RPC の手続き。
//!
//! 運び方は [`oag_rpc`] が担う。ここが決めるのは、どんな手続きがあり、
//! 何を返すかである。
//!
//! # 手続きの一覧
//!
//! | 名前 | 引数 | 返すもの |
//! | --- | --- | --- |
//! | `getinfo` | なし | ネットワーク・高さ・先端・難易度・剪定の有無など |
//! | `getblockcount` | なし | アクティブチェーンの高さ |
//! | `getbestblockhash` | なし | 先端のブロックハッシュ |
//! | `getblockhash` | `[高さ]` | その高さのブロックハッシュ |
//! | `getblockheader` | `[ハッシュ]` | ヘッダの中身 |
//! | `getblock` | `[ハッシュ, 詳細=true]` | ブロック。`false` なら 16 進 |
//! | `getrawtransaction` | `[txid, 詳細=false]` | 取引。索引が無ければ mempool のみ |
//! | `getaddresshistory` | `[アドレス, 開始=0, 件数=100]` | そのアドレスに触れた取引 |
//! | `getindexinfo` | なし | 索引を持っているか |
//! | `getmempool` | なし | mempool の txid 一覧 |
//! | `sendrawtransaction` | `[16 進]` | 受理された txid |
//! | `scanutxos` | `[[アドレス, …]]` | 一致する UTXO |
//!
//! # 索引は任意である
//!
//! コンセンサスが必要とする索引は UTXO セットだけである。txid から取引を
//! 引く索引も、支払い条件から取引を引く索引も、**検証には要らない**
//! (`docs/SPEC.md` §19)。満杯のブロックが続けば年 37 GB を要するので、
//! 既定では作らない。
//!
//! 運用者が `--index` を付けたときだけ作られ、そのとき
//! `getrawtransaction` は確定した取引も引けるようになり、
//! `getaddresshistory` が使えるようになる。
//!
//! **索引が無いときは、空の答えではなく誤りを返す。** 「見つからない」と
//! 答えると、呼び出し側はそれを「その取引は存在しない」と受け取るためで
//! ある。索引の有無は `getindexinfo` で分かる。
//!
//! # `scanutxos` が全件走査である理由
//!
//! 残高は UTXO セットを丸ごと見て拾う。こちらは索引の有無によらず動く。
//! bitcoind の `scantxoutset` と同じ方式である。

use crate::service::{NodeHandle, TxRecord, UtxoRecord};
use oag_consensus::codec::{Decode, Encode};
use oag_consensus::lock::Lock;
use oag_consensus::{Block, BlockHeader, Transaction};
use oag_primitives::{Address, Amount, Hash, Network};
use oag_rpc::jsonrpc::{
    Id, Request, Response, RpcError, INTERNAL_ERROR, INVALID_REQUEST, NODE_ERROR, PARSE_ERROR,
    TX_REJECTED, VERSION,
};
use serde_json::{json, Value};

/// 1 度の走査で返す UTXO の上限。
///
/// 応答が際限なく膨らまないようにする。これを超える場合はアドレスを
/// 分けて呼ぶ。
const MAX_SCAN_RESULTS: usize = 10_000;

/// 要求を 1 個処理し、応答の JSON を返す。
pub async fn handle(handle: NodeHandle, body: String) -> String {
    let response = dispatch(&handle, &body).await;
    serde_json::to_string(&response).unwrap_or_else(|e| {
        // 応答を JSON にできないのは組み立て側の誤りである。せめて
        // 形の整った誤りを返す。
        format!(
            r#"{{"jsonrpc":"{VERSION}","error":{{"code":{INTERNAL_ERROR},"message":"cannot assemble the response: {e}"}},"id":null}}"#
        )
    })
}

async fn dispatch(handle: &NodeHandle, body: &str) -> Response {
    let request: Request = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(e) => {
            return Response::err(
                None,
                RpcError::new(PARSE_ERROR, format!("cannot read: {e}")),
            )
        }
    };
    if request.jsonrpc != VERSION {
        return Response::err(
            Some(request.id),
            RpcError::new(INVALID_REQUEST, format!("jsonrpc must be \"{VERSION}\"")),
        );
    }

    let id = request.id.clone();
    match call(handle, &request.method, request.params.unwrap_or(json!([]))).await {
        Ok(result) => Response::ok(Some(id), result),
        Err(error) => Response::err(Some(id), error),
    }
}

/// 引数の並びから `index` 番目を取り出す。
fn arg(params: &Value, index: usize, name: &str) -> Result<Value, RpcError> {
    params
        .get(index)
        .cloned()
        .ok_or_else(|| RpcError::invalid_params(format!("the argument {name} is required")))
}

fn as_str(value: &Value, name: &str) -> Result<String, RpcError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| RpcError::invalid_params(format!("{name} must be a string")))
}

fn as_hash(value: &Value, name: &str) -> Result<Hash, RpcError> {
    let text = as_str(value, name)?;
    text.parse()
        .map_err(|_| RpcError::invalid_params(format!("{name} must be 64 hex digits")))
}

fn as_u64(value: &Value, name: &str) -> Result<u64, RpcError> {
    value
        .as_u64()
        .ok_or_else(|| RpcError::invalid_params(format!("{name} must be an integer of 0 or more")))
}

fn from_hex(text: &str, name: &str) -> Result<Vec<u8>, RpcError> {
    hex_decode(text).ok_or_else(|| RpcError::invalid_params(format!("{name} is not valid hex")))
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// ノードとのやり取りが失敗した。
fn node_error(message: String) -> RpcError {
    RpcError::new(NODE_ERROR, message)
}

async fn call(handle: &NodeHandle, method: &str, params: Value) -> Result<Value, RpcError> {
    match method {
        "getinfo" => get_info(handle).await,
        "getblockcount" => {
            let status = handle.status().await.map_err(node_error)?;
            Ok(json!(status.height))
        }
        "getbestblockhash" => {
            let status = handle.status().await.map_err(node_error)?;
            Ok(json!(status.tip.to_string()))
        }
        "getblockhash" => {
            let height = as_u64(&arg(&params, 0, "height")?, "height")?;
            let hash = handle.hash_at_height(height).await.map_err(node_error)?;
            hash.map(|h| json!(h.to_string()))
                .ok_or_else(|| RpcError::not_found(format!("there is no block at height {height}")))
        }
        "getblockheader" => {
            let hash = as_hash(&arg(&params, 0, "hash")?, "hash")?;
            let entry = handle
                .entry(hash)
                .await
                .map_err(node_error)?
                .ok_or_else(|| RpcError::not_found(format!("block {hash} is unknown")))?;
            Ok(json!({
                "hash": entry.hash.to_string(),
                "header": header_json(&entry.header),
                "cumulativework": entry.cumulative_work.to_string(),
                "status": status_name(entry.status),
            }))
        }
        "getblock" => get_block(handle, &params).await,
        "getrawtransaction" => get_raw_transaction(handle, &params).await,
        "getaddresshistory" => get_address_history(handle, &params).await,
        "getindexinfo" => {
            let from = handle.index_from().await.map_err(node_error)?;
            Ok(json!({ "indexed": from.is_some(), "from": from }))
        }
        "getmempool" => {
            let txids = handle.mempool_txids().await.map_err(node_error)?;
            Ok(json!(txids
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<String>>()))
        }
        "sendrawtransaction" => send_raw_transaction(handle, &params).await,
        "scanutxos" => scan_utxos(handle, &params).await,
        other => Err(RpcError::method_not_found(other)),
    }
}

async fn get_info(handle: &NodeHandle) -> Result<Value, RpcError> {
    let status = handle.status().await.map_err(node_error)?;
    let best_header = handle.best_header_height().await.map_err(node_error)?;
    Ok(json!({
        "network": status.network.to_string(),
        "height": status.height,
        "bestheaderheight": best_header,
        "bestblockhash": status.tip.to_string(),
        // 累積作業量は u128 で、JSON の数値では表しきれない。文字列で返す。
        "cumulativework": status.cumulative_work.to_string(),
        "nextdifficulty": status.next_difficulty,
        "utxocount": status.utxo_count,
        "indexedblocks": status.indexed_blocks,
        "mempoolsize": status.mempool_len,
        "knownaddresses": status.known_addresses,
        // 剪定していなければ 0 で、「創世から全部ある」を意味する。
        // 0 でなければ、それより下のブロックは配れない (SPEC §14.5)。
        "blocksfrom": status.blocks_from,
        "pruned": status.blocks_from > 0,
    }))
}

async fn get_block(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let hash = as_hash(&arg(params, 0, "hash")?, "hash")?;
    // 既定は中身を展開して返す。false なら 16 進のまま返す。
    let verbose = params.get(1).and_then(Value::as_bool).unwrap_or(true);

    let block = handle
        .block(hash)
        .await
        .map_err(node_error)?
        .ok_or_else(|| RpcError::not_found(format!("the body of block {hash} is not held")))?;

    if !verbose {
        return Ok(json!(to_hex(&block.encode())));
    }
    Ok(block_json(&hash, &block, handle.network()))
}

async fn send_raw_transaction(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let text = as_str(&arg(params, 0, "hex")?, "hex")?;
    let bytes = from_hex(&text, "hex")?;
    let tx = Transaction::decode(&bytes)
        .map_err(|e| RpcError::invalid_params(format!("cannot be read as a transaction: {e}")))?;

    let txid = handle
        .submit_tx(tx)
        .await
        .map_err(|e| RpcError::new(TX_REJECTED, e))?;
    Ok(json!(txid.to_string()))
}

/// 1 度に返す履歴の上限。
///
/// 応答が際限なく膨らまないようにする。続きは `開始` をずらして呼ぶ。
const MAX_HISTORY_RESULTS: usize = 1_000;

async fn get_raw_transaction(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let txid = as_hash(&arg(params, 0, "txid")?, "txid")?;
    let verbose = params.get(1).and_then(Value::as_bool).unwrap_or(false);
    let network = handle.network();

    // 確定したものを先に見る。索引が無ければ mempool だけになる。
    if handle.index_from().await.map_err(node_error)?.is_some() {
        if let Some(record) = handle.tx_record(txid).await.map_err(node_error)? {
            return Ok(if verbose {
                record_json(&record, network)
            } else {
                json!(to_hex(&record.tx.encode()))
            });
        }
    }

    if let Some(tx) = handle.mempool_tx(txid).await.map_err(node_error)? {
        let mut value = if verbose {
            tx_json(&tx, network)
        } else {
            return Ok(json!(to_hex(&tx.encode())));
        };
        if let Some(map) = value.as_object_mut() {
            map.insert("confirmed".to_string(), json!(false));
        }
        return Ok(value);
    }

    // 索引が無い場合は「無い」ではなく「引けない」と答える。取り違えると
    // 呼び出し側が、確定済みの取引を存在しないものとして扱う。
    if handle.index_from().await.map_err(node_error)?.is_none() {
        return Err(RpcError::not_found(format!(
            "{txid} is not in the mempool. Looking up a confirmed transaction by txid needs the index (start with --index).\
             Without one, fetch the block that contains it with getblock and search inside it"
        )));
    }
    Err(RpcError::not_found(format!(
        "there is no transaction {txid}"
    )))
}

async fn get_address_history(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let text = as_str(&arg(params, 0, "address")?, "address")?;
    let network = handle.network();
    let address = Address::decode_on(network, &text)
        .map_err(|e| RpcError::invalid_params(format!("the address {text} is invalid: {e}")))?;
    let lock = Lock::from_address(&address);

    let from = match params.get(1) {
        Some(value) if !value.is_null() => as_u64(value, "from")?,
        _ => 0,
    };
    let count = match params.get(2) {
        Some(value) if !value.is_null() => as_u64(value, "count")? as usize,
        _ => 100,
    }
    .min(MAX_HISTORY_RESULTS);

    if handle.index_from().await.map_err(node_error)?.is_none() {
        return Err(node_error(
            "no index is held, so history cannot be looked up (start the node with --index)"
                .to_string(),
        ));
    }

    let history = handle
        .address_history(lock, from, count)
        .await
        .map_err(node_error)?;

    Ok(json!({
        "address": text,
        "from": from,
        "count": history.len(),
        // 上限に達したなら、返した分がすべてではない。次は最後の高さから
        // 続きを頼む。呼び出し側がそれを知らないまま履歴を出すと、途中で
        // 切れたものを全部だと思い込む。
        "truncated": history.len() >= count,
        "tx": history
            .iter()
            .map(|record| record_json(record, network))
            .collect::<Vec<Value>>(),
    }))
}

async fn scan_utxos(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let list = arg(params, 0, "addresses")?;
    let entries = list
        .as_array()
        .ok_or_else(|| RpcError::invalid_params("addresses must be an array of addresses"))?;

    let network = handle.network();
    let mut locks = Vec::with_capacity(entries.len());
    let mut texts = Vec::with_capacity(entries.len());
    for entry in entries {
        let text = as_str(entry, "address")?;
        let address = Address::decode_on(network, &text)
            .map_err(|e| RpcError::invalid_params(format!("the address {text} is invalid: {e}")))?;
        locks.push(Lock::from_address(&address));
        texts.push(text);
    }

    let found = handle
        .scan_utxos(locks.clone(), MAX_SCAN_RESULTS)
        .await
        .map_err(node_error)?;

    let total = Amount::sum(found.iter().map(|r| r.entry.output.amount))
        .ok_or_else(|| RpcError::new(NODE_ERROR, "the total overflowed"))?;

    Ok(json!({
        "total": total.to_atomic().to_string(),
        "totaloag": total.to_string(),
        "count": found.len(),
        // 上限に達したなら、返した分がすべてではない。呼び出し側が
        // それを知らないまま残高を出すと、実際より少なく見える。
        "truncated": found.len() >= MAX_SCAN_RESULTS,
        "utxos": found
            .iter()
            .map(|record| utxo_json(record, &locks, &texts))
            .collect::<Vec<Value>>(),
    }))
}

fn utxo_json(record: &UtxoRecord, locks: &[Lock], texts: &[String]) -> Value {
    let address = locks
        .iter()
        .position(|l| *l == record.entry.output.lock)
        .map(|i| texts[i].clone());
    json!({
        "txid": record.outpoint.txid.to_string(),
        "index": record.outpoint.index,
        "amount": record.entry.output.amount.to_atomic().to_string(),
        "amountoag": record.entry.output.amount.to_string(),
        "height": record.entry.height,
        "coinbase": record.entry.is_coinbase,
        "address": address,
        "lockversion": record.entry.output.lock.version(),
        "lock": to_hex(record.entry.output.lock.payload()),
    })
}

/// 索引が見つけた取引。入力側の金額と相手まで埋めて返す。
fn record_json(record: &TxRecord, network: Network) -> Value {
    let mut value = tx_json(&record.tx, network);
    if let Some(map) = value.as_object_mut() {
        map.insert("confirmed".to_string(), json!(true));
        map.insert("height".to_string(), json!(record.location.height));
        map.insert(
            "blockhash".to_string(),
            json!(record.location.block.to_string()),
        );
        map.insert("position".to_string(), json!(record.location.position));

        // 入力が指す出力を、同じ並びで vin に足す。これが無いと
        // 「いくら・誰から」が表示できない。
        if let Some(Value::Array(vin)) = map.get_mut("vin") {
            for (slot, spent) in vin.iter_mut().zip(record.spent.iter()) {
                let Some(prev) = spent else { continue };
                let Some(slot) = slot.as_object_mut() else {
                    continue;
                };
                slot.insert(
                    "amount".to_string(),
                    json!(prev.amount.to_atomic().to_string()),
                );
                slot.insert("amountoag".to_string(), json!(prev.amount.to_string()));
                slot.insert(
                    "address".to_string(),
                    json!(prev.lock.to_address(network).ok().map(|a| a.to_string())),
                );
            }
        }
    }
    value
}

fn header_json(header: &BlockHeader) -> Value {
    json!({
        "version": header.version,
        "previousblockhash": header.prev_hash.to_string(),
        "merkleroot": header.merkle_root.to_string(),
        "time": header.timestamp,
        "difficulty": header.difficulty,
        "height": header.height,
        "nonce": header.nonce,
    })
}

fn block_json(hash: &Hash, block: &Block, network: Network) -> Value {
    json!({
        "hash": hash.to_string(),
        "size": block.size(),
        "header": header_json(&block.header),
        "tx": block
            .transactions
            .iter()
            .map(|tx| tx_json(tx, network))
            .collect::<Vec<Value>>(),
    })
}

fn tx_json(tx: &Transaction, network: Network) -> Value {
    json!({
        "txid": tx.txid().to_string(),
        "version": tx.version,
        "size": tx.size(),
        "locktime": tx.locktime,
        "coinbase": tx.is_coinbase(),
        "vin": tx
            .inputs
            .iter()
            .map(|input| json!({
                "txid": input.prev_out.txid.to_string(),
                "index": input.prev_out.index,
                "signature": to_hex(&input.signature),
                "sequence": input.sequence,
            }))
            .collect::<Vec<Value>>(),
        "vout": tx
            .outputs
            .iter()
            .enumerate()
            .map(|(n, out)| json!({
                "n": n,
                "amount": out.amount.to_atomic().to_string(),
                "amountoag": out.amount.to_string(),
                "lockversion": out.lock.version(),
                "lock": to_hex(out.lock.payload()),
                "address": out.lock.to_address(network).ok().map(|a| a.to_string()),
            }))
            .collect::<Vec<Value>>(),
    })
}

fn status_name(status: oag_chain::index::BlockStatus) -> &'static str {
    use oag_chain::index::BlockStatus;
    match status {
        BlockStatus::HeaderOnly => "headeronly",
        BlockStatus::HeaderValid => "headervalid",
        BlockStatus::FullyValid => "fullyvalid",
        BlockStatus::Invalid => "invalid",
    }
}

/// 応答を組み立てる側の識別子を、要求のものと揃える。
///
/// 手続きの中で使うわけではないが、試験が識別子の扱いを確かめられる
/// ようにしておく。
pub fn echo_id(request: &Request) -> Id {
    request.id.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes = vec![0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(to_hex(&bytes), "000fa5ff");
        assert_eq!(hex_decode("000fa5ff"), Some(bytes));
    }

    #[test]
    fn odd_length_hex_is_refused() {
        // 半端な 16 進を黙って切り捨てると、別の取引を送ったことになる。
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
    }

    #[test]
    fn arguments_are_checked() {
        let params = json!(["abc", 5]);
        assert!(as_u64(&arg(&params, 1, "n").unwrap(), "n").is_ok());
        assert!(as_u64(&arg(&params, 0, "n").unwrap(), "n").is_err());
        assert!(arg(&params, 2, "missing").is_err());
        // 負の高さは受け付けない。
        assert!(as_u64(&json!(-1), "height").is_err());
    }
}
