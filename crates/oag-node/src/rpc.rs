//! ノードが提供する JSON-RPC の手続き。
//!
//! 運び方は [`oag_rpc`] が担う。ここが決めるのは、どんな手続きがあり、
//! 何を返すかである。
//!
//! # 手続きの一覧
//!
//! | 名前 | 引数 | 返すもの |
//! | --- | --- | --- |
//! | `getinfo` | なし | ネットワーク・高さ・先端・難易度など |
//! | `getblockcount` | なし | アクティブチェーンの高さ |
//! | `getbestblockhash` | なし | 先端のブロックハッシュ |
//! | `getblockhash` | `[高さ]` | その高さのブロックハッシュ |
//! | `getblockheader` | `[ハッシュ]` | ヘッダの中身 |
//! | `getblock` | `[ハッシュ, 詳細=true]` | ブロック。`false` なら 16 進 |
//! | `getrawtransaction` | `[txid]` | mempool にあれば 16 進 |
//! | `getmempool` | なし | mempool の txid 一覧 |
//! | `sendrawtransaction` | `[16 進]` | 受理された txid |
//! | `scanutxos` | `[[アドレス, …]]` | 一致する UTXO |
//!
//! # `getrawtransaction` が mempool しか見ない理由
//!
//! txid から取引を引く索引を持っていない (`docs/SPEC.md` の未決事項)。
//! コンセンサスが必要とする索引は UTXO セットだけであり、全取引の索引は
//! チェーンの 1/3 に相当する容量を要する。**確定した取引を引きたい場合は、
//! それが入っているブロックを `getblock` で取り、その中から探す。**
//!
//! # `scanutxos` が全件走査である理由
//!
//! 同じ理由で、支払い条件から UTXO を引く索引も無い。ウォレットは
//! UTXO セットを丸ごと見て自分のものを拾う。bitcoind の `scantxoutset`
//! と同じ方式である。

use crate::service::{NodeHandle, UtxoRecord};
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
            r#"{{"jsonrpc":"{VERSION}","error":{{"code":{INTERNAL_ERROR},"message":"応答を組み立てられない: {e}"}},"id":null}}"#
        )
    })
}

async fn dispatch(handle: &NodeHandle, body: &str) -> Response {
    let request: Request = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(e) => return Response::err(None, RpcError::new(PARSE_ERROR, format!("読めない: {e}"))),
    };
    if request.jsonrpc != VERSION {
        return Response::err(
            Some(request.id),
            RpcError::new(
                INVALID_REQUEST,
                format!("jsonrpc は \"{VERSION}\" であること"),
            ),
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
        .ok_or_else(|| RpcError::invalid_params(format!("引数 {name} が要る")))
}

fn as_str(value: &Value, name: &str) -> Result<String, RpcError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| RpcError::invalid_params(format!("{name} は文字列であること")))
}

fn as_hash(value: &Value, name: &str) -> Result<Hash, RpcError> {
    let text = as_str(value, name)?;
    text.parse()
        .map_err(|_| RpcError::invalid_params(format!("{name} は 64 桁の 16 進であること")))
}

fn as_u64(value: &Value, name: &str) -> Result<u64, RpcError> {
    value
        .as_u64()
        .ok_or_else(|| RpcError::invalid_params(format!("{name} は 0 以上の整数であること")))
}

fn from_hex(text: &str, name: &str) -> Result<Vec<u8>, RpcError> {
    hex_decode(text).ok_or_else(|| RpcError::invalid_params(format!("{name} が 16 進として不正")))
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
                .ok_or_else(|| RpcError::not_found(format!("高さ {height} のブロックは無い")))
        }
        "getblockheader" => {
            let hash = as_hash(&arg(&params, 0, "hash")?, "hash")?;
            let entry = handle
                .entry(hash)
                .await
                .map_err(node_error)?
                .ok_or_else(|| RpcError::not_found(format!("ブロック {hash} を知らない")))?;
            Ok(json!({
                "hash": entry.hash.to_string(),
                "header": header_json(&entry.header),
                "cumulativework": entry.cumulative_work.to_string(),
                "status": status_name(entry.status),
            }))
        }
        "getblock" => get_block(handle, &params).await,
        "getrawtransaction" => {
            let txid = as_hash(&arg(&params, 0, "txid")?, "txid")?;
            let tx = handle.mempool_tx(txid).await.map_err(node_error)?;
            tx.map(|tx| json!(to_hex(&tx.encode())))
                .ok_or_else(|| RpcError::not_found(
                    format!("{txid} は mempool に無い。確定した取引はそれが入っているブロックを getblock で取って探すこと"),
                ))
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
        .ok_or_else(|| RpcError::not_found(format!("ブロック {hash} の本体を持っていない")))?;

    if !verbose {
        return Ok(json!(to_hex(&block.encode())));
    }
    Ok(block_json(&hash, &block, handle.network()))
}

async fn send_raw_transaction(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let text = as_str(&arg(params, 0, "hex")?, "hex")?;
    let bytes = from_hex(&text, "hex")?;
    let tx = Transaction::decode(&bytes)
        .map_err(|e| RpcError::invalid_params(format!("取引として読めない: {e}")))?;

    let txid = handle
        .submit_tx(tx)
        .await
        .map_err(|e| RpcError::new(TX_REJECTED, e))?;
    Ok(json!(txid.to_string()))
}

async fn scan_utxos(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let list = arg(params, 0, "addresses")?;
    let entries = list
        .as_array()
        .ok_or_else(|| RpcError::invalid_params("addresses はアドレスの配列であること"))?;

    let network = handle.network();
    let mut locks = Vec::with_capacity(entries.len());
    let mut texts = Vec::with_capacity(entries.len());
    for entry in entries {
        let text = as_str(entry, "address")?;
        let address = Address::decode_on(network, &text)
            .map_err(|e| RpcError::invalid_params(format!("アドレス {text} が不正: {e}")))?;
        locks.push(Lock::from_address(&address));
        texts.push(text);
    }

    let found = handle
        .scan_utxos(locks.clone(), MAX_SCAN_RESULTS)
        .await
        .map_err(node_error)?;

    let total = Amount::sum(found.iter().map(|r| r.entry.output.amount))
        .ok_or_else(|| RpcError::new(NODE_ERROR, "合計が桁あふれした"))?;

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
