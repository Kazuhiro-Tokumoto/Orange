//! JSON-RPC 2.0 の要求と応答。
//!
//! 仕様は <https://www.jsonrpc.org/specification> に従う。取引所や
//! ブロックエクスプローラが繋ぎこむ先であり、独自の形にする理由がない。
//!
//! # 応答は必ず 1 個返す
//!
//! 通知 (`id` の無い要求) には応答しない、という規定があるが、本実装は
//! 通知を受け付けない。ノードへの問い合わせに「返事が要らないもの」は
//! 無く、受け付けると応答の数が要求の数と食い違って扱いが面倒になる。

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC の版数。この値以外は受け付けない。
pub const VERSION: &str = "2.0";

/// 要求の識別子。
///
/// 仕様上は文字列・数値・null を取りうる。そのまま応答に返す。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    /// 数値の識別子。
    Number(i64),
    /// 文字列の識別子。
    Text(String),
}

/// 要求。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    /// 版数。`"2.0"` でなければならない。
    pub jsonrpc: String,
    /// 呼び出す手続きの名前。
    pub method: String,
    /// 引数。省略できる。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// 識別子。
    pub id: Id,
}

impl Request {
    /// 引数付きの要求を組み立てる。
    pub fn new(id: i64, method: &str, params: Value) -> Request {
        Request {
            jsonrpc: VERSION.to_string(),
            method: method.to_string(),
            params: Some(params),
            id: Id::Number(id),
        }
    }
}

/// 応答。
///
/// `result` と `error` はどちらか一方だけが入る。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    /// 版数。
    pub jsonrpc: String,
    /// 成功した場合の結果。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// 失敗した場合の内容。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    /// 対応する要求の識別子。
    pub id: Option<Id>,
}

impl Response {
    /// 成功の応答。
    pub fn ok(id: Option<Id>, result: Value) -> Response {
        Response {
            jsonrpc: VERSION.to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// 失敗の応答。
    pub fn err(id: Option<Id>, error: RpcError) -> Response {
        Response {
            jsonrpc: VERSION.to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

/// 失敗の内容。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcError {
    /// 誤りの種別。
    pub code: i32,
    /// 人間が読む説明。
    pub message: String,
    /// 補足。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// ━━━━━━━━ 仕様が定める番号 ━━━━━━━━

/// JSON として読めなかった。
pub const PARSE_ERROR: i32 = -32700;
/// JSON-RPC の形をしていない。
pub const INVALID_REQUEST: i32 = -32600;
/// 知らない手続き。
pub const METHOD_NOT_FOUND: i32 = -32601;
/// 引数が不正。
pub const INVALID_PARAMS: i32 = -32602;
/// 手続きの中で失敗した。
pub const INTERNAL_ERROR: i32 = -32603;

// ━━━━━━━━ 本実装が定める番号 ━━━━━━━━
//
// 仕様は -32000 から -32099 を実装ごとの用途に空けている。

/// ノードの状態を引けなかった。
pub const NODE_ERROR: i32 = -32000;
/// 求めたものが見つからない。
pub const NOT_FOUND: i32 = -32001;
/// トランザクションが受け付けられなかった。
pub const TX_REJECTED: i32 = -32002;

impl RpcError {
    /// 番号と説明から作る。
    pub fn new(code: i32, message: impl Into<String>) -> RpcError {
        RpcError {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// 知らない手続き。
    pub fn method_not_found(method: &str) -> RpcError {
        RpcError::new(METHOD_NOT_FOUND, format!("知らない手続き: {method}"))
    }

    /// 引数が不正。
    pub fn invalid_params(message: impl Into<String>) -> RpcError {
        RpcError::new(INVALID_PARAMS, message)
    }

    /// 見つからない。
    pub fn not_found(message: impl Into<String>) -> RpcError {
        RpcError::new(NOT_FOUND, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_request_round_trips() {
        let request = Request::new(1, "getblockcount", json!([]));
        let text = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<Request>(&text).unwrap(),
            request,
            "往復して同じにならない"
        );
    }

    #[test]
    fn the_identifier_may_be_a_string() {
        let text = r#"{"jsonrpc":"2.0","method":"getinfo","id":"abc"}"#;
        let request: Request = serde_json::from_str(text).unwrap();
        assert_eq!(request.id, Id::Text("abc".to_string()));
        assert_eq!(request.params, None, "引数は省略できる");
    }

    #[test]
    fn a_successful_response_carries_no_error_field() {
        let text = serde_json::to_string(&Response::ok(Some(Id::Number(7)), json!(42))).unwrap();
        assert!(text.contains("\"result\":42"));
        assert!(!text.contains("error"), "成功なのに error がある: {text}");
    }

    #[test]
    fn a_failed_response_carries_no_result_field() {
        let error = RpcError::not_found("そんなブロックは無い");
        let text = serde_json::to_string(&Response::err(Some(Id::Number(7)), error)).unwrap();
        assert!(text.contains("\"code\":-32001"));
        assert!(!text.contains("result"), "失敗なのに result がある: {text}");
    }

    #[test]
    fn a_response_to_an_unreadable_request_has_a_null_identifier() {
        // 読めなかったのだから識別子も分からない。仕様は null を求める。
        let text = serde_json::to_string(&Response::err(
            None,
            RpcError::new(PARSE_ERROR, "JSON として読めない"),
        ))
        .unwrap();
        assert!(text.contains("\"id\":null"), "{text}");
    }
}
