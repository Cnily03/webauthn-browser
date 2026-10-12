use axum::{http::StatusCode, Json};
use serde_json::Value;

pub(crate) type ApiResult = Result<Json<Value>, (StatusCode, String)>;
pub(crate) fn fail(code: StatusCode, msg: impl ToString) -> (StatusCode, String) {
    (code, msg.to_string())
}
