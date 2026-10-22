//! HTTP errors in the contract shape `{ "error": { "type", "message" } }`.

use std::io::Cursor;

use rocket::{
    Request,
    http::{ContentType, Status},
    response::{self, Responder, Response},
};
use serde_json::json;

use super::log::{RequestMeta, emit};

/// A failure with an HTTP status and a stable error `type`. Messages never carry a secret.
#[derive(Debug)]
pub struct ChaaviError {
    pub status: u16,
    pub kind: &'static str,
    pub message: String,
}

pub type ApiResult<T> = Result<T, ChaaviError>;

impl ChaaviError {
    pub fn new(status: u16, kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            kind,
            message: message.into(),
        }
    }

    /// 422: validation, or a field the item's type lacks.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(422, "invalid_request", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, "not_found", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(409, "conflict", message)
    }

    /// 502: a stored item is not a valid item; `message` names it.
    pub fn corrupt(id: &str, problem: impl std::fmt::Display) -> Self {
        let id = if id.is_empty() {
            "without an id"
        } else {
            id
        };
        Self::new(502, "corrupt_item", format!("vault item {id} {problem}"))
    }

    /// 502: the vault could not be read, unlocked or written.
    pub fn unreachable(message: impl Into<String>) -> Self {
        Self::new(502, "vault_unreachable", message)
    }

    /// 503: an agent unlock variable is empty.
    pub fn unconfigured(variable: &str) -> Self {
        Self::new(503, "vault_unconfigured", format!("{variable} is not set"))
    }
}

/// An upstream (database / model) failure under a `/v1` call.
impl From<crate::Error> for ChaaviError {
    fn from(err: crate::Error) -> Self {
        Self::unreachable(format!("vault storage failed: {err}"))
    }
}

impl<'r> Responder<'r, 'static> for ChaaviError {
    fn respond_to(self, request: &'r Request<'_>) -> response::Result<'static> {
        let request_id = request.local_cache(RequestMeta::default).id.clone();
        let level = if self.status >= 500 {
            "error"
        } else {
            "warn"
        };
        emit(level, &self.message, json!({ "code": self.kind, "request_id": request_id, "status": self.status }));
        let body = json!({ "error": { "type": self.kind, "message": self.message } }).to_string();
        Response::build()
            .status(Status::new(self.status))
            .header(ContentType::JSON)
            .sized_body(body.len(), Cursor::new(body))
            .ok()
    }
}
