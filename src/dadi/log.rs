//! Logs in the Nas JSON contract (`service=chaavi`): one object per line on stdout. Upstream
//! Vaultwarden lines go through `line` from the fern formatter in main.rs; Chaavi's own lines
//! and its request summaries use `emit`. Never log a password, key, note or other secret.

use std::time::Instant;

use rocket::{
    Data, Request, Response,
    fairing::{Fairing, Info, Kind},
    http::Header,
};
use serde_json::{Map, Value, json};

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// A whole log line for an upstream `log` record.
pub fn line(level: log::Level, target: &str, message: &std::fmt::Arguments<'_>) -> String {
    json!({
        "time": now(),
        "level": level.as_str().to_lowercase(),
        "service": "chaavi",
        "msg": message.to_string(),
        "target": target,
    })
    .to_string()
}

/// Print one contract line with `attrs` (an object) merged in.
pub fn emit(level: &str, msg: &str, attrs: Value) {
    let mut out = Map::new();
    out.insert("time".into(), now().into());
    out.insert("level".into(), level.into());
    out.insert("service".into(), "chaavi".into());
    out.insert("msg".into(), msg.into());
    if let Value::Object(attrs) = attrs {
        for (key, value) in attrs {
            if !value.is_null() {
                out.insert(key, value);
            }
        }
    }
    println!("{}", Value::Object(out));
}

/// Correlation id and start time of one Chaavi request.
pub struct RequestMeta {
    pub id: String,
    started: Instant,
}

impl Default for RequestMeta {
    fn default() -> Self {
        Self {
            id: data_encoding::HEXLOWER.encode(&crate::crypto::get_random_bytes::<8>()),
            started: Instant::now(),
        }
    }
}

/// Whether a path is served by Chaavi rather than upstream Vaultwarden.
pub fn is_chaavi_path(path: &str) -> bool {
    path == "/health" || path == "/v1" || path.starts_with("/v1/")
}

/// One request line per Chaavi call (request_id, method, path, status, duration_ms) and the
/// `X-Request-Id` echo. Upstream routes keep upstream's own logging.
pub struct RequestLog;

#[rocket::async_trait]
impl Fairing for RequestLog {
    fn info(&self) -> Info {
        Info {
            name: "Chaavi request log",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        if !is_chaavi_path(request.uri().path().as_str()) {
            return;
        }
        let incoming = request.headers().get_one("X-Request-Id").map(str::trim).filter(|id| !id.is_empty());
        let meta = match incoming {
            Some(id) => RequestMeta {
                id: id.to_owned(),
                started: Instant::now(),
            },
            None => RequestMeta::default(),
        };
        request.local_cache(|| meta);
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        let path = request.uri().path().as_str().to_owned();
        if !is_chaavi_path(&path) {
            return;
        }
        let meta = request.local_cache(RequestMeta::default);
        let status = response.status().code;
        let level = match status {
            500.. => "error",
            400.. => "warn",
            _ => "info",
        };
        emit(
            level,
            "request",
            json!({
                "request_id": meta.id,
                "method": request.method().as_str(),
                "path": path,
                "status": status,
                "duration_ms": u64::try_from(meta.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            }),
        );
        response.set_header(Header::new("X-Request-Id", meta.id.clone()));
    }
}
