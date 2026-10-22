//! Chaavi: dadi's credential API inside the vault. `/v1` serves every item type for Thaali and
//! Hath with the same contract the TypeScript adapter had; Bitwarden clients keep using the
//! upstream routes. Unauthenticated: Caddy keeps it on the private mesh.
//!
//! Reads decrypt straight from the database. Writes build the request a Bitwarden client would
//! send and go through upstream's own `update_cipher_from_data`, so clients get a push at once.

mod cipher;
mod codec;
mod crypto;
mod error;
mod log;
mod password;
mod schemas;
mod ssh;
mod totp;
mod unlock;

use std::sync::LazyLock;

use chrono::Utc;
use rocket::{
    Data, Route, Shutdown, State,
    data::ToByteUnit,
    http::{Status, uri::Origin},
    response::{
        status::Custom,
        stream::{Event, EventStream},
    },
    serde::json::Json,
    tokio::{
        select,
        time::{Duration, Interval, interval},
    },
};
use serde_json::{Value, json};

pub use log::{RequestLog, line as log_line};

use crate::{
    api::{
        Notify, UpdateType,
        core::{CipherData, CipherSyncData, CipherSyncType, update_cipher_from_data},
    },
    db::{
        DbConn, DbPool,
        models::{Cipher, CipherId, Folder, FolderId},
    },
};
use error::{ApiResult, ChaaviError};
use schemas::ItemType;
use unlock::Session;

pub fn routes() -> Vec<Route> {
    routes![
        health,
        list_items,
        events,
        create_item,
        get_item,
        update_item,
        delete_item,
        reveal,
        item_totp,
        item_login,
        item_card,
        item_passkey,
        list_folders,
        create_folder,
        rename_folder,
        delete_folder,
        save_secret,
        reveal_secret,
        generate,
    ]
}

/// Serializes `/v1` writes, so a find-then-create (a secret by name) cannot race another.
static WRITES: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

type Created = Custom<Json<Value>>;

async fn read_body(data: Data<'_>) -> ApiResult<Value> {
    let raw = data
        .open(2.mebibytes())
        .into_string()
        .await
        .map_err(|e| ChaaviError::new(400, "invalid_request", format!("Body could not be read: {e}")))?;
    if !raw.is_complete() {
        return Err(ChaaviError::new(413, "invalid_request", "Body is too large"));
    }
    schemas::body(&raw.into_inner())
}

/// Every live item of the account, decrypted, sorted by name. A cipher that does not open
/// fails the whole list with `corrupt_item`, so the list is never silently short.
async fn opened_ciphers(session: &Session, conn: &DbConn) -> ApiResult<Vec<Value>> {
    let user = session.user();
    let sync = CipherSyncData::new(&user.uuid, CipherSyncType::User, conn).await;
    let mut out = Vec::new();
    for cipher in Cipher::find_by_user_visible(&user.uuid, conn).await {
        if cipher.deleted_at.is_some() {
            continue;
        }
        let raw = cipher.to_json(&session.headers.host, &user.uuid, Some(&sync), CipherSyncType::User, conn).await?;
        out.push(codec::open_cipher(raw, &session.key)?);
    }
    out.sort_by_cached_key(|c| {
        (c["name"].as_str().unwrap_or_default().to_lowercase(), c["id"].as_str().unwrap_or_default().to_owned())
    });
    Ok(out)
}

/// One live item of the account and its decrypted cipher; 404 for unknown, trashed or not
/// the account's.
async fn opened_cipher(id: &str, session: &Session, conn: &DbConn) -> ApiResult<(Cipher, Value)> {
    let id = schemas::item_id(id)?;
    let user = session.user();
    let cipher = match Cipher::find_by_uuid(&CipherId::from(id), conn).await {
        Some(cipher) if cipher.deleted_at.is_none() && cipher.is_accessible_to_user(&user.uuid, conn).await => cipher,
        _ => return Err(ChaaviError::not_found("item not found")),
    };
    let raw = cipher.to_json(&session.headers.host, &user.uuid, None, CipherSyncType::User, conn).await?;
    let opened = codec::open_cipher(raw, &session.key)?;
    Ok((cipher, opened))
}

/// A folder id in a write body must name one of the account's folders.
async fn require_folder(folder_id: Option<&str>, session: &Session, conn: &DbConn) -> ApiResult<()> {
    if let Some(id) = folder_id
        && Folder::find_by_uuid_and_user(&FolderId::from(id.to_owned()), &session.user().uuid, conn).await.is_none()
    {
        return Err(ChaaviError::invalid("folderId does not name a folder"));
    }
    Ok(())
}

/// Encrypt a plaintext cipher and save it through upstream (new when `existing` is None);
/// returns the item as listed.
async fn write_cipher(
    plain: &Value,
    existing: Option<Cipher>,
    session: &Session,
    conn: &DbConn,
    nt: &Notify<'_>,
) -> ApiResult<Value> {
    let user = session.user();
    let sealed = codec::seal_cipher(plain, &session.key, &user.uuid.to_string())?;
    let data: CipherData = serde_json::from_value(sealed)
        .map_err(|e| ChaaviError::new(500, "internal_error", format!("sealed cipher is not cipher data: {e}")))?;
    let (mut cipher, update_type) = match existing {
        Some(cipher) => (cipher, UpdateType::SyncCipherUpdate),
        None => (Cipher::new(data.r#type, data.name.clone()), UpdateType::SyncCipherCreate),
    };
    update_cipher_from_data(&mut cipher, data, &session.headers, None, conn, nt, update_type).await?;
    let raw = cipher.to_json(&session.headers.host, &user.uuid, None, CipherSyncType::User, conn).await?;
    cipher::item_from_cipher(&codec::open_cipher(raw, &session.key)?)
}

/// `ready` when the agent has a password and a vault account to unlock; the vault itself is
/// local, so there is nothing else to ping.
#[get("/health")]
async fn health(conn: DbConn) -> Json<Value> {
    let vault = if unlock::account(&conn).await.is_ok() {
        "ready"
    } else {
        "unconfigured"
    };
    Json(json!({ "status": "ok", "vault": vault }))
}

#[get("/v1/items")]
async fn list_items(origin: &Origin<'_>, conn: DbConn) -> ApiResult<Json<Value>> {
    let filter = schemas::items_query(origin.query().map(|q| q.as_str()))?;
    let session = unlock::open(&conn).await?;
    let items =
        opened_ciphers(&session, &conn).await?.iter().map(cipher::item_from_cipher).collect::<ApiResult<Vec<_>>>()?;
    let folders = decrypted_folders(&session, &conn).await?;
    Ok(Json(json!({ "items": cipher::filter_items(items, &filter, &folders)? })))
}

/// Server-Sent Events: `{ "type": "changed", "at" }` whenever the account's items or folders
/// change, whether through `/v1` or a Bitwarden client. Every write bumps the account's revision
/// date, which a once-a-second check of that one row watches. No replay.
// Rocket's EventStream! expands to a tail expression whose drop order differs in edition 2024;
// nothing in the stream depends on that order.
#[allow(tail_expr_drop_order)]
#[get("/v1/events")]
fn events(pool: &State<DbPool>, mut end: Shutdown) -> EventStream![Event + '_] {
    EventStream! {
        yield Event::comment("connected");
        let mut tick = interval(Duration::from_secs(1));
        let mut since_ping = 0u32;
        let mut seen = account_revision(pool).await;
        loop {
            if !next_tick(&mut tick, &mut end).await {
                break;
            }
            since_ping += 1;
            let now = account_revision(pool).await;
            if now.is_some() && now != seen {
                seen = now;
                since_ping = 0;
                yield Event::json(&json!({ "type": "changed", "at": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true) }));
            } else if since_ping >= PING_EVERY_SECONDS {
                since_ping = 0;
                yield Event::comment("ping");
            }
        }
    }
}

const PING_EVERY_SECONDS: u32 = 20;

/// Wait for the next tick; false when the server is shutting down.
async fn next_tick(tick: &mut Interval, end: &mut Shutdown) -> bool {
    let alive = select! {
        _instant = tick.tick() => true,
        () = end => false,
    };
    alive
}

/// The account's revision date, which every item and folder write bumps; None when the vault
/// is unconfigured or unreadable (the stream stays quiet).
async fn account_revision(pool: &DbPool) -> Option<String> {
    let conn = pool.get().await.ok()?;
    let user = unlock::account(&conn).await.ok()?;
    Some(user.updated_at.to_string())
}

/// The account's folders as (id, decrypted name).
async fn decrypted_folders(session: &Session, conn: &DbConn) -> ApiResult<Vec<(String, String)>> {
    let mut folders = Vec::new();
    for folder in Folder::find_by_user(&session.user().uuid, conn).await {
        let id = folder.uuid.to_string();
        let name = codec::open_folder_name(&folder.name, &session.key, &id)?;
        folders.push((id, name));
    }
    Ok(folders)
}

#[post("/v1/items", data = "<data>")]
async fn create_item(data: Data<'_>, conn: DbConn, nt: Notify<'_>) -> ApiResult<Created> {
    let input = schemas::create_item(&read_body(data).await?)?;
    let _write = WRITES.lock().await;
    let session = unlock::open(&conn).await?;
    require_folder(input.folder_id.as_deref(), &session, &conn).await?;
    let plain = cipher::cipher_for_create(&input)?;
    let item = write_cipher(&plain, None, &session, &conn, &nt).await?;
    Ok(Custom(Status::Created, Json(item)))
}

#[get("/v1/items/<id>")]
async fn get_item(id: &str, conn: DbConn) -> ApiResult<Json<Value>> {
    let session = unlock::open(&conn).await?;
    let (_, opened) = opened_cipher(id, &session, &conn).await?;
    Ok(Json(cipher::item_from_cipher(&opened)?))
}

#[patch("/v1/items/<id>", data = "<data>")]
async fn update_item(id: &str, data: Data<'_>, conn: DbConn, nt: Notify<'_>) -> ApiResult<Json<Value>> {
    let id = schemas::item_id(id)?;
    let input = schemas::update_item(&read_body(data).await?)?;
    let _write = WRITES.lock().await;
    let session = unlock::open(&conn).await?;
    if let schemas::Field::Set(folder_id) = &input.folder_id {
        require_folder(Some(folder_id), &session, &conn).await?;
    }
    let (existing, opened) = opened_cipher(&id, &session, &conn).await?;
    let mut next = cipher::apply_update(&opened, &input)?;
    codec::record_history(&opened, &mut next);
    Ok(Json(write_cipher(&next, Some(existing), &session, &conn, &nt).await?))
}

/// Move to the trash, as `bw delete item` did; clients can restore it.
#[delete("/v1/items/<id>")]
async fn delete_item(id: &str, conn: DbConn, nt: Notify<'_>) -> ApiResult<Status> {
    let _write = WRITES.lock().await;
    let session = unlock::open(&conn).await?;
    let (mut cipher, _) = opened_cipher(id, &session, &conn).await?;
    cipher.deleted_at = Some(Utc::now().naive_utc());
    cipher.save(&conn).await?;
    let users = cipher.update_users_revision(&conn).await;
    nt.send_cipher_update(UpdateType::SyncCipherUpdate, &cipher, &users, &session.headers.device, None, &conn).await;
    Ok(Status::NoContent)
}

#[post("/v1/items/<id>/reveal", data = "<data>")]
async fn reveal(id: &str, data: Data<'_>, conn: DbConn) -> ApiResult<Json<Value>> {
    let id = schemas::item_id(id)?;
    let request = schemas::reveal(&read_body(data).await?)?;
    let session = unlock::open(&conn).await?;
    let (_, opened) = opened_cipher(&id, &session, &conn).await?;
    Ok(Json(cipher::reveal_from_cipher(&opened, &request)?))
}

#[post("/v1/items/<id>/totp")]
async fn item_totp(id: &str, conn: DbConn) -> ApiResult<Json<Value>> {
    let session = unlock::open(&conn).await?;
    let (_, opened) = opened_cipher(id, &session, &conn).await?;
    let now_ms = u64::try_from(Utc::now().timestamp_millis()).unwrap_or_default();
    Ok(Json(cipher::totp_from_cipher(&opened, now_ms)?))
}

#[post("/v1/items/<id>/login")]
async fn item_login(id: &str, conn: DbConn) -> ApiResult<Json<Value>> {
    let session = unlock::open(&conn).await?;
    let (_, opened) = opened_cipher(id, &session, &conn).await?;
    Ok(Json(cipher::login_from_cipher(&opened)?))
}

#[post("/v1/items/<id>/card")]
async fn item_card(id: &str, conn: DbConn) -> ApiResult<Json<Value>> {
    let session = unlock::open(&conn).await?;
    let (_, opened) = opened_cipher(id, &session, &conn).await?;
    Ok(Json(cipher::card_from_cipher(&opened)?))
}

#[post("/v1/items/<id>/passkey")]
async fn item_passkey(id: &str, conn: DbConn) -> ApiResult<Json<Value>> {
    let session = unlock::open(&conn).await?;
    let (_, opened) = opened_cipher(id, &session, &conn).await?;
    Ok(Json(cipher::passkey_from_cipher(&opened)?))
}

fn folder_json(folder: &Folder, name: &str) -> Value {
    json!({ "id": folder.uuid, "name": name })
}

#[get("/v1/folders")]
async fn list_folders(conn: DbConn) -> ApiResult<Json<Value>> {
    let session = unlock::open(&conn).await?;
    let mut folders = Vec::new();
    for folder in Folder::find_by_user(&session.user().uuid, &conn).await {
        let name = codec::open_folder_name(&folder.name, &session.key, &folder.uuid.to_string())?;
        folders.push(folder_json(&folder, &name));
    }
    folders.sort_by_cached_key(|f| {
        (f["name"].as_str().unwrap_or_default().to_lowercase(), f["id"].as_str().unwrap_or_default().to_owned())
    });
    Ok(Json(json!({ "folders": folders })))
}

async fn own_folder(id: &str, session: &Session, conn: &DbConn) -> ApiResult<Folder> {
    let id = schemas::item_id(id)?;
    Folder::find_by_uuid_and_user(&FolderId::from(id), &session.user().uuid, conn)
        .await
        .ok_or_else(|| ChaaviError::not_found("folder not found"))
}

#[post("/v1/folders", data = "<data>")]
async fn create_folder(data: Data<'_>, conn: DbConn, nt: Notify<'_>) -> ApiResult<Created> {
    let name = schemas::folder(&read_body(data).await?)?;
    let _write = WRITES.lock().await;
    let session = unlock::open(&conn).await?;
    let mut folder = Folder::new(session.user().uuid.clone(), crypto::encrypt_str(&name, &session.key));
    folder.save(&conn).await?;
    nt.send_folder_update(UpdateType::SyncFolderCreate, &folder, &session.headers.device, &conn).await;
    Ok(Custom(Status::Created, Json(folder_json(&folder, &name))))
}

#[patch("/v1/folders/<id>", data = "<data>")]
async fn rename_folder(id: &str, data: Data<'_>, conn: DbConn, nt: Notify<'_>) -> ApiResult<Json<Value>> {
    let name = schemas::folder(&read_body(data).await?)?;
    let _write = WRITES.lock().await;
    let session = unlock::open(&conn).await?;
    let mut folder = own_folder(id, &session, &conn).await?;
    folder.name = crypto::encrypt_str(&name, &session.key);
    folder.save(&conn).await?;
    nt.send_folder_update(UpdateType::SyncFolderUpdate, &folder, &session.headers.device, &conn).await;
    Ok(Json(folder_json(&folder, &name)))
}

/// Delete a folder; its items move to no folder.
#[delete("/v1/folders/<id>")]
async fn delete_folder(id: &str, conn: DbConn, nt: Notify<'_>) -> ApiResult<Status> {
    let _write = WRITES.lock().await;
    let session = unlock::open(&conn).await?;
    let folder = own_folder(id, &session, &conn).await?;
    folder.delete(&conn).await?;
    nt.send_folder_update(UpdateType::SyncFolderDelete, &folder, &session.headers.device, &conn).await;
    Ok(Status::NoContent)
}

/// Secure Notes whose name equals `name`, ignoring case.
fn secret_notes<'a>(ciphers: &'a [Value], name: &str) -> Vec<&'a Value> {
    let needle = name.to_lowercase();
    ciphers
        .iter()
        .filter(|c| {
            c["type"].as_i64() == Some(ItemType::Note.code())
                && c["name"].as_str().is_some_and(|n| n.to_lowercase() == needle)
        })
        .collect()
}

/// Create or update the Secure Note named `name` with its hidden `Secret` field set.
#[put("/v1/secrets/<name>", data = "<data>")]
async fn save_secret(name: &str, data: Data<'_>, conn: DbConn, nt: Notify<'_>) -> ApiResult<Custom<Json<Value>>> {
    let name = schemas::secret_name(name)?;
    let (value, notes) = schemas::save_secret(&read_body(data).await?)?;
    let _write = WRITES.lock().await;
    let session = unlock::open(&conn).await?;
    let ciphers = opened_ciphers(&session, &conn).await?;
    let existing = secret_notes(&ciphers, &name);
    match existing.as_slice() {
        [] => {
            let plain = cipher::secret_note_for_create(&name, &value, notes.as_deref())?;
            let item = write_cipher(&plain, None, &session, &conn, &nt).await?;
            Ok(Custom(Status::Created, Json(json!({ "item": item, "created": true }))))
        }
        [one] => {
            let id = one["id"].as_str().unwrap_or_default().to_owned();
            let (row, opened) = opened_cipher(&id, &session, &conn).await?;
            let mut next = cipher::apply_secret(&opened, &value, notes.as_deref())?;
            codec::record_history(&opened, &mut next);
            let item = write_cipher(&next, Some(row), &session, &conn, &nt).await?;
            Ok(Custom(Status::Ok, Json(json!({ "item": item, "created": false }))))
        }
        many => Err(ChaaviError::conflict(format!("{} secure notes are named \"{name}\"", many.len()))),
    }
}

/// The hidden `Secret` field of the one Secure Note named `name` (case-insensitive).
#[post("/v1/secrets/<name>/reveal")]
async fn reveal_secret(name: &str, conn: DbConn) -> ApiResult<Json<Value>> {
    let name = schemas::secret_name(name)?;
    let session = unlock::open(&conn).await?;
    let ciphers = opened_ciphers(&session, &conn).await?;
    match secret_notes(&ciphers, &name).as_slice() {
        [] => Err(ChaaviError::not_found(format!("no secure note is named \"{name}\""))),
        [one] => Ok(Json(cipher::note_secret_from_cipher(one)?)),
        many => Err(ChaaviError::conflict(format!("{} secure notes are named \"{name}\"", many.len()))),
    }
}

#[post("/v1/generate", data = "<data>")]
async fn generate(data: Data<'_>) -> ApiResult<Json<Value>> {
    let (length, special) = schemas::generate(&read_body(data).await?)?;
    let password = password::generate(length.unwrap_or(password::DEFAULT_LENGTH), special.unwrap_or(true))?;
    Ok(Json(json!({ "password": password })))
}
