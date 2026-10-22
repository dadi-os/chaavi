//! Encrypted cipher JSON (what `/api/sync` sends a client) to and from plaintext cipher JSON in
//! the shape `bw get item` prints, which `cipher.rs` maps to Chaavi items. Opening decrypts every
//! encrypted string; sealing encrypts them again for upstream's `update_cipher_from_data`.
//!
//! Rule for an item type's own data (`login`, `card`, …): every string is an EncString except
//! the date keys below; numbers, booleans and null are stored as they are.

use serde_json::{Map, Value, json};

use super::{
    crypto::{self, SymKey},
    error::{ApiResult, ChaaviError},
    schemas::ItemType,
};

/// Keys under a type's data whose strings are stored in the clear.
const PLAIN_KEYS: &[&str] = &["passwordRevisionDate", "creationDate", "lastUsedDate"];

/// How many entries a cipher's password history keeps, as Bitwarden clients do.
const HISTORY_LIMIT: usize = 5;

/// The item key of a cipher (its own `key`, else the user key).
enum ItemKey<'a> {
    User(&'a SymKey),
    Own(Box<SymKey>),
}

impl ItemKey<'_> {
    fn get(&self) -> &SymKey {
        match self {
            Self::User(key) => key,
            Self::Own(key) => key,
        }
    }
}

fn item_key<'a>(cipher: &Value, user_key: &'a SymKey, id: &str) -> ApiResult<ItemKey<'a>> {
    match cipher.get("key") {
        Some(Value::String(wrapped)) => {
            let bytes = crypto::decrypt(wrapped, user_key)
                .map_err(|e| ChaaviError::corrupt(id, format!("has an item key that does not decrypt ({})", e.0)))?;
            let key = SymKey::from_bytes(&bytes)
                .map_err(|e| ChaaviError::corrupt(id, format!("has an invalid item key ({})", e.0)))?;
            Ok(ItemKey::Own(Box::new(key)))
        }
        Some(Value::Null) | None => Ok(ItemKey::User(user_key)),
        Some(_) => Err(ChaaviError::corrupt(id, "has an item key that is not a string")),
    }
}

/// Decrypt one stored cipher (from `Cipher::to_json`) into bw's plaintext shape.
pub fn open_cipher(mut cipher: Value, user_key: &SymKey) -> ApiResult<Value> {
    let id = cipher["id"].as_str().unwrap_or_default().to_owned();
    if !cipher["organizationId"].is_null() {
        return Err(ChaaviError::corrupt(&id, "belongs to an organization, which Chaavi does not read"));
    }
    let key = item_key(&cipher, user_key, &id)?;
    let key = key.get();
    let open = |value: &mut Value, path: &str| -> ApiResult<()> {
        open_value(value, key, path, false).map_err(|p| ChaaviError::corrupt(&id, p))
    };

    open(&mut cipher["name"], "name")?;
    open(&mut cipher["notes"], "notes")?;
    if let Some(fields) = cipher["fields"].as_array_mut() {
        for (index, field) in fields.iter_mut().enumerate() {
            open(&mut field["name"], &format!("fields.{index}.name"))?;
            open(&mut field["value"], &format!("fields.{index}.value"))?;
        }
    }
    if let Some(history) = cipher["passwordHistory"].as_array_mut() {
        for (index, entry) in history.iter_mut().enumerate() {
            open(&mut entry["password"], &format!("passwordHistory.{index}.password"))?;
        }
    }
    let code = cipher["type"].as_i64().unwrap_or_default();
    if let Some(item_type) = ItemType::from_code(code)
        && item_type != ItemType::Note
    {
        let data_key = item_type.data_key();
        open_tree(&mut cipher[data_key], key, data_key).map_err(|p| ChaaviError::corrupt(&id, p))?;
    }
    Ok(cipher)
}

/// Decrypt a string in place. A non-EncString is kept when `plain_ok`, or when empty.
fn open_value(value: &mut Value, key: &SymKey, path: &str, plain_ok: bool) -> Result<(), String> {
    let Value::String(text) = value else {
        return Ok(());
    };
    if crypto::is_enc_string(text) {
        let plain =
            crypto::decrypt_str(text, key).map_err(|e| format!("has a {path} that does not decrypt ({})", e.0))?;
        *value = Value::String(plain);
        return Ok(());
    }
    if plain_ok || text.is_empty() {
        return Ok(());
    }
    Err(format!("has a {path} that is not encrypted"))
}

fn open_tree(value: &mut Value, key: &SymKey, path: &str) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            map.remove("response");
            for (name, child) in map.iter_mut() {
                let child_path = format!("{path}.{name}");
                if PLAIN_KEYS.contains(&name.as_str()) {
                    open_value(child, key, &child_path, true)?;
                } else {
                    open_tree(child, key, &child_path)?;
                }
            }
            Ok(())
        }
        Value::Array(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                open_tree(child, key, &format!("{path}.{index}"))?;
            }
            Ok(())
        }
        Value::String(_) => open_value(value, key, path, false),
        _ => Ok(()),
    }
}

fn seal_string(value: &Value, key: &SymKey) -> Value {
    match value {
        Value::String(text) => Value::String(crypto::encrypt_str(text, key)),
        _ => Value::Null,
    }
}

fn seal_tree(value: &Value, key: &SymKey) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (name, child) in map {
                let sealed = if PLAIN_KEYS.contains(&name.as_str()) {
                    child.clone()
                } else {
                    seal_tree(child, key)
                };
                out.insert(name.clone(), sealed);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(|child| seal_tree(child, key)).collect()),
        Value::String(text) => Value::String(crypto::encrypt_str(text, key)),
        other => other.clone(),
    }
}

/// A login's data as clients write it: each URI carries a checksum (base64 SHA-256 of the
/// URI), and the deprecated top-level `uri` is left to the server.
fn prepare_login(login: &mut Value) {
    if let Some(map) = login.as_object_mut() {
        map.remove("uri");
    }
    if let Some(uris) = login["uris"].as_array_mut() {
        for entry in uris.iter_mut() {
            let checksum = entry["uri"].as_str().map(crypto::sha256_b64);
            if let Some(map) = entry.as_object_mut() {
                map.remove("response");
                map.insert("uriChecksum".into(), checksum.map_or(Value::Null, Value::String));
            }
        }
    }
}

/// The `CipherData` JSON for a plaintext cipher: what a client POSTs or PUTs. `cipher` keeps its
/// wrapped item `key`, if any, so the item stays readable by every client.
pub fn seal_cipher(cipher: &Value, user_key: &SymKey, user_id: &str) -> ApiResult<Value> {
    let id = cipher["id"].as_str().unwrap_or_default().to_owned();
    let item_type = cipher["type"]
        .as_i64()
        .and_then(ItemType::from_code)
        .ok_or_else(|| ChaaviError::corrupt(&id, "has an unknown type"))?;
    let key = item_key(cipher, user_key, &id)?;
    let key = key.get();

    let fields: Vec<Value> = cipher["fields"]
        .as_array()
        .map(|fields| {
            fields
                .iter()
                .map(|field| {
                    json!({
                        "name": seal_string(&field["name"], key),
                        "value": seal_string(&field["value"], key),
                        "type": field["type"],
                        "linkedId": field["linkedId"],
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let history: Vec<Value> = cipher["passwordHistory"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .map(|entry| json!({ "password": seal_string(&entry["password"], key), "lastUsedDate": entry["lastUsedDate"] }))
                .collect()
        })
        .unwrap_or_default();

    let mut data = cipher[item_type.data_key()].clone();
    if item_type == ItemType::Login {
        prepare_login(&mut data);
    }
    let sealed_data = if item_type == ItemType::Note {
        data
    } else {
        seal_tree(&data, key)
    };

    let mut out = json!({
        "type": item_type.code(),
        "name": seal_string(&cipher["name"], key),
        "notes": seal_string(&cipher["notes"], key),
        "folderId": cipher["folderId"],
        "favorite": cipher["favorite"].as_bool().unwrap_or(false),
        "reprompt": cipher["reprompt"].as_i64().unwrap_or(0),
        "key": cipher["key"],
        "fields": fields,
        "passwordHistory": if history.is_empty() { Value::Null } else { Value::Array(history) },
        "encryptedFor": user_id,
        "lastKnownRevisionDate": cipher["revisionDate"],
        "archivedDate": cipher["archivedDate"],
    });
    out[item_type.data_key()] = sealed_data;
    Ok(out)
}

/// Record what an edit replaced, as Bitwarden clients do: a changed login password (and its
/// revision date) and each changed or removed hidden field go to the front of the password
/// history, which keeps the newest five.
pub fn record_history(original: &Value, next: &mut Value) {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut added: Vec<Value> = Vec::new();

    if original["type"].as_i64() == Some(ItemType::Login.code()) {
        let old = original["login"]["password"].as_str().filter(|p| !p.is_empty());
        let new = next["login"]["password"].as_str();
        if let Some(old) = old
            && new != Some(old)
        {
            added.push(json!({ "password": old, "lastUsedDate": now }));
            next["login"]["passwordRevisionDate"] = json!(now);
        }
    }

    let hidden = |cipher: &Value| -> Vec<(String, String)> {
        cipher["fields"]
            .as_array()
            .map(|fields| {
                fields
                    .iter()
                    .filter(|f| f["type"].as_i64() == Some(1))
                    .filter_map(|f| Some((f["name"].as_str()?.to_owned(), f["value"].as_str()?.to_owned())))
                    .filter(|(name, value)| !name.is_empty() && !value.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    let kept = hidden(next);
    for (name, value) in hidden(original) {
        if !kept.iter().any(|(n, v)| *n == name && *v == value) {
            added.push(json!({ "password": format!("{name}: {value}"), "lastUsedDate": now }));
        }
    }

    if added.is_empty() {
        return;
    }
    let mut history = added;
    if let Some(existing) = next["passwordHistory"].as_array() {
        history.extend(existing.iter().cloned());
    }
    history.truncate(HISTORY_LIMIT);
    next["passwordHistory"] = Value::Array(history);
}

/// Decrypt a folder name (folders have no item key).
pub fn open_folder_name(name: &str, user_key: &SymKey, id: &str) -> ApiResult<String> {
    crypto::decrypt_str(name, user_key)
        .map_err(|e| ChaaviError::unreachable(format!("folder {id} name does not decrypt ({})", e.0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SymKey {
        SymKey::from_bytes(&[5u8; 64]).unwrap()
    }

    fn plain_login() -> Value {
        json!({
            "id": "6f1d2b6e-3f3a-4c8a-9b1e-0a1b2c3d4e5f",
            "type": 1,
            "name": "GitHub",
            "notes": null,
            "folderId": null,
            "favorite": true,
            "reprompt": 0,
            "key": null,
            "revisionDate": "2026-10-14T01:54:00.123456Z",
            "archivedDate": null,
            "fields": [{ "name": "Secret", "value": "s3", "type": 1, "linkedId": null }],
            "passwordHistory": [],
            "login": {
                "username": "ankur",
                "password": "pw",
                "totp": null,
                "passwordRevisionDate": "2026-01-01T00:00:00.000Z",
                "uris": [{ "uri": "https://github.com", "match": null }],
                "fido2Credentials": [{ "rpId": "github.com", "counter": "0", "creationDate": "2026-01-01T00:00:00.000Z" }],
            },
        })
    }

    #[test]
    fn seal_then_open_round_trips() {
        let user_key = key();
        let sealed = seal_cipher(&plain_login(), &user_key, "user").unwrap();
        assert!(crypto::is_enc_string(sealed["name"].as_str().unwrap()));
        assert!(crypto::is_enc_string(sealed["login"]["uris"][0]["uriChecksum"].as_str().unwrap()));
        assert_eq!(sealed["login"]["passwordRevisionDate"], "2026-01-01T00:00:00.000Z");
        assert_eq!(sealed["login"]["fido2Credentials"][0]["creationDate"], "2026-01-01T00:00:00.000Z");
        assert!(sealed["login"]["uris"][0]["match"].is_null());

        let mut stored = sealed;
        stored["id"] = plain_login()["id"].clone();
        stored["organizationId"] = Value::Null;
        let opened = open_cipher(stored, &user_key).unwrap();
        assert_eq!(opened["name"], "GitHub");
        assert_eq!(opened["login"]["password"], "pw");
        assert_eq!(opened["login"]["fido2Credentials"][0]["counter"], "0");
        assert_eq!(opened["fields"][0]["value"], "s3");
        assert_eq!(opened["login"]["uris"][0]["uriChecksum"], crypto::sha256_b64("https://github.com"));
    }

    #[test]
    fn an_item_key_is_used_and_kept() {
        let user_key = key();
        let item_bytes = [9u8; 64];
        let mut plain = plain_login();
        plain["key"] = json!(crypto::encrypt(&item_bytes, &user_key));
        let sealed = seal_cipher(&plain, &user_key, "user").unwrap();
        assert_eq!(sealed["key"], plain["key"]);
        let item_key = SymKey::from_bytes(&item_bytes).unwrap();
        assert_eq!(crypto::decrypt_str(sealed["name"].as_str().unwrap(), &item_key).unwrap(), "GitHub");
    }

    #[test]
    fn a_plain_string_where_a_secret_belongs_is_corrupt() {
        let mut stored = json!({ "id": "x", "type": 1, "organizationId": null, "name": "plain", "login": {} });
        assert_eq!(open_cipher(stored.clone(), &key()).unwrap_err().kind, "corrupt_item");
        stored["name"] = json!(crypto::encrypt_str("ok", &key()));
        stored["organizationId"] = json!("org");
        assert!(open_cipher(stored, &key()).unwrap_err().message.contains("organization"));
    }

    #[test]
    fn history_records_password_and_hidden_field_changes() {
        let original = plain_login();
        let mut next = plain_login();
        next["login"]["password"] = json!("new");
        next["fields"] = json!([]);
        record_history(&original, &mut next);
        let history = next["passwordHistory"].as_array().unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0]["password"], "pw");
        assert_eq!(history[1]["password"], "Secret: s3");
        assert_ne!(next["login"]["passwordRevisionDate"], "2026-01-01T00:00:00.000Z");

        let mut unchanged = plain_login();
        record_history(&original, &mut unchanged);
        assert_eq!(unchanged["passwordHistory"], json!([]));
    }
}
