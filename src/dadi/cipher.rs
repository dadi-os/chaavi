//! Plaintext cipher JSON (bw's shape, from `codec::open_cipher`) to and from Chaavi's item
//! contract. Pure: no database, no crypto. Secret values leave a cipher only through the reveal
//! mappers. A port of the TypeScript adapter's `cipher.ts`, function for function.

use data_encoding::{BASE64, BASE64URL_NOPAD, HEXLOWER_PERMISSIVE};
use serde_json::{Map, Value, json};

use super::{
    error::{ApiResult, ChaaviError},
    password,
    schemas::{
        CreateItem, CustomFieldInput, ItemFilter, ItemType, LoginInput, RevealRequest, SshKeyInput, UpdateItem,
        UriInput,
    },
    ssh, totp,
};

/// Name of the hidden field that holds an agent secret on its Secure Note.
pub const SECRET_FIELD: &str = "Secret";

const FIELD_TEXT: i64 = 0;
const FIELD_HIDDEN: i64 = 1;
const FIELD_BOOLEAN: i64 = 2;
const FIELD_LINKED: i64 = 3;

const MATCH_CODES: &[(&str, i64)] =
    &[("domain", 0), ("host", 1), ("startsWith", 2), ("exact", 3), ("regex", 4), ("never", 5)];

/// Bitwarden's linked-field ids per item type. The newer types define none.
fn linked_ids(item_type: ItemType) -> &'static [(&'static str, i64)] {
    match item_type {
        ItemType::Login => &[("username", 100), ("password", 101)],
        ItemType::Card => &[
            ("cardholderName", 300),
            ("expMonth", 301),
            ("expYear", 302),
            ("code", 303),
            ("brand", 304),
            ("number", 305),
        ],
        ItemType::Identity => &[
            ("title", 400),
            ("middleName", 401),
            ("address1", 402),
            ("address2", 403),
            ("address3", 404),
            ("city", 405),
            ("state", 406),
            ("postalCode", 407),
            ("country", 408),
            ("company", 409),
            ("email", 410),
            ("phone", 411),
            ("ssn", 412),
            ("username", 413),
            ("passportNumber", 414),
            ("licenseNumber", 415),
            ("firstName", 416),
            ("lastName", 417),
            ("fullName", 418),
        ],
        _ => &[],
    }
}

/// Item types that hold each named secret.
fn secret_owners(field: &str) -> &'static [ItemType] {
    match field {
        "password" | "totp" => &[ItemType::Login],
        "number" | "code" => &[ItemType::Card],
        "ssn" => &[ItemType::Identity],
        "passportNumber" => &[ItemType::Identity, ItemType::Passport],
        "licenseNumber" => &[ItemType::Identity, ItemType::DriversLicense],
        "privateKey" => &[ItemType::SshKey],
        "accountNumber" | "pin" | "iban" => &[ItemType::BankAccount],
        "nationalIdentificationNumber" => &[ItemType::Passport],
        _ => &[],
    }
}

fn id_of(cipher: &Value) -> &str {
    cipher["id"].as_str().unwrap_or_default()
}

fn corrupt(cipher: &Value, problem: impl std::fmt::Display) -> ChaaviError {
    ChaaviError::corrupt(id_of(cipher), problem)
}

/// Item type of a cipher. Bitwarden has no type outside 1–8, so another is a corrupt item.
pub fn item_type_of(cipher: &Value) -> ApiResult<ItemType> {
    let code = match &cipher["type"] {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    };
    code.and_then(ItemType::from_code).ok_or_else(|| corrupt(cipher, format!("has unknown type {}", cipher["type"])))
}

/// A typed item's own data object; its absence is a corrupt item, never an empty one.
fn type_data(cipher: &Value, item_type: ItemType) -> ApiResult<&Map<String, Value>> {
    let key = item_type.data_key();
    cipher[key].as_object().ok_or_else(|| corrupt(cipher, format!("is a {key} item without its {key} data")))
}

fn type_data_mut(cipher: &mut Value, item_type: ItemType) -> ApiResult<&mut Map<String, Value>> {
    let problem = corrupt(cipher, format!("is a {0} item without its {0} data", item_type.data_key()));
    cipher[item_type.data_key()].as_object_mut().ok_or(problem)
}

/// `has` + the field name with its first letter raised: `accountNumber` → `hasAccountNumber`.
fn has_key(field: &str) -> String {
    let mut chars = field.chars();
    let first = chars.next().map(|c| c.to_ascii_uppercase()).unwrap_or_default();
    format!("has{first}{}", chars.as_str())
}

/// A non-empty string, else None.
fn text(value: &Value) -> Option<String> {
    value.as_str().filter(|s| !s.is_empty()).map(str::to_owned)
}

fn text_json(value: &Value) -> Value {
    text(value).map_or(Value::Null, Value::String)
}

/// A non-empty string, else a 422 with `message`.
fn required(value: &Value, message: &str) -> ApiResult<String> {
    text(value).ok_or_else(|| ChaaviError::invalid(message))
}

fn empty_to_null(value: Option<&str>) -> Value {
    match value {
        Some(text) if !text.is_empty() => Value::String(text.to_owned()),
        _ => Value::Null,
    }
}

/// An RFC 3339 date as bw prints a JS Date: milliseconds, `Z`. Anything else passes through.
fn iso_millis(value: &Value) -> Value {
    match value.as_str().map(chrono::DateTime::parse_from_rfc3339) {
        Some(Ok(date)) => json!(date.with_timezone(&chrono::Utc).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        _ => text_json(value),
    }
}

fn number_of(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Custom fields on a cipher; anything that is not an object is dropped, as bw does.
fn raw_fields(cipher: &Value) -> Vec<Value> {
    cipher["fields"]
        .as_array()
        .map(|fields| fields.iter().filter(|f| f.is_object()).cloned().collect())
        .unwrap_or_default()
}

/// Map a plaintext cipher to its listed item: every non-secret field, only flags for secrets.
pub fn item_from_cipher(cipher: &Value) -> ApiResult<Value> {
    let Some(id) = text(&cipher["id"]) else {
        return Err(corrupt(cipher, "has no id"));
    };
    let item_type = item_type_of(cipher)?;
    let fields =
        raw_fields(cipher).iter().map(|field| custom_field(field, item_type)).collect::<ApiResult<Vec<_>>>()?;
    let mut item = json!({
        "id": id,
        "name": cipher["name"].as_str().unwrap_or_default(),
        "folderId": text_json(&cipher["folderId"]),
        "favorite": cipher["favorite"] == Value::Bool(true),
        "hasNotes": text(&cipher["notes"]).is_some(),
        "fields": fields,
        "revisionDate": iso_millis(&cipher["revisionDate"]),
        "type": item_type.name(),
    });
    match item_type {
        ItemType::Note => {}
        ItemType::Login => {
            let data = type_data(cipher, item_type)?;
            let null = Value::Null;
            let get = |key: &str| data.get(key).unwrap_or(&null);
            item["login"] = json!({
                "username": text_json(get("username")),
                "uris": login_uris(data),
                "hasPassword": text(get("password")).is_some(),
                "hasTotp": text(get("totp")).is_some(),
                "passkeys": fido2_list(cipher).iter().map(passkey_info).collect::<Vec<_>>(),
            });
        }
        ItemType::SshKey => {
            let data = type_data(cipher, item_type)?;
            let null = Value::Null;
            let get = |key: &str| data.get(key).unwrap_or(&null);
            item["sshKey"] = json!({
                "publicKey": text_json(get("publicKey")),
                "keyFingerprint": text_json(get("keyFingerprint")),
                "hasPrivateKey": text(get("privateKey")).is_some(),
            });
        }
        _ => {
            let data = type_data(cipher, item_type)?;
            let mut detail = Map::new();
            let spec = item_type.text_fields().expect("a flat item type");
            for (name, ..) in spec.iter().filter(|(.., secret)| !secret) {
                detail.insert((*name).to_owned(), data.get(*name).map_or(Value::Null, text_json));
            }
            for (name, ..) in spec.iter().filter(|(.., secret)| *secret) {
                detail.insert(has_key(name), json!(data.get(*name).and_then(text).is_some()));
            }
            item[item_type.name()] = Value::Object(detail);
        }
    }
    Ok(item)
}

/// Keep items matching the list query: `type` exactly, `uri` against login websites, and `q`
/// against the name, login username and websites, the public text of the flat types, and text
/// custom fields.
pub fn filter_items(items: Vec<Value>, filter: &ItemFilter, folders: &[(String, String)]) -> ApiResult<Vec<Value>> {
    let scope = filter.folder.as_deref().map(str::to_lowercase);
    if let Some(scope) = &scope
        && !folders.iter().any(|(_, name)| is_within_folder(&name.to_lowercase(), scope))
    {
        return Err(ChaaviError::not_found(format!(
            "no folder named \"{}\"",
            filter.folder.as_deref().unwrap_or_default()
        )));
    }
    Ok(items
        .into_iter()
        .filter(|item| {
            if let Some(scope) = &scope {
                let path = item["folderId"]
                    .as_str()
                    .and_then(|id| folders.iter().find(|(folder_id, _)| folder_id == id))
                    .map(|(_, name)| name.to_lowercase());
                if !path.is_some_and(|path| is_within_folder(&path, scope)) {
                    return false;
                }
            }
            if let Some(item_type) = filter.r#type
                && item["type"] != item_type.name()
            {
                return false;
            }
            let uris: Vec<String> = item["login"]["uris"]
                .as_array()
                .map(|uris| uris.iter().filter_map(|u| u["uri"].as_str()).map(str::to_lowercase).collect())
                .unwrap_or_default();
            if let Some(needle) = &filter.uri {
                let needle = needle.to_lowercase();
                if !uris.iter().any(|uri| uri.contains(&needle)) {
                    return false;
                }
            }
            if let Some(q) = &filter.q {
                let q = q.to_lowercase();
                return search_text(item).iter().any(|value| value.to_lowercase().contains(&q));
            }
            true
        })
        .collect())
}

/// True when the folder name `path` is `scope` or is nested under it (`dev/api` under `dev`).
fn is_within_folder(path: &str, scope: &str) -> bool {
    path == scope || path.strip_prefix(scope).is_some_and(|rest| rest.starts_with('/'))
}

/// The values `q` searches for one item.
fn search_text(item: &Value) -> Vec<String> {
    let mut out = vec![item["name"].as_str().unwrap_or_default().to_owned()];
    let item_type = item["type"].as_str().and_then(ItemType::from_name);
    if item_type == Some(ItemType::Login) {
        if let Some(uris) = item["login"]["uris"].as_array() {
            out.extend(uris.iter().filter_map(|u| u["uri"].as_str()).map(str::to_owned));
        }
        if let Some(username) = item["login"]["username"].as_str() {
            out.push(username.to_owned());
        }
    }
    if let Some(item_type) = item_type
        && let Some(spec) = item_type.text_fields()
    {
        for (name, ..) in spec.iter().filter(|(.., secret)| !secret) {
            if let Some(value) = item[item_type.name()][name].as_str() {
                out.push(value.to_owned());
            }
        }
    }
    if let Some(fields) = item["fields"].as_array() {
        out.extend(
            fields.iter().filter(|f| f["type"] == "text").filter_map(|f| f["value"].as_str()).map(str::to_owned),
        );
    }
    out
}

/// A plaintext cipher for a new item. A login without a password gets a generated one; an SSH
/// key item without key material gets a new Ed25519 key.
pub fn cipher_for_create(input: &CreateItem) -> ApiResult<Value> {
    let mut cipher = json!({
        "type": input.r#type.code(),
        "name": input.name,
        "folderId": input.folder_id,
        "favorite": input.favorite,
        "notes": empty_to_null(input.notes.as_deref()),
        "reprompt": 0,
        "key": null,
        "fields": fields_for_write(&input.fields, &[], input.r#type)?,
        "passwordHistory": [],
    });
    match input.r#type {
        ItemType::Login => {
            let empty = LoginInput::default();
            let login = input.login.as_ref().unwrap_or(&empty);
            if login.password.is_some() && (login.length.is_some() || login.special.is_some()) {
                return Err(ChaaviError::invalid("length and special apply only when password is omitted"));
            }
            let password = match &login.password {
                Some(password) => password.clone(),
                None => {
                    password::generate(login.length.unwrap_or(password::DEFAULT_LENGTH), login.special.unwrap_or(true))?
                }
            };
            cipher["login"] = json!({
                "username": empty_to_null(login.username.as_deref()),
                "password": password,
                "totp": checked_totp(login.totp.as_deref())?,
                "uris": login.uris.as_deref().unwrap_or_default().iter().map(raw_uri).collect::<Vec<_>>(),
            });
        }
        ItemType::Note => cipher["secureNote"] = json!({ "type": 0 }),
        ItemType::SshKey => {
            cipher["sshKey"] = ssh_key_for_create(input.ssh_key.as_ref().unwrap_or(&SshKeyInput::default()))?;
        }
        flat => {
            let mut data = Map::new();
            apply_text(&mut data, flat, input.text.as_deref().unwrap_or_default());
            cipher[flat.data_key()] = Value::Object(data);
        }
    }
    Ok(cipher)
}

/// Apply `PATCH /v1/items/:id` to a plaintext cipher. A type object must match the item's type.
pub fn apply_update(cipher: &Value, input: &UpdateItem) -> ApiResult<Value> {
    let item_type = item_type_of(cipher)?;
    let given: Vec<ItemType> = input
        .login
        .as_ref()
        .map(|_| ItemType::Login)
        .into_iter()
        .chain(input.ssh_key.as_ref().map(|_| ItemType::SshKey))
        .chain(input.texts.iter().map(|(t, _)| *t))
        .collect();
    if let Some(other) = given.iter().find(|t| **t != item_type) {
        return Err(ChaaviError::invalid(format!(
            "{} fields do not apply to a {} item",
            other.name(),
            item_type.name()
        )));
    }
    let mut next = cipher.clone();
    if let Some(name) = &input.name {
        next["name"] = json!(name);
    }
    match &input.folder_id {
        super::schemas::Field::Missing => {}
        super::schemas::Field::Null => next["folderId"] = Value::Null,
        super::schemas::Field::Set(id) => next["folderId"] = json!(id),
    }
    if let Some(favorite) = input.favorite {
        next["favorite"] = json!(favorite);
    }
    if let Some(notes) = &input.notes {
        next["notes"] = empty_to_null(Some(notes));
    }
    if let Some(fields) = &input.fields {
        next["fields"] = Value::Array(fields_for_write(fields, &raw_fields(cipher), item_type)?);
    }
    if let Some(login) = &input.login {
        let data = type_data_mut(&mut next, ItemType::Login)?;
        if let Some(username) = &login.username {
            data.insert("username".into(), empty_to_null(Some(username)));
        }
        if let Some(password) = &login.password {
            data.insert("password".into(), empty_to_null(Some(password)));
        }
        if let Some(totp) = &login.totp {
            data.insert("totp".into(), checked_totp(Some(totp))?);
        }
        if let Some(uris) = &login.uris {
            data.insert("uris".into(), Value::Array(uris.iter().map(raw_uri).collect()));
        }
    }
    if let Some(ssh_key) = &input.ssh_key {
        let data = type_data_mut(&mut next, ItemType::SshKey)?;
        for (key, value) in [
            ("privateKey", &ssh_key.private_key),
            ("publicKey", &ssh_key.public_key),
            ("keyFingerprint", &ssh_key.key_fingerprint),
        ] {
            if let Some(value) = value {
                if value.is_empty() {
                    return Err(ChaaviError::invalid(format!("sshKey.{key} cannot be cleared")));
                }
                data.insert(key.into(), json!(value));
            }
        }
    }
    for (flat, values) in &input.texts {
        apply_text(type_data_mut(&mut next, *flat)?, *flat, values);
    }
    Ok(next)
}

/// One secret of an item, decrypted, for `POST /v1/items/:id/reveal`.
pub fn reveal_from_cipher(cipher: &Value, request: &RevealRequest) -> ApiResult<Value> {
    let item_type = item_type_of(cipher)?;
    let value = match request {
        RevealRequest::Custom(name) => {
            let field = unique_field(cipher, name)?;
            if number_of(&field["type"]) != Some(FIELD_HIDDEN) {
                return Err(ChaaviError::invalid(format!("field \"{name}\" is not hidden")));
            }
            required(&field["value"], &format!("field \"{name}\" is empty"))?
        }
        RevealRequest::Field(field) if field == "notes" => required(&cipher["notes"], "item has no notes")?,
        RevealRequest::Field(field) => {
            if item_type == ItemType::Note || !secret_owners(field).contains(&item_type) {
                return Err(ChaaviError::invalid(format!("a {} item has no {field}", item_type.name())));
            }
            let data = type_data(cipher, item_type)?;
            required(data.get(field.as_str()).unwrap_or(&Value::Null), &format!("item has no {field}"))?
        }
    };
    Ok(json!({ "value": value }))
}

fn require_type(cipher: &Value, item_type: ItemType, message: &str) -> ApiResult<()> {
    if item_type_of(cipher)? == item_type {
        Ok(())
    } else {
        Err(ChaaviError::invalid(message))
    }
}

/// Current one-time code of a login cipher.
pub fn totp_from_cipher(cipher: &Value, now_ms: u64) -> ApiResult<Value> {
    require_type(cipher, ItemType::Login, "item is not a login")?;
    let data = type_data(cipher, ItemType::Login)?;
    totp::totp_code(&required(data.get("totp").unwrap_or(&Value::Null), "item has no authenticator key")?, now_ms)
}

/// Username + password for a login cipher; a login without a username gives null.
pub fn login_from_cipher(cipher: &Value) -> ApiResult<Value> {
    require_type(cipher, ItemType::Login, "item is not a login")?;
    let data = type_data(cipher, ItemType::Login)?;
    Ok(json!({
        "username": data.get("username").map_or(Value::Null, text_json),
        "password": required(data.get("password").unwrap_or(&Value::Null), "item has no password")?,
    }))
}

/// Decrypted card fields for a form fill; the number is required.
pub fn card_from_cipher(cipher: &Value) -> ApiResult<Value> {
    require_type(cipher, ItemType::Card, "item is not a card")?;
    let data = type_data(cipher, ItemType::Card)?;
    let get = |key: &str| data.get(key).map_or(Value::Null, text_json);
    Ok(json!({
        "cardholderName": get("cardholderName"),
        "brand": get("brand"),
        "number": required(data.get("number").unwrap_or(&Value::Null), "card has no number")?,
        "expMonth": get("expMonth"),
        "expYear": get("expYear"),
        "code": get("code"),
    }))
}

/// The value of a Secure Note's one hidden `Secret` field.
pub fn note_secret_from_cipher(cipher: &Value) -> ApiResult<Value> {
    require_type(cipher, ItemType::Note, "item is not a secure note")?;
    let field = unique_field(cipher, SECRET_FIELD)?;
    if number_of(&field["type"]) != Some(FIELD_HIDDEN) {
        return Err(ChaaviError::invalid(format!("field \"{SECRET_FIELD}\" is not hidden")));
    }
    Ok(json!({ "value": required(&field["value"], &format!("field \"{SECRET_FIELD}\" is empty"))? }))
}

/// Set a Secure Note's hidden `Secret` field to `value`, keeping its other fields, and its
/// notes to `notes` when given.
pub fn apply_secret(cipher: &Value, value: &str, notes: Option<&str>) -> ApiResult<Value> {
    require_type(cipher, ItemType::Note, "item is not a secure note")?;
    let fields = raw_fields(cipher);
    let matches = fields.iter().filter(|f| f["name"] == SECRET_FIELD).count();
    if matches > 1 {
        return Err(ChaaviError::conflict(format!("secure note has {matches} fields named \"{SECRET_FIELD}\"")));
    }
    let secret = json!({ "name": SECRET_FIELD, "value": value, "type": FIELD_HIDDEN, "linkedId": null });
    let mut next = cipher.clone();
    next["fields"] = if matches == 1 {
        Value::Array(
            fields
                .into_iter()
                .map(|f| {
                    if f["name"] == SECRET_FIELD {
                        secret.clone()
                    } else {
                        f
                    }
                })
                .collect(),
        )
    } else {
        Value::Array(fields.into_iter().chain([secret]).collect())
    };
    if let Some(notes) = notes {
        next["notes"] = empty_to_null(Some(notes));
    }
    Ok(next)
}

/// A new Secure Note named `name` holding `value` in its hidden `Secret` field.
pub fn secret_note_for_create(name: &str, value: &str, notes: Option<&str>) -> ApiResult<Value> {
    cipher_for_create(&CreateItem {
        r#type: ItemType::Note,
        name: name.to_owned(),
        folder_id: None,
        favorite: false,
        notes: notes.map(str::to_owned),
        fields: vec![CustomFieldInput::Hidden {
            name: SECRET_FIELD.to_owned(),
            value: Some(value.to_owned()),
        }],
        login: None,
        ssh_key: None,
        text: None,
    })
}

/// First FIDO2 credential on a login cipher, encoded for Chrome `WebAuthn.addCredential`
/// (standard base64 PKCS#8 / credential id / user handle).
pub fn passkey_from_cipher(cipher: &Value) -> ApiResult<Value> {
    require_type(cipher, ItemType::Login, "item is not a login")?;
    type_data(cipher, ItemType::Login)?;
    let list = fido2_list(cipher);
    let Some(raw) = list.first() else {
        return Err(ChaaviError::invalid("item has no passkey"));
    };
    let rp_id = required_string(&raw["rpId"], "passkey is missing rpId")?;
    if raw["keyAlgorithm"].as_str() != Some("ECDSA") || raw["keyCurve"].as_str() != Some("P-256") {
        return Err(ChaaviError::invalid("passkey is not ECDSA P-256"));
    }
    let private_key = decode_bitwarden_bytes(&raw["keyValue"], "passkey private key")?;
    let credential_id = decode_credential_id(&raw["credentialId"])?;
    let resident = parse_discoverable(&raw["discoverable"])?;
    let user_handle = decode_optional_bytes(&raw["userHandle"])?;
    if resident && user_handle.is_empty() {
        return Err(ChaaviError::invalid("passkey is missing userHandle"));
    }
    Ok(json!({
        "credentialId": BASE64.encode(&credential_id),
        "rpId": rp_id,
        "privateKey": BASE64.encode(&private_key),
        "userHandle": BASE64.encode(&user_handle),
        "signCount": parse_counter(&raw["counter"])?,
        "resident": resident,
    }))
}

/// A TOTP key to store, checked to produce codes; empty clears it.
fn checked_totp(seed: Option<&str>) -> ApiResult<Value> {
    let value = empty_to_null(seed);
    if let Some(seed) = value.as_str() {
        totp::totp_code(seed, 0)?;
    }
    Ok(value)
}

/// The one field named `name`; none or several is a 422.
fn unique_field(cipher: &Value, name: &str) -> ApiResult<Value> {
    let matches: Vec<Value> = raw_fields(cipher).into_iter().filter(|f| f["name"] == name).collect();
    match matches.len() {
        0 => Err(ChaaviError::invalid(format!("item has no field named \"{name}\""))),
        1 => Ok(matches.into_iter().next().expect("one match")),
        n => Err(ChaaviError::invalid(format!("item has {n} fields named \"{name}\""))),
    }
}

/// A stored custom field as listed, hidden values withheld.
fn custom_field(field: &Value, item_type: ItemType) -> ApiResult<Value> {
    let name = field["name"].as_str().unwrap_or_default();
    match number_of(&field["type"]) {
        Some(FIELD_TEXT) => {
            Ok(json!({ "name": name, "type": "text", "value": field["value"].as_str().unwrap_or_default() }))
        }
        Some(FIELD_HIDDEN) => {
            Ok(json!({ "name": name, "type": "hidden", "hasValue": text(&field["value"]).is_some() }))
        }
        Some(FIELD_BOOLEAN) => {
            let value = field["value"] == "true" || field["value"] == Value::Bool(true);
            Ok(json!({ "name": name, "type": "boolean", "value": value }))
        }
        Some(FIELD_LINKED) => {
            let id = number_of(&field["linkedId"]);
            let target = linked_ids(item_type).iter().find(|(_, value)| Some(*value) == id);
            match target {
                Some((target, _)) => Ok(json!({ "name": name, "type": "linked", "linkedTo": target })),
                None => Err(ChaaviError::unreachable(format!(
                    "linked field \"{name}\" has unknown target {}",
                    field["linkedId"]
                ))),
            }
        }
        _ => Err(ChaaviError::unreachable(format!("field \"{name}\" has unknown type {}", field["type"]))),
    }
}

/// Plaintext fields for a write. Names must be unique. A hidden field without a value keeps the
/// stored value of the hidden field with its name in `existing`.
fn fields_for_write(inputs: &[CustomFieldInput], existing: &[Value], item_type: ItemType) -> ApiResult<Vec<Value>> {
    let mut names: Vec<&str> = Vec::new();
    inputs
        .iter()
        .map(|input| {
            let name = input.name();
            if names.contains(&name) {
                return Err(ChaaviError::invalid(format!("field \"{name}\" appears twice")));
            }
            names.push(name);
            Ok(match input {
                CustomFieldInput::Text {
                    value,
                    ..
                } => json!({ "name": name, "value": value, "type": FIELD_TEXT, "linkedId": null }),
                CustomFieldInput::Boolean {
                    value,
                    ..
                } => json!({ "name": name, "value": if *value { "true" } else { "false" }, "type": FIELD_BOOLEAN, "linkedId": null }),
                CustomFieldInput::Linked {
                    linked_to,
                    ..
                } => {
                    let Some((_, id)) = linked_ids(item_type).iter().find(|(target, _)| target == linked_to) else {
                        return Err(ChaaviError::invalid(format!("a {} item cannot link a field to {linked_to}", item_type.name())));
                    };
                    json!({ "name": name, "value": null, "type": FIELD_LINKED, "linkedId": id })
                }
                CustomFieldInput::Hidden {
                    value: Some(value),
                    ..
                } => json!({ "name": name, "value": value, "type": FIELD_HIDDEN, "linkedId": null }),
                CustomFieldInput::Hidden {
                    value: None,
                    ..
                } => {
                    let stored: Vec<&Value> = existing.iter().filter(|f| f["name"] == name && number_of(&f["type"]) == Some(FIELD_HIDDEN)).collect();
                    if stored.len() != 1 {
                        return Err(ChaaviError::invalid(format!("hidden field \"{name}\" has no stored value to keep; give value")));
                    }
                    json!({ "name": name, "value": stored[0]["value"], "type": FIELD_HIDDEN, "linkedId": null })
                }
            })
        })
        .collect()
}

/// Login websites as listed; a null match is the account default.
fn login_uris(login: &Map<String, Value>) -> Vec<Value> {
    let Some(uris) = login.get("uris").and_then(Value::as_array) else {
        return Vec::new();
    };
    uris.iter()
        .filter_map(|entry| {
            let uri = text(&entry["uri"])?;
            let code = if entry["match"].is_null() {
                None
            } else {
                number_of(&entry["match"])
            };
            let name = MATCH_CODES.iter().find(|(_, value)| Some(*value) == code).map_or("default", |(name, _)| name);
            Some(json!({ "uri": uri, "match": name }))
        })
        .collect()
}

/// A website for a write.
fn raw_uri(entry: &UriInput) -> Value {
    let code =
        entry.r#match.as_deref().and_then(|name| MATCH_CODES.iter().find(|(n, _)| *n == name)).map(|(_, code)| *code);
    json!({ "uri": entry.uri, "match": code })
}

/// Write a flat item's string fields: empty clears. A card number drops its spaces and dashes,
/// and a card month is stored without a leading zero.
fn apply_text(data: &mut Map<String, Value>, item_type: ItemType, input: &[(String, String)]) {
    let spec = item_type.text_fields().expect("a flat item type");
    for (name, ..) in spec {
        let Some((_, value)) = input.iter().find(|(key, _)| key == name) else {
            continue;
        };
        let stored = match (item_type, *name) {
            (ItemType::Card, "number") => {
                let digits: String = value.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
                empty_to_null(Some(&digits))
            }
            (ItemType::Card, "expMonth") if !value.is_empty() => {
                json!(value.parse::<u32>().map_or_else(|_| value.clone(), |n| n.to_string()))
            }
            _ => empty_to_null(Some(value)),
        };
        data.insert((*name).to_owned(), stored);
    }
}

/// Key material for a new SSH key item: all three given, or none to generate an Ed25519 key.
fn ssh_key_for_create(input: &SshKeyInput) -> ApiResult<Value> {
    match (&input.private_key, &input.public_key, &input.key_fingerprint) {
        (None, None, None) => ssh::generate_ssh_key(),
        (Some(private_key), Some(public_key), Some(fingerprint)) => {
            Ok(json!({ "privateKey": private_key, "publicKey": public_key, "keyFingerprint": fingerprint }))
        }
        _ => Err(ChaaviError::invalid(
            "give privateKey, publicKey and keyFingerprint together, or none to generate a key",
        )),
    }
}

/// Non-empty FIDO2 credential objects on a login cipher.
fn fido2_list(cipher: &Value) -> Vec<Value> {
    cipher["login"]["fido2Credentials"]
        .as_array()
        .map(|list| list.iter().filter(|c| c.is_object()).cloned().collect())
        .unwrap_or_default()
}

/// A passkey as listed, without key material.
fn passkey_info(raw: &Value) -> Value {
    json!({
        "rpId": raw["rpId"].as_str().unwrap_or_default(),
        "userName": text_json(&raw["userName"]),
        "creationDate": iso_millis(&raw["creationDate"]),
    })
}

fn required_string(value: &Value, message: &str) -> ApiResult<String> {
    value.as_str().filter(|s| !s.is_empty()).map(str::to_owned).ok_or_else(|| ChaaviError::invalid(message))
}

/// Decode a Bitwarden FIDO2 string: URL-safe base64 (standard alphabet and padding tolerated).
fn base64url(raw: &str) -> Option<Vec<u8>> {
    let normalized: String = raw
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    BASE64URL_NOPAD.decode(normalized.as_bytes()).ok().filter(|bytes| !bytes.is_empty())
}

fn decode_bitwarden_bytes(value: &Value, label: &str) -> ApiResult<Vec<u8>> {
    let raw = required_string(value, &format!("{label} is missing"))?;
    base64url(&raw).ok_or_else(|| ChaaviError::invalid(format!("{label} is not valid base64")))
}

/// Bitwarden's credentialId: UUID hex bytes, or FIDO2 base64url.
fn decode_credential_id(value: &Value) -> ApiResult<Vec<u8>> {
    let raw = required_string(value, "passkey is missing credentialId")?;
    if super::schemas::is_uuid(&raw) {
        return Ok(HEXLOWER_PERMISSIVE.decode(raw.replace('-', "").as_bytes()).expect("a UUID is hex"));
    }
    decode_bitwarden_bytes(value, "passkey credentialId")
}

fn decode_optional_bytes(value: &Value) -> ApiResult<Vec<u8>> {
    match value.as_str() {
        None | Some("") => Ok(Vec::new()),
        Some(raw) => base64url(raw).ok_or_else(|| ChaaviError::invalid("passkey userHandle is not valid base64")),
    }
}

fn parse_counter(value: &Value) -> ApiResult<u64> {
    let parsed = match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) if !s.is_empty() => s.parse().ok(),
        _ => None,
    };
    parsed.ok_or_else(|| ChaaviError::invalid("passkey is missing counter"))
}

fn parse_discoverable(value: &Value) -> ApiResult<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::String(s) if s == "true" => Ok(true),
        Value::String(s) if s == "false" => Ok(false),
        _ => Err(ChaaviError::invalid("passkey is missing discoverable")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dadi::schemas;

    fn login() -> Value {
        json!({
            "id": "6f1d2b6e-3f3a-4c8a-9b1e-0a1b2c3d4e5f",
            "type": 1,
            "name": "GitHub",
            "notes": "n",
            "folderId": null,
            "favorite": true,
            "revisionDate": "2026-10-14T01:54:00.123456Z",
            "fields": [
                { "name": "Team", "value": "core", "type": 0, "linkedId": null },
                { "name": "Pin", "value": "1234", "type": 1, "linkedId": null },
                { "name": "User", "value": null, "type": 3, "linkedId": 100 },
            ],
            "login": {
                "username": "ankur",
                "password": "pw",
                "totp": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                "uris": [{ "uri": "https://github.com", "match": 1 }, { "uri": "https://gist.github.com", "match": null }],
                "fido2Credentials": [],
            },
        })
    }

    #[test]
    fn a_login_lists_without_secrets() {
        let item = item_from_cipher(&login()).unwrap();
        assert_eq!(item["revisionDate"], "2026-10-14T01:54:00.123Z");
        assert_eq!(item["login"]["uris"][0]["match"], "host");
        assert_eq!(item["login"]["uris"][1]["match"], "default");
        assert_eq!(item["login"]["hasPassword"], true);
        assert_eq!(item["fields"][1], json!({ "name": "Pin", "type": "hidden", "hasValue": true }));
        assert_eq!(item["fields"][2], json!({ "name": "User", "type": "linked", "linkedTo": "username" }));
        assert!(!item.to_string().contains("\"pw\""));
        assert!(!item.to_string().contains("1234"));
    }

    #[test]
    fn filters_match_like_the_adapter() {
        let items = vec![item_from_cipher(&login()).unwrap()];
        let filter = |q: Option<&str>, uri: Option<&str>, folder: Option<&str>| ItemFilter {
            q: q.map(str::to_owned),
            uri: uri.map(str::to_owned),
            r#type: None,
            folder: folder.map(str::to_owned),
        };
        let folders = vec![("f1".to_owned(), "Dev".to_owned()), ("f2".to_owned(), "Dev/api".to_owned())];
        let count = |filter: ItemFilter| filter_items(items.clone(), &filter, &folders).map(|found| found.len());
        assert_eq!(count(filter(Some("CORE"), None, None)).unwrap(), 1);
        assert_eq!(count(filter(None, Some("gist"), None)).unwrap(), 1);
        assert_eq!(count(filter(Some("1234"), None, None)).unwrap(), 0);
        // The sample login is in no folder: a real folder scope finds nothing, a made-up one is a 404.
        assert_eq!(count(filter(None, None, Some("dev"))).unwrap(), 0);
        assert_eq!(count(filter(None, None, Some("Nope"))).unwrap_err().status, 404);
    }

    #[test]
    fn reveal_routes() {
        let cipher = login();
        assert_eq!(reveal_from_cipher(&cipher, &RevealRequest::Field("password".into())).unwrap()["value"], "pw");
        assert_eq!(reveal_from_cipher(&cipher, &RevealRequest::Custom("Pin".into())).unwrap()["value"], "1234");
        assert!(reveal_from_cipher(&cipher, &RevealRequest::Custom("Team".into())).is_err());
        assert!(reveal_from_cipher(&cipher, &RevealRequest::Field("number".into())).is_err());
        assert_eq!(login_from_cipher(&cipher).unwrap(), json!({ "username": "ankur", "password": "pw" }));
        assert_eq!(totp_from_cipher(&cipher, 59_000).unwrap()["code"], "287082");
    }

    #[test]
    fn create_and_update() {
        let create =
            schemas::create_item(&json!({ "type": "login", "name": "New", "login": { "username": "a" } })).unwrap();
        let cipher = cipher_for_create(&create).unwrap();
        assert_eq!(cipher["login"]["password"].as_str().unwrap().len(), 20);

        let update = schemas::update_item(
            &json!({ "login": { "password": "next" }, "fields": [{ "name": "Pin", "type": "hidden" }] }),
        )
        .unwrap();
        let next = apply_update(&login(), &update).unwrap();
        assert_eq!(next["login"]["password"], "next");
        assert_eq!(next["fields"], json!([{ "name": "Pin", "value": "1234", "type": 1, "linkedId": null }]));

        let wrong = schemas::update_item(&json!({ "card": { "brand": "Visa" } })).unwrap();
        assert_eq!(apply_update(&login(), &wrong).unwrap_err().message, "card fields do not apply to a login item");
    }

    #[test]
    fn card_text_is_normalized() {
        let create = schemas::create_item(
            &json!({ "type": "card", "name": "Visa", "card": { "number": "4111-1111 1111-1111", "expMonth": "08" } }),
        )
        .unwrap();
        let cipher = cipher_for_create(&create).unwrap();
        assert_eq!(cipher["card"]["number"], "4111111111111111");
        assert_eq!(cipher["card"]["expMonth"], "8");
        let item = item_from_cipher(&json!({ "id": "x", "type": 3, "name": "Visa", "card": cipher["card"] })).unwrap();
        assert_eq!(item["card"]["hasNumber"], true);
        assert!(item["card"].get("number").is_none());
    }

    #[test]
    fn secrets_live_in_a_hidden_field() {
        let note = secret_note_for_create("Stripe API key", "sk_live", None).unwrap();
        assert_eq!(note_secret_from_cipher(&note).unwrap()["value"], "sk_live");
        let next = apply_secret(&note, "sk_new", Some("rotated")).unwrap();
        assert_eq!(note_secret_from_cipher(&next).unwrap()["value"], "sk_new");
        assert_eq!(next["notes"], "rotated");
    }

    #[test]
    fn passkey_is_encoded_for_chrome() {
        let mut cipher = login();
        cipher["login"]["fido2Credentials"] = json!([{
            "credentialId": "6f1d2b6e-3f3a-4c8a-9b1e-0a1b2c3d4e5f",
            "keyAlgorithm": "ECDSA",
            "keyCurve": "P-256",
            "keyValue": "AQID",
            "rpId": "github.com",
            "userHandle": "BAUG",
            "counter": "7",
            "discoverable": "true",
            "creationDate": "2026-01-01T00:00:00Z",
        }]);
        let passkey = passkey_from_cipher(&cipher).unwrap();
        assert_eq!(passkey["privateKey"], "AQID");
        assert_eq!(
            passkey["credentialId"],
            BASE64.encode(&HEXLOWER_PERMISSIVE.decode(b"6f1d2b6e3f3a4c8a9b1e0a1b2c3d4e5f").unwrap())
        );
        assert_eq!(passkey["signCount"], 7);
        assert_eq!(passkey["resident"], true);
        assert_eq!(
            item_from_cipher(&cipher).unwrap()["login"]["passkeys"][0]["creationDate"],
            "2026-01-01T00:00:00.000Z"
        );
    }
}
