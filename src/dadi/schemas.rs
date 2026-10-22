//! Request bodies, params and queries, validated as strictly as the TypeScript zod schemas:
//! unknown keys, wrong types and out-of-range values are `422 invalid_request` naming the path.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use super::{
    error::{ApiResult, ChaaviError},
    password::{LENGTH_MAX, LENGTH_MIN},
};

/// Bitwarden item types as Chaavi names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemType {
    Login,
    Note,
    Card,
    Identity,
    SshKey,
    BankAccount,
    DriversLicense,
    Passport,
}

impl ItemType {
    pub const ALL: [Self; 8] = [
        Self::Login,
        Self::Note,
        Self::Card,
        Self::Identity,
        Self::SshKey,
        Self::BankAccount,
        Self::DriversLicense,
        Self::Passport,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Note => "note",
            Self::Card => "card",
            Self::Identity => "identity",
            Self::SshKey => "sshKey",
            Self::BankAccount => "bankAccount",
            Self::DriversLicense => "driversLicense",
            Self::Passport => "passport",
        }
    }

    /// Bitwarden's cipher type code.
    pub fn code(self) -> i64 {
        match self {
            Self::Login => 1,
            Self::Note => 2,
            Self::Card => 3,
            Self::Identity => 4,
            Self::SshKey => 5,
            Self::BankAccount => 6,
            Self::DriversLicense => 7,
            Self::Passport => 8,
        }
    }

    /// The key of the type's own data object on a cipher.
    pub fn data_key(self) -> &'static str {
        match self {
            Self::Note => "secureNote",
            other => other.name(),
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == name)
    }

    pub fn from_code(code: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.code() == code)
    }

    /// The flat string fields of a card, identity, bank account, driver's license or passport:
    /// (Bitwarden name, max length, secret). None for the other types.
    pub fn text_fields(self) -> Option<&'static [(&'static str, usize, bool)]> {
        match self {
            Self::Card => Some(CARD),
            Self::Identity => Some(IDENTITY),
            Self::BankAccount => Some(BANK_ACCOUNT),
            Self::DriversLicense => Some(DRIVERS_LICENSE),
            Self::Passport => Some(PASSPORT),
            _ => None,
        }
    }
}

const CARD: &[(&str, usize, bool)] = &[
    ("cardholderName", 200, false),
    ("brand", 50, false),
    ("expMonth", 2, false),
    ("expYear", 4, false),
    ("number", 100, true),
    ("code", 4, true),
];

const IDENTITY: &[(&str, usize, bool)] = &[
    ("title", 30, false),
    ("firstName", 200, false),
    ("middleName", 200, false),
    ("lastName", 200, false),
    ("address1", 200, false),
    ("address2", 200, false),
    ("address3", 200, false),
    ("city", 100, false),
    ("state", 100, false),
    ("postalCode", 30, false),
    ("country", 100, false),
    ("company", 200, false),
    ("email", 320, false),
    ("phone", 50, false),
    ("username", 320, false),
    ("ssn", 50, true),
    ("passportNumber", 50, true),
    ("licenseNumber", 50, true),
];

const BANK_ACCOUNT: &[(&str, usize, bool)] = &[
    ("bankName", 200, false),
    ("nameOnAccount", 200, false),
    ("accountType", 50, false),
    ("routingNumber", 50, false),
    ("branchNumber", 50, false),
    ("swiftCode", 20, false),
    ("bankContactPhone", 50, false),
    ("accountNumber", 50, true),
    ("pin", 20, true),
    ("iban", 50, true),
];

const DRIVERS_LICENSE: &[(&str, usize, bool)] = &[
    ("firstName", 200, false),
    ("middleName", 200, false),
    ("lastName", 200, false),
    ("dateOfBirth", 30, false),
    ("issuingCountry", 100, false),
    ("issuingState", 100, false),
    ("issueDate", 30, false),
    ("expirationDate", 30, false),
    ("issuingAuthority", 200, false),
    ("licenseClass", 30, false),
    ("licenseNumber", 50, true),
];

const PASSPORT: &[(&str, usize, bool)] = &[
    ("surname", 200, false),
    ("givenName", 200, false),
    ("dateOfBirth", 30, false),
    ("sex", 30, false),
    ("birthPlace", 200, false),
    ("nationality", 100, false),
    ("issuingCountry", 100, false),
    ("passportType", 30, false),
    ("issuingAuthority", 200, false),
    ("issueDate", 30, false),
    ("expirationDate", 30, false),
    ("passportNumber", 50, true),
    ("nationalIdentificationNumber", 50, true),
];

/// Every target a linked custom field may name.
pub const LINKED_TARGETS: &[&str] = &[
    "username",
    "password",
    "cardholderName",
    "expMonth",
    "expYear",
    "code",
    "brand",
    "number",
    "title",
    "firstName",
    "middleName",
    "lastName",
    "fullName",
    "address1",
    "address2",
    "address3",
    "city",
    "state",
    "postalCode",
    "country",
    "company",
    "email",
    "phone",
    "ssn",
    "passportNumber",
    "licenseNumber",
];

/// The fields `POST /v1/items/:id/reveal` may name besides `custom`.
pub const REVEAL_FIELDS: &[&str] = &[
    "password",
    "totp",
    "number",
    "code",
    "ssn",
    "passportNumber",
    "licenseNumber",
    "privateKey",
    "accountNumber",
    "pin",
    "iban",
    "nationalIdentificationNumber",
    "notes",
];

/// A JSON key that may be absent, null, or set (PATCH semantics).
#[derive(Clone, Debug, Default)]
pub enum Field<T> {
    #[default]
    Missing,
    Null,
    Set(T),
}

pub enum CustomFieldInput {
    Text {
        name: String,
        value: String,
    },
    /// `value` None keeps the stored value of the hidden field with this name.
    Hidden {
        name: String,
        value: Option<String>,
    },
    Boolean {
        name: String,
        value: bool,
    },
    Linked {
        name: String,
        linked_to: String,
    },
}

impl CustomFieldInput {
    pub fn name(&self) -> &str {
        match self {
            Self::Text {
                name,
                ..
            }
            | Self::Hidden {
                name,
                ..
            }
            | Self::Boolean {
                name,
                ..
            }
            | Self::Linked {
                name,
                ..
            } => name,
        }
    }
}

pub struct UriInput {
    pub uri: String,
    /// None is the account default.
    pub r#match: Option<String>,
}

#[derive(Default)]
pub struct LoginInput {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Option<Vec<UriInput>>,
    pub length: Option<u32>,
    pub special: Option<bool>,
}

#[derive(Default)]
pub struct SshKeyInput {
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub key_fingerprint: Option<String>,
}

/// The given string fields of a flat type, in the order the body gave them.
pub type TextInput = Vec<(String, String)>;

pub struct CreateItem {
    pub r#type: ItemType,
    pub name: String,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub notes: Option<String>,
    pub fields: Vec<CustomFieldInput>,
    pub login: Option<LoginInput>,
    pub ssh_key: Option<SshKeyInput>,
    pub text: Option<TextInput>,
}

#[derive(Default)]
pub struct UpdateItem {
    pub name: Option<String>,
    pub folder_id: Field<String>,
    pub favorite: Option<bool>,
    pub notes: Option<String>,
    pub fields: Option<Vec<CustomFieldInput>>,
    pub login: Option<LoginInput>,
    pub ssh_key: Option<SshKeyInput>,
    /// Type objects in the body other than login and sshKey.
    pub texts: Vec<(ItemType, TextInput)>,
}

pub enum RevealRequest {
    Field(String),
    Custom(String),
}

pub struct ItemFilter {
    pub q: Option<String>,
    pub uri: Option<String>,
    pub r#type: Option<ItemType>,
    /// A folder name; takes the items in that folder and in every folder nested under it.
    pub folder: Option<String>,
}

/// One JSON object under validation, with its path for messages.
struct Obj<'a> {
    map: &'a Map<String, Value>,
    path: String,
}

fn at(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

fn bad(path: &str, message: impl std::fmt::Display) -> ChaaviError {
    if path.is_empty() {
        ChaaviError::invalid(message.to_string())
    } else {
        ChaaviError::invalid(format!("{path}: {message}"))
    }
}

fn object<'a>(value: &'a Value, path: &str) -> ApiResult<Obj<'a>> {
    match value {
        Value::Object(map) => Ok(Obj {
            map,
            path: path.to_owned(),
        }),
        _ => Err(bad(path, "expected object")),
    }
}

/// Length in UTF-16 code units, as zod (JavaScript) counts it.
fn js_len(text: &str) -> usize {
    text.encode_utf16().count()
}

impl<'a> Obj<'a> {
    fn allow(&self, keys: &[&str]) -> ApiResult<()> {
        if let Some(key) = self.map.keys().find(|key| !keys.contains(&key.as_str())) {
            return Err(bad(&self.path, format!("Unrecognized key: \"{key}\"")));
        }
        Ok(())
    }

    fn string(&self, key: &str, min: usize, max: usize) -> ApiResult<Option<String>> {
        let path = at(&self.path, key);
        match self.map.get(key) {
            None => Ok(None),
            Some(Value::String(text)) => {
                let len = js_len(text);
                if len < min {
                    return Err(bad(&path, format!("String must contain at least {min} character(s)")));
                }
                if len > max {
                    return Err(bad(&path, format!("String must contain at most {max} character(s)")));
                }
                Ok(Some(text.clone()))
            }
            Some(_) => Err(bad(&path, "expected string")),
        }
    }

    fn required_string(&self, key: &str, min: usize, max: usize) -> ApiResult<String> {
        self.string(key, min, max)?.ok_or_else(|| bad(&at(&self.path, key), "Required"))
    }

    fn boolean(&self, key: &str) -> ApiResult<Option<bool>> {
        match self.map.get(key) {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(bad(&at(&self.path, key), "expected boolean")),
        }
    }

    fn int(&self, key: &str, min: u32, max: u32) -> ApiResult<Option<u32>> {
        let path = at(&self.path, key);
        match self.map.get(key) {
            None => Ok(None),
            Some(Value::Number(n)) => match n.as_i64() {
                Some(n) if n < i64::from(min) => {
                    Err(bad(&path, format!("Number must be greater than or equal to {min}")))
                }
                Some(n) if n > i64::from(max) => Err(bad(&path, format!("Number must be less than or equal to {max}"))),
                Some(n) => Ok(u32::try_from(n).ok()),
                None => Err(bad(&path, "Expected integer, received float")),
            },
            Some(_) => Err(bad(&path, "expected number")),
        }
    }

    fn array(&self, key: &str, max: usize) -> ApiResult<Option<&'a Vec<Value>>> {
        let path = at(&self.path, key);
        match self.map.get(key) {
            None => Ok(None),
            Some(Value::Array(items)) if items.len() > max => {
                Err(bad(&path, format!("Array must contain at most {max} element(s)")))
            }
            Some(Value::Array(items)) => Ok(Some(items)),
            Some(_) => Err(bad(&path, "expected array")),
        }
    }

    fn child(&self, key: &str) -> ApiResult<Option<Obj<'a>>> {
        match self.map.get(key) {
            None => Ok(None),
            Some(value) => object(value, &at(&self.path, key)).map(Some),
        }
    }

    fn uuid_or_null(&self, key: &str) -> ApiResult<Field<String>> {
        let path = at(&self.path, key);
        match self.map.get(key) {
            None => Ok(Field::Missing),
            Some(Value::Null) => Ok(Field::Null),
            Some(Value::String(text)) if is_uuid(text) => Ok(Field::Set(text.clone())),
            Some(Value::String(_)) => Err(bad(&path, "Invalid uuid")),
            Some(_) => Err(bad(&path, "expected string")),
        }
    }

    fn one_of(&self, key: &str, options: &[&str]) -> ApiResult<Option<String>> {
        let path = at(&self.path, key);
        match self.string(key, 0, usize::MAX)? {
            None => Ok(None),
            Some(value) if options.contains(&value.as_str()) => Ok(Some(value)),
            Some(_) => Err(bad(&path, format!("Invalid enum value. Expected {}", quoted(options)))),
        }
    }
}

fn quoted(options: &[&str]) -> String {
    options.iter().map(|o| format!("'{o}'")).collect::<Vec<_>>().join(" | ")
}

static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$").unwrap()
});

pub fn is_uuid(text: &str) -> bool {
    UUID_RE.is_match(text)
}

/// A JSON request body; malformed JSON is a 400 like Fastify's.
pub fn body(raw: &str) -> ApiResult<Value> {
    if raw.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(raw)
        .map_err(|e| ChaaviError::new(400, "invalid_request", format!("Body is not valid JSON: {e}")))
}

/// The `:id` path parameter.
pub fn item_id(id: &str) -> ApiResult<String> {
    if is_uuid(id) {
        Ok(id.to_owned())
    } else {
        Err(bad("id", "Invalid uuid"))
    }
}

/// The `:name` path parameter of a secret.
pub fn secret_name(name: &str) -> ApiResult<String> {
    let len = js_len(name);
    if !(1..=200).contains(&len) {
        return Err(bad("name", "String must contain between 1 and 200 character(s)"));
    }
    Ok(name.to_owned())
}

/// `GET /v1/items` query: `q`, `uri`, `type`; anything else is refused.
pub fn items_query(query: Option<&str>) -> ApiResult<ItemFilter> {
    let mut filter = ItemFilter {
        q: None,
        uri: None,
        r#type: None,
        folder: None,
    };
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        let value = value.into_owned();
        match key.as_ref() {
            "q" | "uri" if value.is_empty() => return Err(bad(&key, "String must contain at least 1 character(s)")),
            "q" => filter.q = Some(value),
            "uri" => filter.uri = Some(value),
            "folder" => {
                let name = value.trim();
                if name.is_empty() {
                    return Err(bad("folder", "String must contain at least 1 character(s)"));
                }
                filter.folder = Some(name.to_owned());
            }
            "type" => {
                let names: Vec<&str> = ItemType::ALL.iter().map(|t| t.name()).collect();
                filter.r#type = Some(
                    ItemType::from_name(&value)
                        .ok_or_else(|| bad("type", format!("Invalid enum value. Expected {}", quoted(&names))))?,
                );
            }
            other => return Err(bad("", format!("Unrecognized key: \"{other}\""))),
        }
    }
    Ok(filter)
}

fn custom_fields(items: &[Value], path: &str) -> ApiResult<Vec<CustomFieldInput>> {
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let field = object(item, &format!("{path}.{index}"))?;
            let name = field.required_string("name", 1, 200)?;
            match field.one_of("type", &["text", "hidden", "boolean", "linked"])?.as_deref() {
                Some("text") => {
                    field.allow(&["name", "type", "value"])?;
                    Ok(CustomFieldInput::Text {
                        name,
                        value: field.required_string("value", 0, 5000)?,
                    })
                }
                Some("hidden") => {
                    field.allow(&["name", "type", "value"])?;
                    Ok(CustomFieldInput::Hidden {
                        name,
                        value: field.string("value", 1, 5000)?,
                    })
                }
                Some("boolean") => {
                    field.allow(&["name", "type", "value"])?;
                    let value = field.boolean("value")?.ok_or_else(|| bad(&at(&field.path, "value"), "Required"))?;
                    Ok(CustomFieldInput::Boolean {
                        name,
                        value,
                    })
                }
                Some("linked") => {
                    field.allow(&["name", "type", "linkedTo"])?;
                    let linked_to = field
                        .one_of("linkedTo", LINKED_TARGETS)?
                        .ok_or_else(|| bad(&at(&field.path, "linkedTo"), "Required"))?;
                    Ok(CustomFieldInput::Linked {
                        name,
                        linked_to,
                    })
                }
                _ => Err(bad(&at(&field.path, "type"), "Invalid discriminator value")),
            }
        })
        .collect()
}

fn login(obj: &Obj<'_>, with_generator: bool) -> ApiResult<LoginInput> {
    let mut keys = vec!["username", "password", "totp", "uris"];
    if with_generator {
        keys.extend(["length", "special"]);
    }
    obj.allow(&keys)?;
    let uris = match obj.array("uris", 20)? {
        None => None,
        Some(items) => Some(
            items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let uri = object(item, &format!("{}.uris.{index}", obj.path))?;
                    uri.allow(&["uri", "match"])?;
                    Ok(UriInput {
                        uri: uri.required_string("uri", 1, 2000)?,
                        r#match: uri
                            .one_of("match", &["default", "domain", "host", "startsWith", "exact", "regex", "never"])?,
                    })
                })
                .collect::<ApiResult<Vec<_>>>()?,
        ),
    };
    Ok(LoginInput {
        username: obj.string("username", 0, 320)?,
        password: obj.string("password", 1, 500)?,
        totp: obj.string("totp", 0, 2000)?,
        uris,
        length: if with_generator {
            obj.int("length", LENGTH_MIN, LENGTH_MAX)?
        } else {
            None
        },
        special: if with_generator {
            obj.boolean("special")?
        } else {
            None
        },
    })
}

fn ssh_key(obj: &Obj<'_>) -> ApiResult<SshKeyInput> {
    obj.allow(&["privateKey", "publicKey", "keyFingerprint"])?;
    Ok(SshKeyInput {
        private_key: obj.string("privateKey", 0, 20000)?,
        public_key: obj.string("publicKey", 0, 5000)?,
        key_fingerprint: obj.string("keyFingerprint", 0, 200)?,
    })
}

static CARD_RULES: LazyLock<[(&str, Regex, &str); 4]> = LazyLock::new(|| {
    [
        ("number", Regex::new(r"^$|^(?:\d[\s-]?){12,19}$").unwrap(), "number must be 12 to 19 digits"),
        ("expMonth", Regex::new(r"^$|^(0?[1-9]|1[0-2])$").unwrap(), "expMonth must be 1 to 12"),
        ("expYear", Regex::new(r"^$|^\d{4}$").unwrap(), "expYear must be four digits"),
        ("code", Regex::new(r"^$|^\d{3,4}$").unwrap(), "code must be 3 or 4 digits"),
    ]
});

fn text(obj: &Obj<'_>, item_type: ItemType) -> ApiResult<TextInput> {
    let spec = item_type.text_fields().expect("a flat item type");
    let names: Vec<&str> = spec.iter().map(|(name, ..)| *name).collect();
    obj.allow(&names)?;
    let mut out = TextInput::new();
    for (name, max, _) in spec {
        let rule = (item_type == ItemType::Card).then(|| CARD_RULES.iter().find(|(field, ..)| field == name)).flatten();
        let value = match rule {
            Some((_, re, message)) => match obj.string(name, 0, usize::MAX)? {
                Some(value) if !re.is_match(&value) => return Err(bad(&at(&obj.path, name), message)),
                other => other,
            },
            None => obj.string(name, 0, *max)?,
        };
        if let Some(value) = value {
            out.push(((*name).to_owned(), value));
        }
    }
    Ok(out)
}

const BASE_KEYS: [&str; 5] = ["name", "folderId", "favorite", "notes", "fields"];

/// `POST /v1/items`.
pub fn create_item(value: &Value) -> ApiResult<CreateItem> {
    let obj = object(value, "")?;
    let names: Vec<&str> = ItemType::ALL.iter().map(|t| t.name()).collect();
    let type_name = obj.one_of("type", &names)?.ok_or_else(|| bad("type", "Invalid discriminator value"))?;
    let item_type = ItemType::from_name(&type_name).expect("checked above");
    let mut keys = BASE_KEYS.to_vec();
    keys.push("type");
    if item_type != ItemType::Note {
        keys.push(item_type.name());
    }
    obj.allow(&keys)?;
    let own = obj.child(item_type.name())?;
    let fields = match obj.array("fields", 50)? {
        Some(items) => custom_fields(items, "fields")?,
        None => Vec::new(),
    };
    Ok(CreateItem {
        r#type: item_type,
        name: obj.required_string("name", 1, 200)?,
        folder_id: match obj.uuid_or_null("folderId")? {
            Field::Set(id) => Some(id),
            _ => None,
        },
        favorite: obj.boolean("favorite")?.unwrap_or(false),
        notes: obj.string("notes", 0, 10000)?,
        fields,
        login: match (&own, item_type) {
            (Some(own), ItemType::Login) => Some(login(own, true)?),
            _ => None,
        },
        ssh_key: match (&own, item_type) {
            (Some(own), ItemType::SshKey) => Some(ssh_key(own)?),
            _ => None,
        },
        text: match (&own, item_type.text_fields()) {
            (Some(own), Some(_)) => Some(text(own, item_type)?),
            _ => None,
        },
    })
}

/// `PATCH /v1/items/:id`: at least one key.
pub fn update_item(value: &Value) -> ApiResult<UpdateItem> {
    let obj = object(value, "")?;
    let mut keys = BASE_KEYS.to_vec();
    keys.extend(["login", "card", "identity", "sshKey", "bankAccount", "driversLicense", "passport"]);
    obj.allow(&keys)?;
    if obj.map.is_empty() {
        return Err(bad("", "give at least one field to change"));
    }
    let mut out = UpdateItem {
        name: obj.string("name", 1, 200)?,
        folder_id: obj.uuid_or_null("folderId")?,
        favorite: obj.boolean("favorite")?,
        notes: obj.string("notes", 0, 10000)?,
        fields: obj.array("fields", 50)?.map(|items| custom_fields(items, "fields")).transpose()?,
        ..UpdateItem::default()
    };
    if let Some(own) = obj.child("login")? {
        out.login = Some(login(&own, false)?);
    }
    if let Some(own) = obj.child("sshKey")? {
        out.ssh_key = Some(ssh_key(&own)?);
    }
    for item_type in
        [ItemType::Card, ItemType::Identity, ItemType::BankAccount, ItemType::DriversLicense, ItemType::Passport]
    {
        if let Some(own) = obj.child(item_type.name())? {
            out.texts.push((item_type, text(&own, item_type)?));
        }
    }
    Ok(out)
}

/// `POST /v1/items/:id/reveal`.
pub fn reveal(value: &Value) -> ApiResult<RevealRequest> {
    let obj = object(value, "")?;
    if obj.map.get("field") == Some(&Value::String("custom".into())) {
        obj.allow(&["field", "name"])?;
        return Ok(RevealRequest::Custom(obj.required_string("name", 1, 200)?));
    }
    obj.allow(&["field"])?;
    let field = obj.one_of("field", REVEAL_FIELDS)?.ok_or_else(|| bad("field", "Required"))?;
    Ok(RevealRequest::Field(field))
}

/// Folder create and rename: the name is trimmed.
pub fn folder(value: &Value) -> ApiResult<String> {
    let obj = object(value, "")?;
    obj.allow(&["name"])?;
    let raw = obj.required_string("name", 0, usize::MAX)?;
    let name = raw.trim();
    let len = js_len(name);
    if len < 1 {
        return Err(bad("name", "String must contain at least 1 character(s)"));
    }
    if len > 100 {
        return Err(bad("name", "String must contain at most 100 character(s)"));
    }
    Ok(name.to_owned())
}

/// `PUT /v1/secrets/:name`: value and optional notes.
pub fn save_secret(value: &Value) -> ApiResult<(String, Option<String>)> {
    let obj = object(value, "")?;
    obj.allow(&["value", "notes"])?;
    Ok((obj.required_string("value", 1, 10000)?, obj.string("notes", 0, 10000)?))
}

/// `POST /v1/generate`: optional length and special; an empty body is the defaults.
pub fn generate(value: &Value) -> ApiResult<(Option<u32>, Option<bool>)> {
    if value.is_null() {
        return Ok((None, None));
    }
    let obj = object(value, "")?;
    obj.allow(&["length", "special"])?;
    Ok((obj.int("length", LENGTH_MIN, LENGTH_MAX)?, obj.boolean("special")?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeSet;

    /// Upstream's write path decides which cipher types exist. When a merge adds one (a wallet, say),
    /// this fails until `ItemType` learns it, instead of `GET /v1/items` returning corrupt_item
    /// for that item in production.
    #[test]
    fn handles_every_cipher_type_upstream_accepts() {
        let upstream: BTreeSet<i64> = include_str!("../api/core/ciphers.rs")
            .lines()
            .filter_map(|line| line.trim().split_once(" => data."))
            .filter_map(|(code, _)| code.trim().parse().ok())
            .collect();
        let ours: BTreeSet<i64> = ItemType::ALL.iter().map(|item_type| item_type.code()).collect();
        assert!(!upstream.is_empty(), "no cipher type arms found in src/api/core/ciphers.rs; update this test");
        assert_eq!(upstream, ours, "upstream accepts cipher types that src/dadi does not handle (see ItemType)");
    }

    #[test]
    fn create_refuses_another_types_object_and_unknown_keys() {
        assert!(create_item(&json!({"type": "login", "name": "x", "card": {}})).is_err());
        assert!(create_item(&json!({"type": "note", "name": "x", "extra": 1})).is_err());
        let ok = create_item(
            &json!({"type": "card", "name": "x", "card": {"number": "4111 1111 1111 1111", "expMonth": "08"}}),
        )
        .unwrap();
        assert_eq!(ok.text.unwrap().len(), 2);
        let err = create_item(&json!({"type": "card", "name": "x", "card": {"number": "12"}})).err().unwrap();
        assert_eq!(err.message, "card.number: number must be 12 to 19 digits");
    }

    #[test]
    fn update_needs_a_key_and_keeps_null_folder() {
        assert!(update_item(&json!({})).is_err());
        let update = update_item(&json!({"folderId": null})).unwrap();
        assert!(matches!(update.folder_id, Field::Null));
        assert!(update_item(&json!({"folderId": "nope"})).is_err());
    }

    #[test]
    fn query_is_strict() {
        assert!(items_query(Some("q=a&type=login")).is_ok());
        assert!(items_query(Some("type=bogus")).is_err());
        assert!(items_query(Some("other=1")).is_err());
        assert!(items_query(Some("q=")).is_err());
        assert_eq!(items_query(Some("folder=%20Dev%20")).unwrap().folder.as_deref(), Some("Dev"));
        assert!(items_query(Some("folder=%20")).is_err());
    }

    #[test]
    fn reveal_and_folder_shapes() {
        assert!(matches!(reveal(&json!({"field": "password"})).unwrap(), RevealRequest::Field(_)));
        assert!(matches!(reveal(&json!({"field": "custom", "name": "Secret"})).unwrap(), RevealRequest::Custom(_)));
        assert!(reveal(&json!({"field": "nope"})).is_err());
        assert_eq!(folder(&json!({"name": "  Work  "})).unwrap(), "Work");
        assert!(folder(&json!({"name": "   "})).is_err());
    }
}
