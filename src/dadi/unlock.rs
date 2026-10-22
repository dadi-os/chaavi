//! The agent's unlock: find the account named by `CHAAVI_EMAIL`, check `CHAAVI_PASSWORD` the
//! way a login would, and hold the decrypted user key. The key is cached for the account's
//! security stamp, so a password change or key rotation re-derives it (or fails closed).

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, LazyLock},
};

use tokio::sync::Mutex;

use super::{
    crypto::{self, Kdf, SymKey},
    error::{ApiResult, ChaaviError},
};
use crate::{
    CONFIG,
    auth::{ClientIp, Headers},
    db::{
        DbConn,
        models::{Device, DeviceId, DeviceType, User, UserId},
    },
};

pub const EMAIL_VAR: &str = "CHAAVI_EMAIL";
pub const PASSWORD_VAR: &str = "CHAAVI_PASSWORD";
const LEGACY_PASSWORD_VAR: &str = "BW_PASSWORD";

/// The device Chaavi's writes come from. Never saved: it only names the origin of pushes, so
/// clients do not ignore them as their own.
const DEVICE_ID: &str = "c4aa71d0-0000-4000-8000-00000000c4a1";

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// The agent's master password: `CHAAVI_PASSWORD`, else the adapter's old `BW_PASSWORD`, so a
/// box whose .env still has the old name keeps working until Preferences rewrites it.
fn password() -> String {
    let password = env(PASSWORD_VAR);
    if password.is_empty() {
        env(LEGACY_PASSWORD_VAR)
    } else {
        password
    }
}

/// The vault account: the one named by `CHAAVI_EMAIL`, or the only account when it is unset.
/// 503 when the password is empty (or the email is, with several accounts); 502 when the
/// account does not exist.
pub async fn account(conn: &DbConn) -> ApiResult<User> {
    if password().is_empty() {
        return Err(ChaaviError::unconfigured(PASSWORD_VAR));
    }
    let email = env(EMAIL_VAR);
    if !email.is_empty() {
        return User::find_by_mail(&email, conn)
            .await
            .ok_or_else(|| ChaaviError::unreachable(format!("no vault account is registered for {EMAIL_VAR}")));
    }
    let mut users = User::get_all(conn).await;
    match (users.pop(), users.is_empty()) {
        (Some((user, _)), true) => Ok(user),
        (None, _) => Err(ChaaviError::unreachable("no vault account exists yet")),
        _ => Err(ChaaviError::unconfigured(EMAIL_VAR)),
    }
}

struct Cached {
    user_uuid: UserId,
    stamp: String,
    key: Arc<SymKey>,
}

static CACHE: LazyLock<Mutex<Option<Cached>>> = LazyLock::new(|| Mutex::new(None));

/// An unlocked account for one request: its user key and the request headers upstream's write
/// path expects from a client.
pub struct Session {
    pub key: Arc<SymKey>,
    pub headers: Headers,
}

impl Session {
    pub fn user(&self) -> &User {
        &self.headers.user
    }
}

/// Unlock for this request: 503 when the password is empty, 502 when the account is missing or
/// the password does not unlock it. The KDF salt is the account's own email.
pub async fn open(conn: &DbConn) -> ApiResult<Session> {
    let user = account(conn).await?;
    let email = user.email.clone();

    let mut cache = CACHE.lock().await;
    let key = match cache.as_ref() {
        Some(cached) if cached.user_uuid == user.uuid && cached.stamp == user.security_stamp => Arc::clone(&cached.key),
        _ => {
            let key = Arc::new(derive(&user, email, password()).await?);
            *cache = Some(Cached {
                user_uuid: user.uuid.clone(),
                stamp: user.security_stamp.clone(),
                key: Arc::clone(&key),
            });
            key
        }
    };
    drop(cache);

    let device = Device::new(
        DeviceId::from(DEVICE_ID.to_owned()),
        user.uuid.clone(),
        "Chaavi".to_owned(),
        DeviceType::Sdk as i32,
    );
    Ok(Session {
        key,
        headers: Headers {
            host: CONFIG.domain(),
            device,
            user,
            ip: ClientIp {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
        },
    })
}

/// Master key → check against the stored password hash → stretched key → user key.
async fn derive(user: &User, email: String, password: String) -> ApiResult<SymKey> {
    let cannot =
        |e: crypto::CryptoError| ChaaviError::unreachable(format!("the vault account key cannot be derived: {}", e.0));
    let kdf =
        Kdf::from_user(user.client_kdf_type, user.client_kdf_iter, user.client_kdf_memory, user.client_kdf_parallelism)
            .map_err(cannot)?;
    let (mut master_key, password) =
        tokio::task::spawn_blocking(move || crypto::master_key(&password, &email, &kdf).map(|key| (key, password)))
            .await
            .map_err(|_| ChaaviError::new(500, "internal_error", "internal error"))?
            .map_err(cannot)?;

    let hash = crypto::master_password_hash(&master_key, &password);
    let verified = user.check_valid_password(&hash);
    let stretched = crypto::stretch(&master_key);
    master_key.fill(0);
    if !verified {
        return Err(ChaaviError::unreachable(format!(
            "{PASSWORD_VAR} does not unlock the vault account for {EMAIL_VAR}"
        )));
    }
    let bytes = crypto::decrypt(&user.akey, &stretched).map_err(cannot)?;
    SymKey::from_bytes(&bytes).map_err(cannot)
}
