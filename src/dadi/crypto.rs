//! Bitwarden client crypto for Chaavi: master key derivation, key stretching, and type 2
//! EncStrings (AES-256-CBC + HMAC-SHA256). The vault server never needed this; Chaavi does
//! because it reads and writes items as a Bitwarden client would. Never log a key or plaintext.

use std::num::NonZeroU32;

use data_encoding::BASE64;
use openssl::symm::{Cipher, decrypt as aes_decrypt, encrypt as aes_encrypt};
use ring::{digest, hkdf, hmac, pbkdf2};

/// Why a key could not be derived or a value could not be decrypted. Carries no secret.
#[derive(Debug)]
pub struct CryptoError(pub String);

type CryptoResult<T> = Result<T, CryptoError>;

fn fail<T>(message: impl Into<String>) -> CryptoResult<T> {
    Err(CryptoError(message.into()))
}

/// A 64-byte symmetric key: 32 bytes for AES-256 and 32 for HMAC-SHA256. Overwritten on drop.
pub struct SymKey {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl SymKey {
    /// A key from its 64-byte form (enc then mac), as a decrypted user or item key is stored.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 64 {
            return fail(format!("key is {} bytes, not 64", bytes.len()));
        }
        let mut key = Self {
            enc: [0; 32],
            mac: [0; 32],
        };
        key.enc.copy_from_slice(&bytes[..32]);
        key.mac.copy_from_slice(&bytes[32..]);
        Ok(key)
    }
}

impl Drop for SymKey {
    fn drop(&mut self) {
        self.enc.fill(0);
        self.mac.fill(0);
        // Keep the wipe from being treated as a dead store.
        std::hint::black_box((&self.enc, &self.mac));
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// The account's client KDF, from the user row.
pub enum Kdf {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        iterations: u32,
        memory_mib: u32,
        parallelism: u32,
    },
}

impl Kdf {
    /// The KDF of a user row (`client_kdf_type` 0 is PBKDF2-SHA256, 1 is Argon2id).
    pub fn from_user(kind: i32, iterations: i32, memory: Option<i32>, parallelism: Option<i32>) -> CryptoResult<Self> {
        let positive = |value: i32, name: &str| -> CryptoResult<u32> {
            u32::try_from(value)
                .ok()
                .filter(|v| *v > 0)
                .ok_or_else(|| CryptoError(format!("account KDF {name} is {value}")))
        };
        match kind {
            0 => Ok(Self::Pbkdf2 {
                iterations: positive(iterations, "iterations")?,
            }),
            1 => Ok(Self::Argon2id {
                iterations: positive(iterations, "iterations")?,
                memory_mib: positive(memory.unwrap_or(0), "memory")?,
                parallelism: positive(parallelism.unwrap_or(0), "parallelism")?,
            }),
            other => fail(format!("account KDF type {other} is not supported")),
        }
    }
}

/// The 32-byte master key from the master password and the account email (the salt).
pub fn master_key(password: &str, email: &str, kdf: &Kdf) -> CryptoResult<[u8; 32]> {
    let email = email.trim().to_lowercase();
    let mut out = [0u8; 32];
    match *kdf {
        Kdf::Pbkdf2 {
            iterations,
        } => {
            let iterations =
                NonZeroU32::new(iterations).ok_or_else(|| CryptoError("PBKDF2 iterations are 0".into()))?;
            pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iterations, email.as_bytes(), password.as_bytes(), &mut out);
        }
        Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            let salt = digest::digest(&digest::SHA256, email.as_bytes());
            let params = argon2::Params::new(memory_mib * 1024, iterations, parallelism, Some(32))
                .map_err(|e| CryptoError(format!("account Argon2 parameters are invalid: {e}")))?;
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(password.as_bytes(), salt.as_ref(), &mut out)
                .map_err(|e| CryptoError(format!("Argon2 failed: {e}")))?;
        }
    }
    Ok(out)
}

/// The master password hash a client sends at login: PBKDF2-SHA256(master key, password, 1).
pub fn master_password_hash(master_key: &[u8; 32], password: &str) -> String {
    let mut out = [0u8; 32];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::MIN, password.as_bytes(), master_key, &mut out);
    BASE64.encode(&out)
}

/// The stretched master key: HKDF-Expand(master key, "enc" / "mac", 32) each, no extract step.
pub fn stretch(master_key: &[u8; 32]) -> SymKey {
    struct Len32;
    impl hkdf::KeyType for Len32 {
        fn len(&self) -> usize {
            32
        }
    }
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, master_key);
    let mut key = SymKey {
        enc: [0; 32],
        mac: [0; 32],
    };
    // Expanding to 32 bytes with SHA-256 cannot exceed HKDF's 255-block limit.
    prk.expand(&[b"enc"], Len32).and_then(|okm| okm.fill(&mut key.enc)).expect("HKDF expand enc");
    prk.expand(&[b"mac"], Len32).and_then(|okm| okm.fill(&mut key.mac)).expect("HKDF expand mac");
    key
}

/// Whether `value` has the shape of a type 2 EncString (`2.<iv>|<data>|<mac>`).
pub fn is_enc_string(value: &str) -> bool {
    parse(value).is_ok()
}

struct Parts {
    iv: Vec<u8>,
    data: Vec<u8>,
    mac: Vec<u8>,
}

fn parse(value: &str) -> CryptoResult<Parts> {
    let Some(body) = value.strip_prefix("2.") else {
        let kind = value.split_once('.').map_or("none", |(kind, _)| kind);
        return fail(format!("encryption type {kind} is not supported"));
    };
    let mut pieces = body.split('|');
    let (Some(iv), Some(data), Some(mac), None) = (pieces.next(), pieces.next(), pieces.next(), pieces.next()) else {
        return fail("encrypted value does not have three parts");
    };
    let decode =
        |part: &str| BASE64.decode(part.as_bytes()).map_err(|_| CryptoError("encrypted value is not base64".into()));
    let parts = Parts {
        iv: decode(iv)?,
        data: decode(data)?,
        mac: decode(mac)?,
    };
    if parts.iv.len() != 16 || parts.mac.len() != 32 || parts.data.is_empty() {
        return fail("encrypted value has the wrong lengths");
    }
    Ok(parts)
}

/// Decrypt a type 2 EncString. The MAC is checked (in constant time) before decrypting.
pub fn decrypt(value: &str, key: &SymKey) -> CryptoResult<Vec<u8>> {
    let parts = parse(value)?;
    let mac_key = hmac::Key::new(hmac::HMAC_SHA256, &key.mac);
    let mut signed = parts.iv.clone();
    signed.extend_from_slice(&parts.data);
    if hmac::verify(&mac_key, &signed, &parts.mac).is_err() {
        return fail("encrypted value fails its MAC");
    }
    aes_decrypt(Cipher::aes_256_cbc(), &key.enc, Some(&parts.iv), &parts.data)
        .map_err(|_| CryptoError("encrypted value does not decrypt".into()))
}

/// Decrypt a type 2 EncString holding UTF-8 text.
pub fn decrypt_str(value: &str, key: &SymKey) -> CryptoResult<String> {
    String::from_utf8(decrypt(value, key)?).map_err(|_| CryptoError("decrypted value is not UTF-8".into()))
}

/// Encrypt `plain` as a type 2 EncString with a fresh random IV.
pub fn encrypt(plain: &[u8], key: &SymKey) -> String {
    let iv = crate::crypto::get_random_bytes::<16>();
    encrypt_with_iv(plain, key, &iv)
}

fn encrypt_with_iv(plain: &[u8], key: &SymKey, iv: &[u8; 16]) -> String {
    // AES-256-CBC with a 32-byte key and 16-byte IV cannot fail for any input length.
    let data = aes_encrypt(Cipher::aes_256_cbc(), &key.enc, Some(iv), plain).expect("AES-256-CBC encrypt");
    let mac_key = hmac::Key::new(hmac::HMAC_SHA256, &key.mac);
    let mut signed = iv.to_vec();
    signed.extend_from_slice(&data);
    let mac = hmac::sign(&mac_key, &signed);
    format!("2.{}|{}|{}", BASE64.encode(iv), BASE64.encode(&data), BASE64.encode(mac.as_ref()))
}

/// Encrypt UTF-8 text as a type 2 EncString.
pub fn encrypt_str(plain: &str, key: &SymKey) -> String {
    encrypt(plain.as_bytes(), key)
}

/// Base64 of SHA-256 of `text`: the plaintext of a login URI's checksum.
pub fn sha256_b64(text: &str) -> String {
    BASE64.encode(digest::digest(&digest::SHA256, text.as_bytes()).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors in testdata/ were computed independently with Node's crypto: PBKDF2-SHA256 at
    // 600000 iterations (Argon2id t=3 m=64MiB p=4), salt "chaavi@example.com", a fixed user
    // key wrapped by the stretched master key, and a value encrypted with that user key.
    const PASSWORD: &str = "correct horse battery staple";
    const EMAIL: &str = "Chaavi@Example.com ";

    #[test]
    fn pbkdf2_master_key_and_hash_match_the_reference() {
        let kdf = Kdf::from_user(0, 600_000, None, None).unwrap();
        let key = master_key(PASSWORD, EMAIL, &kdf).unwrap();
        assert_eq!(BASE64.encode(&key), include_str!("testdata/master_key.b64").trim());
        assert_eq!(master_password_hash(&key, PASSWORD), include_str!("testdata/master_password_hash.b64").trim());
    }

    #[test]
    fn stretched_key_decrypts_the_reference_user_key_and_value() {
        let kdf = Kdf::from_user(0, 600_000, None, None).unwrap();
        let stretched = stretch(&master_key(PASSWORD, EMAIL, &kdf).unwrap());
        let user_key =
            SymKey::from_bytes(&decrypt(include_str!("testdata/akey.txt").trim(), &stretched).unwrap()).unwrap();
        assert_eq!(decrypt_str(include_str!("testdata/value.txt").trim(), &user_key).unwrap(), "hunter2 ✓");
    }

    #[test]
    fn encrypt_round_trips_and_a_tampered_mac_is_refused() {
        let key = SymKey::from_bytes(&[7u8; 64]).unwrap();
        let enc = encrypt_str("secret value", &key);
        assert!(is_enc_string(&enc));
        assert_eq!(decrypt_str(&enc, &key).unwrap(), "secret value");
        let iv = [1u8; 16];
        let fixed = encrypt_with_iv(b"secret value", &key, &iv);
        let other_iv = encrypt_with_iv(b"secret value", &key, &[2u8; 16]);
        let (head, _) = fixed.rsplit_once('|').unwrap();
        let (_, wrong_mac) = other_iv.rsplit_once('|').unwrap();
        assert!(decrypt(&format!("{head}|{wrong_mac}"), &key).unwrap_err().0.contains("MAC"));
        let other = SymKey::from_bytes(&[8u8; 64]).unwrap();
        assert!(decrypt(&enc, &other).is_err());
    }

    #[test]
    fn other_encryption_types_are_refused() {
        let key = SymKey::from_bytes(&[7u8; 64]).unwrap();
        assert!(decrypt("0.abc|def", &key).unwrap_err().0.contains("type 0"));
        assert!(!is_enc_string("plain text"));
    }

    #[test]
    fn argon2id_derives_a_key() {
        let kdf = Kdf::from_user(1, 3, Some(64), Some(4)).unwrap();
        let key = master_key(PASSWORD, EMAIL, &kdf).unwrap();
        assert_eq!(BASE64.encode(&key), include_str!("testdata/argon2_master_key.b64").trim());
    }
}
