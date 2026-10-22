//! Ed25519 SSH keys in OpenSSH format for new SSH key items. Never log the private key.

use data_encoding::BASE64;
use openssl::pkey::PKey;
use ring::digest;
use serde_json::{Value, json};

use super::error::{ApiResult, ChaaviError};

const KEY_TYPE: &str = "ssh-ed25519";

/// A new Ed25519 key as Bitwarden stores it: `privateKey` as an unencrypted `openssh-key-v1`
/// PEM, `publicKey` as an authorized_keys line, and its `SHA256:` `keyFingerprint`.
pub fn generate_ssh_key() -> ApiResult<Value> {
    let failed = |_| ChaaviError::new(500, "internal_error", "internal error");
    let key = PKey::generate_ed25519().map_err(failed)?;
    let seed = key.raw_private_key().map_err(failed)?;
    let public = key.raw_public_key().map_err(failed)?;

    let mut public_blob = Vec::new();
    ssh_string(&mut public_blob, KEY_TYPE.as_bytes());
    ssh_string(&mut public_blob, &public);

    let check = crate::crypto::get_random_bytes::<4>();
    let mut section = Vec::new();
    section.extend_from_slice(&check);
    section.extend_from_slice(&check);
    ssh_string(&mut section, KEY_TYPE.as_bytes());
    ssh_string(&mut section, &public);
    ssh_string(&mut section, &[seed.as_slice(), public.as_slice()].concat());
    ssh_string(&mut section, b"");
    let mut pad = 1u8;
    while section.len() % 8 != 0 {
        section.push(pad);
        pad += 1;
    }

    let mut body = b"openssh-key-v1\0".to_vec();
    ssh_string(&mut body, b"none");
    ssh_string(&mut body, b"none");
    ssh_string(&mut body, b"");
    body.extend_from_slice(&1u32.to_be_bytes());
    ssh_string(&mut body, &public_blob);
    ssh_string(&mut body, &section);

    let encoded = BASE64.encode(&body);
    let lines: Vec<&str> =
        encoded.as_bytes().chunks(70).map(|chunk| std::str::from_utf8(chunk).unwrap_or_default()).collect();
    Ok(json!({
        "privateKey": format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n", lines.join("\n")),
        "publicKey": format!("{KEY_TYPE} {}", BASE64.encode(&public_blob)),
        "keyFingerprint": fingerprint(&public_blob),
    }))
}

/// OpenSSH's `SHA256:` fingerprint of a public key blob (unpadded base64).
fn fingerprint(public_blob: &[u8]) -> String {
    let hash = BASE64.encode(digest::digest(&digest::SHA256, public_blob).as_ref());
    format!("SHA256:{}", hash.trim_end_matches('='))
}

/// SSH wire `string`: a big-endian u32 length, then the bytes.
fn ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).expect("an SSH field under 4 GiB").to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_is_openssh_ed25519() {
        let key = generate_ssh_key().unwrap();
        let private = key["privateKey"].as_str().unwrap();
        assert!(private.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(private.lines().all(|line| line.len() <= 70 || line.starts_with("-----")));
        let public = key["publicKey"].as_str().unwrap();
        let blob = BASE64.decode(public.strip_prefix("ssh-ed25519 ").unwrap().as_bytes()).unwrap();
        assert_eq!(blob.len(), 4 + 11 + 4 + 32);
        assert_eq!(key["keyFingerprint"].as_str().unwrap(), fingerprint(&blob));
    }
}
