//! RFC 6238 one-time codes from a login's stored authenticator key. Never log a seed or code.

use ring::hmac;
use serde_json::{Value, json};

use super::error::{ApiResult, ChaaviError};

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

struct Params {
    key: Vec<u8>,
    period: u64,
    digits: u32,
    algorithm: hmac::Algorithm,
}

/// The code for `seed` at `now_ms` as `{ code, period, remaining }`. `seed` is a base32 key or
/// an `otpauth://totp/…` URI; the URI's period, digits and algorithm apply, and an omitted one
/// takes the otpauth spec's value (30 s, 6 digits, SHA1).
pub fn totp_code(seed: &str, now_ms: u64) -> ApiResult<Value> {
    let params = parse_seed(seed)?;
    let seconds = now_ms / 1000;
    let counter = seconds / params.period;
    let key = hmac::Key::new(params.algorithm, &params.key);
    let mac = hmac::sign(&key, &counter.to_be_bytes());
    let mac = mac.as_ref();
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([mac[offset], mac[offset + 1], mac[offset + 2], mac[offset + 3]]) & 0x7fff_ffff;
    let code = match 10u64.checked_pow(params.digits) {
        Some(modulus) => u64::from(binary) % modulus,
        None => u64::from(binary),
    };
    Ok(json!({
        "code": format!("{code:0>width$}", width = params.digits as usize),
        "period": params.period,
        "remaining": params.period - (seconds % params.period),
    }))
}

fn parse_seed(seed: &str) -> ApiResult<Params> {
    let trimmed = seed.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("steam://") {
        return Err(ChaaviError::invalid("Steam authenticator keys are not supported"));
    }
    if !lower.starts_with("otpauth://") {
        return Ok(Params {
            key: decode_base32(trimmed)?,
            period: 30,
            digits: 6,
            algorithm: hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        });
    }
    let url = url::Url::parse(trimmed).map_err(|_| ChaaviError::invalid("authenticator URI is not a valid URL"))?;
    if url.host_str().is_none_or(|host| !host.eq_ignore_ascii_case("totp")) {
        return Err(ChaaviError::invalid("authenticator key is not a TOTP otpauth URI"));
    }
    let param = |name: &str| url.query_pairs().find(|(key, _)| key == name).map(|(_, value)| value.into_owned());
    let secret = param("secret").filter(|secret| !secret.is_empty());
    let Some(secret) = secret else {
        return Err(ChaaviError::invalid("authenticator URI has no secret"));
    };
    Ok(Params {
        key: decode_base32(&secret)?,
        period: positive_int(param("period"), 30, "period")?.into(),
        digits: positive_int(param("digits"), 6, "digits")?,
        algorithm: algorithm_of(param("algorithm"))?,
    })
}

/// An otpauth integer parameter in 1..=300; absent takes the spec's value.
fn positive_int(raw: Option<String>, spec_value: u32, name: &str) -> ApiResult<u32> {
    let Some(raw) = raw else {
        return Ok(spec_value);
    };
    raw.parse::<u32>()
        .ok()
        .filter(|n| (1..=300).contains(n))
        .ok_or_else(|| ChaaviError::invalid(format!("authenticator URI has an invalid {name}")))
}

fn algorithm_of(raw: Option<String>) -> ApiResult<hmac::Algorithm> {
    let Some(raw) = raw else {
        return Ok(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY);
    };
    match raw.to_ascii_uppercase().as_str() {
        "SHA1" => Ok(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
        "SHA256" => Ok(hmac::HMAC_SHA256),
        "SHA512" => Ok(hmac::HMAC_SHA512),
        _ => Err(ChaaviError::invalid(format!("authenticator algorithm {raw} is not supported"))),
    }
}

/// RFC 4648 base32, ignoring spaces, hyphens, case and padding; trailing bits are dropped.
fn decode_base32(text: &str) -> ApiResult<Vec<u8>> {
    let clean: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=' && *b != b'-')
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if clean.is_empty() {
        return Err(ChaaviError::invalid("authenticator key is empty"));
    }
    let mut bytes = Vec::with_capacity(clean.len() * 5 / 8);
    let (mut bits, mut value) = (0u32, 0u32);
    for c in clean {
        let Some(index) = BASE32.iter().position(|b| *b == c).and_then(|i| u32::try_from(i).ok()) else {
            return Err(ChaaviError::invalid("authenticator key is not valid base32"));
        };
        value = (value << 5) | index;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push(((value >> bits) & 0xff) as u8);
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B: seed "12345678901234567890" (base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ).
    const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_sha1_eight_digits() {
        let uri = format!("otpauth://totp/x?secret={SEED}&digits=8");
        assert_eq!(totp_code(&uri, 59_000).unwrap()["code"], "94287082");
        assert_eq!(totp_code(&uri, 1_111_111_109_000).unwrap()["code"], "07081804");
    }

    #[test]
    fn plain_key_defaults_and_remaining() {
        let out = totp_code("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq", 59_000).unwrap();
        assert_eq!(out["code"], "287082");
        assert_eq!(out["period"], 30);
        assert_eq!(out["remaining"], 1);
    }

    #[test]
    fn bad_keys_are_refused() {
        assert!(totp_code("steam://ABC", 0).is_err());
        assert!(totp_code("not base32!", 0).is_err());
        assert!(totp_code("otpauth://hotp/x?secret=ABC", 0).is_err());
        assert!(totp_code("otpauth://totp/x?secret=GEZD&algorithm=MD5", 0).is_err());
    }
}
