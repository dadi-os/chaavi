//! Generated login passwords. Never log the return value.

use super::error::{ApiResult, ChaaviError};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SPECIAL: &[u8] = b"!@#$%^&*";

/// Default generated login length.
pub const DEFAULT_LENGTH: u32 = 20;
/// Inclusive bounds for a generated length.
pub const LENGTH_MIN: u32 = 12;
pub const LENGTH_MAX: u32 = 64;

/// A uniform random index below `n`, by rejection sampling over the OS RNG.
fn random_below(n: usize) -> usize {
    let n = u64::try_from(n).expect("a small set");
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let value = u64::from_be_bytes(crate::crypto::get_random_bytes::<8>());
        if value < zone {
            return usize::try_from(value % n).expect("below a usize");
        }
    }
}

/// A password of `length` with at least one character from each class (lower, upper, digit,
/// and special when asked), shuffled.
pub fn generate(length: u32, special: bool) -> ApiResult<String> {
    if !(LENGTH_MIN..=LENGTH_MAX).contains(&length) {
        return Err(ChaaviError::invalid("length is out of range"));
    }
    let mut classes = vec![LOWER, UPPER, DIGITS];
    if special {
        classes.push(SPECIAL);
    }
    let pool: Vec<u8> = classes.concat();
    let mut chars: Vec<u8> = classes.iter().map(|set| set[random_below(set.len())]).collect();
    while chars.len() < length as usize {
        chars.push(pool[random_below(pool.len())]);
    }
    for i in (1..chars.len()).rev() {
        chars.swap(i, random_below(i + 1));
    }
    Ok(String::from_utf8(chars).expect("ASCII password"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_every_class_and_the_length() {
        for _ in 0..50 {
            let pw = generate(12, true).unwrap();
            assert_eq!(pw.len(), 12);
            assert!(pw.bytes().any(|b| LOWER.contains(&b)));
            assert!(pw.bytes().any(|b| UPPER.contains(&b)));
            assert!(pw.bytes().any(|b| DIGITS.contains(&b)));
            assert!(pw.bytes().any(|b| SPECIAL.contains(&b)));
        }
        assert!(!generate(30, false).unwrap().bytes().any(|b| SPECIAL.contains(&b)));
        assert!(generate(11, true).is_err());
        assert!(generate(65, true).is_err());
    }
}
