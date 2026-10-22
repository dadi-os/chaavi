//! List order as the Bitwarden CLI and clients show it: names compared case-insensitively with
//! ICU's root collation, simplified to what vault names use. Punctuation sorts before digits and
//! digits before letters, and within punctuation by ICU's order (so `Google - x` comes before
//! `Google (x)`, the opposite of ASCII). A name that differs only in case puts lowercase first.

/// Punctuation and symbols in ICU root-collation order.
const SYMBOLS: &str = r#"_-,;:!?.'"()[]{}@*/\&#%`^+<=>|~$"#;

fn primary(c: char) -> u32 {
    if c.is_whitespace() {
        return 1;
    }
    if let Some(index) = SYMBOLS.find(c) {
        return 10 + u32::try_from(index).unwrap_or(0);
    }
    if let Some(digit) = c.to_digit(10) {
        return 100 + digit;
    }
    if c.is_alphabetic() {
        return 200 + c.to_lowercase().next().map_or(c as u32, |lower| lower as u32);
    }
    1_000_000 + c as u32
}

/// A sort key for `name`, ties broken by `id` so the order is stable.
pub fn key(name: &str, id: &str) -> (Vec<u32>, Vec<bool>, String) {
    (name.chars().map(primary).collect(), name.chars().map(char::is_uppercase).collect(), id.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sorted(names: &[&str]) -> Vec<String> {
        let mut names: Vec<&str> = names.to_vec();
        names.sort_by_cached_key(|name| key(name, ""));
        names.into_iter().map(str::to_owned).collect()
    }

    #[test]
    fn follows_the_clients_order() {
        assert_eq!(
            sorted(&[
                "Google (b)",
                "Google - a",
                "fliks.gg",
                "Email",
                "GitHub",
                "aws",
                "AWS - x",
                "Apple",
                "10 things",
                "_x"
            ]),
            ["_x", "10 things", "Apple", "aws", "AWS - x", "Email", "fliks.gg", "GitHub", "Google - a", "Google (b)"]
        );
    }

    #[test]
    fn a_prefix_comes_first_and_ties_are_stable() {
        assert_eq!(sorted(&["Bank of America", "Bank"]), ["Bank", "Bank of America"]);
        assert!(key("a", "1") < key("a", "2"));
    }
}
