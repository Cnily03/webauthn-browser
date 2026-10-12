//! Bounded, shared wire types and validation. Tokens never enter display state.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use std::time::Duration;
use subtle::ConstantTimeEq;
pub(crate) const MAX_FRAME: usize = 8192;
pub(crate) const MAX_HANDSHAKES: usize = 4;
pub(crate) const LIFETIME: Duration = Duration::from_secs(300);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Approval {
    pub(crate) origin: String,
    pub(crate) token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authentication {
    pub(crate) r#type: String,
    pub(crate) session_id: Option<String>,
    pub(crate) token: String,
}

pub(crate) fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub(crate) fn secret_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
pub(crate) fn valid_token(s: &str) -> bool {
    (32..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
pub(crate) fn valid_origin(s: &str) -> bool {
    url::Url::parse(s).is_ok_and(|u| {
        matches!(u.scheme(), "http" | "https")
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.origin().ascii_serialization() == s
    })
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::pairing::protocol::random_secret;

    #[test]
    fn strict_origins() {
        for s in [
            "https://example.com",
            "http://localhost:3000",
            "https://example.com:8443",
        ] {
            assert!(valid_origin(s));
        }
        for s in [
            "https://example.com/",
            "https://example.com/path",
            "null",
            "file:///tmp",
            "https://user@example.com",
            "https://example.com?x=1",
            "https://EXAMPLE.com",
            "https://example.com\n",
            "https://example.com\r",
            "https://example.com\t",
            "https://example.com\u{1b}[2J",
            "https://example.com\u{7}",
        ] {
            assert!(!valid_origin(s), "{s}");
        }
    }

    #[test]
    fn tokens() {
        assert!(valid_token(&random_secret()));
        assert!(!valid_token("short"));
        assert!(!valid_token(&"!".repeat(43)));
        assert!(secret_eq("abc", "abc"));
        assert!(!secret_eq("abc", "abd"));
    }
}
