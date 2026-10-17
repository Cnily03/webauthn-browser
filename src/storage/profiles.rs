//! Persistent profile identities and revocable access records. Live capabilities
//! never enter this model; the legacy default password field stays authoritative.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub(crate) const ACCESS_SECONDS: u64 = 30 * 24 * 60 * 60;
pub(crate) const MAX_PROFILES: usize = 16;
pub(crate) fn idle_default() -> u64 {
    180
}
fn enabled_default() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Profile {
    pub id: String,
    pub name: String,
    #[serde(default = "enabled_default")]
    pub enabled: bool,
    #[serde(default = "idle_default")]
    pub idle_timeout_seconds: u64,
    #[serde(default)]
    pub password_hash: Option<String>,
    #[serde(default)]
    pub auth_revision: u64,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            id: "default".into(),
            name: "default".into(),
            enabled: true,
            idle_timeout_seconds: idle_default(),
            password_hash: None,
            auth_revision: 0,
        }
    }
}
pub(crate) fn defaults() -> Vec<Profile> {
    vec![Profile::default()]
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AccessToken {
    pub token_hash: String,
    pub profile_id: String,
    pub auth_revision: u64,
    pub last_used_at: u64,
}
pub(crate) fn canonical_name(name: &str) -> Option<String> {
    let bytes = name.as_bytes();
    (1..=100).contains(&bytes.len()).then_some(())?;
    (!matches!(name, "." | "..")
        && !name.to_ascii_lowercase().ends_with(".git")
        && !name.to_ascii_lowercase().ends_with(".wiki"))
    .then_some(())?;
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
        .then_some(())?;
    Some(name.to_ascii_lowercase())
}
pub(crate) fn valid_id(id: &str) -> bool {
    id == "default"
        || uuid::Uuid::parse_str(id)
            .ok()
            .is_some_and(|u| u.get_version_num() == 4 && u.to_string() == id)
}
pub(crate) fn validate(profiles: &[Profile], tokens: &[AccessToken]) -> anyhow::Result<()> {
    anyhow::ensure!(
        !profiles.is_empty() && profiles.len() <= MAX_PROFILES,
        "invalid profile count"
    );
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for p in profiles {
        anyhow::ensure!(
            valid_id(&p.id) && canonical_name(&p.name).as_deref() == Some(&p.name),
            "invalid profile identity"
        );
        anyhow::ensure!(
            ids.insert(p.id.as_str()) && names.insert(p.name.as_str()),
            "duplicate profile identity"
        );
        anyhow::ensure!(
            (1..=86400).contains(&p.idle_timeout_seconds),
            "invalid profile idle timeout"
        );
        anyhow::ensure!(
            p.id != "default" || (p.name == "default" && p.password_hash.is_none()),
            "invalid default profile"
        );
        anyhow::ensure!(
            p.name != "default" || p.id == "default",
            "reserved profile name"
        );
        if let Some(hash) = &p.password_hash {
            anyhow::ensure!(
                argon2::PasswordHash::new(hash).is_ok(),
                "invalid profile password hash"
            );
        }
    }
    anyhow::ensure!(ids.contains("default"), "default profile missing");
    anyhow::ensure!(tokens.len() <= 4096, "too many profile access records");
    let mut hashes = HashSet::new();
    for t in tokens {
        anyhow::ensure!(
            t.token_hash.len() == 64
                && t.token_hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && hashes.insert(&t.token_hash),
            "invalid access digest"
        );
        anyhow::ensure!(
            ids.contains(t.profile_id.as_str()),
            "orphan profile access record"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_and_immutable_identifiers_are_separate() {
        assert_eq!(
            canonical_name("Work.Tree_2-Example").as_deref(),
            Some("work.tree_2-example")
        );
        for value in [
            "",
            ".",
            "..",
            "a.GIT",
            "a.WIKI",
            "../escape",
            "a/b",
            "x y",
            "中文",
            "a%2fb",
        ] {
            assert!(canonical_name(value).is_none());
        }
        assert!(valid_id("default"));
        assert!(valid_id(&uuid::Uuid::new_v4().to_string()));
        assert!(!valid_id("WORK"));
    }
    #[test]
    fn default_identity_and_profile_bounds_fail_closed() {
        let mut profiles = defaults();
        assert!(validate(&profiles, &[]).is_ok());
        profiles[0].name = "renamed".into();
        assert!(validate(&profiles, &[]).is_err());
        profiles = defaults();
        profiles[0].idle_timeout_seconds = 0;
        assert!(validate(&profiles, &[]).is_err());
        assert!(validate(&[], &[]).is_err());
    }
}
