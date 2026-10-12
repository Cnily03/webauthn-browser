//! Persistent software-key configuration. Legacy CDP credentials remain readable;
//! browser interception now uses the native WebAuthenticationProxy API instead.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DEFAULT_PRESENCE_TIMEOUT_SECONDS: u16 = 120;
// Preserve the historical label when loading backups without a provider field.
// New authenticators use the current project name or a user-supplied label.
pub const DEFAULT_PROVIDER_LABEL: &str = "Auth Browser";
pub const DEFAULT_MODEL_AAGUID: &str = "00000000-0000-0000-0000-000000000000";
/// WebAuthn Browser's own software model identifier, shared by every installation.
/// This is not a vendor-certified identity or proof of hardware protection.
#[cfg(test)]
pub const OWN_MODEL_AAGUID: &str = "c73ce10f-e70d-4119-9f29-b382587508d1";

fn yes() -> bool {
    true
}
fn presence_timeout() -> u16 {
    DEFAULT_PRESENCE_TIMEOUT_SECONDS
}
fn provider_label() -> String {
    DEFAULT_PROVIDER_LABEL.to_owned()
}
fn model_aaguid() -> String {
    DEFAULT_MODEL_AAGUID.to_owned()
}

/// Accept exactly 16 hexadecimal bytes, either compact or 8-4-4-4-12.
/// Surrounding whitespace is trimmed; interior whitespace, braces, URNs and
/// non-ASCII characters are not accepted. UUID version/variant bits are not
/// restricted because an AAGUID is an opaque 128-bit model identifier.
pub fn parse_aaguid(value: &str) -> Result<uuid::Uuid> {
    let value = value.trim();
    let bytes = value.as_bytes();
    let valid = match bytes.len() {
        32 => bytes.iter().all(u8::is_ascii_hexdigit),
        36 => bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        }),
        _ => false,
    };
    ensure!(
        valid,
        "Software model AAGUID must be exactly 32 hexadecimal characters or an 8-4-4-4-12 UUID"
    );
    uuid::Uuid::parse_str(value).context("Invalid software model AAGUID")
}

pub fn canonical_aaguid(value: &str) -> Result<String> {
    Ok(parse_aaguid(value)?.hyphenated().to_string())
}

fn deserialize_aaguid<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    canonical_aaguid(&value).map_err(serde::de::Error::custom)
}

fn serialize_aaguid<S: serde::Serializer>(value: &str, serializer: S) -> Result<S::Ok, S::Error> {
    let canonical = canonical_aaguid(value).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&canonical)
}

/// Self attestation proves possession of the credential key, not manufacturer
/// provenance. Basic attestation uses a separate certificate-backed software key;
/// a configured certificate alone never establishes manufacturer trust.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationMode {
    #[default]
    #[serde(rename = "none")]
    None,
    #[serde(rename = "self")]
    SelfAttestation,
    #[serde(rename = "basic")]
    Basic,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyConfig {
    pub id: String,
    pub name: String,
    pub attachment: String,
    /// Editable local display label. Not a WebAuthn provider or trust claim;
    /// editing it never rewrites certificates or previous registration metadata.
    #[serde(default = "provider_label")]
    pub provider_label: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "presence_timeout")]
    pub presence_timeout_seconds: u16,
    /// Controls new registrations only. Existing discoverable credentials are
    /// preserved and remain usable when this setting is disabled.
    #[serde(default = "yes")]
    pub resident_key_supported: bool,
    #[serde(default)]
    pub attestation_mode: AttestationMode,
    /// Private attestation signing material. Excluded from normal API summaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_identity: Option<crate::authenticator::attestation::AttestationIdentity>,
    /// User-chosen model UUID, fixed at creation and included in registration
    /// authenticatorData even without attestation. All-zero explicitly omits
    /// the model identifier. It provides no vendor certification and a unique
    /// value can link registrations across sites.
    #[serde(
        default = "model_aaguid",
        deserialize_with = "deserialize_aaguid",
        serialize_with = "serialize_aaguid"
    )]
    pub model_aaguid: String,
    // Legacy backup fields retained for migration. Neither can authorize requests.
    #[serde(default)]
    pub automatic_presence: bool,
    #[serde(default)]
    pub simulated_uv: bool,
    #[serde(default)]
    pub pin_hash: Option<String>,
    #[serde(default)]
    pub credentials: Vec<Value>,
}

impl KeyConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.provider_label.trim().is_empty()
                && self.provider_label.chars().count() <= 120
                && !self.provider_label.chars().any(char::is_control),
            "Provider label must be 1 to 120 characters without control characters"
        );
        ensure!(
            (1..=DEFAULT_PRESENCE_TIMEOUT_SECONDS).contains(&self.presence_timeout_seconds),
            "Presence timeout must be between 1 and 120 seconds"
        );
        parse_aaguid(&self.model_aaguid)?;
        ensure!(
            (self.attestation_mode == AttestationMode::Basic)
                == self.attestation_identity.is_some(),
            "Certificate attestation requires a certificate and matching signing key"
        );
        if let Some(identity) = &self.attestation_identity {
            // Expiry blocks new basic registrations, not loading existing credentials.
            identity.validate(&self.model_aaguid)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn legacy_key() -> KeyConfig {
        serde_json::from_value(
            json!({"id":"key-1","name":"Security key","attachment":"cross-platform"}),
        )
        .unwrap()
    }

    #[test]
    fn legacy_configuration_defaults_preserve_behavior() {
        let key = legacy_key();
        assert_eq!(key.provider_label, DEFAULT_PROVIDER_LABEL);
        assert_eq!(key.presence_timeout_seconds, 120);
        assert!(key.resident_key_supported);
        assert_eq!(key.attestation_mode, AttestationMode::None);
        assert_eq!(key.model_aaguid, DEFAULT_MODEL_AAGUID);
        key.validate().unwrap();
    }

    #[test]
    fn aaguid_accepts_only_compact_or_hyphenated_hex_and_serializes_canonically() {
        for (canonical, forms) in [
            (
                "00112233-4455-4677-8899-aabbccddeeff",
                [
                    "00112233-4455-4677-8899-aabbccddeeff",
                    "00112233-4455-4677-8899-AABBCCDDEEFF",
                    "00112233445546778899aabbccddeeff",
                    " \t00112233445546778899AABBCCDDEEFF\r\n",
                ],
            ),
            (
                DEFAULT_MODEL_AAGUID,
                [
                    DEFAULT_MODEL_AAGUID,
                    "00000000000000000000000000000000",
                    " 00000000-0000-0000-0000-000000000000 ",
                    "\u{2003}00000000000000000000000000000000\u{2003}",
                ],
            ),
            (
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                [
                    "ffffffff-ffff-ffff-ffff-ffffffffffff",
                    "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
                    "ffffffffffffffffffffffffffffffff",
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                ],
            ),
        ] {
            for form in forms {
                assert_eq!(canonical_aaguid(form).unwrap(), canonical);
                assert_eq!(parse_aaguid(form).unwrap().as_bytes().len(), 16);
                let mut key = legacy_key();
                key.model_aaguid = form.into();
                key.validate().unwrap();
                let encoded = serde_json::to_value(&key).unwrap();
                assert_eq!(encoded["model_aaguid"], canonical);
                let mut raw = encoded;
                raw["model_aaguid"] = json!(form);
                let decoded: KeyConfig = serde_json::from_value(raw).unwrap();
                assert_eq!(decoded.model_aaguid, canonical);
            }
        }
        for invalid in [
            "",
            " ",
            "00112233445546778899aabbccddeef",
            "00112233445546778899aabbccddeeff0",
            "00112233-4455-4677-8899-aabbccddeef",
            "00112233-4455-4677-8899-aabbccddeeff0",
            "00112233_4455-4677-8899-aabbccddeeff",
            "0011223-34455-4677-8899-aabbccddeeff",
            "{00112233-4455-4677-8899-aabbccddeeff}",
            "urn:uuid:00112233-4455-4677-8899-aabbccddeeff",
            "00112233445546778899aabbccddeefg",
            "0011223344554677 8899aabbccddeeff",
            "00112233-4455-4677-8899-aabbccddee\0f",
            "００１１２２３３４４５５４６７７８８９９ａａｂｂｃｃｄｄｅｅｆｆ",
        ] {
            assert!(parse_aaguid(invalid).is_err(), "{invalid:?}");
            let mut key = legacy_key();
            key.model_aaguid = invalid.into();
            assert!(key.validate().is_err());
            assert!(serde_json::to_value(&key).is_err());
            assert!(serde_json::from_value::<KeyConfig>(json!({
                "id":"invalid", "name":"Invalid", "attachment":"platform",
                "model_aaguid":invalid
            }))
            .is_err());
        }
    }

    #[test]
    fn software_configuration_validates_and_round_trips() {
        let mut key = legacy_key();
        key.presence_timeout_seconds = 15;
        key.resident_key_supported = false;
        key.attestation_mode = AttestationMode::SelfAttestation;
        key.model_aaguid = OWN_MODEL_AAGUID.into();
        key.validate().unwrap();
        let encoded = serde_json::to_value(&key).unwrap();
        assert_eq!(encoded["attestation_mode"], "self");
        let decoded: KeyConfig = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
        for timeout in [0, 121, u16::MAX] {
            key.presence_timeout_seconds = timeout;
            assert!(key.validate().is_err());
        }
        key.presence_timeout_seconds = 1;
        for invalid in [
            "not-a-uuid",
            "c73ce10fe70d41199f29b382587508d",
            "{00112233-4455-4677-8899-aabbccddeeff}",
        ] {
            key.model_aaguid = invalid.into();
            assert!(key.validate().is_err());
        }
        key.model_aaguid = "00112233-4455-4677-8899-AABBCCDDEEFF".into();
        key.provider_label = "我的软件身份".into();
        key.validate().unwrap();
        key.provider_label = "界".repeat(120);
        key.validate().unwrap();
        for invalid in [
            "".to_owned(),
            " ".to_owned(),
            "x\ny".to_owned(),
            "x\0y".to_owned(),
            "界".repeat(121),
        ] {
            key.provider_label = invalid;
            assert!(key.validate().is_err());
        }
        let mut invalid_mode = encoded;
        invalid_mode["attestation_mode"] = json!("hardware");
        assert!(serde_json::from_value::<KeyConfig>(invalid_mode).is_err());
    }
}
