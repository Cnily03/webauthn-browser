use crate::authenticator::cdp::KeyConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Data {
    #[serde(default)]
    pub multi_profile: bool,
    #[serde(default = "super::profiles::defaults")]
    pub profiles: Vec<super::profiles::Profile>,
    #[serde(default)]
    pub profile_access_tokens: Vec<super::profiles::AccessToken>,
    #[serde(default)]
    pub pending_profile_cleanup: Vec<String>,
    /// Explicit new deletion requests only; legacy cleanup never implies erasure.
    #[serde(default)]
    pub pending_profile_deletion: Vec<String>,
    #[serde(default)]
    pub keys: Vec<KeyConfig>,
    #[serde(default)]
    pub vnc_password_hash: Option<String>,
    #[serde(default)]
    pub settings_password_hash: Option<String>,
}
impl Default for Data {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            vnc_password_hash: None,
            settings_password_hash: None,
            multi_profile: false,
            profiles: super::profiles::defaults(),
            profile_access_tokens: Vec::new(),
            pending_profile_cleanup: Vec::new(),
            pending_profile_deletion: Vec::new(),
        }
    }
}
impl Data {
    pub(crate) fn validate(&self) -> Result<()> {
        super::profiles::validate(&self.profiles, &self.profile_access_tokens)?;
        anyhow::ensure!(
            self.pending_profile_cleanup.len() <= 32
                && self
                    .pending_profile_cleanup
                    .iter()
                    .all(|id| super::profiles::valid_id(id)),
            "invalid pending profile cleanup"
        );
        anyhow::ensure!(
            self.pending_profile_cleanup
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                == self.pending_profile_cleanup.len(),
            "duplicate pending profile cleanup"
        );
        anyhow::ensure!(
            self.pending_profile_deletion.len() <= 32
                && self.pending_profile_deletion.iter().all(|id| {
                    id != "default"
                        && super::profiles::valid_id(id)
                        && self.profile(id).is_none()
                        && self.pending_profile_cleanup.contains(id)
                })
                && self
                    .pending_profile_deletion
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    == self.pending_profile_deletion.len(),
            "invalid pending profile deletion"
        );
        for key in &self.keys {
            key.validate()
                .context("invalid software authenticator configuration")?;
        }
        Ok(())
    }
    pub(crate) fn profile(&self, id: &str) -> Option<&super::profiles::Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }
    pub(crate) fn effective_enabled(&self, profile: &super::profiles::Profile) -> bool {
        if self.multi_profile {
            profile.enabled
        } else {
            profile.id == "default"
        }
    }
    pub(crate) fn profile_password<'a>(
        &'a self,
        profile: &'a super::profiles::Profile,
    ) -> Option<&'a str> {
        if profile.id == "default" {
            self.vnc_password_hash.as_deref()
        } else {
            profile.password_hash.as_deref()
        }
    }
}
pub struct Store {
    pub data: Data,
    path: PathBuf,
    write_blocked: bool,
}
impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_owned();
        let data = if path.exists() {
            let data = serde_json::from_slice(&fs::read(&path)?)
                .context("invalid persistent store; refusing to discard keys")?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            data
        } else {
            Data::default()
        };
        let store = Self {
            data,
            path,
            write_blocked: false,
        };
        store.save()?;
        Ok(store)
    }
    /// Inspect committed state after an ambiguous persistence error, without writing.
    pub fn read_persisted(&self) -> Result<Data> {
        Ok(serde_json::from_slice(&fs::read(&self.path)?)?)
    }
    pub(crate) fn writes_blocked(&self) -> bool {
        self.write_blocked
    }
    pub fn block_writes(&mut self) {
        self.write_blocked = true;
    }
    pub fn save(&self) -> Result<()> {
        anyhow::ensure!(
            !self.write_blocked,
            "Persistence outcome is unknown; repair storage and restart before writing"
        );
        self.data.validate()?;
        let parent = self.path.parent().context("store must have parent")?;
        fs::create_dir_all(parent)?;
        let temp = parent.join(format!(".webauthn-browser-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(&serde_json::to_vec_pretty(&self.data)?)?;
            file.sync_all()?;
            fs::rename(&temp, &self.path)?;
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durable_private_store() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let path = dir.join("keys.json");
        let store = Store::open(&path).unwrap();
        store.save().unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(Store::open(&path).unwrap().data.keys.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn configured_keys_round_trip_without_changing_credentials() {
        use serde_json::json;
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let path = dir.join("keys.json");
        let mut store = Store::open(&path).unwrap();
        let source = json!({"id":"configured","name":"Configured key","attachment":"cross-platform",
            "presence_timeout_seconds":17,"resident_key_supported":false,"attestation_mode":"self",
            "model_aaguid":"00112233-4455-4677-8899-AABBCCDDEEFF", "provider_label":"实验室 Custom provider",
            "credentials":[{"credentialId":"legacy-id","privateKey":"opaque-legacy-pkcs8","signCount":23,"isResidentCredential":true}]});
        store
            .data
            .keys
            .push(serde_json::from_value(source.clone()).unwrap());
        store.save().unwrap();
        let reopened = Store::open(&path).unwrap();
        let key = &reopened.data.keys[0];
        assert_eq!(key.presence_timeout_seconds, 17);
        assert!(!key.resident_key_supported);
        assert_eq!(
            key.attestation_mode,
            crate::authenticator::cdp::AttestationMode::SelfAttestation
        );
        assert_eq!(key.model_aaguid, "00112233-4455-4677-8899-aabbccddeeff");
        assert_eq!(key.provider_label, "实验室 Custom provider");
        assert_eq!(
            key.credentials,
            source["credentials"].as_array().unwrap().clone()
        );
        let original_bytes = fs::read(&path).unwrap();
        store.data.keys[0].presence_timeout_seconds = 0;
        assert!(store.save().is_err());
        assert_eq!(fs::read(&path).unwrap(), original_bytes);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn custom_registration_identity_survives_store_reload_and_label_edits() {
        use serde_json::json;
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let path = dir.join("store.json");
        let mut store = Store::open(&path).unwrap();
        let mut key: crate::authenticator::cdp::KeyConfig = serde_json::from_value(json!({
            "id":"snapshot-key", "name":"Original nickname", "provider_label":"Custom provider",
            "attachment":"platform", "model_aaguid":"01234567-89ab-4cde-8f01-23456789abcd",
            "attestation_mode":"self", "resident_key_supported":true
        }))
        .unwrap();
        let options = json!({"rp":{"id":"example.test"}, "user":{"id":"dXNlcg","name":"user"},
            "challenge":"Y2hhbGxlbmdl", "pubKeyCredParams":[{"type":"public-key","alg":-7}],
            "authenticatorSelection":{"residentKey":"required"}, "attestation":"direct"});
        let created = crate::authenticator::signer::create_with_config(
            &options,
            "https://example.test",
            false,
            &key,
        )
        .unwrap();
        key.credentials.push(created.credential.clone());
        store.data.keys.push(key);
        store.save().unwrap();
        let mut reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.data.keys[0].credentials[0], created.credential);
        reopened.data.keys[0].name = "New nickname".into();
        reopened.data.keys[0].provider_label = "New provider label".into();
        reopened.data.keys[0].presence_timeout_seconds = 30;
        reopened.save().unwrap();
        let reloaded = Store::open(&path).unwrap();
        assert_eq!(reloaded.data.keys[0].provider_label, "New provider label");
        assert_eq!(reloaded.data.keys[0].credentials[0], created.credential);
        let get = json!({"rpId":"example.test","challenge":"bmV3LWNoYWxsZW5nZQ"});
        let asserted = crate::authenticator::signer::get(
            &get,
            "https://example.test",
            false,
            &reloaded.data.keys[0].credentials[0],
        )
        .unwrap();
        assert_eq!(
            asserted.credential["registrationIdentity"],
            created.credential["registrationIdentity"]
        );
        assert_eq!(
            asserted.credential["privateKey"],
            created.credential["privateKey"]
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_aaguid_format_normalizes_without_rewriting_registration_history() {
        use serde_json::json;
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.json");
        let source = json!({"keys":[{
            "id":"existing", "name":"Existing", "attachment":"platform",
            "model_aaguid":" 00112233445546778899AABBCCDDEEFF ",
            "credentials":[{"privateKey":"untouched legacy key", "signCount":19,
                "registrationAaguid":"00112233-4455-4677-8899-AABBCCDDEEFF",
                "registrationIdentity":{"providerLabel":"Historic label",
                    "modelAaguid":"00112233-4455-4677-8899-AABBCCDDEEFF"}}]
        }], "settings_password_hash":"untouched settings hash", "vnc_password_hash":"untouched VNC hash"});
        fs::write(&path, serde_json::to_vec(&source).unwrap()).unwrap();
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.data.keys[0].model_aaguid,
            "00112233-4455-4677-8899-aabbccddeeff"
        );
        let saved: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            saved["keys"][0]["credentials"],
            source["keys"][0]["credentials"]
        );
        assert_eq!(
            saved["settings_password_hash"],
            source["settings_password_hash"]
        );
        assert_eq!(saved["vnc_password_hash"], source["vnc_password_hash"]);
        assert_eq!(
            Store::open(&path).unwrap().data.keys[0].credentials,
            store.data.keys[0].credentials
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn none_aaguid_correction_preserves_old_registration_history() {
        use serde_json::json;
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let path = dir.join("store.json");
        let mut store = Store::open(&path).unwrap();
        let mut key: KeyConfig = serde_json::from_value(json!({
            "id":"existing-model", "name":"Existing model", "attachment":"cross-platform",
            "model_aaguid":"00112233-4455-4677-8899-aabbccddeeff", "attestation_mode":"self"
        }))
        .unwrap();
        let options = json!({"rp":{"id":"example.test"}, "user":{"id":"dXNlcg"},
            "challenge":"Y2hhbGxlbmdl", "pubKeyCredParams":[{"type":"public-key","alg":-7}],
            "authenticatorSelection":{"residentKey":"required"}, "attestation":"none"});
        let mut old = crate::authenticator::signer::create_with_config(
            &options,
            "https://example.test",
            false,
            &key,
        )
        .unwrap()
        .credential;
        // Model the already-stored v8 result. Historical data is not recomputed
        // from today's configuration, during loading, assertions or new registration.
        old["registrationAaguid"] = json!(crate::authenticator::cdp::DEFAULT_MODEL_AAGUID);
        old["signCount"] = json!(7);
        key.credentials.push(old.clone());
        store.data.keys.push(key);
        store.save().unwrap();
        let mut reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.data.keys[0].credentials[0], old);
        let created = crate::authenticator::signer::create_with_config(
            &options,
            "https://example.test",
            false,
            &reopened.data.keys[0],
        )
        .unwrap();
        assert_eq!(
            created.credential["registrationAaguid"],
            reopened.data.keys[0].model_aaguid
        );
        assert_eq!(created.credential["registrationAttestation"], "none");
        let asserted = crate::authenticator::signer::get(
            &json!({"rpId":"example.test","challenge":"bmV3LWNoYWxsZW5nZQ"}),
            "https://example.test",
            false,
            &reopened.data.keys[0].credentials[0],
        )
        .unwrap();
        let mut expected = old;
        expected["signCount"] = json!(8);
        assert_eq!(asserted.credential, expected);
        reopened.data.keys[0].credentials[0] = asserted.credential;
        reopened.data.keys[0]
            .credentials
            .push(created.credential.clone());
        reopened.save().unwrap();
        let reloaded = Store::open(&path).unwrap();
        assert_eq!(
            reloaded.data.keys[0].credentials,
            vec![expected, created.credential]
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_cdp_pkcs8_survives_upgrade_and_continues_counter() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use serde_json::json;
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.json");
        fs::write(
            &path,
            include_bytes!("../../tests/fixtures/legacy-cdp-store.json"),
        )
        .unwrap();
        let before: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut store = Store::open(&path).unwrap();
        let key = &store.data.keys[0];
        assert!(key.pin_hash.is_none());
        assert_eq!(key.presence_timeout_seconds, 120);
        assert!(key.resident_key_supported);
        assert_eq!(
            key.attestation_mode,
            crate::authenticator::cdp::AttestationMode::None
        );
        assert_eq!(
            key.model_aaguid,
            crate::authenticator::cdp::DEFAULT_MODEL_AAGUID
        );
        assert_eq!(
            key.provider_label,
            crate::authenticator::cdp::DEFAULT_PROVIDER_LABEL
        );
        assert_eq!(
            store.data.vnc_password_hash.as_deref(),
            Some("preserved-vnc-hash")
        );
        assert_eq!(
            store.data.settings_password_hash.as_deref(),
            Some("preserved-settings-hash")
        );
        assert_eq!(key.credentials[0], before["keys"][0]["credentials"][0]);
        let options = json!({"rpId":"example.test","challenge":"bGVnYWN5LWNoYWxsZW5nZQ","userVerification":"discouraged","allowCredentials":[{"type":"public-key","id":"AQIDBA"}]});
        let signed = crate::authenticator::signer::get(
            &options,
            "https://example.test",
            false,
            &key.credentials[0],
        )
        .unwrap();
        assert_eq!(signed.credential["signCount"], 42);
        assert_eq!(
            signed.credential["privateKey"],
            before["keys"][0]["credentials"][0]["privateKey"]
        );
        let response = &signed.response["response"];
        let mut bytes = URL_SAFE_NO_PAD
            .decode(response["authenticatorData"].as_str().unwrap())
            .unwrap();
        let client = URL_SAFE_NO_PAD
            .decode(response["clientDataJSON"].as_str().unwrap())
            .unwrap();
        bytes.extend_from_slice(ring::digest::digest(&ring::digest::SHA256, &client).as_ref());
        let public = include_bytes!("../../tests/fixtures/legacy-public-key.der");
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &public[public.len() - 65..],
        )
        .verify(
            &bytes,
            &URL_SAFE_NO_PAD
                .decode(response["signature"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        store.data.keys[0].credentials[0] = signed.credential;
        store.save().unwrap();
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.data.keys[0].credentials[0]["signCount"], 42);
        assert_eq!(
            reopened.data.keys[0].credentials[0]["credentialId"],
            "AQIDBA=="
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
