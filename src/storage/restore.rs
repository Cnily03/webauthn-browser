//! Keys-only backup import. Preview never returns credential material.
use crate::{
    app::App,
    auth::{authorize, cookie, csrf, token},
    authenticator::cdp::{self, KeyConfig},
    http::error::{fail, ApiResult},
    storage::store::{self},
};
use anyhow::{ensure, Context};
use argon2::PasswordHash;
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
pub const MAX_BYTES: usize = 2 * 1024 * 1024;
#[derive(Default)]
pub struct Pending {
    entry: Option<Preview>,
}
struct Preview {
    token: String,
    file_hash: Vec<u8>,
    revision: Vec<u8>,
    owner: String,
    expires: Instant,
    downloaded: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upload {
    backup: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirm {
    token: String,
    backup: String,
}
fn hash(bytes: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, bytes).as_ref().to_vec()
}
fn revision(data: &store::Data) -> Vec<u8> {
    hash(&serde_json::to_vec(&data.keys).expect("serializable credentials"))
}
fn invalid() -> (StatusCode, String) {
    fail(
        StatusCode::BAD_REQUEST,
        "备份无效：请使用未加密的版本 1 验证器备份，并检查验证器和通行密钥格式。",
    )
}
fn text_ok(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control)
}
fn bytes(c: &Value, field: &str, min: usize, max: usize) -> anyhow::Result<Vec<u8>> {
    let v = STANDARD.decode(c[field].as_str().context("missing binary field")?)?;
    ensure!((min..=max).contains(&v.len()), "binary field bounds");
    Ok(v)
}
fn credential(c: &Value) -> anyhow::Result<Vec<u8>> {
    let obj = c.as_object().context("credential object required")?;
    let allowed = [
        "credentialId",
        "privateKey",
        "rpId",
        "userHandle",
        "signCount",
        "isResidentCredential",
        "registrationAaguid",
        "registrationAttestation",
        "registrationRequestedAttestation",
        "registrationIdentity",
        "userName",
        "userDisplayName",
        "registeredAt",
        "largeBlob",
        "backupEligibility",
        "backupState",
    ];
    ensure!(
        obj.keys().all(|k| allowed.contains(&k.as_str())),
        "unsupported credential field"
    );
    let id = bytes(c, "credentialId", 1, 1023)?;
    let pk = bytes(c, "privateKey", 1, 4096)?;
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pk, &SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("invalid ES256 PKCS8"))?;
    let rp = c["rpId"].as_str().context("missing rp")?;
    ensure!(
        rp.len() <= 253
            && !rp.is_empty()
            && rp.split('.').all(|part| !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "invalid RP"
    );
    let resident = c["isResidentCredential"]
        .as_bool()
        .context("resident flag missing")?;
    if !c["userHandle"].is_null() {
        bytes(c, "userHandle", 1, 64)?;
    } else {
        ensure!(!resident, "resident handle required");
    }
    ensure!(
        c["signCount"]
            .as_u64()
            .is_some_and(|n| n <= u32::MAX as u64),
        "invalid counter"
    );
    for f in ["userName", "userDisplayName"] {
        if !c[f].is_null() {
            ensure!(
                c[f].as_str()
                    .is_some_and(|s| s.len() <= 1024 && !s.chars().any(char::is_control)),
                "invalid user label"
            );
        }
    }
    if !c["registeredAt"].is_null() {
        ensure!(
            c["registeredAt"]
                .as_u64()
                .is_some_and(|timestamp| timestamp <= 253_402_300_799_999),
            "invalid registration time"
        );
    }
    if !c["registrationAaguid"].is_null() {
        cdp::parse_aaguid(c["registrationAaguid"].as_str().context("aaguid type")?)?;
    }
    if !c["registrationAttestation"].is_null() {
        ensure!(
            matches!(
                c["registrationAttestation"].as_str(),
                Some("none" | "packed-self" | "packed-basic")
            ),
            "attestation type"
        );
    }
    if !c["registrationRequestedAttestation"].is_null() {
        ensure!(
            matches!(
                c["registrationRequestedAttestation"].as_str(),
                Some("none" | "direct" | "indirect" | "enterprise")
            ),
            "requested attestation type"
        );
    }
    if !c["registrationIdentity"].is_null() {
        let i = &c["registrationIdentity"];
        ensure!(
            i.as_object().is_some_and(|o| o.len() == 5),
            "identity shape"
        );
        ensure!(
            i["providerLabel"].as_str().is_some_and(|s| text_ok(s, 120)),
            "provider"
        );
        cdp::parse_aaguid(i["modelAaguid"].as_str().context("identity aaguid")?)?;
        ensure!(
            matches!(
                i["attachment"].as_str(),
                Some("platform" | "cross-platform")
            ) && i["residentKeySupported"].is_boolean()
                && matches!(
                    i["attestationMode"].as_str(),
                    Some("none" | "self" | "basic")
                ),
            "identity values"
        );
    }
    for f in ["backupEligibility", "backupState"] {
        if let Some(v) = c.get(f) {
            ensure!(v.is_boolean(), "backup flag");
        }
    }
    if c.get("largeBlob").is_some() {
        bytes(c, "largeBlob", 0, 65536)?;
    }
    Ok(id)
}
fn parse(raw: &str) -> anyhow::Result<Vec<KeyConfig>> {
    ensure!(!raw.is_empty() && raw.len() <= MAX_BYTES, "backup size");
    let value: Value = serde_json::from_str(raw)?;
    let obj = value.as_object().context("backup object")?;
    ensure!(
        obj.len() == 2 && value["version"].as_u64() == Some(1) && obj.contains_key("keys"),
        "unsupported backup version or fields"
    );
    let values = value["keys"].as_array().context("keys array")?;
    ensure!(values.len() <= 256, "too many keys");
    let allowed = [
        "id",
        "name",
        "attachment",
        "provider_label",
        "enabled",
        "presence_timeout_seconds",
        "resident_key_supported",
        "attestation_mode",
        "attestation_identity",
        "model_aaguid",
        "automatic_presence",
        "simulated_uv",
        "pin_hash",
        "credentials",
    ];
    let mut keys = Vec::new();
    let mut ids = HashSet::new();
    let mut credentials = HashSet::new();
    for v in values {
        ensure!(
            v.as_object()
                .is_some_and(|o| o.keys().all(|k| allowed.contains(&k.as_str()))),
            "unsupported key fields"
        );
        let mut k: KeyConfig = serde_json::from_value(v.clone())?;
        k.validate()?;
        ensure!(
            text_ok(&k.id, 128) && k.name.len() <= 512 && ids.insert(k.id.clone()),
            "invalid or duplicate key id/name"
        );
        ensure!(
            matches!(k.attachment.as_str(), "platform" | "cross-platform"),
            "attachment"
        );
        if let Some(pin) = &k.pin_hash {
            let ph = PasswordHash::new(pin).map_err(|_| anyhow::anyhow!("invalid PIN hash"))?;
            ensure!(
                pin.len() <= 512
                    && ph.algorithm.as_str() == "argon2id"
                    && ph.version == Some(19)
                    && ph.salt.is_some()
                    && ph.hash.is_some(),
                "unsupported PIN hash"
            );
            for (p, max) in [("m", 65536), ("t", 10), ("p", 4)] {
                ensure!(
                    ph.params.get_decimal(p).is_some_and(|v| v > 0 && v <= max),
                    "PIN hash cost"
                );
            }
        }
        // Legacy flags never authorize presence or user verification.
        k.automatic_presence = false;
        k.simulated_uv = false;
        for c in &k.credentials {
            ensure!(
                credentials.len() < 4096 && credentials.insert(credential(c)?),
                "duplicate credential or too many credentials"
            );
        }
        keys.push(k);
    }
    Ok(keys)
}
fn reconcile(import: &mut [KeyConfig], current: &[KeyConfig]) -> anyhow::Result<usize> {
    let mut existing = HashMap::new();
    for k in current {
        for c in &k.credentials {
            let id = bytes(c, "credentialId", 1, 1023)?;
            ensure!(
                existing.insert(id, c).is_none(),
                "duplicate current credential"
            );
        }
    }
    let mut preserved = 0;
    for k in import {
        for c in &mut k.credentials {
            if let Some(old) = existing.get(&bytes(c, "credentialId", 1, 1023)?) {
                ensure!(
                    bytes(c, "privateKey", 1, 4096)? == bytes(old, "privateKey", 1, 4096)?
                        && c["rpId"] == old["rpId"]
                        && c["userHandle"] == old["userHandle"]
                        && c["isResidentCredential"] == old["isResidentCredential"],
                    "credential identity conflict"
                );
                for field in [
                    "registrationIdentity",
                    "registrationAaguid",
                    "registrationAttestation",
                    "registrationRequestedAttestation",
                    "registeredAt",
                    "userName",
                    "userDisplayName",
                ] {
                    if let Some(value) = old.get(field) {
                        c[field] = value.clone();
                    } else {
                        c.as_object_mut().unwrap().remove(field);
                    }
                }
                let old_count = old["signCount"]
                    .as_u64()
                    .context("invalid existing counter")?;
                ensure!(old_count <= u32::MAX as u64, "existing counter bounds");
                if old_count > c["signCount"].as_u64().unwrap() {
                    c["signCount"] = json!(old_count);
                    preserved += 1;
                }
            }
        }
    }
    Ok(preserved)
}
fn check<'a>(
    pending: &'a mut Pending,
    token: &str,
    data: &store::Data,
    h: &HeaderMap,
) -> Result<&'a mut Preview, (StatusCode, String)> {
    let p = pending
        .entry
        .as_mut()
        .ok_or_else(|| fail(StatusCode::CONFLICT, "请重新选择备份并预览。"))?;
    if p.token != token
        || p.expires <= Instant::now()
        || p.revision != revision(data)
        || cookie(h, "ab_csrf") != Some(p.owner.as_str())
    {
        return Err(fail(
            StatusCode::CONFLICT,
            "预览已过期或当前验证器及通行密钥已改变，请重新预览。",
        ));
    }
    Ok(p)
}
pub async fn preview(State(app): State<App>, h: HeaderMap, Json(input): Json<Upload>) -> ApiResult {
    let _op = app.operations.lock().await;
    let i = app.inner.lock().await;
    authorize(&i, &h, "settings")?;
    csrf(&i, &h)?;
    let mut imported = parse(&input.backup).map_err(|_| invalid())?;
    let preserved = reconcile(&mut imported, &i.store.data.keys).map_err(|_| {
        fail(
            StatusCode::BAD_REQUEST,
            "备份中的通行密钥与当前身份冲突，无法恢复。",
        )
    })?;
    let token = token();
    app.restore.lock().await.entry = Some(Preview {
        token: token.clone(),
        file_hash: hash(input.backup.as_bytes()),
        revision: revision(&i.store.data),
        owner: cookie(&h, "ab_csrf").unwrap_or_default().into(),
        expires: Instant::now() + Duration::from_secs(600),
        downloaded: false,
    });
    Ok(Json(
        json!({"token":token,"key_count":imported.len(),"credential_count":imported.iter().map(|k|k.credentials.len()).sum::<usize>(),"current_key_count":i.store.data.keys.len(),"current_credential_count":i.store.data.keys.iter().map(|k|k.credentials.len()).sum::<usize>(),"counters_preserved":preserved,"warnings":["恢复将替换全部软件验证器及其通行密钥，不会合并；当前备份中没有的验证器将被移除。","仅恢复软件验证器及其通行密钥，不包含设置访问密码、桌面访问密码或浏览器数据。每个验证器的验证密码会保留。","请先下载并妥善保存恢复前备份。备份包含未加密私钥，不要分享或上传。","较高的现有签名计数器会保留；旧版自动确认和模拟验证设置不会启用。"]}),
    ))
}
pub async fn safety_backup(
    State(app): State<App>,
    h: HeaderMap,
    Json(input): Json<Ticket>,
) -> Result<Response, (StatusCode, String)> {
    let _op = app.operations.lock().await;
    let i = app.inner.lock().await;
    authorize(&i, &h, "settings")?;
    csrf(&i, &h)?;
    let mut pending = app.restore.lock().await;
    let p = check(&mut pending, &input.token, &i.store.data, &h)?;
    let mut r = Json(json!({"version":1,"keys":i.store.data.keys})).into_response();
    r.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=webauthn-browser-before-restore.json"),
    );
    p.downloaded = true;
    Ok(r)
}
pub async fn confirm(
    State(app): State<App>,
    h: HeaderMap,
    Json(input): Json<Confirm>,
) -> ApiResult {
    let _op = app.operations.lock().await;
    let mut broker = app.broker.lock().await;
    let mut i = app.inner.lock().await;
    authorize(&i, &h, "settings")?;
    csrf(&i, &h)?;
    let mut pending = app.restore.lock().await;
    let p = check(&mut pending, &input.token, &i.store.data, &h)?;
    if !p.downloaded || hash(input.backup.as_bytes()) != p.file_hash {
        return Err(fail(
            StatusCode::CONFLICT,
            "请先下载恢复前备份，且不要更换已预览的文件。",
        ));
    }
    let mut imported = parse(&input.backup).map_err(|_| invalid())?;
    reconcile(&mut imported, &i.store.data.keys).map_err(|_| invalid())?;
    broker.cancel_all("Keys restored from backup");
    let old = i.store.data.clone();
    i.store.data.keys = imported;
    if i.store.save().is_err() {
        // A directory fsync can fail after rename committed. Reflect readable disk state,
        // never report success or blindly roll memory back to different disk contents.
        match i.store.read_persisted() {
            Ok(persisted) => i.store.data = persisted,
            Err(_) => {
                i.store.data = old;
                i.store.block_writes();
            }
        }
        pending.entry = None;
        drop(pending);
        drop(i);
        drop(broker);
        app.cancel_brokers("Key restore persistence uncertain")
            .await;
        return Err(fail(StatusCode::INTERNAL_SERVER_ERROR,"保存或持久化确认失败，恢复结果未确认。请保留恢复前备份；如存储无法读取，请修复存储并重启服务，再检查当前验证器和通行密钥。"));
    }
    pending.entry = None;
    drop(pending);
    drop(i);
    drop(broker);
    app.cancel_brokers("Keys restored from backup").await;
    Ok(Json(json!({"ok":true})))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{app::Inner, browser::broker::Broker, http::router};
    use crate::{
        authenticator::{attestation, signer},
        settings::summary,
        storage::store::Store,
    };
    use axum::http::Request;
    use std::sync::Arc;
    use tokio::sync::{mpsc, watch, Mutex, Semaphore};
    fn fixture() -> Value {
        let v: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/legacy-cdp-store.json"))
                .unwrap();
        json!({"version":1,"keys":v["keys"]})
    }
    #[test]
    fn passkey_metadata_roundtrips_through_backup_and_store_without_inventing_history() {
        let mut source = fixture();
        let credential = &mut source["keys"][0]["credentials"][0];
        credential["userName"] = json!("alice@example.test");
        credential["userDisplayName"] = json!("Alice 示例");
        credential["registeredAt"] = json!(1_728_646_800_123u64);
        let keys = parse(&source.to_string()).unwrap();
        assert_eq!(keys[0].credentials[0], source["keys"][0]["credentials"][0]);
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let path = dir.join("store.json");
        let mut store = Store::open(&path).unwrap();
        store.data.keys = keys;
        store.save().unwrap();
        let reopened = Store::open(&path).unwrap();
        let exported = json!({"version":1,"keys":reopened.data.keys});
        let restored = parse(&exported.to_string()).unwrap();
        assert_eq!(
            restored[0].credentials[0],
            source["keys"][0]["credentials"][0]
        );
        assert_eq!(
            summary(&restored[0])["credentials"][0]["registered_at"],
            1_728_646_800_123u64
        );
        let legacy = parse(&fixture().to_string()).unwrap();
        assert!(legacy[0].credentials[0].get("registeredAt").is_none());
        assert!(summary(&legacy[0])["credentials"][0]["registered_at"].is_null());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn restore_validates_optional_registration_time_and_preserves_existing_metadata() {
        let mut source = fixture();
        for invalid in [
            json!(-1),
            json!(1.5),
            json!(true),
            json!("2026-10-11T00:00:00Z"),
            json!({}),
            json!(253_402_300_800_000u64),
        ] {
            source["keys"][0]["credentials"][0]["registeredAt"] = invalid;
            assert!(parse(&source.to_string()).is_err());
        }
        source["keys"][0]["credentials"][0]["registeredAt"] = Value::Null;
        assert!(parse(&source.to_string()).is_ok());
        source["keys"][0]["credentials"][0]["registeredAt"] = json!(1_728_646_800_123u64);
        source["keys"][0]["credentials"][0]["userName"] = json!("original@example.test");
        source["keys"][0]["credentials"][0]["userDisplayName"] = json!("Original user");
        let current = parse(&source.to_string()).unwrap();
        let mut imported = current.clone();
        imported[0].credentials[0]["registeredAt"] = json!(0);
        imported[0].credentials[0]["userName"] = json!("replacement");
        imported[0].credentials[0]
            .as_object_mut()
            .unwrap()
            .remove("userDisplayName");
        reconcile(&mut imported, &current).unwrap();
        assert_eq!(imported[0].credentials, current[0].credentials);
        let legacy = parse(&fixture().to_string()).unwrap();
        reconcile(&mut imported, &legacy).unwrap();
        assert_eq!(imported[0].credentials, legacy[0].credentials);
    }

    #[test]
    fn legacy_roundtrip_and_counter_preservation() {
        let raw = fixture().to_string();
        let mut imported = parse(&raw).unwrap();
        assert!(!imported[0].automatic_presence && !imported[0].simulated_uv);
        let mut current = imported.clone();
        current[0].credentials[0]["signCount"] = json!(100);
        assert_eq!(reconcile(&mut imported, &current).unwrap(), 1);
        assert_eq!(imported[0].credentials[0]["signCount"], 100);
        assert_eq!(
            parse(&json!({"version":1,"keys":imported}).to_string()).unwrap()[0].credentials,
            current[0].credentials
        );
        current[0].credentials[0]["rpId"] = json!("other.test");
        assert!(reconcile(&mut imported, &current).is_err());
    }
    #[test]
    fn restore_canonicalizes_key_aaguid_but_preserves_registration_metadata() {
        let mut source = fixture();
        source["keys"][0]["model_aaguid"] = json!(" 00112233445546778899AABBCCDDEEFF ");
        source["keys"][0]["credentials"][0]["registrationAaguid"] =
            json!("00112233-4455-4677-8899-AABBCCDDEEFF");
        source["keys"][0]["credentials"][0]["registrationIdentity"] = json!({
            "providerLabel":"Historic label", "modelAaguid":"00112233445546778899AABBCCDDEEFF",
            "attachment":"cross-platform", "residentKeySupported":true, "attestationMode":"none"
        });
        let parsed = parse(&source.to_string()).unwrap();
        assert_eq!(
            parsed[0].model_aaguid,
            "00112233-4455-4677-8899-aabbccddeeff"
        );
        assert_eq!(
            serde_json::to_value(&parsed).unwrap()[0]["credentials"],
            source["keys"][0]["credentials"]
        );
        for invalid in [
            "00112233445546778899aabbccddeef",
            "{00112233-4455-4677-8899-aabbccddeeff}",
            "urn:uuid:00112233-4455-4677-8899-aabbccddeeff",
            "00112233_4455-4677-8899-aabbccddeeff",
        ] {
            for path in [
                "/keys/0/model_aaguid",
                "/keys/0/credentials/0/registrationAaguid",
                "/keys/0/credentials/0/registrationIdentity/modelAaguid",
            ] {
                let mut bad = source.clone();
                *bad.pointer_mut(path).unwrap() = json!(invalid);
                assert!(parse(&bad.to_string()).is_err(), "{path}: {invalid}");
            }
        }
        source["keys"][0]["model_aaguid"] = json!("00000000000000000000000000000000");
        assert_eq!(
            parse(&source.to_string()).unwrap()[0].model_aaguid,
            cdp::DEFAULT_MODEL_AAGUID
        );
    }
    #[test]
    fn invalid_files_rejected_entirely() {
        for raw in [
            "",
            "{",
            "[]",
            "null",
            "{\"version\":1,\"keys\":[",
            "{\"version\":2,\"keys\":[]}",
            "{\"version\":1,\"keys\":[],\"encrypted\":true}",
        ] {
            assert!(parse(raw).is_err());
        }
        assert!(parse(&" ".repeat(MAX_BYTES + 1)).is_err());
        let source = fixture();
        for (field, value) in [
            ("credentialId", json!("bad")),
            ("privateKey", json!("AQID")),
            ("rpId", json!("https://example.test")),
            ("userHandle", json!("")),
            ("signCount", json!(-1)),
            ("signCount", json!(4294967296u64)),
            ("isResidentCredential", json!("true")),
            ("unexpected", json!("secret")),
        ] {
            let mut bad = source.clone();
            bad["keys"][0]["credentials"][0][field] = value;
            assert!(parse(&bad.to_string()).is_err(), "{field}");
        }
        let mut dup = source.clone();
        let key = dup["keys"][0].clone();
        dup["keys"].as_array_mut().unwrap().push(key);
        assert!(parse(&dup.to_string()).is_err());
        let mut dup = source.clone();
        let cred = dup["keys"][0]["credentials"][0].clone();
        dup["keys"][0]["credentials"]
            .as_array_mut()
            .unwrap()
            .push(cred);
        assert!(parse(&dup.to_string()).is_err());
        let mut bad = source;
        bad["keys"][0]["pin_hash"] =
            json!("$argon2id$v=19$m=999999999,t=2,p=1$c2FsdHNhbHQ$YWJjZGVmZ2hpamtsbW5vcA");
        assert!(parse(&bad.to_string()).is_err());
    }
    #[test]
    fn same_id_different_private_key_rejected() {
        let mut imported = parse(&fixture().to_string()).unwrap();
        let mut current = imported.clone();
        let pk =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        current[0].credentials[0]["privateKey"] = json!(STANDARD.encode(pk.as_ref()));
        assert!(reconcile(&mut imported, &current).is_err());
    }
    fn app() -> (App, std::path::PathBuf, HeaderMap) {
        let dir = std::env::temp_dir().join(format!("restore-test-{}", uuid::Uuid::new_v4()));
        let mut store = Store::open(dir.join("store.json")).unwrap();
        store.data.keys = parse(&fixture().to_string()).unwrap();
        store.save().unwrap();
        let mut csrf_tokens = HashMap::new();
        csrf_tokens.insert("test".into(), Instant::now() + Duration::from_secs(600));
        let (revoked, _) = watch::channel(0);
        let app = App {
            profile_scope: false,
            profile_name: None,
            profile_id: std::sync::Arc::from("default"),
            endpoints: std::sync::Arc::new(crate::profiles::runtime::Endpoints::legacy()),
            profiles: None,
            inner: Arc::new(Mutex::new(Inner {
                profile_viewers: std::collections::HashMap::new(),
                viewer_tickets: std::collections::HashMap::new(),
                store,
                sessions: HashMap::new(),
                csrf: csrf_tokens,
                vnc_epoch: 0,
                settings_epoch: 0,
                engine_connected: false,
                engine_message: String::new(),
                attempts: HashMap::new(),
            })),
            broker: Arc::new(Mutex::new(Broker::default())),
            revoked,
            operations: Arc::new(Mutex::new(())),
            stream_slots: Arc::new(Semaphore::new(64)),
            recovery_slots: Arc::new(Semaphore::new(1)),
            window_control: Arc::new(crate::browser::window_control::Controller::default()),
            fido_launcher: crate::relay::fido_launcher::Launcher::disabled(),
            restore: Arc::new(Mutex::new(Pending::default())),
        };
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("ab_csrf=test"));
        h.insert("x-csrf-token", HeaderValue::from_static("test"));
        (app, dir, h)
    }
    async fn ticket(app: &App, h: &HeaderMap, raw: &str) -> String {
        preview(
            State(app.clone()),
            h.clone(),
            Json(Upload { backup: raw.into() }),
        )
        .await
        .unwrap()
        .0["token"]
            .as_str()
            .unwrap()
            .into()
    }
    #[tokio::test]
    async fn confirm_requires_backup_exact_file_revision_and_is_one_shot() {
        let (app, dir, h) = app();
        let raw = fixture().to_string();
        let t = ticket(&app, &h, &raw).await;
        let attempt = || Confirm {
            token: t.clone(),
            backup: raw.clone(),
        };
        assert_eq!(
            confirm(State(app.clone()), h.clone(), Json(attempt()))
                .await
                .unwrap_err()
                .0,
            StatusCode::CONFLICT
        );
        safety_backup(
            State(app.clone()),
            h.clone(),
            Json(Ticket { token: t.clone() }),
        )
        .await
        .unwrap();
        assert_eq!(
            confirm(
                State(app.clone()),
                h.clone(),
                Json(Confirm {
                    token: t.clone(),
                    backup: format!("{raw} ")
                })
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::CONFLICT
        );
        app.inner.lock().await.store.data.keys[0].credentials[0]["signCount"] = json!(50);
        assert_eq!(
            confirm(State(app.clone()), h.clone(), Json(attempt()))
                .await
                .unwrap_err()
                .0,
            StatusCode::CONFLICT
        );
        let t = ticket(&app, &h, &raw).await;
        safety_backup(
            State(app.clone()),
            h.clone(),
            Json(Ticket { token: t.clone() }),
        )
        .await
        .unwrap();
        let _ = confirm(
            State(app.clone()),
            h.clone(),
            Json(Confirm {
                token: t.clone(),
                backup: raw.clone(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            app.inner.lock().await.store.data.keys[0].credentials[0]["signCount"],
            50
        );
        assert_eq!(
            Store::open(dir.join("store.json")).unwrap().data.keys[0].credentials[0]["signCount"],
            50
        );
        assert_eq!(
            confirm(
                State(app.clone()),
                h.clone(),
                Json(Confirm {
                    token: t,
                    backup: raw
                })
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::CONFLICT
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn save_failure_restores_memory_and_preserves_disk() {
        let (app, dir, h) = app();
        let original = std::fs::read(dir.join("store.json")).unwrap();
        let raw = json!({"version":1,"keys":[]}).to_string();
        let t = ticket(&app, &h, &raw).await;
        safety_backup(
            State(app.clone()),
            h.clone(),
            Json(Ticket { token: t.clone() }),
        )
        .await
        .unwrap();
        std::fs::rename(&dir, dir.with_extension("saved")).unwrap();
        std::fs::write(&dir, b"block parent directory").unwrap();
        assert_eq!(
            confirm(
                State(app.clone()),
                h,
                Json(Confirm {
                    token: t,
                    backup: raw
                })
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(app.inner.lock().await.store.data.keys.len(), 1);
        assert_eq!(
            std::fs::read(dir.with_extension("saved").join("store.json")).unwrap(),
            original
        );
        std::fs::remove_file(&dir).unwrap();
        std::fs::rename(dir.with_extension("saved"), &dir).unwrap();
        // Unreadable post-failure state freezes future saves until a clean reopen.
        assert!(app.inner.lock().await.store.save().is_err());
        assert!(Store::open(dir.join("store.json")).unwrap().save().is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn expiry_owner_auth_and_empty_restore() {
        let (app, dir, h) = app();
        let raw = json!({"version":1,"keys":[]}).to_string();
        let t = ticket(&app, &h, &raw).await;
        app.restore.lock().await.entry.as_mut().unwrap().expires = Instant::now();
        assert_eq!(
            safety_backup(State(app.clone()), h.clone(), Json(Ticket { token: t }))
                .await
                .unwrap_err()
                .0,
            StatusCode::CONFLICT
        );
        let t = ticket(&app, &h, &raw).await;
        app.inner
            .lock()
            .await
            .csrf
            .insert("other".into(), Instant::now() + Duration::from_secs(600));
        let mut other = h.clone();
        other.insert(header::COOKIE, HeaderValue::from_static("ab_csrf=other"));
        other.insert("x-csrf-token", HeaderValue::from_static("other"));
        assert_eq!(
            safety_backup(State(app.clone()), other, Json(Ticket { token: t }))
                .await
                .unwrap_err()
                .0,
            StatusCode::CONFLICT
        );
        let no_csrf = HeaderMap::new();
        assert_eq!(
            preview(
                State(app.clone()),
                no_csrf,
                Json(Upload {
                    backup: raw.clone()
                })
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::FORBIDDEN
        );
        app.inner.lock().await.store.data.settings_password_hash = Some("protected".into());
        assert_eq!(
            preview(
                State(app.clone()),
                h.clone(),
                Json(Upload {
                    backup: raw.clone()
                })
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::UNAUTHORIZED
        );
        {
            let mut i = app.inner.lock().await;
            i.store.data.settings_password_hash = None;
            i.store.data.vnc_password_hash = Some("unchanged".into());
        }
        let t = ticket(&app, &h, &raw).await;
        safety_backup(
            State(app.clone()),
            h.clone(),
            Json(Ticket { token: t.clone() }),
        )
        .await
        .unwrap();
        let _ = confirm(
            State(app.clone()),
            h,
            Json(Confirm {
                token: t,
                backup: raw,
            }),
        )
        .await
        .unwrap();
        let i = app.inner.lock().await;
        assert!(i.store.data.keys.is_empty());
        assert_eq!(i.store.data.vnc_password_hash.as_deref(), Some("unchanged"));
        drop(i);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn http_invalid_upload_does_not_expose_secrets_or_mutate() {
        use tower::ServiceExt;
        let (app, dir, _) = app();
        let original = std::fs::read(dir.join("store.json")).unwrap();
        let body = json!({"backup":"privateKey secret marker invalid JSON"}).to_string();
        let response = router(app.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/restore/preview")
                    .header("host", "localhost:8080")
                    .header("content-type", "application/json")
                    .header("cookie", "ab_csrf=test")
                    .header("x-csrf-token", "test")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("secret marker"));
        assert_eq!(std::fs::read(dir.join("store.json")).unwrap(), original);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn successful_restore_cancels_pending_approvals() {
        let (app, dir, h) = app();
        let keys = app.inner.lock().await.store.data.keys.clone();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let options = json!({"rp":{"id":"example.test","name":"Test"},"user":{"id":"dXNlcg","name":"test","displayName":"Test"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-7}],"extensions":{"remoteDesktopClientOverride":{"origin":"https://example.test","sameOriginWithAncestors":true}}});
        {
            let mut b = app.broker.lock().await;
            b.connected(tx);
            b.on_message(
                crate::browser::broker::tests::test_ready("proxy", true, 0),
                &[],
            )
            .unwrap();
            b.on_message(
                json!({"type":"create","requestId":42,"requestDetailsJson":options.to_string()}),
                &keys,
            )
            .unwrap();
            assert_eq!(b.public_requests().len(), 1);
        }
        let raw = json!({"version":1,"keys":[]}).to_string();
        let t = ticket(&app, &h, &raw).await;
        safety_backup(
            State(app.clone()),
            h.clone(),
            Json(Ticket { token: t.clone() }),
        )
        .await
        .unwrap();
        let _ = confirm(
            State(app.clone()),
            h,
            Json(Confirm {
                token: t,
                backup: raw,
            }),
        )
        .await
        .unwrap();
        assert!(app.broker.lock().await.public_requests().is_empty());
        assert!(rx.try_recv().unwrap()["error"].is_object());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn certificate_backup_validation_and_immutable_registration_history() {
        let mut keys = parse(&fixture().to_string()).unwrap();
        keys[0].attestation_mode = cdp::AttestationMode::Basic;
        keys[0].attestation_identity = Some(
            attestation::build_identity(
                serde_json::from_value(
                    json!({"kind":"generate","country":"US","organization":"Local Test Lab",
                "common_name":"Synthetic test device","valid_days":30}),
                )
                .unwrap(),
                &keys[0].model_aaguid,
            )
            .unwrap(),
        );
        let backup = json!({"version":1,"keys":keys});
        let parsed = parse(&backup.to_string()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), backup["keys"]);
        let mut compact = backup.clone();
        compact["keys"][0]["model_aaguid"] =
            json!(parsed[0].model_aaguid.replace('-', "").to_uppercase());
        assert_eq!(
            serde_json::to_value(parse(&compact.to_string()).unwrap()).unwrap(),
            backup["keys"]
        );
        compact["keys"][0]["model_aaguid"] = json!("00112233445546778899aabbccddeeff");
        assert!(parse(&compact.to_string()).is_err());
        let mut bad = backup.clone();
        bad["keys"][0]["attestation_identity"] = json!({"unexpected":"secret"});
        assert!(parse(&bad.to_string()).is_err());
        let mut missing = backup.clone();
        missing["keys"][0]
            .as_object_mut()
            .unwrap()
            .remove("attestation_identity");
        assert!(parse(&missing.to_string()).is_err());
        let mut imported = parsed.clone();
        imported[0].credentials[0]["registrationAaguid"] =
            json!("d5f8845e-756d-4f37-b02c-2bfcb446cf62");
        imported[0].credentials[0]["registrationRequestedAttestation"] = json!("direct");
        imported[0].credentials[0]["registrationAttestation"] = json!("packed-basic");
        reconcile(&mut imported, &parsed).unwrap();
        assert_eq!(imported[0].credentials, parsed[0].credentials);
    }

    #[tokio::test]
    async fn legacy_noncanonical_certificate_survives_store_restore_and_existing_assertions() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ring::signature::{KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
        let (app, dir, h) = app();
        {
            let mut i = app.inner.lock().await;
            let key = &mut i.store.data.keys[0];
            key.model_aaguid = "00112233-4455-4677-8899-aabbccddeeff".into();
            key.attestation_mode = cdp::AttestationMode::Basic;
            key.attestation_identity = Some(attestation::legacy_noncanonical_test_identity(
                &key.model_aaguid,
            ));
            // A historical v8 none registration kept the model in the snapshot,
            // but returned a zero AAGUID. Neither record is rewritten now.
            key.credentials[0]["registrationIdentity"] = json!({
                "providerLabel":key.provider_label, "modelAaguid":key.model_aaguid,
                "attachment":key.attachment, "residentKeySupported":key.resident_key_supported,
                "attestationMode":"basic"
            });
            key.credentials[0]["registrationAaguid"] = json!(cdp::DEFAULT_MODEL_AAGUID);
            key.credentials[0]["registrationAttestation"] = json!("none");
            key.credentials[0]["registrationRequestedAttestation"] = json!("none");
            i.store.save().unwrap();
        }
        let before = {
            let reopened = Store::open(dir.join("store.json")).unwrap();
            serde_json::to_value(&reopened.data.keys).unwrap()
        };
        let backup = json!({"version":1,"keys":before}).to_string();
        assert_eq!(
            serde_json::to_value(parse(&backup).unwrap()).unwrap(),
            before
        );
        let t = ticket(&app, &h, &backup).await;
        safety_backup(
            State(app.clone()),
            h.clone(),
            Json(Ticket { token: t.clone() }),
        )
        .await
        .unwrap();
        let _ = confirm(State(app.clone()), h, Json(Confirm { token: t, backup }))
            .await
            .unwrap();
        let mut restored = Store::open(dir.join("store.json")).unwrap();
        assert_eq!(serde_json::to_value(&restored.data.keys).unwrap(), before);
        let key = &restored.data.keys[0];
        let old_credential = key.credentials[0].clone();
        let mut options = json!({"rp":{"id":"example.test"},"user":{"id":"dXNlcg"},
            "challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-7}]});
        for requested in ["direct", "indirect"] {
            options["attestation"] = json!(requested);
            let error = signer::create_with_config(&options, "https://example.test", false, key)
                .err()
                .expect("legacy noncanonical certificate must not sign new basic proof")
                .to_string();
            assert!(!error.contains(
                before[0]["attestation_identity"]["private_key_pkcs8"]
                    .as_str()
                    .unwrap()
            ));
            assert!(!error.contains(old_credential["privateKey"].as_str().unwrap()));
        }
        for requested in [None, Some("none"), Some("enterprise")] {
            options.as_object_mut().unwrap().remove("attestation");
            if let Some(requested) = requested {
                options["attestation"] = json!(requested);
            }
            let created =
                signer::create_with_config(&options, "https://example.test", false, key).unwrap();
            assert_eq!(created.credential["registrationAttestation"], "none");
            assert_eq!(created.credential["registrationAaguid"], key.model_aaguid);
        }
        assert_eq!(serde_json::to_value(&restored.data.keys).unwrap(), before);
        let asserted = signer::get(
            &json!({"rpId":"example.test","challenge":"bmV3LWNoYWxsZW5nZQ"}),
            "https://example.test",
            false,
            &old_credential,
        )
        .unwrap();
        let credential_key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &STANDARD
                .decode(old_credential["privateKey"].as_str().unwrap())
                .unwrap(),
            &SystemRandom::new(),
        )
        .unwrap();
        let response = &asserted.response["response"];
        let mut signed = URL_SAFE_NO_PAD
            .decode(response["authenticatorData"].as_str().unwrap())
            .unwrap();
        signed.extend(hash(
            &URL_SAFE_NO_PAD
                .decode(response["clientDataJSON"].as_str().unwrap())
                .unwrap(),
        ));
        let signature = URL_SAFE_NO_PAD
            .decode(response["signature"].as_str().unwrap())
            .unwrap();
        UnparsedPublicKey::new(
            &ECDSA_P256_SHA256_ASN1,
            credential_key.public_key().as_ref(),
        )
        .verify(&signed, &signature)
        .unwrap();
        let mut expected = old_credential;
        expected["signCount"] = json!(42);
        assert_eq!(asserted.credential, expected);
        restored.data.keys[0].credentials[0] = asserted.credential;
        restored.save().unwrap();
        let reopened = Store::open(dir.join("store.json")).unwrap();
        let mut expected_keys = before;
        expected_keys[0]["credentials"][0] = expected;
        // Full equality includes every certificate DER byte, attestation key,
        // credential key and all four immutable registration snapshot fields.
        assert_eq!(
            serde_json::to_value(&reopened.data.keys).unwrap(),
            expected_keys
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
