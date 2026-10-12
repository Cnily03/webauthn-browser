//! Configured software authenticators, public summaries and explicit backup export.
use crate::{
    app::App,
    auth::{authorize, csrf},
    authenticator::{
        attestation,
        cdp::{self, KeyConfig},
    },
    http::error::{fail, ApiResult},
};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyInput {
    provider_label: Option<String>,
    presence_timeout_seconds: Option<u16>,
    resident_key_supported: Option<bool>,
    attestation_mode: Option<cdp::AttestationMode>,
    attestation: Option<attestation::AttestationInput>,
    model_aaguid: Option<String>,
    name: Option<String>,
    attachment: Option<String>,
    enabled: Option<bool>,
    automatic_presence: Option<bool>,
    simulated_uv: Option<bool>,
}

#[derive(Deserialize)]
pub(crate) struct Credential {
    credential_id: String,
}

fn credential_summary(credential: &Value) -> Value {
    // Stored credentials contain private signing material. Keep this a typed
    // allowlist, including the nested historical identity snapshot.
    let registration_identity = credential
        .get("registrationIdentity")
        .filter(|identity| identity.is_object())
        .map(|identity| {
            json!({
                "providerLabel": identity["providerLabel"].as_str(),
                "modelAaguid": identity["modelAaguid"].as_str(),
                "attachment": identity["attachment"].as_str(),
                "residentKeySupported": identity["residentKeySupported"].as_bool(),
                "attestationMode": identity["attestationMode"].as_str(),
            })
        });
    json!({
        "credential_id": credential["credentialId"].as_str(),
        "rp_id": credential["rpId"].as_str(),
        "user_handle": credential["userHandle"].as_str(),
        "user_name": credential["userName"].as_str(),
        "user_display_name": credential["userDisplayName"].as_str(),
        "registered_at": credential["registeredAt"].as_u64(),
        "sign_count": credential["signCount"].as_u64(),
        "resident": credential["isResidentCredential"].as_bool(),
        "registration_identity": registration_identity,
        "registration_aaguid": credential["registrationAaguid"].as_str(),
        "registration_attestation": credential["registrationAttestation"].as_str(),
        "registration_requested_attestation": credential["registrationRequestedAttestation"].as_str(),
    })
}
pub(crate) fn summary(key: &KeyConfig) -> Value {
    json!({"id":key.id,"name":key.name,"attachment":key.attachment,"enabled":key.enabled,
        "automatic_presence":false,"simulated_uv":false,"pin_configured":key.pin_hash.is_some(),
        "provider":key.provider_label,"provider_label":key.provider_label,"aaguid":key.model_aaguid,"model_aaguid":key.model_aaguid,
        "presence_timeout_seconds":key.presence_timeout_seconds,"resident_key_supported":key.resident_key_supported,
        "attestation_mode":key.attestation_mode,"attestation_certificate":key.attestation_identity.as_ref().and_then(|identity| identity.summary().ok()),"supported_algorithms":["ES256"],
        "protocol":"FIDO2 / WebAuthn (software)","hardware_backed":false,"trusted_attestation":false,
        "credentials":key.credentials.iter().map(credential_summary).collect::<Vec<_>>()})
}
pub(crate) async fn keys(State(app): State<App>, h: HeaderMap) -> ApiResult {
    let i = app.inner.lock().await;
    authorize(&i, &h, "settings")?;
    Ok(Json(
        json!({"keys":i.store.data.keys.iter().map(summary).collect::<Vec<_>>()}),
    ))
}
fn apply(key: &mut KeyConfig, input: KeyInput) -> Result<(), (StatusCode, String)> {
    if let Some(v) = input.provider_label {
        key.provider_label = v;
    }
    if let Some(v) = input.presence_timeout_seconds {
        key.presence_timeout_seconds = v;
    }
    if let Some(v) = input.resident_key_supported {
        key.resident_key_supported = v;
    }
    if let Some(v) = input.attestation_mode {
        key.attestation_mode = v;
    }
    if let Some(v) = input.model_aaguid {
        key.model_aaguid =
            cdp::canonical_aaguid(&v).map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    }
    if let Some(attestation) = input.attestation {
        if key.attestation_mode != cdp::AttestationMode::Basic {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "Certificate details require certificate attestation",
            ));
        }
        key.attestation_identity = Some(
            attestation::build_identity(attestation, &key.model_aaguid)
                .map_err(|e| fail(StatusCode::BAD_REQUEST, e))?,
        );
    }
    key.validate()
        .map_err(|e| fail(StatusCode::BAD_REQUEST, e))?;
    if let Some(v) = input.name {
        if v.len() > 512 {
            return Err(fail(StatusCode::BAD_REQUEST, "Name is too long"));
        }
        key.name = v;
    }
    if let Some(v) = input.attachment {
        if v != "platform" && v != "cross-platform" {
            return Err(fail(StatusCode::BAD_REQUEST, "Invalid attachment"));
        }
        key.attachment = v;
    }
    if let Some(v) = input.enabled {
        key.enabled = v;
    }
    if let Some(v) = input.automatic_presence {
        if v {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "Each request requires approval",
            ));
        }
        key.automatic_presence = false;
    }
    if let Some(v) = input.simulated_uv {
        if v {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "User verification requires a key password",
            ));
        }
        key.simulated_uv = false;
    }
    Ok(())
}
pub(crate) fn validate(_keys: &[KeyConfig]) -> Result<(), (StatusCode, String)> {
    Ok(())
}
pub(crate) async fn update_engine(
    app: &App,
    _keys: Vec<KeyConfig>,
) -> Result<(), (StatusCode, String)> {
    // Changes invalidate pending approvals; each new request gets a fresh key snapshot.
    app.broker
        .lock()
        .await
        .cancel_all("Key configuration changed");
    Ok(())
}
pub(crate) async fn create_key(
    State(app): State<App>,
    h: HeaderMap,
    Json(input): Json<KeyInput>,
) -> ApiResult {
    let _operation = app.operations.lock().await;
    let (key, all) = {
        let mut i = app.inner.lock().await;
        authorize(&i, &h, "settings")?;
        let mut key = KeyConfig {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Security key".into(),
            provider_label: "webauthn-browser".into(),
            attachment: "cross-platform".into(),
            enabled: true,
            automatic_presence: false,
            simulated_uv: false,
            presence_timeout_seconds: 120,
            resident_key_supported: true,
            attestation_mode: cdp::AttestationMode::None,
            attestation_identity: None,
            model_aaguid: cdp::DEFAULT_MODEL_AAGUID.into(),
            pin_hash: None,
            credentials: vec![],
        };
        apply(&mut key, input)?;
        let old = i.store.data.clone();
        i.store.data.keys.push(key.clone());
        if let Err(e) = validate(&i.store.data.keys) {
            i.store.data = old;
            return Err(e);
        }
        if let Err(e) = i.store.save() {
            i.store.data = old;
            return Err(fail(StatusCode::INTERNAL_SERVER_ERROR, e));
        }
        (key, i.store.data.keys.clone())
    };
    update_engine(&app, all).await?;
    Ok(Json(json!({"key":summary(&key)})))
}
pub(crate) async fn edit_key(
    State(app): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<KeyInput>,
) -> ApiResult {
    let _operation = app.operations.lock().await;
    let (key, all) = {
        let mut i = app.inner.lock().await;
        authorize(&i, &h, "settings")?;
        let old = i.store.data.clone();
        let k = i
            .store
            .data
            .keys
            .iter_mut()
            .find(|k| k.id == id)
            .ok_or(fail(StatusCode::NOT_FOUND, "Unknown key"))?;
        if input.model_aaguid.is_some()
            || input.attachment.is_some()
            || input.resident_key_supported.is_some()
            || input.attestation_mode.is_some()
            || input.attestation.is_some()
        {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "Key identity is immutable; create a new key to use another identity",
            ));
        }
        if let Err(e) = apply(k, input) {
            i.store.data = old;
            return Err(e);
        }
        let key = k.clone();
        if let Err(e) = validate(&i.store.data.keys) {
            i.store.data = old;
            return Err(e);
        }
        if let Err(e) = i.store.save() {
            i.store.data = old;
            return Err(fail(StatusCode::INTERNAL_SERVER_ERROR, e));
        }
        (key, i.store.data.keys.clone())
    };
    update_engine(&app, all).await?;
    Ok(Json(json!({"key":summary(&key)})))
}
pub(crate) async fn delete_key(
    State(app): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(_): Json<Value>,
) -> ApiResult {
    let _operation = app.operations.lock().await;
    let all = {
        let mut i = app.inner.lock().await;
        authorize(&i, &h, "settings")?;
        let old = i.store.data.clone();
        i.store.data.keys.retain(|k| k.id != id);
        if old.keys.len() == i.store.data.keys.len() {
            return Err(fail(StatusCode::NOT_FOUND, "Unknown key"));
        }
        if let Err(e) = i.store.save() {
            i.store.data = old;
            return Err(fail(StatusCode::INTERNAL_SERVER_ERROR, e));
        }
        i.store.data.keys.clone()
    };
    update_engine(&app, all).await?;
    Ok(Json(json!({"ok":true})))
}
pub(crate) async fn delete_credential(
    State(app): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Credential>,
) -> ApiResult {
    let _operation = app.operations.lock().await;
    {
        let i = app.inner.lock().await;
        authorize(&i, &h, "settings")?;
        if !i.store.data.keys.iter().any(|k| k.id == id) {
            return Err(fail(StatusCode::NOT_FOUND, "Unknown key"));
        }
    }
    app.broker
        .lock()
        .await
        .cancel_all("Credential configuration changed");
    let mut i = app.inner.lock().await;
    let old = i.store.data.clone();
    if let Some(k) = i.store.data.keys.iter_mut().find(|k| k.id == id) {
        k.credentials.retain(|c| {
            c.get("credentialId").and_then(Value::as_str) != Some(&input.credential_id)
        });
    }
    if let Err(e) = i.store.save() {
        i.store.data = old;
        return Err(fail(StatusCode::INTERNAL_SERVER_ERROR, e));
    }
    Ok(Json(json!({"ok":true})))
}
pub(crate) async fn backup(
    State(app): State<App>,
    h: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let _operation = app.operations.lock().await;
    {
        let i = app.inner.lock().await;
        authorize(&i, &h, "settings")?;
        csrf(&i, &h)?;
    }
    let live = app.inner.lock().await.store.data.keys.clone();
    let mut r = Json(json!({"version":1,"keys":live})).into_response();
    r.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=webauthn-browser-keys-backup.json"),
    );
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authenticator::{
            attestation,
            cdp::{self, KeyConfig},
            signer,
        },
        settings::summary,
        storage::store::Store,
        test_support::{app, call, create_pending_uv, proxy_fixture, select_key, step, value},
    };

    use axum::http::StatusCode;
    use serde_json::{json, Value};

    #[test]
    fn passkey_summary_exposes_only_typed_public_metadata() {
        let credential = json!({
            "credentialId":"+/8=", "rpId":"example.test", "userHandle":"dXNlcg==",
            "userName":"alice@example.test", "userDisplayName":"Alice 示例",
            "registeredAt":1_728_646_800_123u64, "signCount":7, "isResidentCredential":true,
            "privateKey":"credential-secret", "unrecognized":"hidden-secret",
            "registrationAaguid":"00112233-4455-4677-8899-aabbccddeeff",
            "registrationAttestation":"none", "registrationRequestedAttestation":"none",
            "registrationIdentity":{
                "providerLabel":"Historical provider", "modelAaguid":"00112233-4455-4677-8899-aabbccddeeff",
                "attachment":"platform", "residentKeySupported":true, "attestationMode":"none",
                "privateKey":"nested-secret", "private_key_pkcs8":"attestation-secret"
            }
        });
        let key: KeyConfig = serde_json::from_value(json!({
            "id":"public-key", "name":"Current name", "attachment":"platform",
            "provider_label":"Current provider", "pin_hash":"pin-secret",
            "credentials":[credential]
        }))
        .unwrap();
        let before = key.credentials.clone();
        let public = summary(&key);
        assert_eq!(
            public["credentials"][0],
            json!({
                "credential_id":"+/8=", "rp_id":"example.test", "user_handle":"dXNlcg==",
                "user_name":"alice@example.test", "user_display_name":"Alice 示例",
                "registered_at":1_728_646_800_123u64, "sign_count":7, "resident":true,
                "registration_aaguid":"00112233-4455-4677-8899-aabbccddeeff",
                "registration_attestation":"none", "registration_requested_attestation":"none",
                "registration_identity":{
                    "providerLabel":"Historical provider", "modelAaguid":"00112233-4455-4677-8899-aabbccddeeff",
                    "attachment":"platform", "residentKeySupported":true, "attestationMode":"none"
                }
            })
        );
        let serialized = public.to_string();
        for forbidden in ["privateKey", "private_key_pkcs8", "secret", "pin_hash"] {
            assert!(!serialized.contains(forbidden));
        }
        assert_eq!(key.credentials, before);
    }

    #[test]
    fn passkey_summary_does_not_invent_legacy_metadata_or_serialize_nested_values() {
        let legacy = json!({"credentialId":"legacy-id", "rpId":"example.test"});
        let public = credential_summary(&legacy);
        for field in [
            "user_handle",
            "user_name",
            "user_display_name",
            "registered_at",
            "registration_identity",
        ] {
            assert!(public[field].is_null());
        }
        assert!(legacy.get("registeredAt").is_none());
        let mut malformed = json!({});
        for field in [
            "credentialId",
            "rpId",
            "userHandle",
            "userName",
            "userDisplayName",
            "registeredAt",
            "signCount",
            "isResidentCredential",
            "registrationAaguid",
            "registrationAttestation",
            "registrationRequestedAttestation",
        ] {
            malformed[field] = json!({"privateKey":"nested-secret"});
        }
        malformed["registrationIdentity"] = json!({
            "providerLabel":{"privateKey":"nested-secret"},
            "modelAaguid":["nested-secret"], "attachment":false,
            "residentKeySupported":{"privateKey":"nested-secret"},
            "attestationMode":{"privateKey":"nested-secret"},
            "unexpected":"hidden-secret"
        });
        let public = credential_summary(&malformed);
        assert!(public
            .as_object()
            .unwrap()
            .iter()
            .all(|(field, value)| { field == "registration_identity" || value.is_null() }));
        assert!(public["registration_identity"]
            .as_object()
            .unwrap()
            .values()
            .all(Value::is_null));
        assert!(!public.to_string().contains("secret"));
        malformed["registrationIdentity"] = json!("unexpected-secret");
        assert!(credential_summary(&malformed)["registration_identity"].is_null());
    }

    #[tokio::test]
    async fn configuration_http_round_trip_and_invalid_patch_are_atomic() {
        let (app, dir) = app();
        let (cookies, csrf, _output) = proxy_fixture(&app).await;
        let configured = json!({"name":"Software model", "provider_label":"自己的模型", "attachment":"platform", "presence_timeout_seconds":15,
            "resident_key_supported":false,"attestation_mode":"self","model_aaguid":" 00112233445546778899AABBCCDDEEFF "});
        let response = call(&app, "POST", "/api/keys", configured, &cookies, &csrf, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let summary = value(response).await;
        let id = summary["key"]["id"].as_str().unwrap();
        let path = format!("/api/keys/{id}");
        assert_eq!(summary["key"]["provider_label"], "自己的模型");
        assert_eq!(summary["key"]["presence_timeout_seconds"], 15);
        assert_eq!(summary["key"]["resident_key_supported"], false);
        assert_eq!(summary["key"]["attestation_mode"], "self");
        assert_eq!(
            summary["key"]["model_aaguid"],
            "00112233-4455-4677-8899-aabbccddeeff"
        );
        assert_eq!(summary["key"]["trusted_attestation"], false);
        for invalid in [
            json!({"name":"wrong", "presence_timeout_seconds":0}),
            json!({"provider_label":""}),
            json!({"provider_label":"Invalid\nlabel"}),
            json!({"provider_label":"界".repeat(121)}),
            json!({"model_aaguid":"00112233-4455-4677-8899-aabbccddeeff"}),
            json!({"model_aaguid":"00112233445546778899AABBCCDDEEFF"}),
            json!({"model_aaguid":"ffeeddccbbaa99887766554433221100"}),
            json!({"attachment":"cross-platform"}),
            json!({"resident_key_supported":true}),
            json!({"attestation_mode":"none"}),
        ] {
            assert_eq!(
                call(&app, "PATCH", &path, invalid, &cookies, &csrf, None)
                    .await
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            call(
                &app,
                "PATCH",
                &path,
                json!({"name":"New nickname","provider_label":"New local label","presence_timeout_seconds":30,"enabled":false}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        let saved = Store::open(dir.join("store.json")).unwrap();
        let key = saved.data.keys.iter().find(|k| k.id == id).unwrap();
        assert_eq!(key.model_aaguid, "00112233-4455-4677-8899-aabbccddeeff");
        assert_eq!(key.provider_label, "New local label");
        assert_eq!(key.name, "New nickname");
        assert_eq!(key.presence_timeout_seconds, 30);
        assert!(!key.enabled);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn aaguid_http_creation_normalizes_formats_and_rejects_malformed_input_atomically() {
        let (app, dir) = app();
        let (cookies, csrf, _output) = proxy_fixture(&app).await;
        for (input, expected) in [
            (
                "00112233445546778899AABBCCDDEEFF",
                "00112233-4455-4677-8899-aabbccddeeff",
            ),
            (
                "00112233-4455-4677-8899-AABBCCDDEEFF",
                "00112233-4455-4677-8899-aabbccddeeff",
            ),
            (
                " \t00112233445546778899aabbccddeeff\n",
                "00112233-4455-4677-8899-aabbccddeeff",
            ),
            (
                "00000000000000000000000000000000",
                cdp::DEFAULT_MODEL_AAGUID,
            ),
            (cdp::DEFAULT_MODEL_AAGUID, cdp::DEFAULT_MODEL_AAGUID),
        ] {
            let response = call(
                &app,
                "POST",
                "/api/keys",
                json!({"model_aaguid":input}),
                &cookies,
                &csrf,
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let public = value(response).await;
            assert_eq!(public["key"]["model_aaguid"], expected);
            assert_eq!(public["key"]["aaguid"], expected);
            let id = public["key"]["id"].as_str().unwrap();
            let persisted = Store::open(dir.join("store.json")).unwrap();
            assert_eq!(
                persisted
                    .data
                    .keys
                    .iter()
                    .find(|key| key.id == id)
                    .unwrap()
                    .model_aaguid,
                expected
            );
        }
        let before = std::fs::read(dir.join("store.json")).unwrap();
        let count = app.inner.lock().await.store.data.keys.len();
        for invalid in [
            "",
            "00112233445546778899aabbccddeef",
            "00112233445546778899aabbccddeeff0",
            "00112233-4455-4677-8899-aabbccddeefg",
            "0011223344554677 8899aabbccddeeff",
            "0011223-34455-4677-8899-aabbccddeeff",
            "{00112233-4455-4677-8899-aabbccddeeff}",
            "urn:uuid:00112233-4455-4677-8899-aabbccddeeff",
        ] {
            assert_eq!(
                call(
                    &app,
                    "POST",
                    "/api/keys",
                    json!({"model_aaguid":invalid}),
                    &cookies,
                    &csrf,
                    None
                )
                .await
                .status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(std::fs::read(dir.join("store.json")).unwrap(), before);
            assert_eq!(app.inner.lock().await.store.data.keys.len(), count);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn provider_label_edit_preserves_crypto_and_history_and_revokes_pending_touch() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let options = json!({"rp":{"id":"example.test"}, "user":{"id":"dXNlcg"},
            "challenge":"Y2hhbGxlbmdl", "pubKeyCredParams":[{"type":"public-key","alg":-7}],
            "authenticatorSelection":{"residentKey":"required"}, "attestation":"direct"});
        let created;
        let before;
        {
            let mut inner = app.inner.lock().await;
            let key = &mut inner.store.data.keys[0];
            key.provider_label = "Original local provider".into();
            key.model_aaguid = "00112233-4455-4677-8899-aabbccddeeff".into();
            key.attestation_mode = cdp::AttestationMode::Basic;
            key.attestation_identity = Some(attestation::build_identity(
                serde_json::from_value(json!({"kind":"generate", "country":"US", "organization":"Fixed certificate organization", "common_name":"Fixed certificate subject", "valid_days":30})).unwrap(),
                &key.model_aaguid,
            ).unwrap());
            created =
                signer::create_with_config(&options, "https://example.test", false, key).unwrap();
            key.credentials.push(created.credential.clone());
            before = serde_json::to_value(&*key).unwrap();
            inner.store.save().unwrap();
        }
        let request_id = create_pending_uv(&app, 730, "discouraged").await;
        select_key(&app, &request_id, &cookies, &csrf).await;
        let disk_before = std::fs::read(dir.join("store.json")).unwrap();
        for label in [
            "".into(),
            "   ".into(),
            "bad\nlabel".into(),
            "界".repeat(121),
        ] {
            assert_eq!(
                call(
                    &app,
                    "PATCH",
                    "/api/keys/usb",
                    json!({"name":"Do not commit", "provider_label":label}),
                    &cookies,
                    &csrf,
                    None
                )
                .await
                .status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(std::fs::read(dir.join("store.json")).unwrap(), disk_before);
            assert_eq!(app.broker.lock().await.public_requests().len(), 1);
            assert!(output.try_recv().is_err());
        }
        let label = "新的本地 Provider <script>literal</script>";
        let response = call(
            &app,
            "PATCH",
            "/api/keys/usb",
            json!({"provider_label":label}),
            &cookies,
            &csrf,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let public = value(response).await;
        assert_eq!(public["key"]["provider_label"], label);
        assert_eq!(public["key"]["provider"], label);
        assert!(app.broker.lock().await.public_requests().is_empty());
        assert!(output.try_recv().unwrap()["error"].is_object());
        assert_eq!(
            step(
                &app,
                &request_id,
                json!({"action":"touch"}),
                &cookies,
                &csrf
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert!(output.try_recv().is_err());
        let persisted = Store::open(dir.join("store.json")).unwrap();
        let key = &persisted.data.keys[0];
        let mut expected = before;
        expected["provider_label"] = json!(label);
        // Full equality proves certificate DER/subject, attestation private key,
        // credential keys/counters, immutable identity and history were not rewritten.
        assert_eq!(serde_json::to_value(key).unwrap(), expected);
        let asserted = signer::get(
            &json!({"rpId":"example.test", "challenge":"bmV3LWNoYWxsZW5nZQ"}),
            "https://example.test",
            false,
            &key.credentials[0],
        )
        .unwrap();
        let response = &asserted.response["response"];
        let mut signed = URL_SAFE_NO_PAD
            .decode(response["authenticatorData"].as_str().unwrap())
            .unwrap();
        signed.extend_from_slice(
            ring::digest::digest(
                &ring::digest::SHA256,
                &URL_SAFE_NO_PAD
                    .decode(response["clientDataJSON"].as_str().unwrap())
                    .unwrap(),
            )
            .as_ref(),
        );
        let public_key = URL_SAFE_NO_PAD
            .decode(created.response["response"]["publicKey"].as_str().unwrap())
            .unwrap();
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &public_key[public_key.len() - 65..],
        )
        .verify(
            &signed,
            &URL_SAFE_NO_PAD
                .decode(response["signature"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let mut credential = created.credential;
        credential["signCount"] = json!(1);
        assert_eq!(asserted.credential, credential);
        let new_registration =
            signer::create_with_config(&options, "https://example.test", false, key).unwrap();
        assert_eq!(
            new_registration.credential["registrationIdentity"]["providerLabel"],
            label
        );
        assert!(!new_registration.response.to_string().contains(label));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn certificate_identity_is_private_stable_and_immutable() {
        use std::os::unix::fs::PermissionsExt;
        let (app, dir) = app();
        let (cookies, csrf, _output) = proxy_fixture(&app).await;
        let input = json!({"name":"Certificate test", "attestation_mode":"basic",
            "model_aaguid":"D5F8845E756D4F37B02C2BFCB446CF62",
            "attestation":{"kind":"generate","country":"US","organization":"Local Test Lab",
            "common_name":"Synthetic software authenticator","valid_days":30}});
        let response = call(&app, "POST", "/api/keys", input, &cookies, &csrf, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let public = value(response).await;
        let id = public["key"]["id"].as_str().unwrap();
        assert!(public["key"]["attestation_certificate"].is_object());
        assert_eq!(public["key"]["trusted_attestation"], false);
        assert!(!public.to_string().contains("private_key"));
        assert!(!public.to_string().contains("attestation_identity"));
        let before = app
            .inner
            .lock()
            .await
            .store
            .data
            .keys
            .iter()
            .find(|k| k.id == id)
            .map(|k| serde_json::to_value(k).unwrap())
            .unwrap();
        let reopened = Store::open(dir.join("store.json")).unwrap();
        assert_eq!(
            serde_json::to_value(reopened.data.keys.iter().find(|k| k.id == id).unwrap()).unwrap(),
            before
        );
        assert_eq!(
            std::fs::metadata(dir.join("store.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let path = format!("/api/keys/{id}");
        assert_eq!(
            call(
                &app,
                "PATCH",
                &path,
                json!({"attestation":{"kind":"generate","country":"US",
            "organization":"Other","common_name":"Other","valid_days":1}}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &app,
                "PATCH",
                &path,
                json!({"name":"Nickname"}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        let after = app
            .inner
            .lock()
            .await
            .store
            .data
            .keys
            .iter()
            .find(|k| k.id == id)
            .map(|k| serde_json::to_value(k).unwrap())
            .unwrap();
        assert_eq!(
            before["attestation_identity"],
            after["attestation_identity"]
        );
        let invalid = json!({"attestation_mode":"basic","attestation":{"kind":"import",
            "certificate_chain_pem":"INVALID CERTIFICATE","private_key_pem":"PRIVATE SECRET MARKER"}});
        let response = call(&app, "POST", "/api/keys", invalid, &cookies, &csrf, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("PRIVATE SECRET MARKER"));
        assert_eq!(app.inner.lock().await.store.data.keys.len(), 3);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
