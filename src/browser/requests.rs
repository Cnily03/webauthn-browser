//! Request presentation, explicit decisions and software-authenticator ceremony transitions.
use crate::{
    app::App,
    auth::{authorize, csrf},
    authenticator::{cdp::KeyConfig, signer},
    browser::broker,
    http::{
        error::{fail, ApiResult},
        IdPath,
    },
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Decision {
    action: String,
    key_id: Option<String>,
    credential_id: Option<String>,
    password: Option<String>,
    password_confirmation: Option<String>,
}

pub(crate) fn decorate_requests(snapshot: &mut Value, keys: &[KeyConfig]) {
    if let Some(requests) = snapshot["requests"].as_array_mut() {
        for request in requests {
            let uv = request["uv"].as_str().unwrap_or("preferred").to_owned();
            let creating = request["kind"] == "create";
            let attestation_requested = request["attestation_requested"]
                .as_str()
                .unwrap_or("none")
                .to_owned();
            if let Some(candidates) = request["candidates"].as_array_mut() {
                for candidate in candidates {
                    if let Some(key) = keys
                        .iter()
                        .find(|key| Some(key.id.as_str()) == candidate["key_id"].as_str())
                    {
                        if creating {
                            if let Ok((effective, aaguid)) =
                                signer::effective_attestation(&attestation_requested, key)
                            {
                                candidate["attestation_effective"] = json!(effective);
                                candidate["attestation_aaguid"] = json!(aaguid);
                            }
                        }
                        candidate["provider_label"] = json!(key.provider_label);
                        candidate["model_aaguid"] = json!(key.model_aaguid);
                        candidate["key_name"] = json!(key.name);
                        candidate["attachment"] = json!(key.attachment);
                        candidate["pin_setup"] =
                            json!(key.pin_hash.is_none() && uv != "discouraged");
                        candidate["pin_required"] = json!(uv != "discouraged");
                    }
                }
            }
        }
    }
}
pub(crate) async fn pending_requests(State(app): State<App>, h: HeaderMap) -> ApiResult {
    let mut broker = app.broker.lock().await;
    let i = app.inner.lock().await;
    authorize(&i, &h, "vnc")?;
    let mut snapshot = broker.stream_snapshot(None);
    decorate_requests(&mut snapshot, &i.store.data.keys);
    Ok(Json(snapshot))
}

pub(crate) async fn decide_request(
    State(app): State<App>,
    h: HeaderMap,
    Path(IdPath { id }): Path<IdPath>,
    Json(input): Json<Decision>,
) -> ApiResult {
    let mut request = {
        let mut broker = app.broker.lock().await;
        let i = app.inner.lock().await;
        authorize(&i, &h, "vnc")?;
        csrf(&i, &h)?;
        if input.action == "deny" {
            return if broker.deny_request(&id) {
                Ok(Json(json!({"ok":true,"stage":"denied"})))
            } else {
                Err(fail(
                    StatusCode::CONFLICT,
                    "Request expired, canceled, or already handled",
                ))
            };
        }
        broker.take_request(&id).ok_or_else(|| {
            fail(
                StatusCode::CONFLICT,
                "Request expired, canceled, or already handled",
            )
        })?
    };
    let result = advance_request(&app, &h, &mut request, input).await;
    if let Err((_, message)) = &result {
        let mut broker = app.broker.lock().await;
        broker.expire();
        broker.finish(&request, Err(message.clone()));
    }
    result
}
async fn advance_request(
    app: &App,
    h: &HeaderMap,
    request: &mut broker::Request,
    input: Decision,
) -> ApiResult {
    let _operation = app.operations.lock().await;
    let expected = match request.stage.as_str() {
        "select_key" => "select",
        "setup_password" => "setup_password",
        "verify_password" => "verify_password",
        "touch" => "touch",
        _ => {
            return Err(fail(
                StatusCode::CONFLICT,
                "Request is already being handled",
            ))
        }
    };
    if input.action != expected {
        return Err(fail(
            StatusCode::CONFLICT,
            "This action is not the current request stage",
        ));
    }
    // An action is exactly one ceremony step. Extra credentials or approval
    // fields cannot smuggle verification or presence into a selection/setup.
    if (input.action != "select" && (input.key_id.is_some() || input.credential_id.is_some()))
        || (!matches!(input.action.as_str(), "setup_password" | "verify_password")
            && (input.password.is_some() || input.password_confirmation.is_some()))
        || (input.action == "verify_password" && input.password_confirmation.is_some())
    {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "Only fields for the current action are allowed",
        ));
    }
    let wants_uv = request.uv != "discouraged";
    let (key, epoch) = {
        let i = app.inner.lock().await;
        authorize(&i, h, "vnc")?;
        let (key_id, credential_id) = if input.action == "select" {
            (
                input
                    .key_id
                    .as_deref()
                    .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "Choose a key"))?,
                input.credential_id.as_deref(),
            )
        } else {
            let selected = request
                .selection
                .as_ref()
                .ok_or_else(|| fail(StatusCode::CONFLICT, "Choose a key first"))?;
            (selected.key_id.as_str(), selected.credential_id.as_deref())
        };
        let candidate = request
            .candidates
            .iter()
            .find(|candidate| {
                candidate.key_id == key_id && candidate.credential_id.as_deref() == credential_id
            })
            .ok_or_else(|| {
                fail(
                    StatusCode::BAD_REQUEST,
                    "Key/account is not eligible for this request",
                )
            })?;
        if !request.selected_match(key_id, credential_id) {
            return Err(fail(StatusCode::CONFLICT, "Request expired"));
        }
        let key = i
            .store
            .data
            .keys
            .iter()
            .find(|key| key.id == key_id && key.enabled)
            .cloned()
            .ok_or_else(|| fail(StatusCode::CONFLICT, "Key unavailable"))?;
        let revision = request
            .selection
            .as_ref()
            .map(|s| &s.key_revision)
            .unwrap_or(&candidate.key_revision);
        if *revision != broker::key_revision(&key) {
            return Err(fail(
                StatusCode::CONFLICT,
                "Key configuration changed; start a new website request",
            ));
        }
        (key, i.vnc_epoch)
    };
    if input.action == "select" {
        let candidate = request
            .candidates
            .iter()
            .find(|c| c.key_id == key.id && c.credential_id == input.credential_id)
            .unwrap();
        // The chosen key's deadline is authoritative, even if another candidate
        // was configured for a longer presence timeout.
        request.deadline = candidate.deadline;
        request.selection = Some(broker::Selection {
            key_id: key.id.clone(),
            credential_id: input.credential_id,
            key_revision: broker::key_revision(&key),
            verified: false,
            presence: false,
        });
        request.stage = if wants_uv {
            if key.pin_hash.is_none() {
                "setup_password"
            } else {
                "verify_password"
            }
        } else {
            "touch"
        }
        .into();
        let stage = request.stage.clone();
        if !app.broker.lock().await.resume(request.clone()) {
            return Err(fail(StatusCode::CONFLICT, "Request canceled or expired"));
        }
        return Ok(Json(json!({"ok":true,"stage":stage})));
    }
    let mut new_hash = None;
    if matches!(input.action.as_str(), "setup_password" | "verify_password") {
        let password = input
            .password
            .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "Key password required"))?;
        if password.len() > 1024 {
            return Err(fail(StatusCode::BAD_REQUEST, "Password too long"));
        }
        {
            let mut i = app.inner.lock().await;
            let now = Instant::now();
            i.attempts
                .retain(|_, (time, _)| now.duration_since(*time) < Duration::from_secs(60));
            let attempt = i
                .attempts
                .entry(format!("key:{}", key.id))
                .or_insert((now, 0));
            if attempt.1 >= 10 {
                return Err(fail(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Key password attempt limit; wait one minute",
                ));
            }
            attempt.1 += 1;
        }
        app.broker.lock().await.set_stage(
            request,
            if input.action == "setup_password" {
                "setting_password"
            } else {
                "verifying_password"
            },
        );
        if input.action == "setup_password" {
            if key.pin_hash.is_some()
                || password.chars().count() < 6
                || input.password_confirmation.as_deref() != Some(password.as_str())
            {
                return Err(fail(
                    StatusCode::BAD_REQUEST,
                    "Set and confirm a key password of at least six characters",
                ));
            }
            new_hash = Some(
                tokio::task::spawn_blocking(move || {
                    Argon2::default()
                        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
                        .map(|hash| hash.to_string())
                        .map_err(|_| "Password setup unavailable")
                })
                .await
                .map_err(|_| {
                    fail(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Password setup unavailable",
                    )
                })?
                .map_err(|error| fail(StatusCode::INTERNAL_SERVER_ERROR, error))?,
            );
        } else {
            let hash = key
                .pin_hash
                .clone()
                .ok_or_else(|| fail(StatusCode::CONFLICT, "Key password unavailable"))?;
            let verified = tokio::task::spawn_blocking(move || {
                PasswordHash::new(&hash)
                    .map(|parsed| {
                        Argon2::default()
                            .verify_password(password.as_bytes(), &parsed)
                            .is_ok()
                    })
                    .unwrap_or(false)
            })
            .await
            .map_err(|_| {
                fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Password verification unavailable",
                )
            })?;
            if !verified {
                return Err(fail(
                    StatusCode::BAD_REQUEST,
                    "Incorrect key password; start a new website request",
                ));
            }
        }
    }
    // Cancellation and session/config changes are checked after expensive work.
    // The lock covers durable commit and completion so cancellation cannot race
    // a signature or a newly saved password into an already canceled ceremony.
    let mut broker = app.broker.lock().await;
    if !broker.is_current(request) {
        return Err(fail(StatusCode::CONFLICT, "Request canceled or expired"));
    }
    let selection = request.selection.as_mut().unwrap();
    let mut i = app.inner.lock().await;
    authorize(&i, h, "vnc")?;
    if epoch != i.vnc_epoch {
        return Err(fail(StatusCode::CONFLICT, "Browser session was revoked"));
    }
    let old = i.store.data.clone();
    let current = i
        .store
        .data
        .keys
        .iter_mut()
        .find(|k| k.id == key.id && k.enabled)
        .ok_or_else(|| fail(StatusCode::CONFLICT, "Key unavailable"))?;
    if broker::key_revision(current) != broker::key_revision(&key) {
        return Err(fail(
            StatusCode::CONFLICT,
            "Key configuration changed; start a new website request",
        ));
    }
    if input.action == "setup_password" {
        current.pin_hash = new_hash;
        selection.key_revision = broker::key_revision(current);
        if let Err(error) = i.store.save() {
            i.store.data = old;
            return Err(fail(StatusCode::INTERNAL_SERVER_ERROR, error));
        }
        request.stage = "verify_password".into();
    } else if input.action == "verify_password" {
        selection.verified = true;
        request.stage = "touch".into();
    } else {
        selection.presence = true;
        if !selection.presence || (wants_uv && !selection.verified) {
            return Err(fail(
                StatusCode::CONFLICT,
                "Required verification or presence missing",
            ));
        }
        let verified = selection.verified;
        let credential_id = selection.credential_id.clone();
        broker.set_stage(request, "signing");
        let mut response = if request.kind == "create" {
            let signed =
                signer::create_with_config(&request.options, &request.origin, verified, current)
                    .map_err(|error| fail(StatusCode::BAD_REQUEST, error))?;
            current.credentials.push(signed.credential);
            signed.response
        } else {
            let credential = current
                .credentials
                .iter_mut()
                .find(|c| c["credentialId"].as_str() == credential_id.as_deref())
                .ok_or_else(|| fail(StatusCode::CONFLICT, "Credential unavailable"))?;
            let signed = signer::get(&request.options, &request.origin, verified, credential)
                .map_err(|error| fail(StatusCode::BAD_REQUEST, error))?;
            *credential = signed.credential;
            signed.response
        };
        response["authenticatorAttachment"] = json!(current.attachment);
        if request.kind == "create" {
            response["response"]["transports"] = json!([if current.attachment == "platform" {
                "internal"
            } else {
                "usb"
            }]);
        }
        if let Err(error) = i.store.save() {
            i.store.data = old;
            return Err(fail(StatusCode::INTERNAL_SERVER_ERROR, error));
        }
        if !broker.finish(request, Ok(response)) {
            return Err(fail(
                StatusCode::CONFLICT,
                "Request ended before delivery; website may need retry",
            ));
        }
        return Ok(Json(json!({"ok":true,"stage":"completed"})));
    }
    let stage = request.stage.clone();
    if !broker.resume(request.clone()) {
        return Err(fail(StatusCode::CONFLICT, "Request canceled or expired"));
    }
    Ok(Json(json!({"ok":true,"stage":stage})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authenticator::{
            cdp::{self, KeyConfig},
            signer,
        },
        storage::store::Store,
        test_support::{
            app, call, create_pending, create_pending_uv, proxy_fixture, select_key, step, value,
        },
    };
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHasher,
    };
    use axum::http::StatusCode;
    use serde_json::{json, Value};
    use std::time::Duration;

    #[tokio::test]
    async fn approval_is_one_use_key_bound_password_checked_and_persisted() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let id = create_pending(&app, 1).await;
        let pending = value(
            call(
                &app,
                "GET",
                "/api/requests",
                Value::Null,
                &cookies,
                "",
                None,
            )
            .await,
        )
        .await;
        assert_eq!(
            pending["requests"][0]["candidates"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(pending["requests"][0]["candidates"][0]["pin_setup"], true);
        select_key(&app, &id, &cookies, &csrf).await;
        assert_eq!(step(&app, &id, json!({"action":"setup_password","password":"test-password","password_confirmation":"test-password"}), &cookies, &csrf).await.status(), StatusCode::OK);
        assert!(output.try_recv().is_err());
        assert!(app.inner.lock().await.store.data.keys[0]
            .credentials
            .is_empty());
        assert_eq!(
            step(
                &app,
                &id,
                json!({"action":"verify_password","password":"test-password"}),
                &cookies,
                &csrf
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert!(output.try_recv().is_err());
        assert!(app.inner.lock().await.store.data.keys[0]
            .credentials
            .is_empty());
        let decision = json!({"action":"touch"});
        let path = format!("/api/requests/{id}/decision");
        assert_eq!(
            call(&app, "POST", &path, decision.clone(), &cookies, &csrf, None)
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            call(&app, "POST", &path, decision, &cookies, &csrf, None)
                .await
                .status(),
            StatusCode::CONFLICT
        );
        let response = output.recv().await.unwrap();
        assert_eq!(response["requestId"], 1);
        let signed: Value =
            serde_json::from_str(response["responseJson"].as_str().unwrap()).unwrap();
        use base64::Engine as _;
        let auth = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signed["response"]["authenticatorData"].as_str().unwrap())
            .unwrap();
        assert_eq!(auth[32] & 0x05, 0x05);
        let i = app.inner.lock().await;
        assert_eq!(i.store.data.keys[0].credentials.len(), 1);
        assert!(i.store.data.keys[0]
            .pin_hash
            .as_deref()
            .unwrap()
            .starts_with("$argon2"));
        assert!(i.store.data.keys[1].credentials.is_empty());
        let saved = Store::open(dir.join("store.json")).unwrap();
        assert_eq!(saved.data.keys[0].credentials.len(), 1);
        drop(i);
        let public =
            value(call(&app, "GET", "/api/keys", Value::Null, &cookies, "", None).await).await;
        assert!(!public.to_string().contains("$argon2"));
        assert!(!public.to_string().contains("privateKey"));
        let stored = &saved.data.keys[0].credentials[0];
        let passkey = &public["keys"][0]["credentials"][0];
        assert_eq!(passkey["user_name"], "test");
        assert_eq!(passkey["user_display_name"], "Test User");
        assert_eq!(passkey["user_handle"], stored["userHandle"]);
        assert_eq!(passkey["credential_id"], stored["credentialId"]);
        assert!(stored["registeredAt"].as_u64().is_some());
        assert_eq!(passkey["registered_at"], stored["registeredAt"]);
        assert_eq!(
            passkey["registration_identity"],
            stored["registrationIdentity"]
        );
        assert!(!public
            .to_string()
            .contains(stored["privateKey"].as_str().unwrap()));
        let id = create_pending(&app, 2).await;
        select_key(&app, &id, &cookies, &csrf).await;
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/api/requests/{id}/decision"),
                json!({"action":"verify_password","password":"wrong-password"}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(output.recv().await.unwrap()["error"].is_object());
        assert_eq!(
            app.inner.lock().await.store.data.keys[0].credentials.len(),
            1
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn request_cancel_denial_csrf_and_invalid_selection_never_sign() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let id = create_pending(&app, 1).await;
        let path = format!("/api/requests/{id}/decision");
        assert_eq!(
            call(
                &app,
                "POST",
                &path,
                json!({"action":"deny"}),
                &cookies,
                "",
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                "POST",
                &path,
                json!({"action":"select","key_id":"not-eligible"}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(output.recv().await.unwrap()["error"].is_object());
        let id = create_pending(&app, 2).await;
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/api/requests/{id}/decision"),
                json!({"action":"deny"}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert!(output.recv().await.unwrap()["error"].is_object());
        let id = create_pending(&app, 3).await;
        app.broker
            .lock()
            .await
            .on_message(json!({"type":"cancel","requestId":3}), &[])
            .unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/api/requests/{id}/decision"),
                json!({"action":"select","key_id":"usb"}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert!(output.try_recv().is_err());
        assert!(app
            .inner
            .lock()
            .await
            .store
            .data
            .keys
            .iter()
            .all(|key| key.credentials.is_empty() && key.pin_hash.is_none()));
        app.inner.lock().await.store.data.vnc_password_hash = Some("enabled".into());
        assert_eq!(
            call(
                &app,
                "GET",
                "/api/requests",
                Value::Null,
                &cookies,
                "",
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn missing_password_never_sets_uv_or_changes_credentials() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        for (request_id, hash) in [(1, None), (2, Some("configured-password-hash".to_owned()))] {
            app.inner.lock().await.store.data.keys[0].pin_hash = hash.clone();
            let id = create_pending(&app, request_id).await;
            select_key(&app, &id, &cookies, &csrf).await;
            let response = call(
                &app,
                "POST",
                &format!("/api/requests/{id}/decision"),
                json!({"action":if hash.is_none() { "setup_password" } else { "verify_password" }}),
                &cookies,
                &csrf,
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let result = output.recv().await.unwrap();
            assert!(result["error"].is_object());
            assert!(result.get("responseJson").is_none());
            let inner = app.inner.lock().await;
            assert!(inner.store.data.keys[0].credentials.is_empty());
            assert_eq!(inner.store.data.keys[0].pin_hash, hash);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    // Occupy the sole blocking worker so cancellation deterministically occurs
    // while password hashing is pending, rather than relying on machine timing.

    #[test]
    fn cancellation_while_password_hash_is_pending_never_signs_or_saves() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (app, dir) = app();
            let (cookies, csrf, mut output) = proxy_fixture(&app).await;
            let id = create_pending(&app, 81).await;
            select_key(&app, &id, &cookies, &csrf).await;
            let (release, blocked) = std::sync::mpsc::channel();
            let (started, ready) = tokio::sync::oneshot::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                blocked.recv_timeout(Duration::from_secs(10)).unwrap();
            });
            ready.await.unwrap();
            let task_app = app.clone();
            let approval = tokio::spawn(async move {
                call(&task_app, "POST", &format!("/api/requests/{id}/decision"),
                    json!({"action":"setup_password","password":"test-password","password_confirmation":"test-password"}),
                    &cookies, &csrf, None).await.status()
            });
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if app.inner.lock().await.attempts.contains_key("key:usb") { break; }
                    tokio::task::yield_now().await;
                }
            }).await.unwrap();
            app.broker.lock().await.on_message(json!({"type":"cancel","requestId":81}), &[]).unwrap();
            release.send(()).unwrap();
            blocker.await.unwrap();
            assert_eq!(approval.await.unwrap(), StatusCode::CONFLICT);
            assert!(output.try_recv().is_err());
            let inner = app.inner.lock().await;
            assert!(inner.store.data.keys[0].credentials.is_empty());
            assert!(inner.store.data.keys[0].pin_hash.is_none());
            assert!(Store::open(dir.join("store.json")).unwrap().data.keys.is_empty());
            drop(inner);
            std::fs::remove_dir_all(dir).unwrap();
        });
    }

    #[test]
    fn candidate_timeout_while_hashing_cannot_borrow_another_keys_longer_deadline() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (app, dir) = app();
            let (cookies, csrf, mut output) = proxy_fixture(&app).await;
            app.inner.lock().await.store.data.keys[0].presence_timeout_seconds = 1;
            let id = create_pending(&app, 81).await;
            select_key(&app, &id, &cookies, &csrf).await;
            let (release, blocked) = std::sync::mpsc::channel();
            let (started, ready) = tokio::sync::oneshot::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                blocked.recv_timeout(Duration::from_secs(10)).unwrap();
            });
            ready.await.unwrap();
            let task_app = app.clone();
            let approval = tokio::spawn(async move {
                call(&task_app, "POST", &format!("/api/requests/{id}/decision"),
                    json!({"action":"setup_password","password":"test-password","password_confirmation":"test-password"}),
                    &cookies, &csrf, None).await.status()
            });
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if app.inner.lock().await.attempts.contains_key("key:usb") { break; }
                    tokio::task::yield_now().await;
                }
            }).await.unwrap();
            tokio::time::sleep(Duration::from_millis(1100)).await;
            release.send(()).unwrap();
            blocker.await.unwrap();
            assert_eq!(approval.await.unwrap(), StatusCode::CONFLICT);
            assert!(output.try_recv().unwrap()["error"].is_object());
            let inner = app.inner.lock().await;
            assert!(inner.store.data.keys[0].credentials.is_empty());
            assert!(inner.store.data.keys[0].pin_hash.is_none());
            assert!(Store::open(dir.join("store.json")).unwrap().data.keys.is_empty());
            drop(inner);
            std::fs::remove_dir_all(dir).unwrap();
        });
    }

    #[tokio::test]
    async fn stale_key_attachment_cannot_authorize_old_candidate() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let id = create_pending(&app, 91).await;
        // Model a stale event snapshot that survived an earlier invalidation.
        app.inner.lock().await.store.data.keys[0].attachment = "platform".to_owned();
        let response = call(
            &app,
            "POST",
            &format!("/api/requests/{id}/decision"),
            json!({"action":"select","key_id":"usb"}),
            &cookies,
            &csrf,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(output.recv().await.unwrap()["error"].is_object());
        let inner = app.inner.lock().await;
        assert!(inner.store.data.keys[0].credentials.is_empty());
        assert!(inner.store.data.keys[0].pin_hash.is_none());
        drop(inner);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn discouraged_uv_never_requests_setup_and_touch_only_sets_up() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let id = create_pending_uv(&app, 100, "discouraged").await;
        let response = value(
            step(
                &app,
                &id,
                json!({"action":"select","key_id":"usb"}),
                &cookies,
                &csrf,
            )
            .await,
        )
        .await;
        assert_eq!(response["stage"], "touch");
        assert!(output.try_recv().is_err());
        let snapshot = value(
            call(
                &app,
                "GET",
                "/api/requests",
                Value::Null,
                &cookies,
                "",
                None,
            )
            .await,
        )
        .await;
        assert_eq!(snapshot["requests"][0]["stage"], "touch");
        assert_eq!(snapshot["requests"][0]["selected_key_id"], "usb");
        assert_eq!(
            snapshot["requests"][0]["candidates"][0]["pin_required"],
            false
        );
        assert_eq!(snapshot["requests"][0]["candidates"][0]["pin_setup"], false);
        assert_eq!(
            step(&app, &id, json!({"action":"touch"}), &cookies, &csrf)
                .await
                .status(),
            StatusCode::OK
        );
        let response = output.try_recv().unwrap();
        let signed: Value =
            serde_json::from_str(response["responseJson"].as_str().unwrap()).unwrap();
        use base64::Engine as _;
        let auth = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signed["response"]["authenticatorData"].as_str().unwrap())
            .unwrap();
        assert_eq!(auth[32] & 0x05, 0x01);
        assert!(app.inner.lock().await.store.data.keys[0].pin_hash.is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn stages_cannot_be_combined_skipped_or_borrowed_from_another_request() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let id = create_pending(&app, 110).await;
        // Old clients cannot turn a single combined approval into password + UP.
        assert_eq!(
            step(
                &app,
                &id,
                json!({"approve":true,"key_id":"usb","password":"test-password"}),
                &cookies,
                &csrf
            )
            .await
            .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert!(output.try_recv().is_err());
        select_key(&app, &id, &cookies, &csrf).await;
        assert_eq!(step(&app, &id, json!({"action":"setup_password","password":"test-password","password_confirmation":"test-password"}), &cookies, &csrf).await.status(), StatusCode::OK);
        assert!(output.try_recv().is_err());
        assert_eq!(
            step(&app, &id, json!({"action":"touch"}), &cookies, &csrf)
                .await
                .status(),
            StatusCode::CONFLICT
        );
        assert!(output.try_recv().unwrap()["error"].is_object());
        assert!(app.inner.lock().await.store.data.keys[0]
            .credentials
            .is_empty());
        let id = create_pending(&app, 111).await;
        select_key(&app, &id, &cookies, &csrf).await;
        assert_eq!(
            step(
                &app,
                &id,
                json!({"action":"verify_password","password":"test-password"}),
                &cookies,
                &csrf
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert!(output.try_recv().is_err());
        let other = create_pending(&app, 112).await;
        select_key(&app, &other, &cookies, &csrf).await;
        assert_eq!(
            step(&app, &other, json!({"action":"touch"}), &cookies, &csrf)
                .await
                .status(),
            StatusCode::CONFLICT
        );
        assert!(output.try_recv().unwrap()["error"].is_object());
        assert_eq!(
            step(&app, &id, json!({"action":"deny"}), &cookies, &csrf)
                .await
                .status(),
            StatusCode::OK
        );
        assert!(output.try_recv().unwrap()["error"].is_object());
        assert_eq!(
            step(&app, &id, json!({"action":"touch"}), &cookies, &csrf)
                .await
                .status(),
            StatusCode::CONFLICT
        );
        assert!(app.inner.lock().await.store.data.keys[0]
            .credentials
            .is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn verified_authorization_is_invalidated_by_config_deletion_and_cancel() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let hash = Argon2::default()
            .hash_password(b"test-password", &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
        app.inner.lock().await.store.data.keys[0].pin_hash = Some(hash);
        for (request_id, change) in [
            (120, "revision"),
            (121, "provider"),
            (122, "cancel"),
            (123, "delete"),
        ] {
            let id = create_pending(&app, request_id).await;
            select_key(&app, &id, &cookies, &csrf).await;
            assert_eq!(
                step(
                    &app,
                    &id,
                    json!({"action":"verify_password","password":"test-password"}),
                    &cookies,
                    &csrf
                )
                .await
                .status(),
                StatusCode::OK
            );
            assert!(output.try_recv().is_err());
            match change {
                "revision" => app.inner.lock().await.store.data.keys[0]
                    .name
                    .push_str(" changed"),
                "provider" => app.inner.lock().await.store.data.keys[0]
                    .provider_label
                    .push_str(" changed"),
                "cancel" => {
                    app.broker
                        .lock()
                        .await
                        .on_message(json!({"type":"cancel","requestId":request_id}), &[])
                        .unwrap();
                }
                _ => {
                    app.inner.lock().await.store.data.keys.remove(0);
                }
            }
            assert_eq!(
                step(&app, &id, json!({"action":"touch"}), &cookies, &csrf)
                    .await
                    .status(),
                StatusCode::CONFLICT
            );
            if change != "cancel" {
                assert!(output.try_recv().unwrap()["error"].is_object());
            }
            assert!(output.try_recv().is_err());
            assert!(app
                .inner
                .lock()
                .await
                .store
                .data
                .keys
                .iter()
                .all(|key| key.credentials.is_empty()));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn password_rate_limit_and_stage_snapshots_remain_request_local() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let hash = Argon2::default()
            .hash_password(b"test-password", &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
        app.inner.lock().await.store.data.keys[0].pin_hash = Some(hash.clone());
        for request_id in 130..140 {
            let id = create_pending(&app, request_id).await;
            select_key(&app, &id, &cookies, &csrf).await;
            assert_eq!(
                step(
                    &app,
                    &id,
                    json!({"action":"verify_password","password":"wrong"}),
                    &cookies,
                    &csrf
                )
                .await
                .status(),
                StatusCode::BAD_REQUEST
            );
            assert!(output.try_recv().unwrap()["error"].is_object());
        }
        let id = create_pending(&app, 140).await;
        select_key(&app, &id, &cookies, &csrf).await;
        let snapshot = app.broker.lock().await.stream_snapshot(None);
        assert_eq!(snapshot["requests"][0]["stage"], "verify_password");
        let text = snapshot.to_string();
        for secret in [
            "test-password",
            "wrong",
            &hash,
            "key_revision",
            "verified",
            "presence",
        ] {
            assert!(!text.contains(secret), "leaked {secret}");
        }
        assert_eq!(
            step(
                &app,
                &id,
                json!({"action":"verify_password","password":"test-password"}),
                &cookies,
                &csrf
            )
            .await
            .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert!(output.try_recv().unwrap()["error"].is_object());
        assert!(app.inner.lock().await.store.data.keys[0]
            .credentials
            .is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn deny_during_password_verification_clears_busy_stage_and_never_signs() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (app, dir) = app();
            let (cookies, csrf, mut output) = proxy_fixture(&app).await;
            let hash = Argon2::default()
                .hash_password(b"test-password", &SaltString::generate(&mut OsRng))
                .unwrap()
                .to_string();
            app.inner.lock().await.store.data.keys[0].pin_hash = Some(hash);
            let id = create_pending(&app, 150).await;
            select_key(&app, &id, &cookies, &csrf).await;
            let (release, blocked) = std::sync::mpsc::channel();
            let (started, ready) = tokio::sync::oneshot::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                blocked.recv_timeout(Duration::from_secs(10)).unwrap();
            });
            ready.await.unwrap();
            let (task_app, task_id, task_cookies, task_csrf) =
                (app.clone(), id.clone(), cookies.clone(), csrf.clone());
            let verification = tokio::spawn(async move {
                step(
                    &task_app,
                    &task_id,
                    json!({"action":"verify_password","password":"test-password"}),
                    &task_cookies,
                    &task_csrf,
                )
                .await
                .status()
            });
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let state = app.broker.lock().await.stream_snapshot(None);
                    if state["requests"][0]["stage"] == "verifying_password" {
                        assert_eq!(state["requests"][0]["busy"], true);
                        assert_eq!(state["requests"][0]["selected_key_id"], "usb");
                        assert!(!state.to_string().contains("test-password"));
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            // Denial remains possible while the expensive task owns the operation lock.
            assert_eq!(
                step(&app, &id, json!({"action":"deny"}), &cookies, &csrf)
                    .await
                    .status(),
                StatusCode::OK
            );
            assert!(output.try_recv().unwrap()["error"].is_object());
            release.send(()).unwrap();
            blocker.await.unwrap();
            assert_eq!(verification.await.unwrap(), StatusCode::CONFLICT);
            assert!(output.try_recv().is_err());
            assert!(app.broker.lock().await.public_requests().is_empty());
            assert!(app.inner.lock().await.store.data.keys[0]
                .credentials
                .is_empty());
            std::fs::remove_dir_all(dir).unwrap();
        });
    }

    #[tokio::test]
    async fn request_preview_reports_rp_preference_and_effective_identity() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let (app, dir) = app();
        let (cookies, csrf, _output) = proxy_fixture(&app).await;
        {
            let mut i = app.inner.lock().await;
            i.store.data.keys[0].attestation_mode = cdp::AttestationMode::SelfAttestation;
            i.store.data.keys[0].model_aaguid = "d5f8845e-756d-4f37-b02c-2bfcb446cf62".into();
        }
        for (index, preference) in [
            None,
            Some("none"),
            Some("direct"),
            Some("indirect"),
            Some("enterprise"),
        ]
        .into_iter()
        .enumerate()
        {
            let keys = app.inner.lock().await.store.data.keys.clone();
            let mut options = json!({"rp":{"id":"example.test"},"user":{"id":"dXNlcg"},
                "challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-7}],
                "extensions":{"remoteDesktopClientOverride":{"origin":"https://example.test","sameOriginWithAncestors":true}}});
            if let Some(preference) = preference {
                options["attestation"] = json!(preference);
            }
            app.broker
                .lock()
                .await
                .on_message(
                    json!({"type":"create","requestId":index as i64,
                "requestDetailsJson":options.to_string()}),
                    &keys,
                )
                .unwrap();
            let snapshot = value(
                call(
                    &app,
                    "GET",
                    "/api/requests",
                    Value::Null,
                    &cookies,
                    &csrf,
                    None,
                )
                .await,
            )
            .await;
            let request = snapshot["requests"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["attestation_requested"] == preference.unwrap_or("none"))
                .unwrap();
            let candidate = request["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["key_id"] == "usb")
                .unwrap();
            let sends_proof = matches!(preference, Some("direct" | "indirect"));
            assert_eq!(
                candidate["attestation_effective"],
                if sends_proof { "packed-self" } else { "none" }
            );
            assert_eq!(
                candidate["attestation_aaguid"],
                "d5f8845e-756d-4f37-b02c-2bfcb446cf62"
            );
            let created =
                signer::create_with_config(&options, "https://example.test", false, &keys[0])
                    .unwrap();
            assert_eq!(
                candidate["attestation_aaguid"],
                created.credential["registrationAaguid"]
            );
            assert_eq!(
                candidate["attestation_effective"],
                created.credential["registrationAttestation"]
            );
            let auth = URL_SAFE_NO_PAD
                .decode(
                    created.response["response"]["authenticatorData"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap();
            assert_eq!(
                &auth[37..53],
                uuid::Uuid::parse_str(candidate["attestation_aaguid"].as_str().unwrap())
                    .unwrap()
                    .as_bytes()
            );
            // Clear this request so omitted and explicit none are both inspected.
            app.broker
                .lock()
                .await
                .deny_request(request["id"].as_str().unwrap());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn request_identity_details_are_explicit_public_fields_for_both_ceremonies() {
        let key: KeyConfig = serde_json::from_value(json!({
            "id":"details-key", "name":"test", "attachment":"platform", "enabled":true,
            "provider_label":"Local label", "model_aaguid":"11111111-2222-3333-4444-555555555555", "credentials":[]
        })).unwrap();
        for kind in ["create", "get"] {
            let mut snapshot = json!({"requests":[{"kind":kind,"candidates":[{"key_id":key.id}]}]});
            decorate_requests(&mut snapshot, std::slice::from_ref(&key));
            let candidate = &snapshot["requests"][0]["candidates"][0];
            assert_eq!(candidate["provider_label"], key.provider_label);
            assert_eq!(candidate["model_aaguid"], key.model_aaguid);
            assert_eq!(candidate["key_name"], key.name);
            assert!(candidate.get("pin_hash").is_none());
            assert!(candidate.get("credentials").is_none());
        }
    }
}
