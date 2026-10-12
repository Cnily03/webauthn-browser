//! Transient, one-use forwarding to the user's actual browser authenticator.
//! This path never calls the software signer, updates counters, or stores keys.
use crate::{
    app::{App, Inner},
    auth::{authorize, cookie, csrf, token},
    http::error::{fail, ApiResult},
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct Attempt {
    token: String,
    csrf: String,
    session: Option<String>,
    epoch: u64,
}
impl Attempt {
    fn new(inner: &Inner, headers: &HeaderMap) -> Self {
        Self {
            token: token(),
            csrf: cookie(headers, "ab_csrf").unwrap().to_owned(),
            session: cookie(headers, "ab_vnc").map(str::to_owned),
            epoch: inner.vnc_epoch,
        }
    }
    fn matches(&self, inner: &Inner, headers: &HeaderMap, supplied: &str) -> bool {
        self.token == supplied
            && self.epoch == inner.vnc_epoch
            && Some(self.csrf.as_str()) == cookie(headers, "ab_csrf")
            && self.session.as_deref() == cookie(headers, "ab_vnc")
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {}
pub async fn start(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(_input): Json<Start>,
) -> ApiResult {
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    authorize(&inner, &headers, "vnc")?;
    csrf(&inner, &headers)?;
    let attempt = Attempt::new(&inner, &headers);
    let request = broker.start_native(&id, attempt.clone()).ok_or_else(|| {
        fail(
            StatusCode::CONFLICT,
            "Only an unclaimed login request can use this browser",
        )
    })?;
    Ok(Json(
        json!({"attempt_id":attempt.token,"options":request.options,
        "remaining_ms":request.deadline.saturating_duration_since(Instant::now()).as_millis() as u64}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finish {
    attempt_id: String,
    response: Option<Value>,
    error: Option<BrowserError>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserError {
    name: String,
    message: String,
}
pub async fn finish(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Finish>,
) -> ApiResult {
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    authorize(&inner, &headers, "vnc")?;
    csrf(&inner, &headers)?;
    let request = broker
        .native_request(&id)
        .filter(|r| {
            r.native_attempt
                .as_ref()
                .is_some_and(|a| a.matches(&inner, &headers, &input.attempt_id))
        })
        .ok_or_else(|| {
            fail(
                StatusCode::CONFLICT,
                "Native attempt expired, canceled, already handled, or belongs to another session",
            )
        })?;
    // Locks cover validation and consumption, so simultaneous sockets cannot
    // complete twice or race revocation. Invalid owner responses also consume.
    let outcome = match (input.response, input.error) {
        (Some(response), None) => match validate_response(&request, &response) {
            Ok(()) => Ok(broker.finish(&request, Ok(response))),
            Err(message) => Err(message),
        },
        (None, Some(error)) if valid_error(&error) => {
            Ok(broker.finish_native_error(&request, &error.name, &error.message))
        }
        _ => Err("Exactly one valid native response or browser error is required"),
    };
    match outcome {
        Ok(true) => Ok(Json(json!({"ok":true}))),
        Ok(false) => Err(fail(
            StatusCode::CONFLICT,
            "Native request could not be delivered",
        )),
        Err(message) => {
            broker.finish_native_error(&request, "NotAllowedError", message);
            Err(fail(StatusCode::BAD_REQUEST, message))
        }
    }
}
fn valid_error(error: &BrowserError) -> bool {
    matches!(
        error.name.as_str(),
        "NotAllowedError"
            | "NotReadableError"
            | "SecurityError"
            | "NotSupportedError"
            | "AbortError"
            | "InvalidStateError"
            | "ConstraintError"
            | "DataError"
            | "EncodingError"
            | "TypeError"
            | "RangeError"
            | "SyntaxError"
            | "UnknownError"
            | "OperationError"
    ) && error.message.len() <= 2048
}
fn bytes(value: &Value) -> Result<Vec<u8>, &'static str> {
    let s = value.as_str().ok_or("Invalid binary response field")?;
    let decoded = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "Invalid base64url response field")?;
    if URL_SAFE_NO_PAD.encode(&decoded) != s {
        return Err("Noncanonical base64url response field");
    }
    Ok(decoded)
}
fn fields(value: &Value, allowed: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.keys().all(|key| allowed.contains(&key.as_str())))
}
/// Check ceremony binding without ever rewriting signed data. The relying party
/// remains responsible for verifying the real credential's signature/counter.
fn validate_response(
    request: &crate::browser::broker::Request,
    value: &Value,
) -> Result<(), &'static str> {
    if value.to_string().len() > 1024 * 1024
        || !fields(
            value,
            &[
                "id",
                "rawId",
                "type",
                "authenticatorAttachment",
                "response",
                "clientExtensionResults",
            ],
        )
        || value["type"] != "public-key"
    {
        return Err("Invalid native credential response");
    }
    let raw_id = bytes(&value["rawId"])?;
    if raw_id.is_empty() || raw_id.len() > 1023 || value["id"] != value["rawId"] {
        return Err("Invalid native credential ID");
    }
    if value.get("authenticatorAttachment").is_some()
        && !matches!(
            value["authenticatorAttachment"].as_str(),
            Some("platform" | "cross-platform")
        )
    {
        return Err("Invalid authenticator attachment");
    }
    if let Some(allowed) = request.options["allowCredentials"].as_array() {
        if !allowed.is_empty()
            && !allowed.iter().any(|c| {
                c["type"] == "public-key" && bytes(&c["id"]).ok().as_ref() == Some(&raw_id)
            })
        {
            return Err("Native credential was not allowed by this request");
        }
    }
    let response = &value["response"];
    if !fields(
        response,
        &[
            "clientDataJSON",
            "authenticatorData",
            "signature",
            "userHandle",
        ],
    ) {
        return Err("Invalid assertion response fields");
    }
    let client: Value = serde_json::from_slice(&bytes(&response["clientDataJSON"])?)
        .map_err(|_| "Invalid native client data")?;
    if client["type"] != "webauthn.get"
        || client["origin"] != request.origin
        || bytes(&client["challenge"])? != bytes(&request.options["challenge"])?
        || (client.get("crossOrigin").is_some() && client["crossOrigin"] != false)
        || client.get("topOrigin").is_some()
    {
        return Err("Native client data does not match the original browser request");
    }
    let extensions = &value["clientExtensionResults"];
    if !extensions.is_object() {
        return Err("Invalid client extension results");
    }
    let rp = if extensions["appid"] == true {
        let appid = request.options["extensions"]["appid"]
            .as_str()
            .ok_or("Unexpected AppID response")?;
        if appid.is_empty() {
            &request.origin
        } else {
            appid
        }
    } else {
        &request.rp_id
    };
    let auth = bytes(&response["authenticatorData"])?;
    let expected = ring::digest::digest(&ring::digest::SHA256, rp.as_bytes());
    if auth.len() < 37
        || auth[..32] != *expected.as_ref()
        || auth[32] & 1 == 0
        || (request.uv == "required" && auth[32] & 4 == 0)
    {
        return Err("Native authenticator data does not satisfy the original request");
    }
    if bytes(&response["signature"])?.is_empty() {
        return Err("Missing native signature");
    }
    if response.get("userHandle").is_some() && bytes(&response["userHandle"])?.len() > 64 {
        return Err("Invalid native user handle");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::App,
        test_support::{app, call, create_pending, proxy_fixture, select_key, step, value},
    };

    use axum::{http::StatusCode, response::Response};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use serde_json::{json, Value};
    use std::time::Duration;

    async fn native_pending(app: &App, number: i64, extra: Value) -> String {
        let mut options = json!({"rpId":"example.test","challenge":"Y2hhbGxlbmdl","userVerification":"required","extensions":{"remoteDesktopClientOverride":{"origin":"https://example.test","sameOriginWithAncestors":true}}});
        if let Some(object) = extra.as_object() {
            for (k, v) in object {
                options[k] = v.clone();
            }
        }
        let mut broker = app.broker.lock().await;
        broker
            .on_message(
                json!({"type":"get","requestId":number,"requestDetailsJson":options.to_string()}),
                &[],
            )
            .unwrap();
        broker
            .public_requests()
            .into_iter()
            .find(|r| r["stage"] == "select_key")
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    fn assertion() -> Value {
        let mut auth = ring::digest::digest(&ring::digest::SHA256, b"example.test")
            .as_ref()
            .to_vec();
        auth.extend_from_slice(&[5, 0, 0, 0, 1]);
        json!({"id":"AQID","rawId":"AQID","type":"public-key","authenticatorAttachment":"cross-platform",
            "clientExtensionResults":{},"response":{"clientDataJSON":URL_SAFE_NO_PAD.encode(json!({"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.test","crossOrigin":false}).to_string()),
            "authenticatorData":URL_SAFE_NO_PAD.encode(auth),"signature":"BAUG"}})
    }
    async fn native_call(
        app: &App,
        id: &str,
        action: &str,
        input: Value,
        cookies: &str,
        csrf: &str,
    ) -> Response {
        call(
            app,
            "POST",
            &format!("/api/requests/{id}/native/{action}"),
            input,
            cookies,
            csrf,
            None,
        )
        .await
    }
    async fn start_native(app: &App, id: &str, cookies: &str, csrf: &str) -> Value {
        let r = native_call(app, id, "start", json!({}), cookies, csrf).await;
        assert_eq!(r.status(), StatusCode::OK);
        value(r).await
    }
    #[tokio::test]
    async fn native_forward_is_exact_one_use_and_never_writes_credentials() {
        let (app, dir) = app();
        let (cookies, csrf, mut out) = proxy_fixture(&app).await;
        let before = serde_json::to_value(&app.inner.lock().await.store.data.keys).unwrap();
        let id = native_pending(&app, 42, json!({})).await;
        let started = start_native(&app, &id, &cookies, &csrf).await;
        assert_eq!(
            started["options"]["extensions"]["remoteDesktopClientOverride"]["origin"],
            "https://example.test"
        );
        let public = app.broker.lock().await.stream_snapshot(None).to_string();
        assert!(!public.contains(started["attempt_id"].as_str().unwrap()));
        for secret in [
            "Y2hhbGxlbmdl",
            "remoteDesktopClientOverride",
            "AQID",
            "BAUG",
        ] {
            assert!(!public.contains(secret));
        }
        assert_eq!(
            native_call(&app, &id, "start", json!({}), &cookies, &csrf)
                .await
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            step(
                &app,
                &id,
                json!({"action":"select","key_id":"usb"}),
                &cookies,
                &csrf
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let body = json!({"attempt_id":started["attempt_id"],"response":assertion()});
        assert_eq!(
            native_call(&app, &id, "finish", body.clone(), &cookies, &csrf)
                .await
                .status(),
            StatusCode::OK
        );
        let sent = out.recv().await.unwrap();
        assert_eq!(sent["type"], "get");
        assert_eq!(sent["requestId"], 42);
        assert_eq!(
            serde_json::from_str::<Value>(sent["responseJson"].as_str().unwrap()).unwrap(),
            assertion()
        );
        assert_eq!(
            native_call(&app, &id, "finish", body, &cookies, &csrf)
                .await
                .status(),
            StatusCode::CONFLICT
        );
        assert!(out.try_recv().is_err());
        assert_eq!(
            serde_json::to_value(&app.inner.lock().await.store.data.keys).unwrap(),
            before
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn native_session_csrf_token_and_stage_are_bound() {
        let (app, dir) = app();
        let (cookies, csrf, mut out) = proxy_fixture(&app).await;
        let id = native_pending(&app, 43, json!({})).await;
        assert_eq!(
            native_call(&app, &id, "start", json!({}), &cookies, "")
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let started = start_native(&app, &id, &cookies, &csrf).await;
        let body = json!({"attempt_id":started["attempt_id"],"response":assertion()});
        let second = value(call(&app, "GET", "/api/status", Value::Null, "", "", None).await).await;
        let csrf2 = second["csrf_token"].as_str().unwrap();
        assert_eq!(
            native_call(
                &app,
                &id,
                "finish",
                body.clone(),
                &format!("ab_csrf={csrf2}"),
                csrf2
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            native_call(
                &app,
                &id,
                "finish",
                body.clone(),
                &format!("{cookies}; ab_vnc=another-session"),
                &csrf
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            native_call(
                &app,
                &id,
                "finish",
                json!({"attempt_id":"wrong","response":assertion()}),
                &cookies,
                &csrf
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert!(out.try_recv().is_err());
        assert_eq!(
            native_call(&app, &id, "finish", body, &cookies, &csrf)
                .await
                .status(),
            StatusCode::OK
        );
        let registration = create_pending(&app, 44).await;
        assert_eq!(
            native_call(&app, &registration, "start", json!({}), &cookies, &csrf)
                .await
                .status(),
            StatusCode::CONFLICT
        );
        select_key(&app, &registration, &cookies, &csrf).await;
        assert_eq!(
            native_call(&app, &registration, "start", json!({}), &cookies, &csrf)
                .await
                .status(),
            StatusCode::CONFLICT
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn native_invalid_bindings_consume_without_forwarding_assertion() {
        for variant in 0..16 {
            let (app, dir) = app();
            let (cookies, csrf, mut out) = proxy_fixture(&app).await;
            let id = native_pending(&app, 45, json!({})).await;
            let started = start_native(&app, &id, &cookies, &csrf).await;
            let mut a = assertion();
            match variant {
                0 => a["response"]["clientDataJSON"] = json!(URL_SAFE_NO_PAD.encode(json!({"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://attacker.test"}).to_string())),
                1 => a["response"]["clientDataJSON"] = json!(URL_SAFE_NO_PAD.encode(json!({"type":"webauthn.get","challenge":"AQID","origin":"https://example.test"}).to_string())),
                2 => a["response"]["authenticatorData"] = json!(URL_SAFE_NO_PAD.encode([0u8;37])),
                3 | 4 => { let mut auth = URL_SAFE_NO_PAD.decode(a["response"]["authenticatorData"].as_str().unwrap()).unwrap(); auth[32] = if variant == 3 {1} else {4}; a["response"]["authenticatorData"] = json!(URL_SAFE_NO_PAD.encode(auth)); },
                5 => a["id"] = json!("wrong"),
                6 => a["response"]["signature"] = json!(""),
                7 => a["response"]["userHandle"] = json!(URL_SAFE_NO_PAD.encode([0u8;65])),
                8 => a["unexpected"] = json!(true),
                9 => a["clientExtensionResults"]["appid"] = json!(true),
                10 => a["response"]["clientDataJSON"] = json!(URL_SAFE_NO_PAD.encode(json!({"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.test"}).to_string())),
                14 => a["response"]["clientDataJSON"] = json!(URL_SAFE_NO_PAD.encode(json!({"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.test","crossOrigin":null}).to_string())),
                15 => a["response"]["clientDataJSON"] = json!(URL_SAFE_NO_PAD.encode(json!({"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.test","topOrigin":null}).to_string())),
                12 => a["response"]["userHandle"] = Value::Null,
                13 => a["authenticatorAttachment"] = Value::Null,
                _ => a["response"]["clientDataJSON"] = json!(URL_SAFE_NO_PAD.encode(json!({"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.test","crossOrigin":true}).to_string())),
            }
            let body = json!({"attempt_id":started["attempt_id"],"response":a});
            assert_eq!(
                native_call(&app, &id, "finish", body.clone(), &cookies, &csrf)
                    .await
                    .status(),
                StatusCode::BAD_REQUEST,
                "variant {variant}"
            );
            let sent = out.recv().await.unwrap();
            assert!(sent.get("responseJson").is_none());
            assert_eq!(sent["error"]["name"], "NotAllowedError");
            assert_eq!(
                native_call(&app, &id, "finish", body, &cookies, &csrf)
                    .await
                    .status(),
                StatusCode::CONFLICT
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[tokio::test]
    async fn native_cancel_expiry_disconnect_and_epoch_revoke_completion() {
        for variant in 0..5 {
            let (app, dir) = app();
            let (cookies, csrf, mut out) = proxy_fixture(&app).await;
            let id = native_pending(
                &app,
                46,
                if variant == 1 {
                    json!({"timeout":10})
                } else {
                    json!({})
                },
            )
            .await;
            let started = start_native(&app, &id, &cookies, &csrf).await;
            match variant {
                0 => app
                    .broker
                    .lock()
                    .await
                    .on_message(json!({"type":"cancel","requestId":46}), &[])
                    .unwrap(),
                1 => tokio::time::sleep(Duration::from_millis(20)).await,
                2 => app.broker.lock().await.disconnected(),
                3 => app.inner.lock().await.vnc_epoch += 1,
                _ => {
                    assert_eq!(
                        step(&app, &id, json!({"action":"deny"}), &cookies, &csrf)
                            .await
                            .status(),
                        StatusCode::OK
                    );
                }
            }
            assert_eq!(
                native_call(
                    &app,
                    &id,
                    "finish",
                    json!({"attempt_id":started["attempt_id"],"response":assertion()}),
                    &cookies,
                    &csrf
                )
                .await
                .status(),
                StatusCode::CONFLICT
            );
            while let Ok(sent) = out.try_recv() {
                assert!(sent.get("responseJson").is_none());
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[tokio::test]
    async fn native_browser_error_is_exact_and_no_automatic_fallback() {
        for name in [
            "NotReadableError",
            "SecurityError",
            "NotAllowedError",
            "RangeError",
            "SyntaxError",
        ] {
            let (app, dir) = app();
            let (cookies, csrf, mut out) = proxy_fixture(&app).await;
            let id = native_pending(&app, 47, json!({})).await;
            let started = start_native(&app, &id, &cookies, &csrf).await;
            let error = json!({"name":name,"message":"Native device unavailable"});
            assert_eq!(
                native_call(
                    &app,
                    &id,
                    "finish",
                    json!({"attempt_id":started["attempt_id"],"error":error}),
                    &cookies,
                    &csrf
                )
                .await
                .status(),
                StatusCode::OK
            );
            let sent = out.recv().await.unwrap();
            assert_eq!(sent["error"], error);
            assert!(app.broker.lock().await.public_requests().is_empty());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[tokio::test]
    async fn native_simultaneous_finishes_have_one_winner_and_allowlist_is_enforced() {
        let (app, dir) = app();
        let (cookies, csrf, mut out) = proxy_fixture(&app).await;
        let id = native_pending(
            &app,
            48,
            json!({"allowCredentials":[{"type":"public-key","id":"AQID"}]}),
        )
        .await;
        let started = start_native(&app, &id, &cookies, &csrf).await;
        let body = json!({"attempt_id":started["attempt_id"],"response":assertion()});
        let (a, b) = tokio::join!(
            native_call(&app, &id, "finish", body.clone(), &cookies, &csrf),
            native_call(&app, &id, "finish", body, &cookies, &csrf)
        );
        let mut codes = [a.status().as_u16(), b.status().as_u16()];
        codes.sort();
        assert_eq!(codes, [200, 409]);
        assert!(out.recv().await.unwrap().get("responseJson").is_some());
        assert!(out.try_recv().is_err());
        let id = native_pending(
            &app,
            49,
            json!({"allowCredentials":[{"type":"public-key","id":"BwgJ"}]}),
        )
        .await;
        let started = start_native(&app, &id, &cookies, &csrf).await;
        assert_eq!(
            native_call(
                &app,
                &id,
                "finish",
                json!({"attempt_id":started["attempt_id"],"response":assertion()}),
                &cookies,
                &csrf
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(out.recv().await.unwrap().get("responseJson").is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn native_appid_hash_uses_original_validated_input_or_origin() {
        for appid in [
            "",
            "https://example.test/legacy-appid",
            "HTTPS://example.test/legacy-appid",
        ] {
            let (app, dir) = app();
            let (cookies, csrf, mut out) = proxy_fixture(&app).await;
            let id=native_pending(&app,51,json!({"extensions":{"appid":appid,"remoteDesktopClientOverride":{"origin":"https://example.test","sameOriginWithAncestors":true}}})).await;
            let started = start_native(&app, &id, &cookies, &csrf).await;
            let mut response = assertion();
            response["clientExtensionResults"]["appid"] = json!(true);
            let effective = if appid.is_empty() {
                "https://example.test"
            } else {
                appid
            };
            let mut auth = ring::digest::digest(&ring::digest::SHA256, effective.as_bytes())
                .as_ref()
                .to_vec();
            auth.extend_from_slice(&[5, 0, 0, 0, 1]);
            response["response"]["authenticatorData"] = json!(URL_SAFE_NO_PAD.encode(auth));
            assert_eq!(
                native_call(
                    &app,
                    &id,
                    "finish",
                    json!({"attempt_id":started["attempt_id"],"response":response}),
                    &cookies,
                    &csrf
                )
                .await
                .status(),
                StatusCode::OK
            );
            assert!(out.recv().await.unwrap().get("responseJson").is_some());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
