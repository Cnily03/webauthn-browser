//! Owner-bound, short-lived authorization for native Chromium caBLE discovery.
//! This transports radio observations, never QR payloads or authenticator keys.
use crate::{
    app::{App, Inner},
    auth::{authorize, cookie, csrf, token},
    http::error::{fail, ApiResult},
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::{io::AsyncWriteExt, net::UnixStream};

pub struct Session {
    pub id: String,
    pub token: String,
    pub deadline: Instant,
    owner_csrf: String,
    owner_cookie: Option<String>,
    epoch: u64,
    socket: Option<UnixStream>,
    window: Instant,
    count: u32,
    refreshed_at: Option<Instant>,
    pub(crate) fido: Option<crate::relay::fido_relay::Relay>,
    pub(crate) fido_pending: Option<crate::relay::fido_relay::Pending>,
}
fn pairing_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
impl Session {
    pub(crate) fn new(inner: &Inner, headers: &HeaderMap) -> Self {
        let now = Instant::now();
        let csrf_cookie = cookie(headers, "ab_csrf").unwrap();
        let mut deadline = now + Duration::from_secs(120);
        if let Some(expiry) = inner.csrf.get(csrf_cookie) {
            deadline = deadline.min(*expiry);
        }
        if let Some(session) = cookie(headers, "ab_vnc").and_then(|c| inner.sessions.get(c)) {
            deadline = deadline.min(session.expires);
        }
        Self {
            id: token(),
            token: pairing_token(),
            deadline,
            owner_csrf: csrf_cookie.into(),
            owner_cookie: cookie(headers, "ab_vnc").map(str::to_owned),
            epoch: inner.vnc_epoch,
            socket: None,
            window: now,
            count: 0,
            refreshed_at: None,
            fido: None,
            fido_pending: None,
        }
    }
    pub fn disconnected(&self) -> bool {
        self.socket.as_ref().is_some_and(|socket| {
            let mut byte = [0u8];
            match socket.try_read(&mut byte) {
                Ok(_) => true, // This protocol is write-only; incoming bytes are invalid.
                Err(e) => e.kind() != std::io::ErrorKind::WouldBlock,
            }
        })
    }
    pub fn valid_owner(&self, inner: &Inner) -> bool {
        self.deadline > Instant::now()
            && self.epoch == inner.vnc_epoch
            && inner
                .csrf
                .get(&self.owner_csrf)
                .is_some_and(|expiry| *expiry > Instant::now())
            && (inner.store.data.vnc_password_hash.is_none()
                || self
                    .owner_cookie
                    .as_ref()
                    .and_then(|cookie| inner.sessions.get(cookie))
                    .is_some_and(|s| {
                        s.scope == "vnc" && s.epoch == self.epoch && s.expires > Instant::now()
                    }))
    }
    pub(crate) fn renewed_deadline(&self, inner: &Inner) -> Instant {
        let mut deadline = Instant::now() + Duration::from_secs(120);
        if let Some(expiry) = inner.csrf.get(&self.owner_csrf) {
            deadline = deadline.min(*expiry);
        }
        if let Some(session) = self
            .owner_cookie
            .as_ref()
            .and_then(|c| inner.sessions.get(c))
        {
            deadline = deadline.min(session.expires);
        }
        deadline
    }
    pub(crate) fn owned(&self, inner: &Inner, headers: &HeaderMap) -> bool {
        self.valid_owner(inner)
            && Some(self.owner_csrf.as_str()) == cookie(headers, "ab_csrf")
            && self.owner_cookie.as_deref() == cookie(headers, "ab_vnc")
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refresh {
    session_id: String,
    previous_token: String,
}
/// Rotate a potentially consumed helper token, never the owner or native lease.
/// Only a live session owner can retry; a stale or competing response cannot
/// recreate authorization after logout, stop, proxy failure, or expiration.
pub async fn refresh(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Refresh>,
) -> ApiResult {
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    broker.validate_helper_owner(&inner);
    authorize(&inner, &headers, "vnc")?;
    csrf(&inner, &headers)?;
    broker.expire();
    let session = broker
        .helper
        .as_mut()
        .filter(|s| s.id == input.session_id && s.owned(&inner, &headers))
        .ok_or_else(|| {
            fail(
                StatusCode::CONFLICT,
                "Native relay session expired or belongs to another browser",
            )
        })?;
    if session.token != input.previous_token {
        return Err(fail(
            StatusCode::CONFLICT,
            "Pairing token already replaced; close this attempt",
        ));
    }
    if session
        .refreshed_at
        .is_some_and(|time| time.elapsed() < Duration::from_secs(1))
    {
        return Err(fail(
            StatusCode::TOO_MANY_REQUESTS,
            "Retry after one second",
        ));
    }
    // A new helper connection may never inherit in-flight USB reports.
    session.fido = None;
    session.fido_pending = None;
    session.token = pairing_token();
    session.refreshed_at = Some(Instant::now());
    Ok(Json(json!({"session_id":session.id,"token":session.token,
        "remaining_ms":session.deadline.saturating_duration_since(Instant::now()).as_millis() as u64})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stop {
    session_id: String,
}
pub async fn stop(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Stop>,
) -> ApiResult {
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    broker.validate_helper_owner(&inner);
    authorize(&inner, &headers, "vnc")?;
    csrf(&inner, &headers)?;
    broker.expire();
    if !broker
        .helper
        .as_ref()
        .is_some_and(|s| s.id == input.session_id && s.owned(&inner, &headers))
    {
        return Err(fail(
            StatusCode::CONFLICT,
            "Native relay session expired or belongs to another browser",
        ));
    }
    broker.stop_helper();
    Ok(Json(
        json!({"ok":true,"message":"Native relay session ended. Restoring software-key proxy."}),
    ))
}
pub async fn status(State(app): State<App>, headers: HeaderMap) -> ApiResult {
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    broker.validate_helper_owner(&inner);
    authorize(&inner, &headers, "vnc")?;
    broker.expire();
    if let Some(session) = broker.helper.as_ref().filter(|s| s.owned(&inner, &headers)) {
        return Ok(Json(
            json!({"active":true,"experimental_fido_available":session.fido.as_ref().is_some_and(|relay|relay.available()),"experimental_fido_launcher_ready":app.fido_launcher.available(),"remaining_ms":session.deadline.saturating_duration_since(Instant::now()).as_millis() as u64,"generation":broker.mode_generation,"mode":broker.browser_mode(),"state":broker.browser_mode_state(),"message":if broker.native_qr_mode {"Native relay is ready. Start registration or sign-in on the website in the container browser."} else {"Waiting for Chromium to confirm native authentication mode."}}),
        ));
    }
    Ok(Json(
        json!({"active":false,"remaining_ms":0,"generation":broker.mode_generation,"mode":broker.browser_mode(),"state":broker.browser_mode_state(),"message":"No active native relay session for this browser."}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advertisement {
    session_id: String,
    uuid: String,
    data: String,
}
fn valid_advertisement(uuid: &str, data: &str) -> bool {
    matches!(
        uuid,
        "0000fff9-0000-1000-8000-00805f9b34fb" | "0000fde2-0000-1000-8000-00805f9b34fb"
    ) && data.len() <= 88
        && STANDARD
            .decode(data)
            .is_ok_and(|b| !b.is_empty() && b.len() <= 64 && STANDARD.encode(&b) == data)
}
pub async fn advertisement(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Advertisement>,
) -> ApiResult {
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    broker.validate_helper_owner(&inner);
    authorize(&inner, &headers, "vnc")?;
    csrf(&inner, &headers)?;
    broker.expire();
    if !broker.native_qr_mode {
        return Err(fail(StatusCode::CONFLICT, "Native relay mode is not ready"));
    }
    let session = broker
        .helper
        .as_mut()
        .filter(|s| s.id == input.session_id && s.owned(&inner, &headers))
        .ok_or_else(|| {
            fail(
                StatusCode::CONFLICT,
                "Native relay session expired or belongs to another browser",
            )
        })?;
    if !valid_advertisement(&input.uuid, &input.data) {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "Expected bounded caBLE service data in canonical base64",
        ));
    }
    if session.window.elapsed() >= Duration::from_secs(1) {
        session.window = Instant::now();
        session.count = 0;
    }
    if session.count >= 100 {
        return Err(fail(
            StatusCode::TOO_MANY_REQUESTS,
            "Advertisement rate limit exceeded",
        ));
    }
    session.count += 1;
    drop(inner);
    let bytes = format!(
        "{}\n",
        json!({"type":"advertisement","uuid":input.uuid,"data":input.data})
    );
    let outcome = tokio::time::timeout(Duration::from_millis(500), async {
        if session.socket.is_none() {
            let path = std::env::var("AUTH_BROWSER_BLE_SOCKET")
                .unwrap_or_else(|_| "/data/run/ble.sock".into());
            session.socket = Some(UnixStream::connect(path).await?);
        }
        session
            .socket
            .as_mut()
            .unwrap()
            .write_all(bytes.as_bytes())
            .await
    })
    .await;
    if !matches!(outcome, Ok(Ok(()))) {
        broker.stop_helper();
        return Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "BLE bridge disconnected; native relay session revoked",
        ));
    }
    Ok(Json(json!({"ok":true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::{App, Session},
        test_support::{app, call, create_pending, proxy_fixture, value},
    };

    use axum::http::StatusCode;
    use serde_json::{json, Value};
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc;

    #[test]
    fn advertisements_are_bounded_and_canonical() {
        let uuid = "0000fff9-0000-1000-8000-00805f9b34fb";
        assert!(valid_advertisement(uuid, "AQ=="));
        for bad in ["", "AQ", "AB==", "!!!!"] {
            assert!(!valid_advertisement(uuid, bad));
        }
        assert!(!valid_advertisement(uuid, &STANDARD.encode([0; 65])));
        assert!(!valid_advertisement("fff9", "AQ=="));
    }

    async fn native_input(app: &App) -> Value {
        let generation = app.broker.lock().await.mode_generation;
        json!({"mode":"native","expected_generation":generation})
    }

    async fn get_pending(app: &App) -> String {
        let mut broker = app.broker.lock().await;
        let options = json!({"rpId":"example.test","challenge":"AQID","extensions":{"remoteDesktopClientOverride":{"origin":"https://example.test","sameOriginWithAncestors":true}}});
        broker
            .on_message(
                json!({"type":"get","requestId":987,"requestDetailsJson":options.to_string()}),
                &[],
            )
            .unwrap();
        broker.public_requests()[0]["id"].as_str().unwrap().into()
    }
    #[tokio::test]
    async fn helper_owner_csrf_mode_ack_stop_and_expiry() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let _id = get_pending(&app).await;
        let body = native_input(&app).await;
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/browser/mode",
                body.clone(),
                &cookies,
                "",
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let started = value(
            call(
                &app,
                "POST",
                "/api/browser/mode",
                body.clone(),
                &cookies,
                &csrf,
                None,
            )
            .await,
        )
        .await;
        assert_eq!(started["helper_url"], "ws://127.0.0.1:10233");
        let session = started["session_id"].as_str().unwrap();
        assert_eq!(started["token"].as_str().unwrap().len(), 43);
        assert!(output.try_recv().unwrap()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Retry"));
        let mode = output.try_recv().unwrap();
        assert_eq!(mode["mode"], "native");
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/browser/mode",
                body,
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let state = value(
            call(
                &app,
                "GET",
                "/api/helper/status",
                Value::Null,
                &cookies,
                "",
                None,
            )
            .await,
        )
        .await;
        assert_eq!(state["state"], "switching");
        let ad = json!({"session_id":session,"uuid":"0000fff9-0000-1000-8000-00805f9b34fb","data":"AQ=="});
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/advertisement",
                ad.clone(),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let mut broker = app.broker.lock().await;
        assert!(broker
            .on_message(
                json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":99999}),
                &[]
            )
            .is_err());
        assert!(!broker.native_qr_mode);
        broker
            .on_message(
                json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":mode["generation"]}),
                &[],
            )
            .unwrap();
        drop(broker);
        let unrelated =
            value(call(&app, "GET", "/api/status", Value::Null, "", "", None).await).await;
        let other_csrf = unrelated["csrf_token"].as_str().unwrap();
        let other = format!("ab_csrf={other_csrf}");
        assert_eq!(
            value(
                call(
                    &app,
                    "GET",
                    "/api/helper/status",
                    Value::Null,
                    &other,
                    "",
                    None
                )
                .await
            )
            .await["active"],
            false
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/stop",
                json!({"session_id":session}),
                &other,
                other_csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/advertisement",
                ad,
                &other,
                other_csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let invalid = json!({"session_id":session,"uuid":"fff9","data":"AQ=="});
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/advertisement",
                invalid,
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        app.broker.lock().await.helper.as_mut().unwrap().deadline = Instant::now();
        assert_eq!(
            value(
                call(
                    &app,
                    "GET",
                    "/api/helper/status",
                    Value::Null,
                    &cookies,
                    "",
                    None
                )
                .await
            )
            .await["active"],
            false
        );
        let stop_mode = output.try_recv().unwrap();
        assert_eq!(stop_mode["mode"], "proxy");
        let mut broker = app.broker.lock().await;
        assert!(!broker.ready);
        assert!(!broker.native_qr_mode);
        assert!(broker
            .on_message(
                json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":mode["generation"]}),
                &[]
            )
            .is_err());
        broker
            .on_message(
                json!({"type":"mode_ready","mode":"proxy","attached":true,"extensionVersion":"1.0.29","protocolVersion":1,"generation":stop_mode["generation"]}),
                &[],
            )
            .unwrap();
        assert!(broker.ready);
        drop(broker);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn global_mode_cancels_registration_and_claimed_login_without_kind_gate() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let create = create_pending(&app, 1).await;
        let id = get_pending(&app).await;
        let request = app.broker.lock().await.take_request(&id).unwrap();
        let started = call(
            &app,
            "POST",
            "/api/browser/mode",
            native_input(&app).await,
            &cookies,
            &csrf,
            None,
        )
        .await;
        assert_eq!(started.status(), StatusCode::OK);
        let mut cancellations = [output.try_recv().unwrap(), output.try_recv().unwrap()];
        cancellations.sort_by_key(|m| m["type"].as_str().unwrap().to_owned());
        assert_eq!(cancellations[0]["type"], "create");
        assert_eq!(cancellations[1]["type"], "get");
        assert!(cancellations
            .iter()
            .all(|m| m["error"]["name"] == "NotAllowedError"));
        assert_eq!(output.try_recv().unwrap()["mode"], "native");
        let mut broker = app.broker.lock().await;
        assert!(broker.public_requests().is_empty());
        assert!(broker.take_request(&create).is_none());
        assert!(!broker.finish(&request, Ok(json!({}))));
        broker.disconnected();
        assert!(broker.helper.is_none());
        assert!(!broker.native_qr_mode);
        drop(broker);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn helper_owner_epoch_and_session_removal_revoke() {
        for epoch_change in [false, true] {
            let (app, dir) = app();
            let (mut cookies, csrf, mut output) = proxy_fixture(&app).await;
            {
                let mut inner = app.inner.lock().await;
                inner.store.data.vnc_password_hash = Some("enabled".into());
                inner.sessions.insert(
                    "owner".into(),
                    Session {
                        scope: "vnc".into(),
                        epoch: 0,
                        expires: Instant::now() + Duration::from_secs(60),
                    },
                );
            }
            cookies.push_str("; ab_vnc=owner");
            let _id = get_pending(&app).await;
            assert_eq!(
                call(
                    &app,
                    "POST",
                    "/api/browser/mode",
                    native_input(&app).await,
                    &cookies,
                    &csrf,
                    None
                )
                .await
                .status(),
                StatusCode::OK
            );
            output.try_recv().unwrap();
            let mode = output.try_recv().unwrap();
            let mut broker = app.broker.lock().await;
            broker
                .on_message(
                    json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":mode["generation"]}),
                    &[],
                )
                .unwrap();
            let mut inner = app.inner.lock().await;
            if epoch_change {
                inner.vnc_epoch += 1;
            } else {
                inner.sessions.remove("owner");
            }
            broker.validate_helper_owner(&inner);
            assert!(broker.helper.is_none());
            assert!(!broker.native_qr_mode);
            assert_eq!(output.try_recv().unwrap()["mode"], "proxy");
            drop(inner);
            drop(broker);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[tokio::test]
    async fn helper_stop_ack_timeout_and_protected_routes() {
        for timeout in [false, true] {
            let (app, dir) = app();
            let (cookies, csrf, mut output) = proxy_fixture(&app).await;
            let _id = get_pending(&app).await;
            let started = value(
                call(
                    &app,
                    "POST",
                    "/api/browser/mode",
                    native_input(&app).await,
                    &cookies,
                    &csrf,
                    None,
                )
                .await,
            )
            .await;
            output.try_recv().unwrap();
            output.try_recv().unwrap();
            if timeout {
                let mut broker = app.broker.lock().await;
                broker.mode_pending = Some(Instant::now());
                broker.expire();
            } else {
                assert_eq!(
                    call(
                        &app,
                        "POST",
                        "/api/helper/stop",
                        json!({"session_id":started["session_id"]}),
                        &cookies,
                        &csrf,
                        None
                    )
                    .await
                    .status(),
                    StatusCode::OK
                );
            }
            assert_eq!(output.try_recv().unwrap()["mode"], "proxy");
            assert!(app.broker.lock().await.helper.is_none());
            app.inner.lock().await.store.data.vnc_password_hash = Some("protected".into());
            assert_eq!(
                call(
                    &app,
                    "GET",
                    "/api/helper/status",
                    Value::Null,
                    &cookies,
                    "",
                    None
                )
                .await
                .status(),
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                call(
                    &app,
                    "POST",
                    "/api/browser/mode",
                    native_input(&app).await,
                    &cookies,
                    &csrf,
                    None
                )
                .await
                .status(),
                StatusCode::UNAUTHORIZED
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn helper_refresh_rotates_only_current_owner_token_without_extending_lease() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let _id = get_pending(&app).await;
        let started = value(
            call(
                &app,
                "POST",
                "/api/browser/mode",
                native_input(&app).await,
                &cookies,
                &csrf,
                None,
            )
            .await,
        )
        .await;
        output.try_recv().unwrap();
        let mode = output.try_recv().unwrap();
        app.broker.lock().await.on_message(json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":mode["generation"]}), &[]).unwrap();
        let session = started["session_id"].as_str().unwrap();
        let original_token = started["token"].as_str().unwrap();
        let deadline = app.broker.lock().await.helper.as_ref().unwrap().deadline;
        let payload = json!({"session_id":session,"previous_token":original_token});
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/refresh",
                payload.clone(),
                &cookies,
                "",
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let unrelated =
            value(call(&app, "GET", "/api/status", Value::Null, "", "", None).await).await;
        let other_csrf = unrelated["csrf_token"].as_str().unwrap();
        let other = format!("ab_csrf={other_csrf}");
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/refresh",
                payload.clone(),
                &other,
                other_csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let refreshed = value(
            call(
                &app,
                "POST",
                "/api/helper/refresh",
                payload.clone(),
                &cookies,
                &csrf,
                None,
            )
            .await,
        )
        .await;
        assert_eq!(refreshed["session_id"], session);
        let current_token = refreshed["token"].as_str().unwrap();
        assert_eq!(current_token.len(), 43);
        assert_ne!(current_token, original_token);
        assert!(
            refreshed["remaining_ms"].as_u64().unwrap()
                <= started["expires_in_ms"].as_u64().unwrap()
        );
        assert_eq!(
            app.broker.lock().await.helper.as_ref().unwrap().deadline,
            deadline
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/refresh",
                payload,
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let payload = json!({"session_id":session,"previous_token":current_token});
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/refresh",
                payload.clone(),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert!(
            output.try_recv().is_err(),
            "refresh must not replay mode transitions or extend the browser lease"
        );
        app.broker.lock().await.helper.as_mut().unwrap().deadline = Instant::now();
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/refresh",
                payload,
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert!(app.broker.lock().await.helper.is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn helper_refresh_cannot_restore_stopped_or_disconnected_sessions() {
        for disconnect in [false, true] {
            let (app, dir) = app();
            let (cookies, csrf, _output) = proxy_fixture(&app).await;
            let _id = get_pending(&app).await;
            let started = value(
                call(
                    &app,
                    "POST",
                    "/api/browser/mode",
                    native_input(&app).await,
                    &cookies,
                    &csrf,
                    None,
                )
                .await,
            )
            .await;
            if disconnect {
                app.broker.lock().await.disconnected();
            } else {
                app.broker.lock().await.stop_helper();
            }
            assert_eq!(
                call(
                    &app,
                    "POST",
                    "/api/helper/refresh",
                    json!({"session_id":started["session_id"],"previous_token":started["token"]}),
                    &cookies,
                    &csrf,
                    None
                )
                .await
                .status(),
                StatusCode::CONFLICT
            );
            assert!(app.broker.lock().await.helper.is_none());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    // Simulated gateway/broker control fixture: acknowledgements stand in for the
    // extension. This does not launch Chromium, pair a helper, or exercise phone E2E.
    #[tokio::test]
    async fn helper_simulated_control_retry_cancel_restores_proxy_exactly_once() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let _id = get_pending(&app).await;
        let response = call(
            &app,
            "POST",
            "/api/browser/mode",
            native_input(&app).await,
            &cookies,
            &csrf,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let started = value(response).await;
        let session_id = started["session_id"].as_str().unwrap();
        let mut tokens = vec![started["token"].as_str().unwrap().to_owned()];
        let mut remaining_ms = started["expires_in_ms"].as_u64().unwrap();

        let canceled_request = output.try_recv().unwrap();
        assert_eq!(canceled_request["type"], "get");
        assert_eq!(canceled_request["requestId"], 987);
        assert_eq!(canceled_request["error"]["name"], "NotAllowedError");
        let native_command = output.try_recv().unwrap();
        assert_eq!(native_command["type"], "mode");
        assert_eq!(native_command["mode"], "native");
        let native_generation = native_command["generation"].as_u64().unwrap();
        let native_ack = json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":native_generation});
        let deadline = {
            let mut broker = app.broker.lock().await;
            assert!(!broker.ready);
            assert!(!broker.native_qr_mode);
            assert!(broker.mode_pending.is_some());
            assert!(broker.public_requests().is_empty());
            broker.on_message(native_ack.clone(), &[]).unwrap();
            assert!(broker.native_qr_mode);
            assert!(!broker.ready);
            assert!(broker.mode_pending.is_none());
            broker.helper.as_ref().unwrap().deadline
        };

        // Respect the production one-second refresh limit. The lease uses
        // std::time::Instant, so a paused Tokio clock would not advance it.
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(1010)).await;
            }
            let refresh = json!({"session_id":session_id,"previous_token":tokens.last().unwrap()});
            let response = call(
                &app,
                "POST",
                "/api/helper/refresh",
                refresh.clone(),
                &cookies,
                &csrf,
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let refreshed = value(response).await;
            assert_eq!(refreshed["session_id"], session_id);
            let token = refreshed["token"].as_str().unwrap().to_owned();
            assert_eq!(token.len(), 43);
            assert!(!tokens.contains(&token));
            tokens.push(token);
            let refreshed_remaining = refreshed["remaining_ms"].as_u64().unwrap();
            assert!(refreshed_remaining <= remaining_ms);
            remaining_ms = refreshed_remaining;

            // A duplicated refresh cannot consume another token or replay native
            // mode, even if its original response reached the caller late.
            assert_eq!(
                call(
                    &app,
                    "POST",
                    "/api/helper/refresh",
                    refresh,
                    &cookies,
                    &csrf,
                    None,
                )
                .await
                .status(),
                StatusCode::CONFLICT
            );
            let broker = app.broker.lock().await;
            let session = broker.helper.as_ref().unwrap();
            assert_eq!(session.deadline, deadline);
            assert_eq!(&session.token, tokens.last().unwrap());
            assert_eq!(broker.mode_generation, native_generation);
            assert!(broker.native_qr_mode);
            assert!(!broker.ready);
            assert!(broker.mode_pending.is_none());
            assert!(matches!(
                output.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }

        let stop = json!({"session_id":session_id});
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/stop",
                stop.clone(),
                &cookies,
                &csrf,
                None,
            )
            .await
            .status(),
            StatusCode::OK
        );
        let proxy_command = output.try_recv().unwrap();
        assert_eq!(proxy_command["type"], "mode");
        assert_eq!(proxy_command["mode"], "proxy");
        let proxy_generation = proxy_command["generation"].as_u64().unwrap();
        assert_eq!(proxy_generation, native_generation.wrapping_add(1));
        let proxy_deadline = {
            let mut broker = app.broker.lock().await;
            assert!(broker.helper.is_none());
            assert!(!broker.native_qr_mode);
            assert!(!broker.ready);
            assert!(broker.on_message(native_ack.clone(), &[]).is_err());
            assert!(broker
                .on_message(
                    json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":proxy_generation}),
                    &[],
                )
                .is_err());
            broker.mode_pending.unwrap()
        };

        // Simulate canceled-session callbacks racing with repeated Cancel clicks.
        // Even the last current token must be revoked, as must every stale token.
        for token in &tokens {
            let (repeated_stop, late_refresh) = tokio::join!(
                call(
                    &app,
                    "POST",
                    "/api/helper/stop",
                    stop.clone(),
                    &cookies,
                    &csrf,
                    None,
                ),
                call(
                    &app,
                    "POST",
                    "/api/helper/refresh",
                    json!({"session_id":session_id,"previous_token":token}),
                    &cookies,
                    &csrf,
                    None,
                ),
            );
            assert_eq!(repeated_stop.status(), StatusCode::CONFLICT);
            assert_eq!(late_refresh.status(), StatusCode::CONFLICT);
            let broker = app.broker.lock().await;
            assert!(broker.helper.is_none());
            assert!(!broker.native_qr_mode);
            assert!(!broker.ready);
            assert_eq!(broker.mode_generation, proxy_generation);
            assert_eq!(broker.mode_pending, Some(proxy_deadline));
            assert!(matches!(
                output.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }

        {
            let mut broker = app.broker.lock().await;
            broker
                .on_message(
                    json!({"type":"mode_ready","mode":"proxy","attached":true,"extensionVersion":"1.0.29","protocolVersion":1,"generation":proxy_generation}),
                    &[],
                )
                .unwrap();
            assert!(broker.ready);
            assert!(!broker.native_qr_mode);
            assert!(broker.mode_pending.is_none());
            assert!(broker.helper.is_none());
            assert!(broker.on_message(native_ack, &[]).is_err());
        }
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/stop",
                stop,
                &cookies,
                &csrf,
                None,
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let status = value(
            call(
                &app,
                "GET",
                "/api/helper/status",
                Value::Null,
                &cookies,
                "",
                None,
            )
            .await,
        )
        .await;
        assert_eq!(status["active"], false);
        assert_eq!(status["state"], "software");
        assert!(app.broker.lock().await.ready);
        assert!(matches!(
            output.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn extension_handshake_rejection_revokes_active_helper_and_blocks_native_ack() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let _id = get_pending(&app).await;
        let started = call(
            &app,
            "POST",
            "/api/browser/mode",
            native_input(&app).await,
            &cookies,
            &csrf,
            None,
        )
        .await;
        assert_eq!(started.status(), StatusCode::OK);
        assert!(output.try_recv().unwrap().get("error").is_some());
        let mode = output.try_recv().unwrap();
        {
            let mut broker = app.broker.lock().await;
            assert!(broker.helper.is_some());
            assert!(broker.on_message(json!({"type":"ready"}), &[]).is_err());
            assert!(broker.helper.is_none());
            assert!(!broker.ready && !broker.native_qr_mode);
            assert!(broker.mode_pending.is_none());
            assert!(broker.on_message(json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":mode["generation"]}), &[]).is_err());
            let snapshot = broker.stream_snapshot(None);
            assert_eq!(snapshot["mode_error"], "extension_upgrade_required");
            assert_eq!(snapshot["mode_switching"], false);
        }
        assert!(output.try_recv().is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn helper_api_and_legacy_alias_share_session_and_security_boundaries() {
        // Both prefixes are intentional compatibility surfaces, backed by one router.
        for (prefix, alternate) in [
            ("/api/helper", "/api/companion"),
            ("/api/companion", "/api/helper"),
        ] {
            let (app, dir) = app();
            let (cookies, csrf, mut output) = proxy_fixture(&app).await;
            let started = value(
                call(
                    &app,
                    "POST",
                    "/api/browser/mode",
                    native_input(&app).await,
                    &cookies,
                    &csrf,
                    None,
                )
                .await,
            )
            .await;
            let mode = output.try_recv().unwrap();
            let deadline = app.broker.lock().await.helper.as_ref().unwrap().deadline;
            let status_path = format!("{prefix}/status");
            let status =
                value(call(&app, "GET", &status_path, Value::Null, &cookies, "", None).await).await;
            assert_eq!(status["active"], true);
            assert!(status.get("session_id").is_none() && status.get("token").is_none());
            let unrelated =
                value(call(&app, "GET", "/api/status", Value::Null, "", "", None).await).await;
            let other_csrf = unrelated["csrf_token"].as_str().unwrap();
            let other = format!("ab_csrf={other_csrf}");
            assert_eq!(
                value(call(&app, "GET", &status_path, Value::Null, &other, "", None).await).await
                    ["active"],
                false
            );
            let refresh_path = format!("{prefix}/refresh");
            let refresh_input =
                json!({"session_id":started["session_id"], "previous_token":started["token"]});
            assert_eq!(
                call(
                    &app,
                    "POST",
                    &refresh_path,
                    refresh_input.clone(),
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
                    &refresh_path,
                    refresh_input.clone(),
                    &other,
                    other_csrf,
                    None
                )
                .await
                .status(),
                StatusCode::CONFLICT
            );
            let refreshed = value(
                call(
                    &app,
                    "POST",
                    &refresh_path,
                    refresh_input.clone(),
                    &cookies,
                    &csrf,
                    None,
                )
                .await,
            )
            .await;
            assert_ne!(refreshed["token"], started["token"]);
            assert_eq!(
                app.broker.lock().await.helper.as_ref().unwrap().deadline,
                deadline
            );
            assert_eq!(
                call(
                    &app,
                    "POST",
                    &format!("{alternate}/refresh"),
                    refresh_input,
                    &cookies,
                    &csrf,
                    None
                )
                .await
                .status(),
                StatusCode::CONFLICT
            );
            assert_eq!(
                call(
                    &app,
                    "POST",
                    &refresh_path,
                    json!({"session_id":"x".repeat(5000), "previous_token":"x"}),
                    &cookies,
                    &csrf,
                    None
                )
                .await
                .status(),
                StatusCode::PAYLOAD_TOO_LARGE
            );
            {
                let mut broker = app.broker.lock().await;
                broker.on_message(json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":mode["generation"]}), &[]).unwrap();
            }
            let ad_path = format!("{prefix}/advertisement");
            let invalid_ad =
                json!({"session_id":started["session_id"],"uuid":"invalid","data":"AQ=="});
            assert_eq!(
                call(
                    &app,
                    "POST",
                    &ad_path,
                    invalid_ad.clone(),
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
                    &ad_path,
                    invalid_ad.clone(),
                    &other,
                    other_csrf,
                    None
                )
                .await
                .status(),
                StatusCode::CONFLICT
            );
            assert_eq!(
                call(&app, "POST", &ad_path, invalid_ad, &cookies, &csrf, None)
                    .await
                    .status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                call(
                    &app,
                    "POST",
                    &ad_path,
                    json!({"session_id":started["session_id"],"uuid":"x","data":"x".repeat(5000)}),
                    &cookies,
                    &csrf,
                    None
                )
                .await
                .status(),
                StatusCode::PAYLOAD_TOO_LARGE
            );
            let stop_input = json!({"session_id":started["session_id"]});
            assert_eq!(
                call(
                    &app,
                    "POST",
                    &format!("{prefix}/stop"),
                    stop_input.clone(),
                    &other,
                    other_csrf,
                    None
                )
                .await
                .status(),
                StatusCode::CONFLICT
            );
            assert_eq!(
                call(
                    &app,
                    "POST",
                    &format!("{alternate}/stop"),
                    stop_input,
                    &cookies,
                    &csrf,
                    None
                )
                .await
                .status(),
                StatusCode::OK
            );
            assert!(app.broker.lock().await.helper.is_none());
            assert_eq!(
                value(call(&app, "GET", &status_path, Value::Null, &cookies, "", None).await).await
                    ["active"],
                false
            );
            app.inner.lock().await.store.data.vnc_password_hash = Some("protected".into());
            for path in [status_path, format!("{prefix}/downloads")] {
                assert_eq!(
                    call(&app, "GET", &path, Value::Null, &cookies, "", None)
                        .await
                        .status(),
                    StatusCode::UNAUTHORIZED
                );
            }
            for (path, body) in [
                (format!("{prefix}/stop"), json!({"session_id":"stale"})),
                (
                    refresh_path,
                    json!({"session_id":"stale", "previous_token":"stale"}),
                ),
                (
                    ad_path,
                    json!({"session_id":"stale", "uuid":"x", "data":"AQ=="}),
                ),
            ] {
                assert_eq!(
                    call(&app, "POST", &path, body, &cookies, &csrf, None)
                        .await
                        .status(),
                    StatusCode::UNAUTHORIZED
                );
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
