//! Authenticated, owner-capability-bound browser mode selection and lease renewal.
//! Mode selection is global to Chromium and independent of WebAuthn requests.
use crate::{
    app::{App, Inner},
    auth::{authorize, csrf},
    http::error::{fail, ApiResult},
    relay::helper,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

fn snapshot(broker: &crate::browser::broker::Broker, inner: &Inner, headers: &HeaderMap) -> Value {
    let session = broker.helper.as_ref();
    json!({
        "mode":broker.browser_mode(), "state":broker.browser_mode_state(),
        "generation":broker.mode_generation, "active":session.is_some(),
        "owned":session.is_some_and(|s| s.owned(inner, headers)),
        "remaining_ms":session.map_or(0, |s| s.deadline.saturating_duration_since(Instant::now()).as_millis() as u64),
        "control_connected":broker.outbound.is_some(), "mode_error":broker.mode_error,
        "native_qr_mode":broker.native_qr_mode, "mode_switching":broker.mode_pending.is_some(),
        "connected":broker.ready
    })
}

pub async fn status(State(app): State<App>, headers: HeaderMap) -> ApiResult {
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    broker.validate_helper_owner(&inner);
    authorize(&inner, &headers, "vnc")?;
    broker.expire();
    // Never publish the session capability or pairing token to another tab,
    // including one with the same cookies and CSRF token.
    Ok(Json(snapshot(&broker, &inner, &headers)))
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Native,
    Software,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Select {
    mode: Mode,
    expected_generation: u64,
    session_id: Option<String>,
}
fn conflict() -> (StatusCode, String) {
    fail(
        StatusCode::CONFLICT,
        "Browser mode changed or this tab does not own the active native relay session",
    )
}
pub async fn select(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Select>,
) -> ApiResult {
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    broker.validate_helper_owner(&inner);
    authorize(&inner, &headers, "vnc")?;
    csrf(&inner, &headers)?;
    broker.expire();
    if broker.mode_generation != input.expected_generation {
        return Err(conflict());
    }
    match input.mode {
        Mode::Native => {
            // An existing lease cannot be stolen or replaced even by a tab
            // sharing cookies. Only its holder can explicitly release it.
            if broker.helper.is_some() || input.session_id.is_some() {
                return Err(conflict());
            }
            let session = helper::Session::new(&inner, &headers);
            let id = session.id.clone();
            let token = session.token.clone();
            if !broker.start_helper(session) {
                return Err(fail(
                    StatusCode::CONFLICT,
                    "A compatible, ready browser is required before selecting native relay mode",
                ));
            }
            let mut response = snapshot(&broker, &inner, &headers);
            response["session_id"] = json!(id);
            response["token"] = json!(token);
            response["expires_in_ms"] = response["remaining_ms"].clone();
            response["helper_url"] = json!("ws://127.0.0.1:10233");
            Ok(Json(response))
        }
        Mode::Software => {
            if let Some(session) = broker.helper.as_ref() {
                if input.session_id.as_deref() != Some(session.id.as_str())
                    || !session.owned(&inner, &headers)
                {
                    return Err(conflict());
                }
                broker.stop_helper();
            } else if input.session_id.is_some() || broker.mode_pending.is_some() {
                return Err(conflict());
            } else if !broker.ready && !broker.restore_software_mode() {
                return Err(fail(StatusCode::CONFLICT, "Browser control is unavailable"));
            }
            Ok(Json(snapshot(&broker, &inner, &headers)))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Renew {
    session_id: String,
    expected_generation: u64,
}
pub async fn renew(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Renew>,
) -> ApiResult {
    let (lease_generation, mut changed) = {
        let mut broker = app.broker.lock().await;
        let inner = app.inner.lock().await;
        broker.validate_helper_owner(&inner);
        authorize(&inner, &headers, "vnc")?;
        csrf(&inner, &headers)?;
        broker.expire();
        if broker.mode_generation != input.expected_generation {
            return Err(conflict());
        }
        let session = broker
            .helper
            .as_ref()
            .filter(|s| s.id == input.session_id && s.owned(&inner, &headers))
            .ok_or_else(conflict)?;
        let deadline = session.renewed_deadline(&inner);
        let changed = broker.subscribe();
        let generation = broker.renew_native_lease(deadline).ok_or_else(conflict)?;
        (generation, changed)
    };
    // A successful HTTP response means the executing extension acknowledged
    // the renewed lease. No readiness or lifetime is inferred from a write.
    let until = tokio::time::Instant::now() + Duration::from_secs(6);
    loop {
        {
            let mut broker = app.broker.lock().await;
            let inner = app.inner.lock().await;
            broker.validate_helper_owner(&inner);
            authorize(&inner, &headers, "vnc")?;
            csrf(&inner, &headers)?;
            broker.expire();
            if broker.mode_generation != input.expected_generation
                || !broker
                    .helper
                    .as_ref()
                    .is_some_and(|s| s.id == input.session_id && s.owned(&inner, &headers))
            {
                return Err(conflict());
            }
            if broker.lease_generation >= lease_generation {
                return Ok(Json(snapshot(&broker, &inner, &headers)));
            }
        }
        tokio::select! {
            _ = changed.changed() => {},
            _ = tokio::time::sleep(Duration::from_millis(100)) => {},
            _ = tokio::time::sleep_until(until) => {
                let mut broker = app.broker.lock().await;
                if broker.mode_generation == input.expected_generation && broker.helper.as_ref().is_some_and(|s| s.id == input.session_id) {
                    broker.stop_helper();
                }
                return Err(fail(StatusCode::SERVICE_UNAVAILABLE, "Native relay lease acknowledgement timed out"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        app::{App, Session},
        test_support::{app, call, proxy_fixture, value},
    };

    use axum::{http::StatusCode, response::Response};

    use serde_json::{json, Value};
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc;

    async fn select_native(app: &App, cookies: &str, csrf: &str) -> Response {
        let generation = app.broker.lock().await.mode_generation;
        call(
            app,
            "POST",
            "/api/browser/mode",
            json!({"mode":"native","expected_generation":generation}),
            cookies,
            csrf,
            None,
        )
        .await
    }
    fn mode_ack(command: &Value) -> Value {
        json!({"type":"mode_ready","mode":command["mode"],"generation":command["generation"],
            "attached":command["mode"] == "proxy","extensionVersion":"1.0.29","protocolVersion":1})
    }
    fn lease_ack(command: &Value) -> Value {
        json!({"type":"mode_lease_ready","mode":"native","generation":command["generation"],
            "leaseGeneration":command["leaseGeneration"],"attached":false,
            "extensionVersion":"1.0.29","protocolVersion":1})
    }
    async fn enter_native(
        app: &App,
        cookies: &str,
        csrf: &str,
        output: &mut mpsc::UnboundedReceiver<Value>,
    ) -> Value {
        let response = select_native(app, cookies, csrf).await;
        assert_eq!(response.status(), StatusCode::OK);
        let started = value(response).await;
        let command = output.recv().await.unwrap();
        assert_eq!(command["type"], "mode");
        app.broker
            .lock()
            .await
            .on_message(mode_ack(&command), &[])
            .unwrap();
        started
    }
    fn spawn_renew(
        app: &App,
        cookies: &str,
        csrf: &str,
        session: &Value,
    ) -> tokio::task::JoinHandle<Response> {
        let (app, cookies, csrf, session) = (
            app.clone(),
            cookies.to_owned(),
            csrf.to_owned(),
            session.clone(),
        );
        tokio::spawn(async move {
            call(&app, "POST", "/api/browser/mode/renew", json!({"session_id":session["session_id"],"expected_generation":session["generation"]}), &cookies, &csrf, None).await
        })
    }

    #[tokio::test]
    async fn native_selection_precedes_requests_and_requires_truthful_exact_build_ack() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let original_store = app.inner.lock().await.store.data.clone();
        let started = value(select_native(&app, &cookies, &csrf).await).await;
        assert_eq!(started["mode"], "native");
        assert_eq!(started["state"], "switching");
        assert_eq!(started["connected"], false);
        assert_eq!(started["native_qr_mode"], false);
        let command = output.try_recv().unwrap();
        assert_eq!(command["mode"], "native");
        assert!(command["leaseRemainingMs"]
            .as_u64()
            .is_some_and(|n| (1..=120000).contains(&n)));
        let good = mode_ack(&command);
        let mut broker = app.broker.lock().await;
        assert!(broker.public_requests().is_empty());
        for (field, wrong) in [
            ("attached", json!(true)),
            ("extensionVersion", json!("1.0.28")),
            ("protocolVersion", json!(2)),
        ] {
            let mut bad = good.clone();
            bad[field] = wrong;
            assert!(broker.on_message(bad, &[]).is_err());
            assert!(!broker.native_qr_mode && !broker.ready);
        }
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove("attached");
        assert!(broker.on_message(missing, &[]).is_err());
        broker.on_message(good, &[]).unwrap();
        assert!(broker.native_qr_mode && !broker.ready);
        // Interceptor records after confirmed detach are not software-authorized,
        // regardless of create/get. Actual native credentials stay in Chromium.
        for kind in ["create", "get"] {
            assert!(broker
                .on_message(
                    json!({"type":kind,"requestId":92,"requestDetailsJson":"{}"}),
                    &[]
                )
                .is_err());
            assert_eq!(
                output.try_recv().unwrap()["error"]["name"],
                "NotAllowedError"
            );
        }
        let snapshot = broker.stream_snapshot(None).to_string();
        assert!(!snapshot.contains(started["token"].as_str().unwrap()));
        assert!(!snapshot.contains(started["session_id"].as_str().unwrap()));
        assert!(broker.public_requests().is_empty());
        drop(broker);
        assert_eq!(
            serde_json::to_value(original_store).unwrap(),
            serde_json::to_value(&app.inner.lock().await.store.data).unwrap()
        );
        for endpoint in ["/api/browser/mode", "/api/helper/status"] {
            let status =
                value(call(&app, "GET", endpoint, Value::Null, &cookies, "", None).await).await;
            assert_eq!(status["active"], true);
            assert_eq!(status["state"], "native");
            assert_eq!(status["generation"], started["generation"]);
            assert!(status.get("session_id").is_none() && status.get("token").is_none());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn global_mode_cas_and_tab_capability_prevent_steal_and_late_cleanup() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let generation = app.broker.lock().await.mode_generation;
        let input = json!({"mode":"native","expected_generation":generation});
        let (one, two) = tokio::join!(
            call(
                &app,
                "POST",
                "/api/browser/mode",
                input.clone(),
                &cookies,
                &csrf,
                None
            ),
            call(
                &app,
                "POST",
                "/api/browser/mode",
                input,
                &cookies,
                &csrf,
                None
            )
        );
        let started = if one.status() == StatusCode::OK {
            assert_eq!(two.status(), StatusCode::CONFLICT);
            value(one).await
        } else {
            assert_eq!(one.status(), StatusCode::CONFLICT);
            value(two).await
        };
        let command = output.try_recv().unwrap();
        app.broker
            .lock()
            .await
            .on_message(mode_ack(&command), &[])
            .unwrap();
        assert!(output.try_recv().is_err());
        for id in [Value::Null, json!("another-tab")] {
            let response = call(&app,"POST","/api/browser/mode",json!({"mode":"software","expected_generation":started["generation"],"session_id":id}),&cookies,&csrf,None).await;
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }
        assert_eq!(
            select_native(&app, &cookies, &csrf).await.status(),
            StatusCode::CONFLICT
        );
        let stopped = call(&app,"POST","/api/browser/mode",json!({"mode":"software","expected_generation":started["generation"],"session_id":started["session_id"]}),&cookies,&csrf,None).await;
        assert_eq!(stopped.status(), StatusCode::OK);
        assert_eq!(value(stopped).await["state"], "switching");
        let rollback = output.try_recv().unwrap();
        app.broker
            .lock()
            .await
            .on_message(mode_ack(&rollback), &[])
            .unwrap();
        let newer = enter_native(&app, &cookies, &csrf, &mut output).await;
        assert_ne!(newer["session_id"], started["session_id"]);
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
            StatusCode::CONFLICT
        );
        assert_eq!(call(&app,"POST","/api/browser/mode",json!({"mode":"software","expected_generation":started["generation"],"session_id":newer["session_id"]}),&cookies,&csrf,None).await.status(),StatusCode::CONFLICT);
        assert!(app.broker.lock().await.native_qr_mode);
        assert!(output.try_recv().is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn idle_mode_renewal_waits_for_bound_extension_ack_without_changing_mode_or_token() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let started = enter_native(&app, &cookies, &csrf, &mut output).await;
        let before = app.broker.lock().await.helper.as_ref().unwrap().deadline;
        let pending = spawn_renew(&app, &cookies, &csrf, &started);
        let command = output.recv().await.unwrap();
        assert_eq!(command["type"], "mode_lease");
        assert_eq!(command["generation"], started["generation"]);
        assert!(!pending.is_finished());
        let mut broker = app.broker.lock().await;
        assert_eq!(broker.helper.as_ref().unwrap().deadline, before);
        assert!(broker.native_qr_mode && broker.mode_pending.is_none());
        let ack = lease_ack(&command);
        for (field, bad) in [
            ("generation", json!(999)),
            ("leaseGeneration", json!(0)),
            ("attached", json!(true)),
            ("extensionVersion", json!("1.0.28")),
            ("protocolVersion", json!(2)),
        ] {
            let mut malformed = ack.clone();
            malformed[field] = bad;
            assert!(broker.on_message(malformed, &[]).is_err());
        }
        broker.on_message(ack.clone(), &[]).unwrap();
        assert!(broker.on_message(ack, &[]).is_err());
        assert_eq!(
            broker.helper.as_ref().unwrap().token,
            started["token"].as_str().unwrap()
        );
        assert!(broker.helper.as_ref().unwrap().deadline >= before);
        assert!(broker.public_requests().is_empty());
        drop(broker);
        let response = pending.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let renewed = value(response).await;
        assert_eq!(renewed["generation"], started["generation"]);
        assert_eq!(renewed["state"], "native");
        assert!(renewed.get("token").is_none() && renewed.get("session_id").is_none());
        assert!(
            output.try_recv().is_err(),
            "renew must not detach/attach or replay ceremonies"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn renewal_is_capped_by_original_owner_auth_and_csrf_expiry() {
        let (app, dir) = app();
        let (mut cookies, csrf, mut output) = proxy_fixture(&app).await;
        let cap = Instant::now() + Duration::from_secs(30);
        {
            let mut inner = app.inner.lock().await;
            inner.store.data.vnc_password_hash = Some("enabled".into());
            inner.sessions.insert(
                "owner".into(),
                Session {
                    scope: "vnc".into(),
                    epoch: 0,
                    expires: cap + Duration::from_secs(20),
                },
            );
            inner.csrf.insert(csrf.clone(), cap);
        }
        cookies.push_str("; ab_vnc=owner");
        let started = enter_native(&app, &cookies, &csrf, &mut output).await;
        assert_eq!(
            app.broker.lock().await.helper.as_ref().unwrap().deadline,
            cap
        );
        let pending = spawn_renew(&app, &cookies, &csrf, &started);
        let command = output.recv().await.unwrap();
        assert!(command["leaseRemainingMs"].as_u64().unwrap() <= 30000);
        app.broker
            .lock()
            .await
            .on_message(lease_ack(&command), &[])
            .unwrap();
        assert_eq!(pending.await.unwrap().status(), StatusCode::OK);
        assert_eq!(
            app.broker.lock().await.helper.as_ref().unwrap().deadline,
            cap
        );
        // Revocation cannot be repaired by keepalive or a still-valid CSRF token.
        app.inner.lock().await.sessions.remove("owner");
        assert_eq!(
            spawn_renew(&app, &cookies, &csrf, &started)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(app.broker.lock().await.helper.is_none());
        assert_eq!(output.try_recv().unwrap()["mode"], "proxy");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn renewal_stop_disconnect_and_owner_expiry_never_restore_authorization() {
        for reason in ["stop", "disconnect", "expiry"] {
            let (app, dir) = app();
            let (cookies, csrf, mut output) = proxy_fixture(&app).await;
            let started = enter_native(&app, &cookies, &csrf, &mut output).await;
            let pending = spawn_renew(&app, &cookies, &csrf, &started);
            let command = output.recv().await.unwrap();
            let mut broker = app.broker.lock().await;
            match reason {
                "stop" => broker.stop_helper(),
                "disconnect" => broker.disconnected(),
                _ => {
                    broker.helper.as_mut().unwrap().deadline = Instant::now();
                    broker.expire();
                }
            }
            assert!(broker.on_message(lease_ack(&command), &[]).is_err());
            assert!(broker.helper.is_none() && !broker.native_qr_mode);
            drop(broker);
            assert_eq!(pending.await.unwrap().status(), StatusCode::CONFLICT);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn mode_and_renew_require_auth_csrf_exact_generation_and_owner_capability() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let generation = app.broker.lock().await.mode_generation;
        let input = json!({"mode":"native","expected_generation":generation});
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/browser/mode",
                input.clone(),
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
                "/api/browser/mode",
                json!({"mode":"native"}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let started = enter_native(&app, &cookies, &csrf, &mut output).await;
        let renewal =
            json!({"session_id":started["session_id"],"expected_generation":started["generation"]});
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/browser/mode/renew",
                renewal.clone(),
                &cookies,
                "",
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let other = value(call(&app, "GET", "/api/status", Value::Null, "", "", None).await).await;
        let other_csrf = other["csrf_token"].as_str().unwrap();
        let other_cookie = format!("ab_csrf={other_csrf}");
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/browser/mode/renew",
                renewal,
                &other_cookie,
                other_csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        for body in [
            json!({"session_id":"wrong","expected_generation":started["generation"]}),
            json!({"session_id":started["session_id"],"expected_generation":generation}),
        ] {
            assert_eq!(
                call(
                    &app,
                    "POST",
                    "/api/browser/mode/renew",
                    body,
                    &cookies,
                    &csrf,
                    None
                )
                .await
                .status(),
                StatusCode::CONFLICT
            );
        }
        assert!(output.try_recv().is_err());
        app.inner.lock().await.store.data.vnc_password_hash = Some("protected".into());
        assert_eq!(
            call(
                &app,
                "GET",
                "/api/browser/mode",
                Value::Null,
                &cookies,
                "",
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(app.broker.lock().await.helper.is_none());
        assert_eq!(output.try_recv().unwrap()["mode"], "proxy");
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/browser/mode",
                input,
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

    #[tokio::test]
    async fn missing_lease_ack_revokes_once_and_never_reports_renewal_success() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let started = enter_native(&app, &cookies, &csrf, &mut output).await;
        let pending = spawn_renew(&app, &cookies, &csrf, &started);
        let command = output.recv().await.unwrap();
        assert_eq!(command["type"], "mode_lease");
        let response = tokio::time::timeout(Duration::from_secs(7), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let rollback = output.try_recv().unwrap();
        assert_eq!(rollback["mode"], "proxy");
        let mut broker = app.broker.lock().await;
        assert!(broker.helper.is_none() && !broker.native_qr_mode);
        assert_eq!(broker.mode_error.as_deref(), Some("native_lease_timeout"));
        assert!(broker.on_message(lease_ack(&command), &[]).is_err());
        for _ in 0..10 {
            broker.expire();
        }
        assert!(output.try_recv().is_err());
        broker.on_message(mode_ack(&rollback), &[]).unwrap();
        assert!(broker.ready && broker.mode_error.is_none());
        drop(broker);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn acknowledged_renewal_succeeds_when_newer_lease_is_pending_or_acknowledged() {
        for acknowledge_second in [false, true] {
            let (app, dir) = app();
            let (cookies, csrf, mut output) = proxy_fixture(&app).await;
            let started = enter_native(&app, &cookies, &csrf, &mut output).await;
            let pending = spawn_renew(&app, &cookies, &csrf, &started);
            let first = output.recv().await.unwrap();
            let second = {
                // Hold the broker across ACK1 and lease2, so HTTP1 cannot observe
                // ACK1 before lease2 is pending (or has itself been acknowledged).
                let mut broker = app.broker.lock().await;
                broker.on_message(lease_ack(&first), &[]).unwrap();
                assert_eq!(
                    broker.renew_native_lease(Instant::now() + Duration::from_secs(120)),
                    Some(2)
                );
                let second = output.try_recv().unwrap();
                if acknowledge_second {
                    broker.on_message(lease_ack(&second), &[]).unwrap();
                }
                second
            };
            assert_eq!(second["leaseGeneration"], 2);
            let response = tokio::time::timeout(Duration::from_secs(1), pending)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let mut broker = app.broker.lock().await;
            assert!(broker.native_qr_mode && broker.helper.is_some());
            if !acknowledge_second {
                broker.on_message(lease_ack(&second), &[]).unwrap();
            }
            assert_eq!(broker.lease_generation, 2);
            drop(broker);
            assert!(output.try_recv().is_err());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn extension_local_lease_fallback_invalidates_pending_renewal_and_mode_cas() {
        let (app, dir) = app();
        let (cookies, csrf, mut output) = proxy_fixture(&app).await;
        let started = enter_native(&app, &cookies, &csrf, &mut output).await;
        let pending = spawn_renew(&app, &cookies, &csrf, &started);
        let command = output.recv().await.unwrap();
        {
            let mut broker = app.broker.lock().await;
            broker
                .on_message(
                    crate::browser::broker::tests::test_ready("proxy", true, 0),
                    &[],
                )
                .unwrap();
            assert!(broker.ready && broker.helper.is_none());
            assert_ne!(
                broker.mode_generation,
                started["generation"].as_u64().unwrap()
            );
            assert_eq!(
                broker.on_message(lease_ack(&command), &[]).unwrap_err(),
                "No native lease renewal pending"
            );
            assert!(broker.mode_error.is_none());
        }
        assert_eq!(pending.await.unwrap().status(), StatusCode::CONFLICT);
        assert!(
            output.try_recv().is_err(),
            "truthfully restored software mode needs no duplicate rollback"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
