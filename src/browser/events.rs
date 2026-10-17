//! Bounded event-stream subscriptions with authorization and revocation checks.
use crate::{
    app::App,
    auth::{authenticated, authorize, csrf},
    browser::{
        local_navigation::{wall_time_ms, Notification},
        requests::decorate_requests,
    },
    http::error::fail,
};
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use std::time::Duration;
use tokio::sync::{broadcast, watch};

struct StreamLease(tokio::task::JoinHandle<()>);
impl Drop for StreamLease {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct EventStream {
    app: App,
    headers: HeaderMap,
    epoch: u64,
    pulse: watch::Receiver<Option<u64>>,
    navigation: broadcast::Receiver<Notification>,
    subscribed_at_ms: u64,
    _lease: StreamLease,
    cursor: Option<String>,
    first: bool,
}
pub(crate) async fn request_events(
    State(app): State<App>,
    h: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    // Unlike EventSource, fetch can supply the CSRF token in a header: no token
    // in the URL, access log, browser history, or event payload.
    let i = app.inner.lock().await;
    authorize(&i, &h, "vnc")?;
    csrf(&i, &h)?;
    let epoch = crate::auth::vnc_epoch(&i, &h);
    drop(i);
    let cursor = h
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 80)
        .map(str::to_owned);
    let permit = app
        .stream_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| fail(StatusCode::TOO_MANY_REQUESTS, "Too many approval streams"))?;
    // Subscribe before bootstrap, under the broker lock: an already queued
    // observation and Last-Event-ID can never seed a fresh navigation stream.
    let (mut changes, navigation, subscribed_at_ms) = {
        let broker = app.broker.lock().await;
        let inner = app.inner.lock().await;
        if crate::auth::vnc_epoch(&inner, &h) != epoch {
            return Err(fail(StatusCode::UNAUTHORIZED, "Browser session changed"));
        }
        authorize(&inner, &h, "vnc")?;
        csrf(&inner, &h)?;
        (
            broker.subscribe(),
            broker.subscribe_navigation(),
            // Date.now observations have millisecond precision. Discard the
            // ambiguous admission millisecond rather than leak an observation
            // detected immediately before this viewer subscribed.
            wall_time_ms().saturating_add(1),
        )
    };
    let mut revoked = app.revoked.subscribe();
    let (pulse_tx, pulse) = watch::channel(Some(0_u64));
    let lease_app = app.clone();
    let lease_headers = h.clone();
    // A separate lease task releases the broker subscription and capacity even
    // when a slow reader stops polling the HTTP body. Already transmitted bytes
    // cannot be retracted; every later body poll rechecks auth before serialization.
    let lease = tokio::spawn(async move {
        let _permit = permit;
        loop {
            {
                let i = lease_app.inner.lock().await;
                if crate::auth::vnc_epoch(&i, &lease_headers) != epoch
                    || !authenticated(&i, &lease_headers, "vnc")
                    || csrf(&i, &lease_headers).is_err()
                {
                    pulse_tx.send_replace(None);
                    return;
                }
            }
            tokio::select! {
                _ = pulse_tx.closed() => return,
                _ = revoked.changed() => {},
                _ = changes.changed() => {},
                _ = tokio::time::sleep(Duration::from_secs(15)) => {},
            }
            pulse_tx.send_modify(|v| {
                if let Some(seq) = v {
                    *seq = seq.wrapping_add(1);
                }
            });
        }
    });
    let state = EventStream {
        pulse,
        navigation,
        subscribed_at_ms,
        _lease: StreamLease(lease),
        app: app.clone(),
        headers: h,
        epoch,
        cursor,
        first: true,
    };
    let stream = futures_util::stream::unfold(state, |mut state| async move {
        loop {
            // The authoritative snapshot always comes first. Navigation frames
            // are independent live-only events, never appended to that snapshot.
            let notice = if state.first {
                state.first = false;
                state.pulse.borrow_and_update();
                None
            } else {
                tokio::select! {
                    biased;
                    result = state.pulse.changed() => {
                        if result.is_err() { return None; }
                        None
                    },
                    result = state.navigation.recv() => match result {
                        Ok(notice) => Some(notice),
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            // A stalled reader gets no surviving fragment of an
                            // old burst. Start at the tail without replay.
                            state.navigation = state.navigation.resubscribe();
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => return None,
                    },
                }
            };
            if state.pulse.borrow().is_none() {
                return None;
            }
            // Match the broker→inner order used by completion. Authentication
            // cannot be revoked between this check and frame serialization.
            let mut broker = state.app.broker.lock().await;
            let i = state.app.inner.lock().await;
            if crate::auth::vnc_epoch(&i, &state.headers) != state.epoch
                || !authenticated(&i, &state.headers, "vnc")
                || csrf(&i, &state.headers).is_err()
            {
                return None;
            }
            let frame = if let Some(notice) = notice {
                broker.navigation_frame(&notice, state.subscribed_at_ms)
            } else {
                let mut snapshot = broker.stream_snapshot(state.cursor.as_deref());
                decorate_requests(&mut snapshot, &i.store.data.keys);
                state.cursor = snapshot["cursor"].as_str().map(str::to_owned);
                Some(format!(
                    "id: {}\nevent: snapshot\ndata: {}\n\n",
                    state.cursor.as_deref().unwrap_or(""),
                    snapshot
                ))
            };
            drop(i);
            drop(broker);
            if let Some(frame) = frame {
                return Some((Ok::<_, std::convert::Infallible>(frame), state));
            }
        }
    });
    let mut response = Response::new(axum::body::Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::{App, Inner, Session},
        browser::broker::Broker,
        http::router,
        storage::{restore, store::Store},
    };
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHasher,
    };
    use axum::body::BodyDataStream;
    use axum::{
        body::Body,
        http::{header, HeaderMap, HeaderValue, Request, StatusCode},
        response::Response,
    };
    use futures_util::StreamExt;
    use serde_json::{json, Value};
    use std::{
        collections::HashMap,
        sync::Arc,
        time::{Duration, Instant},
    };
    use tokio::sync::{mpsc, watch, Mutex, Semaphore};
    use tower::ServiceExt;

    const VNC_TOKEN: &str = "stream-test-vnc-session";
    const SETTINGS_TOKEN: &str = "stream-test-settings-session";
    const CSRF_TOKEN: &str = "stream-test-csrf-token";
    const CAPACITY: usize = 4;

    struct Fixture {
        app: App,
        dir: std::path::PathBuf,
        _native: mpsc::UnboundedReceiver<Value>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    impl Fixture {
        async fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("stream-test-{}", uuid::Uuid::new_v4()));
            let mut store = Store::open(dir.join("store.json")).unwrap();
            store.data.vnc_password_hash = Some("VNC-HASH-SECRET".into());
            store.data.settings_password_hash = Some("SETTINGS-HASH-SECRET".into());
            store.data.keys.push(
                serde_json::from_value(json!({
                    "id":"usb", "name":"Software USB", "attachment":"cross-platform",
                    "pin_hash":"KEY-HASH-SECRET", "credentials":[{
                        "credentialId":"AQI=", "rpId":"example.test", "isResidentCredential":true,
                        "userHandle":"Aw==", "userName":"alice", "privateKey":"PRIVATE-KEY-SECRET"
                    }]
                }))
                .unwrap(),
            );
            let expires = Instant::now() + Duration::from_secs(3600);
            let sessions = [(VNC_TOKEN, "vnc"), (SETTINGS_TOKEN, "settings")]
                .into_iter()
                .map(|(token, scope)| {
                    (
                        token.into(),
                        Session {
                            scope: scope.into(),
                            epoch: 0,
                            expires,
                        },
                    )
                })
                .collect();
            let (revoked, _) = watch::channel(0);
            let (tx, native) = mpsc::unbounded_channel();
            let mut broker = Broker::default();
            broker.connected(tx);
            broker
                .on_message(
                    crate::browser::broker::tests::test_ready("proxy", true, 0),
                    &[],
                )
                .unwrap();
            Self {
                app: App {
                    profile_scope: false,
                    profile_name: None,
                    profile_id: std::sync::Arc::from("default"),
                    endpoints: std::sync::Arc::new(crate::profiles::runtime::Endpoints::legacy()),
                    profiles: None,
                    inner: Arc::new(Mutex::new(Inner {
                        profile_viewers: std::collections::HashMap::new(),
                        viewer_tickets: std::collections::HashMap::new(),
                        store,
                        sessions,
                        csrf: HashMap::from([(CSRF_TOKEN.into(), expires)]),
                        vnc_epoch: 0,
                        settings_epoch: 0,
                        engine_connected: true,
                        engine_message: String::new(),
                        attempts: HashMap::new(),
                    })),
                    broker: Arc::new(Mutex::new(broker)),
                    revoked,
                    operations: Arc::new(Mutex::new(())),
                    stream_slots: Arc::new(Semaphore::new(CAPACITY)),
                    restore: Arc::new(Mutex::new(restore::Pending::default())),
                    recovery_slots: Arc::new(Semaphore::new(1)),
                    window_control: Arc::new(crate::browser::window_control::Controller::default()),
                    fido_launcher: crate::relay::fido_launcher::Launcher::disabled(),
                },
                dir,
                _native: native,
            }
        }

        fn headers(&self) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert(header::HOST, HeaderValue::from_static("localhost:8080"));
            headers.insert(
                header::ORIGIN,
                HeaderValue::from_static("http://localhost:8080"),
            );
            headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
            headers.insert("x-csrf-token", HeaderValue::from_static(CSRF_TOKEN));
            headers.insert(
                header::COOKIE,
                HeaderValue::from_str(&format!(
                    "ab_csrf={CSRF_TOKEN}; ab_vnc={VNC_TOKEN}; ab_settings={SETTINGS_TOKEN}"
                ))
                .unwrap(),
            );
            headers
        }

        async fn get(&self, headers: HeaderMap) -> Response {
            self.call("GET", "/api/requests/events", headers, None)
                .await
        }

        async fn call(
            &self,
            method: &str,
            path: &str,
            headers: HeaderMap,
            body: Option<Value>,
        ) -> Response {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .body(body.map_or_else(Body::empty, |value| Body::from(value.to_string())))
                .unwrap();
            *request.headers_mut() = headers;
            request.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            router(self.app.clone()).oneshot(request).await.unwrap()
        }

        async fn pending(&self, native_id: i64) -> String {
            let keys = self.app.inner.lock().await.store.data.keys.clone();
            let options = json!({
                "rpId":"example.test", "challenge":"Q0hBTExFTkdFLVNFQ1JFVA",
                "userVerification":"required", "password":"REQUEST-PASSWORD-SECRET",
                "extensions":{"remoteDesktopClientOverride":{
                    "origin":"https://example.test", "sameOriginWithAncestors":true
                }}
            });
            let mut broker = self.app.broker.lock().await;
            broker.on_message(json!({"type":"get", "requestId":native_id, "requestDetailsJson":options.to_string()}), &keys).unwrap();
            broker.public_requests().last().unwrap()["id"]
                .as_str()
                .unwrap()
                .into()
        }

        async fn revoke(&self) {
            self.app.inner.lock().await.sessions.remove(VNC_TOKEN);
            self.app.revoked.send_modify(|v| *v += 1);
        }
    }

    async fn snapshot(body: &mut BodyDataStream) -> Value {
        let bytes = tokio::time::timeout(Duration::from_secs(2), body.next())
            .await
            .expect("stream must wake promptly")
            .expect("expected a snapshot")
            .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("\nevent: snapshot\n"));
        let data = text
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap();
        let value: Value = serde_json::from_str(data).unwrap();
        assert_eq!(
            text.lines().next().unwrap().strip_prefix("id: ").unwrap(),
            value["cursor"].as_str().unwrap()
        );
        value
    }

    async fn until_snapshot(body: &mut BodyDataStream, accept: impl Fn(&Value) -> bool) -> Value {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let value = snapshot(body).await;
                if accept(&value) {
                    return value;
                }
            }
        })
        .await
        .expect("authoritative update must arrive")
    }

    async fn wait_slots(app: &App, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while app.stream_slots.available_permits() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stream capacity must be released independently of body polls");
    }

    async fn eof(body: &mut BodyDataStream) {
        assert!(tokio::time::timeout(Duration::from_secs(2), body.next())
            .await
            .expect("revoked stream must close")
            .is_none());
    }

    #[tokio::test]
    async fn stream_requires_csrf_and_vnc_scope_without_host_admission() {
        let fixture = Fixture::new().await;
        for (name, value) in [
            ("host", "browser.example:9443"),
            ("origin", "https://public.example:9443"),
            ("sec-fetch-site", "cross-site"),
        ] {
            let mut headers = fixture.headers();
            headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_static(value),
            );
            let response = fixture.get(headers).await;
            assert_eq!(response.status(), StatusCode::OK, "{name}");
            drop(response);
            wait_slots(&fixture.app, CAPACITY).await;
        }
        for (name, value) in [("x-csrf-token", "incorrect-token")] {
            let mut headers = fixture.headers();
            headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_static(value),
            );
            assert_eq!(
                fixture.get(headers).await.status(),
                StatusCode::FORBIDDEN,
                "{name}"
            );
        }
        let mut headers = fixture.headers();
        headers.remove("x-csrf-token");
        assert_eq!(fixture.get(headers).await.status(), StatusCode::FORBIDDEN);
        let mut headers = fixture.headers();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "ab_csrf={CSRF_TOKEN}; ab_settings={SETTINGS_TOKEN}"
            ))
            .unwrap(),
        );
        assert_eq!(
            fixture.get(headers).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let mut headers = fixture.headers();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("ab_csrf={CSRF_TOKEN}; ab_vnc={VNC_TOKEN}")).unwrap(),
        );
        let response = fixture.get(headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/event-stream"
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["x-accel-buffering"], "no");
        drop(response);
        wait_slots(&fixture.app, CAPACITY).await;
    }

    #[tokio::test]
    async fn stream_snapshots_are_sanitized_and_claims_and_cancellation_wake_all_tabs() {
        let fixture = Fixture::new().await;
        let id = fixture.pending(1).await;
        let mut first = fixture
            .get(fixture.headers())
            .await
            .into_body()
            .into_data_stream();
        let mut second = fixture
            .get(fixture.headers())
            .await
            .into_body()
            .into_data_stream();
        for stream in [&mut first, &mut second] {
            let state = snapshot(stream).await;
            assert_eq!(state["requests"][0]["id"], id);
            assert_eq!(state["requests"][0]["candidates"][0]["user_name"], "alice");
            for forbidden in [
                "PRIVATE-KEY-SECRET",
                "KEY-HASH-SECRET",
                "VNC-HASH-SECRET",
                "SETTINGS-HASH-SECRET",
                "REQUEST-PASSWORD-SECRET",
                "Q0hBTExFTkdFLVNFQ1JFVA",
                CSRF_TOKEN,
                VNC_TOKEN,
                "requestDetailsJson",
                "pin_hash",
                "privateKey",
            ] {
                assert!(!state.to_string().contains(forbidden), "leaked {forbidden}");
            }
        }
        let claim = fixture.app.broker.lock().await.take_request(&id).unwrap();
        assert!(fixture.app.broker.lock().await.take_request(&id).is_none());
        for stream in [&mut first, &mut second] {
            let state = until_snapshot(stream, |v| {
                v["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["kind"] == "claimed")
            })
            .await;
            assert_eq!(state["requests"][0]["id"], id);
            assert_eq!(state["requests"][0]["busy"], true);
        }
        fixture
            .app
            .broker
            .lock()
            .await
            .on_message(json!({"type":"cancel", "requestId":1}), &[])
            .unwrap();
        assert!(!fixture
            .app
            .broker
            .lock()
            .await
            .finish(&claim, Ok(json!({}))));
        for stream in [&mut first, &mut second] {
            let state = until_snapshot(stream, |v| {
                v["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["kind"] == "canceled")
            })
            .await;
            assert!(state["requests"].as_array().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn stream_reconnects_with_cursor_and_resynchronizes_stale_history() {
        let fixture = Fixture::new().await;
        let mut stream = fixture
            .get(fixture.headers())
            .await
            .into_body()
            .into_data_stream();
        let initial = snapshot(&mut stream).await;
        let cursor = initial["cursor"].as_str().unwrap().to_owned();
        drop(stream);
        let id = fixture.pending(7).await;
        let mut headers = fixture.headers();
        headers.insert("last-event-id", HeaderValue::from_str(&cursor).unwrap());
        let mut stream = fixture.get(headers).await.into_body().into_data_stream();
        let next = snapshot(&mut stream).await;
        assert_eq!(next["resync"], false);
        assert_eq!(next["requests"][0]["id"], id);
        assert!(next["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "pending" && e["request_id"] == id));
        drop(stream);
        // More than the 128-entry journal, with no unbounded live request backlog.
        for native_id in 100..170 {
            fixture.pending(native_id).await;
            fixture
                .app
                .broker
                .lock()
                .await
                .on_message(json!({"type":"cancel", "requestId":native_id}), &[])
                .unwrap();
        }
        for stale in [
            cursor,
            "different-instance:1".into(),
            "malformed".into(),
            format!(
                "{}:18446744073709551615",
                next["cursor"].as_str().unwrap().rsplit_once(':').unwrap().0
            ),
        ] {
            let mut headers = fixture.headers();
            headers.insert("last-event-id", HeaderValue::from_str(&stale).unwrap());
            let mut stream = fixture.get(headers).await.into_body().into_data_stream();
            let state = snapshot(&mut stream).await;
            assert_eq!(state["resync"], true);
            assert!(state["events"].as_array().unwrap().is_empty());
            assert_eq!(state["requests"][0]["id"], id);
            drop(stream);
            wait_slots(&fixture.app, CAPACITY).await;
        }
    }

    #[tokio::test]
    async fn stalled_streams_release_capacity_on_revoke_and_drop() {
        let fixture = Fixture::new().await;
        let mut bodies = Vec::new();
        for _ in 0..CAPACITY {
            let response = fixture.get(fixture.headers()).await;
            assert_eq!(response.status(), StatusCode::OK);
            bodies.push(response.into_body().into_data_stream());
        }
        assert_eq!(
            fixture.get(fixture.headers()).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        drop(bodies.pop());
        wait_slots(&fixture.app, 1).await;
        fixture.revoke().await;
        // No body was polled: revocation must still terminate the independent leases.
        wait_slots(&fixture.app, CAPACITY).await;
        for body in &mut bodies {
            eof(body).await;
        }
    }

    #[tokio::test]
    async fn stream_session_expiry_csrf_expiry_and_epoch_rotation_fail_closed() {
        for mode in ["session", "csrf", "epoch"] {
            let fixture = Fixture::new().await;
            let mut body = fixture
                .get(fixture.headers())
                .await
                .into_body()
                .into_data_stream();
            snapshot(&mut body).await;
            {
                let mut inner = fixture.app.inner.lock().await;
                match mode {
                    "session" => {
                        inner.sessions.get_mut(VNC_TOKEN).unwrap().expires = Instant::now()
                    }
                    "csrf" => *inner.csrf.get_mut(CSRF_TOKEN).unwrap() = Instant::now(),
                    "epoch" => inner.vnc_epoch += 1,
                    _ => unreachable!(),
                }
            }
            fixture.app.revoked.send_modify(|v| *v += 1);
            wait_slots(&fixture.app, CAPACITY).await;
            eof(&mut body).await;
        }
    }

    #[tokio::test]
    async fn settings_logout_does_not_revoke_vnc_stream_but_vnc_logout_does() {
        let fixture = Fixture::new().await;
        let mut body = fixture
            .get(fixture.headers())
            .await
            .into_body()
            .into_data_stream();
        snapshot(&mut body).await;
        let response = fixture
            .call(
                "POST",
                "/api/logout",
                fixture.headers(),
                Some(json!({"scope":"settings"})),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let id = fixture.pending(1).await;
        until_snapshot(&mut body, |v| {
            v["requests"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["id"] == id)
        })
        .await;
        let response = fixture
            .call(
                "POST",
                "/api/logout",
                fixture.headers(),
                Some(json!({"scope":"vnc"})),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        wait_slots(&fixture.app, CAPACITY).await;
        eof(&mut body).await;
    }

    #[tokio::test]
    async fn unauthorized_logout_cannot_cancel_requests() {
        let fixture = Fixture::new().await;
        let id = fixture.pending(1).await;
        let mut headers = fixture.headers();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("ab_csrf={CSRF_TOKEN}")).unwrap(),
        );
        let response = fixture
            .call("POST", "/api/logout", headers, Some(json!({"scope":"vnc"})))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            fixture.app.broker.lock().await.public_requests()[0]["id"],
            id
        );
    }

    #[tokio::test]
    async fn stream_rechecks_auth_after_waiting_for_broker_lock() {
        let fixture = Fixture::new().await;
        fixture.pending(1).await;
        let mut body = fixture
            .get(fixture.headers())
            .await
            .into_body()
            .into_data_stream();
        let broker = fixture.app.broker.lock().await;
        let mut next = Box::pin(body.next());
        assert!(futures_util::poll!(next.as_mut()).is_pending());
        fixture.revoke().await;
        drop(broker);
        assert!(tokio::time::timeout(Duration::from_secs(2), next)
            .await
            .unwrap()
            .is_none());
        wait_slots(&fixture.app, CAPACITY).await;
    }

    #[tokio::test]
    async fn successful_login_rotation_closes_old_stream_in_protected_and_passwordless_modes() {
        let password = "stream-test-login-password";
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
        for enabled in [true, false] {
            let fixture = Fixture::new().await;
            fixture.app.inner.lock().await.store.data.vnc_password_hash =
                enabled.then(|| hash.clone());
            let mut old = fixture
                .get(fixture.headers())
                .await
                .into_body()
                .into_data_stream();
            snapshot(&mut old).await;
            let response = fixture
                .call(
                    "POST",
                    "/api/login",
                    fixture.headers(),
                    Some(json!({
                        "scope":"vnc", "password":password
                    })),
                )
                .await;
            assert_eq!(response.status(), StatusCode::OK);
            let new_cookie = response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            assert!(new_cookie.starts_with("ab_vnc="));
            assert_ne!(new_cookie, format!("ab_vnc={VNC_TOKEN}"));
            wait_slots(&fixture.app, CAPACITY).await;
            eof(&mut old).await;
            {
                let inner = fixture.app.inner.lock().await;
                assert!(!inner.sessions.contains_key(VNC_TOKEN));
                assert!(inner.sessions.contains_key(SETTINGS_TOKEN));
                assert!(authenticated(&inner, &fixture.headers(), "settings"));
            }
            let mut headers = fixture.headers();
            headers.insert(
                header::COOKIE,
                HeaderValue::from_str(&format!(
                    "ab_csrf={CSRF_TOKEN}; {new_cookie}; ab_settings={SETTINGS_TOKEN}"
                ))
                .unwrap(),
            );
            let response = fixture.get(headers).await;
            assert_eq!(response.status(), StatusCode::OK);
            let mut new = response.into_body().into_data_stream();
            assert_eq!(snapshot(&mut new).await["connected"], true);
            drop(new);
            wait_slots(&fixture.app, CAPACITY).await;
        }
    }

    #[tokio::test]
    async fn concurrent_http_approvals_cannot_replay_a_request() {
        let mut fixture = Fixture::new().await;
        fixture.app.inner.lock().await.store.data.keys[0].pin_hash = None;
        let keys = fixture.app.inner.lock().await.store.data.keys.clone();
        let options = json!({
            "rp":{"id":"example.test", "name":"Test"},
            "user":{"id":"dXNlcg", "name":"alice", "displayName":"Alice"},
            "challenge":"Q0hBTExFTkdFLVNFQ1JFVA", "pubKeyCredParams":[{"type":"public-key", "alg":-7}],
            "authenticatorSelection":{"residentKey":"required", "userVerification":"required"},
            "extensions":{"remoteDesktopClientOverride":{"origin":"https://example.test", "sameOriginWithAncestors":true}}
        });
        let id = {
            let mut broker = fixture.app.broker.lock().await;
            broker
                .on_message(
                    json!({"type":"create", "requestId":901, "requestDetailsJson":options.to_string()}),
                    &keys,
                )
                .unwrap();
            broker.public_requests()[0]["id"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        let path = format!("/api/requests/{id}/decision");
        for action in [
            json!({"action":"select", "key_id":"usb"}),
            json!({"action":"setup_password", "password":"one-use-key-password", "password_confirmation":"one-use-key-password"}),
            json!({"action":"verify_password", "password":"one-use-key-password"}),
        ] {
            assert_eq!(
                fixture
                    .call("POST", &path, fixture.headers(), Some(action))
                    .await
                    .status(),
                StatusCode::OK
            );
            assert!(fixture._native.try_recv().is_err());
        }
        let decision = json!({"action":"touch"});
        let (first, second) = tokio::join!(
            fixture.call("POST", &path, fixture.headers(), Some(decision.clone())),
            fixture.call("POST", &path, fixture.headers(), Some(decision.clone())),
        );
        let mut statuses = vec![first.status().as_u16(), second.status().as_u16()];
        statuses.sort_unstable();
        assert_eq!(statuses, vec![200, 409]);
        let result = fixture._native.try_recv().unwrap();
        assert_eq!(result["requestId"], 901);
        assert!(result["responseJson"].is_string());
        assert!(fixture._native.try_recv().is_err());
        let response = fixture
            .call("POST", &path, fixture.headers(), Some(decision))
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            fixture.app.inner.lock().await.store.data.keys[0]
                .credentials
                .len(),
            2
        );
        assert!(fixture._native.try_recv().is_err());
    }
    impl Fixture {
        async fn navigation_scope(&mut self) -> Value {
            let mut ready = crate::browser::broker::tests::test_ready("proxy", true, 0);
            ready["capabilities"]
                .as_array_mut()
                .unwrap()
                .push(json!("local_navigation"));
            self.app.broker.lock().await.on_message(ready, &[]).unwrap();
            let scope = self._native.try_recv().unwrap();
            assert_eq!(scope["type"], "navigation_scope");
            scope
        }

        async fn navigation(&self, scope: &Value, sequence: u64, url: Option<&str>) {
            // A browser's Date.now timestamp must fall strictly after admission.
            tokio::time::sleep(Duration::from_millis(2)).await;
            let mut value = json!({
                "type":if url.is_some() { "local_navigation" } else { "local_navigation_clear" },
                "scope":scope["scope"], "mode_generation":scope["mode_generation"],
                "sequence":sequence, "observed_at_ms":wall_time_ms(),
            });
            if let Some(url) = url {
                value["url"] = json!(url);
            }
            self.app.broker.lock().await.on_message(value, &[]).unwrap();
        }
    }

    async fn next_navigation(body: &mut BodyDataStream, kind: &str) -> Value {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let bytes = body.next().await.unwrap().unwrap();
                let text = std::str::from_utf8(&bytes).unwrap();
                if text.starts_with(&format!("event: {kind}\n")) {
                    assert!(!text.lines().any(|line| line.starts_with("id: ")));
                    return serde_json::from_str(
                        text.lines()
                            .find_map(|line| line.strip_prefix("data: "))
                            .unwrap(),
                    )
                    .unwrap();
                }
                assert!(text.contains("event: snapshot\n"));
                assert!(!text.contains("NAVIGATION-SECRET"));
            }
        })
        .await
        .expect("live navigation event must arrive")
    }

    #[tokio::test]
    async fn navigation_is_live_only_after_initial_snapshot_and_retains_exact_url() {
        let mut fixture = Fixture::new().await;
        let scope = fixture.navigation_scope().await;
        let secret =
            "http://localhost:3030/callback?code=NAVIGATION-SECRET%2f&state=one+two#fragment";
        fixture
            .navigation(&scope, 1, Some("http://localhost/BEFORE-SUBSCRIPTION"))
            .await;
        let mut body = fixture
            .get(fixture.headers())
            .await
            .into_body()
            .into_data_stream();
        fixture.navigation(&scope, 2, Some(secret)).await;
        let initial = snapshot(&mut body).await;
        assert!(!initial.to_string().contains("NAVIGATION-SECRET"));
        let notice = next_navigation(&mut body, "local_navigation").await;
        assert_eq!(notice["url"], secret);
        assert_eq!(notice["mode_generation"], scope["mode_generation"]);
        assert!(notice["remaining_ms"]
            .as_u64()
            .is_some_and(|ms| (1..=5000).contains(&ms)));
        let (instance, counter) = notice["id"].as_str().unwrap().rsplit_once(':').unwrap();
        assert!(uuid::Uuid::parse_str(instance).is_ok());
        assert_eq!(
            instance,
            initial["cursor"]
                .as_str()
                .unwrap()
                .rsplit_once(':')
                .unwrap()
                .0
        );
        assert_eq!(counter, "2");
        let cursor = initial["cursor"].as_str().unwrap().to_owned();
        drop(body);
        fixture
            .navigation(&scope, 3, Some("http://localhost/WHILE-DISCONNECTED"))
            .await;
        let mut headers = fixture.headers();
        headers.insert("last-event-id", HeaderValue::from_str(&cursor).unwrap());
        let mut reconnected = fixture.get(headers).await.into_body().into_data_stream();
        snapshot(&mut reconnected).await;
        fixture.navigation(&scope, 4, None).await;
        let clear = next_navigation(&mut reconnected, "local_navigation_clear").await;
        assert_eq!(clear, json!({"mode_generation":scope["mode_generation"]}));
        assert!(!fixture
            .app
            .broker
            .lock()
            .await
            .stream_snapshot(Some(&cursor))
            .to_string()
            .contains("NAVIGATION-SECRET"));
    }

    #[tokio::test]
    async fn queued_navigation_never_crosses_session_csrf_epoch_or_logout_revocation() {
        for mode in ["session", "csrf", "epoch", "logout"] {
            let mut fixture = Fixture::new().await;
            let scope = fixture.navigation_scope().await;
            let mut body = fixture
                .get(fixture.headers())
                .await
                .into_body()
                .into_data_stream();
            snapshot(&mut body).await;
            fixture
                .navigation(&scope, 1, Some("https://127.0.0.1/?code=NAVIGATION-SECRET"))
                .await;
            if mode == "logout" {
                let response = fixture
                    .call(
                        "POST",
                        "/api/logout",
                        fixture.headers(),
                        Some(json!({"scope":"vnc"})),
                    )
                    .await;
                assert_eq!(response.status(), StatusCode::OK);
            } else {
                let mut inner = fixture.app.inner.lock().await;
                match mode {
                    "session" => {
                        inner.sessions.get_mut(VNC_TOKEN).unwrap().expires = Instant::now()
                    }
                    "csrf" => *inner.csrf.get_mut(CSRF_TOKEN).unwrap() = Instant::now(),
                    "epoch" => inner.vnc_epoch += 1,
                    _ => unreachable!(),
                }
                fixture.app.revoked.send_modify(|v| *v += 1);
            }
            eof(&mut body).await;
            wait_slots(&fixture.app, CAPACITY).await;
        }
    }

    #[tokio::test]
    async fn navigation_auth_recheck_occurs_after_waiting_for_broker_lock() {
        let mut fixture = Fixture::new().await;
        let scope = fixture.navigation_scope().await;
        let mut body = fixture
            .get(fixture.headers())
            .await
            .into_body()
            .into_data_stream();
        snapshot(&mut body).await;
        fixture
            .navigation(&scope, 1, Some("http://localhost/?code=NAVIGATION-SECRET"))
            .await;
        let broker = fixture.app.broker.lock().await;
        let mut next = Box::pin(body.next());
        assert!(futures_util::poll!(next.as_mut()).is_pending());
        fixture.revoke().await;
        drop(broker);
        assert!(tokio::time::timeout(Duration::from_secs(2), next)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn navigation_queued_before_control_loss_or_newer_clear_is_discarded() {
        let mut fixture = Fixture::new().await;
        let scope = fixture.navigation_scope().await;
        let mut body = fixture
            .get(fixture.headers())
            .await
            .into_body()
            .into_data_stream();
        snapshot(&mut body).await;
        fixture
            .navigation(&scope, 1, Some("http://localhost/?code=NAVIGATION-SECRET"))
            .await;
        fixture.navigation(&scope, 2, None).await;
        next_navigation(&mut body, "local_navigation_clear").await;
        fixture
            .navigation(&scope, 3, Some("http://localhost/?code=NAVIGATION-SECRET"))
            .await;
        let (tx, rx) = mpsc::unbounded_channel();
        fixture.app.broker.lock().await.connected(tx);
        fixture._native = rx;
        let fresh = fixture.navigation_scope().await;
        fixture.navigation(&fresh, 1, None).await;
        next_navigation(&mut body, "local_navigation_clear").await;
    }
    #[tokio::test]
    async fn navigation_subscription_rechecks_auth_after_waiting_for_broker_lock() {
        let fixture = Fixture::new().await;
        let broker = fixture.app.broker.lock().await;
        let mut response = Box::pin(fixture.get(fixture.headers()));
        assert!(futures_util::poll!(response.as_mut()).is_pending());
        fixture.revoke().await;
        drop(broker);
        assert_eq!(response.await.status(), StatusCode::UNAUTHORIZED);
        wait_slots(&fixture.app, CAPACITY).await;
    }

    #[tokio::test]
    async fn lagged_navigation_stream_discards_whole_burst_before_next_live_message() {
        let mut fixture = Fixture::new().await;
        let scope = fixture.navigation_scope().await;
        let mut body = fixture
            .get(fixture.headers())
            .await
            .into_body()
            .into_data_stream();
        snapshot(&mut body).await;
        for sequence in 1..=17 {
            fixture
                .navigation(
                    &scope,
                    sequence,
                    Some("http://localhost/?code=NAVIGATION-SECRET"),
                )
                .await;
        }
        let mut next = Box::pin(body.next());
        assert!(
            futures_util::poll!(next.as_mut()).is_pending(),
            "lagged burst must not emit its newest URL"
        );
        fixture.navigation(&scope, 18, None).await;
        let bytes = tokio::time::timeout(Duration::from_secs(2), next)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with("event: local_navigation_clear\n"));
        assert!(!text.contains("NAVIGATION-SECRET"));
    }

    #[tokio::test]
    async fn observations_detected_before_subscription_are_not_delivered_if_ingress_is_delayed() {
        let mut fixture = Fixture::new().await;
        let scope = fixture.navigation_scope().await;
        let observed_at_ms = wall_time_ms();
        let mut body = fixture
            .get(fixture.headers())
            .await
            .into_body()
            .into_data_stream();
        snapshot(&mut body).await;
        fixture.app.broker.lock().await.on_message(json!({
            "type":"local_navigation", "scope":scope["scope"],
            "mode_generation":scope["mode_generation"], "sequence":1,
            "observed_at_ms":observed_at_ms, "url":"http://localhost/?code=NAVIGATION-SECRET"
        }), &[]).unwrap();
        let mut next = Box::pin(body.next());
        assert!(futures_util::poll!(next.as_mut()).is_pending());
        fixture.navigation(&scope, 2, None).await;
        let bytes = tokio::time::timeout(Duration::from_secs(2), next)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(std::str::from_utf8(&bytes)
            .unwrap()
            .starts_with("event: local_navigation_clear\n"));
    }
    #[tokio::test]
    async fn queued_expired_navigation_is_discarded_without_timeout_clear() {
        let mut fixture = Fixture::new().await;
        let scope = fixture.navigation_scope().await;
        let mut body = fixture
            .get(fixture.headers())
            .await
            .into_body()
            .into_data_stream();
        snapshot(&mut body).await;
        let mut delivered = fixture
            .get(fixture.headers())
            .await
            .into_body()
            .into_data_stream();
        snapshot(&mut delivered).await;
        fixture
            .navigation(&scope, 1, Some("http://localhost/?code=NAVIGATION-SECRET"))
            .await;
        next_navigation(&mut delivered, "local_navigation").await;
        tokio::time::sleep(Duration::from_millis(5010)).await;
        fixture.app.broker.lock().await.expire();
        fixture.app.broker.lock().await.expire();
        let mut next = Box::pin(body.next());
        assert!(
            futures_util::poll!(next.as_mut()).is_pending(),
            "delivery expiry must silently discard old data without dismissing received toasts"
        );
        let mut displayed_next = Box::pin(delivered.next());
        assert!(
            futures_util::poll!(displayed_next.as_mut()).is_pending(),
            "timeout cannot clear the delivered toast"
        );
        // A new navigation still explicitly clears a delivered/hovered toast
        // after delivery expiry, even though the old URL is no longer retained.
        fixture.navigation(&scope, 2, None).await;
        for next in [next, displayed_next] {
            let bytes = tokio::time::timeout(Duration::from_secs(2), next)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(text.starts_with("event: local_navigation_clear\n"));
            assert!(!text.contains("NAVIGATION-SECRET"));
        }
        fixture
            .navigation(&scope, 3, Some("http://localhost/new"))
            .await;
        for stream in [&mut body, &mut delivered] {
            assert_eq!(
                next_navigation(stream, "local_navigation").await["url"],
                "http://localhost/new"
            );
        }
    }
}
