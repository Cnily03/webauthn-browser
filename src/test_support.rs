//! Explicit shared test fixtures; this module has no production role or reexports.
use crate::{
    app::{App, Inner},
    authenticator::cdp::{self, KeyConfig},
    browser::broker::Broker,
    http::router,
    relay::fido_launcher,
    storage::{restore, store::Store},
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    response::Response,
};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc, watch, Mutex, Semaphore};
use tower::ServiceExt;

pub(crate) fn app() -> (App, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("webauthn-browser-test-{}", uuid::Uuid::new_v4()));
    let store = Store::open(dir.join("store.json")).unwrap();
    let (revoked, _) = watch::channel(0);
    (
        App {
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
                csrf: HashMap::new(),
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
            restore: Arc::new(Mutex::new(restore::Pending::default())),
            recovery_slots: Arc::new(Semaphore::new(1)),
            window_control: Arc::new(crate::browser::window_control::Controller::default()),
            fido_launcher: fido_launcher::Launcher::disabled(),
        },
        dir,
    )
}

pub(crate) async fn call(
    app: &App,
    method: &str,
    path: &str,
    body: Value,
    cookies: &str,
    csrf: &str,
    origin: Option<&str>,
) -> Response {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost:8080")
        .header("content-type", "application/json");
    if !cookies.is_empty() {
        req = req.header("cookie", cookies)
    }
    if !csrf.is_empty() {
        req = req.header("x-csrf-token", csrf)
    }
    if let Some(origin) = origin {
        req = req.header("origin", origin)
    }
    router(app.clone())
        .oneshot(
            req.body(if method == "GET" {
                Body::empty()
            } else {
                Body::from(body.to_string())
            })
            .unwrap(),
        )
        .await
        .unwrap()
}

pub(crate) async fn value(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap()
}

pub(crate) async fn step(app: &App, id: &str, body: Value, cookies: &str, csrf: &str) -> Response {
    call(
        app,
        "POST",
        &format!("/api/requests/{id}/decision"),
        body,
        cookies,
        csrf,
        None,
    )
    .await
}

pub(crate) async fn select_key(app: &App, id: &str, cookies: &str, csrf: &str) {
    assert_eq!(
        step(
            app,
            id,
            json!({"action":"select","key_id":"usb"}),
            cookies,
            csrf
        )
        .await
        .status(),
        StatusCode::OK
    );
}

pub(crate) async fn proxy_fixture(app: &App) -> (String, String, mpsc::UnboundedReceiver<Value>) {
    let status = value(call(app, "GET", "/api/status", Value::Null, "", "", None).await).await;
    let csrf = status["csrf_token"].as_str().unwrap().to_owned();
    let cookies = format!("ab_csrf={csrf}");
    let (tx, rx) = mpsc::unbounded_channel();
    let mut broker = app.broker.lock().await;
    broker.connected(tx);
    broker
        .on_message(
            crate::browser::broker::tests::test_ready("proxy", true, 0),
            &[],
        )
        .unwrap();
    drop(broker);
    for (id, attachment) in [("usb", "cross-platform"), ("device", "platform")] {
        app.inner.lock().await.store.data.keys.push(KeyConfig {
            id: id.into(),
            name: format!("Key {id}"),
            provider_label: cdp::DEFAULT_PROVIDER_LABEL.into(),
            attachment: attachment.into(),
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
        });
    }
    (cookies, csrf, rx)
}

pub(crate) async fn create_pending(app: &App, request_id: i64) -> String {
    create_pending_uv(app, request_id, "required").await
}

pub(crate) async fn create_pending_uv(app: &App, request_id: i64, uv: &str) -> String {
    let keys = app.inner.lock().await.store.data.keys.clone();
    let options = json!({"rp":{"id":"example.test","name":"Test"},"user":{"id":"dXNlcg","name":"test","displayName":"Test User"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"residentKey":"required","userVerification":uv},"extensions":{"remoteDesktopClientOverride":{"origin":"https://example.test","sameOriginWithAncestors":true}}});
    let mut broker = app.broker.lock().await;
    broker.on_message(json!({"type":"create","requestId":request_id,"requestDetailsJson":options.to_string()}), &keys).unwrap();
    broker.public_requests().last().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}
