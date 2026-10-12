//! Loopback HTTP controls and guarded WebSocket upgrade routes.
use crate::pairing::{
    authorization::refuse_current,
    connection::connection,
    protocol::{
        random_secret, secret_eq, valid_origin, valid_token, Approval, LIFETIME, MAX_FRAME,
    },
    state::{App, BleState, Pairing},
};
use axum::{
    extract::{
        ws::{rejection::WebSocketUpgradeRejection, WebSocketUpgrade},
        DefaultBodyLimit, State,
    },
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::time::Instant;
async fn protections(State(app): State<App>, req: axum::extract::Request, next: Next) -> Response {
    if header(req.headers(), "host") != Some(format!("127.0.0.1:{}", app.port).as_str()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut response = next.run(req).await;
    for (key,value) in [("cache-control","no-store"),("x-content-type-options","nosniff"),("referrer-policy","no-referrer"),("content-security-policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")] { response.headers_mut().insert(axum::http::HeaderName::from_static(key), value.parse().unwrap()); }
    response
}
pub(crate) fn router(app: App) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/api/status", get(status))
        .route("/api/approve", post(approve))
        .route("/api/start", post(start))
        .route("/api/stop", post(stop))
        .route("/api/revoke", post(revoke))
        .route("/bridge", get(bridge))
        .layer(DefaultBodyLimit::max(MAX_FRAME))
        .layer(middleware::from_fn_with_state(app.clone(), protections))
        .with_state(app)
}
async fn root(
    State(app): State<App>,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    match ws {
        Ok(ws) => bridge(State(app), headers, ws).await,
        Err(error)
            if headers.contains_key("upgrade") || headers.contains_key("sec-websocket-key") =>
        {
            error.into_response()
        }
        Err(_) => "WebAuthn Helper bridge. Use CLI or Desktop controls.".into_response(),
    }
}
async fn status(State(app): State<App>, headers: HeaderMap) -> Response {
    if !ui_authorized(&headers, &app, false) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let inner = app.inner.lock().await;
    Json(json!({"port":app.port,"needs_restart":inner.cleanup_failed,"status":inner.status,"connected":inner.connected,"scanning":inner.ble_state == BleState::Scanning,"advertisements":inner.count,"origin":inner.pairing.as_ref().map(|p|p.origin.as_str()),"expires_in":inner.pairing.as_ref().map(|p|p.expires.saturating_duration_since(Instant::now()).as_secs())})).into_response()
}
pub(super) async fn approve(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Approval>,
) -> Response {
    if !ui_authorized(&headers, &app, true) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !valid_origin(&input.origin) || !valid_token(&input.token) {
        return (StatusCode::BAD_REQUEST,"Enter an exact HTTP(S) origin without a trailing slash and a 32–128 character pairing token.").into_response();
    }
    let mut inner = app.inner.lock().await;
    if inner.stopping || inner.connected || inner.cleanup_failed {
        return (
            StatusCode::CONFLICT,
            "Disconnect the existing bridge first.",
        )
            .into_response();
    }
    // This capability-authenticated local control is itself a fresh explicit
    // approval. Browser retry/refresh routes never reach this reset.
    if let Err(error) = app.session.allow_pairing_again(&input.origin) {
        return (StatusCode::CONFLICT, error.to_string()).into_response();
    }
    inner.fido = None;
    inner.pairing = Some(Pairing {
        explicit_approval: true,
        request_id: None,
        session_id: None,
        origin: input.origin,
        token: Some(input.token),
        expires: Instant::now() + LIFETIME,
    });
    inner.status = "Approved. Connect from the outer webpage, then press Start here.".into();
    inner.count = 0;
    StatusCode::NO_CONTENT.into_response()
}
pub(super) async fn start(State(app): State<App>, headers: HeaderMap) -> Response {
    if !ui_authorized(&headers, &app, true) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut inner = app.inner.lock().await;
    if inner.stopping
        || inner.cleanup_failed
        || !inner.connected
        || inner
            .pairing
            .as_ref()
            .is_none_or(|p| p.expires <= Instant::now())
    {
        return (
            StatusCode::CONFLICT,
            "Connect an approved, unexpired webpage first.",
        )
            .into_response();
    }
    if !inner.ble_enabled {
        return (StatusCode::CONFLICT, "BLE is disabled locally.").into_response();
    }
    if let Some(tx) = &inner.scan {
        if *tx.borrow() {
            return StatusCode::NO_CONTENT.into_response();
        }
        let _ = tx.send(true);
        inner.ble_state = BleState::Starting;
    }
    inner.status = "Starting Bluetooth scan…".into();
    StatusCode::NO_CONTENT.into_response()
}
pub(super) async fn stop(State(app): State<App>, headers: HeaderMap) -> Response {
    if !ui_authorized(&headers, &app, true) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut inner = app.inner.lock().await;
    refuse_current(&app.session, &inner);
    inner.fido = None;
    inner.epoch = inner.epoch.wrapping_add(1);
    inner.pairing = None;
    inner.pending = None;
    if let Some(tx) = &inner.scan {
        let _ = tx.send(false);
    }
    if !inner.cleanup_failed {
        if matches!(inner.ble_state, BleState::Starting | BleState::Scanning) {
            inner.ble_state = BleState::Stopping;
        }
        inner.status = "Stopping Bluetooth scan…".into();
    }
    StatusCode::NO_CONTENT.into_response()
}
pub(super) async fn revoke(State(app): State<App>, headers: HeaderMap) -> Response {
    if !ui_authorized(&headers, &app, true) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut inner = app.inner.lock().await;
    app.session.revoke_approved();
    refuse_current(&app.session, &inner);
    inner.fido = None;
    inner.epoch = inner.epoch.wrapping_add(1);
    inner.pairing = None;
    inner.pending = None;
    if let Some(tx) = &inner.scan {
        let _ = tx.send(false);
    }
    if !inner.cleanup_failed {
        inner.status = "Pairing revoked. Stopping Bluetooth…".into();
    }
    StatusCode::NO_CONTENT.into_response()
}
async fn bridge(State(app): State<App>, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    let Some(origin) = header(&headers, "origin")
        .filter(|origin| valid_origin(origin))
        .map(str::to_owned)
    else {
        return StatusCode::FORBIDDEN.into_response();
    };
    // Bound incomplete upgrades/first-frame waits separately from the single candidate. A mere
    // availability probe gets no approval prompt and cannot start Bluetooth.
    let Ok(slot) = app.connection_slot.clone().try_acquire_owned() else {
        return StatusCode::CONFLICT.into_response();
    };
    let epoch = {
        let inner = app.inner.lock().await;
        let preapproved = inner
            .pairing
            .as_ref()
            .is_some_and(|p| p.origin == origin && p.token.is_some() && p.expires > Instant::now());
        if inner.connected
            || inner.stopping
            || inner.cleanup_failed
            || (!preapproved
                && !(app.incoming_pairing && inner.pairing.is_none() && inner.pending.is_none()))
        {
            return StatusCode::FORBIDDEN.into_response();
        }
        inner.epoch
    };
    let request_id = random_secret();
    ws.max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .on_upgrade(move |socket| async move {
            let _slot = slot;
            connection(app.clone(), socket, origin, &request_id, epoch).await;
            let mut inner = app.inner.lock().await;
            if inner
                .pending
                .as_ref()
                .is_some_and(|pending| pending.id == request_id)
            {
                inner.pending = None;
                inner.epoch = inner.epoch.wrapping_add(1);
            }
        })
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name)?.to_str().ok()
}
fn ui_authorized(h: &HeaderMap, app: &App, mutation: bool) -> bool {
    header(h, "authorization").is_some_and(|v| {
        v.strip_prefix("Bearer ")
            .is_some_and(|s| secret_eq(s, &app.secret))
    }) && (!mutation
        || header(h, "origin") == Some(format!("http://127.0.0.1:{}", app.port).as_str()))
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::testing::app;

    use axum::http::StatusCode;
    use serde_json::json;

    use tower::ServiceExt;

    #[tokio::test]
    async fn rejects_dns_rebinding() {
        let res = router(app())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .header("host", "evil.example:10233")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn root_keeps_http_description_and_rejects_malformed_upgrade() {
        let request = || {
            axum::http::Request::builder()
                .uri("/")
                .header("host", ADDRESS)
        };
        let response = router(app())
            .oneshot(request().body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        assert_eq!(
            body.as_ref(),
            b"WebAuthn Helper bridge. Use CLI or Desktop controls."
        );
        let response = router(app())
            .oneshot(
                request()
                    .header("upgrade", "websocket")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_client_error());
    }

    #[tokio::test]
    async fn api_requires_capability() {
        let res = router(app())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/status")
                    .header("host", ADDRESS)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn mutation_requires_local_origin() {
        let res = router(app())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/stop")
                    .header("host", ADDRESS)
                    .header("authorization", "Bearer test-secret")
                    .header("origin", "https://evil.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn approval_does_not_start_bluetooth() {
        let a = app();
        let res = router(a.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/approve")
                    .header("host", ADDRESS)
                    .header("origin", LOCAL_ORIGIN)
                    .header("authorization", "Bearer test-secret")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        json!({"origin":"https://example.com","token":"a".repeat(43)}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let i = a.inner.lock().await;
        assert!(!i.connected);
        assert!(i.scan.is_none());
        assert!(i.pairing.is_some());
    }

    #[tokio::test]
    async fn custom_port_host_and_origin_are_exact() {
        let mut a = app();
        a.port = 21863;
        let res = router(a.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .header("host", "127.0.0.1:21863")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let res = router(a)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/stop")
                    .header("host", "127.0.0.1:21863")
                    .header("origin", LOCAL_ORIGIN)
                    .header("authorization", "Bearer test-secret")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    const ADDRESS: &str = "127.0.0.1:10233";
    const LOCAL_ORIGIN: &str = "http://127.0.0.1:10233";
}
