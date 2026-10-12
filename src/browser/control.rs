//! Runtime readiness, explicit Chromium recovery and native-proxy event ingress.
use crate::{
    app::App,
    auth::{authorize, csrf},
    browser::window_control,
    http::error::{fail, ApiResult},
    relay::native_proxy,
};
use axum::{
    extract::{rejection::JsonRejection, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;

fn read_runtime(path: &std::path::Path) -> Value {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(|v| {
            matches!(
                v["state"].as_str(),
                Some("starting" | "ready" | "recovering" | "failed")
            )
        })
        .unwrap_or_else(|| json!({"state":"unknown", "message":"Runtime status unavailable."}))
}
pub(crate) async fn runtime(State(app): State<App>, headers: HeaderMap) -> ApiResult {
    authorize(&*app.inner.lock().await, &headers, "settings")?;
    Ok(Json(read_runtime(std::path::Path::new(
        "/data/run/runtime.json",
    ))))
}
pub(crate) async fn ready(State(app): State<App>) -> Response {
    let desktop = read_runtime(std::path::Path::new("/data/run/runtime.json"));
    let mut broker = app.broker.lock().await;
    broker.expire();
    if desktop["state"] == "ready"
        && (broker.ready || (broker.native_qr_mode && broker.outbound.is_some()))
    {
        (StatusCode::OK, "ready").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "desktop unavailable").into_response()
    }
}
pub(crate) async fn browser_operation_scope(
    State(app): State<App>,
    h: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    window_control::next_operation(app, h).await
}

pub(crate) async fn browser_reconnect(
    State(app): State<App>,
    h: HeaderMap,
    input: Result<Json<window_control::Input>, JsonRejection>,
) -> Result<Response, (StatusCode, String)> {
    {
        let inner = app.inner.lock().await;
        authorize(&inner, &h, "vnc")?;
        csrf(&inner, &h)?;
    }
    let Json(input) =
        input.map_err(|_| fail(StatusCode::BAD_REQUEST, "Invalid browser operation request"))?;
    window_control::handle(app, h, input).await
}

pub(crate) async fn start_proxy(app: App) -> anyhow::Result<()> {
    eprintln!(
        "[native-proxy] gateway build={}",
        native_proxy::BRIDGE_BUILD
    );
    let (tx, mut rx) = mpsc::unbounded_channel();
    let socket = std::env::var("AUTH_BROWSER_PROXY_SOCKET")
        .unwrap_or_else(|_| "/data/run/webauthn.sock".into());
    tokio::spawn(async move {
        native_proxy::listen_with_recovery(socket, tx).await;
    });
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_millis(250));
        loop {
            tokio::select! {
                event = rx.recv() => {
                    let Some(event) = event else { break };
                    let mut broker = app.broker.lock().await;
                    let keys = {
                        let inner = app.inner.lock().await;
                        broker.validate_helper_owner(&inner);
                        inner.store.data.keys.clone()
                    };
                    let mut recovery = None;
                    match event {
                        native_proxy::ProxyEvent::Connected { outbound } => broker.connected(outbound),
                        native_proxy::ProxyEvent::Disconnected => broker.disconnected(),
                        native_proxy::ProxyEvent::Message(message) => { let _ = broker.on_message(message, &keys); }
                        native_proxy::ProxyEvent::Recovering(message) => {
                            broker.disconnected();
                            recovery = Some(format!("{message}; reconnecting automatically"));
                        }
                    }
                    let ready = broker.ready;
                    drop(broker);
                    let mut i = app.inner.lock().await;
                    i.engine_connected = ready;
                    i.engine_message = recovery.unwrap_or_else(|| if ready { "Native WebAuthn proxy connected; software keys require request approval" } else { "Waiting for Chromium WebAuthn proxy; reconnecting automatically" }.into());
                }
                _ = timer.tick() => {
                    let mut broker = app.broker.lock().await;
                    let inner = app.inner.lock().await;
                    broker.validate_helper_owner(&inner);
                    broker.expire();
                }
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{app, call, proxy_fixture};

    use axum::http::StatusCode;

    use serde_json::{json, Value};

    #[test]
    fn runtime_status_handles_missing_corrupt_and_failed_state() {
        let path = std::env::temp_dir().join(format!("runtime-status-{}", uuid::Uuid::new_v4()));
        assert_eq!(read_runtime(&path)["state"], "unknown");
        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(read_runtime(&path)["state"], "unknown");
        std::fs::write(&path, br#"{"state":"failed","message":"namespace denied"}"#).unwrap();
        assert_eq!(read_runtime(&path)["message"], "namespace denied");
        std::fs::write(
            &path,
            br#"{"state":"recovering","message":"Window restored; engine reconnecting"}"#,
        )
        .unwrap();
        assert_eq!(read_runtime(&path)["state"], "recovering");
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn degraded_management_has_separate_readiness_and_protected_diagnostics() {
        let (app, dir) = app();
        assert_eq!(
            call(&app, "GET", "/healthz", Value::Null, "", "", None)
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            call(&app, "GET", "/readyz", Value::Null, "", "", None)
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            call(&app, "GET", "/api/runtime", Value::Null, "", "", None)
                .await
                .status(),
            StatusCode::OK
        );
        app.inner.lock().await.store.data.settings_password_hash = Some("enabled".into());
        assert_eq!(
            call(&app, "GET", "/api/runtime", Value::Null, "", "", None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, "GET", "/api/keys", Value::Null, "", "", None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, "GET", "/api/backup", Value::Null, "", "", None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn reconnect_requires_csrf_and_desktop_authorization() {
        let (app, dir) = app();
        let (cookies, csrf_token, _output) = proxy_fixture(&app).await;
        let operation = crate::test_support::value(
            call(
                &app,
                "GET",
                "/api/browser/reconnect",
                Value::Null,
                &cookies,
                &csrf_token,
                None,
            )
            .await,
        )
        .await;
        let request = json!({"action":"ensure","request_id":"9498c5e0-ce61-43b8-8d6e-26867f4ca575",
            "operation_scope":operation["operation_scope"],"operation_sequence":operation["operation_sequence"]});
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/browser/reconnect",
                request.clone(),
                &cookies,
                "",
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let slot = app.recovery_slots.acquire().await.unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/browser/reconnect",
                request.clone(),
                &cookies,
                &csrf_token,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        drop(slot);
        app.inner.lock().await.store.data.vnc_password_hash = Some("protected".into());
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/browser/reconnect",
                request.clone(),
                &cookies,
                &csrf_token,
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
                "/api/browser/reconnect",
                request.clone(),
                &cookies,
                &csrf_token,
                Some("https://proxy.example:9443")
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
