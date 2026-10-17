//! HTTP route composition. Domain handlers own their own authorization and logic.
pub(crate) mod assets;
pub(crate) mod downloads;
pub(crate) mod error;
mod middleware;
use crate::{
    app::App,
    auth,
    browser::{control, events, mode, native_client, requests},
    relay::{clipboard, desktop, fido_relay, helper},
    settings,
    storage::restore,
};
use axum::{
    middleware as axum_middleware,
    routing::{delete, get, patch, post},
    Router,
};
use tower_http::services::ServeDir;

/// Select only the inner route's identifier. Profile dispatch preserves outer
/// `name` and `path` captures, so positional/scalar extraction is not valid.
#[derive(serde::Deserialize)]
pub(crate) struct IdPath {
    pub(crate) id: String,
}

pub(crate) fn profile_router(app: App) -> Router {
    profile_router_with_novnc(app, ServeDir::new("/usr/share/novnc"))
}
fn profile_router_with_novnc(app: App, novnc: ServeDir) -> Router {
    let helper_routes = Router::new()
        .route("/stop", post(helper::stop))
        .route(
            "/refresh",
            post(helper::refresh).layer(axum::extract::DefaultBodyLimit::max(4096)),
        )
        .route("/status", get(helper::status))
        .route(
            "/fido/open",
            post(fido_relay::open).layer(axum::extract::DefaultBodyLimit::max(4096)),
        )
        .route(
            "/fido/renew",
            post(fido_relay::renew).layer(axum::extract::DefaultBodyLimit::max(4096)),
        )
        .route(
            "/fido/exchange",
            post(fido_relay::exchange).layer(axum::extract::DefaultBodyLimit::max(4096)),
        )
        .route(
            "/fido/cancel",
            post(fido_relay::cancel).layer(axum::extract::DefaultBodyLimit::max(4096)),
        )
        .route(
            "/advertisement",
            post(helper::advertisement).layer(axum::extract::DefaultBodyLimit::max(4096)),
        );
    let protected_vnc = Router::new()
        .route("/download/:filename", get(downloads::download))
        .route("/api/helper/downloads", get(downloads::manifest))
        // Compatibility alias for clients using the previous API prefix.
        .route("/api/companion/downloads", get(downloads::manifest))
        .route("/ws", get(desktop::websocket))
        .route("/api/clipboard/ws", get(clipboard::websocket))
        .nest_service("/novnc", novnc)
        .route_layer(axum_middleware::from_fn_with_state(
            app.clone(),
            middleware::vnc_guard,
        ));
    // Downloads are global public resources. Scoped compatibility routes keep
    // their existing browser authorization; public links always use the root.
    let downloads_routes = Router::new()
        .route("/api/downloads", get(downloads::list))
        .route("/downloads/:filename", get(downloads::download));
    let downloads_routes = if app.profile_scope {
        downloads_routes.route_layer(axum_middleware::from_fn_with_state(
            app.clone(),
            middleware::vnc_guard,
        ))
    } else {
        downloads_routes
    };
    Router::new()
        .merge(downloads_routes)
        .route(
            "/api/viewer/acquire",
            post(crate::profiles::viewer::acquire),
        )
        .route("/api/viewer/status", get(crate::profiles::viewer::status))
        .route(
            "/api/viewer/activity",
            post(crate::profiles::viewer::activity),
        )
        .route(
            "/api/viewer/release",
            post(crate::profiles::viewer::release),
        )
        .route("/api/viewer/ticket", post(crate::profiles::viewer::ticket))
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(control::ready))
        .route("/api/runtime", get(control::runtime))
        .route("/", get(assets::index))
        .route("/index.html", get(assets::index))
        .route("/settings", get(assets::index))
        .route("/settings/", get(assets::index))
        // The Downloads shell, global listing and files require no password.
        .route("/downloads", get(assets::index))
        .route("/downloads/", get(assets::index))
        .route("/api/status", get(auth::status))
        .route(
            "/api/browser/reconnect",
            get(control::browser_operation_scope).post(control::browser_reconnect),
        )
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout))
        .route("/api/security", get(auth::security).put(auth::set_password))
        .route("/api/keys", get(settings::keys).post(settings::create_key))
        .route(
            "/api/keys/:id",
            patch(settings::edit_key).delete(settings::delete_key),
        )
        .route(
            "/api/keys/:id/credentials",
            delete(settings::delete_credential),
        )
        .route("/api/backup", get(settings::backup))
        .route(
            "/api/restore/preview",
            post(restore::preview).layer(axum::extract::DefaultBodyLimit::max(
                6 * restore::MAX_BYTES + 1024,
            )),
        )
        .route("/api/restore/backup", post(restore::safety_backup))
        .route(
            "/api/restore/confirm",
            post(restore::confirm).layer(axum::extract::DefaultBodyLimit::max(
                6 * restore::MAX_BYTES + 1024,
            )),
        )
        .route("/api/requests", get(requests::pending_requests))
        .route("/api/requests/events", get(events::request_events))
        .route("/api/requests/:id/decision", post(requests::decide_request))
        .route(
            "/api/browser/mode",
            get(mode::status)
                .post(mode::select)
                .layer(axum::extract::DefaultBodyLimit::max(4096)),
        )
        .route(
            "/api/browser/mode/renew",
            post(mode::renew).layer(axum::extract::DefaultBodyLimit::max(4096)),
        )
        .nest("/api/helper", helper_routes.clone())
        // Existing clients retain the same authorization and limits through this alias.
        .nest("/api/companion", helper_routes)
        .route("/api/requests/:id/native/start", post(native_client::start))
        .route(
            "/api/requests/:id/native/finish",
            post(native_client::finish).layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)),
        )
        .merge(protected_vnc)
        .fallback_service(ServeDir::new("web/dist"))
        .layer(axum_middleware::from_fn_with_state(
            app.clone(),
            middleware::guard,
        ))
        .with_state(app)
}

pub(crate) fn router(app: App) -> Router {
    let global = Router::new()
        .route(
            "/api/profiles",
            get(crate::profiles::api::list).post(crate::profiles::api::create),
        )
        .route("/api/profiles/public", get(crate::profiles::api::public))
        .route(
            "/api/runtime/cleanup",
            post(crate::profiles::cleanup::manual)
                .layer(axum::extract::DefaultBodyLimit::max(1024)),
        )
        .route(
            "/api/profiles/config",
            axum::routing::put(crate::profiles::api::configure),
        )
        .route(
            "/api/profiles/:id",
            patch(crate::profiles::api::edit).delete(crate::profiles::api::delete),
        )
        .route(
            "/api/runtime/profiles/:id/engine",
            get(crate::profiles::api::engine),
        )
        .route("/profile", get(assets::profile_index))
        .route("/profile/", get(assets::profile_index))
        .route("/profile/*path", get(assets::profile_index))
        .route("/login", get(assets::index))
        .route("/login/", get(assets::index))
        .route(
            "/p/:name/*path",
            axum::routing::any(crate::profiles::api::scoped),
        )
        .layer(axum_middleware::from_fn_with_state(
            app.clone(),
            middleware::guard,
        ))
        .with_state(app.clone());
    profile_router(app).merge(global)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    #[tokio::test]
    async fn scoped_novnc_module_graph_uses_selected_profile_cookie_and_not_default() {
        let (mut root, dir) = crate::test_support::app();
        let id = uuid::Uuid::new_v4().to_string();
        {
            let mut i = root.inner.lock().await;
            i.store.data.multi_profile = true;
            i.store.data.vnc_password_hash = Some("default-protected".into());
            i.store
                .data
                .profiles
                .push(crate::storage::profiles::Profile {
                    id: id.clone(),
                    name: "work".into(),
                    ..Default::default()
                });
        }
        let registry = crate::profiles::Registry::new();
        root.profiles = Some(registry.clone());
        let app = registry.context(&root, &id);
        let static_dir = dir.join("novnc-fixture");
        std::fs::create_dir_all(static_dir.join("core")).unwrap();
        std::fs::write(static_dir.join("core/rfb.js"), "import './dependency.js';").unwrap();
        std::fs::write(static_dir.join("core/dependency.js"), "export default 1;").unwrap();
        let route = Router::new().nest(
            "/p/work",
            profile_router_with_novnc(app.clone(), ServeDir::new(&static_dir)),
        );
        for file in ["rfb.js", "dependency.js"] {
            let response = route
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/p/work/novnc/core/{file}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(!to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
                .is_empty());
        }
        app.inner
            .lock()
            .await
            .store
            .data
            .profiles
            .iter_mut()
            .find(|p| p.id == id)
            .unwrap()
            .password_hash = Some("profile-protected".into());
        let response = route
            .oneshot(
                Request::builder()
                    .uri("/p/work/novnc/core/rfb.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn unscoped_control_cannot_reuse_profile_tickets_or_forged_internal_headers() {
        let (mut app, dir) = crate::test_support::app();
        app.profiles = Some(crate::profiles::Registry::new());
        for path in [
            "/ws?ticket=anything",
            "/api/clipboard/ws?ticket=anything",
            "/api/browser/mode",
            "/api/requests",
            "/api/helper/status",
        ] {
            let response = router(app.clone())
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("x-auth-profile", "foreign")
                        .header("x-require-owner", "1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
