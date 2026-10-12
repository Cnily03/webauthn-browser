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

pub(crate) fn router(app: App) -> Router {
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
        .route("/api/downloads", get(downloads::list))
        .route("/downloads/:filename", get(downloads::download))
        .route("/download/:filename", get(downloads::download))
        .route("/api/helper/downloads", get(downloads::manifest))
        // Compatibility alias for clients using the previous API prefix.
        .route("/api/companion/downloads", get(downloads::manifest))
        .route("/ws", get(desktop::websocket))
        .route("/api/clipboard/ws", get(clipboard::websocket))
        .nest_service("/novnc", ServeDir::new("/usr/share/novnc"))
        .route_layer(axum_middleware::from_fn_with_state(
            app.clone(),
            middleware::vnc_guard,
        ));
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(control::ready))
        .route("/api/runtime", get(control::runtime))
        .route("/", get(assets::index))
        .route("/index.html", get(assets::index))
        .route("/settings", get(assets::index))
        .route("/settings/", get(assets::index))
        // The shell contains no file metadata and must render the VNC unlock
        // screen on direct visits; the list and file routes remain protected.
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
