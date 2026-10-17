//! Shared React entry document and per-response CSP nonce.
use crate::{auth::token, http::error::fail};
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

fn render_index(body: &str) -> Response {
    let nonce = token();
    let body = body.replace("__CSP_NONCE__", &nonce);
    let mut response = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response();
    // MUI transitions, Popper and noVNC use dynamic style attributes.
    // Only attributes get this exception; style elements need our nonce,
    // Scripts/resources remain same-origin; loopback sockets are only for the
    // explicitly paired local BLE helper. Scripts never allow eval
    // or inline execution. No user content is rendered as HTML.
    let policy = format!("default-src 'self'; script-src 'self'; style-src 'self' 'nonce-{nonce}'; style-src-elem 'self' 'nonce-{nonce}'; style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws://127.0.0.1:* wss://127.0.0.1:* ws://localhost:* wss://localhost:*; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&policy).expect("generated CSP nonce is ASCII"),
    );
    response
}
pub(crate) async fn profile_index(
    axum::extract::State(app): axum::extract::State<crate::app::App>,
) -> Response {
    if !app.inner.lock().await.store.data.multi_profile {
        return axum::response::Redirect::temporary("/").into_response();
    }
    index().await
}
pub(crate) async fn index() -> Response {
    match tokio::fs::read_to_string("web/dist/index.html").await {
        Ok(body) => render_index(&body),
        Err(_) => fail(StatusCode::SERVICE_UNAVAILABLE, "UI assets unavailable").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{body::to_bytes, http::header};

    #[tokio::test]
    async fn single_mode_redirects_every_named_profile_path_to_root() {
        let (app, dir) = crate::test_support::app();
        for path in [
            "/profile",
            "/profile/",
            "/profile/default",
            "/profile/other/",
            "/profile/other/nested?keep=none",
        ] {
            let response =
                crate::test_support::call(&app, "GET", path, serde_json::json!(null), "", "", None)
                    .await;
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT, "{path}");
            assert_eq!(response.headers()[header::LOCATION], "/");
        }
        app.inner.lock().await.store.data.multi_profile = true;
        for path in ["/profile/default", "/profile/other/"] {
            let response =
                crate::test_support::call(&app, "GET", path, serde_json::json!(null), "", "", None)
                    .await;
            assert!(matches!(
                response.status(),
                StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE
            ));
            assert!(!response.headers().contains_key(header::LOCATION));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn material_styles_use_per_document_nonce_without_relaxing_scripts() {
        let html = "<meta name=\"csp-nonce\" content=\"__CSP_NONCE__\"><script src=\"/assets/app.js\"></script>";
        let first = render_index(html);
        let policy = first.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_owned();
        let second = render_index(html);
        assert_ne!(
            policy,
            second.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
        );
        assert!(policy.contains("script-src 'self';"));
        assert!(!policy.contains("unsafe-eval"));
        assert!(policy.contains("style-src-attr 'unsafe-inline'"));
        assert!(policy.contains("frame-ancestors 'none'"));
        let body =
            String::from_utf8(to_bytes(first.into_body(), 4096).await.unwrap().to_vec()).unwrap();
        let nonce = body
            .split("content=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        assert_eq!(nonce.len(), 64);
        assert!(nonce.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(policy.contains(&format!("'nonce-{nonce}'")));
        assert!(!body.contains("__CSP_NONCE__"));
    }
    #[test]
    fn helper_csp_is_limited_to_loopback_sockets() {
        let response = render_index("<html></html>");
        let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(policy
            .contains("ws://127.0.0.1:* wss://127.0.0.1:* ws://localhost:* wss://localhost:*"));
        assert!(!policy.contains("connect-src *"));
        assert!(!policy.contains(" ws:;"));
    }
}
