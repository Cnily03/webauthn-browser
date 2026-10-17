//! JSON/CSRF mutation boundary and response policy, independent of hostnames.
use crate::{
    app::App,
    auth::{authorize, csrf},
    http::error::fail,
};
use axum::{
    extract::State,
    http::{header, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub(crate) async fn guard(
    State(app): State<App>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if let Err(e) = crate::profiles::admission::prepare(&app, &mut req).await {
        return e.into_response();
    }
    // Gateway reachability is deployment-defined: do not admit/reject requests
    // based on Host, Origin, forwarding headers, or Fetch Metadata. Optional
    // session passwords and cookie-bound CSRF checks remain independent.
    if !matches!(
        *req.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    ) {
        let ct = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ct.split(';').next() != Some("application/json") {
            return fail(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "application/json required",
            )
            .into_response();
        }
        if let Err(e) = csrf(&*app.inner.lock().await, req.headers()) {
            return e.into_response();
        }
    }
    let request_headers = req.headers().clone();
    let mut response = next.run(req).await;
    crate::profiles::admission::renew_cookie(&app, &request_headers, &mut response).await;
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
    ] {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    // HTML responses install a per-document Emotion nonce. Other responses keep
    // the restrictive baseline, including all script restrictions.
    if !response
        .headers()
        .contains_key(header::CONTENT_SECURITY_POLICY)
    {
        response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"));
    }
    response
}
pub(crate) async fn vnc_guard(
    State(app): State<App>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if let Err(e) = authorize(&*app.inner.lock().await, req.headers(), "vnc") {
        return e.into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use crate::{
        app::{App, Session},
        http::router,
        test_support::{app, value},
    };

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        response::Response,
    };

    use std::time::{Duration, Instant};

    use tower::ServiceExt;
    #[tokio::test]
    async fn form_posts_and_dns_rebinding_are_rejected() {
        let (app, dir) = app();
        for (host, content_type, expected) in [
            (
                "localhost:8080",
                "application/x-www-form-urlencoded",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                "evil.example:8080",
                "application/json",
                StatusCode::FORBIDDEN,
            ),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri("/api/logout")
                .header("host", host)
                .header("content-type", content_type)
                .body(Body::from("scope=vnc"))
                .unwrap();
            assert_eq!(
                router(app.clone()).oneshot(request).await.unwrap().status(),
                expected
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    // Gateway admission is independent of public/proxy hostnames. These HTTP-layer
    // checks do not claim browser CORS permission or helper Origin approval.

    async fn request(
        app: &App,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Response {
        let mut request = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        router(app.clone())
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap()
    }

    fn proxy_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("host", "gateway.internal:8080"),
            ("origin", "https://browser.example:9443"),
            ("sec-fetch-site", "cross-site"),
            (
                "forwarded",
                "for=192.0.2.50;host=browser.example:9443;proto=https",
            ),
            ("x-forwarded-host", "browser.example:9443"),
            ("x-forwarded-proto", "https"),
        ]
    }

    #[tokio::test]
    async fn arbitrary_lan_domain_port_and_proxy_headers_need_no_allowlist() {
        let (app, dir) = app();
        let cases = [
            vec![
                ("host", "192.168.1.20:9080"),
                ("origin", "http://192.168.1.20:9080"),
            ],
            vec![
                ("host", "[fd00::20]:9080"),
                ("origin", "http://[fd00::20]:9080"),
            ],
            vec![
                ("host", "browser.example:9443"),
                ("origin", "https://browser.example:9443"),
            ],
            proxy_headers(),
            // Rewriting proxies need not supply Forwarded or X-Forwarded-*.
            vec![
                ("host", "gateway:8080"),
                ("origin", "https://public.example"),
                ("sec-fetch-site", "same-origin"),
            ],
            vec![("origin", "null"), ("sec-fetch-site", "cross-site")],
            vec![],
        ];
        for headers in cases {
            for path in ["/api/status", "/healthz", "/api/keys", "/api/requests"] {
                let response = request(&app, "GET", path, &headers, "").await;
                assert_eq!(response.status(), StatusCode::OK, "{path}: {headers:?}");
                assert!(!response
                    .headers()
                    .contains_key("access-control-allow-origin"));
                assert!(!response
                    .headers()
                    .contains_key("access-control-allow-credentials"));
                assert_eq!(response.headers()["x-frame-options"], "DENY");
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn proxy_mutations_still_require_live_cookie_bound_csrf_and_json() {
        let (app, dir) = app();
        let status = value(request(&app, "GET", "/api/status", &proxy_headers(), "").await).await;
        let token = status["csrf_token"].as_str().unwrap();
        let cookie = format!("ab_csrf={token}");
        let mut headers = proxy_headers();
        headers.push(("content-type", "application/json"));
        let body = r#"{"scope":"settings"}"#;
        assert_eq!(
            request(&app, "POST", "/api/logout", &headers, body)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        headers.push(("x-csrf-token", token));
        assert_eq!(
            request(&app, "POST", "/api/logout", &headers, body)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        headers.push(("cookie", &cookie));
        assert_eq!(
            request(&app, "POST", "/api/logout", &headers, body)
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&app, "POST", "/api/logout", &headers, "{")
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        let mut non_json = headers.clone();
        non_json.retain(|(name, _)| *name != "content-type");
        non_json.push(("content-type", "text/plain"));
        assert_eq!(
            request(&app, "POST", "/api/logout", &non_json, body)
                .await
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        app.inner
            .lock()
            .await
            .csrf
            .insert(token.into(), Instant::now() - Duration::from_secs(1));
        assert_eq!(
            request(&app, "POST", "/api/logout", &headers, body)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn proxy_admission_preserves_separate_password_scopes_and_session_expiry() {
        let (app, dir) = app();
        {
            let mut inner = app.inner.lock().await;
            inner.store.data.vnc_password_hash = Some("enabled".into());
            inner.store.data.settings_password_hash = Some("enabled".into());
            for scope in ["vnc", "settings"] {
                inner.sessions.insert(
                    scope.into(),
                    Session {
                        scope: scope.into(),
                        epoch: 0,
                        expires: Instant::now() + Duration::from_secs(60),
                    },
                );
            }
        }
        for path in [
            "/api/keys",
            "/api/requests",
            "/api/helper/downloads",
            "/ws",
            "/api/clipboard/ws",
        ] {
            assert_eq!(
                request(&app, "GET", path, &proxy_headers(), "")
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED,
                "{path}"
            );
        }
        let mut headers = proxy_headers();
        headers.push(("cookie", "ab_settings=settings"));
        assert_eq!(
            request(&app, "GET", "/api/keys", &headers, "")
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&app, "GET", "/api/requests", &headers, "")
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        headers.pop();
        headers.push(("cookie", "ab_vnc=vnc"));
        assert_eq!(
            request(&app, "GET", "/api/requests", &headers, "")
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&app, "GET", "/api/keys", &headers, "")
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        for path in ["/ws", "/api/clipboard/ws"] {
            // No live transport is needed: the authenticated request reaches the
            // extractor and rejects the absent upgrade headers, not Origin/Host.
            assert_eq!(
                request(&app, "GET", path, &headers, "").await.status(),
                StatusCode::BAD_REQUEST,
                "{path}"
            );
        }
        app.inner
            .lock()
            .await
            .sessions
            .get_mut("vnc")
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            request(&app, "GET", "/api/requests", &headers, "")
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
