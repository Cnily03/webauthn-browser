//! Profile-scoped, revocable HttpOnly access cookies; only digests are persisted.
use crate::{
    app::{App, Inner},
    auth::{cookie, token},
    http::error::fail,
    storage::profiles::ACCESS_SECONDS,
};
use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub(crate) fn digest(token: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, token.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub(crate) fn profile_id(headers: &HeaderMap) -> Option<&str> {
    headers.get("x-auth-profile").and_then(|h| h.to_str().ok())
}
pub(crate) const COOKIE_NAME: &str = "ab_profile_access";
pub(crate) fn profile_name(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-auth-profile-name")
        .and_then(|h| h.to_str().ok())
}
pub(crate) fn name_matches(
    headers: &HeaderMap,
    profile: &crate::storage::profiles::Profile,
) -> bool {
    profile_name(headers).is_none_or(|name| name == profile.name)
}
pub(crate) fn token_hash(headers: &HeaderMap) -> Option<String> {
    cookie(headers, COOKIE_NAME)
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(digest)
}
/// Remembered credential validity is independent of temporary availability.
/// Admission must separately require effective_enabled; disabled use cannot slide it.
pub(crate) fn valid_token(inner: &Inner, headers: &HeaderMap, id: &str) -> bool {
    if inner.store.writes_blocked() {
        return false;
    }
    let Some(profile) = inner.store.data.profile(id) else {
        return false;
    };
    if !name_matches(headers, profile) {
        return false;
    }
    let hash = token_hash(headers);
    inner.store.data.profile_access_tokens.iter().any(|t| {
        Some(&t.token_hash) == hash.as_ref()
            && t.profile_id == id
            && t.auth_revision == profile.auth_revision
            && t.last_used_at.saturating_add(ACCESS_SECONDS) > now()
    })
}
pub(crate) fn authorized(inner: &Inner, headers: &HeaderMap) -> bool {
    if inner.store.writes_blocked() {
        return false;
    }
    let Some(id) = profile_id(headers) else {
        return false;
    };
    let Some(profile) = inner.store.data.profile(id) else {
        return false;
    };
    if !name_matches(headers, profile) || !inner.store.data.effective_enabled(profile) {
        return false;
    }
    let access = if inner.store.data.profile_password(profile).is_none() {
        true
    } else {
        valid_token(inner, headers, id)
    };
    access && (!headers.contains_key("x-require-owner") || super::viewer::is_owner(inner, headers))
}
pub(crate) fn set_cookie(response: &mut Response, name: &str, value: &str, clear: bool) {
    let secure = if std::env::var("AUTH_BROWSER_SECURE_COOKIES").as_deref() == Ok("true") {
        "; Secure"
    } else {
        ""
    };
    let value = format!(
        "{}={}; Path=/p/{name}/; HttpOnly; SameSite=Strict; Max-Age={}{secure}",
        COOKIE_NAME,
        value,
        if clear { 0 } else { ACCESS_SECONDS }
    );
    response
        .headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_str(&value).unwrap());
}
pub(crate) async fn login(
    app: &App,
    headers: &HeaderMap,
    password: String,
) -> Result<Response, (StatusCode, String)> {
    let id = app.profile_id.to_string();
    let (hash, revision) = {
        let mut i = app.inner.lock().await;
        let now = Instant::now();
        i.attempts
            .retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(60));
        let attempt = i
            .attempts
            .entry(format!("profile:{id}"))
            .or_insert((now, 0));
        if attempt.1 >= 10 {
            return Err(fail(
                StatusCode::TOO_MANY_REQUESTS,
                "尝试次数过多，请稍后再试。",
            ));
        }
        attempt.1 += 1;
        let p = i
            .store
            .data
            .profile(&id)
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "配置不存在。"))?;
        if !name_matches(headers, p) || !i.store.data.effective_enabled(p) {
            return Err(fail(StatusCode::FORBIDDEN, "配置已停用。"));
        }
        (
            i.store.data.profile_password(p).map(str::to_owned),
            p.auth_revision,
        )
    };
    if let Some(hash) = hash {
        use argon2::PasswordVerifier;
        if !tokio::task::spawn_blocking(move || {
            argon2::PasswordHash::new(&hash).ok().is_some_and(|h| {
                argon2::Argon2::default()
                    .verify_password(password.as_bytes(), &h)
                    .is_ok()
            })
        })
        .await
        .unwrap_or(false)
        {
            return Err(fail(StatusCode::UNAUTHORIZED, "密码错误。"));
        }
    }
    let raw = token();
    let hash = digest(&raw);
    let mut i = app.inner.lock().await;
    let p = i
        .store
        .data
        .profile(&id)
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "配置不存在。"))?;
    if p.auth_revision != revision
        || !name_matches(headers, p)
        || !i.store.data.effective_enabled(p)
    {
        return Err(fail(StatusCode::CONFLICT, "配置权限已变更，请重试。"));
    }
    let name = p.name.clone();
    let old = i.store.data.clone();
    let now = now();
    let previous = token_hash(headers);
    i.store.data.profile_access_tokens.retain(|t| {
        t.last_used_at.saturating_add(ACCESS_SECONDS) > now
            && (t.profile_id != id || Some(&t.token_hash) != previous.as_ref())
    });
    if i.store.data.profile_access_tokens.len() >= 4096 {
        return Err(fail(StatusCode::SERVICE_UNAVAILABLE, "登录数量已达上限。"));
    }
    i.store
        .data
        .profile_access_tokens
        .push(crate::storage::profiles::AccessToken {
            token_hash: hash,
            profile_id: id.clone(),
            auth_revision: revision,
            last_used_at: now,
        });
    super::commit(&mut i, old)?;
    let mut response = Json(json!({"ok":true})).into_response();
    set_cookie(&mut response, &name, &raw, false);
    Ok(response)
}
pub(crate) async fn logout(
    app: &App,
    headers: &HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let id = app.profile_id.to_string();
    let name = profile_name(headers).unwrap_or("default");
    let hash = token_hash(headers);
    let mut broker = app.broker.lock().await;
    let mut i = app.inner.lock().await;
    let old = i.store.data.clone();
    i.store
        .data
        .profile_access_tokens
        .retain(|t| t.profile_id != id || Some(&t.token_hash) != hash.as_ref());
    super::commit(&mut i, old)?;
    let changed = super::viewer::revoke_access(
        &mut i,
        &id,
        hash.as_deref(),
        headers
            .get("x-viewer-token")
            .and_then(|v| v.to_str().ok())
            .map(digest)
            .as_deref(),
    );
    if changed {
        broker.cancel_all("Profile access revoked");
    }
    drop(i);
    drop(broker);
    app.revoked.send_modify(|n| *n = n.wrapping_add(1));
    let mut response = Json(json!({"ok":true})).into_response();
    set_cookie(&mut response, name, "", true);
    Ok(response)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Authority {
    headers: HeaderMap,
}
impl Authority {
    pub(crate) fn capture(headers: &HeaderMap) -> Option<Self> {
        profile_id(headers).map(|_| {
            let mut retained = HeaderMap::new();
            for name in [
                "x-auth-profile",
                "x-auth-profile-name",
                "x-viewer-token",
                "x-owner-generation",
                "x-require-owner",
                "x-csrf-token",
            ] {
                if let Some(value) = headers.get(name) {
                    retained.insert(name, value.clone());
                }
            }
            let mut cookies = Vec::new();
            for name in ["ab_csrf", COOKIE_NAME] {
                if let Some(value) = cookie(headers, name) {
                    cookies.push(format!("{name}={value}"));
                }
            }
            if let Ok(value) = cookies.join("; ").parse() {
                retained.insert(header::COOKIE, value);
            }
            Self { headers: retained }
        })
    }
    pub(crate) fn valid(&self, inner: &Inner) -> bool {
        authorized(inner, &self.headers) && crate::auth::csrf(inner, &self.headers).is_ok()
    }
    pub(crate) fn same(&self, headers: &HeaderMap) -> bool {
        profile_id(&self.headers) == profile_id(headers)
            && token_hash(&self.headers) == token_hash(headers)
            && profile_name(&self.headers) == profile_name(headers)
            && self.headers.get("x-viewer-token") == headers.get("x-viewer-token")
            && self.headers.get("x-owner-generation") == headers.get("x-owner-generation")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        profiles::Registry,
        test_support::{call, value},
    };
    use serde_json::Value;

    async fn fixture() -> (App, std::path::PathBuf, String, String) {
        let (mut app, dir) = crate::test_support::app();
        app.profiles = Some(Registry::new());
        let status = value(call(&app, "GET", "/api/status", Value::Null, "", "", None).await).await;
        let csrf = status["csrf_token"].as_str().unwrap().to_owned();
        let cookies = format!("ab_csrf={csrf}");
        (app, dir, csrf, cookies)
    }
    fn profile_cookie(response: &Response, _id: &str) -> Option<String> {
        let prefix = format!("{COOKIE_NAME}=");
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|h| h.to_str().ok())
            .find(|h| h.starts_with(&prefix))
            .map(str::to_owned)
    }
    async fn mode(app: &App, enabled: bool, csrf: &str, cookies: &str) {
        assert_eq!(
            call(
                app,
                "PUT",
                "/api/profiles/config",
                json!({"multi_profile":enabled}),
                cookies,
                csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
    }
    async fn create(app: &App, csrf: &str, cookies: &str) -> String {
        let response = call(
            app,
            "POST",
            "/api/profiles",
            json!({"name":"remembered","password":"fixture-password"}),
            cookies,
            csrf,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        value(response).await["id"].as_str().unwrap().to_owned()
    }
    async fn login_cookie(
        app: &App,
        id: &str,
        password: &str,
        csrf: &str,
        cookies: &str,
    ) -> String {
        let name = app
            .inner
            .lock()
            .await
            .store
            .data
            .profile(id)
            .unwrap()
            .name
            .clone();
        let response = call(
            app,
            "POST",
            &format!("/p/{name}/api/login"),
            json!({"scope":"vnc","password":password}),
            cookies,
            csrf,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        format!(
            "{cookies}; {}",
            profile_cookie(&response, id)
                .unwrap()
                .split(';')
                .next()
                .unwrap()
        )
    }

    #[tokio::test]
    async fn mode_overrides_preserve_remembered_access_but_password_change_still_revokes() {
        let (app, dir, csrf, cookies) = fixture().await;
        let id = create(&app, &csrf, &cookies).await;
        mode(&app, true, &csrf, &cookies).await;
        let remembered = login_cookie(&app, &id, "fixture-password", &csrf, &cookies).await;
        let original_revision = app
            .inner
            .lock()
            .await
            .store
            .data
            .profile(&id)
            .unwrap()
            .auth_revision;
        for _ in 0..3 {
            let last_used = now() - 120;
            {
                let mut inner = app.inner.lock().await;
                inner.store.data.profile_access_tokens[0].last_used_at = last_used;
                inner.store.save().unwrap();
            }
            mode(&app, false, &csrf, &cookies).await;
            let response = call(
                &app,
                "GET",
                "/p/remembered/api/status",
                Value::Null,
                &remembered,
                "",
                None,
            )
            .await;
            assert!(profile_cookie(&response, &id).is_none());
            assert_eq!(value(response).await["vnc_authenticated"], false);
            assert_eq!(
                call(
                    &app,
                    "GET",
                    "/p/remembered/api/downloads",
                    Value::Null,
                    &remembered,
                    "",
                    None
                )
                .await
                .status(),
                StatusCode::UNAUTHORIZED
            );
            {
                let inner = app.inner.lock().await;
                assert_eq!(
                    inner.store.data.profile(&id).unwrap().auth_revision,
                    original_revision
                );
                assert_eq!(
                    inner.store.data.profile_access_tokens[0].last_used_at,
                    last_used
                );
            }
            mode(&app, true, &csrf, &cookies).await;
            let response = call(
                &app,
                "GET",
                "/p/remembered/api/status",
                Value::Null,
                &remembered,
                "",
                None,
            )
            .await;
            assert!(profile_cookie(&response, &id)
                .unwrap()
                .contains("Max-Age=2592000"));
            assert_eq!(value(response).await["vnc_authenticated"], true);
        }
        let persisted = crate::storage::store::Store::open(dir.join("store.json")).unwrap();
        assert_eq!(persisted.data.profile_access_tokens.len(), 1);
        assert_eq!(
            persisted.data.profile(&id).unwrap().auth_revision,
            original_revision
        );
        let response = call(
            &app,
            "PATCH",
            &format!("/api/profiles/{id}"),
            json!({"password":"changed-password"}),
            &cookies,
            &csrf,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        mode(&app, false, &csrf, &cookies).await;
        mode(&app, true, &csrf, &cookies).await;
        let response = call(
            &app,
            "GET",
            "/p/remembered/api/status",
            Value::Null,
            &remembered,
            "",
            None,
        )
        .await;
        assert!(profile_cookie(&response, &id)
            .unwrap()
            .contains("Max-Age=0"));
        assert_eq!(value(response).await["vnc_authenticated"], false);
        assert!(app
            .inner
            .lock()
            .await
            .store
            .data
            .profile_access_tokens
            .is_empty());
        let fresh = login_cookie(&app, &id, "changed-password", &csrf, &cookies).await;
        for enabled in [false, true] {
            assert_eq!(
                call(
                    &app,
                    "PATCH",
                    &format!("/api/profiles/{id}"),
                    json!({"enabled":enabled}),
                    &cookies,
                    &csrf,
                    None
                )
                .await
                .status(),
                StatusCode::OK
            );
        }
        assert_eq!(
            value(
                call(
                    &app,
                    "GET",
                    "/p/remembered/api/status",
                    Value::Null,
                    &fresh,
                    "",
                    None
                )
                .await
            )
            .await["vnc_authenticated"],
            false
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn mode_changes_preserve_settings_session_and_disabled_access_still_expires() {
        let (app, dir, csrf, cookies) = fixture().await;
        let id = create(&app, &csrf, &cookies).await;
        mode(&app, true, &csrf, &cookies).await;
        let remembered = login_cookie(&app, &id, "fixture-password", &csrf, &cookies).await;
        let admin = format!("{cookies}; ab_settings=fixture-admin");
        let expires = Instant::now() + Duration::from_secs(600);
        {
            let mut i = app.inner.lock().await;
            i.store.data.settings_password_hash = Some("protected-settings".into());
            i.sessions.insert(
                "fixture-admin".into(),
                crate::app::Session {
                    scope: "settings".into(),
                    epoch: 0,
                    expires,
                },
            );
        }
        mode(&app, false, &csrf, &admin).await;
        let expired_at = now() - ACCESS_SECONDS - 1;
        {
            let mut i = app.inner.lock().await;
            i.store.data.profile_access_tokens[0].last_used_at = expired_at;
            i.store.save().unwrap();
        }
        let response = call(
            &app,
            "GET",
            "/p/remembered/api/status",
            Value::Null,
            &remembered,
            "",
            None,
        )
        .await;
        assert!(profile_cookie(&response, &id)
            .unwrap()
            .contains("Max-Age=0"));
        assert_eq!(value(response).await["vnc_authenticated"], false);
        mode(&app, true, &csrf, &admin).await;
        let i = app.inner.lock().await;
        assert_eq!(
            i.store.data.profile_access_tokens[0].last_used_at,
            expired_at
        );
        assert_eq!(i.settings_epoch, 0);
        assert_eq!(i.sessions["fixture-admin"].expires, expires);
        drop(i);
        assert_eq!(
            value(call(&app, "GET", "/api/status", Value::Null, &admin, "", None).await).await
                ["settings_authenticated"],
            true
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn expired_passwordless_cookie_is_cleared_without_sliding_its_server_record() {
        let (app, dir, csrf, cookies) = fixture().await;
        let remembered = login_cookie(&app, "default", "", &csrf, &cookies).await;
        let expired_at = now() - ACCESS_SECONDS - 1;
        {
            let mut inner = app.inner.lock().await;
            inner.store.data.profile_access_tokens[0].last_used_at = expired_at;
            inner.store.save().unwrap();
        }
        let response = call(
            &app,
            "GET",
            "/p/default/api/status",
            Value::Null,
            &remembered,
            "",
            None,
        )
        .await;
        assert!(profile_cookie(&response, "default")
            .unwrap()
            .contains("Max-Age=0"));
        // Passwordless viewing remains public, but it cannot resurrect a token.
        assert_eq!(value(response).await["vnc_authenticated"], true);
        assert_eq!(
            app.inner.lock().await.store.data.profile_access_tokens[0].last_used_at,
            expired_at
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn forgetting_disabled_and_removed_profiles_clears_only_the_matching_cookie() {
        let (app, dir, csrf, cookies) = fixture().await;
        let id = create(&app, &csrf, &cookies).await;
        mode(&app, true, &csrf, &cookies).await;
        let alice = login_cookie(&app, &id, "fixture-password", &csrf, &cookies).await;
        let bob = login_cookie(&app, &id, "fixture-password", &csrf, &cookies).await;
        mode(&app, false, &csrf, &cookies).await;
        let path = "/p/remembered/api/logout".to_owned();
        assert_eq!(
            call(
                &app,
                "POST",
                &path,
                json!({"scope":"vnc"}),
                &alice,
                "",
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let response = call(
            &app,
            "POST",
            &path,
            json!({"scope":"vnc"}),
            &alice,
            &csrf,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(profile_cookie(&response, &id)
            .unwrap()
            .contains("Max-Age=0"));
        assert_eq!(
            app.inner
                .lock()
                .await
                .store
                .data
                .profile_access_tokens
                .len(),
            1
        );
        mode(&app, true, &csrf, &cookies).await;
        assert_eq!(
            value(
                call(
                    &app,
                    "GET",
                    "/p/remembered/api/status",
                    Value::Null,
                    &bob,
                    "",
                    None
                )
                .await
            )
            .await["vnc_authenticated"],
            true
        );
        // This fixture has no manager: revoke access, but never claim erasure.
        assert_eq!(
            call(
                &app,
                "DELETE",
                &format!("/api/profiles/{id}"),
                json!({}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let registry = app.profiles.as_ref().unwrap();
        assert!(!registry.has_context(&id));
        for (body, token, expected) in [
            (json!({"scope":"vnc"}), "", StatusCode::FORBIDDEN),
            (
                json!({"scope":"settings"}),
                csrf.as_str(),
                StatusCode::BAD_REQUEST,
            ),
            (
                json!({"scope":"vnc","extra":true}),
                csrf.as_str(),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            assert_eq!(
                call(&app, "POST", &path, body, &bob, token, None)
                    .await
                    .status(),
                expected
            );
        }
        let response = call(
            &app,
            "POST",
            &path,
            json!({"scope":"vnc"}),
            &bob,
            &csrf,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(profile_cookie(&response, &id)
            .unwrap()
            .contains("Max-Age=0"));
        assert!(!registry.has_context(&id));
        std::fs::remove_dir_all(dir).unwrap();
    }
    async fn public_request(
        app: &App,
        method: &str,
        path: &str,
        body: Value,
        headers: &HeaderMap,
    ) -> Response {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .body(if body.is_null() {
                Body::empty()
            } else {
                Body::from(body.to_string())
            })
            .unwrap();
        *request.headers_mut() = headers.clone();
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        crate::http::router(app.clone())
            .oneshot(request)
            .await
            .unwrap()
    }
    fn assert_private_identity_absent(response: &Response, id: &str) {
        for value in response.headers().values() {
            assert!(!value.to_str().unwrap_or("").contains(id));
            assert!(!value.to_str().unwrap_or("").contains(&id.replace('-', "")));
        }
    }
    async fn public_body(response: Response, id: &str) -> Value {
        assert_private_identity_absent(&response, id);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains(id));
        assert!(!text.contains(&id.replace('-', "")));
        serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(text.to_owned()))
    }
    async fn ready_context(app: &App, id: &str) -> App {
        let registry = app.profiles.as_ref().unwrap();
        let mut context = registry.context(app, id);
        let mut endpoints = (*context.endpoints).clone();
        endpoints.runtime_epoch = Some("ab".repeat(16));
        context.endpoints = std::sync::Arc::new(endpoints);
        let mut stored = context.clone();
        stored.profiles = None;
        registry
            .contexts
            .lock()
            .unwrap()
            .insert(id.to_owned(), stored);
        context
    }
    #[tokio::test]
    async fn public_names_hide_storage_identity_across_auth_viewer_stream_and_downloads() {
        use futures_util::StreamExt;
        let (mut app, dir, csrf, cookies) = fixture().await;
        app.profiles = Some(Registry::test_ready());
        let id = create(&app, &csrf, &cookies).await;
        mode(&app, true, &csrf, &cookies).await;
        let context = ready_context(&app, &id).await;
        let discovery = public_body(
            call(
                &app,
                "GET",
                "/api/profiles/public",
                Value::Null,
                "",
                "",
                None,
            )
            .await,
            &id,
        )
        .await;
        assert!(discovery["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p.get("id").is_none()));
        let response = call(
            &app,
            "GET",
            "/p/REMEMBERED/api/status?case=1",
            Value::Null,
            "",
            "",
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers()[header::LOCATION],
            "/p/remembered/api/status?case=1"
        );
        for path in [
            format!("/p/{id}/api/status"),
            format!("/p/{id}/api/login"),
            format!("/p/{id}/ws?ticket=old"),
        ] {
            let response = call(&app, "GET", &path, Value::Null, "", "", None).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            public_body(response, &id).await;
        }
        for path in ["/api/login", "/api/logout"] {
            assert_eq!(
                call(
                    &app,
                    "POST",
                    path,
                    json!({"scope":"vnc","password":"fixture-password"}),
                    &cookies,
                    &csrf,
                    None
                )
                .await
                .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let response = call(
            &app,
            "POST",
            "/p/remembered/api/login",
            json!({"scope":"vnc","password":"fixture-password"}),
            &cookies,
            &csrf,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = profile_cookie(&response, &id).unwrap();
        assert!(cookie.starts_with("ab_profile_access="));
        assert!(cookie.contains("Path=/p/remembered/;"));
        public_body(response, &id).await;
        let remembered = format!("{cookies}; {}", cookie.split(';').next().unwrap());
        let legacy = format!(
            "{cookies}; ab_profile_{}={}",
            id.replace('-', ""),
            cookie.split(';').next().unwrap().split_once('=').unwrap().1
        );
        let legacy_status = public_body(
            call(
                &app,
                "GET",
                "/p/remembered/api/status",
                Value::Null,
                &legacy,
                "",
                None,
            )
            .await,
            &id,
        )
        .await;
        assert_eq!(legacy_status["vnc_authenticated"], false);
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, remembered.parse().unwrap());
        headers.insert("x-csrf-token", csrf.parse().unwrap());
        // Caller-supplied internal identity headers never affect route selection.
        headers.insert("x-auth-profile", "default".parse().unwrap());
        headers.insert("x-auth-profile-name", "default".parse().unwrap());
        for path in ["/api/status", "/api/downloads", "/api/helper/downloads"] {
            let response = public_request(
                &app,
                "GET",
                &format!("/p/remembered{path}"),
                Value::Null,
                &headers,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = public_body(response, &id).await;
            if path == "/api/status" {
                assert_eq!(body["profile"]["name"], "remembered");
                assert!(body["profile"].get("id").is_none());
                assert_eq!(body["vnc_authenticated"], true);
            }
        }
        let response = public_request(
            &app,
            "POST",
            "/p/remembered/api/viewer/acquire",
            json!({}),
            &headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let viewer = public_body(response, &id).await;
        assert!(viewer["viewer_id"].is_string());
        headers.insert(
            "x-viewer-token",
            viewer["viewer_token"].as_str().unwrap().parse().unwrap(),
        );
        headers.insert(
            "x-owner-generation",
            viewer["generation"].to_string().parse().unwrap(),
        );
        let response = public_request(
            &app,
            "GET",
            "/p/remembered/api/viewer/status",
            Value::Null,
            &headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        public_body(response, &id).await;
        let response = public_request(
            &app,
            "GET",
            "/p/remembered/api/requests/events",
            Value::Null,
            &headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_private_identity_absent(&response, &id);
        let mut stream = response.into_body().into_data_stream();
        let snapshot = stream.next().await.unwrap().unwrap();
        assert!(!std::str::from_utf8(&snapshot).unwrap().contains(&id));
        let response = public_request(
            &app,
            "POST",
            "/p/remembered/api/viewer/ticket",
            json!({"kind":"vnc"}),
            &headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let ticket = public_body(response, &id).await;
        let response = public_request(
            &app,
            "GET",
            &format!(
                "/p/remembered/ws?ticket={}",
                ticket["ticket"].as_str().unwrap()
            ),
            Value::Null,
            &headers,
        )
        .await;
        // Admission consumes the correct name-bound ticket; this in-process
        // request deliberately lacks a real HTTP WebSocket upgrade transport.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_private_identity_absent(&response, &id);
        let response = call(
            &app,
            "PATCH",
            &format!("/api/profiles/{id}"),
            json!({"name":"renamed"}),
            &cookies,
            &csrf,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .is_none());
        assert!(super::super::viewer::empty(&*app.inner.lock().await, &id));
        assert!(context.broker.lock().await.helper.is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn rename_and_reused_name_never_transfer_remembered_or_live_authority() {
        let (mut app, dir, csrf, cookies) = fixture().await;
        app.profiles = Some(Registry::test_ready());
        let id = create(&app, &csrf, &cookies).await;
        mode(&app, true, &csrf, &cookies).await;
        ready_context(&app, &id).await;
        let remembered = login_cookie(&app, &id, "fixture-password", &csrf, &cookies).await;
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, remembered.parse().unwrap());
        headers.insert("x-csrf-token", csrf.parse().unwrap());
        let viewer = value(
            public_request(
                &app,
                "POST",
                "/p/remembered/api/viewer/acquire",
                json!({}),
                &headers,
            )
            .await,
        )
        .await;
        headers.insert(
            "x-viewer-token",
            viewer["viewer_token"].as_str().unwrap().parse().unwrap(),
        );
        headers.insert(
            "x-owner-generation",
            viewer["generation"].to_string().parse().unwrap(),
        );
        let ticket = value(
            public_request(
                &app,
                "POST",
                "/p/remembered/api/viewer/ticket",
                json!({"kind":"vnc"}),
                &headers,
            )
            .await,
        )
        .await;
        let old_endpoints = app
            .profiles
            .as_ref()
            .unwrap()
            .context(&app, &id)
            .endpoints
            .clone();
        let revision = app
            .inner
            .lock()
            .await
            .store
            .data
            .profile(&id)
            .unwrap()
            .auth_revision;
        assert_eq!(
            call(
                &app,
                "PATCH",
                &format!("/api/profiles/{id}"),
                json!({"name":"renamed"}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.inner
                .lock()
                .await
                .store
                .data
                .profile(&id)
                .unwrap()
                .auth_revision,
            revision + 1
        );
        assert_eq!(
            old_endpoints.proxy_path,
            app.profiles
                .as_ref()
                .unwrap()
                .context(&app, &id)
                .endpoints
                .proxy_path
        );
        assert_eq!(
            call(
                &app,
                "GET",
                "/p/remembered/api/status",
                Value::Null,
                &remembered,
                "",
                None
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            value(
                call(
                    &app,
                    "GET",
                    "/p/renamed/api/status",
                    Value::Null,
                    &remembered,
                    "",
                    None
                )
                .await
            )
            .await["vnc_authenticated"],
            false
        );
        // Even changing back to the old name cannot resurrect its former cookie.
        assert_eq!(
            call(
                &app,
                "PATCH",
                &format!("/api/profiles/{id}"),
                json!({"name":"remembered"}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            value(
                call(
                    &app,
                    "GET",
                    "/p/remembered/api/status",
                    Value::Null,
                    &remembered,
                    "",
                    None
                )
                .await
            )
            .await["vnc_authenticated"],
            false
        );
        assert_eq!(
            call(
                &app,
                "PATCH",
                &format!("/api/profiles/{id}"),
                json!({"name":"renamed"}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        let replacement = create(&app, &csrf, &cookies).await;
        assert_ne!(id, replacement);
        assert_eq!(
            value(
                call(
                    &app,
                    "GET",
                    "/p/remembered/api/status",
                    Value::Null,
                    &remembered,
                    "",
                    None
                )
                .await
            )
            .await["vnc_authenticated"],
            false
        );
        for path in [
            "/api/viewer/status".to_owned(),
            format!("/ws?ticket={}", ticket["ticket"].as_str().unwrap()),
            "/api/requests/events".to_owned(),
        ] {
            let response = public_request(
                &app,
                "GET",
                &format!("/p/remembered{path}"),
                Value::Null,
                &headers,
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            public_body(response, &id).await;
        }
        // Correct credentials create fresh access for the replacement only.
        let fresh = login_cookie(&app, &replacement, "fixture-password", &csrf, &cookies).await;
        assert_eq!(
            value(
                call(
                    &app,
                    "GET",
                    "/p/remembered/api/status",
                    Value::Null,
                    &fresh,
                    "",
                    None
                )
                .await
            )
            .await["vnc_authenticated"],
            true
        );
        let inner = app.inner.lock().await;
        assert!(inner
            .store
            .data
            .profile_access_tokens
            .iter()
            .all(|t| t.profile_id == replacement));
        drop(inner);
        // A passwordless replacement allows a fresh public viewer, but never
        // upgrades a stale credential, viewer token or ticket into its authority.
        assert_eq!(
            call(
                &app,
                "PATCH",
                &format!("/api/profiles/{replacement}"),
                json!({"password":null}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        ready_context(&app, &replacement).await;
        let response = public_request(
            &app,
            "GET",
            "/p/remembered/api/status",
            Value::Null,
            &headers,
        )
        .await;
        assert!(profile_cookie(&response, &replacement)
            .unwrap()
            .contains("Max-Age=0"));
        assert_eq!(
            public_body(response, &replacement).await["vnc_authenticated"],
            true
        );
        assert_eq!(
            public_request(
                &app,
                "POST",
                "/p/remembered/api/viewer/acquire",
                json!({}),
                &headers
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            public_request(
                &app,
                "GET",
                "/p/remembered/api/viewer/status",
                Value::Null,
                &headers
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let mut fresh_headers = HeaderMap::new();
        fresh_headers.insert(header::COOKIE, cookies.parse().unwrap());
        fresh_headers.insert("x-csrf-token", csrf.parse().unwrap());
        let response = public_request(
            &app,
            "POST",
            "/p/remembered/api/viewer/acquire",
            json!({}),
            &fresh_headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let fresh_viewer = public_body(response, &replacement).await;
        assert_ne!(fresh_viewer["viewer_id"], viewer["viewer_id"]);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
