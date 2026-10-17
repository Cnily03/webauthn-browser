//! Optional gateway passwords, cookie sessions, CSRF and authentication endpoints.
use crate::{
    app::{App, Inner, Session},
    http::error::{fail, ApiResult},
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
pub(crate) struct Login {
    scope: String,
    password: String,
}

#[derive(Deserialize)]
pub(crate) struct Scope {
    scope: String,
}

#[derive(Deserialize)]
pub(crate) struct Password {
    scope: String,
    password: Option<String>,
}

pub(crate) fn token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}
pub(crate) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|p| {
            p.trim()
                .split_once('=')
                .filter(|(k, _)| *k == name)
                .map(|(_, v)| v)
        })
}
pub(crate) fn vnc_epoch(inner: &Inner, headers: &HeaderMap) -> u64 {
    crate::profiles::access::profile_id(headers)
        .and_then(|id| inner.store.data.profile(id))
        .map(|p| p.auth_revision)
        .unwrap_or(inner.vnc_epoch)
}
pub(crate) fn authenticated(inner: &Inner, headers: &HeaderMap, scope: &str) -> bool {
    if scope == "vnc" && crate::profiles::access::profile_id(headers).is_some() {
        return crate::profiles::access::authorized(inner, headers);
    }
    let (hash, epoch) = if scope == "vnc" {
        (&inner.store.data.vnc_password_hash, inner.vnc_epoch)
    } else {
        (
            &inner.store.data.settings_password_hash,
            inner.settings_epoch,
        )
    };
    if hash.is_none() {
        return true;
    }
    let name = if scope == "vnc" {
        "ab_vnc"
    } else {
        "ab_settings"
    };
    cookie(headers, name)
        .and_then(|s| inner.sessions.get(s))
        .map(|s| s.scope == scope && s.epoch == epoch && s.expires > Instant::now())
        .unwrap_or(false)
}
pub(crate) fn authorize(
    inner: &Inner,
    headers: &HeaderMap,
    scope: &str,
) -> Result<(), (StatusCode, String)> {
    if authenticated(inner, headers, scope) {
        Ok(())
    } else {
        Err(fail(
            StatusCode::UNAUTHORIZED,
            format!("{scope} authentication required"),
        ))
    }
}
pub(crate) fn csrf(inner: &Inner, h: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let c = cookie(h, "ab_csrf");
    let provided = h.get("x-csrf-token").and_then(|v| v.to_str().ok());
    if c.is_some()
        && c == provided
        && c.and_then(|c| inner.csrf.get(c))
            .map(|e| *e > Instant::now())
            .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(fail(
            StatusCode::FORBIDDEN,
            "CSRF token required; refresh /api/status",
        ))
    }
}
pub(crate) async fn status(State(app): State<App>, headers: HeaderMap) -> Response {
    let mut broker = app.broker.lock().await;
    broker.expire();
    let mut i = app.inner.lock().await;
    if app.profile_name.as_deref().is_some_and(|name| {
        i.store
            .data
            .profile(&app.profile_id)
            .is_none_or(|profile| profile.name != name)
    }) {
        return fail(StatusCode::NOT_FOUND, "配置不存在。").into_response();
    }
    let now = Instant::now();
    i.sessions.retain(|_, s| s.expires > now);
    i.csrf.retain(|_, e| *e > now);
    let existing = cookie(&headers, "ab_csrf").filter(|c| i.csrf.contains_key(*c));
    if existing.is_none() && i.csrf.len() >= 4096 {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Session limit reached; retry later",
        )
        .into_response();
    }
    let t = existing.map(str::to_owned).unwrap_or_else(token);
    i.csrf.insert(t.clone(), now + Duration::from_secs(86400));
    broker.validate_helper_owner(&i);
    let body = json!({"vnc_authenticated":authenticated(&i,&headers,"vnc"),"settings_authenticated":authenticated(&i,&headers,"settings"),"vnc_password_enabled":i.store.data.vnc_password_hash.is_some(),"settings_password_enabled":i.store.data.settings_password_hash.is_some(),"csrf_token":t,"engine_connected":broker.ready,"engine_message":if let Some(error) = broker.mode_error.as_deref() { error } else if broker.native_qr_mode { "Native relay mode ready; start registration or sign-in inside the container browser" } else if broker.mode_pending.is_some() { "Switching Chromium authentication mode" } else { i.engine_message.as_str() },"native_qr_mode":broker.native_qr_mode,"mode_switching":broker.mode_pending.is_some(),"mode_error":broker.mode_error,"control_connected":broker.outbound.is_some(),"browser_mode":broker.browser_mode(),"mode_generation":broker.mode_generation});
    let mut body = body;
    if app.profiles.is_some() {
        if let Some(profile) = i.store.data.profile(&app.profile_id) {
            body["profile"] = crate::profiles::api::public_summary(&i.store.data, profile);
            body["vnc_password_enabled"] =
                serde_json::json!(i.store.data.profile_password(profile).is_some());
            body["engine_message"] = serde_json::json!(if broker.ready {
                "Profile engine ready"
            } else {
                "Waiting for profile engine"
            });
        }
    }
    let mut r = Json(body).into_response();
    set_cookie(&mut r, "ab_csrf", &t, false);
    r
}
fn set_cookie(r: &mut Response, name: &str, value: &str, clear: bool) {
    let secure = if std::env::var("AUTH_BROWSER_SECURE_COOKIES")
        .map(|s| s == "true")
        .unwrap_or(false)
    {
        "; Secure"
    } else {
        ""
    };
    r.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{secure}",
            if clear { 0 } else { 86400 }
        ))
        .unwrap(),
    );
}
fn check_scope(scope: &str) -> Result<(), (StatusCode, String)> {
    if scope == "vnc" || scope == "settings" {
        Ok(())
    } else {
        Err(fail(
            StatusCode::BAD_REQUEST,
            "scope must be vnc or settings",
        ))
    }
}
pub(crate) async fn login(
    State(app): State<App>,
    h: HeaderMap,
    Json(input): Json<Login>,
) -> Result<Response, (StatusCode, String)> {
    check_scope(&input.scope)?;
    if input.scope == "vnc" && app.profiles.is_some() {
        if !app.profile_scope {
            return Err(fail(StatusCode::BAD_REQUEST, "请使用明确的配置名称路径。"));
        }
        return crate::profiles::access::login(&app, &h, input.password).await;
    }
    let now = Instant::now();
    let (hash, epoch) = {
        let mut i = app.inner.lock().await;
        i.attempts
            .retain(|_, (time, _)| now.duration_since(*time) < Duration::from_secs(60));
        // Global per-scope budget cannot be reset by minting another CSRF cookie.
        // Only the two validated scopes can ever enter this map.
        let attempt = i.attempts.entry(input.scope.clone()).or_insert((now, 0));
        if attempt.1 >= 10 {
            return Err(fail(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many attempts; wait one minute",
            ));
        }
        attempt.1 += 1;
        if input.scope == "vnc" {
            (i.store.data.vnc_password_hash.clone(), i.vnc_epoch)
        } else {
            (
                i.store.data.settings_password_hash.clone(),
                i.settings_epoch,
            )
        }
    };
    if let Some(hash) = hash {
        let verified = tokio::task::spawn_blocking(move || {
            PasswordHash::new(&hash)
                .map(|parsed| {
                    Argon2::default()
                        .verify_password(input.password.as_bytes(), &parsed)
                        .is_ok()
                })
                .unwrap_or(false)
        })
        .await
        .map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        if !verified {
            return Err(fail(StatusCode::UNAUTHORIZED, "Incorrect password"));
        }
    }
    let mut i = app.inner.lock().await;
    let mut current_epoch = if input.scope == "vnc" {
        i.vnc_epoch
    } else {
        i.settings_epoch
    };
    if epoch != current_epoch {
        return Err(fail(
            StatusCode::CONFLICT,
            "Password changed during sign-in; try again",
        ));
    }
    if input.scope == "vnc" && i.store.data.vnc_password_hash.is_none() {
        i.vnc_epoch += 1;
        current_epoch = i.vnc_epoch;
        app.revoked.send_modify(|v| *v += 1);
    }
    i.sessions.retain(|_, s| s.expires > now);
    if i.sessions.len() >= 4096 {
        return Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Session limit reached",
        ));
    }
    if let Some(previous) = cookie(
        &h,
        if input.scope == "vnc" {
            "ab_vnc"
        } else {
            "ab_settings"
        },
    ) {
        i.sessions.remove(previous);
        app.revoked.send_modify(|v| *v += 1);
    }
    let t = token();
    i.sessions.insert(
        t.clone(),
        Session {
            scope: input.scope.clone(),
            epoch: current_epoch,
            expires: now + Duration::from_secs(86400),
        },
    );
    let mut r = Json(json!({"ok":true})).into_response();
    set_cookie(
        &mut r,
        if input.scope == "vnc" {
            "ab_vnc"
        } else {
            "ab_settings"
        },
        &t,
        false,
    );
    Ok(r)
}
pub(crate) async fn logout(
    State(app): State<App>,
    h: HeaderMap,
    Json(input): Json<Scope>,
) -> Result<Response, (StatusCode, String)> {
    check_scope(&input.scope)?;
    if input.scope == "vnc" && app.profiles.is_some() {
        if !app.profile_scope {
            return Err(fail(StatusCode::BAD_REQUEST, "请使用明确的配置名称路径。"));
        }
        return crate::profiles::access::logout(&app, &h).await;
    }
    let name = if input.scope == "vnc" {
        "ab_vnc"
    } else {
        "ab_settings"
    };
    let mut i = app.inner.lock().await;
    authorize(&i, &h, &input.scope)?;
    if let Some(t) = cookie(&h, name) {
        i.sessions.remove(t);
    }
    if input.scope == "vnc" && i.store.data.vnc_password_hash.is_none() {
        i.vnc_epoch += 1;
    }
    app.revoked.send_modify(|v| *v += 1);
    drop(i);
    if input.scope == "vnc" {
        app.broker.lock().await.cancel_all("Browser session locked");
    } else {
        app.broker.lock().await.stop_helper();
    }
    let mut r = Json(json!({"ok":true})).into_response();
    set_cookie(&mut r, name, "", true);
    Ok(r)
}
pub(crate) async fn security(State(app): State<App>, h: HeaderMap) -> ApiResult {
    let i = app.inner.lock().await;
    authorize(&i, &h, "settings")?;
    Ok(Json(
        json!({"vnc_password_enabled":i.store.data.vnc_password_hash.is_some(),"settings_password_enabled":i.store.data.settings_password_hash.is_some()}),
    ))
}
pub(crate) async fn set_password(
    State(app): State<App>,
    h: HeaderMap,
    Json(input): Json<Password>,
) -> ApiResult {
    check_scope(&input.scope)?;
    let _operation = app.operations.lock().await;
    {
        let i = app.inner.lock().await;
        authorize(&i, &h, "settings")?;
    }
    let hash = tokio::task::spawn_blocking(move || {
        input
            .password
            .map(|p| {
                Argon2::default()
                    .hash_password(p.as_bytes(), &SaltString::generate(&mut OsRng))
                    .map(|h| h.to_string())
                    .map_err(|e| e.to_string())
            })
            .transpose()
    })
    .await
    .map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, e))?
    .map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let mut i = app.inner.lock().await;
    authorize(&i, &h, "settings")?;
    let old = i.store.data.clone();
    if input.scope == "vnc" {
        i.store.data.vnc_password_hash = hash;
        if app.profiles.is_some() {
            let profile = i
                .store
                .data
                .profiles
                .iter_mut()
                .find(|p| p.id == "default")
                .unwrap();
            profile.auth_revision = profile
                .auth_revision
                .checked_add(1)
                .ok_or_else(|| fail(StatusCode::CONFLICT, "授权版本已耗尽。"))?;
            i.store
                .data
                .profile_access_tokens
                .retain(|t| t.profile_id != "default");
        }
    } else {
        i.store.data.settings_password_hash = hash
    };
    crate::profiles::commit(&mut i, old)?;
    if input.scope == "vnc" {
        i.vnc_epoch += 1
    } else {
        i.settings_epoch += 1
    }
    if app.profiles.is_some() && input.scope == "vnc" {
        crate::profiles::viewer::clear(&mut i, "default");
    }
    i.sessions.retain(|_, s| s.scope != input.scope);
    app.revoked.send_modify(|v| *v += 1);
    drop(i);
    if input.scope == "vnc" {
        if let Some(registry) = &app.profiles {
            let _ = registry.revoke("default", false).await;
        }
        app.broker
            .lock()
            .await
            .cancel_all("Browser password changed");
    } else {
        app.broker.lock().await.stop_helper();
    }
    Ok(Json(json!({"ok":true})))
}

#[cfg(test)]
mod tests {
    use crate::{
        authenticator::cdp::{self, KeyConfig},
        test_support::{app, call, value},
    };
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    };
    use axum::http::{header, StatusCode};
    use serde_json::{json, Value};
    use std::time::Instant;

    #[test]
    fn unicode_passwords_are_full_length() {
        let password = "🍋密码 longer than eight characters";
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
        let parsed = PasswordHash::new(&hash).unwrap();
        assert!(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok());
        assert!(Argon2::default()
            .verify_password("🍋密码".as_bytes(), &parsed)
            .is_err());
    }

    #[tokio::test]
    async fn independent_passwords_csrf_and_revocation() {
        let (app, dir) = app();
        let mut revoked = app.revoked.subscribe();
        let status = value(call(&app, "GET", "/api/status", Value::Null, "", "", None).await).await;
        assert_eq!(status["vnc_authenticated"], true);
        assert_eq!(status["settings_authenticated"], true);
        let csrf = status["csrf_token"].as_str().unwrap();
        let cookies = format!("ab_csrf={csrf}");
        assert_eq!(
            call(
                &app,
                "PUT",
                "/api/security",
                json!({"scope":"vnc","password":"秘密🙂 long password"}),
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
                "PUT",
                "/api/security",
                json!({"scope":"vnc","password":"秘密🙂 long password"}),
                &cookies,
                "",
                Some("https://external.example")
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                "PUT",
                "/api/security",
                json!({"scope":"vnc","password":"秘密🙂 long password"}),
                &cookies,
                csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app,
                "GET",
                "/novnc/core/rfb.js",
                Value::Null,
                &cookies,
                "",
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &app,
                "GET",
                "/api/security",
                Value::Null,
                &cookies,
                "",
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/login",
                json!({"scope":"vnc","password":"秘密🙂"}),
                &cookies,
                csrf,
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = call(
            &app,
            "POST",
            "/api/login",
            json!({"scope":"vnc","password":"秘密🙂 long password"}),
            &cookies,
            csrf,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let session = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let cookies = format!("{cookies}; {session}");
        let status =
            value(call(&app, "GET", "/api/status", Value::Null, &cookies, "", None).await).await;
        assert_eq!(status["vnc_authenticated"], true);
        assert_eq!(
            call(
                &app,
                "PUT",
                "/api/security",
                json!({"scope":"settings","password":""}),
                &cookies,
                csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            call(&app, "GET", "/api/keys", Value::Null, &cookies, "", None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = call(
            &app,
            "POST",
            "/api/login",
            json!({"scope":"settings","password":""}),
            &cookies,
            csrf,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let settings_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let cookies = format!("{cookies}; {settings_cookie}");
        assert_eq!(
            call(&app, "GET", "/api/backup", Value::Null, &cookies, "", None)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                "PUT",
                "/api/security",
                json!({"scope":"vnc","password":"new"}),
                &cookies,
                csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        let status =
            value(call(&app, "GET", "/api/status", Value::Null, &cookies, "", None).await).await;
        assert_eq!(status["vnc_authenticated"], false);
        assert_eq!(status["settings_authenticated"], true);
        assert!(revoked.has_changed().unwrap());
        revoked.borrow_and_update();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn csrf_is_cookie_bound_and_backup_redacts_by_default() {
        let (app, dir) = app();
        let status = value(call(&app, "GET", "/api/status", Value::Null, "", "", None).await).await;
        let t = status["csrf_token"].as_str().unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/logout",
                json!({"scope":"settings"}),
                "",
                t,
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let mut i = app.inner.lock().await;
        i.store.data.keys.push(KeyConfig {
            id: "key1".into(),
            name: "Test".into(),
            provider_label: "webauthn-browser".into(),
            attachment: "cross-platform".into(),
            enabled: true,
            automatic_presence: false,
            simulated_uv: false,
            presence_timeout_seconds: 120,
            resident_key_supported: true,
            attestation_mode: cdp::AttestationMode::None,
            attestation_identity: None,
            model_aaguid: cdp::DEFAULT_MODEL_AAGUID.into(),
            pin_hash: None,
            credentials: vec![
                json!({"credentialId":"id","rpId":"example.com","privateKey":"secret-key"}),
            ],
        });
        drop(i);
        let public = value(call(&app, "GET", "/api/keys", Value::Null, "", "", None).await).await;
        assert!(!public.to_string().contains("secret-key"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn login_budget_survives_csrf_rotation() {
        let (app, dir) = app();
        app.inner
            .lock()
            .await
            .attempts
            .insert("vnc".into(), (Instant::now(), 10));
        for _ in 0..2 {
            let status =
                value(call(&app, "GET", "/api/status", Value::Null, "", "", None).await).await;
            let t = status["csrf_token"].as_str().unwrap();
            assert_eq!(
                call(
                    &app,
                    "POST",
                    "/api/login",
                    json!({"scope":"vnc","password":"guess"}),
                    &format!("ab_csrf={t}"),
                    t,
                    None
                )
                .await
                .status(),
                StatusCode::TOO_MANY_REQUESTS
            );
        }
        assert_eq!(app.inner.lock().await.attempts.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
