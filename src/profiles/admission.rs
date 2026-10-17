//! A fixed profile context is selected before handler execution. Internal scope
//! headers are overwritten, never trusted from the network.
use super::{access, viewer};
use crate::{app::App, http::error::fail};
use axum::{
    body::Body,
    http::{HeaderValue, Request, StatusCode},
    response::Response,
};
fn owner_route(path: &str) -> bool {
    path.starts_with("/api/browser/")
        || path.starts_with("/api/requests")
        || ((path.starts_with("/api/helper/") || path.starts_with("/api/companion/"))
            && !path.ends_with("/downloads"))
        || path == "/api/clipboard/ws"
}
pub(crate) async fn prepare(
    app: &App,
    req: &mut Request<Body>,
) -> Result<(), (StatusCode, String)> {
    req.headers_mut().remove("x-auth-profile");
    req.headers_mut().remove("x-auth-profile-name");
    req.headers_mut().remove("x-require-owner");
    if app.profiles.is_none() {
        return Ok(());
    }
    req.headers_mut().insert(
        "x-auth-profile",
        HeaderValue::from_str(&app.profile_id).unwrap(),
    );
    let name = {
        let inner = app.inner.lock().await;
        let profile = inner
            .store
            .data
            .profile(&app.profile_id)
            .ok_or_else(|| fail(StatusCode::NOT_FOUND, "配置不存在。"))?;
        if app
            .profile_name
            .as_deref()
            .is_some_and(|name| name != profile.name)
        {
            return Err(fail(StatusCode::NOT_FOUND, "配置不存在。"));
        }
        profile.name.clone()
    };
    req.headers_mut()
        .insert("x-auth-profile-name", HeaderValue::from_str(&name).unwrap());
    let path = req.uri().path().to_owned();
    if !app.profile_scope
        && (owner_route(&path) || path == "/ws" || path.starts_with("/api/viewer/"))
    {
        return Err(fail(StatusCode::BAD_REQUEST, "请使用明确的配置路径。"));
    }
    let kind = match path.as_str() {
        "/ws" => Some("vnc"),
        "/api/clipboard/ws" => Some("clipboard"),
        _ => None,
    };
    if let Some(kind) = kind {
        let ticket = req
            .uri()
            .query()
            .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("ticket=")))
            .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "需要一次性连接票据。"))?
            .to_owned();
        let mut i = app.inner.lock().await;
        let captured = viewer::consume_ticket(&mut i, &app.profile_id, kind, &ticket)
            .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "连接票据已失效。"))?;
        if access::token_hash(req.headers()) != access::token_hash(&captured) {
            return Err(fail(StatusCode::UNAUTHORIZED, "连接授权已变更。"));
        }
        for name in ["x-viewer-token", "x-owner-generation", "x-csrf-token"] {
            if let Some(v) = captured.get(name) {
                req.headers_mut().insert(name, v.clone());
            }
        }
        if !viewer::viewer_live(&i, req.headers()) {
            return Err(fail(StatusCode::UNAUTHORIZED, "查看连接已失效。"));
        }
    }
    if owner_route(&path) {
        let i = app.inner.lock().await;
        if !access::authorized(&i, req.headers()) {
            return Err(fail(StatusCode::UNAUTHORIZED, "配置需要登录。"));
        }
        if !viewer::is_owner(&i, req.headers()) {
            return Err(fail(StatusCode::FORBIDDEN, "当前标签页不是引擎控制者。"));
        }
        req.headers_mut()
            .insert("x-require-owner", HeaderValue::from_static("1"));
    }
    // Renew access after authenticated use, independently from engine activity.
    if let Some(hash) = access::token_hash(req.headers()) {
        let mut i = app.inner.lock().await;
        let now = access::now();
        if access::valid_token(&i, req.headers(), &app.profile_id)
            && access::authorized(&i, req.headers())
        {
            if let Some(index) = i
                .store
                .data
                .profile_access_tokens
                .iter()
                .position(|t| t.token_hash == hash && t.profile_id == app.profile_id.as_ref())
            {
                if i.store.data.profile_access_tokens[index].last_used_at < now {
                    let previous = i.store.data.clone();
                    i.store.data.profile_access_tokens[index].last_used_at = now;
                    super::commit(&mut i, previous)?;
                }
            }
        }
    }
    Ok(())
}
pub(crate) async fn renew_cookie(
    app: &App,
    req_headers: &axum::http::HeaderMap,
    response: &mut Response,
) {
    if app.profiles.is_some() && app.profile_scope {
        let Some(profile_name) = access::profile_name(req_headers) else {
            return;
        };
        let name = access::COOKIE_NAME;
        if let Some(raw) = crate::auth::cookie(req_headers, name) {
            if !response
                .headers()
                .get_all(axum::http::header::SET_COOKIE)
                .iter()
                .any(|v| {
                    v.to_str()
                        .ok()
                        .is_some_and(|v| v.starts_with(&format!("{name}=")))
                })
            {
                let i = app.inner.lock().await;
                let valid = access::valid_token(&i, req_headers, &app.profile_id);
                let enabled = i
                    .store
                    .data
                    .profile(&app.profile_id)
                    .is_some_and(|p| i.store.data.effective_enabled(p));
                // Preserve remembered access through a mode override without
                // extending either side of the inactivity deadline while blocked.
                if valid && !enabled {
                    return;
                }
                drop(i);
                access::set_cookie(response, profile_name, if valid { raw } else { "" }, !valid);
            }
        }
    }
}
