//! Profile administration is global settings authority; browser access stays scoped.
use crate::{
    app::App,
    auth::authorize,
    http::error::{fail, ApiResult},
    storage::profiles::{canonical_name, Profile, MAX_PROFILES},
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
fn password_field<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Update {
    name: Option<String>,
    enabled: Option<bool>,
    idle_timeout_seconds: Option<i64>,
    #[serde(default, deserialize_with = "password_field")]
    password: Option<Option<String>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    multi_profile: bool,
}
fn summary(data: &crate::storage::store::Data, p: &Profile) -> Value {
    json!({"id":p.id,"name":p.name,"enabled":p.enabled,"effective_enabled":data.effective_enabled(p),"password_enabled":data.profile_password(p).is_some(),"password_required":data.profile_password(p).is_some(),"idle_timeout_seconds":p.idle_timeout_seconds})
}
/// Public browser identity is the editable canonical name. Immutable storage
/// identities are returned only by the settings-authorized administration API.
pub(crate) fn public_summary(data: &crate::storage::store::Data, p: &Profile) -> Value {
    json!({"name":p.name,"enabled":p.enabled,"effective_enabled":data.effective_enabled(p),"password_enabled":data.profile_password(p).is_some(),"password_required":data.profile_password(p).is_some(),"idle_timeout_seconds":p.idle_timeout_seconds})
}
pub(crate) async fn list(State(app): State<App>, h: HeaderMap) -> ApiResult {
    let i = app.inner.lock().await;
    authorize(&i, &h, "settings")?;
    Ok(Json(
        json!({"multi_profile":i.store.data.multi_profile,"profiles":i.store.data.profiles.iter().map(|p|summary(&i.store.data,p)).collect::<Vec<_>>()}),
    ))
}
pub(crate) async fn public(State(app): State<App>) -> ApiResult {
    let i = app.inner.lock().await;
    Ok(Json(
        json!({"multi_profile":i.store.data.multi_profile,"profiles":i.store.data.profiles.iter().filter(|p|i.store.data.effective_enabled(p)).map(|p|public_summary(&i.store.data,p)).collect::<Vec<_>>()}),
    ))
}
async fn hashed(input: &Update) -> Result<Option<Option<String>>, (StatusCode, String)> {
    let Some(password) = input.password.clone() else {
        return Ok(None);
    };
    let Some(password) = password else {
        return Ok(Some(None));
    };
    if password.is_empty() || password.len() > 4096 {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "密码不能为空或超过 4096 字节；清除密码请使用 null。",
        ));
    }
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        PasswordHasher,
    };
    let hash = tokio::task::spawn_blocking(move || {
        argon2::Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .map(|v| v.to_string())
            .map_err(|_| ())
    })
    .await
    .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "密码处理失败。"))?
    .map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "密码处理失败。"))?;
    Ok(Some(Some(hash)))
}
fn name(value: &str) -> Result<String, (StatusCode, String)> {
    canonical_name(value).ok_or_else(|| {
        fail(
            StatusCode::BAD_REQUEST,
            "名称必须为 1–100 个英文字母、数字或 ._-，且不能是 .、.. 或以 .git、.wiki 结尾。",
        )
    })
}
fn check_input(input: &Update) -> Result<(), (StatusCode, String)> {
    if let Some(n) = input.idle_timeout_seconds {
        if !(1..=86400).contains(&n) {
            return Err(fail(StatusCode::BAD_REQUEST, "空闲超时必须为 1–86400 秒。"));
        }
    }
    Ok(())
}
pub(crate) async fn create(
    State(app): State<App>,
    h: HeaderMap,
    Json(input): Json<Update>,
) -> ApiResult {
    let _op = app.operations.lock().await;
    {
        authorize(&*app.inner.lock().await, &h, "settings")?;
    }
    check_input(&input)?;
    let name = name(
        input
            .name
            .as_deref()
            .ok_or_else(|| fail(StatusCode::BAD_REQUEST, "请输入配置名称。"))?,
    )?;
    let password = hashed(&input).await?.flatten();
    let mut i = app.inner.lock().await;
    authorize(&i, &h, "settings")?;
    if name == "default" || i.store.data.profiles.iter().any(|p| p.name == name) {
        return Err(fail(StatusCode::CONFLICT, "配置名称已存在。"));
    }
    if i.store.data.profiles.len() + i.store.data.pending_profile_cleanup.len() >= MAX_PROFILES * 2
        || i.store.data.profiles.len() >= MAX_PROFILES
        || app
            .profiles
            .as_ref()
            .is_some_and(|r| r.context_count() + i.store.data.profiles.len() >= MAX_PROFILES * 2)
    {
        return Err(fail(StatusCode::BAD_REQUEST, "最多支持 16 个配置。"));
    }
    let old = i.store.data.clone();
    let p = Profile {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        enabled: input.enabled.unwrap_or(true),
        idle_timeout_seconds: input.idle_timeout_seconds.unwrap_or(180) as u64,
        password_hash: password,
        auth_revision: 0,
    };
    i.store.data.profiles.push(p.clone());
    super::commit(&mut i, old)?;
    Ok(Json(summary(&i.store.data, &p)))
}
pub(crate) async fn edit(
    State(app): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Update>,
) -> ApiResult {
    let _op = app.operations.lock().await;
    {
        authorize(&*app.inner.lock().await, &h, "settings")?;
    }
    check_input(&input)?;
    let password = hashed(&input).await?;
    let mut i = app.inner.lock().await;
    authorize(&i, &h, "settings")?;
    let idx = i
        .store
        .data
        .profiles
        .iter()
        .position(|p| p.id == id)
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "配置不存在。"))?;
    let renamed = input.name.as_deref().map(name).transpose()?;
    if id == "default" && renamed.as_deref().is_some_and(|n| n != "default") {
        return Err(fail(StatusCode::BAD_REQUEST, "默认配置不能重命名。"));
    }
    if renamed.as_ref().is_some_and(|n| {
        i.store
            .data
            .profiles
            .iter()
            .any(|p| p.id != id && &p.name == n)
    }) {
        return Err(fail(StatusCode::CONFLICT, "配置名称已存在。"));
    }
    let old = i.store.data.clone();
    let stop = input.enabled == Some(false) && i.store.data.multi_profile;
    // A rename invalidates both the old name and its credentials, including a
    // later reuse of that name for this same immutable profile.
    let rename_changed = renamed
        .as_ref()
        .is_some_and(|n| n != &i.store.data.profiles[idx].name);
    let revoke = password.is_some() || stop || rename_changed;
    {
        let p = &mut i.store.data.profiles[idx];
        if let Some(n) = renamed {
            p.name = n;
        }
        if let Some(enabled) = input.enabled {
            p.enabled = enabled;
        }
        if let Some(timeout) = input.idle_timeout_seconds {
            p.idle_timeout_seconds = timeout as u64;
        }
        if revoke {
            p.auth_revision = p
                .auth_revision
                .checked_add(1)
                .ok_or_else(|| fail(StatusCode::CONFLICT, "授权版本已耗尽。"))?;
        }
        if id != "default" {
            if let Some(hash) = &password {
                p.password_hash = hash.clone();
            }
        }
    }
    if id == "default" {
        if let Some(hash) = password {
            i.store.data.vnc_password_hash = hash;
        }
    }
    if revoke {
        i.store
            .data
            .profile_access_tokens
            .retain(|t| t.profile_id != id);
    }
    if stop && !i.store.data.pending_profile_cleanup.contains(&id) {
        i.store.data.pending_profile_cleanup.push(id.clone());
    }
    super::commit(&mut i, old)?;
    let result = summary(&i.store.data, &i.store.data.profiles[idx]);
    if revoke {
        super::viewer::clear(&mut i, &id);
    }
    drop(i);
    if stop {
        super::finish_cleanup(&app, &id).await?;
    } else if revoke {
        if let Some(r) = &app.profiles {
            let _ = r.revoke(&id, false).await;
        }
    }
    Ok(Json(result))
}
pub(crate) async fn delete(
    State(app): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let _op = app.operations.lock().await;
    let mut i = app.inner.lock().await;
    authorize(&i, &h, "settings")?;
    if id == "default" {
        return Err(fail(StatusCode::BAD_REQUEST, "默认配置不能删除。"));
    }
    if i.store.data.profile(&id).is_none() {
        if !i.store.data.pending_profile_cleanup.contains(&id) {
            return Err(fail(StatusCode::NOT_FOUND, "配置不存在。"));
        }
        let deleting_data = i.store.data.pending_profile_deletion.contains(&id);
        drop(i);
        if deleting_data {
            super::finish_deletion(&app, &id).await?;
        } else {
            super::finish_cleanup(&app, &id).await?;
        }
        return Ok(Json(
            json!({"ok":true,"browser_data_retained":!deleting_data}),
        ));
    }
    let old = i.store.data.clone();
    i.store.data.profiles.retain(|p| p.id != id);
    i.store
        .data
        .profile_access_tokens
        .retain(|t| t.profile_id != id);
    if !i.store.data.pending_profile_cleanup.contains(&id) {
        i.store.data.pending_profile_cleanup.push(id.clone());
    }
    i.store.data.pending_profile_deletion.push(id.clone());
    super::commit(&mut i, old)?;
    super::viewer::clear(&mut i, &id);
    drop(i);
    super::finish_deletion(&app, &id).await?;
    Ok(Json(json!({"ok":true,"browser_data_retained":false})))
}
pub(crate) async fn configure(
    State(app): State<App>,
    h: HeaderMap,
    Json(input): Json<Config>,
) -> ApiResult {
    let _op = app.operations.lock().await;
    let mut i = app.inner.lock().await;
    authorize(&i, &h, "settings")?;
    let old = i.store.data.clone();
    i.store.data.multi_profile = input.multi_profile;
    let disabled: Vec<_> = i
        .store
        .data
        .profiles
        .iter()
        .filter(|p| old.effective_enabled(p) && !i.store.data.effective_enabled(p))
        .map(|p| p.id.clone())
        .collect();
    // Availability changes retire live engines, not remembered identity.
    // Explicit password/profile revocation still owns auth_revision changes.
    for id in &disabled {
        if !i.store.data.pending_profile_cleanup.contains(id) {
            i.store.data.pending_profile_cleanup.push(id.clone());
        }
    }
    super::commit(&mut i, old)?;
    for id in &disabled {
        super::viewer::clear(&mut i, id);
    }
    let cleanup = i.store.data.pending_profile_cleanup.clone();
    drop(i);
    if app.profiles.is_some() {
        for id in cleanup {
            super::finish_cleanup(&app, &id).await?;
        }
    }
    Ok(Json(json!({"ok":true,"multi_profile":input.multi_profile})))
}
pub(crate) async fn scoped(
    axum::extract::State(root): State<App>,
    mut req: axum::http::Request<axum::body::Body>,
) -> Response {
    use tower::ServiceExt;
    let Some(registry) = root.profiles.clone() else {
        return fail(StatusCode::NOT_FOUND, "配置功能不可用。").into_response();
    };
    let Some((supplied_name, path)) = req
        .uri()
        .path()
        .strip_prefix("/p/")
        .and_then(|p| p.split_once('/'))
        .map(|(name, path)| (name.to_owned(), path.to_owned()))
    else {
        return fail(StatusCode::BAD_REQUEST, "请求路径无效。").into_response();
    };
    let Some(name) = canonical_name(&supplied_name) else {
        return fail(StatusCode::NOT_FOUND, "配置不存在。").into_response();
    };
    // Cookie paths are case sensitive. Canonicalize before reading or minting
    // credentials so every spelling uses the same browser cookie jar entry.
    if name != supplied_name {
        let query = req
            .uri()
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        return axum::response::Redirect::temporary(&format!("/p/{name}/{path}{query}"))
            .into_response();
    }
    let id = root
        .inner
        .lock()
        .await
        .store
        .data
        .profiles
        .iter()
        .find(|profile| profile.name == name)
        .map(|profile| profile.id.clone());
    let Some(id) = id else {
        // A saved local name may outlive a rename/removal. Clear only that
        // name's cookie; never follow it to another profile or runtime context.
        if req.method() != axum::http::Method::POST || path != "api/logout" {
            return fail(StatusCode::NOT_FOUND, "配置不存在。").into_response();
        }
        if let Err(error) = crate::auth::csrf(&*root.inner.lock().await, req.headers()) {
            return error.into_response();
        }
        let Ok(body) = axum::body::to_bytes(req.into_body(), 1024).await else {
            return fail(StatusCode::BAD_REQUEST, "退出请求无效。").into_response();
        };
        if serde_json::from_slice::<Value>(&body).ok() != Some(json!({"scope":"vnc"})) {
            return fail(StatusCode::BAD_REQUEST, "退出请求无效。").into_response();
        }
        let mut response = Json(json!({"ok":true})).into_response();
        super::access::set_cookie(&mut response, &name, "", true);
        return response;
    };
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let Ok(uri) = format!("/{path}{query}").parse() else {
        return fail(StatusCode::BAD_REQUEST, "请求路径无效。").into_response();
    };
    *req.uri_mut() = uri;
    req.extensions_mut().remove::<axum::extract::OriginalUri>();
    let mut app = registry.context(&root, &id);
    app.profile_name = Some(std::sync::Arc::from(name));
    crate::http::profile_router(app).oneshot(req).await.unwrap()
}
pub(crate) async fn engine(
    State(root): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult {
    let r = root
        .profiles
        .as_ref()
        .ok_or_else(|| fail(StatusCode::SERVICE_UNAVAILABLE, "runtime unavailable"))?;
    if r.manager.token.as_deref()
        != headers
            .get("x-profile-control-token")
            .and_then(|v| v.to_str().ok())
        || r.manager.token.is_none()
    {
        return Err(fail(
            StatusCode::UNAUTHORIZED,
            "runtime authorization required",
        ));
    }
    if root.inner.lock().await.store.data.profile(&id).is_none() {
        return Err(fail(StatusCode::NOT_FOUND, "profile unavailable"));
    }
    let app = r.context(&root, &id);
    let b = app.broker.lock().await;
    Ok(Json(
        json!({"engine_connected":b.ready,"control_connected":b.outbound.is_some(),"native_qr_mode":b.native_qr_mode,"mode_error":b.mode_error}),
    ))
}
