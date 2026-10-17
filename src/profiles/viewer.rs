//! Tab capabilities and engine ownership. Polling and transport heartbeats never
//! update last_activity; only explicit UI activity and parsed RFB input do.
use super::access;
use crate::{
    app::{App, Inner},
    auth::{cookie, token},
    http::error::{fail, ApiResult},
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
#[derive(Default)]
pub(crate) struct Viewers {
    entries: Vec<Viewer>,
    owner: Option<String>,
    generation: u64,
}
struct Viewer {
    id: String,
    hash: String,
    access: Option<String>,
    csrf: String,
    last_activity: Instant,
    admitted: Instant,
    connected: usize,
    connection_id: u64,
    handoff_until: Option<Instant>,
    expired: bool,
    ready: bool,
}
pub(crate) struct Ticket {
    pub headers: HeaderMap,
    pub profile: String,
    pub kind: String,
    expires: Instant,
}
fn supplied(h: &HeaderMap) -> Option<String> {
    h.get("x-viewer-token")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() == 64)
        .map(access::digest)
}
fn generation(h: &HeaderMap) -> Option<u64> {
    h.get("x-owner-generation")
        .and_then(|v| v.to_str().ok())?
        .parse()
        .ok()
}
fn valid_viewer(inner: &Inner, id: &str, v: &Viewer) -> bool {
    let Some(p) = inner.store.data.profile(id) else {
        return false;
    };
    inner.store.data.effective_enabled(p)
        && inner.csrf.get(&v.csrf).is_some_and(|t| *t > Instant::now())
        && match &v.access {
            None => inner.store.data.profile_password(p).is_none(),
            Some(hash) => inner.store.data.profile_access_tokens.iter().any(|t| {
                &t.token_hash == hash
                    && t.profile_id == id
                    && t.auth_revision == p.auth_revision
                    && t.last_used_at
                        .saturating_add(crate::storage::profiles::ACCESS_SECONDS)
                        > access::now()
            }),
        }
}
fn matches_viewer(h: &HeaderMap, v: &Viewer) -> bool {
    access::token_hash(h) == v.access && cookie(h, "ab_csrf") == Some(v.csrf.as_str())
}
pub(crate) fn is_owner(inner: &Inner, h: &HeaderMap) -> bool {
    let Some(id) = access::profile_id(h) else {
        return false;
    };
    let Some(hash) = supplied(h) else {
        return false;
    };
    let Some(state) = inner.profile_viewers.get(id) else {
        return false;
    };
    if state.owner.as_ref() != Some(&hash) || generation(h) != Some(state.generation) {
        return false;
    }
    state
        .entries
        .iter()
        .find(|v| v.hash == hash)
        .is_some_and(|v| {
            !v.expired
                && v.ready
                && matches_viewer(h, v)
                && valid_viewer(inner, id, v)
                && inner.store.data.profile(id).is_some_and(|p| {
                    v.connection_id == 0
                        || v.last_activity.elapsed() < Duration::from_secs(p.idle_timeout_seconds)
                })
        })
}
pub(crate) fn viewer_live(inner: &Inner, h: &HeaderMap) -> bool {
    let Some(id) = access::profile_id(h) else {
        return false;
    };
    let Some(hash) = supplied(h) else {
        return false;
    };
    inner.profile_viewers.get(id).is_some_and(|s| {
        s.entries
            .iter()
            .any(|v| v.hash == hash && matches_viewer(h, v) && valid_viewer(inner, id, v))
    })
}
fn body(inner: &Inner, id: &str, hash: &str) -> Option<Value> {
    let p = inner.store.data.profile(id)?;
    let state = inner.profile_viewers.get(id)?;
    let viewer = state.entries.iter().find(|v| v.hash == hash)?;
    Some(
        json!({"viewer_id":viewer.id,"owner":state.owner.as_deref()==Some(hash)&&!viewer.expired,"generation":state.generation,"expired":viewer.expired,"idle_timeout_seconds":p.idle_timeout_seconds,"idle_remaining_ms":Duration::from_secs(p.idle_timeout_seconds).saturating_sub(viewer.last_activity.elapsed()).as_millis() as u64}),
    )
}
fn elect(state: &mut Viewers) {
    state.owner = state
        .entries
        .iter_mut()
        .find(|v| !v.expired && v.ready && v.connected > 0)
        .map(|v| {
            v.last_activity = Instant::now();
            v.hash.clone()
        });
    state.generation = state
        .generation
        .checked_add(1)
        .expect("viewer generation exhausted");
}
pub(crate) fn empty(inner: &Inner, id: &str) -> bool {
    inner
        .profile_viewers
        .get(id)
        .is_none_or(|v| v.entries.is_empty())
}
pub(crate) fn socket_owner(inner: &Inner, h: &HeaderMap) -> bool {
    let Some(id) = access::profile_id(h) else {
        return false;
    };
    let Some(state) = inner.profile_viewers.get(id) else {
        return false;
    };
    let mut current = h.clone();
    current.insert(
        "x-owner-generation",
        state.generation.to_string().parse().unwrap(),
    );
    is_owner(inner, &current)
}
pub(crate) fn socket_activity(inner: &mut Inner, h: &HeaderMap) {
    let Some(id) = access::profile_id(h) else {
        return;
    };
    let Some(state) = inner.profile_viewers.get(id) else {
        return;
    };
    let mut current = h.clone();
    current.insert(
        "x-owner-generation",
        state.generation.to_string().parse().unwrap(),
    );
    mark_activity(inner, &current);
}
pub(crate) fn permit_handoff(inner: &mut Inner, h: &HeaderMap) {
    if !is_owner(inner, h) {
        return;
    }
    let hash = supplied(h).unwrap();
    if let Some(v) = inner
        .profile_viewers
        .get_mut(access::profile_id(h).unwrap())
        .and_then(|s| s.entries.iter_mut().find(|v| v.hash == hash))
    {
        v.handoff_until = Some(Instant::now() + Duration::from_secs(10));
    }
}

pub(crate) fn revoke_access(
    inner: &mut Inner,
    id: &str,
    hash: Option<&str>,
    viewer: Option<&str>,
) -> bool {
    let Some(state) = inner.profile_viewers.get_mut(id) else {
        return false;
    };
    let old = state.owner.clone();
    state.entries.retain(|v| {
        !hash.is_some_and(|h| v.access.as_deref() == Some(h))
            && !viewer.is_some_and(|h| v.hash == h)
    });
    if !state
        .entries
        .iter()
        .any(|v| Some(&v.hash) == state.owner.as_ref())
    {
        elect(state);
    }
    old != state.owner
}
// A dropped first admission must release only its unpublished reservation.
// Runtime initialization remains owned independently by the registry.
struct PendingAdmission {
    app: App,
    reservation: Option<(String, String, u64)>,
}
impl Drop for PendingAdmission {
    fn drop(&mut self) {
        let Some((hash, entry_id, generation)) = self.reservation.take() else {
            return;
        };
        let app = self.app.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                release_pending_admission(&app, &hash, &entry_id, generation).await;
            });
        }
    }
}
async fn release_pending_admission(app: &App, hash: &str, entry_id: &str, generation: u64) {
    let mut broker = app.broker.lock().await;
    let mut inner = app.inner.lock().await;
    let Some(state) = inner.profile_viewers.get_mut(app.profile_id.as_ref()) else {
        return;
    };
    if state.generation != generation
        || !state
            .entries
            .iter()
            .any(|v| v.hash == hash && v.id == entry_id && !v.ready && v.connected == 0)
    {
        return;
    }
    state.entries.retain(|v| v.hash != hash || v.id != entry_id);
    if state.owner.as_deref() == Some(hash) {
        elect(state);
        broker.cancel_all("Unpublished viewer admission canceled");
        app.revoked.send_modify(|n| *n = n.wrapping_add(1));
    }
}

pub(crate) async fn acquire(State(app): State<App>, h: HeaderMap) -> ApiResult {
    let _configuration = app.operations.lock().await;
    let id = app.profile_id.to_string();
    let registry = app
        .profiles
        .clone()
        .ok_or_else(|| fail(StatusCode::SERVICE_UNAVAILABLE, "配置功能未初始化。"))?;
    {
        let i = app.inner.lock().await;
        crate::auth::authorize(&i, &h, "vnc")?;
    }
    let raw = token();
    let proposed = access::digest(&raw);
    let previous = supplied(&h);
    if previous.is_some() && !viewer_live(&*app.inner.lock().await, &h) {
        return Err(fail(StatusCode::UNAUTHORIZED, "查看连接已失效。"));
    }
    let (hash, new, reservation) = {
        let _broker = app.broker.lock().await;
        let mut i = app.inner.lock().await;
        let state = i.profile_viewers.entry(id.clone()).or_default();
        if state.entries.len() >= 64
            && !previous
                .as_ref()
                .is_some_and(|hash| state.entries.iter().any(|v| &v.hash == hash))
        {
            return Err(fail(
                StatusCode::TOO_MANY_REQUESTS,
                "此配置的查看连接过多。",
            ));
        }
        let existing = previous.and_then(|hash| state.entries.iter_mut().find(|v| v.hash == hash));
        let (hash, new) = if let Some(v) = existing {
            v.expired = false;
            v.last_activity = Instant::now();
            (v.hash.clone(), false)
        } else {
            state.entries.push(Viewer {
                id: uuid::Uuid::new_v4().to_string(),
                hash: proposed.clone(),
                access: access::token_hash(&h),
                csrf: cookie(&h, "ab_csrf").unwrap_or("").into(),
                last_activity: Instant::now(),
                admitted: Instant::now(),
                connected: 0,
                connection_id: 0,
                handoff_until: None,
                expired: false,
                ready: false,
            });
            (proposed.clone(), true)
        };
        if state.owner.is_none() {
            state.owner = Some(hash.clone());
            state.generation += 1;
        }
        let reservation = new.then(|| {
            let entry = state.entries.iter().find(|v| v.hash == hash).unwrap();
            (hash.clone(), entry.id.clone(), state.generation)
        });
        (hash, new, reservation)
    };
    let mut pending = PendingAdmission {
        app: app.clone(),
        reservation,
    };
    drop(_configuration);
    if let Err(e) = registry.ensure(&app, &id).await {
        remove(&app, &hash).await;
        return Err(e);
    }
    let _configuration = app.operations.lock().await;
    let mut i = app.inner.lock().await;
    if !access::authorized(&i, &h) {
        drop(i);
        remove(&app, &hash).await;
        return Err(fail(StatusCode::UNAUTHORIZED, "配置授权已失效。"));
    }
    if let Some(v) = i
        .profile_viewers
        .get_mut(&id)
        .and_then(|s| s.entries.iter_mut().find(|v| v.hash == hash))
    {
        v.ready = true;
        v.last_activity = Instant::now();
    }
    let mut result =
        body(&i, &id, &hash).ok_or_else(|| fail(StatusCode::CONFLICT, "查看连接已失效。"))?;
    result["viewer_token"] = Value::String(if new {
        raw
    } else {
        h.get("x-viewer-token")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    });
    pending.reservation = None;
    Ok(Json(result))
}
pub(crate) async fn status(State(app): State<App>, h: HeaderMap) -> ApiResult {
    expire(&app).await;
    let i = app.inner.lock().await;
    crate::auth::authorize(&i, &h, "vnc")?;
    let hash = supplied(&h).ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "需要标签页令牌。"))?;
    if !viewer_live(&i, &h) {
        return Err(fail(StatusCode::UNAUTHORIZED, "查看连接已失效。"));
    }
    Ok(Json(body(&i, &app.profile_id, &hash).unwrap()))
}
pub(crate) async fn activity(State(app): State<App>, h: HeaderMap) -> ApiResult {
    expire(&app).await;
    let mut i = app.inner.lock().await;
    crate::auth::authorize(&i, &h, "vnc")?;
    if !is_owner(&i, &h) {
        return Err(fail(StatusCode::FORBIDDEN, "当前标签页不是引擎控制者。"));
    }
    mark_activity(&mut i, &h);
    Ok(Json(json!({"ok":true})))
}
pub(crate) fn mark_activity(inner: &mut Inner, h: &HeaderMap) {
    if !is_owner(inner, h) {
        return;
    }
    let id = access::profile_id(h).unwrap();
    let hash = supplied(h).unwrap();
    if let Some(v) = inner
        .profile_viewers
        .get_mut(id)
        .and_then(|s| s.entries.iter_mut().find(|v| v.hash == hash))
    {
        v.last_activity = Instant::now();
    }
}
pub(crate) async fn release(State(app): State<App>, h: HeaderMap) -> ApiResult {
    if let Some(hash) = supplied(&h) {
        {
            let inner = app.inner.lock().await;
            if inner
                .profile_viewers
                .get(app.profile_id.as_ref())
                .is_some_and(|s| generation(&h) != Some(s.generation))
            {
                return Err(fail(StatusCode::CONFLICT, "控制代次已改变。"));
            }
        }
        if !viewer_live(&*app.inner.lock().await, &h) {
            return Err(fail(StatusCode::UNAUTHORIZED, "查看连接已失效。"));
        }
        remove(&app, &hash).await;
    }
    Ok(Json(json!({"ok":true})))
}
async fn remove(app: &App, hash: &str) {
    let (changed, empty) = {
        let mut broker = app.broker.lock().await;
        let mut i = app.inner.lock().await;
        let Some(state) = i.profile_viewers.get_mut(app.profile_id.as_ref()) else {
            return;
        };
        let old = state.owner.clone();
        state.entries.retain(|v| v.hash != hash);
        if state.owner.as_deref() == Some(hash) {
            elect(state);
        }
        let changed = old != state.owner;
        if changed {
            broker.cancel_all("Engine owner released");
            app.revoked.send_modify(|n| *n = n.wrapping_add(1));
        }
        (changed, state.entries.is_empty())
    };
    let _ = (changed, empty);
}
pub(crate) async fn connected(app: &App, h: &HeaderMap) -> Option<u64> {
    let _broker = app.broker.lock().await;
    let mut i = app.inner.lock().await;
    if !viewer_live(&i, h) {
        return None;
    }
    let hash = supplied(h).unwrap();
    let v = i
        .profile_viewers
        .get_mut(app.profile_id.as_ref())?
        .entries
        .iter_mut()
        .find(|v| v.hash == hash)?;
    if v.connected > 0
        && v.handoff_until
            .is_none_or(|deadline| deadline <= Instant::now())
    {
        return None;
    }
    v.connected = 1;
    v.handoff_until = None;
    if v.connection_id == 0 {
        v.last_activity = Instant::now();
    }
    v.connection_id = v.connection_id.checked_add(1)?;
    let connection_id = v.connection_id;
    let state = i.profile_viewers.get_mut(app.profile_id.as_ref())?;
    if state.owner.is_none() {
        elect(state);
        app.revoked.send_modify(|n| *n = n.wrapping_add(1));
    }
    Some(connection_id)
}
pub(crate) async fn disconnected(app: &App, h: &HeaderMap, connection_id: u64) {
    let Some(hash) = supplied(h) else {
        return;
    };
    {
        let mut i = app.inner.lock().await;
        let Some(v) = i
            .profile_viewers
            .get_mut(app.profile_id.as_ref())
            .and_then(|s| s.entries.iter_mut().find(|v| v.hash == hash))
        else {
            return;
        };
        if v.connection_id != connection_id {
            return;
        }
        v.connected = 0;
        if v.handoff_until
            .is_some_and(|deadline| deadline > Instant::now())
        {
            return;
        }
    }
    remove(app, &hash).await;
}
pub(crate) async fn expire(app: &App) {
    let mut changed = false;
    let mut empty = false;
    {
        let mut broker = app.broker.lock().await;
        let mut i = app.inner.lock().await;
        let id = app.profile_id.as_ref();
        let Some(p) = i.store.data.profile(id) else {
            return;
        };
        let timeout = Duration::from_secs(p.idle_timeout_seconds);
        let invalid: Vec<String> = i
            .profile_viewers
            .get(id)
            .map(|s| {
                s.entries
                    .iter()
                    .filter(|v| {
                        !valid_viewer(&i, id, v)
                            || (v.connected == 0
                                && (v
                                    .handoff_until
                                    .is_some_and(|deadline| deadline <= Instant::now())
                                    || v.handoff_until.is_none()
                                        && v.admitted.elapsed() > Duration::from_secs(90)))
                    })
                    .map(|v| v.hash.clone())
                    .collect()
            })
            .unwrap_or_default();
        if let Some(state) = i.profile_viewers.get_mut(id) {
            let old = state.owner.clone();
            state.entries.retain(|v| !invalid.contains(&v.hash));
            if let Some(v) = state
                .entries
                .iter_mut()
                .find(|v| Some(&v.hash) == state.owner.as_ref())
            {
                if v.ready && v.connection_id > 0 && v.last_activity.elapsed() >= timeout {
                    v.expired = true;
                }
            }
            if !state
                .entries
                .iter()
                .any(|v| Some(&v.hash) == state.owner.as_ref() && !v.expired)
                && state.owner.is_some()
            {
                elect(state);
            }
            changed = old != state.owner;
            empty = state.entries.is_empty() && old.is_some();
            if changed {
                broker.cancel_all("Engine owner expired");
                app.revoked.send_modify(|n| *n = n.wrapping_add(1));
            }
        }
        i.viewer_tickets.retain(|_, t| t.expires > Instant::now());
    }
    let _ = (changed, empty);
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TicketRequest {
    kind: String,
}
pub(crate) async fn ticket(
    State(app): State<App>,
    h: HeaderMap,
    Json(input): Json<TicketRequest>,
) -> ApiResult {
    if !matches!(input.kind.as_str(), "vnc" | "clipboard" | "events") {
        return Err(fail(StatusCode::BAD_REQUEST, "连接类型无效。"));
    }
    expire(&app).await;
    let mut i = app.inner.lock().await;
    crate::auth::authorize(&i, &h, "vnc")?;
    if !viewer_live(&i, &h) || input.kind != "vnc" && !is_owner(&i, &h) {
        return Err(fail(StatusCode::FORBIDDEN, "当前标签页没有此连接权限。"));
    }
    i.viewer_tickets.retain(|_, t| t.expires > Instant::now());
    if i.viewer_tickets.len() >= 4096 {
        return Err(fail(StatusCode::TOO_MANY_REQUESTS, "连接票据过多。"));
    }
    let raw = token();
    i.viewer_tickets.insert(
        access::digest(&raw),
        Ticket {
            headers: h,
            profile: app.profile_id.to_string(),
            kind: input.kind,
            expires: Instant::now() + Duration::from_secs(10),
        },
    );
    Ok(Json(json!({"ticket":raw,"expires_in_ms":10000})))
}
pub(crate) fn consume_ticket(
    inner: &mut Inner,
    id: &str,
    kind: &str,
    raw: &str,
) -> Option<HeaderMap> {
    let t = inner.viewer_tickets.remove(&access::digest(raw))?;
    (t.profile == id && t.kind == kind && t.expires > Instant::now()).then_some(t.headers)
}
pub(crate) fn clear(inner: &mut Inner, id: &str) {
    inner.profile_viewers.remove(id);
    inner.viewer_tickets.retain(|_, t| t.profile != id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{profiles::Registry, test_support};
    use std::sync::Arc;
    async fn fixture() -> (App, App, HeaderMap, std::path::PathBuf) {
        let (mut root, dir) = test_support::app();
        let registry = Registry::test_ready();
        root.profiles = Some(registry.clone());
        let mut app = registry.context(&root, "default");
        let mut endpoint = (*app.endpoints).clone();
        endpoint.runtime_epoch = Some("ab".repeat(16));
        app.endpoints = Arc::new(endpoint);
        let mut stored = app.clone();
        stored.profiles = None;
        registry
            .contexts
            .lock()
            .unwrap()
            .insert("default".into(), stored);
        let mut h = HeaderMap::new();
        h.insert("x-auth-profile", "default".parse().unwrap());
        h.insert("cookie", "ab_csrf=fixture-csrf".parse().unwrap());
        h.insert("x-csrf-token", "fixture-csrf".parse().unwrap());
        app.inner.lock().await.csrf.insert(
            "fixture-csrf".into(),
            Instant::now() + Duration::from_secs(3600),
        );
        (root, app, h, dir)
    }
    fn headers(base: &HeaderMap, value: &Value) -> HeaderMap {
        let mut h = base.clone();
        h.insert(
            "x-viewer-token",
            value["viewer_token"].as_str().unwrap().parse().unwrap(),
        );
        h.insert(
            "x-owner-generation",
            value["generation"]
                .as_u64()
                .unwrap()
                .to_string()
                .parse()
                .unwrap(),
        );
        h
    }
    async fn admitted(app: &App, h: &HeaderMap) -> (Value, HeaderMap) {
        let value = acquire(State(app.clone()), h.clone()).await.unwrap().0;
        let h = headers(h, &value);
        (value, h)
    }
    #[tokio::test]
    async fn skipped_stop_for_a_new_viewer_cannot_clear_durable_cleanup_intent() {
        let (root, app, h, dir) = fixture().await;
        let (_, owner) = admitted(&app, &h).await;
        {
            let mut inner = root.inner.lock().await;
            inner
                .store
                .data
                .pending_profile_cleanup
                .push("default".into());
            inner.store.save().unwrap();
        }
        let before = std::fs::read(dir.join("store.json")).unwrap();
        assert_eq!(
            crate::profiles::finish_cleanup(&root, "default")
                .await
                .unwrap_err()
                .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(is_owner(&*app.inner.lock().await, &owner));
        assert_eq!(std::fs::read(dir.join("store.json")).unwrap(), before);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn confirmed_runtime_retirement_revokes_old_viewers_tickets_and_helpers() {
        let (root, app, h, dir) = fixture().await;
        let (_, owner) = admitted(&app, &h).await;
        let token = ticket(
            State(app.clone()),
            owner.clone(),
            Json(TicketRequest { kind: "vnc".into() }),
        )
        .await
        .unwrap()
        .0;
        let helper = crate::relay::helper::Session::new(&*app.inner.lock().await, &owner);
        app.broker.lock().await.helper = Some(helper);
        let revoked = *app.revoked.borrow();
        let registry = root.profiles.as_ref().unwrap();
        let _lifecycle = registry.lifecycle.lock().await;
        assert!(
            !registry
                .retire_confirmed(&root, "default", Some(&"cd".repeat(16)))
                .await
        );
        assert!(is_owner(&*app.inner.lock().await, &owner));
        assert!(app.broker.lock().await.helper.is_some());
        assert!(
            registry
                .retire_confirmed(&root, "default", Some(&"ab".repeat(16)))
                .await
        );
        {
            let mut inner = app.inner.lock().await;
            assert!(!is_owner(&inner, &owner));
            assert!(!viewer_live(&inner, &owner));
            assert!(consume_ticket(
                &mut inner,
                "default",
                "vnc",
                token["ticket"].as_str().unwrap()
            )
            .is_none());
        }
        assert!(app.broker.lock().await.helper.is_none());
        assert!(*app.revoked.borrow() > revoked);
        assert!(!registry.has_context("default"));
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn mode_override_revokes_live_authority_even_when_cleanup_is_unconfirmed() {
        let (root, app, mut h, dir) = fixture().await;
        let raw = "11".repeat(32);
        h.insert(
            "cookie",
            format!("ab_csrf=fixture-csrf; ab_profile_access={raw}")
                .parse()
                .unwrap(),
        );
        {
            let mut i = app.inner.lock().await;
            // Single-profile mode currently overrides the saved disabled state.
            i.store.data.profiles[0].enabled = false;
            i.store
                .data
                .profile_access_tokens
                .push(crate::storage::profiles::AccessToken {
                    token_hash: access::digest(&raw),
                    profile_id: "default".into(),
                    auth_revision: 0,
                    last_used_at: access::now(),
                });
        }
        let (_, owner) = admitted(&app, &h).await;
        let token = ticket(
            State(app.clone()),
            owner.clone(),
            Json(TicketRequest { kind: "vnc".into() }),
        )
        .await
        .unwrap()
        .0;
        let session = crate::relay::helper::Session::new(&*app.inner.lock().await, &owner);
        app.broker.lock().await.helper = Some(session);
        let response = test_support::call(
            &root,
            "PUT",
            "/api/profiles/config",
            json!({"multi_profile":true}),
            "ab_csrf=fixture-csrf",
            "fixture-csrf",
            None,
        )
        .await;
        // The fixture has no runtime manager; no cleanup success is fabricated.
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        {
            let mut i = app.inner.lock().await;
            assert!(!is_owner(&i, &owner));
            assert!(!viewer_live(&i, &owner));
            assert!(
                consume_ticket(&mut i, "default", "vnc", token["ticket"].as_str().unwrap())
                    .is_none()
            );
            assert!(access::valid_token(&i, &h, "default"));
            assert_eq!(i.store.data.profile("default").unwrap().auth_revision, 0);
            assert_eq!(i.store.data.pending_profile_cleanup, vec!["default"]);
        }
        assert!(app.broker.lock().await.helper.is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn scoped_owner_stream_admission_snapshot_and_release_eof() {
        use axum::{body::Body, http::Request};
        use futures_util::StreamExt;
        use tower::ServiceExt;
        let (root, app, base, dir) = fixture().await;
        let (_, owner) = admitted(&app, &base).await;
        let (_, standby) = admitted(&app, &base).await;
        let route = crate::http::router(root);
        let request = |headers: HeaderMap| {
            let mut req = Request::builder()
                .uri("/p/default/api/requests/events")
                .body(Body::empty())
                .unwrap();
            *req.headers_mut() = headers;
            req
        };
        assert_eq!(
            route
                .clone()
                .oneshot(request(standby))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut no_csrf = owner.clone();
        no_csrf.remove("x-csrf-token");
        assert_eq!(
            route
                .clone()
                .oneshot(request(no_csrf))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let response = route.oneshot(request(owner.clone())).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        let mut body = response.into_body().into_data_stream();
        let bytes = body.next().await.unwrap().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("event: snapshot") && text.contains("\"requests\":[]"));
        let _ = release(State(app.clone()), owner).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), body.next())
            .await
            .unwrap()
            .is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn simultaneous_tabs_share_login_but_only_one_engine_owner() {
        let (_, app, h, dir) = fixture().await;
        let (a, b) = tokio::join!(
            acquire(State(app.clone()), h.clone()),
            acquire(State(app.clone()), h.clone())
        );
        let a = a.unwrap().0;
        let b = b.unwrap().0;
        assert_ne!(a["viewer_token"], b["viewer_token"]);
        assert_ne!(a["owner"], b["owner"]);
        let inner = app.inner.lock().await;
        assert!(is_owner(&inner, &headers(&h, &a)));
        assert!(!is_owner(&inner, &headers(&h, &b)));
        drop(inner);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn polling_does_not_extend_idle_and_standby_promotion_gets_fresh_interval() {
        let (_, app, h, dir) = fixture().await;
        let (a, ha) = admitted(&app, &h).await;
        let (b, hb) = admitted(&app, &h).await;
        connected(&app, &ha).await.unwrap();
        connected(&app, &hb).await.unwrap();
        let old = Instant::now() - Duration::from_secs(181);
        {
            let mut i = app.inner.lock().await;
            for v in &mut i.profile_viewers.get_mut("default").unwrap().entries {
                v.last_activity = old;
            }
        }
        let expired = status(State(app.clone()), ha.clone()).await.unwrap().0;
        assert_eq!(expired["expired"], true);
        assert_eq!(expired["owner"], false);
        let promoted = status(State(app.clone()), hb.clone()).await.unwrap().0;
        assert_eq!(promoted["owner"], true);
        {
            let i = app.inner.lock().await;
            assert!(socket_owner(&i, &hb));
            assert!(!socket_owner(&i, &ha));
            assert!(!is_owner(&i, &hb));
        }
        assert!(promoted["idle_remaining_ms"].as_u64().unwrap() > 179000);
        assert_ne!(a["generation"], promoted["generation"]);
        assert_ne!(a["viewer_token"], b["viewer_token"]);
        let before = {
            let i = app.inner.lock().await;
            i.profile_viewers["default"].entries[1].last_activity
        };
        for _ in 0..4 {
            let _ = status(State(app.clone()), hb.clone()).await.unwrap();
        }
        assert_eq!(
            before,
            app.inner.lock().await.profile_viewers["default"].entries[1].last_activity
        );
        assert_eq!(
            activity(State(app.clone()), ha).await.unwrap_err().0,
            StatusCode::FORBIDDEN
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn late_release_cannot_cancel_new_owner_and_last_disconnect_preserves_runtime() {
        let (root, app, h, dir) = fixture().await;
        let (a, ha) = admitted(&app, &h).await;
        let (_, hb) = admitted(&app, &h).await;
        let ca = connected(&app, &ha).await.unwrap();
        let cb = connected(&app, &hb).await.unwrap();
        disconnected(&app, &ha, ca).await;
        let promoted = status(State(app.clone()), hb.clone()).await.unwrap().0;
        assert_eq!(promoted["owner"], true);
        assert_eq!(
            release(State(app.clone()), ha).await.unwrap_err().0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            status(State(app.clone()), hb.clone()).await.unwrap().0["owner"],
            true
        );
        disconnected(&app, &hb, cb).await;
        assert!(empty(&*app.inner.lock().await, "default"));
        assert!(root
            .profiles
            .as_ref()
            .unwrap()
            .context(&root, "default")
            .endpoints
            .runtime_epoch
            .is_some());
        assert_eq!(a["owner"], true);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn idle_reacquire_returns_existing_capability_and_rejects_stale_cleanup() {
        let (_, app, h, dir) = fixture().await;
        let (a, ha) = admitted(&app, &h).await;
        connected(&app, &ha).await.unwrap();
        app.inner
            .lock()
            .await
            .profile_viewers
            .get_mut("default")
            .unwrap()
            .entries[0]
            .last_activity = Instant::now() - Duration::from_secs(181);
        expire(&app).await;
        let reacquired = acquire(State(app.clone()), ha.clone()).await.unwrap().0;
        assert_eq!(a["viewer_token"], reacquired["viewer_token"]);
        assert_eq!(reacquired["owner"], true);
        assert_eq!(
            release(State(app.clone()), ha).await.unwrap_err().0,
            StatusCode::CONFLICT
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn anonymous_logout_removes_only_the_current_tab() {
        let (_, app, h, dir) = fixture().await;
        let (_, ha) = admitted(&app, &h).await;
        let (_, hb) = admitted(&app, &h).await;
        connected(&app, &ha).await.unwrap();
        connected(&app, &hb).await.unwrap();
        access::logout(&app, &ha).await.unwrap();
        let promoted = status(State(app.clone()), hb).await.unwrap().0;
        assert_eq!(promoted["owner"], true);
        assert_eq!(
            app.inner.lock().await.profile_viewers["default"]
                .entries
                .len(),
            1
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn tickets_are_one_use_profile_bound_and_standby_cannot_open_helper_stream() {
        let (_, app, h, dir) = fixture().await;
        let (_, ha) = admitted(&app, &h).await;
        let (_, hb) = admitted(&app, &h).await;
        assert_eq!(
            ticket(
                State(app.clone()),
                hb.clone(),
                Json(TicketRequest {
                    kind: "clipboard".into()
                })
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::FORBIDDEN
        );
        let value = ticket(
            State(app.clone()),
            ha,
            Json(TicketRequest { kind: "vnc".into() }),
        )
        .await
        .unwrap()
        .0;
        let raw = value["ticket"].as_str().unwrap();
        let mut i = app.inner.lock().await;
        assert!(consume_ticket(&mut i, "foreign", "vnc", raw).is_none());
        assert!(consume_ticket(&mut i, "default", "vnc", raw).is_none());
        drop(i);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn viewer_capability_is_bound_to_csrf_and_exact_profile() {
        let (_, app, h, dir) = fixture().await;
        let (_, mut ha) = admitted(&app, &h).await;
        ha.insert("cookie", "ab_csrf=another-csrf".parse().unwrap());
        assert!(!is_owner(&*app.inner.lock().await, &ha));
        assert!(!viewer_live(&*app.inner.lock().await, &ha));
        assert_eq!(
            acquire(State(app.clone()), ha).await.unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn intentional_rfb_handoff_keeps_owner_and_ignores_old_socket_cleanup() {
        let (_, app, h, dir) = fixture().await;
        let (_, ha) = admitted(&app, &h).await;
        let old = connected(&app, &ha).await.unwrap();
        permit_handoff(&mut *app.inner.lock().await, &ha);
        disconnected(&app, &ha, old).await;
        assert!(is_owner(&*app.inner.lock().await, &ha));
        let new = connected(&app, &ha).await.unwrap();
        assert!(new > old);
        disconnected(&app, &ha, old).await;
        assert!(is_owner(&*app.inner.lock().await, &ha));
        disconnected(&app, &ha, new).await;
        assert!(!is_owner(&*app.inner.lock().await, &ha));
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn delayed_first_attachment_does_not_consume_idle_budget_and_pending_standby_is_elected()
    {
        let (_, app, h, dir) = fixture().await;
        app.inner.lock().await.store.data.profiles[0].idle_timeout_seconds = 1;
        let (_, ha) = admitted(&app, &h).await;
        let (_, hb) = admitted(&app, &h).await;
        {
            let mut i = app.inner.lock().await;
            for v in &mut i.profile_viewers.get_mut("default").unwrap().entries {
                v.last_activity = Instant::now() - Duration::from_secs(10);
            }
        }
        expire(&app).await;
        assert!(is_owner(&*app.inner.lock().await, &ha));
        let _ = release(State(app.clone()), ha).await.unwrap();
        assert!(!socket_owner(&*app.inner.lock().await, &hb));
        connected(&app, &hb).await.unwrap();
        assert!(socket_owner(&*app.inner.lock().await, &hb));
        let state = status(State(app.clone()), hb).await.unwrap().0;
        assert_eq!(state["owner"], true);
        assert!(state["idle_remaining_ms"].as_u64().unwrap() > 900);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn canceled_new_acquire_releases_only_unpublished_reservation() {
        let (_root, app, h, dir) = fixture().await;
        let registry = app.profiles.as_ref().unwrap().clone();
        let blocked = registry.lifecycle.lock().await;
        let worker = app.clone();
        let caller = tokio::spawn(async move { acquire(State(worker), h).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while empty(&*app.inner.lock().await, "default") {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !empty(&*app.inner.lock().await, "default") {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(blocked);
        // The independently owned ensure can still finish without a viewer.
        tokio::task::yield_now().await;
        let _finished = registry.lifecycle.lock().await;
        assert!(empty(&*app.inner.lock().await, "default"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn canceled_existing_acquire_preserves_its_viewer() {
        let (_root, app, h, dir) = fixture().await;
        let (_, headers) = admitted(&app, &h).await;
        let registry = app.profiles.as_ref().unwrap().clone();
        let blocked = registry.lifecycle.lock().await;
        let worker = app.clone();
        let request = headers.clone();
        let caller = tokio::spawn(async move { acquire(State(worker), request).await });
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        drop(blocked);
        tokio::task::yield_now().await;
        assert!(is_owner(&*app.inner.lock().await, &headers));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn pending_cleanup_preserves_ready_replaced_and_successor_entries() {
        let (_root, app, h, dir) = fixture().await;
        let (_, headers) = admitted(&app, &h).await;
        let hash = supplied(&headers).unwrap();
        let (entry_id, generation) = {
            let inner = app.inner.lock().await;
            let state = &inner.profile_viewers["default"];
            (state.entries[0].id.clone(), state.generation)
        };
        release_pending_admission(&app, &hash, &entry_id, generation).await;
        assert!(is_owner(&*app.inner.lock().await, &headers));
        {
            let mut inner = app.inner.lock().await;
            inner.profile_viewers.get_mut("default").unwrap().entries[0].ready = false;
        }
        release_pending_admission(&app, &hash, "different-entry", generation).await;
        assert!(!empty(&*app.inner.lock().await, "default"));
        release_pending_admission(&app, &hash, &entry_id, generation + 1).await;
        assert!(!empty(&*app.inner.lock().await, "default"));
        release_pending_admission(&app, &hash, &entry_id, generation).await;
        assert!(empty(&*app.inner.lock().await, "default"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
