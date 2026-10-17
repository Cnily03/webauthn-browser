//! Immutable profile contexts, with shared credentials and isolated engine state.
pub(crate) mod access;
pub(crate) mod admission;
pub(crate) mod api;
pub(crate) mod cleanup;
pub(crate) mod rfb;
pub(crate) mod runtime;
pub(crate) mod viewer;

use crate::{
    app::App,
    browser::{broker::Broker, window_control},
    relay::fido_launcher,
};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
use tokio::sync::{watch, Mutex as AsyncMutex, Semaphore};

pub(crate) struct Registry {
    contexts: Mutex<HashMap<String, App>>,
    #[cfg(test)]
    fixture_runtime: bool,
    uncertain: Mutex<HashSet<String>>,
    cleanup_cursor: Mutex<usize>,
    pending_receipt_ack: Mutex<bool>,
    cleanup_pass: AsyncMutex<()>,
    pub(crate) lifecycle: AsyncMutex<()>,
    pub(crate) manager: runtime::Manager,
    revision_sequence: Mutex<u64>,
    jobs: Mutex<HashMap<String, Vec<tokio::task::JoinHandle<()>>>>,
}
impl Registry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            contexts: Mutex::new(HashMap::new()),
            #[cfg(test)]
            fixture_runtime: false,
            uncertain: Mutex::new(HashSet::new()),
            cleanup_cursor: Mutex::new(0),
            pending_receipt_ack: Mutex::new(false),
            cleanup_pass: AsyncMutex::new(()),
            lifecycle: AsyncMutex::new(()),
            manager: runtime::Manager::from_environment(),
            revision_sequence: Mutex::new(0),
            jobs: Mutex::new(HashMap::new()),
        })
    }
    #[cfg(test)]
    pub(crate) fn test_ready() -> Arc<Self> {
        let mut registry = Self::new();
        Arc::get_mut(&mut registry).unwrap().fixture_runtime = true;
        registry
    }
    pub(crate) fn context(self: &Arc<Self>, root: &App, id: &str) -> App {
        let mut contexts = self.contexts.lock().unwrap();
        let entry = contexts.entry(id.into()).or_insert_with(|| {
            let (revoked, _) = watch::channel(0);
            let mut app = root.clone();
            app.profile_scope = true;
            app.profile_name = None;
            app.profile_id = Arc::from(id);
            app.profiles = None;
            app.endpoints = Arc::new(runtime::Endpoints::for_profile(id));
            app.broker = Arc::new(AsyncMutex::new(Broker::default()));
            app.revoked = revoked;
            app.stream_slots = Arc::new(Semaphore::new(64));
            app.recovery_slots = Arc::new(Semaphore::new(1));
            app.window_control = Arc::new(window_control::Controller::default());
            app.fido_launcher = fido_launcher::Launcher::disabled();
            app
        });
        let mut app = entry.clone();
        app.profiles = Some(self.clone());
        app
    }
    pub(crate) fn jobs(&self, id: &str, jobs: Vec<tokio::task::JoinHandle<()>>) {
        if let Some(old) = self.jobs.lock().unwrap().insert(id.into(), jobs) {
            for job in old {
                job.abort();
            }
        }
    }
    fn proxy_jobs_live(&self, id: &str) -> bool {
        self.jobs
            .lock()
            .unwrap()
            .get(id)
            .is_some_and(|jobs| jobs.len() == 2 && jobs.iter().all(|job| !job.is_finished()))
    }

    /// Caller owns lifecycle. Wait for old tasks to exit before replacing their
    /// socket incarnation; abort alone cannot prevent a late unlink/rebind.
    async fn repair_proxy_jobs(&self, app: &mut App) -> anyhow::Result<()> {
        let retired_control = app.fido_launcher.control_retired();
        if self.proxy_jobs_live(&app.profile_id) && !retired_control {
            return Ok(());
        }
        let previous = self.jobs.lock().unwrap().remove(app.profile_id.as_ref());
        if let Some(jobs) = previous {
            for job in &jobs {
                job.abort();
            }
            for job in jobs {
                let _ = job.await;
            }
        }
        app.broker.lock().await.disconnected();
        if retired_control {
            let (endpoints, launcher) = self
                .manager
                .ensure(&app.profile_id, self.next_revision())
                .await
                .map_err(|_| anyhow::anyhow!("FIDO control reattachment failed"))?;
            anyhow::ensure!(
                &endpoints == app.endpoints.as_ref(),
                "FIDO reattachment changed runtime generation"
            );
            app.fido_launcher = launcher;
            let mut stored = app.clone();
            stored.profiles = None;
            self.contexts
                .lock()
                .unwrap()
                .insert(app.profile_id.to_string(), stored);
        }
        crate::browser::control::start_proxy(app.clone()).await
    }

    pub(crate) async fn recover_proxy_jobs(self: &Arc<Self>, root: &App) {
        let _lifecycle = self.lifecycle.lock().await;
        for mut context in self.all() {
            let id = context.profile_id.to_string();
            if context.endpoints.runtime_epoch.is_none()
                || (self.proxy_jobs_live(&id) && !context.fido_launcher.control_retired())
                || self.uncertain.lock().unwrap().contains(&id)
            {
                continue;
            }
            {
                let inner = root.inner.lock().await;
                if inner.store.data.pending_profile_cleanup.contains(&id)
                    || inner
                        .store
                        .data
                        .profile(&id)
                        .is_none_or(|p| !inner.store.data.effective_enabled(p))
                {
                    continue;
                }
            }
            context.profiles = Some(self.clone());
            if self.repair_proxy_jobs(&mut context).await.is_err() {
                self.uncertain.lock().unwrap().insert(id.clone());
                let _ = queue_failed_cleanup(root, &id).await;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn has_context(&self, id: &str) -> bool {
        self.contexts.lock().unwrap().contains_key(id)
    }
    pub(crate) fn context_count(&self) -> usize {
        self.contexts.lock().unwrap().len()
    }
    pub(crate) fn all(&self) -> Vec<App> {
        self.contexts.lock().unwrap().values().cloned().collect()
    }
    // A gateway-wide sequence keeps retired identities out of memory without
    // resetting their request order if a delayed reply or later retry arrives.
    fn next_revision(&self) -> u64 {
        let mut sequence = self.revision_sequence.lock().unwrap();
        *sequence = sequence.checked_add(1).expect("profile revision exhausted");
        *sequence
    }
    pub(crate) async fn ensure(
        self: &Arc<Self>,
        root: &App,
        id: &str,
    ) -> Result<App, (axum::http::StatusCode, String)> {
        let registry = self.clone();
        let root = root.clone();
        let id = id.to_owned();
        // The browser and transferred control descriptor outlive an HTTP
        // caller. Keep adoption and listener binding in one owned transaction.
        own_initialization(async move { registry.ensure_owned(&root, &id).await }).await
    }

    async fn ensure_owned(
        self: &Arc<Self>,
        root: &App,
        id: &str,
    ) -> Result<App, (axum::http::StatusCode, String)> {
        let _operation = self.lifecycle.lock().await;
        let mut app = self.context(root, id);
        if self.uncertain.lock().unwrap().contains(id)
            || root
                .inner
                .lock()
                .await
                .store
                .data
                .pending_profile_cleanup
                .iter()
                .any(|p| p == id)
        {
            return Err(crate::http::error::fail(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "此配置的运行资源尚未确认释放，正在后台重试。",
            ));
        }
        if app.endpoints.runtime_epoch.is_some() {
            #[cfg(test)]
            if self.fixture_runtime {
                return Ok(app);
            }
            if let Err(failure) = self
                .manager
                .cached(id, self.next_revision(), &app.endpoints)
                .await
            {
                if failure.cleanup_confirmed {
                    self.retire_confirmed(root, id, app.endpoints.runtime_epoch.as_deref())
                        .await;
                } else {
                    self.uncertain.lock().unwrap().insert(id.into());
                    self.reconcile_uncertain(root, id).await;
                }
                return Err(crate::http::error::fail(
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "配置运行环境不可用，请重试；若仍失败，请在设置中清理资源。",
                ));
            }
            if self.repair_proxy_jobs(&mut app).await.is_err() {
                self.uncertain.lock().unwrap().insert(id.into());
                queue_failed_cleanup(root, id).await?;
                return Err(crate::http::error::fail(
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "配置控制通道恢复失败，正在后台清理此配置的运行资源。",
                ));
            }
            return Ok(app);
        }
        self.uncertain.lock().unwrap().insert(id.into());
        let revision = self.next_revision();
        let result = self.manager.ensure(id, revision).await;
        let (endpoints, launcher) = match result {
            Ok(v) => v,
            Err(()) => {
                queue_failed_cleanup(root, id).await?;
                if self
                    .manager
                    .stop(id, self.next_revision(), None)
                    .await
                    .is_ok()
                {
                    self.retire_confirmed(root, id, None).await;
                } else {
                    self.reconcile_uncertain(root, id).await;
                }
                return Err(crate::http::error::fail(
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "配置浏览器启动失败，请重试。",
                ));
            }
        };
        app.endpoints = Arc::new(endpoints);
        app.fido_launcher = launcher;
        let mut stored = app.clone();
        stored.profiles = None;
        self.contexts.lock().unwrap().insert(id.into(), stored);
        if crate::browser::control::start_proxy(app.clone())
            .await
            .is_err()
        {
            queue_failed_cleanup(root, id).await?;
            if self
                .manager
                .stop(
                    id,
                    self.next_revision(),
                    app.endpoints.runtime_epoch.as_deref(),
                )
                .await
                .is_ok()
            {
                self.uncertain.lock().unwrap().remove(id);
                self.contexts.lock().unwrap().remove(id);
            }
            return Err(crate::http::error::fail(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "配置控制通道不可用，启动未确认。",
            ));
        }
        self.uncertain.lock().unwrap().remove(id);
        Ok(app)
    }
    /// Exactly one read-only receipt lookup when an IPC failure first makes a
    /// generation uncertain. Future ensure calls hit the uncertainty guard, so
    /// neither polling nor reconnect loops can repeat an automatic cleanup.
    async fn reconcile_uncertain(&self, root: &App, id: &str) {
        if let Ok(report) = self
            .manager
            .cleanup_status(self.next_revision(), &[id.to_owned()])
            .await
        {
            if let Some(receipt) = report
                .results
                .iter()
                .find(|receipt| receipt.profile_id == id && receipt.stopped)
            {
                self.retire_confirmed(root, id, receipt.runtime_epoch.as_deref())
                    .await;
            }
        }
    }
    /// Call only while holding lifecycle and with a manager stop receipt. This
    /// shared path retires live authority as well as resource bookkeeping.
    async fn retire_confirmed(&self, root: &App, id: &str, epoch: Option<&str>) -> bool {
        let context = self.contexts.lock().unwrap().get(id).cloned();
        if context.as_ref().is_some_and(|context| {
            context.endpoints.runtime_epoch.is_some()
                && context.endpoints.runtime_epoch.as_deref() != epoch
        }) {
            return false;
        }
        if let Some(context) = context {
            let mut broker = context.broker.lock().await;
            let mut inner = root.inner.lock().await;
            viewer::clear(&mut inner, id);
            broker.cancel_all("Failed runtime resources released");
            context.revoked.send_modify(|n| *n = n.wrapping_add(1));
        } else {
            viewer::clear(&mut *root.inner.lock().await, id);
        }
        self.retire(id);
        true
    }
    // The caller holds lifecycle and has a confirmed stop for the cached epoch.
    fn retire(&self, id: &str) {
        self.uncertain.lock().unwrap().remove(id);
        self.contexts.lock().unwrap().remove(id);
        if let Some(jobs) = self.jobs.lock().unwrap().remove(id) {
            for job in jobs {
                job.abort();
            }
        }
    }
    pub(crate) async fn revoke(&self, id: &str, stop: bool) -> Result<(), ()> {
        let _operation = self.lifecycle.lock().await;
        let app = self.contexts.lock().unwrap().get(id).cloned();
        if let Some(app) = app {
            let mut broker = app.broker.lock().await;
            let inner = app.inner.lock().await;
            // A late last-viewer cleanup must not cancel a newly admitted tab.
            if !viewer::empty(&inner, id) {
                // A skipped stop is not an acknowledgement and must never
                // erase a durable cleanup intent for a successor viewer.
                return if stop { Err(()) } else { Ok(()) };
            }
            broker.cancel_all("Profile authority released");
            app.revoked.send_modify(|n| *n = n.wrapping_add(1));
            drop(inner);
            drop(broker);
            if stop {
                let stopped = if app.endpoints.runtime_epoch.is_none()
                    && !self.uncertain.lock().unwrap().contains(id)
                    && self.manager.token.is_none()
                {
                    Ok(())
                } else {
                    self.manager
                        .stop(
                            id,
                            self.next_revision(),
                            app.endpoints.runtime_epoch.as_deref(),
                        )
                        .await
                };
                if stopped.is_ok() {
                    self.retire(id);
                } else {
                    return Err(());
                }
            }
        } else if stop && self.manager.token.is_some() {
            self.manager.stop(id, self.next_revision(), None).await?;
            self.retire(id);
        }
        Ok(())
    }
}

async fn queue_failed_cleanup(
    root: &App,
    id: &str,
) -> Result<(), (axum::http::StatusCode, String)> {
    let mut inner = root.inner.lock().await;
    if inner
        .store
        .data
        .pending_profile_cleanup
        .iter()
        .any(|p| p == id)
    {
        return Ok(());
    }
    let previous = inner.store.data.clone();
    inner.store.data.pending_profile_cleanup.push(id.into());
    commit(&mut inner, previous)
}

async fn own_initialization<F>(operation: F) -> Result<App, (axum::http::StatusCode, String)>
where
    F: std::future::Future<Output = Result<App, (axum::http::StatusCode, String)>> + Send + 'static,
{
    tokio::spawn(operation).await.map_err(|_| {
        crate::http::error::fail(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "配置运行环境初始化任务失败，请稍后重试。",
        )
    })?
}

/// A failed directory fsync may follow a committed rename. Adopt readable disk
/// state, otherwise block further authority rather than trusting a guessed rollback.
pub(crate) fn commit(
    inner: &mut crate::app::Inner,
    previous: crate::storage::store::Data,
) -> Result<(), (axum::http::StatusCode, String)> {
    if let Err(error) = inner.store.save() {
        match inner.store.read_persisted() {
            Ok(persisted) if persisted.validate().is_ok() => inner.store.data = persisted,
            _ => {
                inner.store.data = previous;
                inner.store.block_writes();
            }
        }
        inner.profile_viewers.clear();
        inner.viewer_tickets.clear();
        return Err(crate::http::error::fail(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("配置持久化未确认：{error}"),
        ));
    }
    Ok(())
}

/// Callers serialize administrative configuration with App.operations. The intent
/// remains durable until a confirmed stop, including across gateway restarts.
pub(crate) async fn finish_cleanup(
    app: &App,
    id: &str,
) -> Result<(), (axum::http::StatusCode, String)> {
    if let Some(registry) = &app.profiles {
        let result = registry.revoke(id, true).await;
        result.map_err(|_| {
            crate::http::error::fail(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "权限已撤销，但浏览器资源清理未确认，请稍后重试。",
            )
        })?;
    }
    let mut inner = app.inner.lock().await;
    // Runtime-only operations cannot consume a separately authorized erasure.
    if inner
        .store
        .data
        .pending_profile_deletion
        .iter()
        .any(|p| p == id)
    {
        return Ok(());
    }
    let previous = inner.store.data.clone();
    inner.store.data.pending_profile_cleanup.retain(|p| p != id);
    commit(&mut inner, previous)
}

/// The delete endpoint resumes erasure here. Cleanup recovery uses exact stop
/// receipts and the same durable deletion intent; availability edits retain data.
pub(crate) async fn finish_deletion(
    app: &App,
    id: &str,
) -> Result<(), (axum::http::StatusCode, String)> {
    finish_cleanup(app, id).await?;
    let registry = app.profiles.as_ref().ok_or_else(deletion_unconfirmed)?;
    let _lifecycle = registry.lifecycle.lock().await;
    delete_data_locked(app, registry, id).await?;
    let mut inner = app.inner.lock().await;
    let previous = inner.store.data.clone();
    inner.store.data.pending_profile_cleanup.retain(|p| p != id);
    inner
        .store
        .data
        .pending_profile_deletion
        .retain(|p| p != id);
    commit(&mut inner, previous)?;
    drop(inner);
    if registry
        .manager
        .forget_deleted(id, registry.next_revision())
        .await
        .is_err()
    {
        *registry.pending_receipt_ack.lock().unwrap() = true;
    }
    Ok(())
}

fn deletion_unconfirmed() -> (axum::http::StatusCode, String) {
    crate::http::error::fail(
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "配置已移除，但浏览器数据删除未确认，待删除任务已保留，请稍后重试删除。",
    )
}

/// Caller owns operations and lifecycle. The manager independently verifies
/// stopped ownership and safe paths; a missing runtime context is not proof.
async fn delete_data_locked(
    app: &App,
    registry: &Registry,
    id: &str,
) -> Result<(), (axum::http::StatusCode, String)> {
    {
        let inner = app.inner.lock().await;
        if id == "default"
            || !crate::storage::profiles::valid_id(id)
            || inner.store.data.profile(id).is_some()
            || !inner
                .store
                .data
                .pending_profile_deletion
                .iter()
                .any(|p| p == id)
        {
            return Err(deletion_unconfirmed());
        }
    }
    registry
        .manager
        .delete_data(id, registry.next_revision())
        .await
        .map_err(|code| {
            crate::http::error::fail(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "配置已移除，浏览器数据待删除：{}",
                    cleanup::failure_reason(&code)
                ),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        Json,
    };
    use serde_json::json;

    fn unavailable_registry(dir: &std::path::Path) -> Arc<Registry> {
        let mut registry = Registry::new();
        Arc::get_mut(&mut registry).unwrap().manager =
            runtime::Manager::unavailable(dir.join("absent-manager.sock"));
        registry
    }

    #[tokio::test]
    async fn durable_cleanup_with_placeholder_never_skips_manager_stop() {
        let (mut app, dir) = crate::test_support::app();
        app.profiles = Some(unavailable_registry(&dir));
        let id = uuid::Uuid::new_v4().to_string();
        {
            let mut inner = app.inner.lock().await;
            inner.store.data.pending_profile_cleanup.push(id.clone());
            inner.store.save().unwrap();
        }
        app.profiles.as_ref().unwrap().context(&app, &id);
        assert_eq!(
            finish_cleanup(&app, &id).await.unwrap_err().0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        let disk = crate::storage::store::Store::open(dir.join("store.json")).unwrap();
        assert_eq!(disk.data.pending_profile_cleanup, vec![id.clone()]);
        assert!(app.profiles.as_ref().unwrap().has_context(&id));
        // A repeated global disable must retry the already-persisted intent.
        for _ in 0..2 {
            let result = api::configure(
                State(app.clone()),
                HeaderMap::new(),
                Json(serde_json::from_value(json!({"multi_profile":false})).unwrap()),
            )
            .await;
            assert_eq!(result.unwrap_err().0, StatusCode::SERVICE_UNAVAILABLE);
        }
        assert_eq!(
            app.inner.lock().await.store.data.pending_profile_cleanup,
            vec![id]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn cached_runtime_and_pending_cleanup_cannot_claim_success() {
        let (mut root, dir) = crate::test_support::app();
        let registry = unavailable_registry(&dir);
        root.profiles = Some(registry.clone());
        let mut app = registry.context(&root, "default");
        Arc::make_mut(&mut app.endpoints).runtime_epoch = Some("ab".repeat(16));
        app.profiles = None;
        registry
            .contexts
            .lock()
            .unwrap()
            .insert("default".into(), app);
        assert_eq!(
            registry.ensure(&root, "default").await.err().unwrap().0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(registry.uncertain.lock().unwrap().contains("default"));
        let registry = Registry::test_ready();
        root.profiles = Some(registry.clone());
        root.inner
            .lock()
            .await
            .store
            .data
            .pending_profile_cleanup
            .push("default".into());
        assert_eq!(
            registry.ensure(&root, "default").await.err().unwrap().0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn failed_commit_adopts_verified_disk_and_rejects_invalid_cleanup_journal() {
        let (app, dir) = crate::test_support::app();
        let mut inner = app.inner.lock().await;
        let old = inner.store.data.clone();
        inner.store.block_writes();
        inner.store.data.multi_profile = true;
        assert!(commit(&mut inner, old).is_err());
        assert!(!inner.store.data.multi_profile);
        let mut invalid = inner.store.data.clone();
        invalid.pending_profile_cleanup = vec!["../unsafe".into()];
        assert!(invalid.validate().is_err());
        invalid.pending_profile_cleanup = vec!["default".into(), "default".into()];
        assert!(invalid.validate().is_err());
        drop(inner);
        std::fs::remove_dir_all(dir).unwrap();
    }

    pub(super) fn deletion_manager(
        dir: &std::path::Path,
        actions: Vec<(&'static str, bool)>,
    ) -> (Arc<Registry>, std::thread::JoinHandle<()>) {
        use std::io::{BufRead, BufReader, Write};
        let path = dir.join("deletion-manager.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let task = std::thread::spawn(move || {
            for (action, success) in actions {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                assert_eq!(request["action"], action);
                let mut response = json!({"ok":true,"version":1,"request_id":request["request_id"],
                    "profile_id":request["profile_id"],"revision":request["revision"]});
                response[if action == "stop" {
                    "stopped"
                } else {
                    "browser_data_deleted"
                }] = json!(success);
                writeln!(stream, "{response}").unwrap();
            }
        });
        let mut registry = Registry::new();
        Arc::get_mut(&mut registry).unwrap().manager = runtime::Manager::unavailable(path);
        (registry, task)
    }

    #[tokio::test]
    #[ignore = "requires named AF_UNIX listener binding; current environment returns EPERM; run only in a permitted environment"]
    async fn explicit_deletion_is_durable_until_stop_and_erasure_confirmed() {
        use axum::extract::Path;
        let (mut app, dir) = crate::test_support::app();
        let id = uuid::Uuid::new_v4().to_string();
        {
            let mut inner = app.inner.lock().await;
            inner
                .store
                .data
                .profiles
                .push(crate::storage::profiles::Profile {
                    id: id.clone(),
                    name: "remove-me".into(),
                    ..Default::default()
                });
            inner.store.save().unwrap();
        }
        let (registry, worker) = deletion_manager(
            &dir,
            vec![
                ("stop", true),
                ("delete_data", false),
                ("stop", true),
                ("delete_data", true),
            ],
        );
        app.profiles = Some(registry);
        assert_eq!(
            api::delete(State(app.clone()), HeaderMap::new(), Path(id.clone()))
                .await
                .unwrap_err()
                .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        {
            let disk = crate::storage::store::Store::open(dir.join("store.json")).unwrap();
            assert!(disk.data.profile(&id).is_none());
            assert_eq!(disk.data.pending_profile_deletion, vec![id.clone()]);
            assert_eq!(disk.data.pending_profile_cleanup, vec![id.clone()]);
            assert!(disk.data.profile("default").is_some());
        }
        let response = api::delete(State(app.clone()), HeaderMap::new(), Path(id.clone()))
            .await
            .unwrap()
            .0;
        assert_eq!(response, json!({"ok":true,"browser_data_retained":false}));
        let disk = crate::storage::store::Store::open(dir.join("store.json")).unwrap();
        assert!(disk.data.pending_profile_deletion.is_empty());
        assert!(disk.data.pending_profile_cleanup.is_empty());
        worker.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn deletion_never_uses_missing_manager_as_absence_proof() {
        let (app, dir) = crate::test_support::app();
        let id = uuid::Uuid::new_v4().to_string();
        {
            let mut inner = app.inner.lock().await;
            inner.store.data.pending_profile_cleanup.push(id.clone());
            inner.store.data.pending_profile_deletion.push(id.clone());
            inner.store.save().unwrap();
        }
        assert_eq!(
            finish_deletion(&app, &id).await.unwrap_err().0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        let disk = crate::storage::store::Store::open(dir.join("store.json")).unwrap();
        assert_eq!(disk.data.pending_profile_deletion, vec![id]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn deletion_journal_is_explicit_validated_and_legacy_safe() {
        let mut data = crate::storage::store::Data::default();
        let id = uuid::Uuid::new_v4().to_string();
        data.pending_profile_cleanup.push(id.clone());
        let mut legacy = serde_json::to_value(&data).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("pending_profile_deletion");
        let restored: crate::storage::store::Data = serde_json::from_value(legacy).unwrap();
        assert!(restored.pending_profile_deletion.is_empty());
        for invalid in ["default", "../unsafe"] {
            data.pending_profile_deletion = vec![invalid.into()];
            assert!(data.validate().is_err());
        }
        data.pending_profile_deletion = vec![id.clone(), id.clone()];
        assert!(data.validate().is_err());
        data.pending_profile_deletion = vec![id.clone()];
        assert!(data.validate().is_ok());
        data.pending_profile_cleanup.clear();
        assert!(data.validate().is_err());
    }

    #[tokio::test]
    async fn unrelated_pending_cleanup_never_blocks_a_healthy_profile() {
        let (mut app, dir) = crate::test_support::app();
        let registry = Registry::test_ready();
        app.profiles = Some(registry.clone());
        let failed = uuid::Uuid::new_v4().to_string();
        {
            let mut inner = app.inner.lock().await;
            inner
                .store
                .data
                .pending_profile_cleanup
                .push(failed.clone());
            inner
                .store
                .data
                .pending_profile_deletion
                .push(failed.clone());
            inner.store.save().unwrap();
        }
        registry.uncertain.lock().unwrap().insert(failed);
        let mut healthy = registry.context(&app, "default");
        Arc::make_mut(&mut healthy.endpoints).runtime_epoch = Some("ab".repeat(16));
        healthy.profiles = None;
        registry
            .contexts
            .lock()
            .unwrap()
            .insert("default".into(), healthy);
        assert!(registry.ensure(&app, "default").await.is_ok());
        assert_eq!(
            app.inner
                .lock()
                .await
                .store
                .data
                .pending_profile_deletion
                .len(),
            1
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn canceled_caller_does_not_abandon_control_adoption_and_listener_initialization() {
        use std::os::fd::OwnedFd;
        let (app, dir) = crate::test_support::app();
        let (gateway, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let (started, running) = tokio::sync::oneshot::channel();
        let (release, proceed) = tokio::sync::oneshot::channel();
        let (done, completion) = tokio::sync::oneshot::channel();
        let adopted = Arc::new(Mutex::new(None::<OwnedFd>));
        let destination = adopted.clone();
        let caller = tokio::spawn(own_initialization(async move {
            started.send(()).unwrap();
            proceed.await.unwrap();
            // Simulate adopting the late IPC descriptor before binding the
            // listener. Dropping the request must not drop this owned offer.
            *destination.lock().unwrap() = Some(gateway.into());
            done.send(()).unwrap();
            Ok(app)
        }));
        running.await.unwrap();
        caller.abort();
        assert!(matches!(caller.await, Err(error) if error.is_cancelled()));
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), completion)
            .await
            .unwrap()
            .unwrap();
        use std::io::Read;
        let mut peer = peer;
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(adopted.lock().unwrap().is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn canceled_ensure_keeps_lifecycle_owned_until_transaction_finishes() {
        let (app, dir) = crate::test_support::app();
        let registry = Registry::test_ready();
        let blocker = registry.lifecycle.lock().await;
        let worker = registry.clone();
        let root = app.clone();
        let task = tokio::spawn(async move { worker.ensure(&root, "default").await });
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        drop(blocker);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if registry.uncertain.lock().unwrap().contains("default") {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let _finished = registry.lifecycle.lock().await;
        assert!(registry.has_context("default"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn proxy_job_health_detects_finished_tasks_without_rotating_live_tasks() {
        let registry = Registry::new();
        let live1 = tokio::spawn(std::future::pending());
        let live2 = tokio::spawn(std::future::pending());
        registry.jobs("default", vec![live1, live2]);
        assert!(registry.proxy_jobs_live("default"));
        assert!(!registry.proxy_jobs_live("missing"));
        registry.jobs(
            "default",
            vec![tokio::spawn(async {}), tokio::spawn(std::future::pending())],
        );
        tokio::task::yield_now().await;
        assert!(!registry.proxy_jobs_live("default"));
        registry.retire("default");
    }
    #[tokio::test]
    async fn repeated_retirement_leaves_no_profile_history_and_revisions_never_reset() {
        let (app, dir) = crate::test_support::app();
        let registry = Registry::test_ready();
        let mut previous = 0;
        for _ in 0..512 {
            let id = uuid::Uuid::new_v4().to_string();
            registry.context(&app, &id);
            registry.uncertain.lock().unwrap().insert(id.clone());
            let revision = registry.next_revision();
            assert!(revision > previous);
            previous = revision;
            assert!(registry.retire_confirmed(&app, &id, None).await);
            assert!(registry.contexts.lock().unwrap().is_empty());
            assert!(registry.uncertain.lock().unwrap().is_empty());
            assert!(registry.jobs.lock().unwrap().is_empty());
            assert!(app.inner.lock().await.profile_viewers.is_empty());
        }
        assert_eq!(*registry.revision_sequence.lock().unwrap(), 512);
        assert_eq!(registry.next_revision(), 513);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
