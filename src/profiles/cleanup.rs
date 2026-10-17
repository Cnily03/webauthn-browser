//! Bounded administrative reconciliation, separate from browser restart/stop.
use super::{
    runtime::{CleanupIntent, CleanupReport},
    Registry,
};
use crate::{
    app::App,
    auth::{authorize, csrf},
    http::error::{fail, ApiResult},
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {}

pub(crate) async fn manual(
    State(app): State<App>,
    headers: HeaderMap,
    Json(_): Json<Input>,
) -> ApiResult {
    let configured_snapshot = {
        let inner = app.inner.lock().await;
        authorize(&inner, &headers, "settings")?;
        csrf(&inner, &headers)?;
        inner
            .store
            .data
            .profiles
            .iter()
            .map(|profile| profile.id.clone())
            .collect::<HashSet<_>>()
    };
    // Keep the pass owned by the task if the HTTP caller disconnects.
    // The dedicated pass lock prevents overlapping manager reconciliations.
    tokio::spawn(async move {
        {
            let _configuration = app.operations.lock().await;
            let inner = app.inner.lock().await;
            authorize(&inner, &headers, "settings")?;
            csrf(&inner, &headers)?;
        }
        run_locked(&app, true, true, Some(configured_snapshot)).await
    })
    .await
    .map_err(|_| {
        fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "资源清理任务未完成，请稍后重试。",
        )
    })?
}

/// One manager pass has its own bounded deadline; it never turns a pending
/// journal into a series of unbounded stop requests.
pub(crate) async fn startup(app: &App) -> ApiResult {
    // Generic orphan cleanup already ran in the manager. A bounded intent-only
    // pass also completes persisted disable/delete requests after gateway loss;
    // the manager deduplicates any generation already attempted automatically.
    run_locked(app, false, false, None).await
}

pub(crate) async fn recover(app: App) {
    let mut needs_inventory = startup(&app).await.is_err();
    let mut delay = std::time::Duration::from_secs(5);
    let mut previous = None;
    loop {
        tokio::time::sleep(delay).await;
        if let Some(registry) = &app.profiles {
            registry.recover_proxy_jobs(&app).await;
        }
        let pending = pending_ids(&app).await;
        let pending_ack = app
            .profiles
            .as_ref()
            .is_some_and(|registry| *registry.pending_receipt_ack.lock().unwrap());
        if pending.is_empty() && !needs_inventory && !pending_ack {
            delay = std::time::Duration::from_secs(5);
            previous = None;
            continue;
        }
        // Newly pending work receives the short delay even after an older
        // unrecoverable generation has reached the maximum backoff.
        let changed = previous.as_ref() != Some(&pending);
        needs_inventory = run_locked(&app, true, false, None).await.is_err();
        let remaining = pending_ids(&app).await;
        let progress = remaining != pending;
        delay = next_delay(
            delay,
            changed || progress || (remaining.is_empty() && !needs_inventory),
        );
        previous = Some(remaining);
    }
}

async fn pending_ids(app: &App) -> Vec<String> {
    let mut ids = app
        .inner
        .lock()
        .await
        .store
        .data
        .pending_profile_cleanup
        .clone();
    if let Some(registry) = &app.profiles {
        ids.extend(registry.uncertain.lock().unwrap().iter().cloned());
    }
    ids.sort();
    ids.dedup();
    ids
}

fn next_delay(current: std::time::Duration, progress: bool) -> std::time::Duration {
    if progress {
        std::time::Duration::from_secs(5)
    } else {
        (current * 2).min(std::time::Duration::from_secs(60))
    }
}

async fn run_locked(
    app: &App,
    retry: bool,
    force_uncertain: bool,
    configured_snapshot: Option<HashSet<String>>,
) -> ApiResult {
    let registry = app.profiles.as_ref().ok_or_else(unavailable)?;
    let _pass = registry.cleanup_pass.lock().await;
    let configuration = app.operations.lock().await;
    let lifecycle = registry.lifecycle.lock().await;
    let journal = app
        .inner
        .lock()
        .await
        .store
        .data
        .pending_profile_cleanup
        .clone();
    let mut candidates = journal.clone();
    candidates.extend(registry.uncertain.lock().unwrap().iter().cloned());
    candidates.sort();
    candidates.dedup();
    // Large retained journals are reconciled fairly across explicit passes.
    // The cursor changes only candidate order, never cleanup authority.
    if !candidates.is_empty() {
        let mut cursor = registry.cleanup_cursor.lock().unwrap();
        let length = candidates.len();
        candidates.rotate_left(*cursor % length);
        *cursor = (*cursor + 16) % length;
    }
    candidates.truncate(16);
    if force_uncertain {
        let mut inner = app.inner.lock().await;
        let previous = inner.store.data.clone();
        for id in &candidates {
            if !inner.store.data.pending_profile_cleanup.contains(id) {
                inner.store.data.pending_profile_cleanup.push(id.clone());
            }
        }
        if previous.pending_profile_cleanup != inner.store.data.pending_profile_cleanup {
            super::commit(&mut inner, previous)?;
        }
    }
    let revision = registry.next_revision();
    // Durable disable/delete intents and this explicit force request may stop
    // a live generation. Automatic transient uncertainty cannot grant authority.
    let intents = {
        let contexts = registry.contexts.lock().unwrap();
        candidates
            .iter()
            .filter(|id| journal.contains(id) || force_uncertain)
            .map(|id| CleanupIntent {
                profile_id: id.clone(),
                runtime_epoch: contexts
                    .get(id)
                    .and_then(|context| context.endpoints.runtime_epoch.clone()),
            })
            .collect::<Vec<_>>()
    };
    // Journal/uncertainty guards keep these identities from being restarted.
    // Do not block unrelated profile admission during bounded manager waits.
    drop(lifecycle);
    drop(configuration);
    let result = if retry {
        registry
            .manager
            .cleanup(revision, &candidates, &intents)
            .await
    } else {
        registry
            .manager
            .cleanup_startup(revision, &candidates, &intents)
            .await
    };
    let report = result.map_err(|_| unavailable())?;
    let _configuration = app.operations.lock().await;
    let _lifecycle = registry.lifecycle.lock().await;
    if let Some(snapshot) = configured_snapshot {
        reconcile_snapshot(app, registry, report, Some(&snapshot)).await
    } else {
        reconcile(app, registry, report).await
    }
}

fn unavailable() -> (StatusCode, String) {
    fail(
        StatusCode::SERVICE_UNAVAILABLE,
        "无法连接运行管理器或验证其清理回复；待清理状态已保留，后台将重试。",
    )
}

/// The manager receipt and current cached epoch must agree. Administrative and
/// lifecycle serialization protect retirement. Receipts from the unlocked wait
/// must still match the current cached generation before changing authority.
async fn reconcile(app: &App, registry: &Registry, report: CleanupReport) -> ApiResult {
    reconcile_snapshot(app, registry, report, None).await
}

async fn reconcile_snapshot(
    app: &App,
    registry: &Registry,
    report: CleanupReport,
    configured_snapshot: Option<&HashSet<String>>,
) -> ApiResult {
    let mut confirmed = HashSet::new();
    let mut pending = HashSet::new();
    let mut reasons: HashMap<String, String> = report
        .results
        .iter()
        .filter_map(|receipt| {
            receipt
                .error
                .as_deref()
                .map(|code| (receipt.profile_id.clone(), failure_reason(code)))
        })
        .collect();
    for receipt in report.results.iter().filter(|receipt| !receipt.stopped) {
        let contexts = registry.contexts.lock().unwrap();
        let replaced = contexts.get(&receipt.profile_id).is_some_and(|context| {
            context.endpoints.runtime_epoch.is_some()
                && context.endpoints.runtime_epoch != receipt.runtime_epoch
        });
        if !replaced {
            pending.insert(receipt.profile_id.clone());
            // Startup can discover failed generations before a gateway context
            // exists. Retain them as retry candidates, not just a result count.
            registry
                .uncertain
                .lock()
                .unwrap()
                .insert(receipt.profile_id.clone());
        }
    }
    for receipt in &report.results {
        if !receipt.stopped {
            continue;
        }
        if !registry
            .retire_confirmed(app, &receipt.profile_id, receipt.runtime_epoch.as_deref())
            .await
        {
            // An old receipt cannot retire a healthy/newer cached generation.
            pending.insert(receipt.profile_id.clone());
            continue;
        }
        confirmed.insert(receipt.profile_id.clone());
    }
    let deletions = app
        .inner
        .lock()
        .await
        .store
        .data
        .pending_profile_deletion
        .clone();
    let mut deleted_profiles = 0;
    for id in deletions
        .iter()
        .filter(|id| confirmed.contains(*id))
        .cloned()
        .collect::<Vec<_>>()
    {
        if let Err((_, reason)) = super::delete_data_locked(app, registry, &id).await {
            confirmed.remove(&id);
            reasons.insert(id.clone(), reason);
            pending.insert(id);
        } else {
            deleted_profiles += 1;
        }
    }
    let mut inner = app.inner.lock().await;
    if inner
        .store
        .data
        .pending_profile_cleanup
        .iter()
        .any(|id| confirmed.contains(id))
    {
        let previous = inner.store.data.clone();
        inner
            .store
            .data
            .pending_profile_cleanup
            .retain(|id| !confirmed.contains(id));
        inner
            .store
            .data
            .pending_profile_deletion
            .retain(|id| !confirmed.contains(id));
        super::commit(&mut inner, previous)?;
    }
    pending.extend(inner.store.data.pending_profile_cleanup.iter().cloned());
    pending.extend(registry.uncertain.lock().unwrap().iter().cloned());
    // User-visible counts describe the configured identities at admission,
    // never historical deletion jobs or mutable configuration after the wait.
    let (cleaned_count, pending_count, skipped_count) = if let Some(snapshot) = configured_snapshot
    {
        let pending_count = pending.intersection(snapshot).count();
        let cleaned_count = confirmed
            .intersection(snapshot)
            .filter(|id| !pending.contains(*id))
            .count();
        (
            cleaned_count,
            pending_count,
            snapshot.len() - cleaned_count - pending_count,
        )
    } else {
        (report.cleaned, pending.len(), report.skipped)
    };
    let mut pending_details = pending.iter()
        .filter(|id| configured_snapshot.is_none_or(|snapshot| snapshot.contains(*id)))
        .map(|id| json!({"profile_id":id,"reason":reasons.remove(id).unwrap_or_else(|| "此配置尚未收到停止确认，后台将重试；可点清理资源强制停止已确认归属的进程。".into())}))
        .collect::<Vec<_>>();
    pending_details.sort_by_key(|detail| detail["profile_id"].as_str().unwrap().to_owned());
    pending_details.truncate(64);
    let mut result = json!({"ok":true,"cleaned":cleaned_count,"pending":pending_count,
        "skipped":skipped_count,"browser_data_retained":deleted_profiles == 0,
        "deleted_profiles":deleted_profiles,"pending_details":pending_details});
    if let Some(snapshot) = configured_snapshot {
        result["profile_count"] = json!(snapshot.len());
    }
    let acknowledged = confirmed
        .iter()
        .filter(|id| {
            id.as_str() != "default"
                && inner.store.data.profile(id).is_none()
                && !inner.store.data.pending_profile_cleanup.contains(id)
                && !inner.store.data.pending_profile_deletion.contains(id)
        })
        .cloned()
        .collect::<Vec<_>>();
    drop(inner);
    // Completed deletion receipts stay recoverable until the durable journals
    // are committed. One more pass drains any bounded receipt batch remaining.
    *registry.pending_receipt_ack.lock().unwrap() = !acknowledged.is_empty();
    for id in acknowledged {
        let _ = registry
            .manager
            .forget_deleted(&id, registry.next_revision())
            .await;
    }
    Ok(Json(result))
}

pub(super) fn failure_reason(code: &str) -> String {
    match code {
        "permission_denied" | "profile_data_permission_denied" => {
            "系统拒绝了停止进程或删除文件的权限。"
        }
        "process_survived" | "resource_cleanup_timeout" => {
            "停止此配置进程超时，仍未确认进程已退出。"
        }
        "resource_generation_changed"
        | "display_generation_changed"
        | "stale_runtime"
        | "stale_revision" => "运行代次已变化，为避免影响其他实例，已停止本次清理。",
        "ownership_unconfirmed" | "resource_namespace_changed" => {
            "无法验证残留进程归属，未对未知进程发送信号。"
        }
        "runtime_unavailable" => "无法连接运行管理器，未收到清理结果。",
        "storage_io_error" => "删除浏览器目录时发生文件系统读写错误。",
        "profile_data_delete_failed" => "浏览器目录删除失败，目录仍被占用或文件系统未确认写入。",
        "invalid_reply" => "运行管理器返回了无法验证的清理结果。",
        code if code == "profile_data_unsafe_path"
            || code.starts_with("unsafe_")
            || code.contains("symlink") =>
        {
            "运行文件或目录的类型、归属或链接状态不安全，未继续删除。"
        }
        _ => "清理未完成：运行资源验证失败，后台将重试。",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::Session,
        profiles::runtime::{CleanupReceipt, Manager},
        test_support::{app, call, value},
    };
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    fn report(epoch: Option<&str>, stopped: bool) -> CleanupReport {
        CleanupReport {
            cleaned: usize::from(stopped),
            pending: usize::from(!stopped),
            skipped: 1,
            results: vec![CleanupReceipt {
                profile_id: "default".into(),
                runtime_epoch: epoch.map(str::to_owned),
                stopped,
                error: None,
            }],
        }
    }

    #[tokio::test]
    async fn manual_cleanup_requires_settings_and_csrf_and_preserves_failed_journal() {
        let (mut app, dir) = app();
        let status = value(call(&app, "GET", "/api/status", json!(null), "", "", None).await).await;
        let csrf = status["csrf_token"].as_str().unwrap();
        let cookie = format!("ab_csrf={csrf}");
        let mut registry = Registry::new();
        Arc::get_mut(&mut registry).unwrap().manager =
            Manager::unavailable(dir.join("absent.sock"));
        app.profiles = Some(registry);
        {
            let mut inner = app.inner.lock().await;
            inner.store.data.settings_password_hash = Some("enabled".into());
            inner
                .store
                .data
                .pending_profile_cleanup
                .push("default".into());
            for scope in ["settings", "vnc"] {
                inner.sessions.insert(
                    scope.into(),
                    Session {
                        scope: scope.into(),
                        epoch: 0,
                        expires: Instant::now() + Duration::from_secs(60),
                    },
                );
            }
            inner.store.save().unwrap();
        }
        let before = std::fs::read(dir.join("store.json")).unwrap();
        for (cookies, token, status) in [
            (
                format!("{cookie}; ab_settings=settings"),
                "",
                StatusCode::FORBIDDEN,
            ),
            (cookie.clone(), csrf, StatusCode::UNAUTHORIZED),
            (
                format!("{cookie}; ab_vnc=vnc"),
                csrf,
                StatusCode::UNAUTHORIZED,
            ),
            (
                format!("{cookie}; ab_settings=settings"),
                csrf,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let result = call(
                &app,
                "POST",
                "/api/runtime/cleanup",
                json!({}),
                &cookies,
                token,
                None,
            )
            .await;
            assert_eq!(result.status(), status);
            assert_eq!(std::fs::read(dir.join("store.json")).unwrap(), before);
        }
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/runtime/cleanup",
                json!({"profile_id":"default"}),
                &format!("{cookie}; ab_settings=settings"),
                csrf,
                None
            )
            .await
            .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn receipts_keep_unconfirmed_and_newer_epochs_and_only_commit_exact_proof() {
        let (mut app, dir) = app();
        let registry = Registry::test_ready();
        app.profiles = Some(registry.clone());
        let epoch = "ab".repeat(16);
        let mut failed = registry.context(&app, "default");
        Arc::make_mut(&mut failed.endpoints).runtime_epoch = Some(epoch.clone());
        failed.profiles = None;
        registry
            .contexts
            .lock()
            .unwrap()
            .insert("default".into(), failed);
        registry.uncertain.lock().unwrap().insert("default".into());
        let healthy_id = uuid::Uuid::new_v4().to_string();
        let mut healthy = registry.context(&app, &healthy_id);
        Arc::make_mut(&mut healthy.endpoints).runtime_epoch = Some("cd".repeat(16));
        healthy.profiles = None;
        registry
            .contexts
            .lock()
            .unwrap()
            .insert(healthy_id.clone(), healthy);
        {
            let mut inner = app.inner.lock().await;
            inner
                .store
                .data
                .pending_profile_cleanup
                .push("default".into());
            inner.store.save().unwrap();
        }
        let before = std::fs::read(dir.join("store.json")).unwrap();
        for receipt in [
            report(Some(&epoch), false),
            report(None, true),
            report(Some(&"ef".repeat(16)), true),
        ] {
            let response = reconcile(&app, &registry, receipt).await.unwrap().0;
            assert_eq!(response["pending"], 1);
            assert!(registry.has_context("default"));
            assert!(registry.uncertain.lock().unwrap().contains("default"));
            assert_eq!(std::fs::read(dir.join("store.json")).unwrap(), before);
        }
        let response = reconcile(&app, &registry, report(Some(&epoch), true))
            .await
            .unwrap()
            .0;
        assert_eq!(
            response,
            json!({"ok":true,"cleaned":1,"pending":0,"skipped":1,"browser_data_retained":true,"deleted_profiles":0,"pending_details":[]})
        );
        assert!(!registry.has_context("default"));
        assert!(registry.has_context(&healthy_id));
        assert!(registry.uncertain.lock().unwrap().is_empty());
        let mut expected: serde_json::Value = serde_json::from_slice(&before).unwrap();
        expected["pending_profile_cleanup"] = json!([]);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(dir.join("store.json")).unwrap()
            )
            .unwrap(),
            expected
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn failed_journal_commit_never_reports_cleanup_success() {
        let (app, dir) = app();
        let registry = Registry::test_ready();
        {
            let mut inner = app.inner.lock().await;
            inner
                .store
                .data
                .pending_profile_cleanup
                .push("default".into());
            inner.store.save().unwrap();
            inner.store.block_writes();
        }
        assert_eq!(
            reconcile(&app, &registry, report(None, true))
                .await
                .unwrap_err()
                .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            app.inner.lock().await.store.data.pending_profile_cleanup,
            vec!["default"]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires named AF_UNIX listener binding; current environment returns EPERM; run only in a permitted environment"]
    async fn manual_cleanup_resumes_explicit_deletion_intent() {
        let (mut app, dir) = app();
        let id = uuid::Uuid::new_v4().to_string();
        let (registry, worker) =
            super::super::tests::deletion_manager(&dir, vec![("delete_data", true)]);
        app.profiles = Some(registry.clone());
        {
            let mut inner = app.inner.lock().await;
            inner.store.data.pending_profile_cleanup.push(id.clone());
            inner.store.data.pending_profile_deletion.push(id.clone());
            inner.store.save().unwrap();
        }
        let receipt = || CleanupReport {
            cleaned: 1,
            pending: 0,
            skipped: 0,
            results: vec![CleanupReceipt {
                profile_id: id.clone(),
                runtime_epoch: None,
                stopped: true,
                error: None,
            }],
        };
        let result = reconcile(&app, &registry, receipt()).await.unwrap().0;
        assert_eq!(result["browser_data_retained"], false);
        assert_eq!(result["deleted_profiles"], 1);
        assert_eq!(result["pending"], 0);
        let disk = crate::storage::store::Store::open(dir.join("store.json")).unwrap();
        assert!(disk.data.pending_profile_deletion.is_empty());
        assert!(disk.data.pending_profile_cleanup.is_empty());
        worker.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires named AF_UNIX listener binding; current environment returns EPERM; run only in a permitted environment"]
    async fn startup_erasure_commit_failure_retains_idempotent_retry_journal() {
        let (mut app, dir) = app();
        let id = uuid::Uuid::new_v4().to_string();
        let (registry, worker) =
            super::super::tests::deletion_manager(&dir, vec![("delete_data", true)]);
        app.profiles = Some(registry.clone());
        {
            let mut inner = app.inner.lock().await;
            inner.store.data.pending_profile_cleanup.push(id.clone());
            inner.store.data.pending_profile_deletion.push(id.clone());
            inner.store.save().unwrap();
            inner.store.block_writes();
        }
        let receipt = CleanupReport {
            cleaned: 1,
            pending: 0,
            skipped: 0,
            results: vec![CleanupReceipt {
                profile_id: id.clone(),
                runtime_epoch: None,
                stopped: true,
                error: None,
            }],
        };
        assert_eq!(
            reconcile(&app, &registry, receipt).await.unwrap_err().0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            app.inner.lock().await.store.data.pending_profile_deletion,
            vec![id]
        );
        worker.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn manual_receipt_preserves_deletion_until_erasure_is_confirmed() {
        let (app, dir) = app();
        let registry = Registry::test_ready();
        let id = uuid::Uuid::new_v4().to_string();
        {
            let mut inner = app.inner.lock().await;
            inner.store.data.pending_profile_cleanup.push(id.clone());
            inner.store.data.pending_profile_deletion.push(id.clone());
            inner.store.save().unwrap();
        }
        let before = std::fs::read(dir.join("store.json")).unwrap();
        let receipt = CleanupReport {
            cleaned: 1,
            pending: 0,
            skipped: 0,
            results: vec![CleanupReceipt {
                profile_id: id.clone(),
                runtime_epoch: None,
                stopped: true,
                error: None,
            }],
        };
        let result = reconcile(&app, &registry, receipt).await.unwrap().0;
        assert_eq!(result["browser_data_retained"], true);
        assert_eq!(result["pending"], 1);
        assert_eq!(std::fs::read(dir.join("store.json")).unwrap(), before);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn startup_unavailable_erasure_preserves_explicit_intent() {
        let (app, dir) = app();
        let registry = Registry::test_ready();
        let id = uuid::Uuid::new_v4().to_string();
        {
            let mut inner = app.inner.lock().await;
            inner.store.data.pending_profile_cleanup.push(id.clone());
            inner.store.data.pending_profile_deletion.push(id.clone());
            inner.store.save().unwrap();
        }
        let before = std::fs::read(dir.join("store.json")).unwrap();
        let receipt = CleanupReport {
            cleaned: 1,
            pending: 0,
            skipped: 0,
            results: vec![CleanupReceipt {
                profile_id: id.clone(),
                runtime_epoch: None,
                stopped: true,
                error: None,
            }],
        };
        let result = reconcile(&app, &registry, receipt).await.unwrap().0;
        assert_eq!(result["browser_data_retained"], true);
        assert_eq!(result["pending"], 1);
        assert_eq!(std::fs::read(dir.join("store.json")).unwrap(), before);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn automatic_recovery_backs_off_but_progress_resets_delay() {
        let mut delay = Duration::from_secs(5);
        for expected in [10, 20, 40, 60, 60] {
            delay = next_delay(delay, false);
            assert_eq!(delay, Duration::from_secs(expected));
        }
        assert_eq!(next_delay(delay, true), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn automatic_candidates_cover_failed_runtime_and_durable_deletion_only() {
        let (mut app, dir) = app();
        let registry = Registry::test_ready();
        app.profiles = Some(registry.clone());
        assert!(pending_ids(&app).await.is_empty());
        let id = uuid::Uuid::new_v4().to_string();
        registry.uncertain.lock().unwrap().insert(id.clone());
        {
            let mut inner = app.inner.lock().await;
            inner.store.data.pending_profile_cleanup.push(id.clone());
            inner.store.data.pending_profile_deletion.push(id.clone());
        }
        registry.context(&app, "default");
        assert_eq!(pending_ids(&app).await, vec![id]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn startup_discovered_failed_generation_remains_an_automatic_candidate() {
        let (mut app, dir) = app();
        let registry = Registry::test_ready();
        app.profiles = Some(registry.clone());
        let receipt = report(Some(&"ab".repeat(16)), false);
        let result = reconcile(&app, &registry, receipt).await.unwrap().0;
        assert_eq!(result["pending"], 1);
        assert_eq!(pending_ids(&app).await, vec!["default"]);
        let result = reconcile(&app, &registry, report(Some(&"ab".repeat(16)), true))
            .await
            .unwrap()
            .0;
        assert_eq!(result["pending"], 0);
        assert!(pending_ids(&app).await.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn create_only_never_initializes_runtime_or_adds_cleanup_intent() {
        let (mut app, dir) = app();
        let registry = Registry::test_ready();
        app.profiles = Some(registry.clone());
        let result = super::super::api::create(
            State(app.clone()),
            HeaderMap::new(),
            Json(serde_json::from_value(json!({"name":"created-only"})).unwrap()),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(result["name"], "created-only");
        assert_eq!(registry.context_count(), 0);
        assert!(registry.uncertain.lock().unwrap().is_empty());
        let inner = app.inner.lock().await;
        assert!(inner.store.data.pending_profile_cleanup.is_empty());
        assert!(inner.store.data.pending_profile_deletion.is_empty());
        assert!(!dir.join("profiles").exists());
        drop(inner);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn manual_force_intent_survives_unavailable_manager() {
        let (mut app, dir) = app();
        let registry = Registry::test_ready();
        registry.uncertain.lock().unwrap().insert("default".into());
        app.profiles = Some(registry);
        assert!(run_locked(&app, true, true, None).await.is_err());
        let inner = app.inner.lock().await;
        assert_eq!(inner.store.data.pending_profile_cleanup, vec!["default"]);
        assert!(inner.store.data.pending_profile_deletion.is_empty());
        drop(inner);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn pending_receipt_exposes_bounded_concrete_reason() {
        let (app, dir) = app();
        let registry = Registry::test_ready();
        let mut receipt = report(Some(&"ab".repeat(16)), false);
        receipt.results[0].error = Some("permission_denied".into());
        let result = reconcile(&app, &registry, receipt).await.unwrap().0;
        assert_eq!(
            result["pending_details"][0]["reason"],
            failure_reason("permission_denied")
        );
        assert!(failure_reason("profile_data_unsafe_path").contains("不安全"));
        assert!(failure_reason("profile_data_permission_denied").contains("权限"));
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn manual_counts_use_admission_snapshot_despite_config_changes_and_history() {
        let (app, dir) = app();
        let registry = Registry::test_ready();
        let removed = uuid::Uuid::new_v4().to_string();
        let pending_id = uuid::Uuid::new_v4().to_string();
        let added = uuid::Uuid::new_v4().to_string();
        let historical = uuid::Uuid::new_v4().to_string();
        let historical_done = uuid::Uuid::new_v4().to_string();
        let snapshot = HashSet::from(["default".into(), removed.clone(), pending_id.clone()]);
        // The configuration changes while the manager pass is in flight.
        {
            let mut inner = app.inner.lock().await;
            let mut profile = inner.store.data.profiles[0].clone();
            profile.id = added;
            profile.name = "created-during-cleanup".into();
            inner.store.data.profiles.push(profile);
            inner
                .store
                .data
                .pending_profile_cleanup
                .push(historical.clone());
        }
        let receipt = CleanupReport {
            cleaned: 2,
            pending: 2,
            skipped: 0,
            results: vec![
                CleanupReceipt {
                    profile_id: removed,
                    runtime_epoch: None,
                    stopped: true,
                    error: None,
                },
                CleanupReceipt {
                    profile_id: pending_id.clone(),
                    runtime_epoch: None,
                    stopped: false,
                    error: None,
                },
                CleanupReceipt {
                    profile_id: historical.clone(),
                    runtime_epoch: None,
                    stopped: false,
                    error: None,
                },
                CleanupReceipt {
                    profile_id: historical_done,
                    runtime_epoch: None,
                    stopped: true,
                    error: None,
                },
            ],
        };
        let result = reconcile_snapshot(&app, &registry, receipt, Some(&snapshot))
            .await
            .unwrap()
            .0;
        assert_eq!(result["profile_count"], 3);
        assert_eq!(result["cleaned"], 1);
        assert_eq!(result["pending"], 1);
        assert_eq!(result["skipped"], 1);
        assert_eq!(result["pending_details"].as_array().unwrap().len(), 1);
        assert_eq!(result["pending_details"][0]["profile_id"], pending_id);
        assert!(app
            .inner
            .lock()
            .await
            .store
            .data
            .pending_profile_cleanup
            .contains(&historical));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn never_started_profiles_are_skipped_once_and_deleted_history_is_excluded() {
        let (app, dir) = app();
        let registry = Registry::test_ready();
        let absent = uuid::Uuid::new_v4().to_string();
        let snapshot = HashSet::from(["default".into(), absent]);
        let historical = uuid::Uuid::new_v4().to_string();
        registry.uncertain.lock().unwrap().insert(historical);
        for _ in 0..3 {
            let result = reconcile_snapshot(
                &app,
                &registry,
                CleanupReport {
                    cleaned: 0,
                    pending: 0,
                    skipped: 0,
                    results: vec![],
                },
                Some(&snapshot),
            )
            .await
            .unwrap()
            .0;
            assert_eq!(result["cleaned"], 0);
            assert_eq!(result["pending"], 0);
            assert_eq!(result["skipped"], 2);
            assert_eq!(result["profile_count"], 2);
            assert_eq!(result["pending_details"], json!([]));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
