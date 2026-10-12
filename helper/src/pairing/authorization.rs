//! Process-only Origin approval, explicit local withholding and one-use tokens.

use crate::pairing::state::Inner;
use std::{collections::HashSet, sync::Arc};
pub(crate) const MAX_WITHHELD_ORIGINS: usize = 256;

/// Volatile authorization shared by all listeners in one CLI/Desktop process.
/// Never serialize this state. Browser tokens/session IDs cannot reset local consent.
#[derive(Clone, Default)]
pub struct ProcessSession(Arc<std::sync::Mutex<SessionMemory>>);
#[derive(Default)]
pub(crate) struct SessionMemory {
    pub(crate) approved_origins: HashSet<String>,
    pub(crate) used_tokens: HashSet<String>,
    pub(crate) withheld_origins: HashSet<String>,
    pub(crate) withholding_saturated: bool,
}
impl SessionMemory {
    pub(crate) fn withheld(&self, origin: &str) -> bool {
        self.withholding_saturated || self.withheld_origins.contains(origin)
    }
    pub(crate) fn withhold(&mut self, origin: &str) {
        if self.withheld_origins.contains(origin) {
            return;
        }
        if self.withheld_origins.len() < MAX_WITHHELD_ORIGINS {
            self.withheld_origins.insert(origin.into());
        } else {
            // Never evict an explicit refusal or reopen it on a timer. Overflow
            // fails closed until a local process restart resets all consent.
            self.withholding_saturated = true;
        }
    }
}
impl ProcessSession {
    pub(crate) fn memory(&self) -> std::sync::MutexGuard<'_, SessionMemory> {
        self.0.lock().unwrap_or_else(|error| error.into_inner())
    }
    pub(crate) fn withheld(&self, origin: &str) -> bool {
        self.memory().withheld(origin)
    }
    /// Explicit local reset of withholding only. This does not grant approval.
    pub fn allow_pairing_again(&self, origin: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            crate::pairing::protocol::valid_origin(origin),
            "Use an exact HTTP(S) Origin without a trailing slash."
        );
        let mut memory = self.memory();
        anyhow::ensure!(
            !memory.withholding_saturated,
            "Too many withheld Origins. Restart the helper to reset local consent."
        );
        memory.withheld_origins.remove(origin);
        Ok(())
    }
    pub(crate) fn revoke_approved(&self) {
        let mut memory = self.memory();
        let approved: Vec<_> = memory.approved_origins.drain().collect();
        for origin in approved {
            memory.withhold(&origin);
        }
    }
}
/// Withhold after local Reject/Revoke/Stop, including CLI refusal without a TTY.
/// Timeout, network loss and finite lease expiry must not create this latch.
pub(crate) fn refuse_current(session: &ProcessSession, inner: &Inner) {
    let mut memory = session.memory();
    if let Some(pending) = &inner.pending {
        memory.withhold(&pending.origin);
    }
    if let Some(pairing) = &inner.pairing {
        memory.withhold(&pairing.origin);
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::pairing::protocol::random_secret;

    use crate::testing::{session_socket, socket_state, test_port, wait_snapshot};
    use crate::{launch_incoming_with_session, ProcessSession};

    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn approved_exact_origin_survives_listener_restart_but_not_new_process_session() {
        let session = ProcessSession::default();
        let handle = launch_incoming_with_session(Some(test_port()), session.clone())
            .await
            .unwrap();
        let origin = "https://session.example:8443";
        let mut first = session_socket(&handle, origin, &random_secret()).await;
        let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some())
            .await
            .pending_approval
            .unwrap();
        assert!(session.memory().approved_origins.is_empty());
        handle.decide_pending(&pending.id, true).await.unwrap();
        assert_eq!(socket_state(&mut first).await, "paired");
        first.close(None).await.unwrap();
        wait_snapshot(&handle, |s| !s.connected).await;
        let mut again = session_socket(&handle, origin, &random_secret()).await;
        assert_eq!(socket_state(&mut again).await, "paired");
        assert!(handle.snapshot().await.pending_approval.is_none());
        let port = handle.address().port();
        handle.shutdown().await.unwrap();
        let restarted = launch_incoming_with_session(Some(port), session.clone())
            .await
            .unwrap();
        assert!(session.memory().approved_origins.contains(origin));
        assert!(session.withheld(origin));
        session.allow_pairing_again(origin).unwrap();
        let mut again = session_socket(&restarted, origin, &random_secret()).await;
        assert_eq!(socket_state(&mut again).await, "paired");
        again.close(None).await.unwrap();
        wait_snapshot(&restarted, |s| !s.connected).await;
        for other in [
            "http://session.example:8443",
            "https://session.example",
            "https://other.example:8443",
        ] {
            let mut candidate = session_socket(&restarted, other, &random_secret()).await;
            let pending = wait_snapshot(&restarted, |s| s.pending_approval.is_some())
                .await
                .pending_approval
                .unwrap();
            assert_eq!(pending.origin, other);
            restarted.decide_pending(&pending.id, false).await.unwrap();
            assert_eq!(socket_state(&mut candidate).await, "closed");
            assert!(!session.memory().approved_origins.contains(other));
        }
        restarted.shutdown().await.unwrap();
        assert!(session.memory().approved_origins.contains(origin));
        // A new executable constructs a new session; no persisted state can seed it.
        let fresh = launch_incoming_with_session(Some(port), ProcessSession::default())
            .await
            .unwrap();
        let mut candidate = session_socket(&fresh, origin, &random_secret()).await;
        let pending = wait_snapshot(&fresh, |s| s.pending_approval.is_some())
            .await
            .pending_approval
            .unwrap();
        fresh.decide_pending(&pending.id, false).await.unwrap();
        assert_eq!(socket_state(&mut candidate).await, "closed");
        fresh.shutdown().await.unwrap();
        restarted.revoke().await.unwrap();
        assert!(session.memory().approved_origins.is_empty());
    }

    #[tokio::test]
    async fn failed_or_expired_confirmation_does_not_remember_origin() {
        let session = ProcessSession::default();
        let handle = launch_incoming_with_session(Some(test_port()), session.clone())
            .await
            .unwrap();
        let origin = "https://failed-confirmation.example";
        let mut socket = session_socket(&handle, origin, &random_secret()).await;
        let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some())
            .await
            .pending_approval
            .unwrap();
        assert!(handle.decide_pending("wrong-id", true).await.is_err());
        handle
            .app
            .inner
            .lock()
            .await
            .pending
            .as_mut()
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        assert!(handle.decide_pending(&pending.id, true).await.is_err());
        assert_eq!(socket_state(&mut socket).await, "closed");
        assert!(session.memory().approved_origins.is_empty());
        assert!(
            !session.withheld(origin),
            "Approval timeout must remain retryable"
        );
        let mut socket = session_socket(&handle, origin, &random_secret()).await;
        wait_snapshot(&handle, |s| s.pending_approval.is_some()).await;
        socket.close(None).await.unwrap();
        wait_snapshot(&handle, |s| s.pending_approval.is_none()).await;
        assert!(session.memory().approved_origins.is_empty());
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn explicit_reject_survives_fresh_session_and_token_until_local_allow() {
        let process = ProcessSession::default();
        let handle = launch_incoming_with_session(Some(test_port()), process.clone())
            .await
            .unwrap();
        let origin = "https://refusal.example";
        let mut first = session_socket(&handle, origin, &random_secret()).await;
        let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some())
            .await
            .pending_approval
            .unwrap();
        handle.decide_pending(&pending.id, false).await.unwrap();
        assert_eq!(socket_state(&mut first).await, "closed");
        drop(first);
        for _ in 0..4 {
            let mut retry = session_socket(&handle, origin, &random_secret()).await;
            assert_eq!(socket_state(&mut retry).await, "closed");
            assert!(handle.snapshot().await.pending_approval.is_none());
            assert!(!handle.snapshot().await.connected);
        }
        process.allow_pairing_again(origin).unwrap();
        assert!(!process.memory().approved_origins.contains(origin));
        let mut next = session_socket(&handle, origin, &random_secret()).await;
        let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some())
            .await
            .pending_approval
            .unwrap();
        assert!(!handle.snapshot().await.connected);
        handle.decide_pending(&pending.id, true).await.unwrap();
        assert_eq!(socket_state(&mut next).await, "paired");
        handle.shutdown().await.unwrap();
    }

    #[test]
    fn origin_withholding_is_bounded_and_overflow_never_evicts_or_auto_resets() {
        let process = ProcessSession::default();
        for index in 0..MAX_WITHHELD_ORIGINS {
            process
                .memory()
                .withhold(&format!("https://example{index}.com"));
        }
        assert_eq!(
            process.memory().withheld_origins.len(),
            MAX_WITHHELD_ORIGINS
        );
        process.memory().withhold("https://overflow.example");
        assert!(process.withheld("https://example0.com"));
        assert!(process.withheld("https://overflow.example"));
        assert!(process.withheld("https://unknown.example"));
        assert!(process.allow_pairing_again("https://example0.com").is_err());
        assert!(process.memory().withholding_saturated);
        assert!(!ProcessSession::default().withheld("https://example0.com"));
    }

    #[tokio::test]
    async fn local_allow_after_revoke_needs_new_approval_but_stop_retains_previous_approval() {
        for revoke in [false, true] {
            let process = ProcessSession::default();
            let handle = launch_incoming_with_session(Some(test_port()), process.clone())
                .await
                .unwrap();
            let origin = "https://local-reset.example";
            let mut first = session_socket(&handle, origin, &random_secret()).await;
            let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some())
                .await
                .pending_approval
                .unwrap();
            handle.decide_pending(&pending.id, true).await.unwrap();
            assert_eq!(socket_state(&mut first).await, "paired");
            if revoke {
                handle.revoke().await.unwrap();
            } else {
                handle.stop().await.unwrap();
            }
            wait_snapshot(&handle, |s| !s.connected && s.origin.is_none()).await;
            assert!(process.withheld(origin));
            assert_eq!(process.memory().approved_origins.contains(origin), !revoke);
            let mut retry = session_socket(&handle, origin, &random_secret()).await;
            assert_eq!(socket_state(&mut retry).await, "closed");
            assert!(handle.snapshot().await.pending_approval.is_none());
            process.allow_pairing_again(origin).unwrap();
            let mut allowed = session_socket(&handle, origin, &random_secret()).await;
            if revoke {
                let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some())
                    .await
                    .pending_approval
                    .unwrap();
                assert!(!process.memory().approved_origins.contains(origin));
                handle.decide_pending(&pending.id, true).await.unwrap();
            }
            assert_eq!(socket_state(&mut allowed).await, "paired");
            handle.shutdown().await.unwrap();
        }
    }

    #[test]
    fn revoke_withholds_disconnected_approved_origins_and_local_reset_is_exact() {
        let process = ProcessSession::default();
        process
            .memory()
            .approved_origins
            .insert("https://one.example".into());
        process
            .memory()
            .approved_origins
            .insert("https://two.example".into());
        process.revoke_approved();
        assert!(process.memory().approved_origins.is_empty());
        assert!(process.withheld("https://one.example"));
        assert!(process.withheld("https://two.example"));
        assert!(process
            .allow_pairing_again("https://one.example/path")
            .is_err());
        process.allow_pairing_again("https://one.example").unwrap();
        assert!(!process.withheld("https://one.example"));
        assert!(process.withheld("https://two.example"));
        assert!(process.memory().approved_origins.is_empty());
    }
}
