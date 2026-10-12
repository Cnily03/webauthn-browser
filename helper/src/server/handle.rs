//! Local capability controls, display snapshots, and bounded listener shutdown.

use super::http::{approve, revoke, start, stop};
use crate::pairing::{
    authorization::refuse_current,
    protocol::{secret_eq, Approval, MAX_HANDSHAKES},
    state::{App, BleState, ConnectionEvent, PendingApproval, Snapshot},
};
use axum::{extract::State, http::HeaderMap, response::Response, Json};
use std::time::{Duration, Instant};
use tokio::sync::watch;
#[derive(Clone)]
pub struct Handle {
    pub(crate) app: App,
    pub(crate) shutdown: watch::Sender<bool>,
    pub(crate) server_done: watch::Receiver<bool>,
}
impl Handle {
    /// Attach a locally supplied opaque endpoint to this exact, already paired session.
    /// This local attachment call does not open an OS device or grant pairing consent.
    /// Its renewable lease is capped at 30 seconds and the paired session expiry.
    pub async fn attach_experimental_fido(
        &self,
        session_id: &str,
        endpoint: fido_report_relay::Endpoint,
    ) -> anyhow::Result<()> {
        crate::relay::fido::attach(&self.app, session_id, endpoint).await
    }
    pub fn address(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], self.app.port))
    }
    pub fn websocket_url(&self) -> String {
        format!("ws://{}", self.address())
    }
    /// Drain successful connection events exactly once, including already closed sockets.
    pub async fn take_connection_events(&self) -> Vec<ConnectionEvent> {
        std::mem::take(&mut self.app.inner.lock().await.connection_events)
    }
    pub async fn snapshot(&self) -> Snapshot {
        let i = self.app.inner.lock().await;
        let memory = self.app.session.memory();
        let mut withheld_origins: Vec<_> = memory.withheld_origins.iter().cloned().collect();
        withheld_origins.sort();
        Snapshot {
            port: self.app.port,
            withheld_origins,
            withholding_saturated: memory.withholding_saturated,
            needs_restart: i.cleanup_failed,
            status: i.status.clone(),
            connected: i.connected,
            connection_id: i
                .pairing
                .as_ref()
                .filter(|_| i.connected)
                .and_then(|p| p.request_id.clone()),
            scanning: i.ble_state == BleState::Scanning,
            ble_state: i.ble_state,
            advertisements: i.count,
            origin: i.pairing.as_ref().map(|p| p.origin.clone()),
            pending_approval: i
                .pending
                .as_ref()
                .filter(|pending| !pending.approved && pending.expires > Instant::now())
                .map(|pending| PendingApproval {
                    id: pending.id.clone(),
                    origin: pending.origin.clone(),
                    expires_in: pending
                        .expires
                        .saturating_duration_since(Instant::now())
                        .as_secs(),
                }),
            expires_in: i.pairing.as_ref().map(|p| {
                p.expires
                    .saturating_duration_since(Instant::now())
                    .as_secs()
            }),
        }
    }
    // Direct local callers use the same validation and state transitions as HTTP controls.
    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "authorization",
            format!("Bearer {}", self.app.secret).parse().unwrap(),
        );
        h.insert(
            "origin",
            format!("http://127.0.0.1:{}", self.app.port)
                .parse()
                .unwrap(),
        );
        h
    }
    /// Explicit native UI confirmation of this one inbound browser request.
    pub async fn decide_pending(&self, id: &str, approve: bool) -> anyhow::Result<()> {
        let mut inner = self.app.inner.lock().await;
        anyhow::ensure!(
            self.app.incoming_pairing
                && !inner.stopping
                && !inner.connected
                && !inner.cleanup_failed,
            "Incoming pairing is not available."
        );
        let pending = inner
            .pending
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("The browser pairing request is no longer active."))?;
        anyhow::ensure!(
            secret_eq(&pending.id, id) && pending.expires > Instant::now(),
            "The browser pairing request changed or expired."
        );
        if approve {
            pending.approved = true;
        } else {
            refuse_current(&self.app.session, &inner);
            inner.pending = None;
            inner.epoch = inner.epoch.wrapping_add(1);
        }
        Ok(())
    }
    pub async fn approve(&self, origin: &str, token: &str) -> anyhow::Result<()> {
        control_result(
            approve(
                State(self.app.clone()),
                self.headers(),
                Json(Approval {
                    origin: origin.into(),
                    token: token.into(),
                }),
            )
            .await,
        )
        .await
    }
    /// Enable/disable this listener's BLE channel without revoking pairing or USB.
    /// Re-enabling permits a separate start; it never starts OS discovery itself.
    pub async fn set_ble_enabled(&self, enabled: bool) {
        let mut inner = self.app.inner.lock().await;
        inner.ble_enabled = enabled;
        if !enabled {
            if let Some(scan) = &inner.scan {
                scan.send_replace(false);
            }
            if !inner.cleanup_failed
                && matches!(inner.ble_state, BleState::Starting | BleState::Scanning)
            {
                inner.ble_state = BleState::Stopping;
            }
        }
    }
    pub async fn start(&self) -> anyhow::Result<()> {
        control_result(start(State(self.app.clone()), self.headers()).await).await
    }
    pub async fn stop(&self) -> anyhow::Result<()> {
        control_result(stop(State(self.app.clone()), self.headers()).await).await
    }
    pub async fn revoke(&self) -> anyhow::Result<()> {
        control_result(revoke(State(self.app.clone()), self.headers()).await).await
    }
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.app.inner.lock().await.stopping = true;
        // Listener shutdown preserves process approval while refusing this active attempt.
        control_result(stop(State(self.app.clone()), self.headers()).await).await?;
        let _ = self.shutdown.send(true);
        // Allow the bounded OS stop_scan cleanup to finish before the UI drops its runtime.
        let end = tokio::time::Instant::now() + Duration::from_secs(6);
        while self.app.inner.lock().await.connected {
            if tokio::time::Instant::now() >= end {
                anyhow::bail!("Bluetooth cleanup did not finish. Check OS Bluetooth controls.");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if self.app.inner.lock().await.cleanup_failed {
            anyhow::bail!("OS did not confirm Bluetooth stopped. Check OS Bluetooth controls.");
        }
        let mut done = self.server_done.clone();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !*done.borrow() {
                done.changed().await.map_err(|_| {
                    anyhow::anyhow!("The listener exited without confirming shutdown.")
                })?;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("The local listener did not finish shutting down."))??;
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.app.connection_slot.available_permits() != MAX_HANDSHAKES {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("Browser sockets did not finish shutting down."))?;
        Ok(())
    }
}
pub(crate) async fn control_result(response: Response) -> anyhow::Result<()> {
    if response.status().is_success() {
        return Ok(());
    }
    let body = axum::body::to_bytes(response.into_body(), 8192).await?;
    anyhow::bail!("{}", String::from_utf8_lossy(&body));
}

#[cfg(test)]
mod tests {

    use crate::pairing::protocol::random_secret;
    use crate::pairing::state::BleState;
    use crate::testing::{app, session_socket, socket_state, test_port, wait_snapshot};
    use crate::{launch_incoming, Handle};

    use tokio::sync::watch;

    #[tokio::test]
    async fn ble_opt_out_preserves_pairing_usb_and_local_consent() {
        let app = app();
        let (shutdown, _) = watch::channel(false);
        let (_, server_done) = watch::channel(true);
        let handle = Handle {
            app,
            shutdown,
            server_done,
        };
        let origin = "https://channel.example";
        let request = random_secret();
        let session = random_secret();
        let (scan, scan_state) = watch::channel(true);
        {
            let mut inner = handle.app.inner.lock().await;
            inner.connected = true;
            inner.connection_owner = Some((request.clone(), 0));
            inner.pairing = Some(crate::pairing::state::Pairing {
                explicit_approval: true,
                request_id: Some(request),
                session_id: Some(session.clone()),
                origin: origin.into(),
                token: None,
                expires: std::time::Instant::now() + std::time::Duration::from_secs(20),
            });
            inner.scan = Some(scan);
            inner.ble_state = BleState::Scanning;
        }
        let (endpoint, device) = fido_report_relay::endpoint_pair();
        handle
            .attach_experimental_fido(&session, endpoint)
            .await
            .unwrap();
        handle.set_ble_enabled(false).await;
        assert!(!*scan_state.borrow());
        assert_eq!(handle.snapshot().await.ble_state, BleState::Stopping);
        assert!(handle.snapshot().await.connected);
        assert!(!device.is_closed());
        assert!(handle
            .start()
            .await
            .unwrap_err()
            .to_string()
            .contains("disabled"));
        assert!(handle.snapshot().await.withheld_origins.is_empty());
        handle.set_ble_enabled(true).await;
        assert!(
            !*scan_state.borrow(),
            "re-enable itself never starts discovery"
        );
        handle.start().await.unwrap();
        assert!(*scan_state.borrow());
        assert!(!device.is_closed());
        handle.revoke().await.unwrap();
        handle.set_ble_enabled(false).await;
        handle.set_ble_enabled(true).await;
        assert!(device.is_closed());
        assert_eq!(handle.snapshot().await.withheld_origins, vec![origin]);
        assert!(handle.start().await.is_err());
    }

    #[tokio::test]
    async fn direct_handle_requires_explicit_pairing_and_start_and_hides_secrets() {
        let app = app();
        let secret = app.secret.clone();
        let (shutdown, _) = watch::channel(false);
        let (_, server_done) = watch::channel(true);
        let handle = Handle {
            app,
            shutdown,
            server_done,
        };
        assert!(!handle.snapshot().await.scanning);
        assert!(handle.start().await.is_err());
        let token = "T".repeat(32);
        handle.approve("https://example.com", &token).await.unwrap();
        let snapshot = handle.snapshot().await;
        assert!(!snapshot.scanning);
        assert!(!snapshot.connected);
        assert_eq!(snapshot.origin.as_deref(), Some("https://example.com"));
        let debug = format!("{snapshot:?}");
        assert!(!debug.contains(&token));
        assert!(!debug.contains(&secret));
        assert!(handle.start().await.is_err());
        handle.revoke().await.unwrap();
        assert!(handle.snapshot().await.origin.is_none());
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn scan_request_is_not_reported_as_confirmed_scanning() {
        let app = app();
        let (tx, _rx) = watch::channel(true);
        {
            let mut inner = app.inner.lock().await;
            inner.scan = Some(tx);
            inner.ble_state = BleState::Starting;
        }
        let (shutdown, _) = watch::channel(false);
        let (_, server_done) = watch::channel(true);
        let handle = Handle {
            app,
            shutdown,
            server_done,
        };
        assert_eq!(handle.snapshot().await.ble_state, BleState::Starting);
        assert!(!handle.snapshot().await.scanning);
        handle.app.inner.lock().await.ble_state = BleState::Scanning;
        assert!(handle.snapshot().await.scanning);
    }

    #[tokio::test]
    async fn connection_events_survive_rapid_reconnect_and_exclude_denials() {
        let handle = launch_incoming(Some(test_port())).await.unwrap();
        let origin = "https://connection-events.example:8443";
        let mut first = session_socket(&handle, origin, &random_secret()).await;
        let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some())
            .await
            .pending_approval
            .unwrap();
        // Socket upgrade and a waiting request are not successful connections.
        assert!(handle.take_connection_events().await.is_empty());
        let before = std::time::SystemTime::now();
        handle.decide_pending(&pending.id, true).await.unwrap();
        assert_eq!(socket_state(&mut first).await, "paired");
        first.close(None).await.unwrap();
        wait_snapshot(&handle, |s| !s.connected).await;
        let mut second = session_socket(&handle, origin, &random_secret()).await;
        assert_eq!(socket_state(&mut second).await, "paired");
        second.close(None).await.unwrap();
        wait_snapshot(&handle, |s| !s.connected).await;
        // Deliberately consume neither event until both connections have ended.
        let events = handle.take_connection_events().await;
        assert_eq!(events.len(), 2);
        assert_ne!(events[0].connection_id, events[1].connection_id);
        for event in events {
            assert_eq!(event.origin, origin);
            assert!(event.connected_at >= before);
            assert!(event.connected_at <= std::time::SystemTime::now());
        }
        assert!(handle.take_connection_events().await.is_empty());
        let mut denied = session_socket(&handle, "https://denied.example", &random_secret()).await;
        let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some())
            .await
            .pending_approval
            .unwrap();
        handle.decide_pending(&pending.id, false).await.unwrap();
        assert_eq!(socket_state(&mut denied).await, "closed");
        assert!(handle.take_connection_events().await.is_empty());
        handle.shutdown().await.unwrap();
    }
}
