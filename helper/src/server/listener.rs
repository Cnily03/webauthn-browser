//! Loopback binding and bounded listener startup.
use super::{handle::Handle, http::router};
use crate::pairing::{
    authorization::ProcessSession,
    protocol::{random_secret, MAX_HANDSHAKES},
    state::{App, BleState, Inner},
};
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
pub const DEFAULT_PORT: u16 = 10233;
fn valid_port(port: u16) -> bool {
    port >= 1024
}
async fn bind_available(preferred: u16) -> std::io::Result<tokio::net::TcpListener> {
    // Bind directly and retain the listener: no probe/rebind race and no request
    // is sent to an existing service. Stay loopback-only for every fallback.
    for offset in 0..20u16 {
        let Some(port) = preferred.checked_add(offset) else {
            break;
        };
        match tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await {
            Ok(listener) => return Ok(listener),
            Err(e)
                if e.kind() == std::io::ErrorKind::AddrInUse
                    || e.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(e) => return Err(e),
        }
    }
    tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await
}
/// Launch the loopback bridge without opening any browser or starting Bluetooth.
/// Keep the calling Tokio runtime alive until shutdown completes.
pub async fn launch(preferred_port: Option<u16>) -> anyhow::Result<Handle> {
    launch_mode(preferred_port, false, ProcessSession::default()).await
}
/// CLI and Desktop accept one bounded inbound request for explicit local approval.
pub async fn launch_incoming(preferred_port: Option<u16>) -> anyhow::Result<Handle> {
    launch_incoming_with_session(preferred_port, ProcessSession::default()).await
}
/// Launch the native Desktop bridge with the shared incoming approval flow.
pub async fn launch_desktop(preferred_port: Option<u16>) -> anyhow::Result<Handle> {
    launch_incoming(preferred_port).await
}
/// Reuse only for listener restarts in the same running CLI/Desktop process.
pub async fn launch_incoming_with_session(
    port: Option<u16>,
    session: ProcessSession,
) -> anyhow::Result<Handle> {
    launch_mode(port, true, session).await
}
async fn launch_mode(
    preferred_port: Option<u16>,
    incoming_pairing: bool,
    session: ProcessSession,
) -> anyhow::Result<Handle> {
    let preferred_port = match preferred_port {
        Some(p) if valid_port(p) => p,
        Some(_) => anyhow::bail!("Choose a port from 1024 to 65535."),
        None => DEFAULT_PORT,
    };
    let listener = bind_available(preferred_port).await?;
    let port = listener.local_addr()?.port();
    let app = App {
        secret: random_secret(),
        port,
        session,
        incoming_pairing,
        connection_slot: Arc::new(tokio::sync::Semaphore::new(MAX_HANDSHAKES)),
        inner: Arc::new(Mutex::new(Inner {
            stopping: false,
            epoch: 0,
            cleanup_failed: false,
            pairing: None,
            pending: None,
            fido: None,
            connected: false,
            connection_owner: None,
            connection_events: Vec::new(),
            ble_enabled: true,
            scan: None,
            ble_state: BleState::Stopped,
            status: if incoming_pairing {
                "Ready. Connect from the webpage, then confirm its Origin here."
            } else {
                "Ready. Approve the exact webpage origin and one-use pairing token."
            }
            .into(),
            count: 0,
        })),
    };
    let (shutdown, mut stop_rx) = watch::channel(false);
    let (done_tx, server_done) = watch::channel(false);
    let handle = Handle {
        app: app.clone(),
        shutdown,
        server_done,
    };
    let error_app = app.clone();
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router(app))
            .with_graceful_shutdown(async move {
                while !*stop_rx.borrow() {
                    if stop_rx.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
        {
            error_app.inner.lock().await.status = format!("Local listener failed: {error}");
        }
        let _ = done_tx.send(true);
    });
    Ok(handle)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::pairing::protocol::random_secret;

    use crate::testing::{session_socket, socket_state, test_port, wait_snapshot};
    use crate::{launch_incoming_with_session, ProcessSession, DEFAULT_PORT};

    use std::time::Duration;

    #[test]
    fn port_validation_and_defaults() {
        assert_eq!(DEFAULT_PORT, 10233);
        assert!(!valid_port(0));
        assert!(!valid_port(1023));
        assert!(valid_port(1024));
        assert!(valid_port(65535));
    }

    #[tokio::test]
    async fn occupied_port_falls_back_without_touching_service() {
        let occupied = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = occupied.local_addr().unwrap().port();
        let selected = bind_available(port).await.unwrap();
        assert_ne!(selected.local_addr().unwrap().port(), port);
        assert!(selected.local_addr().unwrap().ip().is_loopback());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), occupied.accept())
                .await
                .is_err()
        );
        assert!(
            tokio::net::TcpListener::bind(selected.local_addr().unwrap())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn listener_stop_and_restart_preserves_pending_origin_withholding() {
        let process = ProcessSession::default();
        let handle = launch_incoming_with_session(Some(test_port()), process.clone())
            .await
            .unwrap();
        let address = handle.address();
        let origin = "https://restart.example";
        let mut first = session_socket(&handle, origin, &random_secret()).await;
        wait_snapshot(&handle, |s| s.pending_approval.is_some()).await;
        handle.shutdown().await.unwrap();
        assert_eq!(socket_state(&mut first).await, "closed");
        let restarted = launch_incoming_with_session(Some(address.port()), process)
            .await
            .unwrap();
        let mut retry = session_socket(&restarted, origin, &random_secret()).await;
        assert_eq!(socket_state(&mut retry).await, "closed");
        assert!(restarted.snapshot().await.pending_approval.is_none());
        restarted.shutdown().await.unwrap();
    }
}
