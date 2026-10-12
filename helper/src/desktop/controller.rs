//! Native controller commands and bounded background listener lifecycle.
use eframe::egui;
use std::{
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use webauthn_helper::{Handle, Snapshot};
pub(super) const ACTION_TIMEOUT: Duration = Duration::from_secs(12);

pub(super) enum Command {
    StartListener(u16),
    StopListener,
    DecidePairing { id: String, approve: bool },
    AllowPairing(String),
    UsbEnabled(bool),
    UsbSelect(String),
    BleEnabled(bool),
    Shutdown,
}
pub(super) enum Event {
    Listening(String),
    Stopped(Result<(), String>),
    Approved,
    Allowed,
    Usb(webauthn_helper::fido_device::Status),
    Failed(String),
    Fatal(String),
    ShutdownFinished(Result<(), String>),
}

// Replace periodic snapshots instead of queuing them while the window is minimized.
pub(super) type LatestSnapshot = Arc<Mutex<Option<Snapshot>>>;

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) enum CloseState {
    #[default]
    Open,
    Stopping,
    Failed(String),
    ReadyToExit,
}
impl CloseState {
    pub(super) fn begin(&mut self) -> bool {
        if matches!(self, Self::Open) {
            *self = Self::Stopping;
            true
        } else {
            false
        }
    }
    pub(super) fn finish(&mut self, result: Result<(), String>) {
        if matches!(self, Self::Stopping) {
            *self = match result {
                Ok(()) => Self::ReadyToExit,
                Err(message) => Self::Failed(message),
            };
        }
    }
}

pub(super) fn parse_listen_address(text: &str) -> Result<u16, &'static str> {
    let text = text.trim();
    let text = text.strip_prefix("ws://").unwrap_or(text);
    let address: std::net::SocketAddr = text
        .strip_suffix('/')
        .unwrap_or(text)
        .parse()
        .map_err(|_| "Use 127.0.0.1:PORT, with a port from 1024 to 65535.")?;
    if address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) || address.port() < 1024
    {
        return Err("Only 127.0.0.1 and ports from 1024 to 65535 are supported.");
    }
    Ok(address.port())
}

pub(super) async fn stop_listener(handle: &mut Option<Handle>) -> Result<(), String> {
    if let Some(active) = handle.as_ref() {
        tokio::time::timeout(ACTION_TIMEOUT, active.shutdown())
            .await
            .map_err(|_| {
                "Shutdown timed out. Check OS Bluetooth controls before exiting.".to_string()
            })?
            .map_err(|error| error.to_string())?;
    }
    *handle = None;
    Ok(())
}

// Apply the actual local channel setting once. A duplicate command is not a
// request to restart a scanner or discard the current connection's start guard.
async fn apply_ble_setting(
    current: &mut bool,
    scan_attempted: &mut Option<String>,
    active: Option<&Handle>,
    enabled: bool,
) -> bool {
    if *current == enabled {
        return false;
    }
    *current = enabled;
    if let Some(active) = active {
        active.set_ble_enabled(enabled).await;
    }
    *scan_attempted = None;
    // Channel intent and actual scanning/stopped phases are distinct events.
    // Apply cancellation before logging, including with a slow console sink.
    webauthn_helper::diagnostics::ble_enabled(enabled);
    true
}

pub(super) fn backend(
    commands: Receiver<Command>,
    events: Sender<Event>,
    latest: LatestSnapshot,
    context: egui::Context,
) {
    backend_with_usb(
        commands,
        events,
        latest,
        context,
        webauthn_helper::fido_device::Controller::default(),
    );
}

pub(super) fn backend_with_usb(
    commands: Receiver<Command>,
    events: Sender<Event>,
    latest: LatestSnapshot,
    context: egui::Context,
    mut usb: webauthn_helper::fido_device::Controller,
) {
    let report = |event| {
        let _ = events.send(event);
        context.request_repaint();
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            report(Event::Fatal(format!(
                "Cannot start listener runtime: {error}"
            )));
            return;
        }
    };
    let session = webauthn_helper::ProcessSession::default();
    let mut handle: Option<Handle> = None;
    let mut next_snapshot = Instant::now();
    let mut scan_attempted: Option<String> = None;
    let mut cleanup_failed = false;
    let mut ble_enabled = true;
    usb.set_enabled(true);
    let mut usb_previous = None;
    loop {
        match commands.recv_timeout(Duration::from_millis(100)) {
            Ok(Command::Shutdown) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Ok(Command::StartListener(port)) => {
                if handle.is_some() || cleanup_failed {
                    report(Event::Failed(
                        "Stop the current listener before starting another.".into(),
                    ));
                    continue;
                }
                match runtime.block_on(async {
                    tokio::time::timeout(
                        ACTION_TIMEOUT,
                        webauthn_helper::launch_incoming_with_session(Some(port), session.clone()),
                    )
                    .await
                }) {
                    Ok(Ok(active)) => {
                        runtime.block_on(active.set_ble_enabled(ble_enabled));
                        report(Event::Listening(active.address().to_string()));
                        handle = Some(active);
                        scan_attempted = None;
                    }
                    Ok(Err(error)) => {
                        report(Event::Failed(format!("Cannot start listener: {error}")))
                    }
                    Err(_) => report(Event::Failed("Starting the listener timed out.".into())),
                }
                next_snapshot = Instant::now();
            }
            Ok(Command::StopListener) => {
                let result = runtime.block_on(async {
                    let usb_result = usb.shutdown().await.map_err(|e| e.to_string());
                    let listener_result = stop_listener(&mut handle).await;
                    usb_result.and(listener_result)
                });
                cleanup_failed = result.is_err();
                if result.is_ok() {
                    *latest.lock().unwrap_or_else(|e| e.into_inner()) = None;
                }
                report(Event::Stopped(result));
            }
            Ok(Command::AllowPairing(origin)) => {
                match session.allow_pairing_again(&origin) {
                    Ok(()) => report(Event::Allowed),
                    Err(error) => report(Event::Failed(error.to_string())),
                }
                next_snapshot = Instant::now();
            }
            Ok(Command::UsbEnabled(enabled)) => usb.set_enabled(enabled),
            Ok(Command::UsbSelect(id)) => {
                if let Err(error) = usb.select(&id) {
                    report(Event::Failed(error.to_string()));
                }
            }
            Ok(Command::BleEnabled(enabled)) => {
                if runtime.block_on(apply_ble_setting(
                    &mut ble_enabled,
                    &mut scan_attempted,
                    handle.as_ref(),
                    enabled,
                )) {
                    next_snapshot = Instant::now();
                }
            }
            Ok(Command::DecidePairing { id, approve }) => {
                let result = runtime.block_on(async {
                    let active = handle
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Start the listener first."))?;
                    tokio::time::timeout(ACTION_TIMEOUT, active.decide_pending(&id, approve))
                        .await??;
                    Ok::<(), anyhow::Error>(())
                });
                match result {
                    Ok(()) => report(Event::Approved),
                    Err(error) => report(Event::Failed(error.to_string())),
                }
                next_snapshot = Instant::now();
            }
        }
        runtime.block_on(usb.tick(handle.as_ref()));
        let status = usb.status();
        if usb_previous.as_ref() != Some(&status) {
            report(Event::Usb(status.clone()));
            usb_previous = Some(status);
        }
        if Instant::now() >= next_snapshot {
            if let Some(active) = handle.as_ref() {
                if let Ok(snapshot) = runtime.block_on(async {
                    tokio::time::timeout(Duration::from_millis(500), active.snapshot()).await
                }) {
                    // Start and local pairing approval authorize receive-only scanning for
                    // this one browser connection. Never dial a browser or a backend.
                    if !snapshot.connected {
                        scan_attempted = None;
                    }
                    if ble_enabled
                        && snapshot.connected
                        && scan_attempted != snapshot.connection_id
                        && !snapshot.needs_restart
                        && !cleanup_failed
                    {
                        scan_attempted = snapshot.connection_id.clone();
                        if let Err(error) = runtime.block_on(active.start()) {
                            report(Event::Failed(error.to_string()));
                        }
                    }
                    *latest.lock().unwrap_or_else(|e| e.into_inner()) = Some(snapshot);
                    context.request_repaint();
                }
            }
            next_snapshot = Instant::now() + Duration::from_millis(250);
        }
    }
    let result = runtime.block_on(async {
        let usb_result = usb.shutdown().await.map_err(|e| e.to_string());
        let listener_result = stop_listener(&mut handle).await;
        usb_result.and(listener_result)
    });
    runtime.shutdown_timeout(Duration::from_secs(1));
    report(Event::ShutdownFinished(result));
}

#[cfg(test)]
mod tests {

    #[derive(Clone, Default)]
    struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Capture {
        fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
            let writer = self.clone();
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_target(false)
                .with_max_level(tracing::Level::INFO)
                .with_writer(move || writer.clone())
                .finish()
        }
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    #[test]
    fn idle_backend_logs_ble_setting_changes_before_listener_start_exactly_once() {
        let capture = Capture::default();
        let worker_capture = capture.clone();
        let (commands, receiver) = std::sync::mpsc::channel();
        let (events, results) = std::sync::mpsc::channel();
        let latest = std::sync::Arc::new(std::sync::Mutex::new(None));
        let worker = std::thread::spawn(move || {
            tracing::subscriber::with_default(worker_capture.subscriber(), || {
                super::backend(receiver, events, latest, eframe::egui::Context::default());
            });
        });
        for enabled in [true, false, false, true, true] {
            commands.send(super::Command::BleEnabled(enabled)).unwrap();
        }
        commands.send(super::Command::Shutdown).unwrap();
        loop {
            match results
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap()
            {
                super::Event::ShutdownFinished(result) => {
                    assert!(result.is_ok());
                    break;
                }
                super::Event::Listening(_) => panic!("Idle toggles must not start the listener"),
                _ => {}
            }
        }
        worker.join().unwrap();
        let text = capture.text();
        assert_eq!(text.matches("INFO BLE: disabled").count(), 1, "{text}");
        assert_eq!(text.matches("INFO BLE: enabled").count(), 1, "{text}");
        assert!(
            !text.contains("scanning") && !text.contains("starting") && !text.contains("Connected"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn ble_command_preserves_active_scan_attempt_on_duplicate_and_clears_on_change() {
        use tracing::instrument::WithSubscriber;
        let capture = Capture::default();
        async {
            let mut enabled = true;
            let mut attempted = Some("existing-approved-connection".to_owned());
            assert!(!super::apply_ble_setting(&mut enabled, &mut attempted, None, true).await);
            assert_eq!(attempted.as_deref(), Some("existing-approved-connection"));
            assert!(capture.text().is_empty());
            assert!(super::apply_ble_setting(&mut enabled, &mut attempted, None, false).await);
            assert!(!enabled && attempted.is_none());
            assert!(!super::apply_ble_setting(&mut enabled, &mut attempted, None, false).await);
            assert!(super::apply_ble_setting(&mut enabled, &mut attempted, None, true).await);
            assert!(enabled && attempted.is_none());
            attempted = Some("resumed-approved-connection".to_owned());
            assert!(!super::apply_ble_setting(&mut enabled, &mut attempted, None, true).await);
            assert_eq!(attempted.as_deref(), Some("resumed-approved-connection"));
        }
        .with_subscriber(capture.subscriber())
        .await;
        let text = capture.text();
        assert_eq!(text.matches("INFO BLE: disabled").count(), 1, "{text}");
        assert_eq!(text.matches("INFO BLE: enabled").count(), 1, "{text}");
        assert!(
            !text.contains("approved-connection") && !text.contains("scanning"),
            "{text}"
        );
    }

    use super::*;

    #[test]
    fn listen_address_accepts_only_loopback_socket() {
        assert_eq!(parse_listen_address(" 127.0.0.1:10233 "), Ok(10233));
        assert_eq!(parse_listen_address(" ws://127.0.0.1:10233 "), Ok(10233));
        assert_eq!(parse_listen_address("ws://127.0.0.1:12000/"), Ok(12000));
        for input in [
            "0.0.0.0:10233",
            "192.168.1.1:10233",
            "[::1]:10233",
            "127.0.0.1:80",
            "127.0.0.1:65536",
            "10233",
            "https://example.com",
            "http://127.0.0.1:10233",
            "wss://127.0.0.1:10233",
            "ws://localhost:10233",
            "ws://0.0.0.0:10233",
            "ws://127.0.0.1:80",
            "ws://127.0.0.1:10233/bridge",
            "ws://user@127.0.0.1:10233",
            "ws://127.0.0.1:10233?token=secret",
            "ws://127.0.0.1:10233#fragment",
            "",
        ] {
            assert!(parse_listen_address(input).is_err(), "{input}");
        }
    }

    #[test]
    fn repeated_close_requests_do_not_restart_shutdown() {
        let mut state = CloseState::Open;
        assert!(state.begin());
        assert!(!state.begin());
        state.finish(Ok(()));
        assert_eq!(state, CloseState::ReadyToExit);
        state.finish(Err("stale".into()));
        assert_eq!(state, CloseState::ReadyToExit);
    }

    #[test]
    fn failed_shutdown_requires_explicit_exit() {
        let mut state = CloseState::Open;
        state.begin();
        state.finish(Err("OS cleanup failed".into()));
        assert!(matches!(state, CloseState::Failed(_)));
        assert!(!state.begin());
        state.finish(Ok(()));
        assert!(matches!(state, CloseState::Failed(_)));
    }

    #[tokio::test]
    async fn stopping_listener_closes_real_socket_and_allows_rebind() {
        let mut handle = Some(webauthn_helper::launch(Some(10233)).await.unwrap());
        let address = handle.as_ref().unwrap().address();
        assert!(tokio::net::TcpStream::connect(address).await.is_ok());
        stop_listener(&mut handle).await.unwrap();
        assert!(handle.is_none());
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
        let mut reopened = Some(webauthn_helper::launch(Some(address.port())).await.unwrap());
        assert_eq!(reopened.as_ref().unwrap().address(), address);
        stop_listener(&mut reopened).await.unwrap();
    }
}
