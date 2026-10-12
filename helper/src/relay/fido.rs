//! Opaque reports bound to a locally attached endpoint and one approved paired socket.
//! No report interpretation, credential storage, device discovery, or USB access.

use crate::pairing::{protocol::random_secret, state::App};
use fido_report_relay::{
    Endpoint, Sequence, Wire, MAX_BATCH, MAX_LEASE_MS, MAX_WIRE_BYTES, VERSION,
};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

const DIAGNOSTIC_INTERVAL: Duration = Duration::from_secs(5);

/// Only state flags, saturating counters and static reasons enter relay logs.
/// In particular, never format an attachment, frame, endpoint or caller input.
struct RelayDiagnostics {
    last_summary: Instant,
    offer_sent: bool,
    ready_sent: bool,
    browser_reports: u64,
    device_reports_queued: u64,
    device_reports_sent: u64,
    renewals: u64,
    waiting_renewals: u64,
    terminal_reason: &'static str,
}
impl Default for RelayDiagnostics {
    fn default() -> Self {
        Self {
            last_summary: Instant::now(),
            offer_sent: false,
            ready_sent: false,
            browser_reports: 0,
            device_reports_queued: 0,
            device_reports_sent: 0,
            renewals: 0,
            waiting_renewals: 0,
            terminal_reason: "attachment released",
        }
    }
}
impl RelayDiagnostics {
    fn sent(&mut self, frame_type: Option<&str>) {
        match frame_type {
            Some("fido_available") if !self.offer_sent => {
                self.offer_sent = true;
                tracing::info!(stage = "offer sent", "USB relay");
            }
            Some("fido_ready") if !self.ready_sent => {
                self.ready_sent = true;
                tracing::info!(stage = "ready sent", "USB relay");
            }
            Some("fido_report") => {
                if self.device_reports_sent == 0 {
                    tracing::info!(stage = "first device report sent", "USB relay");
                }
                self.device_reports_sent = self.device_reports_sent.saturating_add(1);
            }
            _ => {}
        }
    }
    fn summary(&self, advertised: bool, opened: bool, reason: &'static str) {
        tracing::debug!(
            advertised,
            offer_sent = self.offer_sent,
            opened,
            ready_sent = self.ready_sent,
            browser_reports = self.browser_reports,
            device_reports_queued = self.device_reports_queued,
            device_reports_sent = self.device_reports_sent,
            renewals = self.renewals,
            waiting_renewals = self.waiting_renewals,
            reason,
            "USB counters"
        );
    }
    fn periodic(&mut self, advertised: bool, opened: bool, now: Instant) {
        if now.saturating_duration_since(self.last_summary) >= DIAGNOSTIC_INTERVAL {
            self.last_summary = now;
            self.summary(advertised, opened, "periodic");
        }
    }
}

pub(crate) struct Attachment {
    request_id: String,
    session_id: String,
    origin: String,
    epoch: u64,
    relay_id: String,
    expires: Instant,
    advertised: bool,
    opened: bool,
    next_lease_sequence: u64,
    incoming: Sequence,
    outgoing: Sequence,
    endpoint: Endpoint,
    diagnostics: RelayDiagnostics,
}
impl Drop for Attachment {
    fn drop(&mut self) {
        tracing::info!(
            stage = "relay",
            reason = self.diagnostics.terminal_reason,
            "USB relay"
        );
        self.diagnostics.summary(
            self.advertised,
            self.opened,
            self.diagnostics.terminal_reason,
        );
    }
}

pub(crate) async fn attach(app: &App, session_id: &str, endpoint: Endpoint) -> anyhow::Result<()> {
    attach_bound(app, session_id, None, endpoint).await
}

pub(crate) async fn attach_bound(
    app: &App,
    session_id: &str,
    expected: Option<(&str, &str, u64)>,
    endpoint: Endpoint,
) -> anyhow::Result<()> {
    let mut inner = app.inner.lock().await;
    anyhow::ensure!(
        !inner.stopping && inner.connected && !inner.cleanup_failed && !endpoint.is_closed(),
        "Experimental FIDO requires a live paired connection and a local endpoint."
    );
    let pairing = inner
        .pairing
        .as_ref()
        .filter(|pairing| {
            pairing.session_id.as_deref() == Some(session_id)
                && pairing.expires > Instant::now()
                && pairing.token.is_none()
        })
        .ok_or_else(|| anyhow::anyhow!("The paired session changed or expired."))?;
    let request_id = pairing
        .request_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("The paired connection has no request identifier."))?;
    anyhow::ensure!(
        inner.connection_owned_by(&request_id, inner.epoch),
        "The paired connection changed."
    );
    anyhow::ensure!(
        expected.is_none_or(|(id, origin, epoch)| id == request_id
            && origin == pairing.origin
            && epoch == inner.epoch),
        "The selected USB session changed."
    );
    let attachment = Attachment {
        request_id,
        session_id: session_id.into(),
        origin: pairing.origin.clone(),
        epoch: inner.epoch,
        relay_id: random_secret(),
        expires: pairing
            .expires
            .min(Instant::now() + Duration::from_millis(MAX_LEASE_MS)),
        advertised: false,
        opened: false,
        next_lease_sequence: 1,
        incoming: Sequence::default(),
        outgoing: Sequence::default(),
        endpoint,
        diagnostics: RelayDiagnostics::default(),
    };
    // Replacement requires this local attachment path and a live pairing. Dropping
    // the old endpoint cancels both directions; a fresh ID rejects late old frames.
    if let Some(previous) = inner.fido.as_mut() {
        previous.diagnostics.terminal_reason = "attachment replaced";
    }
    inner.fido = Some(attachment);
    Ok(())
}

fn caller_matches(attachment: &Attachment, request_id: &str, origin: &str, epoch: u64) -> bool {
    attachment.epoch == epoch && attachment.request_id == request_id && attachment.origin == origin
}

/// Cleanup may be called after a replacement socket has taken ownership.
pub(crate) fn cancel_owned(
    inner: &mut crate::pairing::state::Inner,
    request_id: &str,
    origin: &str,
    epoch: u64,
) {
    if inner
        .fido
        .as_ref()
        .is_some_and(|attachment| caller_matches(attachment, request_id, origin, epoch))
    {
        if let Some(attachment) = inner.fido.as_mut() {
            if attachment.diagnostics.terminal_reason == "attachment released" {
                attachment.diagnostics.terminal_reason = "paired connection ended";
            }
        }
        inner.fido = None;
    }
}

fn owned(
    inner: &crate::pairing::state::Inner,
    attachment: &Attachment,
    request_id: &str,
    origin: &str,
    epoch: u64,
) -> bool {
    !inner.stopping
        && inner.connected
        && inner.epoch == epoch
        && inner.connection_owned_by(request_id, epoch)
        && caller_matches(attachment, request_id, origin, epoch)
        && inner.pairing.as_ref().is_some_and(|pairing| {
            pairing.request_id.as_deref() == Some(request_id)
                && pairing.session_id.as_deref() == Some(attachment.session_id.as_str())
                && pairing.origin == origin
                && pairing.token.is_none()
                && pairing.expires > Instant::now()
        })
        && attachment.expires > Instant::now()
        && !attachment.endpoint.is_closed()
}

fn ownership_ended(inner: &crate::pairing::state::Inner, attachment: &Attachment) -> &'static str {
    if attachment.expires <= Instant::now()
        || inner
            .pairing
            .as_ref()
            .is_some_and(|pairing| pairing.expires <= Instant::now())
    {
        "lease expired"
    } else if attachment.endpoint.is_closed() {
        "device endpoint closed"
    } else {
        "pairing changed or stopped"
    }
}

/// Physical worker lifetime follows the actual renewable attachment deadline,
/// independently of the WebSocket polling interval.
pub(crate) async fn device_deadline(
    app: &App,
    request: &str,
    origin: &str,
    epoch: u64,
) -> Option<Instant> {
    let inner = app.inner.lock().await;
    let attachment = inner.fido.as_ref()?;
    owned(&inner, attachment, request, origin, epoch).then_some(attachment.expires)
}

/// Whether the exact live physical attachment has received its one FidoOpen.
/// Deferred native readiness must never initiate HID report I/O.
pub(crate) async fn device_opened(
    app: &App,
    request: &str,
    origin: &str,
    epoch: u64,
) -> Option<bool> {
    let inner = app.inner.lock().await;
    let attachment = inner.fido.as_ref()?;
    owned(&inner, attachment, request, origin, epoch).then_some(attachment.opened)
}

fn wire_value(wire: Wire) -> Value {
    // All members are bounded, serializable primitives, with payload Debug disabled.
    serde_json::to_value(wire).expect("bounded report serialization")
}

fn closed(relay_id: String) -> Value {
    wire_value(Wire::FidoClose {
        version: VERSION,
        relay_id,
    })
}

fn unavailable() -> Value {
    json!({"type":"fido_status", "state":"unavailable", "message":"Experimental FIDO relay is unavailable."})
}

/// Return None for unrelated text so the existing socket policy stays unchanged.
pub(crate) async fn incoming(
    app: &App,
    request_id: &str,
    origin: &str,
    epoch: u64,
    text: &str,
) -> Option<Vec<Value>> {
    let value: Value = serde_json::from_str(text).ok()?;
    if !value["type"]
        .as_str()
        .is_some_and(|tag| tag.starts_with("fido_"))
    {
        return None;
    }
    let wire = (text.len() <= MAX_WIRE_BYTES)
        .then(|| serde_json::from_value::<Wire>(value).ok())
        .flatten()
        .filter(Wire::valid);
    let mut inner = app.inner.lock().await;
    let Some(mut attachment) = inner.fido.take() else {
        return Some(vec![unavailable()]);
    };
    if !caller_matches(&attachment, request_id, origin, epoch) {
        // A late previous connection must never consume the current attachment.
        inner.fido = Some(attachment);
        return Some(vec![unavailable()]);
    }
    if !owned(&inner, &attachment, request_id, origin, epoch) {
        attachment.diagnostics.terminal_reason = ownership_ended(&inner, &attachment);
        return Some(vec![closed(attachment.relay_id.clone())]);
    }
    let Some(wire) = wire else {
        attachment.diagnostics.terminal_reason = "invalid frame";
        return Some(vec![closed(attachment.relay_id.clone())]);
    };
    if wire.relay_id() != attachment.relay_id {
        // Stale frames cannot consume or deliver into a replacement attachment.
        let response = closed(wire.relay_id().into());
        inner.fido = Some(attachment);
        return Some(vec![response]);
    }
    let response = match wire {
        Wire::FidoOpen { remaining_ms, .. } if !attachment.opened && attachment.advertised => {
            attachment.opened = true;
            tracing::info!(stage = "open accepted", "USB relay");
            attachment.expires = attachment
                .expires
                .min(Instant::now() + Duration::from_millis(remaining_ms));
            Some(wire_value(Wire::FidoReady {
                version: VERSION,
                relay_id: attachment.relay_id.clone(),
            }))
        }
        Wire::FidoRenew {
            lease_sequence,
            remaining_ms,
            ..
        } if attachment.advertised => {
            // A waiting offer may renew before native readiness, but cannot carry
            // reports until FidoOpen. Sequence/deadline/binding checks are identical.
            if lease_sequence != attachment.next_lease_sequence || lease_sequence == u64::MAX {
                attachment.diagnostics.terminal_reason = "invalid renewal sequence";
                return Some(vec![closed(attachment.relay_id.clone())]);
            }
            attachment.next_lease_sequence += 1;
            attachment.diagnostics.renewals = attachment.diagnostics.renewals.saturating_add(1);
            if !attachment.opened {
                attachment.diagnostics.waiting_renewals =
                    attachment.diagnostics.waiting_renewals.saturating_add(1);
            }
            attachment.expires = inner
                .pairing
                .as_ref()
                .unwrap()
                .expires
                .min(Instant::now() + Duration::from_millis(remaining_ms));
            let remaining_ms = attachment
                .expires
                .saturating_duration_since(Instant::now())
                .as_millis() as u64;
            if remaining_ms == 0 {
                attachment.diagnostics.terminal_reason = "renewal expired";
                return Some(vec![closed(attachment.relay_id.clone())]);
            }
            Some(wire_value(Wire::FidoRenewed {
                version: VERSION,
                relay_id: attachment.relay_id.clone(),
                lease_sequence,
                remaining_ms,
            }))
        }
        Wire::FidoReport { sequence, data, .. } if attachment.opened => {
            if attachment.incoming.accept(sequence).is_err() {
                attachment.diagnostics.terminal_reason = "invalid report sequence";
                return Some(vec![closed(attachment.relay_id.clone())]);
            }
            if attachment.endpoint.send(data).is_err() {
                attachment.diagnostics.terminal_reason = "device endpoint unavailable";
                return Some(vec![closed(attachment.relay_id.clone())]);
            }
            if attachment.diagnostics.browser_reports == 0 {
                tracing::info!(stage = "first browser report queued", "USB relay");
            }
            attachment.diagnostics.browser_reports =
                attachment.diagnostics.browser_reports.saturating_add(1);
            None
        }
        Wire::FidoClose { .. } => {
            attachment.diagnostics.terminal_reason = "browser closed relay";
            return Some(vec![closed(attachment.relay_id.clone())]);
        }
        // Duplicate open, wrong-direction ready, and pre-open reports cancel.
        _ => {
            attachment.diagnostics.terminal_reason = "unexpected frame for relay state";
            return Some(vec![closed(attachment.relay_id.clone())]);
        }
    };
    inner.fido = Some(attachment);
    Some(response.into_iter().collect())
}

/// Poll only this connection's attachment, emitting at most one bounded batch.
pub(crate) async fn poll(app: &App, request_id: &str, origin: &str, epoch: u64) -> Vec<Value> {
    let mut inner = app.inner.lock().await;
    let Some(mut attachment) = inner.fido.take() else {
        return Vec::new();
    };
    if !caller_matches(&attachment, request_id, origin, epoch) {
        inner.fido = Some(attachment);
        return Vec::new();
    }
    if !owned(&inner, &attachment, request_id, origin, epoch) {
        attachment.diagnostics.terminal_reason = ownership_ended(&inner, &attachment);
        return vec![closed(attachment.relay_id.clone())];
    }
    let mut output = Vec::new();
    if !attachment.advertised {
        attachment.advertised = true;
        tracing::info!(stage = "offer queued", "USB relay");
        output.push(json!({
            "type":"fido_available", "experimental_fido":true, "version":VERSION,
            "relay_id":attachment.relay_id,
            "helper_connection_id":attachment.request_id,
            "remaining_ms":attachment.expires.saturating_duration_since(Instant::now()).as_millis().min(u128::from(MAX_LEASE_MS)) as u64,
        }));
    }
    if attachment.opened {
        for _ in 0..MAX_BATCH {
            let data = match attachment.endpoint.try_receive() {
                Ok(Some(data)) => data,
                Ok(None) => break,
                Err(_) => {
                    attachment.diagnostics.terminal_reason = "device endpoint unavailable";
                    return vec![closed(attachment.relay_id.clone())];
                }
            };
            let Ok(frame) = attachment.outgoing.frame(data) else {
                attachment.diagnostics.terminal_reason = "outgoing report sequence exhausted";
                return vec![closed(attachment.relay_id.clone())];
            };
            if attachment.diagnostics.device_reports_queued == 0 {
                tracing::info!(stage = "first device report queued", "USB relay");
            }
            attachment.diagnostics.device_reports_queued = attachment
                .diagnostics
                .device_reports_queued
                .saturating_add(1);
            output.push(wire_value(Wire::FidoReport {
                version: VERSION,
                relay_id: attachment.relay_id.clone(),
                sequence: frame.sequence,
                data: frame.data,
            }));
        }
    }
    attachment
        .diagnostics
        .periodic(attachment.advertised, attachment.opened, Instant::now());
    inner.fido = Some(attachment);
    output
}

/// Do not publish a buffered capability, ready, or report after replacement or
/// cancellation. Serialize lifecycle changes with each bounded socket write.
pub(crate) async fn send(
    app: &App,
    socket: &mut axum::extract::ws::WebSocket,
    request_id: &str,
    origin: &str,
    epoch: u64,
    frame: Value,
) -> bool {
    use axum::extract::ws::Message;
    if matches!(
        frame["type"].as_str(),
        Some("fido_available" | "fido_ready" | "fido_report" | "fido_renewed")
    ) {
        let mut inner = app.inner.lock().await;
        let Some(attachment) = inner.fido.as_ref().filter(|attachment| {
            owned(&inner, attachment, request_id, origin, epoch)
                && frame["relay_id"].as_str() == Some(attachment.relay_id.as_str())
        }) else {
            return true;
        };
        let timeout = attachment
            .expires
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(2));
        let sent = matches!(
            tokio::time::timeout(timeout, socket.send(Message::Text(frame.to_string()))).await,
            Ok(Ok(()))
        );
        // The existing write guard still owns this exact attachment.
        if let Some(attachment) = inner.fido.as_mut() {
            if !sent {
                attachment.diagnostics.terminal_reason = "WebSocket write failed";
            } else {
                attachment.diagnostics.sent(frame["type"].as_str());
            }
        }
        sent
    } else {
        crate::server::websocket::send_message(socket, Message::Text(frame.to_string())).await
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{launch, Handle};
    use fido_report_relay::{endpoint_pair, RelayError, Report, QUEUE_CAPACITY};
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::{
        tungstenite::{client::IntoClientRequest, Message},
        MaybeTlsStream, WebSocketStream,
    };

    type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
    const ORIGIN: &str = "https://fido-adapter.example";

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
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
        fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
            let writer = self.clone();
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_ansi(false)
                .with_target(false)
                .without_time()
                .with_writer(move || writer.clone())
                .finish()
        }
    }

    const PRIVATE_REQUEST: &str = "NeverLogRequest01234567890123456789";
    const PRIVATE_SESSION: &str = "NeverLogSession01234567890123456789";
    const PRIVATE_RELAY: &str = "NeverLogRelay0123456789012345678901";
    const PRIVATE_ORIGIN: &str = "https://never-log-origin.example";
    const PRIVATE_EPOCH: u64 = 7;

    // In-memory pairing and opaque endpoints only: no listener, OS adapter,
    // physical worker, HID enumeration, Bluetooth or authenticator operation.
    async fn diagnostic_fixture() -> (App, Endpoint) {
        let app = crate::testing::app();
        {
            let mut inner = app.inner.lock().await;
            inner.connected = true;
            inner.epoch = PRIVATE_EPOCH;
            inner.connection_owner = Some((PRIVATE_REQUEST.into(), PRIVATE_EPOCH));
            inner.pairing = Some(crate::pairing::state::Pairing {
                explicit_approval: true,
                request_id: Some(PRIVATE_REQUEST.into()),
                session_id: Some(PRIVATE_SESSION.into()),
                origin: PRIVATE_ORIGIN.into(),
                token: None,
                expires: Instant::now() + Duration::from_secs(60),
            });
        }
        let (endpoint, peer) = endpoint_pair();
        super::attach(&app, PRIVATE_SESSION, endpoint)
            .await
            .unwrap();
        app.inner.lock().await.fido.as_mut().unwrap().relay_id = PRIVATE_RELAY.into();
        (app, peer)
    }
    async fn diagnostic_incoming(app: &App, wire: Wire) -> Vec<Value> {
        super::incoming(
            app,
            PRIVATE_REQUEST,
            PRIVATE_ORIGIN,
            PRIVATE_EPOCH,
            &serde_json::to_string(&wire).unwrap(),
        )
        .await
        .unwrap()
    }
    async fn diagnostic_poll(app: &App) -> Vec<Value> {
        super::poll(app, PRIVATE_REQUEST, PRIVATE_ORIGIN, PRIVATE_EPOCH).await
    }

    #[tokio::test]
    async fn diagnostics_capture_waiting_open_and_reports_without_private_data() {
        use tracing::instrument::WithSubscriber;
        let captured = Capture::default();
        let payload = Report::from_slice(&[0xa7; 64]).unwrap();
        let encoded = serde_json::to_value(&payload)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        async {
            let (app, mut peer) = diagnostic_fixture().await;
            assert_eq!(diagnostic_poll(&app).await[0]["type"], "fido_available");
            assert!(diagnostic_poll(&app).await.is_empty());
            {
                let mut inner = app.inner.lock().await;
                let diagnostics = &mut inner.fido.as_mut().unwrap().diagnostics;
                // Exercise the same recorder used only after successful writes.
                diagnostics.sent(Some("fido_available"));
                diagnostics.sent(Some("fido_available"));
            }
            let renewed = diagnostic_incoming(
                &app,
                Wire::FidoRenew {
                    version: VERSION,
                    relay_id: PRIVATE_RELAY.into(),
                    lease_sequence: 1,
                    remaining_ms: MAX_LEASE_MS,
                },
            )
            .await;
            assert_eq!(renewed[0]["type"], "fido_renewed");
            {
                let mut inner = app.inner.lock().await;
                inner.fido.as_mut().unwrap().diagnostics.last_summary -= DIAGNOSTIC_INTERVAL;
            }
            assert!(diagnostic_poll(&app).await.is_empty());
            assert!(peer.try_receive().unwrap().is_none());
            let ready = diagnostic_incoming(
                &app,
                Wire::FidoOpen {
                    version: VERSION,
                    relay_id: PRIVATE_RELAY.into(),
                    remaining_ms: MAX_LEASE_MS,
                },
            )
            .await;
            assert_eq!(ready[0]["type"], "fido_ready");
            {
                let mut inner = app.inner.lock().await;
                let diagnostics = &mut inner.fido.as_mut().unwrap().diagnostics;
                diagnostics.sent(Some("fido_ready"));
                diagnostics.sent(Some("fido_ready"));
            }
            for sequence in 0..2 {
                assert!(
                    diagnostic_incoming(&app, report(PRIVATE_RELAY, sequence, 0xa7))
                        .await
                        .is_empty()
                );
                assert_eq!(
                    peer.try_receive().unwrap().unwrap().bytes(),
                    payload.bytes()
                );
                peer.send(Report::from_slice(payload.bytes()).unwrap())
                    .unwrap();
                assert_eq!(diagnostic_poll(&app).await[0]["type"], "fido_report");
                app.inner
                    .lock()
                    .await
                    .fido
                    .as_mut()
                    .unwrap()
                    .diagnostics
                    .sent(Some("fido_report"));
            }
            let closed = diagnostic_incoming(
                &app,
                Wire::FidoClose {
                    version: VERSION,
                    relay_id: PRIVATE_RELAY.into(),
                },
            )
            .await;
            assert_eq!(closed[0]["type"], "fido_close");
            assert!(peer.is_closed());
        }
        .with_subscriber(captured.subscriber())
        .await;
        let text = captured.text();
        for transition in [
            "USB relay stage=\"offer queued\"",
            "USB relay stage=\"offer sent\"",
            "USB relay stage=\"open accepted\"",
            "USB relay stage=\"ready sent\"",
            "USB relay stage=\"first browser report queued\"",
            "USB relay stage=\"first device report queued\"",
            "USB relay stage=\"first device report sent\"",
            "USB relay stage=\"relay\" reason=\"browser closed relay\"",
        ] {
            assert_eq!(text.matches(transition).count(), 1, "{text}");
        }
        for expected in [
            "advertised=true offer_sent=true opened=false ready_sent=false",
            "browser_reports=0 device_reports_queued=0 device_reports_sent=0 renewals=1 waiting_renewals=1",
            "browser_reports=2 device_reports_queued=2 device_reports_sent=2",
            "reason=\"browser closed relay\"",
        ] {
            assert!(text.contains(expected), "{text}");
        }
        for private in [
            PRIVATE_REQUEST,
            PRIVATE_SESSION,
            PRIVATE_RELAY,
            PRIVATE_ORIGIN,
            "test-secret",
            "NeverLog",
            encoded.as_str(),
        ] {
            assert!(!text.contains(private), "private value leaked: {text}");
        }
    }

    #[test]
    fn actual_usb_counters_are_debug_while_relay_transitions_remain_info() {
        let captured = Capture::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let mut diagnostics = RelayDiagnostics::default();
            diagnostics.summary(true, true, "periodic");
            diagnostics.sent(Some("fido_ready"));
        });
        let text = captured.text();
        assert!(!text.contains("USB counters"), "{text}");
        assert!(
            text.contains("INFO") && text.contains("ready sent"),
            "{text}"
        );
    }

    #[test]
    fn diagnostics_periodic_summaries_are_rate_limited_and_delivery_counts_saturate() {
        let captured = Capture::default();
        tracing::subscriber::with_default(captured.subscriber(), || {
            let mut diagnostics = RelayDiagnostics::default();
            let started = diagnostics.last_summary;
            diagnostics.periodic(true, false, started + Duration::from_millis(4999));
            assert!(captured.text().is_empty());
            diagnostics.periodic(true, false, started + DIAGNOSTIC_INTERVAL);
            diagnostics.periodic(true, false, started + DIAGNOSTIC_INTERVAL);
            assert_eq!(captured.text().matches("USB counters").count(), 1);
            diagnostics.periodic(true, true, started + DIAGNOSTIC_INTERVAL * 2);
            diagnostics.device_reports_sent = u64::MAX;
            diagnostics.sent(Some("fido_report"));
            diagnostics.sent(Some("NeverLogUntrustedType"));
            assert_eq!(diagnostics.device_reports_sent, u64::MAX);
        });
        let text = captured.text();
        assert_eq!(text.matches("USB counters").count(), 2);
        assert!(!text.contains("NeverLog"));
    }

    #[tokio::test]
    async fn diagnostics_protocol_counters_saturate_without_changing_opaque_delivery() {
        let (app, mut peer) = diagnostic_fixture().await;
        diagnostic_poll(&app).await;
        {
            let mut inner = app.inner.lock().await;
            let diagnostics = &mut inner.fido.as_mut().unwrap().diagnostics;
            diagnostics.browser_reports = u64::MAX;
            diagnostics.device_reports_queued = u64::MAX;
            diagnostics.renewals = u64::MAX;
            diagnostics.waiting_renewals = u64::MAX;
        }
        assert_eq!(
            diagnostic_incoming(
                &app,
                Wire::FidoRenew {
                    version: VERSION,
                    relay_id: PRIVATE_RELAY.into(),
                    lease_sequence: 1,
                    remaining_ms: MAX_LEASE_MS,
                }
            )
            .await[0]["type"],
            "fido_renewed"
        );
        diagnostic_incoming(
            &app,
            Wire::FidoOpen {
                version: VERSION,
                relay_id: PRIVATE_RELAY.into(),
                remaining_ms: MAX_LEASE_MS,
            },
        )
        .await;
        diagnostic_incoming(&app, report(PRIVATE_RELAY, 0, 0x5c)).await;
        assert_eq!(peer.try_receive().unwrap().unwrap().bytes(), &[0x5c; 64]);
        peer.send(Report::from_slice(&[0xa7; 64]).unwrap()).unwrap();
        assert_eq!(diagnostic_poll(&app).await[0]["type"], "fido_report");
        let inner = app.inner.lock().await;
        let diagnostics = &inner.fido.as_ref().unwrap().diagnostics;
        assert_eq!(diagnostics.browser_reports, u64::MAX);
        assert_eq!(diagnostics.device_reports_queued, u64::MAX);
        assert_eq!(diagnostics.renewals, u64::MAX);
        assert_eq!(diagnostics.waiting_renewals, u64::MAX);
    }

    async fn receive(socket: &mut Socket) -> Value {
        let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        serde_json::from_str(&message).unwrap()
    }

    async fn send(socket: &mut Socket, wire: Wire) {
        socket
            .send(Message::Text(serde_json::to_string(&wire).unwrap()))
            .await
            .unwrap();
    }

    async fn pair(handle: &Handle, session: &str) -> Socket {
        let token = random_secret();
        handle.approve(ORIGIN, &token).await.unwrap();
        connect(handle, session, &token).await
    }

    async fn connect(handle: &Handle, session: &str, token: &str) -> Socket {
        let mut request = handle.websocket_url().into_client_request().unwrap();
        request
            .headers_mut()
            .insert("origin", ORIGIN.parse().unwrap());
        let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        socket
            .send(Message::Text(
                json!({"type":"pair","token":token,"session_id":session}).to_string(),
            ))
            .await
            .unwrap();
        let paired = receive(&mut socket).await;
        assert_eq!(paired["state"], "paired");
        assert!(paired.get("experimental_fido").is_none());
        assert!(paired.get("capabilities").is_none());
        socket
    }

    async fn paired() -> (Handle, String, Socket) {
        let handle = launch(None).await.unwrap();
        let session = random_secret();
        let socket = pair(&handle, &session).await;
        (handle, session, socket)
    }

    async fn attach(handle: &Handle, session: &str, socket: &mut Socket) -> (Endpoint, String) {
        let (attached, peer) = endpoint_pair();
        handle
            .attach_experimental_fido(session, attached)
            .await
            .unwrap();
        let available = receive(socket).await;
        assert_eq!(available["type"], "fido_available");
        assert_eq!(available["experimental_fido"], true);
        assert_eq!(available["version"], VERSION);
        assert_eq!(
            available["helper_connection_id"].as_str(),
            handle.snapshot().await.connection_id.as_deref()
        );
        assert!((1..=MAX_LEASE_MS).contains(&available["remaining_ms"].as_u64().unwrap()));
        let id = available["relay_id"].as_str().unwrap().to_owned();
        assert!(fido_report_relay::valid_id(&id));
        (peer, id)
    }

    async fn open(socket: &mut Socket, id: &str) {
        send(
            socket,
            Wire::FidoOpen {
                version: VERSION,
                relay_id: id.into(),
                remaining_ms: MAX_LEASE_MS,
            },
        )
        .await;
        let ready = receive(socket).await;
        assert_eq!(ready["type"], "fido_ready");
        assert_eq!(ready["relay_id"], id);
    }

    fn report(id: &str, sequence: u64, byte: u8) -> Wire {
        Wire::FidoReport {
            version: VERSION,
            relay_id: id.into(),
            sequence,
            data: Report::from_slice(&[byte; 64]).unwrap(),
        }
    }

    async fn ping(handle: &Handle, socket: &mut Socket) {
        socket.send(Message::Ping(vec![1, 2, 3])).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            Message::Pong(vec![1, 2, 3])
        );
        assert!(handle.snapshot().await.connected);
        assert!(!handle.snapshot().await.scanning);
    }

    async fn wait_disconnected(handle: &Handle) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while handle.snapshot().await.connected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn opt_out_rejects_fido_and_never_advertises_capability() {
        let handle = launch(None).await.unwrap();
        let (endpoint, peer) = endpoint_pair();
        assert!(handle
            .attach_experimental_fido(&random_secret(), endpoint)
            .await
            .is_err());
        assert!(peer.is_closed());
        let session = random_secret();
        let mut socket = pair(&handle, &session).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(300), socket.next())
                .await
                .is_err()
        );
        send(
            &mut socket,
            Wire::FidoOpen {
                version: VERSION,
                relay_id: random_secret(),
                remaining_ms: MAX_LEASE_MS,
            },
        )
        .await;
        let rejected = receive(&mut socket).await;
        assert_eq!(rejected["type"], "fido_status");
        assert_eq!(rejected["state"], "unavailable");
        ping(&handle, &mut socket).await;
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn explicit_attachment_binds_session_and_relays_opaque_reports_both_directions() {
        let (handle, session, mut socket) = paired().await;
        let (endpoint, peer) = endpoint_pair();
        assert!(handle
            .attach_experimental_fido(&random_secret(), endpoint)
            .await
            .is_err());
        assert!(peer.is_closed());
        let (mut peer, id) = attach(&handle, &session, &mut socket).await;
        open(&mut socket, &id).await;
        for sequence in 0..2 {
            send(&mut socket, report(&id, sequence, 0xa7)).await;
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), peer.receive())
                    .await
                    .unwrap()
                    .unwrap()
                    .bytes(),
                &[0xa7; 64]
            );
            peer.send(Report::from_slice(&[0x5c; 64]).unwrap()).unwrap();
            let received = receive(&mut socket).await;
            assert_eq!(received["type"], "fido_report");
            assert_eq!(received["relay_id"], id);
            assert_eq!(received["sequence"], sequence);
            let Wire::FidoReport { data, .. } = serde_json::from_value(received).unwrap() else {
                panic!("Expected opaque report");
            };
            assert_eq!(data.bytes(), &[0x5c; 64]);
        }
        {
            // Real loopback writes, but only supplied opaque endpoints: queued
            // and successfully sent counters must agree after both replies.
            let inner = handle.app.inner.lock().await;
            let diagnostics = &inner.fido.as_ref().unwrap().diagnostics;
            assert!(diagnostics.offer_sent);
            assert!(diagnostics.ready_sent);
            assert_eq!(diagnostics.browser_reports, 2);
            assert_eq!(diagnostics.device_reports_queued, 2);
            assert_eq!(diagnostics.device_reports_sent, 2);
        }
        ping(&handle, &mut socket).await;
        handle.shutdown().await.unwrap();
        assert!(peer.is_closed());
    }

    #[tokio::test]
    async fn wrong_sequence_and_duplicate_open_cancel_only_fido() {
        for mode in ["gap", "replay", "duplicate_open"] {
            let (handle, session, mut socket) = paired().await;
            let (mut peer, id) = attach(&handle, &session, &mut socket).await;
            open(&mut socket, &id).await;
            if mode == "duplicate_open" {
                send(
                    &mut socket,
                    Wire::FidoOpen {
                        version: VERSION,
                        relay_id: id.clone(),
                        remaining_ms: MAX_LEASE_MS,
                    },
                )
                .await;
            } else if mode == "gap" {
                send(&mut socket, report(&id, 1, 7)).await;
            } else {
                send(&mut socket, report(&id, 0, 7)).await;
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(2), peer.receive())
                        .await
                        .unwrap()
                        .unwrap()
                        .bytes(),
                    &[7; 64]
                );
                send(&mut socket, report(&id, 0, 8)).await;
            }
            assert_eq!(receive(&mut socket).await["type"], "fido_close");
            assert_eq!(peer.try_receive().err(), Some(RelayError::Closed));
            send(&mut socket, report(&id, 0, 8)).await;
            assert_eq!(receive(&mut socket).await["state"], "unavailable");
            ping(&handle, &mut socket).await;
            handle.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn stale_relay_frames_cannot_consume_or_reach_replacement_attachment() {
        let (handle, session, mut socket) = paired().await;
        let (old_peer, old_id) = attach(&handle, &session, &mut socket).await;
        open(&mut socket, &old_id).await;
        let (mut peer, id) = attach(&handle, &session, &mut socket).await;
        assert!(old_peer.is_closed());
        assert_ne!(old_id, id);
        for stale in [
            Wire::FidoOpen {
                version: VERSION,
                relay_id: old_id.clone(),
                remaining_ms: MAX_LEASE_MS,
            },
            report(&old_id, 0, 11),
            Wire::FidoClose {
                version: VERSION,
                relay_id: old_id.clone(),
            },
        ] {
            send(&mut socket, stale).await;
            let rejected = receive(&mut socket).await;
            assert_eq!(rejected["type"], "fido_close");
            assert_eq!(rejected["relay_id"], old_id);
            assert!(!peer.is_closed());
            assert!(peer.try_receive().unwrap().is_none());
        }
        open(&mut socket, &id).await;
        send(&mut socket, report(&id, 0, 12)).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), peer.receive())
                .await
                .unwrap()
                .unwrap()
                .bytes(),
            &[12; 64]
        );
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn bounded_incoming_and_outgoing_queue_overflow_cancel_without_replay() {
        for incoming in [true, false] {
            let (handle, session, mut socket) = paired().await;
            let (mut peer, id) = attach(&handle, &session, &mut socket).await;
            open(&mut socket, &id).await;
            if incoming {
                for sequence in 0..=QUEUE_CAPACITY {
                    send(&mut socket, report(&id, sequence as u64, 3)).await;
                }
            } else {
                for _ in 0..QUEUE_CAPACITY {
                    peer.send(Report::from_slice(&[4; 64]).unwrap()).unwrap();
                }
                assert_eq!(
                    peer.send(Report::from_slice(&[4; 64]).unwrap()),
                    Err(RelayError::Overflow)
                );
            }
            assert_eq!(receive(&mut socket).await["type"], "fido_close");
            assert_eq!(peer.try_receive().err(), Some(RelayError::Closed));
            ping(&handle, &mut socket).await;
            handle.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn close_peer_cancel_and_finite_expiry_preserve_paired_connection() {
        for mode in ["wire", "peer", "expiry"] {
            let (handle, session, mut socket) = paired().await;
            let (peer, id) = attach(&handle, &session, &mut socket).await;
            open(&mut socket, &id).await;
            match mode {
                "wire" => {
                    send(
                        &mut socket,
                        Wire::FidoClose {
                            version: VERSION,
                            relay_id: id.clone(),
                        },
                    )
                    .await
                }
                "peer" => peer.close(),
                _ => handle.app.inner.lock().await.fido.as_mut().unwrap().expires = Instant::now(),
            }
            assert_eq!(receive(&mut socket).await["type"], "fido_close");
            assert!(peer.is_closed());
            ping(&handle, &mut socket).await;
            send(
                &mut socket,
                Wire::FidoOpen {
                    version: VERSION,
                    relay_id: id,
                    remaining_ms: MAX_LEASE_MS,
                },
            )
            .await;
            assert_eq!(receive(&mut socket).await["state"], "unavailable");
            handle.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn stop_revoke_shutdown_and_disconnect_drop_attached_endpoint() {
        for mode in ["stop", "revoke", "shutdown", "disconnect"] {
            let (handle, session, mut socket) = paired().await;
            let (peer, id) = attach(&handle, &session, &mut socket).await;
            open(&mut socket, &id).await;
            match mode {
                "stop" => handle.stop().await.unwrap(),
                "revoke" => handle.revoke().await.unwrap(),
                "shutdown" => handle.shutdown().await.unwrap(),
                _ => socket.close(None).await.unwrap(),
            }
            if mode == "disconnect" {
                wait_disconnected(&handle).await;
            }
            assert!(peer.is_closed());
            handle.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn disconnected_session_cannot_reuse_attachment_after_new_token_pairing() {
        let (handle, session, mut socket) = paired().await;
        let (peer, id) = attach(&handle, &session, &mut socket).await;
        open(&mut socket, &id).await;
        socket.close(None).await.unwrap();
        wait_disconnected(&handle).await;
        assert!(peer.is_closed());
        let mut replacement = pair(&handle, &session).await;
        send(
            &mut replacement,
            Wire::FidoOpen {
                version: VERSION,
                relay_id: id,
                remaining_ms: MAX_LEASE_MS,
            },
        )
        .await;
        assert_eq!(receive(&mut replacement).await["state"], "unavailable");
        ping(&handle, &mut replacement).await;
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn malformed_oversized_or_wrong_direction_fido_closes_only_endpoint() {
        for mode in ["short_report", "oversized", "ready", "version"] {
            let (handle, session, mut socket) = paired().await;
            let (peer, id) = attach(&handle, &session, &mut socket).await;
            open(&mut socket, &id).await;
            let invalid = match mode {
                "short_report" => {
                    json!({"type":"fido_report","version":VERSION,"relay_id":id,"sequence":0,"data":"AQ=="})
                }
                "oversized" => {
                    json!({"type":"fido_report","version":VERSION,"relay_id":id,"sequence":0,"data":"A".repeat(MAX_WIRE_BYTES)})
                }
                "ready" => json!({"type":"fido_ready","version":VERSION,"relay_id":id}),
                _ => json!({"type":"fido_close","version":2,"relay_id":id}),
            };
            socket
                .send(Message::Text(invalid.to_string()))
                .await
                .unwrap();
            assert_eq!(receive(&mut socket).await["type"], "fido_close");
            assert!(peer.is_closed());
            ping(&handle, &mut socket).await;
            handle.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn attachment_lease_never_exceeds_pairing_or_thirty_seconds() {
        let (handle, session, mut socket) = paired().await;
        let (peer, _) = attach(&handle, &session, &mut socket).await;
        {
            let mut inner = handle.app.inner.lock().await;
            let expires = inner.fido.as_ref().unwrap().expires;
            assert!(expires <= Instant::now() + Duration::from_millis(MAX_LEASE_MS));
            assert!(expires <= inner.pairing.as_ref().unwrap().expires);
            inner.pairing.as_mut().unwrap().expires = Instant::now() + Duration::from_secs(5);
        }
        let (_peer, _) = attach(&handle, &session, &mut socket).await;
        assert!(peer.is_closed());
        {
            let inner = handle.app.inner.lock().await;
            assert_eq!(
                inner.fido.as_ref().unwrap().expires,
                inner.pairing.as_ref().unwrap().expires
            );
        }
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn remembered_ble_approval_never_attaches_or_advertises_fido() {
        let handle = crate::launch_incoming(None).await.unwrap();
        // This is the same process-only BLE grant used by a remembered reconnect.
        handle
            .app
            .session
            .memory()
            .approved_origins
            .insert(ORIGIN.into());
        let session = random_secret();
        let mut socket = connect(&handle, &session, &random_secret()).await;
        assert!(
            !handle
                .app
                .inner
                .lock()
                .await
                .pairing
                .as_ref()
                .unwrap()
                .explicit_approval
        );
        assert!(handle.snapshot().await.pending_approval.is_none());
        assert!(
            tokio::time::timeout(Duration::from_millis(300), socket.next())
                .await
                .is_err()
        );
        send(
            &mut socket,
            Wire::FidoOpen {
                version: VERSION,
                relay_id: random_secret(),
                remaining_ms: MAX_LEASE_MS,
            },
        )
        .await;
        assert_eq!(receive(&mut socket).await["state"], "unavailable");
        let (peer, id) = attach(&handle, &session, &mut socket).await;
        open(&mut socket, &id).await;
        assert!(!peer.is_closed());
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn changed_request_session_or_origin_never_delivers_into_old_attachment() {
        for mode in ["request", "session", "origin"] {
            let (handle, session, mut socket) = paired().await;
            let (mut peer, id) = attach(&handle, &session, &mut socket).await;
            open(&mut socket, &id).await;
            {
                let mut inner = handle.app.inner.lock().await;
                let pairing = inner.pairing.as_mut().unwrap();
                match mode {
                    "request" => pairing.request_id = Some(random_secret()),
                    "session" => pairing.session_id = Some(random_secret()),
                    _ => pairing.origin = "https://changed.example".into(),
                }
            }
            send(&mut socket, report(&id, 0, 19)).await;
            assert_eq!(receive(&mut socket).await["type"], "fido_close");
            assert_eq!(peer.try_receive().err(), Some(RelayError::Closed));
            ping(&handle, &mut socket).await;
            handle.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn stale_connection_incoming_poll_and_cleanup_preserve_replacement_endpoint() {
        let (handle, session, mut old_socket) = paired().await;
        let (old_peer, old_id) = attach(&handle, &session, &mut old_socket).await;
        open(&mut old_socket, &old_id).await;
        let (old_request, old_epoch) = handle
            .app
            .inner
            .lock()
            .await
            .connection_owner
            .clone()
            .unwrap();
        old_socket.close(None).await.unwrap();
        wait_disconnected(&handle).await;
        assert!(old_peer.is_closed());

        let mut socket = pair(&handle, &session).await;
        let (mut peer, id) = attach(&handle, &session, &mut socket).await;
        open(&mut socket, &id).await;
        let (request, epoch) = handle
            .app
            .inner
            .lock()
            .await
            .connection_owner
            .clone()
            .unwrap();
        assert_ne!(old_request, request);
        assert_ne!(old_epoch, epoch);
        let before_stale_cleanup = handle.snapshot().await;
        {
            let mut inner = handle.app.inner.lock().await;
            crate::pairing::connection::begin_cleanup(&mut inner, &old_request, ORIGIN, old_epoch);
            crate::pairing::connection::finish_cleanup(&mut inner, &old_request, old_epoch);
            assert!(inner.fido.is_some());
            assert!(inner.scan.is_some());
            assert!(inner.connection_owned_by(&request, epoch));
        }
        assert_eq!(handle.snapshot().await, before_stale_cleanup);
        for (stale_request, stale_origin, stale_epoch) in [
            (old_request.as_str(), ORIGIN, old_epoch),
            (old_request.as_str(), ORIGIN, epoch),
            (request.as_str(), ORIGIN, old_epoch),
            (request.as_str(), "https://old-origin.example", epoch),
        ] {
            // Even naming the new relay cannot grant an old socket ownership.
            let text = serde_json::to_string(&report(&id, 0, 20)).unwrap();
            assert_eq!(
                super::incoming(&handle.app, stale_request, stale_origin, stale_epoch, &text)
                    .await
                    .unwrap()[0]["state"],
                "unavailable"
            );
            assert!(
                super::poll(&handle.app, stale_request, stale_origin, stale_epoch)
                    .await
                    .is_empty()
            );
            {
                let mut inner = handle.app.inner.lock().await;
                super::cancel_owned(&mut inner, stale_request, stale_origin, stale_epoch);
                assert!(inner.fido.is_some());
                assert!(inner.connection_owned_by(&request, epoch));
            }
            assert!(!peer.is_closed());
            assert!(peer.try_receive().unwrap().is_none());
        }
        send(&mut socket, report(&id, 0, 21)).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), peer.receive())
                .await
                .unwrap()
                .unwrap()
                .bytes(),
            &[21; 64]
        );
        peer.send(Report::from_slice(&[22; 64]).unwrap()).unwrap();
        assert!(super::poll(&handle.app, &old_request, ORIGIN, old_epoch)
            .await
            .is_empty());
        let response = receive(&mut socket).await;
        assert_eq!(response["type"], "fido_report");
        assert_eq!(response["sequence"], 0);
        assert_eq!(response["relay_id"], id);
        let Wire::FidoReport { data, .. } = serde_json::from_value(response).unwrap() else {
            panic!("Expected opaque report");
        };
        assert_eq!(data.bytes(), &[22; 64]);
        ping(&handle, &mut socket).await;
        handle.shutdown().await.unwrap();
        assert!(peer.is_closed());
    }

    #[tokio::test]
    async fn renewable_live_lease_keeps_identity_and_sequence_but_replay_revokes() {
        let (handle, session, mut socket) = paired().await;
        let (mut peer, id) = attach(&handle, &session, &mut socket).await;
        open(&mut socket, &id).await;
        let old_expiry = handle.app.inner.lock().await.fido.as_ref().unwrap().expires;
        tokio::time::sleep(Duration::from_millis(10)).await;
        send(
            &mut socket,
            Wire::FidoRenew {
                version: VERSION,
                relay_id: id.clone(),
                lease_sequence: 1,
                remaining_ms: MAX_LEASE_MS,
            },
        )
        .await;
        let renewed = receive(&mut socket).await;
        assert_eq!(renewed["type"], "fido_renewed");
        assert_eq!(renewed["relay_id"], id);
        assert_eq!(renewed["lease_sequence"], 1);
        assert!(handle.app.inner.lock().await.fido.as_ref().unwrap().expires > old_expiry);
        send(&mut socket, report(&id, 0, 7)).await;
        assert_eq!(peer.receive().await.unwrap().bytes(), &[7; 64]);
        send(
            &mut socket,
            Wire::FidoRenew {
                version: VERSION,
                relay_id: id.clone(),
                lease_sequence: 1,
                remaining_ms: MAX_LEASE_MS,
            },
        )
        .await;
        assert_eq!(receive(&mut socket).await["type"], "fido_close");
        assert!(peer.is_closed());
        ping(&handle, &mut socket).await;
        handle.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn renewable_lease_cannot_exceed_pairing_or_resurrect_expiry() {
        let (handle, session, mut socket) = paired().await;
        let (peer, id) = attach(&handle, &session, &mut socket).await;
        open(&mut socket, &id).await;
        let limit = Instant::now() + Duration::from_secs(2);
        handle
            .app
            .inner
            .lock()
            .await
            .pairing
            .as_mut()
            .unwrap()
            .expires = limit;
        send(
            &mut socket,
            Wire::FidoRenew {
                version: VERSION,
                relay_id: id.clone(),
                lease_sequence: 1,
                remaining_ms: MAX_LEASE_MS,
            },
        )
        .await;
        assert_eq!(receive(&mut socket).await["type"], "fido_renewed");
        assert!(handle.app.inner.lock().await.fido.as_ref().unwrap().expires <= limit);
        handle.app.inner.lock().await.fido.as_mut().unwrap().expires = Instant::now();
        send(
            &mut socket,
            Wire::FidoRenew {
                version: VERSION,
                relay_id: id.clone(),
                lease_sequence: 2,
                remaining_ms: MAX_LEASE_MS,
            },
        )
        .await;
        assert_eq!(receive(&mut socket).await["type"], "fido_close");
        assert!(peer.is_closed());
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn waiting_offer_renews_without_opening_and_sequence_continues_after_open() {
        let (handle, session, mut socket) = paired().await;
        let (mut peer, id) = attach(&handle, &session, &mut socket).await;
        let original_expiry = handle.app.inner.lock().await.fido.as_ref().unwrap().expires;
        tokio::time::sleep(Duration::from_millis(10)).await;
        for lease_sequence in 1..=2 {
            send(
                &mut socket,
                Wire::FidoRenew {
                    version: VERSION,
                    relay_id: id.clone(),
                    lease_sequence,
                    remaining_ms: MAX_LEASE_MS,
                },
            )
            .await;
            let renewed = receive(&mut socket).await;
            assert_eq!(renewed["type"], "fido_renewed");
            assert_eq!(renewed["relay_id"], id);
            assert_eq!(renewed["lease_sequence"], lease_sequence);
            let inner = handle.app.inner.lock().await;
            let attachment = inner.fido.as_ref().unwrap();
            assert!(!attachment.opened);
            assert!(attachment.expires > original_expiry);
            assert_eq!(attachment.next_lease_sequence, lease_sequence + 1);
            assert!(peer.try_receive().unwrap().is_none());
        }
        open(&mut socket, &id).await;
        send(
            &mut socket,
            Wire::FidoRenew {
                version: VERSION,
                relay_id: id.clone(),
                lease_sequence: 3,
                remaining_ms: MAX_LEASE_MS,
            },
        )
        .await;
        assert_eq!(receive(&mut socket).await["lease_sequence"], 3);
        send(&mut socket, report(&id, 0, 7)).await;
        assert_eq!(peer.receive().await.unwrap().bytes(), &[7; 64]);
        // Replaying a pre-open sequence after open must revoke, never restart.
        send(
            &mut socket,
            Wire::FidoRenew {
                version: VERSION,
                relay_id: id.clone(),
                lease_sequence: 1,
                remaining_ms: MAX_LEASE_MS,
            },
        )
        .await;
        assert_eq!(receive(&mut socket).await["type"], "fido_close");
        assert!(peer.is_closed());
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn waiting_offer_renewal_still_caps_pairing_and_preopen_report_cancels() {
        let (handle, session, mut socket) = paired().await;
        let (peer, id) = attach(&handle, &session, &mut socket).await;
        let limit = Instant::now() + Duration::from_secs(2);
        handle
            .app
            .inner
            .lock()
            .await
            .pairing
            .as_mut()
            .unwrap()
            .expires = limit;
        send(
            &mut socket,
            Wire::FidoRenew {
                version: VERSION,
                relay_id: id.clone(),
                lease_sequence: 1,
                remaining_ms: MAX_LEASE_MS,
            },
        )
        .await;
        assert_eq!(receive(&mut socket).await["type"], "fido_renewed");
        assert!(handle.app.inner.lock().await.fido.as_ref().unwrap().expires <= limit);
        send(&mut socket, report(&id, 0, 8)).await;
        assert_eq!(receive(&mut socket).await["type"], "fido_close");
        assert!(peer.is_closed());
        send(
            &mut socket,
            Wire::FidoRenew {
                version: VERSION,
                relay_id: id,
                lease_sequence: 2,
                remaining_ms: MAX_LEASE_MS,
            },
        )
        .await;
        assert_eq!(receive(&mut socket).await["state"], "unavailable");
        handle.shutdown().await.unwrap();
    }
}
