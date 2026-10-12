//! Request-bound authorization for the native browser WebAuthn proxy.
//! Nothing here accesses secret key material or performs user verification.
use super::local_navigation::{LocalNavigation, Notification};
use super::window_control::{Failure, WindowAction, WindowReply, WindowRpc};
use crate::authenticator::cdp::KeyConfig;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, mpsc::UnboundedSender, watch};
use uuid::Uuid;

const EXTENSION_VERSION: &str = "1.0.29";
// Compiled with the image: a stale worker cannot obtain a new build stamp by
// reading files from disk. This is a freshness check, not a hostile-code attestation.
const EXTENSION_BUILD: &str = include_str!("../../extension/build.sha256");
const PROTOCOL_VERSION: u64 = 1;
const REQUIRED_CAPABILITIES: [&str; 4] = [
    "heartbeat",
    "mode_ack_generation",
    "mode_progress",
    "mode_lease",
];
const UPGRADE_REQUIRED: &str =
    "Browser extension upgrade required. Restart the managed browser with extension 1.0.29.";

const MAX_PENDING: usize = 32;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_LIFETIME: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    #[serde(skip)]
    pub key_revision: Value,
    #[serde(skip)]
    pub deadline: Instant,
    pub key_id: String,
    pub key_name: String,
    pub attachment: String,
    pub credential_id: Option<String>,
    pub user_name: Option<String>,
    pub display_name: Option<String>,
    pub user_handle: Option<String>,
}
/// A request-local authorization record, never a browser-session UV grant.
#[derive(Clone, Debug)]
pub struct Selection {
    pub key_id: String,
    pub credential_id: Option<String>,
    pub key_revision: Value,
    pub verified: bool,
    pub presence: bool,
}
pub fn key_revision(key: &KeyConfig) -> Value {
    let mut value = serde_json::to_value(key).expect("key configuration serializes");
    // Credential counters may advance independently; configuration and password
    // changes invalidate authorization. Never expose this secret-bearing value.
    value.as_object_mut().unwrap().remove("credentials");
    value
}
#[derive(Clone, Debug)]
pub struct Request {
    pub native_attempt: Option<crate::browser::native_client::Attempt>,
    pub stage: String,
    pub selection: Option<Selection>,
    pub id: String,
    pub request_id: i64,
    pub generation: u64,
    pub kind: String,
    pub options: Value,
    pub origin: String,
    pub rp_id: String,
    pub uv: String,
    pub candidates: Vec<Candidate>,
    pub deadline: Instant,
}
impl Request {
    pub fn selected_match(&self, key_id: &str, credential_id: Option<&str>) -> bool {
        self.candidates.iter().any(|c| {
            c.key_id == key_id
                && c.credential_id.as_deref() == credential_id
                && Instant::now() < c.deadline
        })
    }
}
pub struct Broker {
    pub helper: Option<crate::relay::helper::Session>,
    pub native_qr_mode: bool,
    pub mode_generation: u64,
    pub mode_pending: Option<Instant>,
    pub mode_error: Option<String>,
    pub lease_generation: u64,
    lease_pending: Option<(u64, Instant, Instant)>,
    // A late rollback acknowledgement may recover this exact failed transition.
    timed_out_proxy_generation: Option<u64>,
    // Selected mode is runtime-only. Loss of the owner/control connection
    // revokes the lease; a detached reconnect must first restore interception.
    native_mode_requested: bool,
    native_mode_deadline: Option<Instant>,
    proxy_mode_required: bool,
    stream_id: String,
    sequence: u64,
    events: VecDeque<Value>,
    changed: watch::Sender<u64>,
    extension_compatible: bool,
    navigation_supported: bool,
    window_supported: bool,
    window_rpc: WindowRpc,
    local_navigation: LocalNavigation,
    extension_rejected: bool,
    pub ready: bool,
    pub outbound: Option<UnboundedSender<Value>>,
    generation: u64,
    pending: HashMap<String, Request>,
    // Claimed requests cannot be approved again, but are still cancellable while
    // an asynchronous PIN verification or durable credential write runs.
    claimed: HashMap<String, Request>,
}
impl Default for Broker {
    fn default() -> Self {
        let (changed, _) = watch::channel(0);
        let stream_id = Uuid::new_v4().to_string();
        Self {
            helper: None,
            native_qr_mode: false,
            mode_generation: 0,
            mode_pending: None,
            mode_error: None,
            lease_generation: 0,
            lease_pending: None,
            timed_out_proxy_generation: None,
            native_mode_requested: false,
            native_mode_deadline: None,
            proxy_mode_required: false,
            stream_id: stream_id.clone(),
            sequence: 0,
            events: VecDeque::new(),
            changed,
            extension_compatible: false,
            navigation_supported: false,
            window_supported: false,
            window_rpc: WindowRpc::default(),
            local_navigation: LocalNavigation::new(stream_id),
            extension_rejected: false,
            ready: false,
            outbound: None,
            generation: 0,
            pending: HashMap::new(),
            claimed: HashMap::new(),
        }
    }
}
impl Broker {
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }
    pub(super) fn window_connection(&self) -> Option<&str> {
        (self.extension_compatible
            && self.window_supported
            && self.outbound.as_ref().is_some_and(|tx| !tx.is_closed()))
        .then(|| self.window_rpc.connection())
        .flatten()
    }
    pub(super) fn cancel_window_control(&mut self) {
        if let Some(cancel) = self.window_rpc.cancel() {
            self.send(cancel);
        }
    }
    fn expire_window_control(&mut self) {
        if let Some(cancel) = self.window_rpc.expire() {
            self.send(cancel);
        }
    }
    pub(super) fn begin_window_control(
        &mut self,
        action: WindowAction,
        expected_count: u32,
        fingerprint: Option<String>,
        remaining_ms: u64,
    ) -> Result<tokio::sync::oneshot::Receiver<Result<WindowReply, Failure>>, Failure> {
        self.expire_window_control();
        if self.window_connection().is_none() {
            return Err(super::window_control::UNAVAILABLE);
        }
        let (request, receiver) =
            self.window_rpc
                .begin(action, expected_count, fingerprint, remaining_ms)?;
        if !self.send(request) {
            self.disconnected();
            return Err(super::window_control::UNAVAILABLE);
        }
        Ok(receiver)
    }
    pub(super) fn subscribe_navigation(&self) -> broadcast::Receiver<Notification> {
        self.local_navigation.subscribe()
    }
    fn sync_navigation_scope(&mut self) {
        let available = self.extension_compatible
            && self.navigation_supported
            && self.outbound.as_ref().is_some_and(|tx| !tx.is_closed());
        if let Some(scope) = self
            .local_navigation
            .sync_scope(available, self.mode_generation)
        {
            if !self.send(scope) {
                self.local_navigation.revoke();
            }
        }
    }
    pub(super) fn navigation_frame(
        &mut self,
        notice: &Notification,
        subscribed_at_ms: u64,
    ) -> Option<String> {
        self.expire();
        self.sync_navigation_scope();
        self.local_navigation.frame(notice, subscribed_at_ms)
    }
    fn event(&mut self, kind: &str, request_id: Option<&str>) {
        self.sync_navigation_scope();
        self.sequence += 1;
        // Deliberate allowlist: no options, challenges, passwords, hashes or keys.
        self.events
            .push_back(json!({"sequence":self.sequence,"kind":kind,"request_id":request_id}));
        while self.events.len() > 128 {
            self.events.pop_front();
        }
        self.changed.send_replace(self.sequence);
    }
    #[cfg(test)]
    pub fn lifecycle(&mut self, request: &Request, kind: &str) {
        if self.is_current(request) {
            self.event(kind, Some(&request.id));
        }
    }
    pub fn stream_snapshot(&mut self, cursor: Option<&str>) -> Value {
        let requests = self.public_requests();
        let since = cursor
            .and_then(|c| c.rsplit_once(':'))
            .filter(|(instance, _)| *instance == self.stream_id)
            .and_then(|(_, seq)| seq.parse::<u64>().ok())
            .filter(|seq| *seq <= self.sequence);
        let oldest = self
            .events
            .front()
            .and_then(|e| e["sequence"].as_u64())
            .unwrap_or(self.sequence + 1);
        let resync = since.is_none_or(|seq| seq.saturating_add(1) < oldest);
        let events: Vec<_> = if resync {
            vec![]
        } else {
            self.events
                .iter()
                .filter(|e| e["sequence"].as_u64().unwrap() > since.unwrap())
                .cloned()
                .collect()
        };
        json!({"requests":requests,"connected":self.ready,"control_connected":self.outbound.is_some(),"native_qr_mode":self.native_qr_mode,"mode_switching":self.mode_pending.is_some(),"mode_error":self.mode_error,"browser_mode":self.browser_mode(),"mode_generation":self.mode_generation,"cursor":format!("{}:{}",self.stream_id,self.sequence),"events":events,"resync":resync})
    }

    pub fn connected(&mut self, outbound: UnboundedSender<Value>) {
        self.disconnected();
        self.extension_rejected = false;
        self.outbound = Some(outbound);
        self.window_rpc.connected();
        eprintln!("[native-proxy] control connected; awaiting browser readiness");
        self.event("control_connected", None);
    }
    pub fn disconnected(&mut self) {
        let changed = self.ready
            || self.outbound.is_some()
            || self.native_qr_mode
            || self.helper.is_some()
            || self.mode_pending.is_some()
            || !self.pending.is_empty()
            || !self.claimed.is_empty();
        if changed {
            eprintln!(
                "[native-proxy] control disconnected; native_mode={} phone_session={}",
                self.native_qr_mode,
                self.helper.is_some()
            );
        }
        self.helper = None;
        self.lease_pending = None;
        self.native_mode_requested = false;
        self.native_mode_deadline = None;
        self.proxy_mode_required |= changed;
        self.native_qr_mode = false;
        self.mode_pending = None;
        self.timed_out_proxy_generation = None;
        self.mode_generation = self.mode_generation.wrapping_add(1);
        self.ready = false;
        self.extension_compatible = false;
        self.navigation_supported = false;
        self.window_supported = false;
        self.window_rpc.revoke();
        self.local_navigation.revoke();
        self.outbound = None;
        self.pending.clear();
        self.claimed.clear();
        self.generation = self.generation.wrapping_add(1);
        // Retrying an already-offline listener must not manufacture lifecycle
        // changes or flood approval streams with identical empty snapshots.
        if changed {
            self.event("disconnected", None);
        }
    }
    pub fn cancel_all(&mut self, message: &str) {
        self.stop_helper();
        self.cancel_requests(message);
    }
    fn cancel_requests(&mut self, message: &str) {
        let all: Vec<_> = self
            .pending
            .values()
            .chain(self.claimed.values())
            .cloned()
            .collect();
        self.pending.clear();
        self.claimed.clear();
        for request in all {
            self.event("canceled", Some(&request.id));
            self.error(
                &request.kind,
                request.request_id,
                "NotAllowedError",
                message,
            );
        }
    }
    pub fn start_helper(&mut self, session: crate::relay::helper::Session) -> bool {
        self.expire();
        if !self.ready || self.helper.is_some() || self.mode_pending.is_some() {
            return false;
        }
        self.cancel_requests(
            "Authentication mode changed. Retry the website request after native mode is ready.",
        );
        self.native_mode_deadline = Some(session.deadline);
        self.helper = Some(session);
        self.set_mode(true)
    }
    pub fn browser_mode(&self) -> &'static str {
        if self.native_mode_requested {
            "native"
        } else {
            "software"
        }
    }
    pub fn browser_mode_state(&self) -> &'static str {
        if self.mode_pending.is_some() {
            "switching"
        } else if self.mode_error.is_some() {
            "error"
        } else if self.native_qr_mode {
            "native"
        } else if self.ready {
            "software"
        } else {
            "unavailable"
        }
    }
    pub fn renew_native_lease(&mut self, deadline: Instant) -> Option<u64> {
        self.expire();
        if !self.native_qr_mode
            || !self.extension_compatible
            || self.mode_pending.is_some()
            || self.lease_pending.is_some()
            || self.helper.is_none()
        {
            return None;
        }
        let lease = self.lease_generation.checked_add(1)?;
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as u64;
        if !(1..=120_000).contains(&remaining) {
            return None;
        }
        self.lease_pending = Some((lease, deadline, Instant::now() + Duration::from_secs(5)));
        if !self.send(
            json!({"type":"mode_lease","generation":self.mode_generation,
            "leaseGeneration":lease,"leaseRemainingMs":remaining}),
        ) {
            self.disconnected();
            return None;
        }
        Some(lease)
    }
    pub fn restore_software_mode(&mut self) -> bool {
        self.set_mode(false)
    }
    fn set_mode(&mut self, native: bool) -> bool {
        if self.extension_rejected || (native && !self.extension_compatible) {
            return false;
        }
        eprintln!(
            "[native-proxy] mode requested: {}",
            if native { "native" } else { "proxy" }
        );
        // A mode transition cannot leave a claimed approval dormant and revive
        // it when the proxy later becomes ready again.
        self.cancel_requests(
            "Authentication mode changed. Retry the website request after the new mode is ready.",
        );
        self.generation = self.generation.wrapping_add(1);
        self.lease_pending = None;
        self.lease_generation = 0;
        self.mode_error = None;
        self.timed_out_proxy_generation = None;
        self.native_mode_requested = native;
        self.proxy_mode_required = !native;
        if !native {
            self.native_mode_deadline = None;
        }
        self.ready = false;
        self.mode_generation = self.mode_generation.wrapping_add(1);
        self.mode_pending = Some(Instant::now() + Duration::from_secs(5));
        self.native_qr_mode = false;
        if !self.extension_compatible {
            self.mode_pending = None;
            return false;
        }
        let remaining = self.native_mode_deadline.map_or(120_000, |deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as u64
        });
        let delivered = self.send(json!({"type":"mode","mode":if native {"native"} else {"proxy"},"generation":self.mode_generation,"leaseRemainingMs":if native { remaining } else { 0 }}));
        if delivered {
            self.event("mode_switching", None);
        } else {
            self.disconnected();
        }
        delivered
    }
    pub fn validate_helper_owner(&mut self, inner: &crate::app::Inner) {
        if self.helper.as_ref().is_some_and(|s| !s.valid_owner(inner)) {
            self.stop_helper();
        }
    }
    pub fn stop_helper(&mut self) {
        self.lease_pending = None;
        if self.helper.take().is_some() || self.native_mode_requested {
            self.set_mode(false);
        }
    }
    fn send(&self, value: Value) -> bool {
        self.outbound
            .as_ref()
            .is_some_and(|tx| tx.send(value).is_ok())
    }
    fn error(&self, kind: &str, request_id: i64, name: &str, message: &str) -> bool {
        self.send(
            json!({"type":kind,"requestId":request_id,"error":{"name":name,"message":message}}),
        )
    }
    fn reject_extension(&mut self) -> Result<(), String> {
        // Rejection is terminal for this port. Never let later partial records
        // recover old requests, native authorization, or a pending transition.
        self.extension_compatible = false;
        self.extension_rejected = true;
        self.window_supported = false;
        self.window_rpc.revoke();
        self.lease_pending = None;
        self.helper = None;
        self.native_mode_requested = false;
        self.native_mode_deadline = None;
        self.proxy_mode_required = true;
        self.native_qr_mode = false;
        self.mode_pending = None;
        self.timed_out_proxy_generation = None;
        self.mode_generation = self.mode_generation.wrapping_add(1);
        self.ready = false;
        self.cancel_all(UPGRADE_REQUIRED);
        self.generation = self.generation.wrapping_add(1);
        self.mode_error = Some("extension_upgrade_required".into());
        eprintln!("[native-proxy] extension upgrade required; expected=1.0.29 protocol=1");
        self.event("mode_error", None);
        Err(UPGRADE_REQUIRED.into())
    }
    pub fn on_message(&mut self, value: Value, keys: &[KeyConfig]) -> Result<(), String> {
        let kind = value["type"]
            .as_str()
            .ok_or("Missing native message type")?;
        if kind == "ping" {
            let nonce = value["nonce"]
                .as_u64()
                .filter(|nonce| *nonce <= 9_007_199_254_740_991)
                .ok_or("Invalid heartbeat nonce")?;
            return self
                .send(json!({"type":"pong","nonce":nonce}))
                .then_some(())
                .ok_or_else(|| "Native transport is unavailable".into());
        }
        if (self.extension_rejected
            || (!self.extension_compatible
                && self.mode_error.as_deref() == Some("extension_upgrade_required")
                && kind != "ready"))
            && kind != "disconnected"
        {
            return Err(UPGRADE_REQUIRED.into());
        }
        if kind == "ready" {
            let capabilities = value["capabilities"].as_array();
            let coherent_mode = (value["mode"] == "proxy" && value["attached"] == true)
                || (value["mode"] == "native" && value["attached"] == false);
            if value["extensionVersion"] != EXTENSION_VERSION
                || value["extensionBuild"].as_str() != Some(EXTENSION_BUILD)
                || value["protocolVersion"].as_u64() != Some(PROTOCOL_VERSION)
                || !REQUIRED_CAPABILITIES.iter().all(|required| {
                    capabilities.is_some_and(|caps| caps.iter().any(|cap| cap == required))
                })
                || !coherent_mode
            {
                return self.reject_extension();
            }
            self.extension_compatible = true;
            self.navigation_supported =
                capabilities.is_some_and(|caps| caps.iter().any(|cap| cap == "local_navigation"));
            self.window_supported =
                capabilities.is_some_and(|caps| caps.iter().any(|cap| cap == "window_control"));
            if !self.window_supported {
                self.cancel_window_control();
            }
        }
        if kind == "mode_progress" {
            let stage = match value["stage"].as_str() {
                Some("received") => "received",
                Some("attach_started") => "attach_started",
                Some("attach_completed") => "attach_completed",
                Some("detach_started") => "detach_started",
                Some("detach_completed") => "detach_completed",
                _ => return Err("Invalid mode progress stage".into()),
            };
            let initializing = value["generation"].as_i64() == Some(-1)
                && self.mode_pending.is_none()
                && !self.ready
                && !self.native_mode_requested
                && !self.proxy_mode_required;
            if value["generation"].as_u64() != Some(self.mode_generation) && !initializing {
                return Err("Stale mode progress".into());
            }
            let version = if value["extensionVersion"] == EXTENSION_VERSION {
                EXTENSION_VERSION
            } else {
                "legacy/unknown"
            };
            eprintln!("[native-proxy] mode progress: {stage}; extension={version}");
            return Ok(());
        }
        self.expire();
        if kind == "window_control_result" {
            return self.window_rpc.reply(value);
        }
        if matches!(kind, "local_navigation" | "local_navigation_clear") {
            self.sync_navigation_scope();
            return self.local_navigation.accept(&value);
        }
        if kind == "mode_lease_ready" {
            let Some((lease, deadline, _)) = self.lease_pending else {
                return Err("No native lease renewal pending".into());
            };
            if !self.extension_compatible
                || !self.native_qr_mode
                || !self.native_mode_requested
                || value["generation"].as_u64() != Some(self.mode_generation)
                || value["leaseGeneration"].as_u64() != Some(lease)
                || value["mode"] != "native"
                || value["attached"] != false
                || value["extensionVersion"] != EXTENSION_VERSION
                || value["protocolVersion"].as_u64() != Some(PROTOCOL_VERSION)
            {
                return Err("Invalid native lease acknowledgement".into());
            }
            let session = self.helper.as_mut().ok_or("Native session revoked")?;
            session.deadline = deadline;
            self.native_mode_deadline = Some(deadline);
            self.lease_generation = lease;
            self.lease_pending = None;
            self.event("mode_lease_renewed", None);
            return Ok(());
        }
        if kind == "mode_ready" {
            if !self.extension_compatible {
                return Err("Browser capability handshake required".into());
            }
            if value["generation"].as_u64() != Some(self.mode_generation)
                || (self.mode_pending.is_none()
                    && self.timed_out_proxy_generation != Some(self.mode_generation))
            {
                return Err("Stale mode acknowledgement".into());
            }
            let native = self.native_mode_requested;
            if value["mode"] != if native { "native" } else { "proxy" }
                || value["attached"].as_bool() != Some(!native)
                || value["extensionVersion"] != EXTENSION_VERSION
                || value["protocolVersion"].as_u64() != Some(PROTOCOL_VERSION)
            {
                return Err("Unexpected mode acknowledgement".into());
            }
            self.mode_pending = None;
            self.mode_error = None;
            self.timed_out_proxy_generation = None;
            self.proxy_mode_required = false;
            self.native_qr_mode = native;
            self.ready = !native && self.outbound.is_some();
            eprintln!(
                "[native-proxy] mode ready: {}",
                if native { "native" } else { "proxy" }
            );
            self.event("mode_ready", None);
            return Ok(());
        }
        if kind == "ready" {
            if self.mode_pending.is_some() {
                return Err("Mode acknowledgement required".into());
            }
            match (value.get("mode"), value.get("attached")) {
                (Some(mode), Some(attached)) if mode == "native" && attached == false => {
                    // An explicit stop or shorter owner/session expiry may
                    // have happened while the transport was unavailable.
                    if self.proxy_mode_required
                        || !self.native_mode_requested
                        || self.helper.is_none()
                    {
                        self.set_mode(false);
                        return Err("Native mode was revoked during disconnection".into());
                    }
                    let Some(remaining) = value["leaseRemainingMs"]
                        .as_u64()
                        .filter(|millis| (1..=120_000).contains(millis))
                    else {
                        self.helper = None;
                        self.set_mode(false);
                        return Err("Invalid native mode lease".into());
                    };
                    let deadline = Instant::now() + Duration::from_millis(remaining);
                    self.native_mode_deadline = Some(
                        self.native_mode_deadline
                            .map_or(deadline, |old| old.min(deadline)),
                    );
                    self.native_mode_requested = true;
                    self.native_qr_mode = self.outbound.is_some();
                    self.ready = false;
                    self.pending.clear();
                    self.claimed.clear();
                    self.generation = self.generation.wrapping_add(1);
                }
                (Some(mode), Some(attached)) if mode == "proxy" && attached == true => {
                    if self.helper.is_some() || self.native_mode_requested || self.native_qr_mode {
                        self.mode_generation = self.mode_generation.wrapping_add(1);
                        self.generation = self.generation.wrapping_add(1);
                    }
                    self.lease_pending = None;
                    self.lease_generation = 0;
                    self.helper = None;
                    self.native_mode_requested = false;
                    self.native_mode_deadline = None;
                    self.proxy_mode_required = false;
                    self.native_qr_mode = false;
                    self.ready = self.outbound.is_some();
                }
                _ => return Err("Unexpected browser mode readiness".into()),
            }
            self.mode_error = None;
            self.timed_out_proxy_generation = None;
            let version = if value["extensionVersion"] == EXTENSION_VERSION {
                EXTENSION_VERSION
            } else {
                "legacy/unknown"
            };
            eprintln!("[native-proxy] browser ready; extension={version}");
            self.event("connected", None);
            return Ok(());
        }
        if kind == "disconnected" {
            self.disconnected();
            return Ok(());
        }
        if kind == "mode_error" {
            let operation = value["operation"].as_str();
            let reason = value["reason"].as_str();
            if !matches!(operation, Some("attach" | "detach"))
                || !matches!(reason, Some("timeout" | "api_error"))
            {
                return Err("Invalid mode error".into());
            }
            let initializing = value["generation"].as_i64() == Some(-1)
                && self.mode_pending.is_none()
                && !self.ready
                && !self.native_mode_requested
                && !self.proxy_mode_required;
            let current_transition = value["generation"].as_u64() == Some(self.mode_generation)
                && (self.mode_pending.is_some()
                    || self.timed_out_proxy_generation == Some(self.mode_generation));
            if !current_transition && !initializing {
                return Err("Stale mode error".into());
            }
            let native_failed = self.native_mode_requested;
            if (native_failed && operation != Some("detach"))
                || (!native_failed && operation != Some("attach"))
            {
                return Err("Unexpected mode error".into());
            }
            self.cancel_all("Browser mode transition failed");
            self.ready = false;
            self.native_qr_mode = false;
            if !native_failed {
                self.mode_pending = None;
                self.timed_out_proxy_generation = (!initializing).then_some(self.mode_generation);
            }
            self.mode_error = Some(
                match (native_failed, reason) {
                    (true, Some("timeout")) => "native_mode_timeout",
                    (false, Some("timeout")) => "proxy_mode_timeout",
                    (true, _) => "native_mode_api_error",
                    (false, _) => "proxy_mode_api_error",
                }
                .into(),
            );
            self.event("mode_error", None);
            return Ok(());
        }
        if kind == "error" {
            let native_failed = self.native_mode_requested;
            self.cancel_all("Browser bridge failed");
            self.ready = false;
            self.native_qr_mode = false;
            // A failed native transition gets one rollback. A failed rollback
            // is terminal until an actual acknowledgement or reconnect arrives.
            if !native_failed {
                self.mode_pending = None;
                self.timed_out_proxy_generation = Some(self.mode_generation);
            }
            self.mode_error = Some("browser_mode_error".into());
            self.event("mode_error", None);
            return Err(value["message"]
                .as_str()
                .unwrap_or("Browser bridge failed")
                .to_owned());
        }
        let request_id = value["requestId"]
            .as_i64()
            .ok_or("Missing native request ID")?;
        if kind == "uvpaa" {
            self.send(json!({"type":"uvpaa","requestId":request_id,"isUvpaa":self.ready && keys.iter().any(|k| k.enabled && k.attachment == "platform")}));
            return Ok(());
        }
        if kind == "cancel" {
            let ids: Vec<_> = self
                .pending
                .values()
                .chain(self.claimed.values())
                .filter(|r| r.request_id == request_id)
                .map(|r| r.id.clone())
                .collect();
            for id in ids {
                self.event("canceled", Some(&id));
            }
            self.pending.retain(|_, r| r.request_id != request_id);
            self.claimed.retain(|_, r| r.request_id != request_id);
            return Ok(());
        }
        if !matches!(kind, "create" | "get") {
            return Err("Unknown native message type".into());
        }
        if !self.ready {
            self.error(
                kind,
                request_id,
                "NotAllowedError",
                "Browser bridge is not ready",
            );
            return Err("Browser bridge is not ready".into());
        }
        if self
            .pending
            .values()
            .chain(self.claimed.values())
            .any(|r| r.request_id == request_id)
        {
            self.pending.retain(|_, r| r.request_id != request_id);
            self.claimed.retain(|_, r| r.request_id != request_id);
            self.event("canceled", None);
            self.error(
                kind,
                request_id,
                "NotAllowedError",
                "Duplicate native request ID",
            );
            return Err("Duplicate native request ID".into());
        }
        if self.pending.len() + self.claimed.len() >= MAX_PENDING {
            self.error(
                kind,
                request_id,
                "NotAllowedError",
                "Too many pending requests",
            );
            return Err("Too many pending requests".into());
        }
        match self.parse_request(kind, request_id, &value, keys) {
            Ok(request) => {
                self.event("pending", Some(&request.id));
                self.pending.insert(request.id.clone(), request);
                Ok(())
            }
            Err(message) => {
                self.error(kind, request_id, "NotAllowedError", &message);
                Err(message)
            }
        }
    }
    fn parse_request(
        &self,
        kind: &str,
        request_id: i64,
        value: &Value,
        keys: &[KeyConfig],
    ) -> Result<Request, String> {
        let raw = value["requestDetailsJson"]
            .as_str()
            .ok_or("Missing native request details")?;
        if raw.len() > MAX_REQUEST_BYTES {
            return Err("Native request is too large".into());
        }
        let options: Value =
            serde_json::from_str(raw).map_err(|_| "Invalid native request JSON")?;
        let remote = &options["extensions"]["remoteDesktopClientOverride"];
        let origin = remote["origin"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("Missing browser-validated origin")?
            .to_owned();
        if remote["sameOriginWithAncestors"].as_bool() != Some(true) {
            return Err("Cross-origin frames are not supported by this authenticator".into());
        }
        let rp_id = if kind == "create" {
            options["rp"]["id"].as_str()
        } else {
            options["rpId"].as_str()
        }
        .filter(|s| !s.is_empty())
        .ok_or("Missing browser-validated RP ID")?
        .to_owned();
        let challenge = options["challenge"].as_str().ok_or("Missing challenge")?;
        if decode(challenge)
            .filter(|bytes| !bytes.is_empty())
            .is_none()
        {
            return Err("Invalid challenge".into());
        }
        let uv = if kind == "create" {
            options["authenticatorSelection"]["userVerification"].as_str()
        } else {
            options["userVerification"].as_str()
        }
        .unwrap_or("preferred");
        if !matches!(uv, "required" | "preferred" | "discouraged") {
            return Err("Invalid user verification requirement".into());
        }
        if kind == "create"
            && !options["pubKeyCredParams"].as_array().is_some_and(|algs| {
                algs.iter()
                    .any(|a| a["type"] == "public-key" && a["alg"] == -7)
            })
        {
            return Err("Only ES256 credentials are supported".into());
        }
        let millis = options["timeout"]
            .as_u64()
            .unwrap_or(MAX_LIFETIME.as_millis() as u64)
            .clamp(1, MAX_LIFETIME.as_millis() as u64);
        let mut candidates = Vec::new();
        for key in keys.iter().filter(|k| k.enabled) {
            let base = Candidate {
                key_revision: key_revision(key),
                deadline: Instant::now()
                    + Duration::from_millis(
                        millis.min(u64::from(key.presence_timeout_seconds) * 1000),
                    ),
                key_id: key.id.clone(),
                key_name: key.name.clone(),
                attachment: key.attachment.clone(),
                credential_id: None,
                user_name: None,
                display_name: None,
                user_handle: None,
            };
            if kind == "create" {
                if crate::authenticator::signer::resident_key_required(&options)
                    && !key.resident_key_supported
                {
                    continue;
                }
                if options["authenticatorSelection"]["authenticatorAttachment"]
                    .as_str()
                    .is_some_and(|a| a != key.attachment)
                {
                    continue;
                }
                if descriptors(&options, "excludeCredentials")
                    .iter()
                    .any(|excluded| {
                        key.credentials
                            .iter()
                            .any(|c| c["rpId"] == rp_id && credential_matches(c, excluded))
                    })
                {
                    continue;
                }
                candidates.push(Candidate {
                    user_name: string(&options["user"], "name"),
                    display_name: string(&options["user"], "displayName"),
                    ..base
                });
            } else {
                let allow = descriptors(&options, "allowCredentials");
                for credential in &key.credentials {
                    if credential["rpId"] != rp_id {
                        continue;
                    }
                    if allow.is_empty() {
                        if credential["isResidentCredential"].as_bool() != Some(true) {
                            continue;
                        }
                    } else if !allow
                        .iter()
                        .any(|allowed| credential_matches(credential, allowed))
                    {
                        continue;
                    }
                    let Some(id) = credential["credentialId"].as_str() else {
                        continue;
                    };
                    candidates.push(Candidate {
                        credential_id: Some(id.to_owned()),
                        user_name: string(credential, "userName"),
                        display_name: string(credential, "userDisplayName"),
                        user_handle: string(credential, "userHandle"),
                        ..base.clone()
                    });
                }
            }
        }
        // Phone/native login has its own ceremony deadline, independent of
        // virtual key presence timers. Selecting a virtual key still narrows
        // the request deadline to that candidate in advance_request.
        let deadline = if kind == "get" {
            Instant::now() + Duration::from_millis(millis)
        } else {
            candidates
                .iter()
                .map(|c| c.deadline)
                .max()
                .unwrap_or_else(|| Instant::now() + Duration::from_millis(millis))
        };
        Ok(Request {
            native_attempt: None,
            stage: "select_key".into(),
            selection: None,
            id: Uuid::new_v4().to_string(),
            request_id,
            generation: self.generation,
            kind: kind.to_owned(),
            origin,
            rp_id,
            uv: uv.to_owned(),
            options,
            candidates,
            deadline,
        })
    }
    pub fn public_requests(&mut self) -> Vec<Value> {
        self.expire();
        let now = Instant::now();
        let mut requests: Vec<_> = self.pending.values().chain(self.claimed.values()).collect();
        requests.sort_by_key(|r| r.deadline);
        requests.into_iter().map(|r| json!({"id":r.id,"stage":r.stage,"busy":self.claimed.contains_key(&r.id),"selected_key_id":r.selection.as_ref().map(|s| &s.key_id),"selected_credential_id":r.selection.as_ref().and_then(|s| s.credential_id.as_ref()),"kind":r.kind,"request_excludes_hybrid":r.kind == "get" && request_excludes_hybrid(&r.options),"attestation_requested":if r.kind == "create" { Some(r.options["attestation"].as_str().unwrap_or("none")) } else {None},"origin":r.origin,"rp_id":r.rp_id,"uv":r.uv,"remaining_ms":r.deadline.saturating_duration_since(now).as_millis() as u64,"candidates":r.candidates.iter().filter(|c| c.deadline > now).map(|c| { let mut v = serde_json::to_value(c).unwrap(); v["remaining_ms"] = json!(c.deadline.saturating_duration_since(now).as_millis() as u64); v }).collect::<Vec<_>>()})).collect()
    }
    pub fn deny_request(&mut self, id: &str) -> bool {
        self.expire();
        let request = self
            .take_request(id)
            .or_else(|| self.claimed.get(id).cloned());
        request.is_some_and(|request| self.finish(&request, Err("User denied this request".into())))
    }
    pub fn take_request(&mut self, id: &str) -> Option<Request> {
        self.expire();
        let request = self.pending.remove(id)?;
        self.claimed.insert(id.to_owned(), request.clone());
        self.event("claimed", Some(id));
        Some(request)
    }
    /// Atomically claim a native login. The token and browser options are never
    /// included in public snapshots. A virtual selection cannot be converted.
    pub fn start_native(
        &mut self,
        id: &str,
        attempt: crate::browser::native_client::Attempt,
    ) -> Option<Request> {
        self.expire();
        let pending = self.pending.get(id)?;
        if pending.kind != "get" || pending.stage != "select_key" {
            return None;
        }
        let mut request = self.take_request(id)?;
        request.native_attempt = Some(attempt);
        self.set_stage(&mut request, "native_pending");
        Some(request)
    }
    pub fn native_request(&mut self, id: &str) -> Option<Request> {
        self.expire();
        self.claimed
            .get(id)
            .filter(|r| r.stage == "native_pending")
            .cloned()
    }
    pub fn finish_native_error(&mut self, request: &Request, name: &str, message: &str) -> bool {
        if !self.is_current(request) {
            return false;
        }
        self.claimed.remove(&request.id);
        let delivered = self.error(&request.kind, request.request_id, name, message);
        self.event(
            if delivered {
                "failed"
            } else {
                "delivery_failed"
            },
            Some(&request.id),
        );
        delivered
    }
    pub fn resume(&mut self, request: Request) -> bool {
        if !self.is_current(&request) {
            return false;
        }
        self.claimed.remove(&request.id);
        let id = request.id.clone();
        let stage = request.stage.clone();
        self.pending.insert(id.clone(), request);
        self.event(&stage, Some(&id));
        true
    }
    pub fn set_stage(&mut self, request: &mut Request, stage: &str) {
        if self.is_current(request) {
            request.stage = stage.into();
            self.claimed.insert(request.id.clone(), request.clone());
            self.event(stage, Some(&request.id));
        }
    }
    pub fn is_current(&self, request: &Request) -> bool {
        self.ready
            && request.generation == self.generation
            && Instant::now() < request.deadline
            && self.claimed.get(&request.id).is_some_and(|r| {
                r.request_id == request.request_id && r.generation == request.generation
            })
    }
    pub fn finish(&mut self, request: &Request, response: Result<Value, String>) -> bool {
        let valid = self.is_current(request);
        self.claimed.remove(&request.id);
        if !valid {
            return false;
        }
        let succeeded = response.is_ok();
        let delivered = match response {
            Ok(response) => self.send(json!({"type":request.kind,"requestId":request.request_id,"responseJson":response.to_string()})),
            Err(message) => self.error(&request.kind, request.request_id, "NotAllowedError", &message),
        };
        self.event(
            if !delivered {
                "delivery_failed"
            } else if succeeded {
                "completed"
            } else {
                "failed"
            },
            Some(&request.id),
        );
        delivered
    }

    pub fn expire(&mut self) {
        let now = Instant::now();
        if self
            .native_mode_deadline
            .is_some_and(|deadline| deadline <= now)
            || self
                .helper
                .as_ref()
                .is_some_and(|s| s.deadline <= now || s.disconnected())
        {
            self.stop_helper();
        }
        if self
            .lease_pending
            .is_some_and(|(_, _, deadline)| deadline <= now)
        {
            self.stop_helper();
            self.mode_error = Some("native_lease_timeout".into());
            self.event("mode_error", None);
        }
        if self.mode_pending.is_some_and(|d| d <= now) {
            self.helper = None;
            if self.native_mode_requested {
                // Revoke native authorization and request exactly one rollback.
                self.set_mode(false);
                self.mode_error = Some("native_mode_timeout".into());
            } else {
                // Reissuing every deadline keeps the UI switching forever and
                // invalidates late, otherwise truthful proxy acknowledgements.
                self.mode_pending = None;
                self.ready = false;
                self.native_qr_mode = false;
                self.timed_out_proxy_generation = Some(self.mode_generation);
                self.mode_error = Some("proxy_mode_timeout".into());
            }
            self.event("mode_error", None);
        }
        let mut candidate_expired = false;
        for request in self.pending.values_mut() {
            let count = request.candidates.len();
            request.candidates.retain(|c| c.deadline > now);
            candidate_expired |= request.candidates.len() != count;
        }
        if candidate_expired {
            self.event("candidate_expired", None);
        }
        let expired: Vec<_> = self
            .pending
            .values()
            .chain(self.claimed.values())
            .filter(|r| r.deadline <= now)
            .cloned()
            .collect();
        for request in expired {
            self.event("expired", Some(&request.id));
            self.pending.remove(&request.id);
            self.claimed.remove(&request.id);
            self.error(
                &request.kind,
                request.request_id,
                "NotAllowedError",
                "Authentication request timed out",
            );
        }
        self.sync_navigation_scope();
        self.local_navigation.expire();
        self.expire_window_control();
    }
}
fn string(value: &Value, field: &str) -> Option<String> {
    value[field].as_str().map(str::to_owned)
}
fn decode(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .or_else(|_| STANDARD.decode(value))
        .ok()
}
// Conservative diagnostic only: never changes the relying party's request.
// Missing/empty or unrecognized transport lists remain unknown/eligible. The
// browser may normalize legacy "cable" to hybrid; never call that excluded.
fn request_excludes_hybrid(options: &Value) -> bool {
    options["allowCredentials"]
        .as_array()
        .is_some_and(|credentials| {
            !credentials.is_empty()
                && credentials.iter().all(|credential| {
                    credential["transports"]
                        .as_array()
                        .is_some_and(|transports| {
                            !transports.is_empty()
                                && transports.iter().all(|transport| {
                                    matches!(
                                        transport.as_str(),
                                        Some("usb" | "nfc" | "ble" | "internal")
                                    )
                                })
                        })
                })
        })
}

fn descriptors<'a>(options: &'a Value, field: &str) -> Vec<&'a str> {
    options[field]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|v| v["type"] == "public-key")
                .filter_map(|v| v["id"].as_str())
                .collect()
        })
        .unwrap_or_default()
}
fn credential_matches(credential: &Value, other: &str) -> bool {
    credential["credentialId"]
        .as_str()
        .and_then(decode)
        .zip(decode(other))
        .is_some_and(|(a, b)| !a.is_empty() && a == b)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn test_ready(mode: &str, attached: bool, lease: u64) -> Value {
        json!({"type":"ready","extensionVersion":EXTENSION_VERSION,"extensionBuild":EXTENSION_BUILD,"protocolVersion":PROTOCOL_VERSION,
            "capabilities":REQUIRED_CAPABILITIES,"mode":mode,"attached":attached,"leaseRemainingMs":lease})
    }

    fn key() -> KeyConfig {
        serde_json::from_value(json!({"id":"key-1","name":"USB","attachment":"cross-platform","enabled":true,"credentials":[
            {"credentialId":"AQI=","rpId":"example.com","isResidentCredential":true,"userHandle":"Aw==","userName":"alice","privateKey":"SECRET"},
            {"credentialId":"BAU=","rpId":"example.com","isResidentCredential":true,"userHandle":"Bg==","userName":"bob","privateKey":"SECRET"},
            {"credentialId":"Bwg=","rpId":"other.example","isResidentCredential":true,"privateKey":"SECRET"}
        ]})).unwrap()
    }
    fn options() -> Value {
        json!({"rpId":"example.com","challenge":"AQID","extensions":{"remoteDesktopClientOverride":{"origin":"https://example.com","sameOriginWithAncestors":true}}})
    }
    fn event(id: i64, options: Value) -> Value {
        json!({"type":"get","requestId":id,"requestDetailsJson":options.to_string()})
    }
    fn broker() -> (Broker, tokio::sync::mpsc::UnboundedReceiver<Value>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut broker = Broker::default();
        broker.connected(tx);
        assert!(!broker.ready);
        broker
            .on_message(
                crate::browser::broker::tests::test_ready("proxy", true, 0),
                &[],
            )
            .unwrap();
        (broker, rx)
    }
    #[test]
    fn hybrid_exclusion_diagnostic_is_conservative_and_ignores_hints() {
        for transports in [json!(["usb"]), json!(["internal", "nfc", "ble"])] {
            assert!(request_excludes_hybrid(
                &json!({"allowCredentials":[{"transports":transports}]})
            ));
        }
        for options in [
            json!({}),
            json!({"allowCredentials":[]}),
            json!({"hints":["security-key"]}),
            json!({"allowCredentials":[{}]}),
            json!({"allowCredentials":[{"transports":[]}]}),
            json!({"allowCredentials":[{"transports":["hybrid"]}]}),
            json!({"allowCredentials":[{"transports":["cable"]}]}),
            json!({"allowCredentials":[{"transports":["future-transport"]}]}),
            json!({"allowCredentials":[{"transports":["usb", "unknown"]}]}),
            json!({"allowCredentials":[{"transports":["usb"]}, {}]}),
            json!({"allowCredentials":[{"transports":["usb"]}, {"transports":["hybrid"]}]}),
            json!({"allowCredentials":[{"transports":"usb"}]}),
        ] {
            assert!(!request_excludes_hybrid(&options), "{options}");
        }
        let (mut b, _rx) = broker();
        let mut o = options();
        o["allowCredentials"] = json!([{"type":"public-key","id":"AQI","transports":["usb"]}]);
        b.on_message(event(1, o), &[key()]).unwrap();
        assert_eq!(b.public_requests()[0]["request_excludes_hybrid"], true);
        let public = serde_json::to_string(&b.public_requests()).unwrap();
        assert!(!public.contains("transports"));
        assert!(!public.contains("challenge"));
    }

    #[test]
    fn incompatible_or_incomplete_handshake_fails_closed_until_reconnect() {
        let good = test_ready("proxy", true, 0);
        let mut invalid = vec![json!({"type":"ready"})];
        for (field, value) in [
            ("extensionVersion", json!("1.0.27")),
            ("extensionVersion", json!("unknown")),
            ("extensionBuild", json!("0".repeat(64))),
            (
                "extensionBuild",
                json!("wrong build with the same extension version"),
            ),
            ("extensionBuild", json!(null)),
            ("protocolVersion", json!(2)),
            ("capabilities", json!(["heartbeat", "mode_ack_generation"])),
            ("capabilities", json!(["heartbeat", "mode_progress"])),
            (
                "capabilities",
                json!(["mode_ack_generation", "mode_progress"]),
            ),
            ("attached", json!(false)),
            ("mode", json!("unknown")),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            invalid.push(bad);
        }
        for field in [
            "extensionVersion",
            "extensionBuild",
            "protocolVersion",
            "capabilities",
            "mode",
            "attached",
        ] {
            let mut bad = good.clone();
            bad.as_object_mut().unwrap().remove(field);
            invalid.push(bad);
        }
        for bad in invalid {
            let (mut b, mut output) = broker();
            b.on_message(event(1, options()), &[key()]).unwrap();
            let id = b.public_requests()[0]["id"].as_str().unwrap().to_owned();
            let claimed = b.take_request(&id).unwrap();
            b.on_message(event(2, options()), &[key()]).unwrap();
            assert_eq!(b.on_message(bad, &[]).unwrap_err(), UPGRADE_REQUIRED);
            assert_eq!(b.mode_error.as_deref(), Some("extension_upgrade_required"));
            assert!(!b.ready && !b.native_qr_mode && b.mode_pending.is_none());
            assert!(b.public_requests().is_empty());
            assert!(!b.finish(&claimed, Ok(json!({}))));
            assert!(!b.set_mode(true));
            assert!(b.on_message(good.clone(), &[]).is_err());
            assert!(b
                .on_message(
                    json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":b.mode_generation}),
                    &[]
                )
                .is_err());
            let replies: Vec<_> = std::iter::from_fn(|| output.try_recv().ok()).collect();
            assert_eq!(replies.len(), 2);
            assert!(replies
                .iter()
                .all(|r| r["error"]["message"] == UPGRADE_REQUIRED));
            let (tx, _output) = tokio::sync::mpsc::unbounded_channel();
            b.connected(tx);
            assert_eq!(b.mode_error.as_deref(), Some("extension_upgrade_required"));
            assert!(b.on_message(json!({"type":"mode_error","operation":"attach","reason":"timeout","generation":-1}), &[]).is_err());
            assert_eq!(b.mode_error.as_deref(), Some("extension_upgrade_required"));
            b.on_message(good.clone(), &[]).unwrap();
            assert!(b.ready && b.mode_error.is_none());
        }
    }

    #[test]
    fn rejected_native_handshake_cannot_activate_or_restore_phone_mode() {
        let (mut b, mut output) = broker();
        assert!(b.set_mode(true));
        let mode = output.try_recv().unwrap();
        let mut bad = test_ready("native", false, 60000);
        bad["extensionVersion"] = json!("1.0.27");
        assert!(b.on_message(bad, &[]).is_err());
        assert!(!b.native_qr_mode && !b.native_mode_requested);
        assert!(b.native_mode_deadline.is_none() && b.helper.is_none());
        assert!(b
            .on_message(
                json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":mode["generation"]}),
                &[]
            )
            .is_err());
        b.expire();
        assert!(output.try_recv().is_err());
    }

    #[test]
    fn current_capability_handshake_roundtrips_generation_bound_modes() {
        let mut b = Broker::default();
        let (tx, mut output) = tokio::sync::mpsc::unbounded_channel();
        b.connected(tx);
        assert!(!b.set_mode(true));
        b.on_message(json!({"type":"ping","nonce":1}), &[]).unwrap();
        assert_eq!(output.try_recv().unwrap()["type"], "pong");
        assert!(!b.ready);
        b.on_message(test_ready("proxy", true, 0), &[]).unwrap();
        assert!(b.set_mode(true));
        let mode = output.try_recv().unwrap();
        assert!(b
            .on_message(
                json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":0}),
                &[]
            )
            .is_err());
        b.on_message(
            json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":mode["generation"]}),
            &[],
        )
        .unwrap();
        assert!(b.native_qr_mode && !b.ready);
        assert!(b.set_mode(false));
        let mode = output.try_recv().unwrap();
        b.on_message(
            json!({"type":"mode_ready","mode":"proxy","attached":true,"extensionVersion":"1.0.29","protocolVersion":1,"generation":mode["generation"]}),
            &[],
        )
        .unwrap();
        assert!(b.ready && !b.native_qr_mode);
    }

    #[test]
    fn mode_progress_is_validated_and_never_changes_readiness_or_expires_mode() {
        let (mut b, mut output) = broker();
        b.set_mode(true);
        let mode = output.try_recv().unwrap();
        b.mode_pending = Some(Instant::now());
        let before = b.sequence;
        for stage in [
            "received",
            "attach_started",
            "attach_completed",
            "detach_started",
            "detach_completed",
        ] {
            b.on_message(json!({"type":"mode_progress","stage":stage,"generation":mode["generation"],"extensionVersion":"1.0.29"}), &[]).unwrap();
        }
        assert!(b.mode_pending.is_some());
        assert!(b.native_mode_requested);
        assert!(!b.ready);
        assert_eq!(b.sequence, before);
        assert!(output.try_recv().is_err());
        assert!(b.on_message(json!({"type":"mode_progress","stage":"secret\nforged log","generation":mode["generation"]}), &[]).is_err());
        assert!(b
            .on_message(
                json!({"type":"mode_progress","stage":"received","generation":-1}),
                &[]
            )
            .is_err());
        assert_eq!(b.sequence, before);
    }

    #[test]
    fn stalled_native_transition_rolls_back_once_and_exits_switching() {
        let (mut b, mut output) = broker();
        b.set_mode(true);
        let native = output.try_recv().unwrap();
        b.mode_pending = Some(Instant::now());
        b.expire();
        let rollback = output.try_recv().unwrap();
        assert_eq!(rollback["mode"], "proxy");
        assert_eq!(b.mode_error.as_deref(), Some("native_mode_timeout"));
        assert!(b.mode_pending.is_some());
        assert!(b
            .on_message(
                json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":native["generation"]}),
                &[]
            )
            .is_err());
        b.mode_pending = Some(Instant::now());
        b.expire();
        assert_eq!(b.mode_error.as_deref(), Some("proxy_mode_timeout"));
        assert!(!b.ready);
        assert!(!b.native_qr_mode);
        assert_eq!(b.stream_snapshot(None)["mode_switching"], false);
        let generation = b.mode_generation;
        for _ in 0..20 {
            b.expire();
        }
        assert_eq!(b.mode_generation, generation);
        assert!(output.try_recv().is_err());
        assert!(b.on_message(event(42, options()), &[key()]).is_err());
        assert_eq!(
            output.try_recv().unwrap()["error"]["message"],
            "Browser bridge is not ready"
        );
        b.on_message(
            json!({"type":"mode_ready","mode":"proxy","attached":true,"extensionVersion":"1.0.29","protocolVersion":1,"generation":rollback["generation"]}),
            &[],
        )
        .unwrap();
        assert!(b.ready);
        assert!(b.mode_error.is_none());
        assert!(b
            .on_message(
                json!({"type":"mode_ready","mode":"proxy","attached":true,"extensionVersion":"1.0.29","protocolVersion":1,"generation":rollback["generation"]}),
                &[]
            )
            .is_err());
    }

    #[test]
    fn mode_errors_are_validated_and_rollback_is_bounded() {
        let (mut b, mut output) = broker();
        b.set_mode(true);
        let native = output.try_recv().unwrap();
        let failure = json!({"type":"mode_error","operation":"detach","reason":"timeout","generation":native["generation"]});
        b.on_message(failure.clone(), &[]).unwrap();
        let rollback = output.try_recv().unwrap();
        assert_eq!(rollback["mode"], "proxy");
        assert!(b.on_message(failure, &[]).is_err());
        assert!(b.on_message(json!({"type":"mode_error","operation":"detach","reason":"timeout","generation":rollback["generation"]}), &[]).is_err());
        assert!(b.on_message(json!({"type":"mode_error","operation":"attach","reason":"SECRET","generation":rollback["generation"]}), &[]).is_err());
        b.on_message(json!({"type":"mode_error","operation":"attach","reason":"api_error","generation":rollback["generation"]}), &[]).unwrap();
        assert!(b.mode_pending.is_none());
        assert_eq!(
            b.stream_snapshot(None)["mode_error"],
            "proxy_mode_api_error"
        );
        for _ in 0..20 {
            b.expire();
        }
        assert!(output.try_recv().is_err());
        b.on_message(
            json!({"type":"mode_ready","mode":"proxy","attached":true,"extensionVersion":"1.0.29","protocolVersion":1,"generation":rollback["generation"]}),
            &[],
        )
        .unwrap();
        assert!(b.ready);
        assert!(b.mode_error.is_none());
    }

    #[test]
    fn initialization_mode_error_recovers_only_after_truthful_readiness() {
        let mut b = Broker::default();
        let (tx, mut output) = tokio::sync::mpsc::unbounded_channel();
        b.connected(tx);
        let failure =
            json!({"type":"mode_error","operation":"attach","reason":"timeout","generation":-1});
        b.on_message(failure.clone(), &[]).unwrap();
        assert_eq!(b.mode_error.as_deref(), Some("proxy_mode_timeout"));
        assert!(!b.ready);
        assert!(b.mode_pending.is_none());
        assert!(output.try_recv().is_err());
        b.on_message(
            crate::browser::broker::tests::test_ready("proxy", true, 0),
            &[],
        )
        .unwrap();
        assert!(b.ready);
        assert!(b.mode_error.is_none());
        assert!(b.on_message(failure, &[]).is_err());
    }

    #[test]
    fn failed_proxy_transition_reconnect_invalidates_late_ack() {
        let (mut b, mut output) = broker();
        b.set_mode(false);
        let old = output.try_recv().unwrap();
        b.mode_pending = Some(Instant::now());
        b.expire();
        b.disconnected();
        let (tx, _output) = tokio::sync::mpsc::unbounded_channel();
        b.connected(tx);
        assert!(b
            .on_message(
                json!({"type":"mode_ready","mode":"proxy","attached":true,"extensionVersion":"1.0.29","protocolVersion":1,"generation":old["generation"]}),
                &[]
            )
            .is_err());
        assert!(!b.ready);
        b.on_message(
            crate::browser::broker::tests::test_ready("proxy", true, 0),
            &[],
        )
        .unwrap();
        assert!(b.ready);
        assert!(b.mode_error.is_none());
    }

    #[test]
    fn mode_switches_publish_readiness_changes_before_acknowledgement() {
        let (mut b, mut output) = broker();
        let mut changes = b.subscribe();
        assert!(b.set_mode(true));
        assert!(changes.has_changed().unwrap());
        changes.borrow_and_update();
        let mode = output.try_recv().unwrap();
        b.on_message(
            json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":mode["generation"]}),
            &[],
        )
        .unwrap();
        changes.borrow_and_update();
        assert!(b.set_mode(false));
        assert!(
            changes.has_changed().unwrap(),
            "leaving native mode must wake SSE before acknowledgement"
        );
        let snapshot = b.stream_snapshot(None);
        assert_eq!(snapshot["mode_switching"], true);
        assert_eq!(snapshot["native_qr_mode"], false);
        assert_eq!(snapshot["connected"], false);
        assert_eq!(b.events.back().unwrap()["kind"], "mode_switching");
    }

    #[test]
    fn snapshot_distinguishes_transport_proxy_and_native_readiness() {
        let mut b = Broker::default();
        let snapshot = b.stream_snapshot(None);
        assert_eq!(snapshot["connected"], false);
        assert_eq!(snapshot["control_connected"], false);
        assert_eq!(snapshot["native_qr_mode"], false);
        assert_eq!(snapshot["mode_switching"], false);
        let (tx, mut output) = tokio::sync::mpsc::unbounded_channel();
        b.connected(tx);
        let snapshot = b.stream_snapshot(None);
        assert_eq!(snapshot["control_connected"], true);
        assert_eq!(snapshot["connected"], false);
        b.on_message(
            crate::browser::broker::tests::test_ready("proxy", true, 0),
            &[],
        )
        .unwrap();
        assert_eq!(b.stream_snapshot(None)["connected"], true);
        assert!(b.set_mode(true));
        let snapshot = b.stream_snapshot(None);
        assert_eq!(snapshot["connected"], false);
        assert_eq!(snapshot["control_connected"], true);
        assert_eq!(snapshot["mode_switching"], true);
        assert_eq!(snapshot["native_qr_mode"], false);
        let mode = output.try_recv().unwrap();
        b.on_message(
            json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":mode["generation"]}),
            &[],
        )
        .unwrap();
        let snapshot = b.stream_snapshot(None);
        assert_eq!(
            snapshot["connected"], false,
            "native mode must never authorize software-key approvals"
        );
        assert_eq!(snapshot["control_connected"], true);
        assert_eq!(snapshot["native_qr_mode"], true);
        assert_eq!(snapshot["mode_switching"], false);
        b.disconnected();
        let snapshot = b.stream_snapshot(None);
        assert_eq!(snapshot["control_connected"], false);
        assert_eq!(snapshot["native_qr_mode"], false);
        assert_eq!(snapshot["connected"], false);
    }

    #[test]
    fn heartbeat_is_bounded_and_does_not_authorize_or_expire_requests() {
        let (mut b, mut rx) = broker();
        b.on_message(event(1, options()), &[key()]).unwrap();
        let id = b.public_requests()[0]["id"].as_str().unwrap().to_owned();
        let request = b.take_request(&id).unwrap();
        let sequence = b.sequence;
        b.on_message(json!({"type":"ping","nonce":42}), &[])
            .unwrap();
        assert_eq!(rx.try_recv().unwrap(), json!({"type":"pong","nonce":42}));
        assert_eq!(b.sequence, sequence);
        assert!(b.is_current(&request));
        for nonce in [
            json!(-1),
            json!(9_007_199_254_740_992u64),
            json!("secret"),
            Value::Null,
        ] {
            assert!(b
                .on_message(json!({"type":"ping","nonce":nonce}), &[])
                .is_err());
        }
        assert!(rx.try_recv().is_err());
        b.disconnected();
        assert!(b
            .on_message(json!({"type":"ping","nonce":43}), &[])
            .is_err());
        assert!(!b.ready);
    }
    #[test]
    fn repeated_offline_recovery_does_not_publish_duplicate_disconnects() {
        let mut cold = Broker::default();
        let cold_changes = cold.subscribe();
        for _ in 0..3 {
            cold.disconnected();
        }
        assert!(!cold_changes.has_changed().unwrap());
        assert!(cold.events.is_empty());
        let (mut b, _output) = broker();
        let mut changes = b.subscribe();
        b.disconnected();
        assert!(changes.has_changed().unwrap());
        changes.borrow_and_update();
        let sequence = b.sequence;
        let generation = b.generation;
        b.disconnected();
        assert!(!changes.has_changed().unwrap());
        assert_eq!(b.sequence, sequence);
        assert_ne!(b.generation, generation);
    }
    #[test]
    fn reconnect_never_replays_claims_or_recreates_helper_authorization() {
        let (mut b, mut old_output) = broker();
        b.on_message(event(1, options()), &[key()]).unwrap();
        let id = b.public_requests()[0]["id"].as_str().unwrap().to_owned();
        let old = b.take_request(&id).unwrap();
        b.native_mode_requested = true;
        b.native_mode_deadline = Some(Instant::now() + Duration::from_secs(30));
        b.disconnected();
        let (tx, mut output) = tokio::sync::mpsc::unbounded_channel();
        b.connected(tx);
        assert!(b
            .on_message(test_ready("native", false, 60000), &[])
            .is_err());
        assert!(!b.native_qr_mode && !b.ready);
        assert!(b.helper.is_none() && b.native_mode_deadline.is_none());
        assert!(!b.finish(&old, Ok(json!({}))));
        assert!(b.public_requests().is_empty());
        assert!(old_output.try_recv().is_err());
        let rollback = output.try_recv().unwrap();
        assert_eq!(rollback["mode"], "proxy");
        b.on_message(
            json!({"type":"mode_ready","mode":"proxy","attached":true,
            "extensionVersion":"1.0.29","protocolVersion":1,"generation":rollback["generation"]}),
            &[],
        )
        .unwrap();
        assert!(b.ready);
        b.on_message(event(1, options()), &[key()]).unwrap();
        let new_id = b.public_requests()[0]["id"].as_str().unwrap().to_owned();
        let new_request = b.take_request(&new_id).unwrap();
        assert_ne!(new_request.id, old.id);
        assert!(!b.finish(&old, Ok(json!({}))));
        assert!(b.is_current(&new_request));
        assert!(output.try_recv().is_err());
    }
    #[test]
    fn fresh_gateway_rejects_ownerless_native_readiness_and_cancels_claims() {
        let (mut b, mut output) = broker();
        for lease in [0, 5000, 120000] {
            b.on_message(event(2, options()), &[key()]).unwrap();
            let id = b.public_requests()[0]["id"].as_str().unwrap().to_owned();
            let request = b.take_request(&id).unwrap();
            assert!(b
                .on_message(test_ready("native", false, lease), &[])
                .is_err());
            assert!(!b.native_qr_mode && !b.ready);
            assert!(b.helper.is_none());
            assert_eq!(
                output.try_recv().unwrap()["error"]["name"],
                "NotAllowedError"
            );
            let mode = output.try_recv().unwrap();
            assert_eq!(mode["mode"], "proxy");
            b.on_message(
                json!({"type":"mode_ready","mode":"proxy","attached":true,
                "extensionVersion":"1.0.29","protocolVersion":1,"generation":mode["generation"]}),
                &[],
            )
            .unwrap();
            assert!(b.ready);
            assert!(!b.finish(&request, Ok(json!({}))));
        }
    }
    #[test]
    fn reconnect_rejects_stale_mode_acknowledgements() {
        let (mut b, mut output) = broker();
        b.native_mode_deadline = Some(Instant::now() + Duration::from_secs(30));
        assert!(b.set_mode(true));
        let old = output.try_recv().unwrap();
        b.disconnected();
        let (tx, _output) = tokio::sync::mpsc::unbounded_channel();
        b.connected(tx);
        assert!(b
            .on_message(
                json!({"type":"mode_ready","mode":"native","attached":false,"extensionVersion":"1.0.29","protocolVersion":1,"generation":old["generation"]}),
                &[]
            )
            .is_err());
        assert!(!b.ready);
        assert!(!b.native_qr_mode);
    }
    #[test]
    fn native_mode_revoked_offline_cannot_be_renewed_by_reconnect() {
        let (mut b, _output) = broker();
        b.set_mode(true);
        b.disconnected();
        let (tx, mut output) = tokio::sync::mpsc::unbounded_channel();
        b.connected(tx);
        assert!(b
            .on_message(test_ready("native", false, 60000), &[])
            .is_err());
        assert!(!b.native_qr_mode);
        assert!(b.helper.is_none());
        assert_eq!(output.try_recv().unwrap()["mode"], "proxy");
        assert!(b
            .renew_native_lease(Instant::now() + Duration::from_secs(120))
            .is_none());
    }
    #[test]
    fn native_login_keeps_ceremony_timeout_independent_of_virtual_presence() {
        let (mut b, _) = broker();
        let mut key = key();
        key.presence_timeout_seconds = 1;
        b.on_message(event(1, options()), &[key]).unwrap();
        let id = b.public_requests()[0]["id"].as_str().unwrap().to_owned();
        let request = b.take_request(&id).unwrap();
        assert!(request.deadline.duration_since(Instant::now()).as_secs() >= 119);
        assert!(
            request.candidates[0]
                .deadline
                .duration_since(Instant::now())
                .as_secs()
                <= 1
        );
    }
    #[test]
    fn registration_candidates_show_the_request_account_without_guessing() {
        let (mut b, _) = broker();
        let mut o = options();
        o["rp"] = json!({"id":"example.com", "name":"Example"});
        o["user"] = json!({"id":"AQID", "name":"misaka", "displayName":"御坂"});
        o["pubKeyCredParams"] = json!([{"type":"public-key", "alg":-7}]);
        b.on_message(
            json!({"type":"create", "requestId":77,"requestDetailsJson":o.to_string()}),
            &[key()],
        )
        .unwrap();
        let public = b.public_requests();
        let candidate = &public[0]["candidates"][0];
        assert_eq!(candidate["user_name"], "misaka");
        assert_eq!(candidate["display_name"], "御坂");
        assert!(candidate["credential_id"].is_null());
        assert!(candidate["user_handle"].is_null());
    }
    #[test]
    fn key_revision_tracks_provider_edits_but_not_aaguid_text_representation() {
        let mut original = key();
        original.model_aaguid = "00112233-4455-4677-8899-aabbccddeeff".into();
        let before = key_revision(&original);
        let mut formatted = original.clone();
        formatted.model_aaguid = " 00112233445546778899AABBCCDDEEFF ".into();
        assert_eq!(key_revision(&formatted), before);
        formatted.provider_label = "Changed local display label".into();
        assert_ne!(key_revision(&formatted), before);
        assert_eq!(formatted.credentials, original.credentials);
    }
    #[test]
    fn filters_rp_and_allow_list_and_never_exposes_secrets() {
        let (mut b, _) = broker();
        let mut o = options();
        o["allowCredentials"] = json!([{"type":"public-key","id":"AQI"}]);
        b.on_message(event(1, o), &[key()]).unwrap();
        let public = b.public_requests();
        assert_eq!(public[0]["candidates"].as_array().unwrap().len(), 1);
        assert_eq!(public[0]["candidates"][0]["user_name"], "alice");
        assert!(!serde_json::to_string(&public).unwrap().contains("SECRET"));
    }
    #[test]
    fn multiple_accounts_remain_distinct_and_claim_is_one_use() {
        let (mut b, mut rx) = broker();
        b.on_message(event(1, options()), &[key()]).unwrap();
        let id = b.public_requests()[0]["id"].as_str().unwrap().to_owned();
        let request = b.take_request(&id).unwrap();
        assert_eq!(request.candidates.len(), 2);
        assert!(request.selected_match("key-1", Some("AQI=")));
        assert!(!request.selected_match("key-1", Some("Bwg=")));
        assert!(b.take_request(&id).is_none());
        assert!(b.finish(&request, Err("Wrong PIN".into())));
        assert!(!b.finish(&request, Ok(json!({}))));
        assert_eq!(rx.try_recv().unwrap()["error"]["name"], "NotAllowedError");
        assert!(rx.try_recv().is_err());
    }
    #[test]
    fn cancel_and_reconnect_invalidate_claimed_work() {
        let (mut b, mut rx) = broker();
        b.on_message(event(1, options()), &[key()]).unwrap();
        let id = b.public_requests()[0]["id"].as_str().unwrap().to_owned();
        let r = b.take_request(&id).unwrap();
        b.on_message(json!({"type":"cancel","requestId":1}), &[])
            .unwrap();
        assert!(!b.is_current(&r));
        assert!(!b.finish(&r, Ok(json!({}))));
        assert!(rx.try_recv().is_err());
        b.on_message(event(2, options()), &[key()]).unwrap();
        let id = b.public_requests()[0]["id"].as_str().unwrap().to_owned();
        let r = b.take_request(&id).unwrap();
        b.disconnected();
        assert!(!b.is_current(&r));
        assert!(!b.finish(&r, Ok(json!({}))));
    }
    #[test]
    fn rejects_missing_origin_and_cross_origin() {
        let (mut b, _) = broker();
        let mut o = options();
        o["extensions"] = json!({});
        assert!(b.on_message(event(1, o), &[key()]).is_err());
        let mut o = options();
        o["extensions"]["remoteDesktopClientOverride"]["sameOriginWithAncestors"] = json!(false);
        assert!(b.on_message(event(2, o), &[key()]).is_err());
        assert!(b.public_requests().is_empty());
    }
    #[test]
    fn create_respects_attachment_excludes_and_algorithm() {
        let (mut b, _) = broker();
        let mut o = options();
        o["rp"] = json!({"id":"example.com"});
        o["pubKeyCredParams"] = json!([{"type":"public-key","alg":-7}]);
        o["excludeCredentials"] = json!([{"type":"public-key","id":"AQI"}]);
        let e =
            |o: Value| json!({"type":"create","requestId":1,"requestDetailsJson":o.to_string()});
        b.on_message(e(o.clone()), &[key()]).unwrap();
        assert!(b.public_requests()[0]["candidates"]
            .as_array()
            .unwrap()
            .is_empty());
        b.cancel_all("reset");
        o["excludeCredentials"] = json!([]);
        o["authenticatorSelection"] = json!({"authenticatorAttachment":"platform"});
        b.on_message(e(o.clone()), &[key()]).unwrap();
        assert!(b.public_requests()[0]["candidates"]
            .as_array()
            .unwrap()
            .is_empty());
        b.cancel_all("reset");
        o["pubKeyCredParams"] = json!([{"type":"public-key","alg":-257}]);
        assert!(b.on_message(e(o), &[key()]).is_err());
    }
    #[test]
    fn bounds_pending_and_clamps_timeout_and_expires_claims() {
        let (mut b, mut rx) = broker();
        let mut o = options();
        o["timeout"] = json!(99999999);
        b.on_message(event(0, o), &[key()]).unwrap();
        assert!(b.public_requests()[0]["remaining_ms"].as_u64().unwrap() <= 120000);
        for i in 1..32 {
            b.on_message(event(i, options()), &[key()]).unwrap();
        }
        assert!(b.on_message(event(32, options()), &[key()]).is_err());
        let id = b.public_requests()[0]["id"].as_str().unwrap().to_owned();
        let r = b.take_request(&id).unwrap();
        b.claimed.get_mut(&id).unwrap().deadline = Instant::now();
        b.expire();
        assert!(!b.is_current(&r));
        assert!(rx.try_recv().is_ok());
    }
    #[test]
    fn stream_cursor_resync_lifecycle_and_secret_redaction() {
        let (mut b, mut rx) = broker();
        let initial = b.stream_snapshot(None);
        assert_eq!(initial["resync"], true);
        let cursor = initial["cursor"].as_str().unwrap().to_owned();
        b.on_message(event(1, options()), &[key()]).unwrap();
        let snapshot = b.stream_snapshot(Some(&cursor));
        assert_eq!(snapshot["resync"], false);
        assert_eq!(snapshot["events"][0]["kind"], "pending");
        assert!(!snapshot.to_string().contains("SECRET"));
        assert!(!snapshot.to_string().contains("challenge"));
        let id = snapshot["requests"][0]["id"].as_str().unwrap();
        let request = b.take_request(id).unwrap();
        b.lifecycle(&request, "verifying_password");
        b.lifecycle(&request, "presence_confirmed");
        assert!(b.finish(&request, Ok(json!({"credential":"result"}))));
        assert!(rx.try_recv().is_ok());
        let snapshot = b.stream_snapshot(Some(&cursor));
        assert!(snapshot["requests"].as_array().unwrap().is_empty());
        let kinds: Vec<_> = snapshot["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["kind"].as_str().unwrap())
            .collect();
        assert_eq!(
            kinds,
            [
                "pending",
                "claimed",
                "verifying_password",
                "presence_confirmed",
                "completed"
            ]
        );
        assert_eq!(b.stream_snapshot(Some("foreign:0"))["resync"], true);
        for _ in 0..130 {
            b.event("test", None);
        }
        let reset = b.stream_snapshot(Some(&cursor));
        assert_eq!(reset["resync"], true);
        assert!(reset["events"].as_array().unwrap().is_empty());
        assert_eq!(b.events.len(), 128);
    }
    #[test]
    fn duplicate_disconnect_and_failed_delivery_notify_subscribers() {
        let (mut b, rx) = broker();
        let mut changed = b.subscribe();
        b.on_message(event(1, options()), &[key()]).unwrap();
        changed.borrow_and_update();
        assert!(b.on_message(event(1, options()), &[key()]).is_err());
        assert!(changed.has_changed().unwrap());
        assert!(b.public_requests().is_empty());
        changed.borrow_and_update();
        assert!(b.on_message(json!({"type":"error"}), &[]).is_err());
        assert!(changed.has_changed().unwrap());
        b.on_message(
            crate::browser::broker::tests::test_ready("proxy", true, 0),
            &[],
        )
        .unwrap();
        b.on_message(event(2, options()), &[key()]).unwrap();
        let id = b.public_requests()[0]["id"].as_str().unwrap().to_owned();
        let r = b.take_request(&id).unwrap();
        drop(rx);
        assert!(!b.finish(&r, Ok(json!({}))));
        assert_eq!(b.events.back().unwrap()["kind"], "delivery_failed");
    }
    #[test]
    fn per_key_timeouts_and_resident_capability_are_enforced() {
        let (mut b, _) = broker();
        let mut first = key();
        first.presence_timeout_seconds = 1;
        let mut second = key();
        second.id = "second".into();
        b.on_message(event(1, options()), &[first.clone(), second.clone()])
            .unwrap();
        let id = b.public_requests()[0]["id"].as_str().unwrap().to_owned();
        let r = b.pending.get_mut(&id).unwrap();
        assert!(r.candidates[0].deadline < r.deadline);
        r.candidates[0].deadline = Instant::now();
        assert!(!r.selected_match("key-1", Some("AQI=")));
        b.expire();
        assert_eq!(b.pending[&id].candidates.len(), 3);
        b.cancel_all("reset");
        first.resident_key_supported = false;
        let mut o = options();
        o["rp"] = json!({"id":"example.com"});
        o["pubKeyCredParams"] = json!([{"type":"public-key","alg":-7}]);
        o["authenticatorSelection"] = json!({"residentKey":"required"});
        b.on_message(
            json!({"type":"create","requestId":2,"requestDetailsJson":o.to_string()}),
            &[first, second],
        )
        .unwrap();
        assert_eq!(
            b.public_requests()[0]["candidates"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(b.public_requests()[0]["candidates"][0]["key_id"], "second");
    }
    #[test]
    fn navigation_scope_requires_capability_and_survives_native_readiness() {
        let (mut broker, mut outbound) = broker();
        assert!(outbound.try_recv().is_err());
        let mut ready = test_ready("proxy", true, 0);
        ready["capabilities"]
            .as_array_mut()
            .unwrap()
            .push(json!("local_navigation"));
        broker.on_message(ready.clone(), &[]).unwrap();
        let scope = outbound.try_recv().unwrap();
        assert_eq!(scope["type"], "navigation_scope");
        assert_eq!(scope["mode_generation"], broker.mode_generation);
        broker.on_message(ready, &[]).unwrap();
        assert!(outbound.try_recv().is_err());
        let mut subscriber = broker.subscribe_navigation();
        let message = json!({"type":"local_navigation", "scope":scope["scope"],
            "mode_generation":scope["mode_generation"], "sequence":1,
            "observed_at_ms":super::super::local_navigation::wall_time_ms(),
            "url":"http://127.0.0.1:3333/?private=EXACT-URL"});
        broker.ready = false;
        broker.native_qr_mode = true;
        broker.on_message(message.clone(), &[]).unwrap();
        let notice = subscriber.try_recv().unwrap();
        assert!(broker
            .navigation_frame(&notice, 0)
            .unwrap()
            .contains("EXACT-URL"));
        assert!(!broker
            .stream_snapshot(None)
            .to_string()
            .contains("EXACT-URL"));
        assert!(
            outbound.try_recv().is_err(),
            "never forward URLs back to browser control"
        );
        broker.mode_generation += 1;
        broker.event("mode_switching", None);
        let next = outbound.try_recv().unwrap();
        assert_eq!(next["type"], "navigation_scope");
        assert_ne!(next["scope"], scope["scope"]);
        assert!(broker.navigation_frame(&notice, 0).is_none());
        assert!(broker.on_message(message, &[]).is_err());
        assert!(
            subscriber.try_recv().is_err(),
            "generation changes do not forge explicit clear events"
        );
        broker.disconnected();
        assert!(broker.navigation_frame(&notice, 0).is_none());
    }

    #[test]
    fn closed_control_revokes_queued_navigation_even_without_disconnect_message() {
        let (mut broker, mut outbound) = broker();
        let mut ready = test_ready("proxy", true, 0);
        ready["capabilities"]
            .as_array_mut()
            .unwrap()
            .push(json!("local_navigation"));
        broker.on_message(ready, &[]).unwrap();
        let scope = outbound.try_recv().unwrap();
        let mut subscriber = broker.subscribe_navigation();
        broker
            .on_message(
                json!({"type":"local_navigation", "scope":scope["scope"],
            "mode_generation":scope["mode_generation"], "sequence":1,
            "observed_at_ms":super::super::local_navigation::wall_time_ms(),
            "url":"https://localhost/one"}),
                &[],
            )
            .unwrap();
        let notice = subscriber.try_recv().unwrap();
        drop(outbound);
        assert!(broker.navigation_frame(&notice, 0).is_none());
    }
}
