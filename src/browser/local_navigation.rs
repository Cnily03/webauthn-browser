//! Short-lived navigation notifications. URLs never enter snapshots, journals,
//! logs, outbound browser commands, or any network client.
use serde_json::{json, Value};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use uuid::Uuid;

pub(super) const MAX_URL_BYTES: usize = 8192;
const MAX_AGE_MS: u64 = 5000;
const QUEUE_CAPACITY: usize = 16;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const INVALID: &str = "Invalid local navigation notification";

pub(super) fn wall_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

// Validate the literal authority before URL parsing: WHATWG normalization would
// otherwise turn 127.1, decimal/hex addresses, escaped hosts, or backslashes into
// apparently permitted loopback hosts. Keep the original bytes for forwarding.
fn valid_url(raw: &str) -> bool {
    if raw.len() > MAX_URL_BYTES
        || raw
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b'\\')
    {
        return false;
    }
    let Some((scheme, rest)) = raw.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if !host.eq_ignore_ascii_case("localhost") && host != "127.0.0.1" {
        return false;
    }
    if port.is_some_and(|p| {
        p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u16>().is_err()
    }) {
        return false;
    }
    reqwest::Url::parse(raw).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
            && url.username().is_empty()
            && url.password().is_none()
    })
}

struct Scope {
    token: String,
    generation: u64,
    sequence: u64,
}

// The broadcast queue contains metadata only, never URL copies. Only frame()
// can resolve a current ID to the pending URL after the SSE handler checks its
// viewer's current session and CSRF authorization.
#[derive(Clone)]
pub(super) struct Notification {
    scope: String,
    generation: u64,
    sequence: u64,
    observed_at_ms: u64,
    deadline: Instant,
    id: Option<String>,
}

pub(super) struct LocalNavigation {
    scope: Option<Scope>,
    tx: broadcast::Sender<Notification>,
    // Public broker identity and a never-reset counter let viewers retain a
    // bounded replay high-water mark without exposing the private scope token.
    stream_id: String,
    counter: u64,
    // Exactly one pending URL, resolved only for existing live subscribers.
    // Expiry drops it silently; it must not dismiss a previously delivered toast.
    target: Option<(String, String)>,
    expiry: Option<(u64, Instant)>,
}
impl LocalNavigation {
    pub(super) fn new(stream_id: String) -> Self {
        let (tx, _) = broadcast::channel(QUEUE_CAPACITY);
        Self {
            scope: None,
            tx,
            stream_id,
            counter: 0,
            target: None,
            expiry: None,
        }
    }
    pub(super) fn subscribe(&self) -> broadcast::Receiver<Notification> {
        // broadcast subscriptions start at the tail; there is no replay/snapshot.
        self.tx.subscribe()
    }

    pub(super) fn revoke(&mut self) {
        self.scope = None;
        self.target = None;
        self.expiry = None;
    }

    pub(super) fn sync_scope(&mut self, available: bool, generation: u64) -> Option<Value> {
        if !available {
            self.revoke();
            return None;
        }
        if self
            .scope
            .as_ref()
            .is_some_and(|s| s.generation == generation)
        {
            return None;
        }
        let token = Uuid::new_v4().to_string();
        self.target = None;
        self.expiry = None;
        self.scope = Some(Scope {
            token: token.clone(),
            generation,
            sequence: 0,
        });
        Some(json!({"type":"navigation_scope", "scope":token, "mode_generation":generation}))
    }

    pub(super) fn accept(&mut self, value: &Value) -> Result<(), String> {
        // Capture monotonic time first: scheduler delay between the two clock
        // reads must shorten the remaining lifetime, never extend it.
        let now = Instant::now();
        self.accept_at(value, wall_time_ms(), now)
    }

    fn accept_at(&mut self, value: &Value, now_ms: u64, now: Instant) -> Result<(), String> {
        let scope = self.scope.as_mut().ok_or(INVALID)?;
        let sequence = value["sequence"].as_u64().ok_or(INVALID)?;
        if value["scope"].as_str() != Some(&scope.token)
            || value["mode_generation"].as_u64() != Some(scope.generation)
            || !(1..=MAX_SAFE_INTEGER).contains(&sequence)
            || sequence <= scope.sequence
        {
            return Err(INVALID.into());
        }
        // Consume the sequence even for an expired/malformed observation. No
        // earlier queued notice can reappear after a newer navigation arrived.
        scope.sequence = sequence;
        self.target = None;
        self.expiry = None;
        let observed_at_ms = value["observed_at_ms"].as_u64().ok_or(INVALID)?;
        let age = now_ms.checked_sub(observed_at_ms).ok_or(INVALID)?;
        let remaining = MAX_AGE_MS
            .checked_sub(age)
            .filter(|v| *v > 0)
            .ok_or(INVALID)?;
        let target = match value["type"].as_str() {
            Some("local_navigation") => {
                let raw = value["url"]
                    .as_str()
                    .filter(|raw| valid_url(raw))
                    .ok_or(INVALID)?;
                self.counter = self.counter.checked_add(1).ok_or(INVALID)?;
                Some((
                    format!("{}:{}", self.stream_id, self.counter),
                    raw.to_owned(),
                ))
            }
            Some("local_navigation_clear") if value.get("url").is_none() => None,
            _ => return Err(INVALID.into()),
        };
        let deadline = now + Duration::from_millis(remaining);
        self.expiry = target.as_ref().map(|_| (sequence, deadline));
        let notification = Notification {
            scope: scope.token.clone(),
            generation: scope.generation,
            sequence,
            observed_at_ms,
            deadline,
            id: target.as_ref().map(|(id, _)| id.clone()),
        };
        self.target = target;
        // No receivers means drop immediately, not retain a pending notification.
        if self.tx.send(notification).is_err() {
            self.target = None;
            self.expiry = None;
        }
        Ok(())
    }

    pub(super) fn expire(&mut self) {
        self.expire_at(Instant::now());
    }

    fn expire_at(&mut self, now: Instant) {
        let Some((sequence, deadline)) = self.expiry else {
            return;
        };
        if deadline > now {
            return;
        }
        self.expiry = None;
        if self
            .scope
            .as_ref()
            .is_some_and(|scope| scope.sequence == sequence)
        {
            self.target = None;
        }
        // Delivery freshness and visible-toast lifetime are separate. A timeout
        // emits no clear, so it cannot shorten or interrupt an already visible
        // toast's five-second receipt budget or its hover/focus pause.
    }

    pub(super) fn frame(&self, notice: &Notification, subscribed_at_ms: u64) -> Option<String> {
        self.frame_at(notice, subscribed_at_ms, Instant::now())
    }

    fn frame_at(
        &self,
        notice: &Notification,
        subscribed_at_ms: u64,
        now: Instant,
    ) -> Option<String> {
        let scope = self.scope.as_ref()?;
        let remaining = notice.deadline.saturating_duration_since(now).as_millis() as u64;
        if notice.scope != scope.token
            || notice.generation != scope.generation
            || notice.sequence != scope.sequence
            || notice.observed_at_ms < subscribed_at_ms
            || !(1..=MAX_AGE_MS).contains(&remaining)
        {
            return None;
        }
        let (kind, payload) = match &notice.id {
            Some(id) => {
                let (_, url) = self.target.as_ref().filter(|(current, _)| current == id)?;
                (
                    "local_navigation",
                    // remaining_ms is the server delivery budget, not the
                    // lifetime of the toast after a viewer receives this frame.
                    json!({
                        "id":id,"url":url,"remaining_ms":remaining,"mode_generation":notice.generation
                    }),
                )
            }
            None => (
                "local_navigation_clear",
                json!({"mode_generation":notice.generation}),
            ),
        };
        // No SSE id: Last-Event-ID is solely the existing approval-snapshot cursor.
        Some(format!("event: {kind}\ndata: {payload}\n\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (LocalNavigation, Value, Instant) {
        let mut state = LocalNavigation::new(Uuid::new_v4().to_string());
        let scope = state.sync_scope(true, 7).unwrap();
        let message = json!({
            "type":"local_navigation", "scope":scope["scope"], "mode_generation":7,
            "sequence":1, "observed_at_ms":10_000,
            "url":"http://localhost:3000/callback?code=FORWARD-ONLY%2f&state=ONE+TWO#frag"
        });
        (state, message, Instant::now())
    }

    #[test]
    fn exact_loopback_authority_without_normalization_aliases() {
        for url in [
            "http://localhost",
            "https://LOCALHOST:443/cb?q=%2F%2f+#x",
            "http://127.0.0.1:0/",
            "HTTP://localhost:65535/path",
            "https://localhost/é",
        ] {
            assert!(valid_url(url), "allowed literal rejected");
        }
        for url in [
            "ftp://localhost/",
            "http:localhost/",
            "//localhost/",
            " http://localhost/",
            "http://localhost /",
            "http://localhost\n/",
            "http://localhost\\evil/",
            "http://localhost./",
            "http://localhost.evil/",
            "http://evil.localhost/",
            "http://user@localhost/",
            "http://localhost@evil/",
            "http://localhost:pw@localhost/",
            "http://localhost:/",
            "http://localhost:65536/",
            "http://localhost:-1/",
            "http://localhost:+80/",
            "http://localhost:80:90/",
            "http://%6cocalhost/",
            "http://127.1/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://127.0.0.01/",
            "http://127.0.0.2/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://localһost/",
            "http://localhost\u{3002}/",
        ] {
            assert!(!valid_url(url), "nonliteral authority accepted");
        }
        let prefix = "http://localhost/";
        assert!(valid_url(&format!(
            "{prefix}{}",
            "x".repeat(MAX_URL_BYTES - prefix.len())
        )));
        assert!(!valid_url(&format!(
            "{prefix}{}",
            "x".repeat(MAX_URL_BYTES - prefix.len() + 1)
        )));
        assert!(!valid_url(&format!(
            "{prefix}{}",
            "é".repeat(MAX_URL_BYTES / 2)
        )));
    }

    #[test]
    fn forwards_exact_payload_only_until_monotonic_deadline() {
        let (mut state, message, now) = setup();
        let mut receiver = state.subscribe();
        state.accept_at(&message, 11_000, now).unwrap();
        let notice = receiver.try_recv().unwrap();
        let frame = state.frame_at(&notice, 10_000, now).unwrap();
        assert!(!frame.contains("id: "));
        let value: Value = serde_json::from_str(
            frame
                .lines()
                .nth(1)
                .unwrap()
                .strip_prefix("data: ")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(value["url"], message["url"]);
        assert_eq!(value["remaining_ms"], 4000);
        assert_eq!(value["mode_generation"], 7);
        let (instance, counter) = value["id"].as_str().unwrap().rsplit_once(':').unwrap();
        assert!(Uuid::parse_str(instance).is_ok());
        assert_eq!(counter, "1");
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert!(state.frame_at(&notice, 10_001, now).is_none());
        assert!(state
            .frame_at(&notice, 0, now + Duration::from_millis(4000))
            .is_none());
        assert!(state
            .frame_at(&notice, 0, now + Duration::from_secs(8))
            .is_none());
    }

    #[test]
    fn no_cold_subscription_snapshot_replay_or_queue_without_receivers() {
        let (mut state, message, now) = setup();
        state.accept_at(&message, 10_000, now).unwrap();
        let mut receiver = state.subscribe();
        assert!(matches!(
            receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
        assert!(state.sync_scope(true, 7).is_none());
        assert_eq!(state.accept_at(&message, 10_000, now).unwrap_err(), INVALID);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn scope_generation_sequence_and_freshness_reject_replays_without_urls_in_errors() {
        for (field, invalid) in [
            ("scope", json!("old-scope")),
            ("mode_generation", json!(6)),
            ("sequence", json!(0)),
            ("sequence", json!(-1)),
            ("sequence", json!(1.5)),
            ("sequence", json!(MAX_SAFE_INTEGER + 1)),
            ("observed_at_ms", json!(10_001)),
            ("observed_at_ms", json!(5_000)),
            ("observed_at_ms", json!(0)),
            ("url", json!("http://evil/callback?secret=NO-LOG")),
        ] {
            let (mut state, mut message, now) = setup();
            let mut receiver = state.subscribe();
            message[field] = invalid;
            assert_eq!(state.accept_at(&message, 10_000, now).unwrap_err(), INVALID);
            assert!(receiver.try_recv().is_err());
        }
        let (mut state, message, now) = setup();
        let mut receiver = state.subscribe();
        state.accept_at(&message, 10_000, now).unwrap();
        let old = receiver.try_recv().unwrap();
        assert!(state.accept_at(&message, 10_000, now).is_err());
        state.sync_scope(true, 8).unwrap();
        assert!(state.frame_at(&old, 0, now).is_none());
        assert!(state.accept_at(&message, 10_000, now).is_err());
        state.revoke();
        assert!(state.accept_at(&message, 10_000, now).is_err());
        let new = state.sync_scope(true, 7).unwrap();
        assert_ne!(new["scope"], message["scope"]);
        assert!(state.accept_at(&message, 10_000, now).is_err());
    }

    #[test]
    fn newer_navigation_clear_and_even_expired_messages_invalidate_old_pending_urls() {
        let (mut state, mut message, now) = setup();
        let mut receiver = state.subscribe();
        state.accept_at(&message, 10_000, now).unwrap();
        let first = receiver.try_recv().unwrap();
        message["sequence"] = json!(2);
        message["url"] = json!("https://127.0.0.1/next");
        state.accept_at(&message, 10_000, now).unwrap();
        let second = receiver.try_recv().unwrap();
        assert!(state.frame_at(&first, 0, now).is_none());
        assert!(state.frame_at(&second, 0, now).is_some());
        message["sequence"] = json!(3);
        message["type"] = json!("local_navigation_clear");
        message.as_object_mut().unwrap().remove("url");
        state.accept_at(&message, 10_000, now).unwrap();
        let clear = receiver.try_recv().unwrap();
        assert!(state.frame_at(&second, 0, now).is_none());
        assert_eq!(
            state.frame_at(&clear, 0, now).unwrap(),
            "event: local_navigation_clear\ndata: {\"mode_generation\":7}\n\n"
        );
        message["sequence"] = json!(4);
        message["observed_at_ms"] = json!(0);
        assert!(state.accept_at(&message, 10_000, now).is_err());
        assert!(state.frame_at(&clear, 0, now).is_none());
    }

    #[test]
    fn bounded_broadcast_exposes_lag_without_payload_and_resubscription_discards_burst() {
        let (mut state, mut message, now) = setup();
        let mut receiver = state.subscribe();
        for sequence in 1..=QUEUE_CAPACITY + 1 {
            message["sequence"] = json!(sequence);
            state.accept_at(&message, 10_000, now).unwrap();
        }
        assert!(matches!(
            receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(1))
        ));
        receiver = receiver.resubscribe();
        assert!(matches!(
            receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }
    #[test]
    fn public_ids_increase_across_scope_changes_without_exposing_scope_and_never_wrap() {
        let (mut state, mut message, now) = setup();
        let mut receiver = state.subscribe();
        for generation in 7..=9 {
            if generation != 7 {
                state.revoke();
                let scope = state.sync_scope(true, generation).unwrap();
                message["scope"] = scope["scope"].clone();
                message["mode_generation"] = json!(generation);
            }
            state.accept_at(&message, 10_000, now).unwrap();
            let notice = receiver.try_recv().unwrap();
            let frame = state.frame_at(&notice, 0, now).unwrap();
            assert!(frame.contains(&format!("{}:{}", state.stream_id, generation - 6)));
            assert!(!frame.contains(message["scope"].as_str().unwrap()));
        }
        state.counter = u64::MAX;
        message["sequence"] = json!(2);
        assert_eq!(state.accept_at(&message, 10_000, now).unwrap_err(), INVALID);
        assert!(receiver.try_recv().is_err());
    }
    #[test]
    fn expiration_silently_drops_url_without_dismissing_delivery_or_resetting_ingress_sequence() {
        let (mut state, message, now) = setup();
        let mut fast = state.subscribe();
        let mut slow = state.subscribe();
        state.accept_at(&message, 10_000, now).unwrap();
        let delivered = fast.try_recv().unwrap();
        assert!(state
            .frame_at(&delivered, 0, now)
            .unwrap()
            .contains("FORWARD-ONLY"));
        state.expire_at(now + Duration::from_millis(4999));
        assert!(state.target.is_some());
        assert!(fast.try_recv().is_err());
        state.expire_at(now + Duration::from_secs(5));
        assert!(state.target.is_none());
        assert!(state.expiry.is_none());
        let queued_metadata = slow.try_recv().unwrap();
        assert!(queued_metadata.id.is_some());
        assert!(state
            .frame_at(&queued_metadata, 0, now + Duration::from_secs(5))
            .is_none());
        assert!(
            fast.try_recv().is_err(),
            "expiry cannot dismiss an already received toast"
        );
        assert!(
            slow.try_recv().is_err(),
            "expiry cannot add a clear after queued metadata"
        );
        state.expire_at(now + Duration::from_secs(600));
        assert!(fast.try_recv().is_err());
        assert_eq!(state.counter, 1);
        assert!(state
            .accept_at(&message, 15_000, now + Duration::from_secs(5))
            .is_err());
        assert_eq!(state.scope.as_ref().unwrap().sequence, 1);
        // A toast may remain hovered for minutes. A fresh explicit navigation
        // clear still works after its original URL was dropped from the server.
        let mut clear = message;
        clear["type"] = json!("local_navigation_clear");
        clear["sequence"] = json!(2);
        clear["observed_at_ms"] = json!(610_000);
        clear.as_object_mut().unwrap().remove("url");
        state
            .accept_at(&clear, 610_000, now + Duration::from_secs(600))
            .unwrap();
        let notice = fast.try_recv().unwrap();
        assert!(state
            .frame_at(&notice, 0, now + Duration::from_secs(600))
            .unwrap()
            .starts_with("event: local_navigation_clear\n"));
        assert!(state.target.is_none());
        assert_eq!(state.counter, 1);
    }

    #[test]
    fn superseded_expiry_preserves_replacement_and_explicit_clear_and_scope_reset_drop_target() {
        let (mut state, mut message, now) = setup();
        let mut receiver = state.subscribe();
        state.accept_at(&message, 10_000, now).unwrap();
        let old = receiver.try_recv().unwrap();
        message["sequence"] = json!(2);
        message["observed_at_ms"] = json!(11_000);
        message["url"] = json!("https://127.0.0.1/replacement");
        state
            .accept_at(&message, 11_000, now + Duration::from_secs(1))
            .unwrap();
        let replacement = receiver.try_recv().unwrap();
        state.expire_at(now + Duration::from_secs(5));
        assert!(receiver.try_recv().is_err());
        assert!(state
            .frame_at(&old, 0, now + Duration::from_secs(5))
            .is_none());
        assert!(state
            .frame_at(&replacement, 0, now + Duration::from_secs(5))
            .unwrap()
            .contains("https://127.0.0.1/replacement"));
        state.expire_at(now + Duration::from_secs(6));
        assert!(receiver.try_recv().is_err());
        assert!(state.target.is_none());
        message["sequence"] = json!(3);
        message["observed_at_ms"] = json!(16_000);
        state
            .accept_at(&message, 16_000, now + Duration::from_secs(6))
            .unwrap();
        receiver.try_recv().unwrap();
        message["sequence"] = json!(4);
        message["type"] = json!("local_navigation_clear");
        message.as_object_mut().unwrap().remove("url");
        state
            .accept_at(&message, 16_000, now + Duration::from_secs(6))
            .unwrap();
        let clear = receiver.try_recv().unwrap();
        assert!(state.target.is_none());
        assert!(state
            .frame_at(&clear, 0, now + Duration::from_secs(6))
            .unwrap()
            .starts_with("event: local_navigation_clear\n"));
        state.expire_at(now + Duration::from_secs(11));
        assert!(receiver.try_recv().is_err());
        message["sequence"] = json!(5);
        message["type"] = json!("local_navigation");
        message["url"] = json!("http://localhost/replacement");
        message["observed_at_ms"] = json!(21_000);
        state
            .accept_at(&message, 21_000, now + Duration::from_secs(11))
            .unwrap();
        receiver.try_recv().unwrap();
        state.sync_scope(true, 8).unwrap();
        assert!(state.target.is_none());
        state.expire_at(now + Duration::from_secs(16));
        assert!(receiver.try_recv().is_err());
    }
}
