//! Receive-only hybrid BLE advertisements with bounded operation and cleanup.
use base64::{engine::general_purpose::STANDARD, Engine};
use btleplug::{
    api::{Central, CentralEvent, Manager as _, ScanFilter},
    platform::Manager,
};
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;
pub(crate) const MAX_SERVICE_DATA: usize = 64;
pub(crate) const FFF9: Uuid = Uuid::from_u128(0x0000fff900001000800000805f9b34fb);
pub(crate) const FDE2: Uuid = Uuid::from_u128(0x0000fde200001000800000805f9b34fb);
pub(crate) fn advertisement(uuid: Uuid, data: &[u8]) -> Option<Value> {
    if (uuid == FFF9 || uuid == FDE2) && !data.is_empty() && data.len() <= MAX_SERVICE_DATA {
        Some(json!({"type":"advertisement", "uuid":uuid.to_string(), "data":STANDARD.encode(data)}))
    } else {
        None
    }
}

/// BlueZ matches UUID filters against UUID-list AD fields, not ServiceData AD
/// keys. caBLE may advertise only ServiceData, so Linux must filter locally.
/// Other platforms keep their existing OS service filter.
fn scan_filter() -> ScanFilter {
    platform_scan_filter(cfg!(target_os = "linux"))
}
fn platform_scan_filter(linux: bool) -> ScanFilter {
    if linux {
        ScanFilter::default()
    } else {
        ScanFilter {
            services: vec![FFF9, FDE2],
        }
    }
}

// Deliberately discard peripheral identifiers and never retrieve cached properties.
enum Observation {
    ServiceData(HashMap<Uuid, Vec<u8>>),
    DiscoveryOrUpdate,
    Other,
}
impl From<CentralEvent> for Observation {
    fn from(event: CentralEvent) -> Self {
        match event {
            CentralEvent::ServiceDataAdvertisement { service_data, .. } => {
                Self::ServiceData(service_data)
            }
            CentralEvent::DeviceDiscovered(_) | CentralEvent::DeviceUpdated(_) => {
                Self::DiscoveryOrUpdate
            }
            _ => Self::Other,
        }
    }
}

struct Forwarder {
    events_seen: u64,
    service_data_events: u64,
    discovery_update_notifications: u64,
    budget: u32,
    window: Instant,
    accepted: u64,
    dropped: u64,
}
impl Forwarder {
    fn new(now: Instant) -> Self {
        Self {
            events_seen: 0,
            service_data_events: 0,
            discovery_update_notifications: 0,
            budget: 0,
            window: now,
            accepted: 0,
            dropped: 0,
        }
    }
    fn observe(&mut self, observation: Observation, tx: &mpsc::Sender<Value>, now: Instant) {
        self.events_seen = self.events_seen.saturating_add(1);
        match observation {
            Observation::ServiceData(data) => {
                self.service_data_events = self.service_data_events.saturating_add(1);
                self.service_data(data, tx, now);
            }
            // These include synthetic cached notifications, not fresh proximity.
            Observation::DiscoveryOrUpdate => {
                self.discovery_update_notifications =
                    self.discovery_update_notifications.saturating_add(1);
            }
            Observation::Other => {}
        }
    }
    fn log_totals(&self) {
        tracing::debug!(
            accepted = self.accepted,
            dropped = self.dropped,
            events_seen = self.events_seen,
            service_data_events = self.service_data_events,
            discovery_update_notifications = self.discovery_update_notifications,
            "BLE counters"
        );
    }
    fn service_data(
        &mut self,
        service_data: impl IntoIterator<Item = (Uuid, Vec<u8>)>,
        tx: &mpsc::Sender<Value>,
        now: Instant,
    ) {
        if now.saturating_duration_since(self.window) >= Duration::from_secs(1) {
            self.budget = 0;
            self.window = now;
        }
        for (uuid, data) in service_data {
            // This is the authoritative allowlist on every platform. Broader
            // Linux discovery must never broaden what enters the relay or logs.
            let Some(value) = advertisement(uuid, &data) else {
                continue;
            };
            if self.budget >= 20 || tx.try_send(value).is_err() {
                self.dropped = self.dropped.saturating_add(1);
            } else {
                self.budget += 1;
                self.accepted = self.accepted.saturating_add(1);
            }
        }
    }
}

pub(crate) async fn cancellable<T>(
    commands: &mut watch::Receiver<bool>,
    future: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<Option<T>> {
    if !*commands.borrow() {
        return Ok(None);
    }
    tokio::select! {
        result=tokio::time::timeout(Duration::from_secs(5),future) => Ok(Some(result.map_err(|_|anyhow::anyhow!("Bluetooth operation timed out"))??)),
        _=commands.changed() => Ok(None),
    }
}
pub(crate) async fn scan(
    commands: &mut watch::Receiver<bool>,
    tx: &mpsc::Sender<Value>,
) -> anyhow::Result<()> {
    scan_operation(scan_inner(commands, tx), tx).await
}

async fn scan_operation(
    operation: impl std::future::Future<Output = anyhow::Result<()>>,
    tx: &mpsc::Sender<Value>,
) -> anyhow::Result<()> {
    crate::diagnostics::ble(crate::BleState::Starting);
    let result = operation.await;
    if let Err(error) = &result {
        crate::diagnostics::ble(if format!("{error:#}").contains("OS did not confirm") {
            crate::BleState::CleanupFailed
        } else {
            crate::BleState::Unavailable
        });
    } else {
        // Also covers cancellation during adapter setup, before start_scan.
        crate::diagnostics::ble(crate::BleState::Stopped);
        let _ = tx.try_send(
            json!({"type":"status","state":"stopped","message":"Bluetooth scan stopped."}),
        );
    }
    result
}

async fn scan_inner(
    commands: &mut watch::Receiver<bool>,
    tx: &mpsc::Sender<Value>,
) -> anyhow::Result<()> {
    let Some(manager) = cancellable(commands, async { Ok(Manager::new().await?) }).await? else {
        return Ok(());
    };
    let Some(adapters) = cancellable(commands, async { Ok(manager.adapters().await?) }).await?
    else {
        return Ok(());
    };
    tracing::info!(adapter_count = adapters.len(), "BLE: adapters");
    if adapters.len() > 1 {
        tracing::warn!("BLE: multiple adapters; selecting first");
    }
    let adapter = adapters
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no Bluetooth adapter found"))?;
    tracing::info!(selected_index = 0, "BLE: adapter selected");
    let Some(mut events) = cancellable(commands, async { Ok(adapter.events().await?) }).await?
    else {
        return Ok(());
    };
    tracing::info!("BLE: event stream ready");
    // Always attempt bounded stop_scan after a start attempt, even if start is
    // cancelled or times out. Never abort the worker without cleanup.
    let result=async {
        let Some(())=cancellable(commands,async {Ok(adapter.start_scan(scan_filter()).await?)}).await? else {return Ok(())};
        crate::diagnostics::ble(crate::BleState::Scanning);
        let _=tx.try_send(json!({"type":"status","state":"scanning","message":"Listening for nearby phone passkey advertisements (FFF9/FDE2 only)."}));
        let mut forwarder = Forwarder::new(Instant::now());
        let mut diagnostics=tokio::time::interval(Duration::from_secs(5));
        diagnostics.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        diagnostics.tick().await;
        loop {
            if !*commands.borrow() {break;}
            tokio::select! {
                _=diagnostics.tick()=> {
                    forwarder.log_totals();
                },
                changed=commands.changed() => {if changed.is_err() || !*commands.borrow() {break;}},
                event=events.next() => {
                    let Some(event) = event else { return Err(anyhow::anyhow!("Bluetooth event stream closed")); };
                    forwarder.observe(event.into(), tx, Instant::now());
                }
            }
        }
        forwarder.log_totals();
        crate::diagnostics::ble(crate::BleState::Stopping);
        Ok(())
    }.await;
    let cleanup = tokio::time::timeout(Duration::from_secs(3), adapter.stop_scan()).await;
    match cleanup {
        Ok(Ok(()))=>{},
        _=>return Err(anyhow::anyhow!("OS did not confirm Bluetooth scan stopped; exit the helper and check OS Bluetooth controls")),
    }
    result
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn platform_filter_does_not_hide_service_data_only_advertisements_on_linux() {
        // Exercise both policies even when these tests run on Linux.
        for linux in [true, false] {
            let filter = platform_scan_filter(linux);
            if linux {
                // BlueZ matches a separate UUID-list AD field, absent in this case.
                let advertised_services: Vec<Uuid> = vec![];
                assert!(filter.services.is_empty());
                assert!(
                    filter.services.is_empty()
                        || filter
                            .services
                            .iter()
                            .any(|uuid| advertised_services.contains(uuid))
                );
            } else {
                assert_eq!(filter.services, vec![FFF9, FDE2]);
            }
        }
        assert_eq!(
            scan_filter().services,
            platform_scan_filter(cfg!(target_os = "linux")).services
        );
    }

    #[test]
    fn service_data_only_phone_advertisement_reaches_queue_without_service_list() {
        let now = Instant::now();
        let mut forwarder = Forwarder::new(now);
        let (tx, mut rx) = mpsc::channel(4);
        // There is deliberately no separate advertised-service-list requirement.
        forwarder.service_data([(FFF9, vec![1; 20]), (FDE2, vec![2; 20])], &tx, now);
        assert_eq!(forwarder.accepted, 2);
        assert_eq!(forwarder.dropped, 0);
        assert_eq!(
            rx.try_recv().unwrap(),
            advertisement(FFF9, &[1; 20]).unwrap()
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            advertisement(FDE2, &[2; 20]).unwrap()
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn broad_discovery_still_excludes_other_services_empty_and_oversized_data() {
        let now = Instant::now();
        let mut forwarder = Forwarder::new(now);
        let (tx, mut rx) = mpsc::channel(4);
        forwarder.service_data(
            [
                (Uuid::nil(), vec![9; 20]),
                (FFF9, vec![]),
                (FDE2, vec![7; 65]),
            ],
            &tx,
            now,
        );
        assert_eq!(forwarder.accepted, 0);
        assert_eq!(forwarder.dropped, 0);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn broader_scan_preserves_twenty_per_second_limit_and_bounded_queue() {
        let now = Instant::now();
        let mut forwarder = Forwarder::new(now);
        let (tx, mut rx) = mpsc::channel(32);
        forwarder.service_data((0..21).map(|_| (FFF9, vec![1; 20])), &tx, now);
        assert_eq!(forwarder.accepted, 20);
        assert_eq!(forwarder.dropped, 1);
        forwarder.service_data([(FDE2, vec![2; 20])], &tx, now + Duration::from_secs(1));
        assert_eq!(forwarder.accepted, 21);
        for _ in 0..21 {
            assert!(rx.try_recv().is_ok());
        }
        assert!(rx.try_recv().is_err());

        let (tx, _rx) = mpsc::channel(1);
        let mut full = Forwarder::new(now);
        full.service_data([(FFF9, vec![1]), (FDE2, vec![2])], &tx, now);
        assert_eq!(full.accepted, 1);
        assert_eq!(full.dropped, 1);
    }

    #[test]
    fn cached_discovery_notifications_are_counted_but_never_forwarded() {
        let now = Instant::now();
        let mut forwarder = Forwarder::new(now);
        let (tx, mut rx) = mpsc::channel(4);
        for _ in 0..3 {
            forwarder.observe(Observation::DiscoveryOrUpdate, &tx, now);
        }
        forwarder.observe(Observation::Other, &tx, now);
        assert_eq!(forwarder.events_seen, 4);
        assert_eq!(forwarder.discovery_update_notifications, 3);
        assert_eq!(forwarder.service_data_events, 0);
        assert_eq!(forwarder.accepted, 0);
        assert!(rx.try_recv().is_err());
        forwarder.observe(
            Observation::ServiceData(HashMap::from([(Uuid::nil(), vec![1])])),
            &tx,
            now,
        );
        assert_eq!(forwarder.service_data_events, 1);
        assert_eq!(forwarder.accepted, 0);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn counters_saturate_and_logs_contain_only_aggregate_values() {
        use std::sync::{Arc, Mutex};
        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let now = Instant::now();
        let mut forwarder = Forwarder::new(now);
        let (tx, _rx) = mpsc::channel(4);
        let private_data = b"NeverLogBlePayload".to_vec();
        forwarder.observe(
            Observation::ServiceData(HashMap::from([(FFF9, private_data.clone())])),
            &tx,
            now,
        );
        forwarder.events_seen = u64::MAX;
        forwarder.discovery_update_notifications = u64::MAX;
        forwarder.observe(Observation::DiscoveryOrUpdate, &tx, now);
        assert_eq!(forwarder.events_seen, u64::MAX);
        assert_eq!(forwarder.discovery_update_notifications, u64::MAX);
        let captured = Capture(Arc::default());
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_target(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || forwarder.log_totals());
        let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        for expected in [
            "accepted=1",
            "dropped=0",
            "service_data_events=1",
            "discovery_update_notifications=",
            "BLE counters",
        ] {
            assert!(text.contains(expected), "{text}");
        }
        assert!(!text.contains("NeverLogBlePayload"));
        assert!(!text.contains(&STANDARD.encode(private_data)));
        assert!(!text.contains(&FFF9.to_string()));
    }

    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };
    use tokio::sync::watch;

    use uuid::Uuid;
    #[test]
    fn bounds_and_whitelist() {
        assert!(advertisement(FFF9, &[1; 20]).is_some());
        assert!(advertisement(FDE2, &[2; 20]).is_some());
        assert!(advertisement(Uuid::nil(), &[1; 20]).is_none());
        assert!(advertisement(FFF9, &[]).is_none());
        assert!(advertisement(FFF9, &[1; 65]).is_none());
    }

    #[tokio::test]
    async fn cancelled_ble_setup_does_not_wait_for_os() {
        let (tx, mut rx) = watch::channel(true);
        let task =
            tokio::spawn(async move { cancellable::<()>(&mut rx, std::future::pending()).await });
        tx.send(false).unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(100), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn cancellation_during_pending_adapter_setup_reports_stopped() {
        let (control, mut receiver) = watch::channel(true);
        let (tx, mut rx) = mpsc::channel(2);
        let scan = scan_operation(
            async {
                let _ = cancellable(&mut receiver, std::future::pending::<anyhow::Result<()>>())
                    .await?;
                Ok(())
            },
            &tx,
        );
        tokio::pin!(scan);
        tokio::select! { result=&mut scan=>panic!("pending startup ended: {result:?}"), _=tokio::time::sleep(Duration::from_millis(5))=>{} }
        control.send_replace(false);
        scan.await.unwrap();
        assert_eq!(rx.try_recv().unwrap()["state"], "stopped");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn actual_ble_counters_are_debug_while_scan_transitions_remain_info() {
        #[derive(Clone, Default)]
        struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = Capture::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            Forwarder::new(Instant::now()).log_totals();
            crate::diagnostics::ble(crate::BleState::Scanning);
        });
        let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(!text.contains("BLE counters"), "{text}");
        assert!(
            text.contains("INFO") && text.contains("BLE: scanning"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn cancelled_ble_scan_logs_request_without_polling_any_adapter_operation() {
        use tracing::instrument::WithSubscriber;
        #[derive(Clone)]
        struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = Capture(Arc::default());
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339())
            .with_ansi(false)
            .with_target(false)
            .with_writer(move || writer.clone())
            .finish();
        let (_control, mut receiver) = watch::channel(false);
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        scan(&mut receiver, &tx)
            .with_subscriber(subscriber)
            .await
            .unwrap();
        assert_eq!(rx.try_recv().unwrap()["state"], "stopped");
        let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("INFO BLE: starting"), "{text}");
        assert!(!text.contains("ready"));
        assert!(!text.contains("started"));
        assert!(!text.contains("failed"));
        // The false control is checked before constructing/polling any OS work.
        let mut polled = false;
        let _ = cancellable(&mut receiver, async {
            polled = true;
            Ok(())
        })
        .await
        .unwrap();
        assert!(!polled);
    }
}
