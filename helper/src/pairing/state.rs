//! Shared in-memory listener, pairing, and display state.

use crate::pairing::authorization::ProcessSession;
use std::{sync::Arc, time::Instant};
use tokio::sync::{watch, Mutex};
#[derive(Clone)]
pub(crate) struct App {
    pub(crate) secret: String,
    pub(crate) port: u16,
    pub(crate) session: ProcessSession,
    pub(crate) incoming_pairing: bool,
    pub(crate) connection_slot: Arc<tokio::sync::Semaphore>,
    pub(crate) inner: Arc<Mutex<Inner>>,
}
pub(crate) struct Inner {
    pub(crate) stopping: bool,
    // Changes invalidate in-flight work; cleanup still checks the saved socket owner.
    pub(crate) epoch: u64,
    pub(crate) cleanup_failed: bool,
    pub(crate) pairing: Option<Pairing>,
    pub(crate) pending: Option<PendingPairing>,
    pub(crate) fido: Option<crate::relay::fido::Attachment>,
    pub(crate) connected: bool,
    // Retained through revocation until the owning socket finishes cleanup.
    pub(crate) connection_owner: Option<(String, u64)>,
    // At most 4096 successful pairs per process (the consumed-token limit).
    // Queue events so short connections cannot disappear between UI polls.
    pub(crate) connection_events: Vec<ConnectionEvent>,
    pub(crate) ble_enabled: bool,
    pub(crate) scan: Option<watch::Sender<bool>>,
    pub(crate) ble_state: BleState,
    pub(crate) status: String,
    pub(crate) count: u64,
}
impl Inner {
    pub(crate) fn connection_owned_by(&self, request_id: &str, epoch: u64) -> bool {
        self.connection_owner
            .as_ref()
            .is_some_and(|(id, owner_epoch)| id == request_id && *owner_epoch == epoch)
    }
}
pub(crate) struct PendingPairing {
    pub(crate) id: String,
    pub(crate) origin: String,
    pub(crate) expires: Instant,
    pub(crate) approved: bool,
}
pub(crate) struct Pairing {
    pub(crate) explicit_approval: bool,
    pub(crate) request_id: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) origin: String,
    pub(crate) token: Option<String>,
    pub(crate) expires: Instant,
}
/// BLE lifecycle state, including pending transitions and confirmed OS outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BleState {
    Stopped,
    Starting,
    Scanning,
    Stopping,
    Unavailable,
    CleanupFailed,
}

/// A pending origin confirmation; never includes the one-use token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingApproval {
    pub id: String,
    pub origin: String,
    pub expires_in: u64,
}

/// One successfully authorized browser connection. No token or BLE data is included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionEvent {
    pub connection_id: String,
    pub origin: String,
    pub connected_at: std::time::SystemTime,
}

/// A read-only snapshot. Pairing tokens and local capabilities are never exposed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub port: u16,
    /// Locally withheld exact Origins; contains no tokens or reports.
    pub withheld_origins: Vec<String>,
    pub withholding_saturated: bool,
    pub needs_restart: bool,
    pub status: String,
    pub connected: bool,
    /// Public request identifier for a paired connection, never an authorization token.
    pub connection_id: Option<String>,
    pub scanning: bool,
    pub ble_state: BleState,
    pub advertisements: u64,
    pub origin: Option<String>,
    pub expires_in: Option<u64>,
    pub pending_approval: Option<PendingApproval>,
}
