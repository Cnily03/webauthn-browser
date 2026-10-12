//! Consent-bound BLE and opaque FIDO USB helper, with separate server and UI layers.
//! No credentials are stored; native UI approval gates every paired Origin.
pub mod diagnostics;
pub mod logging;
mod pairing;
mod relay;
mod server;

pub use fido_report_relay;
pub use pairing::authorization::ProcessSession;
pub use pairing::state::{BleState, ConnectionEvent, PendingApproval, Snapshot};
pub use relay::usb as fido_device;
pub use server::{
    launch, launch_desktop, launch_incoming, launch_incoming_with_session, Handle, DEFAULT_PORT,
};

#[cfg(test)]
mod testing;
