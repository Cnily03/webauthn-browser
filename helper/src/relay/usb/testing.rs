//! Shared synthetic identities for USB unit tests; never accesses a device.
use super::{wire::Device, Binding};
pub(super) fn device(path: u8) -> Device {
    Device {
        path: vec![path],
        vendor: 1,
        product: 2,
        interface: 0,
        serial: None,
    }
}
pub(super) fn dummy_binding() -> Binding {
    Binding {
        request: "request".into(),
        session: "session".into(),
        origin: "https://fixture.example".into(),
        epoch: 1,
    }
}
