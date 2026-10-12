//! Audited Origin and static transport lifecycle messages; standard libraries own all formatting.
use crossterm::style::{Color, ContentStyle, StyledContent};
use std::{
    io::{self, IsTerminal},
    sync::atomic::{AtomicBool, Ordering},
};

// Plain by default, including when an embedder installs a different subscriber.
static COLORS: AtomicBool = AtomicBool::new(false);
pub(crate) fn set_colors(enabled: bool) {
    COLORS.store(enabled, Ordering::Relaxed);
}
/// Compatibility helper for an explicitly installed stderr formatter.
pub fn use_stderr() {
    set_colors(io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none());
}
fn label(text: &'static str, color: Color) -> StyledContent<&'static str> {
    styled(text, color, COLORS.load(Ordering::Relaxed))
}
fn styled(text: &'static str, color: Color, enabled: bool) -> StyledContent<&'static str> {
    let mut style = ContentStyle::default();
    if enabled {
        style.foreground_color = Some(color);
    }
    style.apply(text)
}

pub fn approved(origin: &str, remembered: bool) {
    if !crate::pairing::protocol::valid_origin(origin) {
        return;
    }
    if remembered {
        tracing::info!(
            "{}: {} (remembered process Origin)",
            label("Approved", Color::Green),
            origin
        );
    } else {
        tracing::info!("{}: {}", label("Approved", Color::Green), origin);
    }
}
pub fn rejected(origin: &str) {
    if !crate::pairing::protocol::valid_origin(origin) {
        return;
    }
    tracing::warn!("{}: {}", label("Rejected", Color::Red), origin);
}
pub fn connected(origin: &str) {
    if !crate::pairing::protocol::valid_origin(origin) {
        return;
    }
    tracing::info!("{}: {}", label("Connected", Color::Green), origin);
}
pub fn disconnected(origin: &str, pending: bool) {
    if !crate::pairing::protocol::valid_origin(origin) {
        return;
    }
    if pending {
        tracing::info!(
            "{}: {} (pending request ended)",
            label("Disconnected", Color::Yellow),
            origin
        );
    } else {
        tracing::info!("{}: {}", label("Disconnected", Color::Yellow), origin);
    }
}
pub fn timed_out(origin: &str) {
    if !crate::pairing::protocol::valid_origin(origin) {
        return;
    }
    tracing::warn!("{}: {}", label("Timed out", Color::Yellow), origin);
}

/// A local channel-setting change, independent of whether a scanner is active.
/// The controller emits this once for an actual change, never for duplicate input.
pub fn ble_enabled(enabled: bool) {
    let (word, color) = if enabled {
        ("enabled", Color::Green)
    } else {
        ("disabled", Color::Yellow)
    };
    tracing::info!("BLE: {}", label(word, color));
}

/// These events contain only static transport names/states, never device data.
pub(crate) fn ble(state: crate::BleState) {
    let (word, color) = match state {
        crate::BleState::Starting => ("starting", Color::Cyan),
        crate::BleState::Scanning => ("scanning", Color::Green),
        crate::BleState::Stopping => ("stopping", Color::Yellow),
        crate::BleState::Stopped => ("stopped", Color::Yellow),
        crate::BleState::Unavailable => ("unavailable", Color::Red),
        crate::BleState::CleanupFailed => ("cleanup unconfirmed", Color::Red),
    };
    if matches!(
        state,
        crate::BleState::Unavailable | crate::BleState::CleanupFailed
    ) {
        tracing::warn!("BLE: {}", label(word, color));
    } else {
        tracing::info!("BLE: {}", label(word, color));
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum UsbState {
    Disabled,
    Finding,
    Selecting,
    Waiting,
    Ready,
    Stopping,
    Disconnected,
    Unavailable,
    CleanupFailed,
}
pub(crate) fn usb(state: UsbState) {
    let (word, color) = match state {
        UsbState::Disabled => ("disabled", Color::Yellow),
        UsbState::Finding => ("finding device", Color::Cyan),
        UsbState::Selecting => ("select device", Color::Cyan),
        UsbState::Waiting => ("waiting for browser", Color::Yellow),
        UsbState::Ready => ("ready", Color::Green),
        UsbState::Stopping => ("stopping", Color::Yellow),
        UsbState::Disconnected => ("disconnected", Color::Yellow),
        UsbState::Unavailable => ("unavailable", Color::Red),
        UsbState::CleanupFailed => ("cleanup unconfirmed", Color::Red),
    };
    if matches!(state, UsbState::Unavailable | UsbState::CleanupFailed) {
        tracing::warn!("USB: {}", label(word, color));
    } else {
        tracing::info!("USB: {}", label(word, color));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_words_use_library_color_only_when_enabled() {
        assert_eq!(styled("ready", Color::Green, false).to_string(), "ready");
        let value = styled("ready", Color::Green, true).to_string();
        assert!(value.contains("ready") && value.contains(''));
    }
}
