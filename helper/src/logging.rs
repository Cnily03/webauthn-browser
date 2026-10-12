//! Shared standard formatter and helper-only RUST_LOG level/target filtering.
//! Arbitrary dependency logging and untrusted ANSI are never enabled by a filter.
use tracing::{level_filters::LevelFilter, Subscriber};
use tracing_subscriber::{
    filter::{filter_fn, Targets},
    fmt::{self, MakeWriter},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    Layer,
};

const DIAGNOSTICS: &str = "webauthn_helper::diagnostics";
fn targets(spec: Option<&str>) -> Targets {
    spec.filter(|value| !value.trim().is_empty() && value.len() <= 8192)
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| Targets::new().with_default(LevelFilter::INFO))
}
fn in_module(target: &str, root: &str) -> bool {
    target == root
        || target
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with("::"))
}
fn allowed(target: &str, ui_target: &str) -> bool {
    in_module(target, "webauthn_helper") || in_module(target, ui_target)
}
fn subscriber<W>(
    writer: W,
    color: bool,
    spec: Option<&str>,
    ui_target: &'static str,
) -> impl Subscriber + Send + Sync
where
    W: for<'a> MakeWriter<'a> + Clone + Send + Sync + 'static,
{
    let ordinary_targets = targets(spec);
    let lifecycle_targets = ordinary_targets.clone();
    let ordinary = fmt::layer()
        .with_timer(fmt::time::UtcTime::rfc_3339())
        .with_target(false)
        .with_ansi(color)
        .with_ansi_sanitization(true)
        .with_writer(writer.clone())
        .with_filter(filter_fn(move |metadata| {
            metadata.target() != DIAGNOSTICS
                && allowed(metadata.target(), ui_target)
                && ordinary_targets.would_enable(metadata.target(), metadata.level())
        }));
    let lifecycle = fmt::layer()
        .with_timer(fmt::time::UtcTime::rfc_3339())
        .with_target(false)
        .with_ansi(color)
        // Only this exact module emits validated canonical Origins/static words.
        // The trusted crossterm Display output must reach the terminal as ESC,
        // not the default formatter's printable "\\x1b" escape representation.
        .with_ansi_sanitization(false)
        .with_writer(writer)
        .with_filter(filter_fn(move |metadata| {
            metadata.target() == DIAGNOSTICS
                && lifecycle_targets.would_enable(metadata.target(), metadata.level())
        }));
    tracing_subscriber::registry()
        .with(ordinary)
        .with(lifecycle)
}

/// Install the same audited formatter for either UI's chosen output sink.
/// `RUST_LOG` accepts tracing-subscriber's levels and comma-separated target=level
/// directives. It cannot enable dependency targets or disable ANSI sanitization
/// for arbitrary messages. Missing, malformed or oversized settings use INFO.
pub fn install<W>(writer: W, color: bool, ui_target: &'static str) -> anyhow::Result<()>
where
    W: for<'a> MakeWriter<'a> + Clone + Send + Sync + 'static,
{
    let spec = std::env::var("RUST_LOG").ok();
    subscriber(writer, color, spec.as_deref(), ui_target)
        .try_init()
        .map_err(|_| anyhow::anyhow!("Cannot initialize helper logging"))?;
    // A preinstalled subscriber may sanitize values itself. Default plain words
    // remain safe unless our matching formatter was actually installed.
    crate::diagnostics::set_colors(color);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io,
        sync::{Arc, Mutex},
    };
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn render(spec: Option<&str>, color: bool, emit: impl FnOnce()) -> String {
        let captured = Capture::default();
        let writer = captured.clone();
        tracing::subscriber::with_default(
            subscriber(move || writer.clone(), color, spec, "test_ui"),
            emit,
        );
        let bytes = captured.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }
    #[test]
    fn standard_filter_preserves_info_and_exposes_debug_only_when_requested() {
        for (spec, ble, usb) in [
            (None, false, false),
            (Some("debug"), true, true),
            (Some("info,webauthn_helper::relay::ble=debug"), true, false),
            (Some("malformed=not-a-level"), false, false),
        ] {
            let text = render(spec, false, || {
                tracing::info!(target: "webauthn_helper::diagnostics", "Connected: https://example.test");
                tracing::debug!(target: "webauthn_helper::relay::ble", accepted=2, "BLE counters");
                tracing::debug!(target: "webauthn_helper::relay::fido", renewals=3, "USB counters");
            });
            assert_eq!(text.contains("BLE counters"), ble, "{text}");
            assert_eq!(text.contains("USB counters"), usb, "{text}");
            assert_eq!(text.matches("INFO Connected:").count(), 1, "{text}");
            assert!(!text.contains('\u{1b}') && !text.contains("\\x1b"));
        }
    }
    #[test]
    fn environment_directives_cannot_enable_dependency_or_prefix_impostor_logs() {
        let text = render(
            Some("trace,btleplug=trace,hidapi=trace,tungstenite=trace"),
            false,
            || {
                tracing::trace!(target: "btleplug", "NeverLogBluetoothPayload");
                tracing::trace!(target: "hidapi", "NeverLogHidReport");
                tracing::trace!(target: "tungstenite", "NeverLogWireToken");
                tracing::info!(target: "webauthn_helper_impostor", "NeverLogPrefixImpostor");
                tracing::debug!(target: "test_ui::commands", "Local command completed");
            },
        );
        assert!(!text.contains("NeverLog"), "{text}");
        assert!(text.contains("DEBUG Local command completed"), "{text}");
    }
    #[test]
    fn trusted_colored_fields_are_not_escaped_and_ordinary_fields_stay_sanitized() {
        use crossterm::style::{Color, Stylize};
        let text = render(None, true, || {
            tracing::info!(target: "webauthn_helper::diagnostics", "{}: https://example.test", "Connected".with(Color::Green));
            tracing::info!(target: "webauthn_helper::relay::fido", "untrusted {}", "\u{1b}[31mvalue");
        });
        let lifecycle = text
            .lines()
            .find(|line| line.contains("Connected"))
            .unwrap();
        assert!(lifecycle.contains('\u{1b}'), "{lifecycle}");
        assert!(!lifecycle.contains("\\x1b"), "{lifecycle}");
        assert_eq!(text.matches("Connected").count(), 1);
        let ordinary = text
            .lines()
            .find(|line| line.contains("untrusted"))
            .unwrap();
        assert!(ordinary.contains("\\x1b[31mvalue"), "{ordinary}");
        assert!(!ordinary.contains("untrusted \u{1b}[31mvalue"));
    }
}
