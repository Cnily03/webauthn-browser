//! Actual logger initialization with synthetic events only, never a device or runtime.
//! The completion-marker handshake drains the CLI queue without changing its guard.
#[path = "../../src/desktop/logging.rs"]
mod desktop_logging;
#[allow(dead_code)]
#[path = "../../src/cli/logging.rs"]
mod logging;
#[allow(dead_code)]
#[path = "../../src/cli/terminal_ui.rs"]
mod terminal_ui;

use std::io::{self, Write};
use tracing_subscriber::util::SubscriberInitExt;

const COMPLETE: &str = "LOGGER_FIXTURE_DRAINED\n";

fn main() -> anyhow::Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "--fixture-identify" {
        println!("webauthn-helper fake logging fixture v1");
        return Ok(());
    }
    let _guard = match mode.as_str() {
        "cli" => Some(logging::init()?),
        "desktop" => {
            desktop_logging::init();
            None
        }
        "desktop-preinstalled" => {
            // Simulate an embedder's ordinary, sanitizing subscriber. Desktop
            // must preserve it and must not enable styled message arguments.
            tracing_subscriber::fmt()
                .with_target(false)
                .with_ansi(false)
                .with_writer(io::stderr)
                .finish()
                .try_init()
                .map_err(|error| {
                    anyhow::anyhow!("Cannot initialize fixture subscriber: {error}")
                })?;
            desktop_logging::init();
            None
        }
        _ => anyhow::bail!("Expected cli, desktop or desktop-preinstalled fixture mode"),
    };

    webauthn_helper::diagnostics::connected("https://logging-fixture.example");
    webauthn_helper::diagnostics::approved("https://logging-fixture.example", false);
    webauthn_helper::diagnostics::ble_enabled(false);
    webauthn_helper::diagnostics::ble_enabled(true);
    // Invalid Origins must never enter the trusted, unsanitized lifecycle layer.
    webauthn_helper::diagnostics::connected("https://invalid-fixture.example\x1b[2J");

    if mode == "desktop-preinstalled" {
        tracing::info!(target: "embedder", "Preinstalled subscriber preserved");
    } else {
        tracing::info!(target: "webauthn_helper::relay::ble", "BLE fixture transition");
        tracing::info!(target: "webauthn_helper::relay::fido", "USB fixture transition");
        tracing::debug!(target: "webauthn_helper::relay::ble", accepted = 7, dropped = 2, "BLE fixture counters");
        tracing::debug!(target: "webauthn_helper::relay::fido", browser_reports = 3, device_reports_sent = 3, "USB fixture counters");
        tracing::info!(target: "webauthn_helper::relay::fido", "ordinary fixture injection {}", "\x1b[31muntrusted\x1b[0m");

        // Deliberately synthetic targets, not calls into these dependencies.
        tracing::trace!(target: "btleplug", "FORBIDDEN_DEPENDENCY_BTLEPLUG");
        tracing::trace!(target: "hidapi", "FORBIDDEN_DEPENDENCY_HIDAPI");
        tracing::trace!(target: "tungstenite", "FORBIDDEN_DEPENDENCY_WEBSOCKET");
        tracing::error!(target: "btleplug", "FORBIDDEN_DEPENDENCY_ERROR");
        tracing::info!(target: "webauthn_helper_untrusted", "FORBIDDEN_LOOKALIKE_TARGET");
    }

    if mode == "cli" {
        // FIFO with all preceding records; the parent acknowledges only once read.
        logging::write_text(COMPLETE)?;
    } else {
        // Desktop's real stderr writer is synchronous.
        io::stderr().write_all(COMPLETE.as_bytes())?;
        io::stderr().flush()?;
    }
    let mut acknowledgment = String::new();
    io::stdin().read_line(&mut acknowledgment)?;
    anyhow::ensure!(
        acknowledgment == "done\n",
        "Missing output-drain acknowledgment"
    );
    Ok(())
}
