//! Native desktop entry point for webauthn-helper-desktop.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
#[path = "../desktop/mod.rs"]
mod desktop;

fn main() -> eframe::Result {
    if webauthn_helper::fido_device::worker_entry() {
        return Ok(());
    }
    desktop::run()
}

#[cfg(test)]
mod tests {
    #[test]
    fn macos_bundle_display_name_preserves_executable_and_identifier() {
        let plist = include_str!("../../Info-desktop.plist");
        assert!(plist.contains("<key>CFBundleName</key><string>WebAuthn Helper Desktop</string>"));
        assert!(
            plist.contains("<key>CFBundleExecutable</key><string>webauthn-helper-desktop</string>")
        );
        assert!(plist.contains(
            "<key>CFBundleIdentifier</key><string>org.webauthnbrowser.helper.desktop</string>"
        ));
        assert!(plist.contains("<key>NSBluetoothAlwaysUsageDescription</key><string>Listen for nearby phone passkey Bluetooth advertisements only during an approved WebAuthn Browser pairing with BLE enabled.</string>"));
    }
}
