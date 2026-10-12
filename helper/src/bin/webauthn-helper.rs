//! Terminal entry point for webauthn-helper.
#[path = "../cli/mod.rs"]
mod cli;

fn main() {
    cli::entry();
}

#[cfg(test)]
mod tests {
    #[test]
    fn macos_bundle_display_name_preserves_executable_and_identifier() {
        let plist = include_str!("../../Info.plist");
        assert!(plist.contains("<key>CFBundleName</key><string>WebAuthn Helper</string>"));
        assert!(plist.contains("<key>CFBundleExecutable</key><string>webauthn-helper</string>"));
        assert!(plist
            .contains("<key>CFBundleIdentifier</key><string>org.webauthnbrowser.helper</string>"));
        assert!(plist.contains("<key>NSBluetoothAlwaysUsageDescription</key><string>Listen for nearby phone passkey Bluetooth advertisements only during an approved WebAuthn Browser pairing with BLE enabled.</string>"));
    }
}
