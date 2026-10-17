//! Strict startup-output contract shared by captured and streaming CLI tests.
use std::net::SocketAddr;

#[derive(Default)]
pub struct StartupOutput {
    pub listener: Option<SocketAddr>,
    usb_unavailable: bool,
}
impl StartupOutput {
    pub fn observe(&mut self, line: &str, physical_usb_supported: bool) -> Result<(), String> {
        if line.contains('\x1b') {
            return Err(format!("Unexpected ANSI in piped startup output: {line:?}"));
        }
        if let Some((_, address)) = line.split_once(" INFO Listening: ws://") {
            let address: SocketAddr = address
                .parse()
                .map_err(|_| format!("Invalid listener address: {line:?}"))?;
            if address.ip() != std::net::Ipv4Addr::LOCALHOST || address.port() == 0 {
                return Err(format!("Invalid listener address: {line:?}"));
            }
            if self.listener.replace(address).is_some() {
                return Err(format!("Duplicate listener announcement: {line:?}"));
            }
            return Ok(());
        }
        if !physical_usb_supported
            && line
                .split_once(" WARN ")
                .is_some_and(|(_, message)| message == "USB: unavailable")
            && !self.usb_unavailable
        {
            self.usb_unavailable = true;
            return Ok(());
        }
        Err(format!("Unexpected startup output: {line:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const LISTENER: &str = "2026-10-17T18:00:00Z  INFO Listening: ws://127.0.0.1:10233";
    const UNAVAILABLE: &str = "2026-10-17T18:00:00Z  WARN USB: unavailable";

    #[test]
    fn unsupported_usb_warning_does_not_change_listener_port() {
        // On macOS the first controller tick can run before EOF is processed.
        // Exercise both log orders without requiring macOS or physical hardware.
        for lines in [[LISTENER, UNAVAILABLE], [UNAVAILABLE, LISTENER]] {
            let mut startup = StartupOutput::default();
            for line in lines {
                startup.observe(line, false).unwrap();
            }
            assert_eq!(startup.listener.unwrap().port(), 10233);
        }
        // EOF may win the select before that first tick, so a warning is optional.
        let mut startup = StartupOutput::default();
        startup.observe(LISTENER, false).unwrap();
        assert_eq!(startup.listener.unwrap().port(), 10233);
    }

    #[test]
    fn startup_contract_rejects_unexpected_logs_and_malformed_addresses() {
        for line in [
            "2026-10-17T18:00:00Z  WARN BLE: unavailable",
            "2026-10-17T18:00:00Z  INFO Approved: https://example.test",
            "2026-10-17T18:00:00Z  INFO USB: unavailable",
            "2026-10-17T18:00:00Z  WARN USB: unavailable extra",
            "2026-10-17T18:00:00Z  INFO Listening: ws://127.0.0.1:",
            "2026-10-17T18:00:00Z  INFO Listening: ws://127.0.0.1:10233/bridge",
            "2026-10-17T18:00:00Z  INFO Listening: ws://0.0.0.0:10233",
            "2026-10-17T18:00:00Z  INFO Listening: ws://127.0.0.2:10233",
            "\x1b[31m2026-10-17T18:00:00Z  WARN USB: unavailable",
        ] {
            assert!(
                StartupOutput::default().observe(line, false).is_err(),
                "{line}"
            );
        }
        assert!(StartupOutput::default().observe(UNAVAILABLE, true).is_err());
        for line in [LISTENER, UNAVAILABLE] {
            let mut startup = StartupOutput::default();
            startup.observe(line, false).unwrap();
            assert!(startup.observe(line, false).is_err());
        }
    }
}
