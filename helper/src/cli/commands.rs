//! Clap-generated arguments and interactive command parsing.
use clap::{Parser, Subcommand};
/// Relay phone BLE advertisements and USB security keys for an approved browser.
#[derive(Debug, Parser, PartialEq)]
#[command(version)]
pub(super) struct Options {
    /// Loopback address (default: 127.0.0.1:10233; never saved).
    #[arg(long, value_name = "ADDRESS", value_parser = listen_address)]
    pub(super) listen: Option<std::net::SocketAddr>,
    /// Disable USB relay for this process (enabled after Origin approval by default).
    #[arg(long)]
    pub(super) disable_usb: bool,
    /// Disable BLE scanning for this process; USB and pairing stay available.
    #[arg(long)]
    pub(super) disable_ble: bool,
}
pub(super) fn listen_address(text: &str) -> Result<std::net::SocketAddr, String> {
    let address: std::net::SocketAddr = text
        .parse()
        .map_err(|_| "Use 127.0.0.1:PORT (1024-65535).".to_owned())?;
    if address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
        return Err("Only 127.0.0.1 is supported; network and IPv6 listeners are disabled.".into());
    }
    if address.port() < 1024 {
        return Err("Choose a port from 1024 to 65535.".into());
    }
    Ok(address)
}
#[derive(Parser)]
#[command(name = "webauthn-helper", disable_help_subcommand = true)]
pub(super) struct TerminalCommands {
    #[command(subcommand)]
    pub(super) command: Command,
}
#[derive(Debug, PartialEq, Subcommand)]
pub(super) enum Command {
    /// Retry Bluetooth for the approved browser.
    Start,
    /// Revoke pairing and stop BLE and USB.
    Stop,
    /// Revoke pairing and stop BLE and USB.
    Revoke,
    /// Allow a withheld exact Origin to request pairing again (does not grant approval).
    Allow { origin: String },
    /// Show listener, browser and Bluetooth state.
    Status,
    /// Change the current process listener port; never saved.
    Port { port: u16 },
    /// Show terminal commands.
    Help,
    /// USB status, stable selection, retry, or detach.
    Usb {
        #[command(subcommand)]
        action: UsbCommand,
    },
    /// Stop the helper.
    #[command(alias = "exit")]
    Quit,
}
pub(super) fn command(text: &str) -> Option<Command> {
    let parsed = TerminalCommands::try_parse_from(
        std::iter::once("webauthn-helper").chain(text.split_whitespace()),
    )
    .ok()?
    .command;
    match parsed {
        Command::Port { port } if port < 1024 => None,
        command => Some(command),
    }
}

#[derive(Debug, PartialEq, Subcommand)]
pub(super) enum UsbCommand {
    Status,
    Select { id: String },
    Retry,
    Detach,
}

#[cfg(test)]
mod tests {

    use super::*;
    use clap::CommandFactory;
    fn args(v: &[&str]) -> Result<Options, clap::Error> {
        Options::try_parse_from(std::iter::once("webauthn-helper").chain(v.iter().copied()))
    }
    #[test]
    fn no_arguments_use_default_port() {
        assert_eq!(
            args(&[]).unwrap(),
            Options {
                listen: None,
                disable_usb: false,
                disable_ble: false
            }
        );
    }

    #[test]
    fn custom_listen_is_loopback_only() {
        assert_eq!(
            args(&["--listen", "127.0.0.1:18000"]).unwrap(),
            Options {
                listen: Some("127.0.0.1:18000".parse().unwrap()),
                disable_usb: false,
                disable_ble: false
            }
        );
        for a in [
            "0.0.0.0:18000",
            "192.168.1.1:18000",
            "[::1]:18000",
            "127.0.0.1:0",
            "127.0.0.1:80",
        ] {
            assert!(args(&["--listen", a]).is_err());
        }
        assert!(args(&["--no-open"]).is_err());
    }

    #[test]
    fn clap_generates_help_and_version() {
        assert_eq!(
            args(&["--help"]).unwrap_err().kind(),
            clap::error::ErrorKind::DisplayHelp
        );
        assert_eq!(
            args(&["--version"]).unwrap_err().kind(),
            clap::error::ErrorKind::DisplayVersion
        );
        Options::command().debug_assert();
        TerminalCommands::command().debug_assert();
    }

    #[test]
    fn usb_defaults_enabled_with_explicit_opt_out_and_opaque_selection() {
        assert!(!args(&[]).unwrap().disable_usb);
        assert!(args(&["--disable-usb"]).unwrap().disable_usb);
        assert!(args(&["--disable-ble"]).unwrap().disable_ble);
        assert!(args(&["--disable-fido"]).is_err());
        assert!(args(&["--experimental-fido"]).is_err());
        assert_eq!(
            command("usb detach"),
            Some(Command::Usb {
                action: UsbCommand::Detach
            })
        );
        assert!(command("usb select").is_none());
    }

    #[test]
    fn allow_command_is_explicit_and_requires_exact_origin_argument() {
        assert_eq!(
            command("allow https://example.test:8443"),
            Some(Command::Allow {
                origin: "https://example.test:8443".into()
            })
        );
        assert!(command("allow").is_none());
        assert!(command("allow https://example.test extra").is_none());
        let session = webauthn_helper::ProcessSession::default();
        assert!(session
            .allow_pairing_again("https://example.test/path")
            .is_err());
        assert!(session.allow_pairing_again("https://example.test").is_ok());
    }
}
