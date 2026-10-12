//! Terminal runtime coordinating commands, request-bound input, and the core helper.
mod bootstrap;
mod commands;
mod logging;
mod prompts;
mod terminal_input;
mod terminal_ui;
use clap::{CommandFactory, Parser};
use commands::{command, Command, Options, TerminalCommands, UsbCommand};
use prompts::{display_prompt, ApprovalPrompt, AutoScan};
use terminal_input::Control;
use tokio::sync::mpsc;
use webauthn_helper::Snapshot;
fn status_line(s: &Snapshot) -> String {
    format!(
        "{} | connected={} scanning={} received={}{}",
        s.status,
        s.connected,
        s.scanning,
        s.advertisements,
        s.origin
            .as_ref()
            .map(|o| format!(" origin={o}"))
            .unwrap_or_default()
    )
}
pub fn entry() {
    bootstrap::dispatch(webauthn_helper::fido_device::worker_entry, || {
        let result = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(anyhow::Error::from)
            .and_then(|runtime| runtime.block_on(run()));
        if let Err(error) = result {
            tracing::error!("{error}");
            std::process::exit(1);
        }
    });
}
pub async fn run() -> anyhow::Result<()> {
    run_with_usb(webauthn_helper::fido_device::Controller::default()).await
}
pub(crate) async fn run_with_usb(
    mut usb: webauthn_helper::fido_device::Controller,
) -> anyhow::Result<()> {
    let options = Options::parse();
    let _logging = logging::init()?;
    terminal_ui::install_panic_cleanup();
    let _restore_terminal = terminal_ui::Restore;
    let usb_enabled = !options.disable_usb;
    usb.set_enabled(usb_enabled);
    terminal_ui::set_channels(!options.disable_ble, usb_enabled);
    let mut usb_previous = None;
    let session = webauthn_helper::ProcessSession::default();
    let mut handle = webauthn_helper::launch_incoming_with_session(
        options.listen.map(|address| address.port()),
        session.clone(),
    )
    .await?;
    handle.set_ble_enabled(!options.disable_ble).await;
    tracing::info!("Listening: {}", handle.websocket_url());
    let mut prompt = ApprovalPrompt::default();
    let (controls, input_controls) = std::sync::mpsc::channel();
    let (tx, mut rx) = mpsc::channel(8);
    std::thread::spawn(move || {
        if let Err(error) = terminal_input::run(terminal_input::StdinSource, input_controls, tx) {
            tracing::error!("Terminal input failed: {error}; closing webauthn-helper.");
        }
    });
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(50));
    let mut previous = None;
    let mut previous_withheld = Vec::new();
    let mut auto_scan = AutoScan::default();
    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => break,
            input = rx.recv() => {
                let Some(input) = input else { break; };
                let result = if let Some(command) = command(&input.text) {
                    match command {
                        Command::Start => handle.start().await,
                        // Stop also invalidates pending approvals and in-flight pairing.
                        Command::Stop => { usb.cancel(); handle.stop().await },
                        Command::Revoke => { usb.cancel(); handle.revoke().await },
                        Command::Allow { origin } => { session.allow_pairing_again(&origin).map(|()| tracing::info!("Local withholding cleared for {origin}; pairing approval is unchanged.")) },
                        Command::Port { port } => {
                            let usb_result = usb.shutdown().await;
                            let helper_result = handle.shutdown().await;
                            usb_result?;
                            helper_result?;

                            handle = webauthn_helper::launch_incoming_with_session(Some(port), session.clone()).await?;
                            handle.set_ble_enabled(!options.disable_ble).await;
                            auto_scan = AutoScan::default();
                            tracing::info!("Listening: {} (this process only)", handle.websocket_url());
                            Ok(())
                        },
                        Command::Status => { tracing::info!("Listening: {}\n{}", handle.websocket_url(), status_line(&handle.snapshot().await)); Ok(()) },
                        Command::Help => terminal_ui::write_text(&format!("{}\n", TerminalCommands::command().render_help())).map_err(Into::into),
                        Command::Usb { action } => {
                            if !usb_enabled { Err(anyhow::anyhow!("USB is disabled for this process. Restart without --disable-usb to enable it after Origin approval.")) }
                            else { match action {
                                UsbCommand::Status => { let status = usb.status(); tracing::info!("{}", status.message); for choice in status.choices { tracing::info!("{}: {}", choice.id, choice.label); } Ok(()) },
                                UsbCommand::Select { id } => usb.select(&id),
                                UsbCommand::Retry => { usb.retry(); Ok(()) },
                                UsbCommand::Detach => { usb.detach(); Ok(()) },
                            } }
                        },
                        Command::Quit => break,
                    }
                } else {
                    let snapshot = handle.snapshot().await;
                    display_prompt(&mut prompt, snapshot.pending_approval.as_ref(), &controls);
                    match prompt.answer(&input) {
                        Ok((id, origin, approve)) => {
                            let _ = controls.send(Control::Clear);
                            let result = handle.decide_pending(&id, approve).await;
                            if result.is_ok() {
                                if approve { webauthn_helper::diagnostics::approved(&origin, false); }
                                else { webauthn_helper::diagnostics::rejected(&origin); }
                            }
                            result
                        },
                        Err(message) => { tracing::warn!("{message}"); Ok(()) },
                    }
                };
                if let Err(error) = result { tracing::error!("{error}"); }
            }
            _ = tick.tick() => {},
        }

        usb.tick(Some(&handle)).await;
        if usb_enabled {
            let current = usb.status();
            if usb_previous.as_ref() != Some(&current) {
                if usb_previous.is_some() || current.message != "USB: waiting for approved browser"
                {
                    // Core transition logging is shared with Desktop; only the
                    // explicit stable-device selection instructions belong here.
                    for choice in &current.choices {
                        tracing::info!("usb select {}  ({})", choice.id, choice.label);
                    }
                }
                usb_previous = Some(current);
            }
        }
        let snapshot = handle.snapshot().await;
        if previous_withheld != snapshot.withheld_origins {
            for origin in &snapshot.withheld_origins {
                if !previous_withheld.contains(origin) {
                    tracing::warn!("Pairing withheld for {origin}. Local reset: allow {origin}");
                }
            }
            previous_withheld = snapshot.withheld_origins.clone();
        }
        let current = format!(
            "{} | connected={} scanning={}",
            snapshot.status, snapshot.connected, snapshot.scanning
        );
        if previous.as_ref() != Some(&current) {
            if snapshot.ble_state == webauthn_helper::BleState::Unavailable
                || snapshot.needs_restart
                || snapshot.status.starts_with("Local listener failed:")
            {
                tracing::error!("{}", snapshot.status);
            }
            previous = Some(current);
        }
        display_prompt(&mut prompt, snapshot.pending_approval.as_ref(), &controls);
        if !options.disable_ble
            && auto_scan.should_start(snapshot.connection_id.as_deref(), snapshot.needs_restart)
        {
            if let Err(error) = handle.start().await {
                tracing::error!("{error}");
            }
        }
    }
    display_prompt(&mut prompt, None, &controls);
    drop(controls);
    let usb_result = usb.shutdown().await;
    let helper_result = handle.shutdown().await;
    usb_result?;
    helper_result?;
    terminal_ui::finish();
    Ok(())
}
