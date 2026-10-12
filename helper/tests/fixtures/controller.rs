//! Fake-only executable: actual CLI or Desktop controller, same synthetic pipe device.
//! Requires desktop and test-support features; intended only for fixture builds.
#[allow(dead_code)] // Complete production module; only injected run path is used here.
#[path = "../../src/cli/mod.rs"]
mod cli;
#[allow(dead_code)] // Complete production module; only injected backend is used here.
#[path = "../../src/desktop/controller.rs"]
mod desktop_controller;
#[path = "../../src/desktop/logging.rs"]
mod desktop_logging;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};

fn fake_device() {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut delay = std::env::var("FIXTURE_DELAY_MS")
        .ok()
        .map(|value| Duration::from_millis(value.parse::<u64>().unwrap().min(60_000)));
    let exchange_delay = std::env::var("FIXTURE_EXCHANGE_DELAY_MS")
        .ok()
        .map(|value| Duration::from_millis(value.parse::<u64>().unwrap().min(100)));
    let mut pending: Option<(serde_json::Value, Instant, Instant)> = None;
    loop {
        let mut prefix = [0; 4];
        if input.read_exact(&mut prefix).is_err() {
            break;
        }
        let size = u32::from_be_bytes(prefix) as usize;
        assert!(size > 0 && size <= 16384);
        let mut data = vec![0; size];
        input.read_exact(&mut data).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&data).unwrap();
        let reply = match value["type"].as_str().unwrap() {
            "discover" => {
                serde_json::json!({"type":"devices","devices":[{"path":[1],"vendor":1,"product":2,"interface":0,"serial":null}]})
            }
            "open" => serde_json::json!({"type":"opened"}),
            "exchange" => {
                if let Some(delay) = exchange_delay {
                    std::thread::sleep(delay);
                }
                let now = Instant::now();
                if !value["report"].is_null() {
                    assert!(
                        pending.is_none(),
                        "Only one delayed fake request is supported"
                    );
                    if let Some(delay) = delay.take() {
                        pending = Some((value["report"].clone(), now + delay, now));
                    }
                }
                let report = if let Some((report, ready, keepalive)) = &mut pending {
                    if now >= *ready {
                        let report = report.clone();
                        pending = None;
                        report
                    } else if now >= *keepalive {
                        *keepalive = now + Duration::from_secs(1);
                        // Synthetic opaque bytes, not a parsed authenticator command.
                        serde_json::Value::String(STANDARD.encode([0xCE; 64]))
                    } else {
                        std::thread::sleep(Duration::from_millis(10));
                        serde_json::Value::Null
                    }
                } else {
                    value["report"].clone()
                };
                serde_json::json!({"type":"report","report":report})
            }
            _ => panic!("invalid fake pipe request"),
        };
        let bytes = serde_json::to_vec(&reply).unwrap();
        output
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        output.write_all(&bytes).unwrap();
        output.flush().unwrap();
    }
}
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--fixture-identify") {
        println!("webauthn-helper fake controller fixture v1");
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("--fixture-device") {
        fake_device();
        return;
    }
    let controller = webauthn_helper::fido_device::Controller::with_test_worker(
        std::env::current_exe().unwrap(),
    );
    if std::env::var("FIXTURE_UI").as_deref() == Ok("desktop") {
        desktop_logging::init();
        let (tx, rx) = std::sync::mpsc::channel();
        let (events, event_rx) = std::sync::mpsc::channel();
        let latest = std::sync::Arc::new(std::sync::Mutex::new(None));
        let snapshots = latest.clone();
        let worker = std::thread::spawn(move || {
            desktop_controller::backend_with_usb(
                rx,
                events,
                latest,
                eframe::egui::Context::default(),
                controller,
            )
        });
        // The fixture driver represents local checkbox and approval actions. The
        // actual Desktop backend still owns all listener, consent and USB work.
        tx.send(desktop_controller::Command::UsbEnabled(
            std::env::var("FIXTURE_DISABLE_USB").as_deref() != Ok("1"),
        ))
        .unwrap();
        tx.send(desktop_controller::Command::BleEnabled(false))
            .unwrap();
        tx.send(desktop_controller::Command::StartListener(
            std::env::var("FIXTURE_PORT").unwrap().parse().unwrap(),
        ))
        .unwrap();
        let (input, commands) = std::sync::mpsc::sync_channel(4);
        std::thread::spawn(move || loop {
            let mut line = String::new();
            let command = match std::io::stdin().read_line(&mut line) {
                Ok(0) | Err(_) => "quit".to_string(),
                Ok(_) => line.trim().to_owned(),
            };
            let done = command == "quit";
            if input.send(command).is_err() || done {
                break;
            }
        });
        loop {
            if let Ok(command) = commands.try_recv() {
                match command.as_str() {
                    "quit" => {
                        tx.send(desktop_controller::Command::Shutdown).unwrap();
                        break;
                    }
                    // Desktop's actual local revocation action is Stop listening.
                    "revoke" => tx.send(desktop_controller::Command::StopListener).unwrap(),
                    _ => panic!("Unexpected fixture control"),
                }
            }
            if let Ok(event) = event_rx.recv_timeout(std::time::Duration::from_millis(10)) {
                match event {
                    desktop_controller::Event::Listening(address) => {
                        println!("Listening: ws://{address}")
                    }
                    desktop_controller::Event::Fatal(message)
                    | desktop_controller::Event::Failed(message) => panic!("{message}"),
                    desktop_controller::Event::Stopped(Err(message)) => panic!("{message}"),
                    _ => {}
                }
                std::io::stdout().flush().unwrap();
            }
            let snapshot = snapshots.lock().unwrap().take();
            if let Some(webauthn_helper::Snapshot {
                pending_approval: Some(pending),
                ..
            }) = snapshot
            {
                assert_eq!(pending.origin, "https://fixture.example");
                tx.send(desktop_controller::Command::DecidePairing {
                    id: pending.id,
                    approve: true,
                })
                .unwrap();
            }
        }
        worker.join().unwrap();
    } else {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(cli::run_with_usb(controller))
            .unwrap();
    }
}
