//! One candidate socket, exact-Origin approval, bounded pairing, and BLE forwarding.
use crate::{
    pairing::{
        protocol::{secret_eq, valid_token, Authentication, LIFETIME},
        state::{App, BleState, ConnectionEvent, Inner, Pairing, PendingPairing},
    },
    relay::ble::scan,
    server::websocket::{send_message, send_status},
};
use axum::extract::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

pub(crate) fn begin_cleanup(inner: &mut Inner, request_id: &str, origin: &str, epoch: u64) {
    crate::relay::fido::cancel_owned(inner, request_id, origin, epoch);
    if inner.connection_owned_by(request_id, epoch) {
        if let Some(tx) = inner.scan.take() {
            let _ = tx.send(false);
        }
    }
}

pub(crate) fn finish_cleanup(inner: &mut Inner, request_id: &str, epoch: u64) {
    if !inner.connection_owned_by(request_id, epoch) {
        return;
    }
    inner.connected = false;
    inner.connection_owner = None;
    inner.epoch = inner.epoch.wrapping_add(1);
    inner.pairing = None;
    inner.pending = None;
    if !inner.cleanup_failed {
        inner.ble_state = BleState::Stopped;
        inner.status = "Disconnected. Bluetooth stopped; waiting for browser reconnection.".into();
    }
}

pub(crate) async fn await_local_approval(
    app: &App,
    socket: &mut WebSocket,
    origin: &str,
    token: &str,
    session_id: Option<&str>,
    id: &str,
    epoch: u64,
) -> bool {
    {
        let mut inner = app.inner.lock().await;
        if inner.stopping || inner.epoch != epoch || app.session.withheld(origin) {
            return false;
        }
        if inner.pairing.is_some() {
            return true;
        }
        if !app.incoming_pairing || inner.pending.is_some() || inner.cleanup_failed {
            return false;
        }
        let remembered = {
            let memory = app.session.memory();
            if memory.used_tokens.contains(token) || memory.used_tokens.len() >= 4096 {
                return false;
            }
            memory.approved_origins.contains(origin)
        };
        if remembered {
            inner.pairing = Some(Pairing {
                explicit_approval: false,
                request_id: Some(id.into()),
                session_id: session_id.map(str::to_owned),
                origin: origin.into(),
                token: Some(token.into()),
                expires: Instant::now() + LIFETIME,
            });
            return true;
        }
        inner.pending = Some(PendingPairing {
            id: id.into(),
            origin: origin.into(),
            expires: Instant::now() + Duration::from_secs(60),
            approved: false,
        });
        inner.status = "Browser is requesting local pairing approval.".into();
    }
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    loop {
        tokio::select! {
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Ping(value))) => { if !send_message(socket, Message::Pong(value)).await { return false; } },
                Some(Ok(Message::Pong(_))) => {},
                _ => return false,
            },
            _ = tick.tick() => {
                let mut inner = app.inner.lock().await;
                if inner.stopping || inner.epoch != epoch { return false; }
                let Some(pending) = inner.pending.as_ref() else { return false; };
                if pending.id != id { return false; }
                if pending.expires <= Instant::now() {
                    return false;
                }
                if pending.approved {
                    inner.pairing = Some(Pairing { explicit_approval: true, request_id: Some(id.into()), session_id: session_id.map(str::to_owned), origin: origin.into(), token: Some(token.into()), expires: Instant::now() + LIFETIME });
                    inner.pending = None;
                    return true;
                }
            }
        }
    }
}
pub(crate) async fn connection(
    app: App,
    mut socket: WebSocket,
    origin: String,
    request_id: &str,
    epoch: u64,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut cancellation = tokio::time::interval(Duration::from_millis(50));
    let text = loop {
        tokio::select! {
            incoming = socket.recv() => match incoming { Some(Ok(Message::Text(text))) => break text, _ => return },
            _ = tokio::time::sleep_until(deadline) => return,
            _ = cancellation.tick() => { let inner = app.inner.lock().await; if inner.stopping || inner.epoch != epoch { return; } },
        }
    };
    let Ok(auth) = serde_json::from_str::<Authentication>(&text) else {
        return;
    };
    if auth.r#type != "pair"
        || !valid_token(&auth.token)
        || auth
            .session_id
            .as_deref()
            .is_some_and(|id| !valid_token(id))
    {
        return;
    }
    if !await_local_approval(
        &app,
        &mut socket,
        &origin,
        &auth.token,
        auth.session_id.as_deref(),
        request_id,
        epoch,
    )
    .await
    {
        let _ = send_status(
            &mut socket,
            "closed",
            "Waiting for local helper authorization.",
        )
        .await;
        return;
    }
    let (control, mut commands) = watch::channel(false);
    let expires = 'authorization: {
        let mut inner = app.inner.lock().await;
        if inner.connected
            || inner.stopping
            || inner.epoch != epoch
            || app.session.withheld(&origin)
        {
            break 'authorization None;
        }
        let Some(p) = inner.pairing.as_mut() else {
            break 'authorization None;
        };
        if p.request_id.as_ref().is_some_and(|id| id != request_id)
            || p.origin != origin
            || p.expires <= Instant::now()
            || auth.r#type != "pair"
            || !p.token.as_ref().is_some_and(|t| secret_eq(t, &auth.token))
        {
            break 'authorization None;
        }
        {
            let mut memory = app.session.memory();
            if memory.used_tokens.len() >= 4096 || !memory.used_tokens.insert(auth.token.clone()) {
                break 'authorization None;
            }
            if p.explicit_approval {
                memory.approved_origins.insert(origin.clone());
            }
        }
        if !p.explicit_approval {
            crate::diagnostics::approved(&origin, true);
        }
        p.token = None;
        p.request_id = Some(request_id.into());
        p.session_id = auth.session_id.clone();
        let expires = p.expires;
        inner.connected = true;
        inner.connection_owner = Some((request_id.into(), epoch));
        crate::diagnostics::connected(&origin);
        inner.connection_events.push(ConnectionEvent {
            connection_id: request_id.to_owned(),
            origin: origin.clone(),
            connected_at: std::time::SystemTime::now(),
        });
        inner.scan = Some(control);
        inner.status = if app.incoming_pairing {
            "Browser paired. Local channel settings apply."
        } else {
            "Webpage paired. Press Start to listen for your phone."
        }
        .into();
        Some(expires)
    };
    let Some(expires) = expires else {
        let _ = send_status(
            &mut socket,
            "closed",
            "Pairing authorization is not currently available.",
        )
        .await;
        return;
    };
    let (events_tx, mut events) = mpsc::channel::<Value>(64);
    let scan_app = app.clone();
    let scan_request = request_id.to_owned();
    let worker = tokio::spawn(async move {
        loop {
            if !*commands.borrow() && commands.changed().await.is_err() {
                break;
            }
            if *commands.borrow() {
                if let Err(e) = scan(&mut commands, &events_tx).await {
                    let message = if format!("{e:#}").contains("OS did not confirm") {
                        format!("Bluetooth unavailable: {e:#}. Restart the helper before pairing again.")
                    } else {
                        format!("Bluetooth unavailable: {e:#}. Check Bluetooth power and OS permissions, then Stop and Start to retry.")
                    };
                    {
                        let mut i = scan_app.inner.lock().await;
                        if message.contains("OS did not confirm") {
                            i.cleanup_failed = true;
                            i.ble_state = BleState::CleanupFailed;
                        } else {
                            i.ble_state = BleState::Unavailable;
                        }
                        {
                            i.status = message.clone();
                        }
                    }
                    let _ = events_tx
                        .try_send(json!({"type":"status","state":"error","message":message}));
                    // Wait for Stop rather than retrying the OS indefinitely.
                    while *commands.borrow() {
                        if commands.changed().await.is_err() {
                            return;
                        }
                    }
                } else {
                    // Successful return confirms either no scan was started or
                    // stop_scan completed. Do not rely on a bounded event queue.
                    let mut inner = scan_app.inner.lock().await;
                    if inner.connection_owned_by(&scan_request, epoch)
                        && !inner.cleanup_failed
                        && !*commands.borrow()
                    {
                        inner.ble_state = BleState::Stopped;
                    }
                }
            }
        }
    });
    let _ = send_status(
        &mut socket,
        "paired",
        if app.incoming_pairing {
            "Paired. Local channel settings apply."
        } else {
            "Paired. Press Start in the local helper to listen for your phone."
        },
    )
    .await;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Ping(v))) => {if !send_message(&mut socket,Message::Pong(v)).await{break;}},
                Some(Ok(Message::Pong(_))) => {},
                Some(Ok(Message::Text(text))) => {
                    let Some(replies) = crate::relay::fido::incoming(&app, request_id, &origin, epoch, &text).await else { break; };
                    let mut sent = true;
                    for reply in replies {
                        if !crate::relay::fido::send(&app, &mut socket, request_id, &origin, epoch, reply).await { sent = false; break; }
                    }
                    if !sent { break; }
                },
                _ => break
            },
            event = events.recv() => { if let Some(value) = event { if value["type"] == "advertisement" { let mut i=app.inner.lock().await;if Instant::now()>=expires || i.pairing.is_none() || !i.scan.as_ref().is_some_and(|tx|*tx.borrow()){continue;} i.count += 1; } else if let Some(m) = value["message"].as_str() {let mut i=app.inner.lock().await;if !i.cleanup_failed {i.status=m.into(); match value["state"].as_str() {Some("scanning") if i.scan.as_ref().is_some_and(|tx|*tx.borrow()) => i.ble_state=BleState::Scanning,Some("stopped") => i.ble_state=BleState::Stopped,Some("error") => i.ble_state=BleState::Unavailable,_=>{}}}}
                if !send_message(&mut socket,Message::Text(value.to_string())).await{break;} } else {break;} },
            _ = tick.tick() => {
                let ended = {
                    let inner = app.inner.lock().await;
                    // Explicit revocation always wins a simultaneous clock expiry.
                    let state = if inner.stopping || inner.epoch != epoch || inner.pairing.is_none() {
                        Some(("closed", "Pairing is awaiting local helper authorization."))
                    } else if Instant::now() >= expires {
                        Some(("lease_expired", "The finite helper lease ended. A fresh authorized pairing is required."))
                    } else { None };
                    if state.is_some() && inner.connection_owned_by(request_id, epoch) { if let Some(tx) = &inner.scan { let _ = tx.send(false); } }
                    state
                };
                if let Some((state, message)) = ended { let _ = send_status(&mut socket, state, message).await; break; }
                let mut sent = true;
                let frames = crate::relay::fido::poll(&app, request_id, &origin, epoch).await;
                let full_batch = frames.len() == fido_report_relay::MAX_BATCH;
                for frame in frames {
                    if !crate::relay::fido::send(&app, &mut socket, request_id, &origin, epoch, frame).await { sent = false; break; }
                }
                if !sent { break; }
                // A legal CTAPHID message spans up to 129 reports. Drain another
                // bounded batch promptly, yielding through select so incoming
                // cancellation/pings and authorization checks stay responsive.
                // An empty/partial batch retains the normal idle cadence.
                if full_batch { tick.reset_immediately(); }
            }
        }
    }
    {
        let mut inner = app.inner.lock().await;
        begin_cleanup(&mut inner, request_id, &origin, epoch);
    }
    // Dropping the only sender cancels an active scan, including on websocket loss.
    let _ = worker.await;
    {
        let mut inner = app.inner.lock().await;
        finish_cleanup(&mut inner, request_id, epoch);
    }
    crate::diagnostics::disconnected(&origin, false);
    let _ = tokio::time::timeout(Duration::from_secs(2), socket.close()).await;
}

#[cfg(test)]
mod tests {
    use crate::server::http::router;

    use super::*;
    use crate::pairing::protocol::{random_secret, MAX_FRAME, MAX_HANDSHAKES};

    use crate::testing::{
        app, session_socket, socket_request, socket_state, test_port, wait_snapshot,
    };
    use crate::{launch_desktop, launch_incoming};
    use axum::http::StatusCode;
    use futures_util::StreamExt;
    use serde_json::{json, Value};
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn real_websocket_pairing_is_one_use_without_scanning() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message as ClientMessage};
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let mut a = app();
        a.port = listener.local_addr().unwrap().port();
        let token = random_secret();
        a.inner.lock().await.pairing = Some(Pairing {
            explicit_approval: true,
            request_id: None,
            session_id: None,
            origin: "https://example.com".into(),
            token: Some(token.clone()),
            expires: Instant::now() + LIFETIME,
        });
        let server_app = a.clone();
        let server =
            tokio::spawn(async move { axum::serve(listener, router(server_app)).await.unwrap() });
        let request = || {
            let mut r = format!("ws://127.0.0.1:{}/bridge", a.port)
                .into_client_request()
                .unwrap();
            r.headers_mut()
                .insert("origin", "https://example.com".parse().unwrap());
            r
        };
        let (mut socket, _) = tokio_tungstenite::connect_async(request()).await.unwrap();
        socket
            .send(ClientMessage::Text(
                json!({"type":"pair","token":token}).to_string(),
            ))
            .await
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&reply).unwrap()["state"],
            "paired"
        );
        {
            let i = a.inner.lock().await;
            assert!(i.connected);
            assert!(!*i.scan.as_ref().unwrap().borrow());
            assert!(i.pairing.as_ref().unwrap().token.is_none());
        }
        assert!(tokio_tungstenite::connect_async(request()).await.is_err());
        socket.close(None).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while a.inner.lock().await.connected {
                tokio::time::sleep(Duration::from_millis(10)).await
            }
        })
        .await
        .unwrap();
        assert!(a.inner.lock().await.pairing.is_none());
        assert!(tokio_tungstenite::connect_async(request()).await.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn root_websocket_stays_open_through_pairing_idle_and_ping_until_stopped() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as ClientMessage;
        let handle = launch_desktop(Some(test_port())).await.unwrap();
        let (mut socket, response) =
            tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        // Opening the real root socket neither closes it nor starts pairing/BLE.
        assert!(
            tokio::time::timeout(Duration::from_millis(150), socket.next())
                .await
                .is_err()
        );
        assert!(handle.snapshot().await.pending_approval.is_none());
        assert!(!handle.snapshot().await.scanning);
        socket
            .send(ClientMessage::Text(
                json!({"type":"pair", "token":random_secret()}).to_string(),
            ))
            .await
            .unwrap();
        let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some())
            .await
            .pending_approval
            .unwrap();
        handle.decide_pending(&pending.id, true).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&reply).unwrap()["state"],
            "paired"
        );
        // The five-second first-frame deadline must not close a paired idle socket.
        assert!(
            tokio::time::timeout(Duration::from_millis(5200), socket.next())
                .await
                .is_err()
        );
        let ping = vec![1, 2, 3];
        socket
            .send(ClientMessage::Ping(ping.clone()))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            ClientMessage::Pong(ping)
        );
        assert!(handle.snapshot().await.connected);
        assert!(!handle.snapshot().await.scanning);
        assert!(handle
            .app
            .inner
            .lock()
            .await
            .pairing
            .as_ref()
            .unwrap()
            .token
            .is_none());
        handle.shutdown().await.unwrap();
        assert!(!handle.snapshot().await.connected);
        assert!(handle.snapshot().await.origin.is_none());
        assert!(tokio::net::TcpStream::connect(handle.address())
            .await
            .is_err());
        let mut saw_close = false;
        tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(Ok(message)) = socket.next().await {
                if message.is_close() {
                    saw_close = true;
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(saw_close, "Explicit stop must close the active root socket");
    }

    #[tokio::test]
    async fn desktop_probe_is_silent_and_incoming_pair_needs_specific_local_approval() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as ClientMessage;
        let handle = launch_desktop(Some(test_port())).await.unwrap();
        let (mut probe, _) =
            tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                .await
                .unwrap();
        assert!(handle.snapshot().await.pending_approval.is_none());
        // A no-frame probe does not occupy the sole actual pairing candidate.
        let (mut socket, _) =
            tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                .await
                .unwrap();
        let (mut stale, _) =
            tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                .await
                .unwrap();
        let token = random_secret();
        socket
            .send(ClientMessage::Text(
                json!({"type":"pair", "token":token}).to_string(),
            ))
            .await
            .unwrap();
        let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some()).await;
        assert!(!pending.connected);
        assert!(!pending.scanning);
        assert!(!format!("{pending:?}").contains(&token));
        assert_eq!(
            pending.pending_approval.as_ref().unwrap().origin,
            "https://example.com"
        );
        probe.close(None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            handle.snapshot().await.pending_approval.is_some(),
            "Probe cleanup must not revoke another socket's candidate"
        );
        assert!(handle.decide_pending("stale-request", true).await.is_err());
        let id = pending.pending_approval.unwrap().id;
        handle.decide_pending(&id, true).await.unwrap();
        assert!(handle.snapshot().await.pending_approval.is_none());
        let reply = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&reply).unwrap()["state"],
            "paired"
        );
        let snapshot = handle.snapshot().await;
        assert!(snapshot.connected);
        assert!(!snapshot.scanning);
        assert!(snapshot.pending_approval.is_none());
        assert!(handle
            .app
            .inner
            .lock()
            .await
            .pairing
            .as_ref()
            .unwrap()
            .token
            .is_none());
        assert!(
            tokio_tungstenite::connect_async(socket_request(&handle, "https://other.example"))
                .await
                .is_err()
        );
        assert!(
            tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                .await
                .is_err()
        );
        socket.close(None).await.unwrap();
        wait_snapshot(&handle, |s| !s.connected && s.origin.is_none()).await;
        let _ = stale
            .send(ClientMessage::Text(
                json!({"type":"pair", "token":random_secret()}).to_string(),
            ))
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(2), stale.next())
            .await
            .unwrap();
        assert!(handle.snapshot().await.pending_approval.is_none());
        // Remembered origins still cannot replay consumed one-use tokens.
        let (mut replay, _) =
            tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                .await
                .unwrap();
        replay
            .send(ClientMessage::Text(
                json!({"type":"pair", "token":token}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(socket_state(&mut replay).await, "closed");
        assert!(!handle.snapshot().await.connected);
        assert!(handle.snapshot().await.pending_approval.is_none());
        assert!(handle.decide_pending(&id, true).await.is_err());
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn desktop_invalid_origin_token_and_frame_never_prompt_or_scan() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as ClientMessage;
        let handle = launch_desktop(Some(test_port())).await.unwrap();
        for origin in [
            "null",
            "file:///tmp",
            "https://example.com/path",
            "https://EXAMPLE.com",
        ] {
            assert!(
                tokio_tungstenite::connect_async(socket_request(&handle, origin))
                    .await
                    .is_err()
            );
        }
        for payload in [
            json!({"type":"pair", "token":"short"}),
            json!({"type":"wrong", "token":random_secret()}),
            json!({"type":"pair", "token":random_secret(), "extra":true}),
            json!({"type":"pair", "token":random_secret(), "session_id":"short"}),
            json!({"type":"pair", "token":random_secret(), "session_id":"x".repeat(129)}),
            json!({"type":"pair", "token":random_secret(), "session_id":"/".repeat(32)}),
        ] {
            let (mut socket, _) =
                tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                    .await
                    .unwrap();
            socket
                .send(ClientMessage::Text(payload.to_string()))
                .await
                .unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap();
            let snapshot = handle.snapshot().await;
            assert!(!snapshot.connected);
            assert!(!snapshot.scanning);
            assert!(snapshot.pending_approval.is_none());
        }
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn desktop_pending_disconnect_expiry_and_stop_clear_candidates() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as ClientMessage;
        let handle = launch_desktop(Some(test_port())).await.unwrap();
        let address = handle.address();
        for stage in 0..3 {
            let (mut socket, _) =
                tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                    .await
                    .unwrap();
            socket
                .send(ClientMessage::Text(
                    json!({"type":"pair", "token":random_secret()}).to_string(),
                ))
                .await
                .unwrap();
            let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some())
                .await
                .pending_approval
                .unwrap();
            match stage {
                0 => {
                    socket.close(None).await.unwrap();
                }
                1 => {
                    handle
                        .app
                        .inner
                        .lock()
                        .await
                        .pending
                        .as_mut()
                        .unwrap()
                        .expires = Instant::now() - Duration::from_secs(1);
                }
                _ => {
                    handle.shutdown().await.unwrap();
                }
            }
            wait_snapshot(&handle, |s| s.pending_approval.is_none()).await;
            assert!(handle.decide_pending(&pending.id, true).await.is_err());
            assert!(!handle.snapshot().await.connected);
            if stage >= 1 {
                let reply = tokio::time::timeout(Duration::from_secs(2), socket.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .into_text()
                    .unwrap();
                assert_eq!(
                    serde_json::from_str::<Value>(&reply).unwrap()["state"],
                    "closed"
                );
            }
        }
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
        let restarted = launch_desktop(Some(address.port())).await.unwrap();
        assert_eq!(restarted.address(), address);
        assert!(restarted.snapshot().await.pending_approval.is_none());
        restarted.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn desktop_revoke_and_shutdown_invalidate_pre_frame_sockets() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as ClientMessage;
        let handle = launch_desktop(Some(test_port())).await.unwrap();
        for shutdown in [false, true] {
            let (mut socket, _) =
                tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                    .await
                    .unwrap();
            if shutdown {
                handle.shutdown().await.unwrap();
            } else {
                handle.revoke().await.unwrap();
            }
            let _ = socket
                .send(ClientMessage::Text(
                    json!({"type":"pair", "token":random_secret()}).to_string(),
                ))
                .await;
            let _ = tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap();
            assert!(handle.snapshot().await.pending_approval.is_none());
            assert!(!handle.snapshot().await.connected);
            if shutdown {
                assert_eq!(
                    handle.app.connection_slot.available_permits(),
                    MAX_HANDSHAKES
                );
            }
        }
    }

    #[tokio::test]
    async fn desktop_approval_cannot_be_stolen_by_preupgraded_same_token_socket() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as ClientMessage;
        let handle = launch_desktop(Some(test_port())).await.unwrap();
        let (mut owner, _) =
            tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                .await
                .unwrap();
        let (mut other, _) =
            tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                .await
                .unwrap();
        let token = random_secret();
        owner
            .send(ClientMessage::Text(
                json!({"type":"pair", "token":token}).to_string(),
            ))
            .await
            .unwrap();
        let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some())
            .await
            .pending_approval
            .unwrap();
        // Expose the precise approval-to-consumption interleaving, using real sockets.
        handle.app.inner.lock().await.pairing = Some(Pairing {
            explicit_approval: true,
            request_id: Some(pending.id.clone()),
            session_id: None,
            origin: pending.origin.clone(),
            token: Some(token.clone()),
            expires: Instant::now() + LIFETIME,
        });
        other
            .send(ClientMessage::Text(
                json!({"type":"pair", "token":token}).to_string(),
            ))
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), other.next())
            .await
            .unwrap();
        assert!(!handle.snapshot().await.connected);
        assert!(handle
            .app
            .inner
            .lock()
            .await
            .pairing
            .as_ref()
            .unwrap()
            .token
            .is_some());
        handle.decide_pending(&pending.id, true).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), owner.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&reply).unwrap()["state"],
            "paired"
        );
        assert!(handle.snapshot().await.connected);
        owner.close(None).await.unwrap();
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn desktop_limits_incomplete_handshakes_and_first_frame_sizes() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as ClientMessage;
        let handle = launch_desktop(Some(test_port())).await.unwrap();
        let mut sockets = Vec::new();
        for _ in 0..MAX_HANDSHAKES {
            sockets.push(
                tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                    .await
                    .unwrap()
                    .0,
            );
        }
        assert!(
            tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                .await
                .is_err()
        );
        assert!(handle.snapshot().await.pending_approval.is_none());
        for mut socket in sockets {
            socket.close(None).await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while handle.app.connection_slot.available_permits() != MAX_HANDSHAKES {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        for frame in [
            ClientMessage::Text("x".repeat(MAX_FRAME + 1)),
            ClientMessage::Binary(vec![0; MAX_FRAME + 1]),
            ClientMessage::Binary(vec![0; 32]),
        ] {
            let (mut socket, _) =
                tokio_tungstenite::connect_async(socket_request(&handle, "https://example.com"))
                    .await
                    .unwrap();
            let _ = socket.send(frame).await;
            let _ = tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap();
            assert!(handle.snapshot().await.pending_approval.is_none());
            assert!(!handle.snapshot().await.scanning);
        }
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn paired_transport_loss_can_retry_but_explicit_revoke_and_stop_cannot() {
        for action in ["disconnect", "revoke", "stop"] {
            let handle = launch_desktop(Some(test_port())).await.unwrap();
            let id = random_secret();
            let origin = "https://retry.example";
            let mut first = session_socket(&handle, origin, &id).await;
            let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some())
                .await
                .pending_approval
                .unwrap();
            handle.decide_pending(&pending.id, true).await.unwrap();
            assert_eq!(socket_state(&mut first).await, "paired");
            match action {
                "disconnect" => {
                    first.close(None).await.unwrap();
                }
                "revoke" => {
                    handle.revoke().await.unwrap();
                }
                _ => {
                    handle.stop().await.unwrap();
                }
            }
            wait_snapshot(&handle, |s| !s.connected && s.origin.is_none()).await;
            let mut next = session_socket(&handle, origin, &random_secret()).await;
            assert_eq!(
                socket_state(&mut next).await,
                if action == "disconnect" {
                    "paired"
                } else {
                    "closed"
                }
            );
            assert!(handle.snapshot().await.pending_approval.is_none());
            handle.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn pending_transport_loss_is_retryable_but_pending_stop_and_revoke_are_terminal() {
        for action in ["disconnect", "revoke", "stop"] {
            let handle = launch_desktop(Some(test_port())).await.unwrap();
            let id = random_secret();
            let origin = "https://pending-retry.example";
            let mut first = session_socket(&handle, origin, &id).await;
            wait_snapshot(&handle, |s| s.pending_approval.is_some()).await;
            match action {
                "disconnect" => {
                    first.close(None).await.unwrap();
                }
                "revoke" => {
                    handle.revoke().await.unwrap();
                }
                _ => {
                    handle.stop().await.unwrap();
                }
            }
            wait_snapshot(&handle, |s| s.pending_approval.is_none()).await;
            let mut retry = session_socket(&handle, origin, &random_secret()).await;
            if action == "disconnect" {
                let pending = wait_snapshot(&handle, |s| s.pending_approval.is_some())
                    .await
                    .pending_approval
                    .unwrap();
                handle.decide_pending(&pending.id, false).await.unwrap();
            }
            assert_eq!(socket_state(&mut retry).await, "closed");
            assert!(handle.snapshot().await.pending_approval.is_none());
            assert!(!handle.snapshot().await.connected);
            handle.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn finite_lease_expiry_is_distinct_and_fresh_pair_keeps_process_origin_approval() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as ClientMessage;
        let handle = launch_incoming(Some(test_port())).await.unwrap();
        let origin = "https://lease.example.test";
        let first_token = random_secret();
        handle.approve(origin, &first_token).await.unwrap();
        handle
            .app
            .inner
            .lock()
            .await
            .pairing
            .as_mut()
            .unwrap()
            .expires = Instant::now() + Duration::from_millis(150);
        let (mut first, _) = tokio_tungstenite::connect_async(socket_request(&handle, origin))
            .await
            .unwrap();
        first
            .send(ClientMessage::Text(
                json!({"type":"pair", "token":first_token}).to_string(),
            ))
            .await
            .unwrap();
        let paired = first.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&paired).unwrap()["state"],
            "paired"
        );
        let ended = tokio::time::timeout(Duration::from_secs(2), first.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&ended).unwrap()["state"],
            "lease_expired"
        );
        wait_snapshot(&handle, |s| !s.connected).await;
        assert!(handle
            .app
            .session
            .memory()
            .approved_origins
            .contains(origin));
        let second_token = random_secret();
        let (mut second, _) = tokio_tungstenite::connect_async(socket_request(&handle, origin))
            .await
            .unwrap();
        second
            .send(ClientMessage::Text(
                json!({"type":"pair", "token":second_token}).to_string(),
            ))
            .await
            .unwrap();
        let paired = tokio::time::timeout(Duration::from_secs(2), second.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&paired).unwrap()["state"],
            "paired"
        );
        assert!(handle.snapshot().await.pending_approval.is_none());
        handle.stop().await.unwrap();
        let stopped = tokio::time::timeout(Duration::from_secs(2), second.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&stopped).unwrap()["state"],
            "closed"
        );
        handle.shutdown().await.unwrap();
    }
}
