//! Small shared loopback fixtures for colocated unit suites; no tests live here.
use crate::pairing::{
    protocol::{random_secret, MAX_HANDSHAKES},
    state::{App, BleState, Inner},
};
use crate::{Handle, ProcessSession, Snapshot, DEFAULT_PORT};
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
pub(crate) fn test_port() -> u16 {
    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub(crate) fn app() -> App {
    App {
        secret: "test-secret".into(),
        port: DEFAULT_PORT,
        session: ProcessSession::default(),
        incoming_pairing: false,
        connection_slot: Arc::new(tokio::sync::Semaphore::new(MAX_HANDSHAKES)),
        inner: Arc::new(Mutex::new(Inner {
            stopping: false,
            epoch: 0,
            cleanup_failed: false,
            pairing: None,
            pending: None,
            fido: None,
            connected: false,
            connection_owner: None,
            connection_events: Vec::new(),
            ble_enabled: true,
            scan: None,
            ble_state: BleState::Stopped,
            status: "ready".into(),
            count: 0,
        })),
    }
}

pub(crate) async fn wait_snapshot(
    handle: &Handle,
    predicate: impl Fn(&Snapshot) -> bool,
) -> Snapshot {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = handle.snapshot().await;
            if predicate(&snapshot) {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Expected snapshot transition")
}

pub(crate) fn socket_request(
    handle: &Handle,
    origin: &str,
) -> tokio_tungstenite::tungstenite::http::Request<()> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = handle.websocket_url().into_client_request().unwrap();
    request
        .headers_mut()
        .insert("origin", origin.parse().unwrap());
    request
}

pub(crate) async fn session_socket(
    handle: &Handle,
    origin: &str,
    session_id: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    use futures_util::SinkExt;
    let (mut socket, _) = tokio_tungstenite::connect_async(socket_request(handle, origin))
        .await
        .unwrap();
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({"type":"pair", "token":random_secret(), "session_id":session_id}).to_string(),
        ))
        .await
        .unwrap();
    socket
}

pub(crate) async fn socket_state(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> String {
    let reply = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    serde_json::from_str::<Value>(&reply).unwrap()["state"]
        .as_str()
        .unwrap()
        .into()
}
