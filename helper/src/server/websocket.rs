//! Bounded socket writes shared by pairing and relay protocols.
use axum::extract::ws::{Message, WebSocket};
use serde_json::json;
use std::time::Duration;
pub(crate) async fn send_message(socket: &mut WebSocket, message: Message) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(2), socket.send(message)).await,
        Ok(Ok(()))
    )
}
pub(crate) async fn send_status(socket: &mut WebSocket, state: &str, message: &str) -> bool {
    send_message(
        socket,
        Message::Text(json!({"type":"status","state":state,"message":message}).to_string()),
    )
    .await
}
