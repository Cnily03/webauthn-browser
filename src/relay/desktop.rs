//! Authenticated remote desktop WebSocket with revocation-bound transport.
use crate::{
    app::App,
    auth::{authenticated, authorize},
};
use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    http::{HeaderMap, StatusCode},
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) async fn websocket(
    State(app): State<App>,
    h: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, (StatusCode, String)> {
    let i = app.inner.lock().await;
    authorize(&i, &h, "vnc")?;
    let epoch = i.vnc_epoch;
    drop(i);
    Ok(ws.on_upgrade(move |s| bridge(s, app, h, epoch)))
}
async fn bridge(socket: WebSocket, app: App, h: HeaderMap, epoch: u64) {
    let mut revoked = app.revoked.subscribe();
    let relay = async move {
        let Ok(tcp) = tokio::net::TcpStream::connect("127.0.0.1:5900").await else {
            return;
        };
        let (mut reader, mut writer) = tcp.into_split();
        let (mut sink, mut stream) = socket.split();
        let mut buf = vec![0u8; 65536];
        loop {
            tokio::select! {
                result=reader.read(&mut buf)=>match result {Ok(0)|Err(_)=>break,Ok(n)=>if sink.send(Message::Binary(buf[..n].to_vec())).await.is_err(){break}},
                msg=stream.next()=>match msg {Some(Ok(Message::Binary(bytes)))=>if writer.write_all(&bytes).await.is_err(){break},Some(Ok(Message::Ping(p)))=>if sink.send(Message::Pong(p)).await.is_err(){break},Some(Ok(Message::Close(_)))|None|Some(Err(_))=>break,_=>{}}
            }
        }
    };
    let cancellation = async {
        let mut timer = tokio::time::interval(Duration::from_secs(15));
        loop {
            {
                let i = app.inner.lock().await;
                if i.vnc_epoch != epoch || !authenticated(&i, &h, "vnc") {
                    break;
                }
            }
            tokio::select! {_=revoked.changed()=>{},_=timer.tick()=>{}}
        }
    };
    // Cancellation surrounds all relay I/O, including a peer stalled on writes.
    tokio::select! {_=relay=>{},_=cancellation=>{}}
}
