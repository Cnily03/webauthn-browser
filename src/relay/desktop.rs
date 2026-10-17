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
    let epoch = crate::auth::vnc_epoch(&i, &h);
    drop(i);
    Ok(ws.on_upgrade(move |s| bridge(s, app, h, epoch)))
}
async fn bridge(socket: WebSocket, app: App, h: HeaderMap, epoch: u64) {
    let connection_id = if app.profiles.is_some() {
        let Some(id) = crate::profiles::viewer::connected(&app, &h).await else {
            return;
        };
        Some(id)
    } else {
        None
    };
    let mut revoked = app.revoked.subscribe();
    let relay = async {
        let Ok(tcp) = tokio::net::TcpStream::connect(("127.0.0.1", app.endpoints.vnc_port)).await
        else {
            return;
        };
        let (mut reader, mut writer) = tcp.into_split();
        let (mut sink, mut stream) = socket.split();
        let mut buf = vec![0u8; 65536];
        let mut filter = crate::profiles::rfb::Filter::new();
        loop {
            tokio::select! {
                result=reader.read(&mut buf)=>match result {Ok(0)|Err(_)=>break,Ok(n)=>if sink.send(Message::Binary(buf[..n].to_vec())).await.is_err(){break}},
                msg=stream.next()=>match msg {Some(Ok(Message::Binary(bytes)))=>{
                    let mut input_authority=app.revoked.subscribe();
                    let (output,is_input)=if app.profiles.is_some(){
                        let mut inner=app.inner.lock().await;
                        let owner=crate::profiles::viewer::socket_owner(&inner,&h);
                        let Ok((output,activity))=filter.push(&bytes,owner)else{break;};
                        if activity{crate::profiles::viewer::socket_activity(&mut inner,&h);}(output,activity)
                    }else{(bytes,false)};
                    if !output.is_empty(){
                        if is_input {
                            if !crate::profiles::viewer::socket_owner(&*app.inner.lock().await,&h){break;}
                            // Do not finish a backpressured input write after ownership changes.
                            let written=tokio::select!{biased;_=input_authority.changed()=>false,result=writer.write_all(&output)=>result.is_ok()};
                            if !written{break;}
                        }else if writer.write_all(&output).await.is_err(){break;}
                    }
                },Some(Ok(Message::Ping(p)))=>if sink.send(Message::Pong(p)).await.is_err(){break},Some(Ok(Message::Close(_)))|None|Some(Err(_))=>break,_=>{}}
            }
        }
    };
    let cancellation = async {
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        loop {
            {
                let i = app.inner.lock().await;
                if crate::auth::vnc_epoch(&i, &h) != epoch
                    || !authenticated(&i, &h, "vnc")
                    || app.profiles.is_some() && !crate::profiles::viewer::viewer_live(&i, &h)
                {
                    break;
                }
            }
            tokio::select! {_=revoked.changed()=>{},_=timer.tick()=>{}}
        }
    };
    // Cancellation surrounds all relay I/O, including a peer stalled on writes.
    tokio::select! {_=relay=>{},_=cancellation=>{}}
    if let Some(id) = connection_id {
        crate::profiles::viewer::disconnected(&app, &h, id).await;
    }
}
