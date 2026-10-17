//! Bounded, transient clipboard transport. Payloads are never retained in App,
//! the store, logs, URLs, or a replay queue. The private X11 service owns requests.
use crate::{
    app::App,
    auth::{authenticated, authorize},
    http::error::fail,
};
use axum::{
    extract::{ws::Message, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::{future::Future, io, time::Duration};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

const MAX_TEXT_BYTES: usize = 1024 * 1024;
// JSON can expand each control byte into a six-byte Unicode escape.
const MAX_WIRE_BYTES: usize = 6 * MAX_TEXT_BYTES + 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ClipboardError {
    Denied,
    Unavailable,
    TooLarge,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CopyFailure {
    Unavailable,
    TooLarge,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ClientMessage {
    ReadResult {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<ClipboardError>,
    },
    CopyResult {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<ClipboardError>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum RuntimeMessage {
    Read { id: String },
    Copy { id: String, text: String },
    CopyFailed { id: String, error: CopyFailure },
    Cancel { id: String },
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:".contains(&byte))
}

fn client_message(bytes: &[u8]) -> Option<String> {
    if bytes.len() > MAX_WIRE_BYTES {
        return None;
    }
    let message: ClientMessage = serde_json::from_slice(bytes).ok()?;
    match &message {
        ClientMessage::ReadResult { id, text, error }
            if valid_id(id)
                && (text.is_some() ^ error.is_some())
                && text
                    .as_ref()
                    .is_none_or(|text| text.len() <= MAX_TEXT_BYTES) => {}
        ClientMessage::CopyResult { id, .. } if valid_id(id) => {}
        _ => return None,
    }
    // Canonicalize before newline framing: a browser frame may contain pretty
    // printed JSON, but must never inject a second private-socket command.
    serde_json::to_string(&message).ok()
}

fn runtime_message(bytes: &[u8]) -> Option<String> {
    if bytes.len() > MAX_WIRE_BYTES {
        return None;
    }
    let message: RuntimeMessage = serde_json::from_slice(bytes).ok()?;
    match &message {
        RuntimeMessage::Read { id }
        | RuntimeMessage::Cancel { id }
        | RuntimeMessage::CopyFailed { id, .. }
            if valid_id(id) => {}
        RuntimeMessage::Copy { id, text } if valid_id(id) && text.len() <= MAX_TEXT_BYTES => {}
        _ => return None,
    }
    serde_json::to_string(&message).ok()
}

// The partial frame lives here so cancellation of next() by select! cannot
// discard a prefix. It is moved out, then dropped after the one delivery.
struct Frames<R> {
    reader: R,
    partial: Vec<u8>,
    limit: usize,
}
impl<R: AsyncBufRead + Unpin> Frames<R> {
    fn new(reader: R, limit: usize) -> Self {
        Self {
            reader,
            partial: Vec::new(),
            limit,
        }
    }

    async fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            let available = self.reader.fill_buf().await?;
            if available.is_empty() {
                return if self.partial.is_empty() {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let take = newline.unwrap_or(available.len());
            if self.partial.len().saturating_add(take) > self.limit {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.partial.extend_from_slice(&available[..take]);
            self.reader.consume(take + usize::from(newline.is_some()));
            if newline.is_some() {
                return Ok(Some(std::mem::take(&mut self.partial)));
            }
        }
    }
}

pub(crate) async fn websocket(
    State(app): State<App>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, (StatusCode, String)> {
    let inner = app.inner.lock().await;
    authorize(&inner, &headers, "vnc")?;
    let epoch = crate::auth::vnc_epoch(&inner, &headers);
    drop(inner);
    // Share the existing global stream budget; each connection has no queues.
    let permit = app
        .stream_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| fail(StatusCode::TOO_MANY_REQUESTS, "Too many live connections"))?;
    let path = app.endpoints.clipboard_path.clone();
    Ok(ws
        .max_message_size(MAX_WIRE_BYTES)
        .max_frame_size(MAX_WIRE_BYTES)
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_WIRE_BYTES + 1024)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            let transfer = async {
                let Ok(Ok(runtime)) =
                    tokio::time::timeout(IO_TIMEOUT, tokio::net::UnixStream::connect(path)).await
                else {
                    return;
                };
                let (sink, stream) = socket.split();
                relay(runtime, sink, stream, &app, &headers, epoch).await;
            };
            until_revoked(&app, &headers, epoch, transfer).await;
        }))
}

async fn still_authorized(app: &App, headers: &HeaderMap, epoch: u64) -> bool {
    let inner = app.inner.lock().await;
    crate::auth::vnc_epoch(&inner, headers) == epoch && authenticated(&inner, headers, "vnc")
}

async fn until_revoked<F: Future<Output = ()>>(
    app: &App,
    headers: &HeaderMap,
    epoch: u64,
    transfer: F,
) {
    let mut revoked = app.revoked.subscribe();
    let cancellation = async {
        let mut expiry = tokio::time::interval(Duration::from_secs(1));
        loop {
            if !still_authorized(app, headers, epoch).await {
                return;
            }
            tokio::select! {
                _ = revoked.changed() => {},
                _ = expiry.tick() => {},
            }
        }
    };
    // This includes connect() and sends blocked by either peer's backpressure.
    // Prefer revocation if a frame and the notification become ready together.
    tokio::select! { biased; _ = cancellation => {}, _ = transfer => {} }
}

async fn relay<R, S, I, E>(
    runtime: R,
    mut sink: S,
    mut stream: I,
    app: &App,
    headers: &HeaderMap,
    epoch: u64,
) where
    R: AsyncRead + AsyncWrite + Unpin,
    S: Sink<Message> + Unpin,
    I: Stream<Item = Result<Message, E>> + Unpin,
{
    let (reader, mut writer) = tokio::io::split(runtime);
    let mut frames = Frames::new(BufReader::new(reader), MAX_WIRE_BYTES);
    let from_runtime = async {
        loop {
            let Ok(Some(bytes)) = frames.next().await else {
                break;
            };
            let Some(text) = runtime_message(&bytes) else {
                break;
            };
            if !still_authorized(app, headers, epoch).await {
                break;
            }
            if !matches!(
                tokio::time::timeout(IO_TIMEOUT, sink.send(Message::Text(text))).await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
    };
    let from_browser = async {
        loop {
            let message = stream.next().await;
            if !still_authorized(app, headers, epoch).await {
                break;
            }
            match message {
                Some(Ok(Message::Text(text))) => {
                    let Some(mut text) = client_message(text.as_bytes()) else {
                        break;
                    };
                    text.push('\n');
                    if !matches!(
                        tokio::time::timeout(IO_TIMEOUT, writer.write_all(text.as_bytes())).await,
                        Ok(Ok(()))
                    ) {
                        break;
                    }
                }
                // axum/tungstenite responds to Ping automatically.
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                // Binary frames, protocol errors and closure terminate the
                // private connection; runtime cancels its pending request.
                _ => break,
            }
        }
    };
    // Independent directions allow a close frame to cancel an outbound write.
    // A stalled private reader is bounded too; neither direction has a queue.
    tokio::select! { _ = from_runtime => {}, _ = from_browser => {} }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::{Inner, Session},
        browser::broker::Broker,
        storage::{restore, store::Store},
    };
    use axum::{
        body::Body,
        http::{header, HeaderValue, Request},
    };
    use serde_json::json;
    use std::{collections::HashMap, sync::Arc, time::Instant};
    use tokio::{
        io::AsyncReadExt,
        sync::{watch, Mutex, Semaphore},
    };
    use tower::ServiceExt;

    struct Fixture {
        app: App,
        headers: HeaderMap,
        dir: std::path::PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("clipboard-test-{}", uuid::Uuid::new_v4()));
            let mut store = Store::open(dir.join("store.json")).unwrap();
            store.data.vnc_password_hash = Some("test-hash".into());
            let (revoked, _) = watch::channel(0);
            let app = App {
                profile_scope: false,
                profile_name: None,
                profile_id: std::sync::Arc::from("default"),
                endpoints: std::sync::Arc::new(crate::profiles::runtime::Endpoints::legacy()),
                profiles: None,
                inner: Arc::new(Mutex::new(Inner {
                    profile_viewers: std::collections::HashMap::new(),
                    viewer_tickets: std::collections::HashMap::new(),
                    store,
                    sessions: HashMap::from([(
                        "session".into(),
                        Session {
                            scope: "vnc".into(),
                            epoch: 0,
                            expires: Instant::now() + Duration::from_secs(60),
                        },
                    )]),
                    csrf: HashMap::new(),
                    vnc_epoch: 0,
                    settings_epoch: 0,
                    engine_connected: false,
                    engine_message: String::new(),
                    attempts: HashMap::new(),
                })),
                broker: Arc::new(Mutex::new(Broker::default())),
                revoked,
                operations: Arc::new(Mutex::new(())),
                stream_slots: Arc::new(Semaphore::new(2)),
                restore: Arc::new(Mutex::new(restore::Pending::default())),
                recovery_slots: Arc::new(Semaphore::new(1)),
                window_control: Arc::new(crate::browser::window_control::Controller::default()),
                fido_launcher: crate::relay::fido_launcher::Launcher::disabled(),
            };
            let mut headers = HeaderMap::new();
            headers.insert(header::HOST, HeaderValue::from_static("localhost:8080"));
            headers.insert(
                header::ORIGIN,
                HeaderValue::from_static("http://localhost:8080"),
            );
            headers.insert(header::COOKIE, HeaderValue::from_static("ab_vnc=session"));
            Self { app, headers, dir }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn strict_directional_protocol_and_lossless_unicode() {
        let text = "中文🙂\n\0\r\t";
        for message in [
            json!({"type":"read_result","id":"request-1","text":text}),
            json!({"type":"read_result","id":"request-1","text":""}),
            json!({"type":"read_result","id":"request-1","error":"denied"}),
            json!({"type":"read_result","id":"request-1","error":"unavailable"}),
            json!({"type":"copy_result","id":"request-1"}),
            json!({"type":"copy_result","id":"request-1","error":"too_large"}),
        ] {
            let canonical = client_message(message.to_string().as_bytes()).unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&canonical).unwrap(),
                message
            );
            assert!(!canonical.contains('\n'));
        }
        for message in [
            json!({"type":"read","id":"request-1"}),
            json!({"type":"copy","id":"request-1","text":text}),
            json!({"type":"copy_failed","id":"request-1","error":"unavailable"}),
            json!({"type":"copy_failed","id":"request-1","error":"too_large"}),
            json!({"type":"cancel","id":"request-1"}),
        ] {
            let canonical = runtime_message(message.to_string().as_bytes()).unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&canonical).unwrap(),
                message
            );
            assert!(!canonical.contains('\n'));
            assert!(client_message(message.to_string().as_bytes()).is_none());
        }
        // Formatting newlines are normalized, not forwarded as commands.
        assert!(client_message(b"{\n\"type\":\"copy_result\",\n\"id\":\"1\"\n}").is_some());
    }

    #[test]
    fn rejects_commands_unknown_fields_invalid_ids_and_ambiguous_results() {
        for message in [
            json!({"type":"execute","id":"1","command":"echo unwanted"}),
            json!({"type":"copy_result","id":"1","text":"unwanted"}),
            json!({"type":"copy_result","id":"1","error":"arbitrary"}),
            json!({"type":"copy_result","id":"1","destination":"other"}),
            json!({"type":"read_result","id":"1"}),
            json!({"type":"read_result","id":"1","text":"x","error":"denied"}),
            json!({"type":"read_result","id":"1","text":42}),
            json!({"type":"read_result","id":"","text":"x"}),
            json!({"type":"read_result","id":1,"text":"x"}),
            json!({"type":"read_result","id":"x\ny","text":"x"}),
            json!({"type":"read_result","id":"x".repeat(129),"text":"x"}),
        ] {
            assert!(client_message(message.to_string().as_bytes()).is_none());
        }
        assert!(client_message(b"{}\n{}").is_none());
        assert!(runtime_message(br#"{"type":"cancel","id":"1","text":"unwanted"}"#).is_none());
        assert!(runtime_message(br#"{"type":"read_result","id":"1","text":"unwanted"}"#).is_none());
        assert!(client_message(b"{\"type\":\"copy_result\",\"id\":\"\xff\"}").is_none());
        for message in [
            json!({"type":"copy_failed","id":"1","error":"denied"}),
            json!({"type":"copy_failed","id":"1","error":"arbitrary"}),
            json!({"type":"copy_failed","id":"1"}),
            json!({"type":"copy_failed","id":"1","error":"too_large","text":"secret"}),
            json!({"type":"copy_failed","id":"","error":"unavailable"}),
        ] {
            assert!(runtime_message(message.to_string().as_bytes()).is_none());
        }
    }

    #[test]
    fn bounds_utf8_text_and_worst_case_json_expansion() {
        let exact =
            json!({"type":"read_result","id":"1","text":"\0".repeat(MAX_TEXT_BYTES)}).to_string();
        assert!(exact.len() <= MAX_WIRE_BYTES);
        assert!(client_message(exact.as_bytes()).is_some());
        let oversized =
            json!({"type":"read_result","id":"1","text":"a".repeat(MAX_TEXT_BYTES+1)}).to_string();
        assert!(client_message(oversized.as_bytes()).is_none());
        let oversized_utf8 =
            json!({"type":"copy","id":"1","text":"🙂".repeat(MAX_TEXT_BYTES/4+1)}).to_string();
        assert!(runtime_message(oversized_utf8.as_bytes()).is_none());
        assert!(runtime_message(&vec![b' '; MAX_WIRE_BYTES + 1]).is_none());
    }

    #[tokio::test]
    async fn line_reader_preserves_partial_frames_when_cancelled_and_bounds_allocation() {
        let (mut peer, local) = tokio::io::duplex(64);
        let mut frames = Frames::new(BufReader::new(local), 8);
        peer.write_all(b"abc").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), frames.next())
                .await
                .is_err()
        );
        peer.write_all(b"def\n12\n").await.unwrap();
        assert_eq!(frames.next().await.unwrap().unwrap(), b"abcdef");
        assert_eq!(frames.next().await.unwrap().unwrap(), b"12");
        peer.write_all(b"123456789").await.unwrap();
        assert_eq!(
            frames.next().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(frames.partial.len() <= 8);
    }

    #[tokio::test]
    async fn line_reader_rejects_unterminated_eof() {
        let (mut peer, local) = tokio::io::duplex(64);
        let mut frames = Frames::new(BufReader::new(local), 64);
        peer.write_all(b"partial").await.unwrap();
        drop(peer);
        assert_eq!(
            frames.next().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn route_keeps_vnc_auth_without_origin_admission() {
        let fixture = Fixture::new();
        for (cookie, origin, expected) in [
            ("", "http://localhost:8080", StatusCode::UNAUTHORIZED),
            (
                "ab_vnc=session",
                "https://proxy.example:9443",
                StatusCode::BAD_REQUEST,
            ),
            ("ab_vnc=session", "null", StatusCode::BAD_REQUEST),
        ] {
            // An authenticated request reaches the WebSocket extractor, which
            // rejects the missing Connection: Upgrade header rather than its public Origin.
            let request = Request::builder()
                .uri("/api/clipboard/ws")
                .header(header::HOST, "localhost:8080")
                .header(header::ORIGIN, origin)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap();
            let response = crate::http::router(fixture.app.clone())
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
    }

    #[tokio::test]
    async fn epoch_or_session_revocation_cancels_stalled_io_and_releases_capacity() {
        for revoke_epoch in [false, true] {
            let fixture = Fixture::new();
            let app = fixture.app.clone();
            let headers = fixture.headers.clone();
            let permit = app.stream_slots.clone().try_acquire_owned().unwrap();
            let (mut peer, local) = tokio::io::duplex(1);
            let message =
                Message::Text(json!({"type":"read_result","id":"1","text":"abcdef"}).to_string());
            let task = tokio::spawn(async move {
                let _permit = permit;
                let stream = futures_util::stream::iter([Ok::<_, ()>(message)])
                    .chain(futures_util::stream::pending());
                let transfer = relay(
                    local,
                    futures_util::sink::drain(),
                    stream,
                    &app,
                    &headers,
                    0,
                );
                until_revoked(&app, &headers, 0, transfer).await;
            });
            // Runtime is not reading beyond one byte: the relay is stuck inside
            // write_all, rather than sitting at its outer select!.
            let mut first = [0];
            tokio::time::timeout(Duration::from_secs(1), peer.read_exact(&mut first))
                .await
                .unwrap()
                .unwrap();
            {
                let mut inner = fixture.app.inner.lock().await;
                if revoke_epoch {
                    inner.vnc_epoch += 1;
                } else {
                    inner.sessions.clear();
                }
            }
            fixture.app.revoked.send_modify(|value| *value += 1);
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(fixture.app.stream_slots.available_permits(), 2);
        }
    }

    #[tokio::test]
    async fn expired_sessions_cancel_without_a_revocation_notification() {
        let fixture = Fixture::new();
        fixture
            .app
            .inner
            .lock()
            .await
            .sessions
            .get_mut("session")
            .unwrap()
            .expires = Instant::now();
        tokio::time::timeout(
            Duration::from_millis(100),
            until_revoked(&fixture.app, &fixture.headers, 0, std::future::pending()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn browser_close_cancels_a_stalled_outbound_write() {
        let fixture = Fixture::new();
        let (local, mut remote) = tokio::io::duplex(4096);
        let sending = Arc::new(tokio::sync::Notify::new());
        let signal = sending.clone();
        let sink = Box::pin(futures_util::sink::unfold(
            signal,
            |signal, _message| async move {
                signal.notify_one();
                std::future::pending::<Result<Arc<tokio::sync::Notify>, ()>>().await
            },
        ));
        let (input, incoming) = tokio::sync::mpsc::unbounded_channel();
        let stream = Box::pin(futures_util::stream::unfold(
            incoming,
            |mut incoming| async move {
                incoming
                    .recv()
                    .await
                    .map(|message| (Ok::<_, ()>(message), incoming))
            },
        ));
        let app = fixture.app.clone();
        let headers = fixture.headers.clone();
        let task = tokio::spawn(async move {
            relay(local, sink, stream, &app, &headers, 0).await;
        });
        remote
            .write_all(b"{\"type\":\"copy\",\"id\":\"1\",\"text\":\"transient\"}\n")
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), sending.notified())
            .await
            .unwrap();
        input.send(Message::Close(None)).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(remote.read(&mut [0]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn relay_preserves_text_and_stops_on_invalid_client_frames() {
        let fixture = Fixture::new();
        let (local, remote) = tokio::io::duplex(4096);
        let (reader, mut writer) = tokio::io::split(remote);
        let mut remote_frames = Frames::new(BufReader::new(reader), MAX_WIRE_BYTES);
        let (output, mut received) = tokio::sync::mpsc::unbounded_channel();
        let sink = Box::pin(futures_util::sink::unfold(
            output,
            |output, message| async move {
                output.send(message).map_err(|_| ())?;
                Ok::<_, ()>(output)
            },
        ));
        let (input, incoming) = tokio::sync::mpsc::unbounded_channel();
        let stream = Box::pin(futures_util::stream::unfold(
            incoming,
            |mut incoming| async move {
                incoming
                    .recv()
                    .await
                    .map(|message| (Ok::<_, ()>(message), incoming))
            },
        ));
        let app = fixture.app.clone();
        let headers = fixture.headers.clone();
        let task = tokio::spawn(async move {
            relay(local, sink, stream, &app, &headers, 0).await;
        });
        let payload = json!({"type":"copy","id":"1","text":"中文🙂\nline2"});
        writer
            .write_all(format!("{payload}\n").as_bytes())
            .await
            .unwrap();
        let Message::Text(text) = received.recv().await.unwrap() else {
            panic!("expected text");
        };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text).unwrap(),
            payload
        );
        input
            .send(Message::Text(
                "{\n\"type\":\"copy_result\",\"id\":\"1\"\n}".into(),
            ))
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &remote_frames.next().await.unwrap().unwrap()
            )
            .unwrap(),
            json!({"type":"copy_result","id":"1"})
        );
        input.send(Message::Binary(vec![1, 2, 3])).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(remote_frames.next().await.unwrap().is_none());
    }
}
