//! Private native-messaging bridge. No TCP listener or page-accessible endpoint.
use anyhow::{bail, Context, Result};
use futures_util::FutureExt;
use serde_json::Value;
use std::{
    io::{Read, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    panic::AssertUnwindSafe,
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{mpsc, oneshot},
    time::{sleep, sleep_until, timeout, Instant},
};

pub const BRIDGE_BUILD: &str = "v29-global-mode-lease";
pub const MAX_MESSAGE: usize = 1024 * 1024;
pub const DEFAULT_SOCKET: &str = "/data/run/webauthn.sock";
const CONNECTION_IDLE: Duration = Duration::from_secs(20);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum ProxyEvent {
    Connected {
        outbound: mpsc::UnboundedSender<Value>,
    },
    Message(Value),
    Disconnected,
    Recovering(String),
}

/// Read a newline-delimited JSON record without permitting unbounded buffering.
async fn read_record<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    record: &mut Vec<u8>,
) -> Result<Option<Value>> {
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if record.is_empty() {
                return Ok(None);
            }
            bail!("truncated proxy record");
        }
        let end = available.iter().position(|b| *b == b'\n');
        let n = end.map_or(available.len(), |i| i + 1);
        if record.len() + n > MAX_MESSAGE + 1 {
            bail!("proxy record too large");
        }
        record.extend_from_slice(&available[..n]);
        reader.consume(n);
        if end.is_some() {
            return Ok(Some(serde_json::from_slice(&std::mem::take(record))?));
        }
    }
}

async fn write_record<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    value: &Value,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_MESSAGE {
        bail!("proxy record too large");
    }
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

// Never interpolate a browser-provided type or payload into diagnostics.
fn diagnostic_kind(value: &Value) -> &'static str {
    match value["type"].as_str() {
        Some("ready") => "ready",
        Some("ping") => "ping",
        Some("mode_ready") => "mode_ready",
        Some("mode_error") => "mode_error",
        Some("mode_progress") => "mode_progress",
        Some("mode_lease_ready") => "mode_lease_ready",
        Some("create") => "create",
        Some("get") => "get",
        Some("uvpaa") => "uvpaa",
        Some("cancel") => "cancel",
        Some("error") => "error",
        _ => "unknown",
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    events: &mpsc::UnboundedSender<ProxyEvent>,
    mut outbound: mpsc::UnboundedReceiver<Value>,
    idle: Duration,
) -> Result<()> {
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let mut record = Vec::new();
    let mut deadline = Instant::now() + idle;
    let mut last_kind = "none";
    let mut records = 0u64;
    loop {
        tokio::select! {
            incoming = read_record(&mut reader, &mut record) => match incoming? {
                Some(value) => {
                    deadline = Instant::now() + idle;
                    last_kind = diagnostic_kind(&value);
                    records = records.saturating_add(1);
                    events.send(ProxyEvent::Message(value)).context("broker closed")?;
                },
                None => return Ok(()),
            },
            value = outbound.recv() => match value {
                Some(value) => timeout(WRITE_TIMEOUT, write_record(&mut write, &value))
                    .await.context("native proxy write timed out")??,
                None => return Ok(()),
            },
            _ = sleep_until(deadline) => bail!("native proxy heartbeat timed out (idle={}s records={} last={} partial_bytes={})", idle.as_secs(), records, last_kind, record.len()),
        }
    }
}

fn retry_delay(attempt: u32) -> Duration {
    Duration::from_secs(1u64 << attempt.min(5)).min(Duration::from_secs(30))
}

/// A bound listener and the filesystem entry owned by this incarnation.
pub(crate) struct BoundListener {
    listener: UnixListener,
    identity: (u64, u64),
}

fn socket_identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

/// Initial binding runs before startup is acknowledged. The profile lifecycle
/// serializes initial owners; recovery may only replace its own stale entry.
pub(crate) async fn bind_listener(path: &Path) -> Result<BoundListener> {
    bind_listener_owned(path, None).await
}

async fn bind_listener_owned(path: &Path, previous: Option<(u64, u64)>) -> Result<BoundListener> {
    let parent = path.parent().context("socket has no parent")?;
    tokio::fs::create_dir_all(parent).await?;
    let metadata = tokio::fs::symlink_metadata(parent).await?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("invalid socket directory");
    }
    tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_socket() => {
            if previous.is_some_and(|identity| identity != socket_identity(&metadata)) {
                bail!("proxy socket belongs to another listener incarnation");
            }
            tokio::fs::remove_file(path).await?;
        }
        Ok(_) => bail!("refusing to replace non-socket proxy path"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(path)?;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    let identity = socket_identity(&tokio::fs::symlink_metadata(path).await?);
    Ok(BoundListener { listener, identity })
}

/// Recover the private listener without taking down the HTTP/settings service.
/// Retrying is rate-limited; each failed incarnation revokes its broker epoch.
#[cfg(test)]
pub async fn listen_with_recovery(
    path: impl AsRef<Path>,
    events: mpsc::UnboundedSender<ProxyEvent>,
) {
    recover_listener(path.as_ref(), events, None).await;
}

pub(crate) async fn listen_bound_with_recovery(
    path: impl AsRef<Path>,
    events: mpsc::UnboundedSender<ProxyEvent>,
    listener: BoundListener,
) {
    recover_listener(path.as_ref(), events, Some(listener)).await;
}

async fn recover_listener(
    path: &Path,
    events: mpsc::UnboundedSender<ProxyEvent>,
    mut listener: Option<BoundListener>,
) {
    let mut previous = listener.as_ref().map(|bound| bound.identity);
    let mut attempt = 0;
    loop {
        let started = Instant::now();
        let incarnation = async {
            let bound = match listener.take() {
                Some(bound) => bound,
                None => bind_listener_owned(path, previous).await?,
            };
            previous = Some(bound.identity);
            serve_listener(path, &bound, events.clone()).await
        };
        let outcome = tokio::select! {
            result = AssertUnwindSafe(incarnation).catch_unwind() => result,
            _ = events.closed() => return,
        };
        let message = match outcome {
            Ok(Ok(())) => "Native WebAuthn listener stopped".into(),
            Ok(Err(error)) => format!("Native WebAuthn listener unavailable: {error}"),
            Err(_) => "Native WebAuthn listener crashed".into(),
        };
        eprintln!("[native-proxy] {message}; recovering automatically");
        if events.send(ProxyEvent::Recovering(message)).is_err() {
            return;
        }
        if started.elapsed() >= Duration::from_secs(30) {
            attempt = 0;
        }
        let delay = retry_delay(attempt);
        attempt = attempt.saturating_add(1);
        tokio::select! {
            _ = sleep(delay) => {},
            _ = events.closed() => return,
        }
    }
}

#[cfg(test)]
pub async fn listen(
    path: impl AsRef<Path>,
    events: mpsc::UnboundedSender<ProxyEvent>,
) -> Result<()> {
    let path = path.as_ref();
    let bound = bind_listener(path).await?;
    serve_listener(path, &bound, events).await
}

async fn watch_socket_path(path: &Path, identity: (u64, u64)) -> Result<()> {
    loop {
        sleep(Duration::from_millis(250)).await;
        let metadata = tokio::fs::symlink_metadata(path)
            .await
            .context("private proxy socket path disappeared")?;
        if !metadata.file_type().is_socket() || socket_identity(&metadata) != identity {
            bail!("private proxy socket path was replaced");
        }
    }
}

/// One active bridge. A replacement invalidates all requests from its predecessor.
async fn serve_listener(
    path: &Path,
    bound: &BoundListener,
    events: mpsc::UnboundedSender<ProxyEvent>,
) -> Result<()> {
    // A Unix listener can keep accepting on its fd after its pathname is
    // unlinked. Detect that otherwise permanent ENOENT even with a live peer.
    tokio::select! {
        result = accept_connections(&bound.listener, &events) => result,
        result = watch_socket_path(path, bound.identity) => result,
        _ = events.closed() => Ok(()),
    }
}

async fn accept_connections(
    listener: &UnixListener,
    events: &mpsc::UnboundedSender<ProxyEvent>,
) -> Result<()> {
    let mut next = None;
    loop {
        let stream = match next.take() {
            Some(stream) => stream,
            None => listener.accept().await?.0,
        };
        let (outbound, receiver) = mpsc::unbounded_channel();
        events
            .send(ProxyEvent::Connected { outbound })
            .context("broker closed")?;
        let accepted = tokio::select! {
            result = serve(stream, events, receiver, CONNECTION_IDLE) => {
                if let Err(error) = result { eprintln!("native proxy disconnected: {error}"); }
                Ok(None)
            },
            incoming = listener.accept() => incoming.map(|(stream, _)| Some(stream)),
        };
        events
            .send(ProxyEvent::Disconnected)
            .context("broker closed")?;
        next = accepted?;
    }
}

fn read_native<R: Read>(input: &mut R) -> Result<Option<Value>> {
    let mut header = [0; 4];
    let first = input.read(&mut header[..1])?;
    if first == 0 {
        return Ok(None);
    }
    input.read_exact(&mut header[1..])?;
    let size = u32::from_le_bytes(header) as usize;
    if size == 0 || size > MAX_MESSAGE {
        bail!("invalid native message size");
    }
    let mut data = vec![0; size];
    input.read_exact(&mut data)?;
    Ok(Some(serde_json::from_slice(&data)?))
}

struct NativeFrame {
    bytes: Vec<u8>,
    completed: oneshot::Sender<std::io::Result<()>>,
}

// This must run on a detached OS thread, never Tokio's blocking pool. A pipe
// held open without a reader must not prevent runtime shutdown after a timeout.
fn write_native_frames<W: Write>(mut output: W, mut frames: mpsc::Receiver<NativeFrame>) {
    while let Some(frame) = frames.blocking_recv() {
        let result = output.write_all(&frame.bytes).and_then(|()| output.flush());
        let failed = result.is_err();
        if frame.completed.send(result).is_err() || failed {
            break;
        }
    }
}

fn spawn_native_writer<F, W>(output: F) -> mpsc::Sender<NativeFrame>
where
    F: FnOnce() -> W + Send + 'static,
    W: Write,
{
    let (sender, frames) = mpsc::channel(1);
    std::thread::spawn(move || write_native_frames(output(), frames));
    sender
}

async fn pump_host<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    mut input: mpsc::Receiver<Result<Value>>,
    output: mpsc::Sender<NativeFrame>,
    write_timeout: Duration,
) -> Result<()> {
    let (read, mut write) = tokio::io::split(stream);
    let to_broker = async {
        let mut first_ping = true;
        while let Some(value) = input.recv().await {
            let value = value?;
            let ping = value["type"] == "ping";
            timeout(write_timeout, write_record(&mut write, &value))
                .await
                .context("native host broker write timed out")??;
            if ping && first_ping {
                first_ping = false;
                eprintln!("[native-host] first heartbeat forwarded to broker");
            }
        }
        Ok(())
    };
    let to_browser = async {
        let mut reader = BufReader::new(read);
        let mut record = Vec::new();
        let mut first_pong = true;
        while let Some(value) = read_record(&mut reader, &mut record).await? {
            let mode = value["type"] == "mode";
            let pong = value["type"] == "pong" && first_pong;
            if mode {
                eprintln!("[native-host] mode frame received from broker");
            }
            if pong {
                eprintln!("[native-host] first heartbeat reply received");
            }
            let bytes = serde_json::to_vec(&value)?;
            if bytes.len() > MAX_MESSAGE {
                bail!("native response too large");
            }
            let mut framed = Vec::with_capacity(4 + bytes.len());
            framed.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            framed.extend_from_slice(&bytes);
            let (completed, acknowledgement) = oneshot::channel();
            // The deadline includes queue admission, all frame bytes, and flush.
            // Timeout terminates the host; a partial frame is never retried.
            timeout(write_timeout, async {
                output
                    .send(NativeFrame {
                        bytes: framed,
                        completed,
                    })
                    .await
                    .map_err(|_| anyhow::anyhow!("native stdout writer closed"))?;
                acknowledgement
                    .await
                    .context("native stdout writer stopped")??;
                Ok::<(), anyhow::Error>(())
            })
            .await
            .context("native host stdout write timed out")??;
            if mode {
                eprintln!("[native-host] mode frame written to browser");
            }
            if pong {
                first_pong = false;
                eprintln!("[native-host] first heartbeat reply written to browser");
            }
        }
        Ok(())
    };
    // Independent pumps: blocked browser stdout must not starve browser stdin
    // heartbeats. The first EOF/error cancels its peer and closes both queues.
    tokio::select! {
        result = to_broker => result,
        result = to_browser => result,
    }
}

/// Invoked only by the native host wrapper; stdout is exclusively framed JSON.
pub async fn run_host() -> Result<()> {
    eprintln!("[native-host] build={BRIDGE_BUILD}");
    let path = std::env::var("AUTH_BROWSER_PROXY_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.into());
    let stream = UnixStream::connect(path)
        .await
        .context("connect to private broker")?;
    let (tx, rx) = mpsc::channel(16);
    // Detached threads cannot hold Tokio runtime shutdown hostage on stdio.
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        loop {
            match read_native(&mut input) {
                Ok(Some(value)) => {
                    if tx.blocking_send(Ok(value)).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let _ = tx.blocking_send(Err(error));
                    break;
                }
            }
        }
    });
    let output = spawn_native_writer(|| std::io::stdout().lock());
    pump_host(stream, rx, output, WRITE_TIMEOUT).await
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn assert_backpressure_is_independent<S, B>(host: S, mut broker: B)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        let (input, incoming) = mpsc::channel(2);
        let (output, mut frames) = mpsc::channel(1);
        let task = tokio::spawn(pump_host(
            host,
            incoming,
            output,
            Duration::from_millis(100),
        ));
        write_record(
            &mut broker,
            &serde_json::json!({"type":"mode","mode":"native","generation":1}),
        )
        .await
        .unwrap();
        let frame = timeout(Duration::from_secs(1), frames.recv())
            .await
            .unwrap()
            .unwrap();
        // Holding the acknowledgement simulates stdout blocked mid-frame.
        input
            .send(Ok(serde_json::json!({"type":"ping","nonce":7})))
            .await
            .unwrap();
        let mut broker = BufReader::new(broker);
        let value = timeout(
            Duration::from_millis(80),
            read_record(&mut broker, &mut Vec::new()),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(value["type"], "ping");
        assert_eq!(value["nonce"], 7);
        let error = timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(
            error.to_string().contains("stdout write timed out"),
            "{error}"
        );
        // A late complete write cannot recover this abandoned frame/session.
        assert!(frame.completed.send(Ok(())).is_err());
        assert!(frames.recv().await.is_none());
        assert!(input
            .send(Ok(serde_json::json!({"type":"ping","nonce":8})))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn blocked_stdout_does_not_starve_input_and_times_out() {
        let (host, broker) = tokio::io::duplex(1024);
        assert_backpressure_is_independent(host, broker).await;
    }

    #[tokio::test]
    async fn socket_path_watch_detects_missing_and_replaced_entries() {
        let directory = std::env::temp_dir().join(format!("proxy-watch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("proxy.sock");
        let error = watch_socket_path(&path, (0, 0)).await.unwrap_err();
        assert!(error.to_string().contains("disappeared"));
        std::fs::write(&path, "preserve replacement").unwrap();
        let error = watch_socket_path(&path, (0, 0)).await.unwrap_err();
        assert!(error.to_string().contains("replaced"));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "preserve replacement"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires execution environment permitting loopback TCP; run with --ignored"]
    async fn tcp_host_output_backpressure_preserves_input_until_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let broker = listener.accept().await.unwrap().0;
        assert_backpressure_is_independent(host, broker).await;
    }

    #[tokio::test]
    async fn host_frames_are_acknowledged_in_order_and_eof_cancels_input() {
        let (host, mut broker) = tokio::io::duplex(1024);
        let (_input, incoming) = mpsc::channel(2);
        let (output, mut frames) = mpsc::channel(1);
        let task = tokio::spawn(pump_host(host, incoming, output, Duration::from_secs(1)));
        for nonce in 1..=2 {
            write_record(
                &mut broker,
                &serde_json::json!({"type":"pong","nonce":nonce}),
            )
            .await
            .unwrap();
        }
        let first = frames.recv().await.unwrap();
        assert_eq!(
            read_native(&mut first.bytes.as_slice()).unwrap().unwrap()["nonce"],
            1
        );
        assert!(
            frames.try_recv().is_err(),
            "second frame must wait for first flush acknowledgement"
        );
        first.completed.send(Ok(())).unwrap();
        let second = frames.recv().await.unwrap();
        assert_eq!(
            read_native(&mut second.bytes.as_slice()).unwrap().unwrap()["nonce"],
            2
        );
        second.completed.send(Ok(())).unwrap();
        drop(broker);
        assert!(timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_ok());
        assert!(frames.recv().await.is_none());
    }

    #[tokio::test]
    async fn stdout_writer_failure_terminates_without_retry() {
        let (host, mut broker) = tokio::io::duplex(1024);
        let (_input, incoming) = mpsc::channel(2);
        let (output, mut frames) = mpsc::channel(1);
        let task = tokio::spawn(pump_host(host, incoming, output, Duration::from_secs(1)));
        write_record(&mut broker, &serde_json::json!({"type":"mode"}))
            .await
            .unwrap();
        let frame = frames.recv().await.unwrap();
        frame
            .completed
            .send(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            )))
            .unwrap();
        assert!(timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(frames.recv().await.is_none());
    }

    #[test]
    #[ignore = "subprocess helper, invoked by blocked_stdout_thread_does_not_hold_process_open"]
    fn blocked_stdout_subprocess_helper() {
        if std::env::var_os("AUTH_BROWSER_TEST_BLOCKED_STDOUT").is_none() {
            return;
        }
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        struct PartialThenBlocked(Arc<AtomicUsize>);
        impl Write for PartialThenBlocked {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0.load(Ordering::SeqCst) == 0 {
                    let n = bytes.len().min(2);
                    self.0.store(n, Ordering::SeqCst);
                    return Ok(n);
                }
                loop {
                    std::thread::park();
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                panic!("partial frame cannot flush")
            }
        }
        let written = Arc::new(AtomicUsize::new(0));
        let writer_state = written.clone();
        // Use the production thread factory with a writer that never exits.
        let output = spawn_native_writer(move || PartialThenBlocked(writer_state));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (host, mut broker) = tokio::io::duplex(1024);
            let (_input, incoming) = mpsc::channel(1);
            write_record(&mut broker, &serde_json::json!({"type":"mode"}))
                .await
                .unwrap();
            let error = pump_host(host, incoming, output, Duration::from_millis(100))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("stdout write timed out"));
            assert_eq!(written.load(Ordering::SeqCst), 2);
        });
        drop(runtime);
        assert_eq!(written.load(Ordering::SeqCst), 2, "no partial-frame replay");
    }

    #[test]
    fn blocked_stdout_thread_does_not_hold_process_open() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "relay::native_proxy::tests::blocked_stdout_subprocess_helper",
                "--ignored",
            ])
            .env("AUTH_BROWSER_TEST_BLOCKED_STDOUT", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                let output = child.wait_with_output().unwrap();
                assert!(
                    status.success(),
                    "child failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("blocked detached stdout kept the native host process alive");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn detached_writer_finishes_short_writes_and_flushes_before_ack() {
        struct ShortWriter(std::sync::Arc<std::sync::Mutex<(Vec<u8>, bool)>>);
        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let n = bytes.len().min(2);
                self.0.lock().unwrap().0.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.lock().unwrap().1 = true;
                Ok(())
            }
        }
        let state = std::sync::Arc::new(std::sync::Mutex::new((Vec::new(), false)));
        let (sender, receiver) = mpsc::channel(1);
        let (completed, ack) = oneshot::channel();
        sender
            .blocking_send(NativeFrame {
                bytes: vec![1, 2, 3, 4, 5],
                completed,
            })
            .unwrap();
        drop(sender);
        write_native_frames(ShortWriter(state.clone()), receiver);
        ack.blocking_recv().unwrap().unwrap();
        assert_eq!(*state.lock().unwrap(), (vec![1, 2, 3, 4, 5], true));
    }

    #[test]
    fn diagnostic_message_kind_never_echoes_untrusted_data() {
        assert_eq!(
            diagnostic_kind(&serde_json::json!({"type":"ping","nonce":"secret"})),
            "ping"
        );
        assert_eq!(
            diagnostic_kind(&serde_json::json!({"type":"secret\nforged log","challenge":"secret"})),
            "unknown"
        );
        assert_eq!(diagnostic_kind(&serde_json::json!({"type":42})), "unknown");
    }

    #[test]
    fn listener_retries_are_exponential_and_capped() {
        let delays: Vec<_> = (0..8).map(|n| retry_delay(n).as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(retry_delay(u32::MAX), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn idle_connection_is_closed_without_a_browser_restart() {
        let (_browser, backend) = tokio::io::duplex(256);
        let (events, mut received) = mpsc::unbounded_channel();
        let (_outbound, receiver) = mpsc::unbounded_channel();
        let result = timeout(
            Duration::from_secs(1),
            serve(backend, &events, receiver, Duration::from_millis(20)),
        )
        .await
        .unwrap();
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("heartbeat timed out"));
        assert!(received.try_recv().is_err());
    }

    #[tokio::test]
    async fn timeout_diagnostics_describe_framing_without_payloads() {
        let (mut browser, backend) = tokio::io::duplex(256);
        let (events, mut received) = mpsc::unbounded_channel();
        let (_outbound, receiver) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            serve(backend, &events, receiver, Duration::from_millis(30)).await
        });
        browser
            .write_all(b"{\"type\":\"ping\",\"nonce\":123}\n")
            .await
            .unwrap();
        assert!(matches!(
            received.recv().await,
            Some(ProxyEvent::Message(_))
        ));
        browser.write_all(b"private-payload").await.unwrap();
        let error = timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("records=1 last=ping partial_bytes=15"),
            "{error}"
        );
        assert!(!error.contains("private-payload"));
        assert!(!error.contains("123"));
    }

    #[tokio::test]
    async fn complete_heartbeat_records_refresh_idle_deadline() {
        let (mut browser, backend) = tokio::io::duplex(256);
        let (events, mut received) = mpsc::unbounded_channel();
        let (_outbound, receiver) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            serve(backend, &events, receiver, Duration::from_millis(100)).await
        });
        for nonce in 0..4 {
            sleep(Duration::from_millis(40)).await;
            write_record(
                &mut browser,
                &serde_json::json!({"type":"ping","nonce":nonce}),
            )
            .await
            .unwrap();
            assert!(
                matches!(received.recv().await, Some(ProxyEvent::Message(value)) if value["nonce"] == nonce)
            );
            assert!(!task.is_finished());
        }
        drop(browser);
        assert!(timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    #[ignore = "requires an execution environment permitting Unix sockets; run with --ignored"]
    async fn removed_listener_path_recovers_with_and_without_connected_peer() {
        for connected in [false, true] {
            let directory =
                std::env::temp_dir().join(format!("proxy-unlink-{}", uuid::Uuid::new_v4()));
            let path = directory.join("proxy.sock");
            let bound = bind_listener(&path).await.unwrap();
            let (events, mut received) = mpsc::unbounded_channel();
            let task_path = path.clone();
            let task =
                tokio::spawn(
                    async move { listen_bound_with_recovery(task_path, events, bound).await },
                );
            let mut peer = None;
            let mut outbound = None;
            if connected {
                peer = Some(UnixStream::connect(&path).await.unwrap());
                match received.recv().await.unwrap() {
                    ProxyEvent::Connected { outbound: sender } => outbound = Some(sender),
                    _ => panic!("expected connection"),
                }
            }
            std::fs::remove_file(&path).unwrap();
            let event = timeout(Duration::from_secs(2), received.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(event, ProxyEvent::Recovering(_)));
            if let Some(outbound) = outbound {
                assert!(outbound.is_closed());
            }
            let replacement = timeout(Duration::from_secs(3), async {
                loop {
                    if let Ok(stream) = UnixStream::connect(&path).await {
                        break stream;
                    }
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert!(matches!(
                received.recv().await.unwrap(),
                ProxyEvent::Connected { .. }
            ));
            drop(received);
            timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
            drop((peer, replacement));
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "requires an execution environment permitting Unix sockets; run with --ignored"]
    async fn recovery_never_unlinks_a_successor_socket() {
        let directory =
            std::env::temp_dir().join(format!("proxy-successor-{}", uuid::Uuid::new_v4()));
        let path = directory.join("proxy.sock");
        let old = bind_listener(&path).await.unwrap();
        std::fs::rename(&path, directory.join("old.sock")).unwrap();
        let successor = bind_listener(&path).await.unwrap();
        assert!(watch_socket_path(&path, old.identity).await.is_err());
        let error = match bind_listener_owned(&path, Some(old.identity)).await {
            Ok(_) => panic!("recovery replaced successor"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("another listener"));
        assert_eq!(
            socket_identity(&std::fs::metadata(&path).unwrap()),
            successor.identity
        );
        let stream = UnixStream::connect(&path).await.unwrap();
        let accepted = successor.listener.accept().await.unwrap();
        drop((old, successor, stream, accepted));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn failed_listener_reports_recovery_and_stops_when_broker_closes() {
        let directory =
            std::env::temp_dir().join(format!("webauthn-recovery-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("proxy.sock");
        std::fs::write(&path, "do not replace").unwrap();
        let (events, mut received) = mpsc::unbounded_channel();
        let task_path = path.clone();
        let task = tokio::spawn(async move { listen_with_recovery(task_path, events).await });
        let event = timeout(Duration::from_secs(1), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(event, ProxyEvent::Recovering(message) if message.contains("non-socket")));
        assert!(!task.is_finished());
        let retry_started = Instant::now();
        let retried = timeout(Duration::from_secs(3), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(retried, ProxyEvent::Recovering(_)));
        assert!(retry_started.elapsed() >= Duration::from_millis(900));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "do not replace");
        drop(received);
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn native_frames_are_bounded_and_strict() {
        let bytes = b"{\"type\":\"cancel\",\"requestId\":7}";
        let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(bytes);
        assert_eq!(
            read_native(&mut frame.as_slice()).unwrap().unwrap()["requestId"],
            7
        );
        assert!(read_native(&mut &[][..]).unwrap().is_none());
        assert!(read_native(&mut &[1, 0][..]).is_err());
        assert!(read_native(&mut ((MAX_MESSAGE + 1) as u32).to_le_bytes().as_slice()).is_err());
        assert!(read_native(&mut &[2, 0, 0, 0, b'{'][..]).is_err());
    }
    #[tokio::test]
    async fn records_reject_oversize_and_truncation() {
        assert!(
            read_record(&mut BufReader::new(&b"{}"[..]), &mut Vec::new())
                .await
                .is_err()
        );
        let oversized = vec![b' '; MAX_MESSAGE + 2];
        assert!(
            read_record(&mut BufReader::new(oversized.as_slice()), &mut Vec::new())
                .await
                .is_err()
        );
        assert_eq!(
            read_record(
                &mut BufReader::new(&b"{\"ok\":true}\n"[..]),
                &mut Vec::new()
            )
            .await
            .unwrap()
            .unwrap()["ok"],
            true
        );
    }
    #[tokio::test]
    async fn partial_record_survives_future_cancellation() {
        use tokio::time::{timeout, Duration};
        let (mut writer, reader) = tokio::io::duplex(256);
        let mut reader = BufReader::new(reader);
        let mut record = Vec::new();
        writer.write_all(b"{\"type\":").await.unwrap();
        assert!(timeout(
            Duration::from_millis(10),
            read_record(&mut reader, &mut record)
        )
        .await
        .is_err());
        assert_eq!(record, b"{\"type\":");
        writer.write_all(b"\"cancel\"}\n").await.unwrap();
        assert_eq!(
            read_record(&mut reader, &mut record)
                .await
                .unwrap()
                .unwrap()["type"],
            "cancel"
        );
        assert!(record.is_empty());
    }

    #[tokio::test]
    async fn listener_refuses_non_socket_and_symlink_paths() {
        let directory = std::env::temp_dir().join(format!(
            "webauthn-browser-proxy-path-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("proxy.sock");
        std::fs::write(&path, "preserve me").unwrap();
        let (tx, _) = mpsc::unbounded_channel();
        assert!(listen(&path, tx)
            .await
            .unwrap_err()
            .to_string()
            .contains("non-socket"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "preserve me");
        std::fs::remove_file(&path).unwrap();
        let link = directory.join("linked");
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        let (tx, _) = mpsc::unbounded_channel();
        assert!(listen(link.join("proxy.sock"), tx)
            .await
            .unwrap_err()
            .to_string()
            .contains("invalid socket directory"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an execution environment permitting Unix sockets; run with --ignored"]
    async fn private_socket_replacement_invalidates_old_connection() {
        use tokio::time::{timeout, Duration};
        let directory =
            std::env::temp_dir().join(format!("webauthn-browser-proxy-{}", uuid::Uuid::new_v4()));
        let path = directory.join("proxy.sock");
        let (tx, mut events) = mpsc::unbounded_channel();
        let task_path = path.clone();
        let listener = tokio::spawn(async move { listen(task_path, tx).await });
        timeout(Duration::from_secs(2), async {
            while !path.exists() {
                if listener.is_finished() {
                    return false;
                }
                tokio::task::yield_now().await;
            }
            true
        })
        .await
        .inspect(|ready| {
            if !ready {
                eprintln!("private socket listener exited before readiness");
            }
        })
        .unwrap();
        if listener.is_finished() {
            panic!("private socket listener failed: {:?}", listener.await);
        }
        let mut first = UnixStream::connect(&path).await.unwrap();
        let outbound = match events.recv().await.unwrap() {
            ProxyEvent::Connected { outbound } => outbound,
            _ => panic!("expected initial connection"),
        };
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        first.write_all(b"{\"type\":\"ready\"}\n").await.unwrap();
        assert!(
            matches!(events.recv().await.unwrap(), ProxyEvent::Message(value) if value["type"] == "ready")
        );
        // A partial record must survive an outgoing response winning select!.
        first.write_all(b"{\"type\":").await.unwrap();
        outbound.send(serde_json::json!({"type":"probe"})).unwrap();
        let mut first_reader = BufReader::new(first);
        assert_eq!(
            read_record(&mut first_reader, &mut Vec::new())
                .await
                .unwrap()
                .unwrap()["type"],
            "probe"
        );
        first_reader
            .get_mut()
            .write_all(b"\"cancel\",\"requestId\":1}\n")
            .await
            .unwrap();
        assert!(
            matches!(events.recv().await.unwrap(), ProxyEvent::Message(value) if value["requestId"] == 1)
        );
        let second = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            events.recv().await.unwrap(),
            ProxyEvent::Disconnected
        ));
        assert!(matches!(
            events.recv().await.unwrap(),
            ProxyEvent::Connected { .. }
        ));
        assert!(outbound.send(serde_json::json!({"type":"stale"})).is_err());
        drop(second);
        assert!(matches!(
            events.recv().await.unwrap(),
            ProxyEvent::Disconnected
        ));
        listener.abort();
        let _ = listener.await;
        std::fs::remove_dir_all(directory).unwrap();
    }
}
