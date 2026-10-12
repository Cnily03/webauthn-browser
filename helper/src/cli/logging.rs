//! Standard tracing formatters and a bounded off-thread terminal sink.
use std::{
    io::{self, IsTerminal, Write},
    sync::OnceLock,
};
use tracing_appender::non_blocking::{NonBlocking, NonBlockingBuilder, WorkerGuard};

const MAX_RECORD: usize = 8192;
const QUEUED_RECORDS: usize = 256;
static OUTPUT: OnceLock<NonBlocking> = OnceLock::new();

/// Formatting stays on tracing-subscriber; only complete bounded records are queued.
struct Record {
    writer: NonBlocking,
    bytes: Vec<u8>,
    oversized: bool,
}
impl Record {
    fn new(writer: NonBlocking) -> Self {
        Self {
            writer,
            bytes: Vec::new(),
            oversized: false,
        }
    }
}
impl Write for Record {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.oversized {
            if self.bytes.len().saturating_add(bytes.len()) > MAX_RECORD {
                self.oversized = true;
                self.bytes.clear();
            } else {
                self.bytes.extend_from_slice(bytes);
            }
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for Record {
    fn drop(&mut self) {
        if !self.oversized {
            let _ = self.writer.write_all(&self.bytes);
        }
    }
}

/// One process-lifetime logging worker. Its queue is bounded and never owns HID,
/// pairing or authorization resources. Ordinary logs are best-effort at exit.
///
/// tracing-appender 0.2.5's WorkerGuard timeout prints synchronously to stdout;
/// dropping it can therefore hang even after its advertised shutdown timeout.
/// Keep the guard alive until process termination instead of entering that path.
/// No join/drain is required for consent or transport cleanup, and Rust can exit
/// while the sink's independent output handle is blocked by terminal flow control.
pub(super) struct Guard(Option<WorkerGuard>);
impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(guard) = self.0.take() {
            std::mem::forget(guard);
        }
    }
}
pub(super) fn write_text(text: &str) -> io::Result<()> {
    if let Some(writer) = OUTPUT.get() {
        let mut record = Record::new(writer.clone());
        record.write_all(text.as_bytes())
    } else {
        Err(io::Error::other("Terminal logging is not initialized"))
    }
}
pub(super) fn init() -> anyhow::Result<Guard> {
    let color = io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let (writer, guard) = NonBlockingBuilder::default()
        .buffered_lines_limit(QUEUED_RECORDS)
        .lossy(true)
        .thread_name("helper-terminal-logs")
        .finish(super::terminal_ui::RenderWriter);
    let _ = OUTPUT.set(writer.clone());
    webauthn_helper::logging::install(
        move || Record::new(writer.clone()),
        color,
        module_path!().rsplit_once("::").unwrap().0,
    )?;
    Ok(Guard(Some(guard)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn bounded_records_and_lossy_queue_never_block_transport() {
        struct Blocked(std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>);
        impl Write for Blocked {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let _ = self.1.send(());
                let _ = self.0.recv();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (release, blocked) = std::sync::mpsc::channel();
        let (entered, started) = std::sync::mpsc::channel();
        let (writer, guard) = NonBlockingBuilder::default()
            .buffered_lines_limit(2)
            .lossy(true)
            .finish(Blocked(blocked, entered));
        let errors = writer.error_counter();
        let mut record = Record::new(writer.clone());
        record.write_all(&[b'x'; MAX_RECORD + 1]).unwrap();
        assert!(record.oversized && record.bytes.len() <= MAX_RECORD);
        drop(record);
        writer.clone().write_all(b"first").unwrap();
        started.recv_timeout(Duration::from_secs(1)).unwrap();
        let before = std::time::Instant::now();
        for _ in 0..1000 {
            let mut record = Record::new(writer.clone());
            record.write_all(b"bounded record\n").unwrap();
        }
        assert!(before.elapsed() < Duration::from_secs(1));
        assert!(errors.dropped_lines() > 0);
        drop(Guard(Some(guard)));
        assert!(before.elapsed() < Duration::from_secs(2));
        drop(release); // Let the fake output thread finish, with no device operations.
    }
}
