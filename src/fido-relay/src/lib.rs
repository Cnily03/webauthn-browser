//! Fixed opaque FIDO reports and bounded transport endpoints. No RP, CTAP,
//! credential, authenticator policy, or authentication-result interpretation.
#[cfg(target_os = "linux")]
pub mod control;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::sync::{mpsc, watch};

pub const REPORT_BYTES: usize = 64;
/// CTAPHID fragmentation: one initialization plus up to 128 continuation reports.
/// At 64 bytes/report that carries (64-7)+128*(64-5)=7,609 payload bytes.
/// https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#message-and-packet-structure
pub const CTAPHID_MAX_REPORTS: usize = 1 + 128;
/// One complete maximum message plus an equally sized control/keepalive reserve.
/// Fixed 16,512 raw bytes per direction; overflow remains terminal, never replayed.
/// Keep aligned with web/src/FidoRelay.ts. Forwarding does not parse CTAPHID.
pub const QUEUE_CAPACITY: usize = 2 * CTAPHID_MAX_REPORTS;
pub const MAX_BATCH: usize = 8;
pub const MAX_WIRE_BYTES: usize = 2048;
pub const MAX_LEASE_MS: u64 = 30_000;
pub const VERSION: u8 = 1;

// Deliberately no Debug implementation: payloads must never enter diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct Report([u8; REPORT_BYTES]);
impl Report {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, RelayError> {
        Ok(Self(
            bytes.try_into().map_err(|_| RelayError::InvalidReport)?,
        ))
    }
    pub fn bytes(&self) -> &[u8; REPORT_BYTES] {
        &self.0
    }
}
impl Serialize for Report {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(self.0))
    }
}
impl<'de> Deserialize<'de> for Report {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() != 88 {
            return Err(serde::de::Error::custom("Expected one 64-byte report"));
        }
        let bytes = STANDARD
            .decode(&value)
            .map_err(|_| serde::de::Error::custom("Invalid report encoding"))?;
        if bytes.len() != REPORT_BYTES || STANDARD.encode(&bytes) != value {
            return Err(serde::de::Error::custom("Noncanonical report encoding"));
        }
        Self::from_slice(&bytes).map_err(|_| serde::de::Error::custom("Invalid report length"))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub sequence: u64,
    pub data: Report,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Wire {
    FidoOpen {
        version: u8,
        relay_id: String,
        remaining_ms: u64,
    },
    FidoReady {
        version: u8,
        relay_id: String,
    },
    FidoReport {
        version: u8,
        relay_id: String,
        sequence: u64,
        data: Report,
    },
    FidoClose {
        version: u8,
        relay_id: String,
    },
    FidoRenew {
        version: u8,
        relay_id: String,
        lease_sequence: u64,
        remaining_ms: u64,
    },
    FidoRenewed {
        version: u8,
        relay_id: String,
        lease_sequence: u64,
        remaining_ms: u64,
    },
}
impl Wire {
    pub fn relay_id(&self) -> &str {
        match self {
            Self::FidoOpen { relay_id, .. }
            | Self::FidoReady { relay_id, .. }
            | Self::FidoReport { relay_id, .. }
            | Self::FidoClose { relay_id, .. }
            | Self::FidoRenew { relay_id, .. }
            | Self::FidoRenewed { relay_id, .. } => relay_id,
        }
    }
    pub fn valid(&self) -> bool {
        let version = match self {
            Self::FidoOpen { version, .. }
            | Self::FidoReady { version, .. }
            | Self::FidoReport { version, .. }
            | Self::FidoClose { version, .. }
            | Self::FidoRenew { version, .. }
            | Self::FidoRenewed { version, .. } => *version,
        };
        version == VERSION
            && valid_id(self.relay_id())
            && match self {
                Self::FidoOpen { remaining_ms, .. } => (1..=MAX_LEASE_MS).contains(remaining_ms),
                Self::FidoRenew {
                    lease_sequence,
                    remaining_ms,
                    ..
                }
                | Self::FidoRenewed {
                    lease_sequence,
                    remaining_ms,
                    ..
                } => *lease_sequence > 0 && (1..=MAX_LEASE_MS).contains(remaining_ms),
                _ => true,
            }
    }
}
pub fn valid_id(id: &str) -> bool {
    (32..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayError {
    InvalidReport,
    Closed,
    Overflow,
    Sequence,
    Io,
}
impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::InvalidReport => "Invalid report",
                Self::Closed => "Relay closed",
                Self::Overflow => "Relay queue full",
                Self::Sequence => "Unexpected report sequence",
                Self::Io => "Relay I/O failed",
            }
        )
    }
}
impl std::error::Error for RelayError {}
#[derive(Clone, Default)]
pub struct Sequence(u64);
impl Sequence {
    pub fn accept(&mut self, sequence: u64) -> Result<(), RelayError> {
        if self.0 != sequence {
            return Err(RelayError::Sequence);
        }
        self.0 = self.0.checked_add(1).ok_or(RelayError::Sequence)?;
        Ok(())
    }
    pub fn frame(&mut self, data: Report) -> Result<Frame, RelayError> {
        let sequence = self.0;
        self.accept(sequence)?;
        Ok(Frame { sequence, data })
    }
}
pub struct Endpoint {
    outgoing: mpsc::Sender<Report>,
    incoming: mpsc::Receiver<Report>,
    canceled: watch::Receiver<bool>,
    cancel: watch::Sender<bool>,
}
pub fn endpoint_pair() -> (Endpoint, Endpoint) {
    let (a_tx, a_rx) = mpsc::channel(QUEUE_CAPACITY);
    let (b_tx, b_rx) = mpsc::channel(QUEUE_CAPACITY);
    let (cancel, canceled) = watch::channel(false);
    (
        Endpoint {
            outgoing: a_tx,
            incoming: b_rx,
            canceled: canceled.clone(),
            cancel: cancel.clone(),
        },
        Endpoint {
            outgoing: b_tx,
            incoming: a_rx,
            canceled,
            cancel,
        },
    )
}
impl Endpoint {
    pub fn is_closed(&self) -> bool {
        *self.canceled.borrow() || self.outgoing.is_closed()
    }
    pub fn close(&self) {
        self.cancel.send_replace(true);
    }
    pub fn send(&self, report: Report) -> Result<(), RelayError> {
        if self.is_closed() {
            return Err(RelayError::Closed);
        }
        self.outgoing.try_send(report).map_err(|error| {
            self.close();
            match error {
                mpsc::error::TrySendError::Full(_) => RelayError::Overflow,
                _ => RelayError::Closed,
            }
        })
    }
    pub fn try_receive(&mut self) -> Result<Option<Report>, RelayError> {
        if self.is_closed() {
            return Err(RelayError::Closed);
        }
        match self.incoming.try_recv() {
            Ok(report) => Ok(Some(report)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(_) => {
                self.close();
                Err(RelayError::Closed)
            }
        }
    }
    pub async fn receive(&mut self) -> Result<Report, RelayError> {
        if self.is_closed() {
            return Err(RelayError::Closed);
        }
        tokio::select! {biased;
            _=self.canceled.changed()=>Err(RelayError::Closed),
            report=self.incoming.recv()=>report.ok_or(RelayError::Closed),
        }
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(target_os = "linux")]
pub mod packet {
    use super::*;
    use std::{
        io,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
    };
    use tokio::io::unix::AsyncFd;
    /// Anonymous packet sockets only. No bind/listener, host device or kernel HID.
    pub fn pair() -> io::Result<(OwnedFd, AsyncFd<OwnedFd>)> {
        let mut fds = [-1; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                fds.as_mut_ptr(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let a = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let b = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        Ok((a, AsyncFd::new(b)?))
    }
    pub async fn receive(socket: &AsyncFd<OwnedFd>) -> io::Result<Report> {
        loop {
            let mut ready = socket.readable().await?;
            let result = ready.try_io(|fd| {
                let mut report = [0u8; REPORT_BYTES];
                let size = unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        report.as_mut_ptr().cast(),
                        REPORT_BYTES,
                        libc::MSG_TRUNC | libc::MSG_DONTWAIT,
                    )
                };
                if size < 0 {
                    return Err(io::Error::last_os_error());
                }
                if size != REPORT_BYTES as isize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Expected one complete FIDO report",
                    ));
                }
                Ok(Report(report))
            });
            if let Ok(result) = result {
                return result;
            }
        }
    }
    pub async fn send(socket: &AsyncFd<OwnedFd>, report: &Report) -> io::Result<()> {
        loop {
            let mut ready = socket.writable().await?;
            let result = ready.try_io(|fd| {
                let size = unsafe {
                    libc::send(
                        fd.as_raw_fd(),
                        report.bytes().as_ptr().cast(),
                        REPORT_BYTES,
                        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                    )
                };
                if size < 0 {
                    return Err(io::Error::last_os_error());
                }
                if size != REPORT_BYTES as isize {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Incomplete report send",
                    ));
                }
                Ok(())
            });
            if let Ok(result) = result {
                return result;
            }
        }
    }
    pub async fn bridge(
        socket: AsyncFd<OwnedFd>,
        mut endpoint: Endpoint,
    ) -> Result<(), RelayError> {
        loop {
            tokio::select! {biased;
                report=endpoint.receive()=>{let report=report?;tokio::select!{biased;_=endpoint.canceled.changed()=>return Err(RelayError::Closed),result=send(&socket,&report)=>result.map_err(|_|RelayError::Io)?,}},
                report=receive(&socket)=>{endpoint.send(report.map_err(|_|RelayError::Io)?)?;},
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_require_canonical_exact_length() {
        let report = Report::from_slice(&[7; 64]).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        assert!(serde_json::from_str::<Report>(&json).unwrap() == report);
        for size in [0, 1, 63, 65, 4096] {
            assert!(Report::from_slice(&vec![0; size]).is_err());
        }
        assert!(serde_json::from_str::<Report>("\"AQ==\"").is_err());
    }
    #[test]
    fn sequence_replay_gap_and_overflow_fail() {
        let mut s = Sequence::default();
        assert_eq!(s.accept(1), Err(RelayError::Sequence));
        assert!(s.accept(0).is_ok());
        assert_eq!(s.accept(0), Err(RelayError::Sequence));
        let mut s = Sequence(u64::MAX);
        assert_eq!(s.accept(u64::MAX), Err(RelayError::Sequence));
    }
    #[tokio::test]
    async fn opaque_bidirectional_and_drop_cancel() {
        let (mut a, mut b) = endpoint_pair();
        a.send(Report([1; 64])).unwrap();
        assert!(b.receive().await.unwrap() == Report([1; 64]));
        b.send(Report([2; 64])).unwrap();
        assert!(a.receive().await.unwrap() == Report([2; 64]));
        drop(b);
        assert_eq!(a.receive().await.err(), Some(RelayError::Closed));
    }
    // Public CTAPHID framing only: a maximum PING payload with no authenticator
    // semantics. Endpoint/bridge forwarding must preserve all 129 reports opaque.
    fn maximum_message() -> Vec<Report> {
        (0..CTAPHID_MAX_REPORTS)
            .map(|index| {
                let mut bytes = [index as u8; REPORT_BYTES];
                bytes[..4].copy_from_slice(&[1, 2, 3, 4]);
                if index == 0 {
                    bytes[4..7].copy_from_slice(&[0x81, 0x1d, 0xb9]);
                } else {
                    bytes[4] = (index - 1) as u8;
                }
                Report(bytes)
            })
            .collect()
    }
    #[tokio::test]
    async fn maximum_messages_burst_bidirectionally_then_continue_without_replay() {
        let (mut a, mut b) = endpoint_pair();
        let message = maximum_message();
        assert_eq!(message.len(), 129);
        assert_eq!(QUEUE_CAPACITY * REPORT_BYTES, 16_512);
        for _operation in 0..3 {
            // Fill both directions before either peer drains: two complete legal
            // messages model a response plus bounded control/keepalive headroom.
            for report in message.iter().cycle().take(QUEUE_CAPACITY) {
                a.send(report.clone()).unwrap();
                b.send(report.clone()).unwrap();
            }
            for report in message.iter().cycle().take(QUEUE_CAPACITY) {
                assert!(a.receive().await.unwrap() == *report);
                assert!(b.receive().await.unwrap() == *report);
            }
            assert!(a.try_receive().unwrap().is_none());
            assert!(b.try_receive().unwrap().is_none());
        }
        a.send(message[0].clone()).unwrap();
        a.close();
        assert_eq!(b.receive().await.err(), Some(RelayError::Closed));
        let (fresh, mut peer) = endpoint_pair();
        fresh.send(message[1].clone()).unwrap();
        assert!(peer.receive().await.unwrap() == message[1]);
        assert!(peer.try_receive().unwrap().is_none());
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn packet_bridge_preserves_maximal_burst_in_both_directions() {
        let (native, socket) = packet::pair().unwrap();
        let native = tokio::io::unix::AsyncFd::new(native).unwrap();
        let (mut endpoint, bridge) = endpoint_pair();
        let task = tokio::spawn(packet::bridge(socket, bridge));
        let message = maximum_message();
        for report in &message {
            packet::send(&native, report).await.unwrap();
        }
        for report in &message {
            let received = endpoint.receive().await.unwrap();
            assert!(received == *report);
        }
        for report in &message {
            endpoint.send(report.clone()).unwrap();
        }
        for report in &message {
            let received = packet::receive(&native).await.unwrap();
            assert!(received == *report);
        }
        endpoint.close();
        assert_eq!(task.await.unwrap(), Err(RelayError::Closed));
    }
    #[tokio::test]
    async fn full_queue_cancels_instead_of_dropping_or_replaying() {
        let (a, mut b) = endpoint_pair();
        for _ in 0..QUEUE_CAPACITY {
            a.send(Report([0; 64])).unwrap();
        }
        assert_eq!(a.send(Report([0; 64])), Err(RelayError::Overflow));
        assert_eq!(b.receive().await.err(), Some(RelayError::Closed));
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn real_packet_socket_roundtrip_and_malformed_boundary() {
        let (a, b) = packet::pair().unwrap();
        let a = tokio::io::unix::AsyncFd::new(a).unwrap();
        packet::send(&a, &Report([9; 64])).await.unwrap();
        assert!(packet::receive(&b).await.unwrap() == Report([9; 64]));
        use std::os::fd::AsRawFd;
        assert_eq!(
            unsafe {
                libc::send(
                    a.as_raw_fd(),
                    [0u8; 63].as_ptr().cast(),
                    63,
                    libc::MSG_NOSIGNAL,
                )
            },
            63
        );
        assert!(packet::receive(&b).await.is_err());
    }
}
