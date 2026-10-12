// SPDX-License-Identifier: MIT
// Linux-only, synchronous userspace FIDO control transport. This file deliberately
// depends only on std and libc so a preload hook can include the same wire code.
// It never reads, interprets, or logs authenticator reports.

use std::io;
use std::mem::{size_of, size_of_val, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

pub const FRAME_BYTES: usize = 96;
pub const MAGIC: [u8; 4] = *b"UFHC";
pub const VERSION: u8 = 1;
pub const FLAG_GENUINE_MONITOR: u8 = 1;
pub const FLAG_SIMULATED: u8 = 128;
pub const MAX_DEADLINE_NS: u64 = 30_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Opcode {
    Hello = 1,
    Ready = 2,
    Prepare = 3,
    Prepared = 4,
    Activate = 5,
    Active = 6,
    Revoke = 7,
    Revoked = 8,
    Unavailable = 9,
    Renew = 10,
    Renewed = 11,
}

impl TryFrom<u8> for Opcode {
    type Error = io::Error;

    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Ready),
            3 => Ok(Self::Prepare),
            4 => Ok(Self::Prepared),
            5 => Ok(Self::Activate),
            6 => Ok(Self::Active),
            7 => Ok(Self::Revoke),
            8 => Ok(Self::Revoked),
            9 => Ok(Self::Unavailable),
            10 => Ok(Self::Renew),
            11 => Ok(Self::Renewed),
            _ => Err(invalid("Unknown control opcode")),
        }
    }
}

/// Metadata only. All integer fields are unsigned big-endian on the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub opcode: Opcode,
    pub flags: u8,
    pub gateway_epoch: [u8; 16],
    pub browser_epoch: [u8; 16],
    pub attachment_id: [u8; 16],
    pub device_generation: u64,
    pub mode_generation: u64,
    pub deadline_ns: u64,
    pub lease_sequence: u64,
}

impl Frame {
    /// Structural validation only. Deadline freshness and connection identity
    /// belong to the state machine; an expired Revoke must remain decodable.
    pub fn validate(&self) -> io::Result<()> {
        let valid_flags = match self.opcode {
            Opcode::Ready | Opcode::Prepared | Opcode::Active | Opcode::Renewed => {
                self.flags == FLAG_GENUINE_MONITOR
                    || self.flags == (FLAG_GENUINE_MONITOR | FLAG_SIMULATED)
            }
            Opcode::Unavailable => self.flags == 0 || self.flags == FLAG_SIMULATED,
            _ => self.flags == 0,
        };
        if !valid_flags {
            return Err(invalid("Invalid control flags"));
        }
        if self.gateway_epoch == [0; 16] || self.browser_epoch == [0; 16] {
            return Err(invalid("Missing control epoch"));
        }
        match self.opcode {
            Opcode::Hello | Opcode::Ready | Opcode::Unavailable => {
                if self.attachment_id != [0; 16]
                    || self.device_generation != 0
                    || self.mode_generation != 0
                    || self.deadline_ns != 0
                    || self.lease_sequence != 0
                {
                    return Err(invalid("Noncanonical connection frame"));
                }
            }
            _ => {
                if self.attachment_id == [0; 16]
                    || self.device_generation == 0
                    || self.mode_generation == 0
                    || self.deadline_ns == 0
                {
                    return Err(invalid("Missing attachment identity"));
                }
                match self.opcode {
                    Opcode::Prepare | Opcode::Prepared | Opcode::Activate | Opcode::Active
                        if self.lease_sequence != 0 =>
                    {
                        return Err(invalid("Nonzero initial lease sequence"));
                    }
                    Opcode::Renew | Opcode::Renewed if self.lease_sequence == 0 => {
                        return Err(invalid("Missing renewal sequence"));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> io::Result<[u8; FRAME_BYTES]> {
        self.validate()?;
        let mut bytes = [0; FRAME_BYTES];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4] = VERSION;
        bytes[5] = self.opcode as u8;
        bytes[6] = self.flags;
        bytes[8..24].copy_from_slice(&self.gateway_epoch);
        bytes[24..40].copy_from_slice(&self.browser_epoch);
        bytes[40..56].copy_from_slice(&self.attachment_id);
        bytes[56..64].copy_from_slice(&self.device_generation.to_be_bytes());
        bytes[64..72].copy_from_slice(&self.mode_generation.to_be_bytes());
        bytes[72..80].copy_from_slice(&self.deadline_ns.to_be_bytes());
        bytes[80..88].copy_from_slice(&self.lease_sequence.to_be_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != FRAME_BYTES
            || bytes[..4] != MAGIC
            || bytes[4] != VERSION
            || bytes[7] != 0
            || bytes[88..96] != [0; 8]
        {
            return Err(invalid("Invalid control frame encoding"));
        }
        // Exact length was checked above, so each fixed-width conversion fits.
        let frame = Self {
            opcode: Opcode::try_from(bytes[5])?,
            flags: bytes[6],
            gateway_epoch: bytes[8..24].try_into().unwrap(),
            browser_epoch: bytes[24..40].try_into().unwrap(),
            attachment_id: bytes[40..56].try_into().unwrap(),
            device_generation: u64::from_be_bytes(bytes[56..64].try_into().unwrap()),
            mode_generation: u64::from_be_bytes(bytes[64..72].try_into().unwrap()),
            deadline_ns: u64::from_be_bytes(bytes[72..80].try_into().unwrap()),
            lease_sequence: u64::from_be_bytes(bytes[80..88].try_into().unwrap()),
        };
        frame.validate()?;
        Ok(frame)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// CLOCK_MONOTONIC uses the same clock as absolute lease deadlines.
pub fn monotonic_now_ns() -> io::Result<u64> {
    let mut time: libc::timespec = unsafe { zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u64::try_from(time.tv_sec).map_err(|_| invalid("Invalid monotonic time"))?;
    let nanos = u64::try_from(time.tv_nsec).map_err(|_| invalid("Invalid monotonic time"))?;
    if nanos >= 1_000_000_000 {
        return Err(invalid("Invalid monotonic time"));
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(nanos))
        .ok_or_else(|| invalid("Monotonic time overflow"))
}

/// Validate a future deadline bounded to thirty seconds from a supplied time.
/// Apply to Prepare/Renew at acceptance, not to revocation acknowledgements.
pub fn validate_deadline_at(deadline_ns: u64, now_ns: u64) -> io::Result<()> {
    let maximum = now_ns
        .checked_add(MAX_DEADLINE_NS)
        .ok_or_else(|| invalid("Deadline bound overflow"))?;
    if deadline_ns <= now_ns || deadline_ns > maximum {
        return Err(invalid("Deadline outside lease bound"));
    }
    Ok(())
}

pub fn bounded_deadline(deadline_ns: u64) -> io::Result<()> {
    validate_deadline_at(deadline_ns, monotonic_now_ns()?)
}

/// An explicitly imported, connected AF_UNIX SOCK_SEQPACKET endpoint.
/// All operations are nonblocking. Ownership guarantees cleanup on errors.
pub struct ControlSocket {
    fd: OwnedFd,
}

impl ControlSocket {
    pub fn pair() -> io::Result<(Self, Self)> {
        let mut fds = [-1; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // Both descriptors were created by the successful socketpair call.
        let first = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let second = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        Ok((Self { fd: first }, Self { fd: second }))
    }

    /// Validation precedes flag changes. No ambient descriptors are discovered.
    pub fn from_owned(fd: OwnedFd) -> io::Result<Self> {
        validate_packet_socket(fd.as_fd())?;
        set_owned_flags(&fd)?;
        Ok(Self { fd })
    }

    pub fn send(&self, frame: &Frame, report_fd: Option<BorrowedFd<'_>>) -> io::Result<()> {
        let bytes = frame.encode()?;
        if (frame.opcode == Opcode::Prepare) != report_fd.is_some() {
            return Err(invalid("Wrong control descriptor count"));
        }
        if let Some(fd) = report_fd {
            // A borrowed endpoint is validated but never reconfigured here.
            validate_packet_socket(fd)?;
        }
        let mut iov = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        // usize storage gives cmsghdr native alignment, unlike a byte array.
        let mut ancillary = [0usize; 4];
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        if let Some(fd) = report_fd {
            message.msg_control = ancillary.as_mut_ptr().cast();
            message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as _) } as usize;
            // The storage has space and alignment for one header and descriptor.
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as _) as usize;
                std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), fd.as_raw_fd());
            }
        }
        loop {
            let count = unsafe {
                libc::sendmsg(
                    self.as_raw_fd(),
                    &message,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if count != FRAME_BYTES as isize {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "Incomplete control send",
                ));
            }
            return Ok(());
        }
    }

    pub fn receive(&self) -> io::Result<(Frame, Option<OwnedFd>)> {
        let mut bytes = [0u8; FRAME_BYTES];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        // Deliberately bounded. On MSG_CTRUNC Linux closes excess SCM_RIGHTS
        // descriptors; every descriptor actually delivered is owned below.
        let mut ancillary = [0usize; 32];
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        let count = loop {
            message.msg_controllen = size_of_val(&ancillary);
            message.msg_flags = 0;
            let count = unsafe {
                libc::recvmsg(
                    self.as_raw_fd(),
                    &mut message,
                    libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC | libc::MSG_TRUNC,
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            break count;
        };
        // Collect ownership before rejecting *anything*, including the payload,
        // flags or unknown ancillary records. Dropping this vector closes all
        // installed descriptors on every rejection path.
        let (mut received, ancillary_valid) = unsafe { collect_rights(&message) };
        if !ancillary_valid
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || count != FRAME_BYTES as isize
        {
            return Err(invalid("Invalid control packet or ancillary data"));
        }
        let frame = Frame::decode(&bytes)?;
        let expected = usize::from(frame.opcode == Opcode::Prepare);
        if received.len() != expected {
            return Err(invalid("Wrong control descriptor count"));
        }
        let report_fd = received.pop();
        if let Some(fd) = report_fd.as_ref() {
            validate_packet_socket(fd.as_fd())?;
            set_owned_flags(fd)?;
        }
        Ok((frame, report_fd))
    }
}

impl AsRawFd for ControlSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for ControlSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

// The caller supplies an msghdr just filled by the kernel, backed by live,
// aligned storage. SCM_RIGHTS values returned by recvmsg are newly owned FDs.
unsafe fn collect_rights(message: &libc::msghdr) -> (Vec<OwnedFd>, bool) {
    let mut descriptors = Vec::new();
    let mut valid = true;
    let mut rights_records = 0;
    let mut offset = 0usize;
    let header_bytes = unsafe { libc::CMSG_LEN(0) } as usize;
    while offset < message.msg_controllen {
        let remaining = message.msg_controllen - offset;
        if remaining < size_of::<libc::cmsghdr>() {
            valid = false;
            break;
        }
        let header = unsafe {
            std::ptr::read_unaligned(
                message
                    .msg_control
                    .cast::<u8>()
                    .add(offset)
                    .cast::<libc::cmsghdr>(),
            )
        };
        if header.cmsg_len < header_bytes || header.cmsg_len > remaining {
            valid = false;
            break;
        }
        let payload_bytes = header.cmsg_len - header_bytes;
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            rights_records += 1;
            if payload_bytes == 0 || !payload_bytes.is_multiple_of(size_of::<RawFd>()) {
                valid = false;
            }
            for index in 0..payload_bytes / size_of::<RawFd>() {
                let fd = unsafe {
                    std::ptr::read_unaligned(
                        message
                            .msg_control
                            .cast::<u8>()
                            .add(offset + header_bytes + index * size_of::<RawFd>())
                            .cast::<RawFd>(),
                    )
                };
                if fd < 0 {
                    valid = false;
                } else {
                    descriptors.push(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
        } else {
            valid = false;
        }
        let aligned_len = (header.cmsg_len + size_of::<usize>() - 1) & !(size_of::<usize>() - 1);
        // A final record may omit trailing alignment padding.
        if aligned_len >= remaining {
            break;
        }
        offset += aligned_len;
    }
    (descriptors, valid && rights_records <= 1)
}

fn validate_packet_socket(fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut socket_type: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::c_int>() || socket_type != libc::SOCK_SEQPACKET {
        return Err(invalid("Expected a packet socket"));
    }
    for peer in [false, true] {
        let mut address: libc::sockaddr_storage = unsafe { zeroed() };
        let mut length = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let result = unsafe {
            if peer {
                libc::getpeername(
                    fd.as_raw_fd(),
                    (&mut address as *mut libc::sockaddr_storage).cast(),
                    &mut length,
                )
            } else {
                libc::getsockname(
                    fd.as_raw_fd(),
                    (&mut address as *mut libc::sockaddr_storage).cast(),
                    &mut length,
                )
            }
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if (length as usize) < size_of::<libc::sa_family_t>()
            || address.ss_family as libc::c_int != libc::AF_UNIX
        {
            return Err(invalid("Expected a connected Unix packet socket"));
        }
    }
    Ok(())
}

fn set_owned_flags(fd: &OwnedFd) -> io::Result<()> {
    let status = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if status < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, status | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(opcode: Opcode) -> Frame {
        let connection = matches!(opcode, Opcode::Hello | Opcode::Ready | Opcode::Unavailable);
        Frame {
            opcode,
            flags: if matches!(
                opcode,
                Opcode::Ready | Opcode::Prepared | Opcode::Active | Opcode::Renewed
            ) {
                FLAG_GENUINE_MONITOR
            } else {
                0
            },
            gateway_epoch: [1; 16],
            browser_epoch: [2; 16],
            attachment_id: if connection { [0; 16] } else { [3; 16] },
            device_generation: u64::from(!connection),
            mode_generation: u64::from(!connection),
            deadline_ns: if connection { 0 } else { 0x0102_0304_0506_0708 },
            lease_sequence: u64::from(matches!(opcode, Opcode::Renew | Opcode::Renewed)),
        }
    }

    fn raw_pair(kind: libc::c_int) -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, kind, 0, fds.as_mut_ptr()) },
            0
        );
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn raw_send(fd: BorrowedFd<'_>, bytes: &[u8], rights: &[RawFd]) {
        let mut iov = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        let mut ancillary = [0usize; 160];
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        if !rights.is_empty() {
            message.msg_control = ancillary.as_mut_ptr().cast();
            message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of_val(rights) as _) } as usize;
            assert!(message.msg_controllen <= size_of_val(&ancillary));
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(size_of_val(rights) as _) as usize;
                std::ptr::copy_nonoverlapping(
                    rights.as_ptr().cast::<u8>(),
                    libc::CMSG_DATA(header),
                    size_of_val(rights),
                );
            }
        }
        assert_eq!(
            unsafe {
                libc::sendmsg(
                    fd.as_raw_fd(),
                    &message,
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            },
            bytes.len() as isize
        );
    }

    #[test]
    fn canonical_wire_and_all_opcodes() {
        for opcode in 1..=11 {
            let original = frame(Opcode::try_from(opcode).unwrap());
            let encoded = original.encode().unwrap();
            assert_eq!(encoded.len(), 96);
            assert_eq!(
                &encoded[..8],
                &[b'U', b'F', b'H', b'C', 1, opcode, original.flags, 0]
            );
            assert_eq!(&encoded[72..80], &original.deadline_ns.to_be_bytes());
            assert_eq!(&encoded[80..88], &original.lease_sequence.to_be_bytes());
            assert_eq!(&encoded[88..96], &[0; 8]);
            assert_eq!(Frame::decode(&encoded).unwrap(), original);
        }
        let canonical = frame(Opcode::Prepare).encode().unwrap();
        for index in [0, 4, 5, 6, 7, 88, 95] {
            let mut bytes = canonical;
            bytes[index] = 255;
            assert!(Frame::decode(&bytes).is_err(), "index {index}");
        }
        for size in [0, 1, 95, 97, 192] {
            assert!(Frame::decode(&vec![0; size]).is_err());
        }
    }

    #[test]
    fn identities_flags_and_sequences_are_strict() {
        for opcode in 1..=11 {
            let mut value = frame(Opcode::try_from(opcode).unwrap());
            for flags in 0..=255 {
                value.flags = flags;
                let expected = match value.opcode {
                    Opcode::Ready | Opcode::Prepared | Opcode::Active | Opcode::Renewed => {
                        flags == 1 || flags == 129
                    }
                    Opcode::Unavailable => flags == 0 || flags == 128,
                    _ => flags == 0,
                };
                assert_eq!(value.encode().is_ok(), expected);
            }
            value = frame(value.opcode);
            value.gateway_epoch = [0; 16];
            assert!(value.encode().is_err());
            value = frame(value.opcode);
            value.browser_epoch = [0; 16];
            assert!(value.encode().is_err());
        }
        for opcode in [Opcode::Hello, Opcode::Ready, Opcode::Unavailable] {
            for field in 0..5 {
                let mut value = frame(opcode);
                match field {
                    0 => value.attachment_id = [9; 16],
                    1 => value.device_generation = 1,
                    2 => value.mode_generation = 1,
                    3 => value.deadline_ns = 1,
                    _ => value.lease_sequence = 1,
                }
                assert!(value.encode().is_err());
            }
        }
        for opcode in [
            Opcode::Prepare,
            Opcode::Prepared,
            Opcode::Activate,
            Opcode::Active,
            Opcode::Revoke,
            Opcode::Revoked,
            Opcode::Renew,
            Opcode::Renewed,
        ] {
            for field in 0..4 {
                let mut value = frame(opcode);
                match field {
                    0 => value.attachment_id = [0; 16],
                    1 => value.device_generation = 0,
                    2 => value.mode_generation = 0,
                    _ => value.deadline_ns = 0,
                }
                assert!(value.encode().is_err());
            }
        }
        for opcode in [
            Opcode::Prepare,
            Opcode::Prepared,
            Opcode::Activate,
            Opcode::Active,
        ] {
            let mut value = frame(opcode);
            value.lease_sequence = 1;
            assert!(value.encode().is_err());
        }
        for opcode in [Opcode::Renew, Opcode::Renewed] {
            let mut value = frame(opcode);
            value.lease_sequence = 0;
            assert!(value.encode().is_err());
        }
        for opcode in [Opcode::Revoke, Opcode::Revoked] {
            let mut value = frame(opcode);
            value.lease_sequence = u64::MAX;
            value.deadline_ns = 1;
            assert_eq!(Frame::decode(&value.encode().unwrap()).unwrap(), value);
        }
    }

    #[test]
    fn deadline_bounds_are_explicit_and_overflow_checked() {
        let now = 100;
        assert!(validate_deadline_at(now + 1, now).is_ok());
        assert!(validate_deadline_at(now + MAX_DEADLINE_NS, now).is_ok());
        for deadline in [0, now - 1, now, now + MAX_DEADLINE_NS + 1] {
            assert!(validate_deadline_at(deadline, now).is_err());
        }
        assert!(validate_deadline_at(u64::MAX, u64::MAX - 1).is_err());
        let now = monotonic_now_ns().unwrap();
        assert!(bounded_deadline(now + MAX_DEADLINE_NS).is_ok());
        // Decoder accepts expired deadlines. State-machine callers decide when
        // freshness is required and can always decode revocation after expiry.
        let mut expired = frame(Opcode::Revoke);
        expired.deadline_ns = 1;
        assert!(Frame::decode(&expired.encode().unwrap()).is_ok());
    }

    #[test]
    fn packet_roundtrip_and_descriptor_ownership() {
        let (a, b) = ControlSocket::pair().unwrap();
        assert_eq!(b.receive().err().unwrap().kind(), io::ErrorKind::WouldBlock);
        for socket in [&a, &b] {
            assert_ne!(
                unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
                0
            );
            assert_ne!(
                unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
        let hello = frame(Opcode::Hello);
        a.send(&hello, None).unwrap();
        let (received, descriptor) = b.receive().unwrap();
        assert_eq!(received, hello);
        assert!(descriptor.is_none());
        let (report, peer) = raw_pair(libc::SOCK_SEQPACKET);
        let prepare = frame(Opcode::Prepare);
        a.send(&prepare, Some(report.as_fd())).unwrap();
        let (received, descriptor) = b.receive().unwrap();
        assert_eq!(received, prepare);
        let descriptor = descriptor.unwrap();
        assert_ne!(descriptor.as_raw_fd(), report.as_raw_fd());
        assert_ne!(
            unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
        assert_ne!(
            unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        drop(report);
        // Descriptor transport did not consume anything from the report queue.
        let opaque = [0x5au8; 64];
        raw_send(peer.as_fd(), &opaque, &[]);
        let mut received = [0u8; 64];
        assert_eq!(
            unsafe {
                libc::recv(
                    descriptor.as_raw_fd(),
                    received.as_mut_ptr().cast(),
                    64,
                    libc::MSG_DONTWAIT,
                )
            },
            64
        );
        assert_eq!(received, opaque);
        assert!(a.send(&prepare, None).is_err());
        assert!(a.send(&hello, Some(descriptor.as_fd())).is_err());
        drop(b);
        assert!(a.send(&hello, None).is_err()); // MSG_NOSIGNAL keeps this process alive.
    }

    #[test]
    fn imports_validate_before_changing_shared_status_flags() {
        let (stream, _peer) = raw_pair(libc::SOCK_STREAM);
        let duplicate = unsafe { libc::dup(stream.as_raw_fd()) };
        assert!(duplicate >= 0);
        let before = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
        assert!(ControlSocket::from_owned(unsafe { OwnedFd::from_raw_fd(duplicate) }).is_err());
        assert_eq!(
            unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) },
            before
        );
        let (datagram, _peer) = raw_pair(libc::SOCK_DGRAM);
        assert!(ControlSocket::from_owned(datagram).is_err());
        let (packet, _peer) = raw_pair(libc::SOCK_SEQPACKET);
        let imported = ControlSocket::from_owned(packet).unwrap();
        assert_ne!(
            unsafe { libc::fcntl(imported.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
        assert_ne!(
            unsafe { libc::fcntl(imported.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }

    #[test]
    fn rejections_close_received_rights() {
        // Isolate process-wide FD counts from the other parallel unit tests.
        const CHILD: &str = "UFHC_CONTROL_FD_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let current = std::thread::current();
            let test_name = current.name().expect("Named unit-test thread");
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test_name, "--test-threads=1"])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        fn count_fds() -> usize {
            std::fs::read_dir("/proc/self/fd").unwrap().count()
        }
        let (sender, receiver) = ControlSocket::pair().unwrap();
        let (report, _peer) = raw_pair(libc::SOCK_SEQPACKET);
        let (stream, _peer) = raw_pair(libc::SOCK_STREAM);
        let baseline = count_fds();
        let prepare = frame(Opcode::Prepare).encode().unwrap();
        let hello = frame(Opcode::Hello).encode().unwrap();
        for size in [0, 1, 95, 97, 192] {
            raw_send(sender.as_fd(), &vec![0; size], &[report.as_raw_fd()]);
            assert!(receiver.receive().is_err());
            assert_eq!(count_fds(), baseline, "payload size {size}");
        }
        for (bytes, rights) in [
            (prepare, vec![]),
            (hello, vec![report.as_raw_fd()]),
            (prepare, vec![report.as_raw_fd(), report.as_raw_fd()]),
            (prepare, vec![report.as_raw_fd(); 253]), // MSG_CTRUNC
            (prepare, vec![stream.as_raw_fd()]),
        ] {
            raw_send(sender.as_fd(), &bytes, &rights);
            assert!(receiver.receive().is_err());
            assert_eq!(count_fds(), baseline);
        }
        let mut malformed = prepare;
        malformed[95] = 1;
        raw_send(sender.as_fd(), &malformed, &[report.as_raw_fd()]);
        assert!(receiver.receive().is_err());
        assert_eq!(count_fds(), baseline);
        // The kernel adds SCM_CREDENTIALS. Unknown ancillary must reject the
        // packet and still close SCM_RIGHTS even when it occurs after it.
        let enabled: libc::c_int = 1;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    receiver.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&enabled as *const libc::c_int).cast(),
                    size_of_val(&enabled) as _,
                )
            },
            0
        );
        raw_send(sender.as_fd(), &prepare, &[report.as_raw_fd()]);
        assert!(receiver.receive().is_err());
        assert_eq!(count_fds(), baseline);
    }
}
