//! Opt-in metadata-only control loop. READY requires a successfully enabled
//! genuine monitor adapter, or an explicitly compiled simulation marked 129.
use super::*;
use crate::control_wire::{ControlSocket, Frame, Opcode};
use std::collections::HashSet;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::{Mutex, MutexGuard};

// Lock order is RIGHTS -> fd registry -> udev registry. recvmsg installs rights
// before returning, so this gate covers validation, rejection and registration.
static RIGHTS: Mutex<()> = Mutex::new(());
static mut FORK_GUARD: std::mem::MaybeUninit<MutexGuard<'static, ()>> =
    std::mem::MaybeUninit::uninit();
pub fn rights_guard() -> MutexGuard<'static, ()> {
    RIGHTS.lock().unwrap_or_else(|p| p.into_inner())
}
pub unsafe fn before_fork() {
    (&raw mut FORK_GUARD).write(std::mem::MaybeUninit::new(rights_guard()));
}
pub unsafe fn after_fork() {
    drop((&raw const FORK_GUARD).read().assume_init());
}
pub unsafe fn browser_epoch() -> Option<[u8; 16]> {
    let p = libc::getenv(c(b"UHF_BROWSER_EPOCH\0"));
    if p.is_null() {
        return None;
    }
    let bytes = std::ffi::CStr::from_ptr(p).to_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let mut result = [0u8; 16];
    for i in 0..16 {
        let digit = |b: u8| -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            }
        };
        result[i] = (digit(bytes[i * 2])? << 4) | digit(bytes[i * 2 + 1])?;
    }
    (result != [0; 16]).then_some(result)
}
pub fn now_ns() -> u64 {
    control_wire::monotonic_now_ns().unwrap_or(u64::MAX)
}
fn ack_flags() -> u8 {
    control_wire::FLAG_GENUINE_MONITOR
        | if cfg!(feature = "simulation") {
            control_wire::FLAG_SIMULATED
        } else {
            0
        }
}
struct Record {
    frame: Frame,
    active: bool,
}
struct Controller {
    browser: [u8; 16],
    hello: Option<Frame>,
    ready: bool,
    unavailable_sent: bool,
    highwater: u64,
    mode_highwater: u64,
    seen: HashSet<[u8; 16]>,
    gateway_seen: HashSet<[u8; 16]>,
    terminal: std::collections::HashMap<[u8; 16], Frame>,
    suspended: bool,
    current: Option<Record>,
}
fn same_identity(a: &Frame, b: &Frame) -> bool {
    a.gateway_epoch == b.gateway_epoch
        && a.browser_epoch == b.browser_epoch
        && a.attachment_id == b.attachment_id
        && a.device_generation == b.device_generation
        && a.mode_generation == b.mode_generation
}
impl Controller {
    fn reply(socket: &ControlSocket, mut frame: Frame, opcode: Opcode) -> bool {
        frame.opcode = opcode;
        frame.flags = if matches!(
            opcode,
            Opcode::Ready | Opcode::Prepared | Opcode::Active | Opcode::Renewed
        ) {
            ack_flags()
        } else {
            0
        };
        socket.send(&frame, None).is_ok()
    }
    fn revoke(&mut self) -> bool {
        if let Some(r) = self.current.take() {
            self.terminal.insert(r.frame.attachment_id, r.frame);
        }
        if let Some(g) = fd::revoke_generation() {
            return udev::publish(g, false);
        }
        true
    }
    fn tick(&mut self, socket: &ControlSocket) -> bool {
        let monitor_ready = udev::monitor_ready();
        if self.ready && !monitor_ready {
            // Monitor loss revokes its generation but does not destroy the
            // authenticated control scope; a later genuine monitor may Ready.
            self.revoke();
            self.ready = false;
        }
        if !self.ready && !monitor_ready && !self.suspended && !self.unavailable_sent {
            if let Some(hello) = self.hello.clone() {
                if !Self::reply(socket, hello, Opcode::Unavailable) {
                    return false;
                }
                self.unavailable_sent = true;
            }
        }
        if self
            .current
            .as_ref()
            .is_some_and(|r| r.frame.deadline_ns <= now_ns() || fd::generation_disconnected())
        {
            let previous = self.current.as_ref().unwrap().frame.clone();
            if !self.revoke() || !Self::reply(socket, previous, Opcode::Revoked) {
                return false;
            }
        }
        if !self.ready && !self.suspended && udev::monitor_ready() {
            if let Some(hello) = self.hello.clone() {
                if !Self::reply(socket, hello, Opcode::Ready) {
                    return false;
                }
                self.ready = true;
                self.unavailable_sent = false;
            }
        }
        true
    }
    fn accept(&mut self, socket: &ControlSocket, frame: Frame, report: Option<c_int>) -> bool {
        if frame.browser_epoch != self.browser {
            return false;
        }
        if frame.opcode == Opcode::Hello {
            // A changed epoch must actually be fresh for this browser owner.
            // Replaying an older gateway epoch must never reset its high-water
            // marks or rebind paths retained from an earlier scope.
            if self.gateway_seen.contains(&frame.gateway_epoch) || self.gateway_seen.len() >= 256 {
                return false;
            }
            self.gateway_seen.insert(frame.gateway_epoch);
            if self.current.is_some()
                || self
                    .hello
                    .as_ref()
                    .is_some_and(|h| h.gateway_epoch == frame.gateway_epoch)
            {
                return false;
            }
            if self
                .hello
                .as_ref()
                .is_some_and(|h| h.gateway_epoch != frame.gateway_epoch)
            {
                self.highwater = 0;
                self.mode_highwater = 0;
                self.seen.clear();
                self.terminal.clear();
                self.ready = false;
            }
            self.unavailable_sent = false;
            self.suspended = false;
            self.hello = Some(frame.clone());
            return self.tick(socket);
        }
        let Some(hello) = self.hello.as_ref() else {
            return false;
        };
        if frame.gateway_epoch != hello.gateway_epoch {
            return false;
        }
        if frame.opcode == Opcode::Unavailable {
            self.ready = false;
            self.suspended = true;
            return self.revoke();
        }
        if !self.ready {
            return false;
        }
        match frame.opcode {
            Opcode::Prepare => {
                if self.current.is_some()
                    || frame.device_generation <= self.highwater
                    || frame.mode_generation < self.mode_highwater
                    || self.seen.contains(&frame.attachment_id)
                    || self.seen.len() >= 256
                    || control_wire::bounded_deadline(frame.deadline_ns).is_err()
                {
                    return false;
                }
                let Some(fd) = report else {
                    return false;
                };
                if !fd::install_generation(
                    fd,
                    frame.device_generation,
                    frame.deadline_ns,
                    &frame.gateway_epoch,
                    &frame.attachment_id,
                ) {
                    return false;
                }
                self.highwater = frame.device_generation;
                self.mode_highwater = frame.mode_generation;
                self.seen.insert(frame.attachment_id);
                self.current = Some(Record {
                    frame: frame.clone(),
                    active: false,
                });
                Self::reply(socket, frame, Opcode::Prepared)
            }
            Opcode::Activate => {
                let Some(r) = self.current.as_mut() else {
                    return false;
                };
                if r.active
                    || !same_identity(&r.frame, &frame)
                    || r.frame.deadline_ns != frame.deadline_ns
                    || r.frame.deadline_ns <= now_ns()
                {
                    return false;
                }
                let Some(g) = fd::activate_generation(frame.device_generation) else {
                    return false;
                };
                r.active = true;
                if !udev::publish(g, true) {
                    return false;
                }
                Self::reply(socket, frame, Opcode::Active)
            }
            Opcode::Renew => {
                let Some(r) = self.current.as_mut() else {
                    return false;
                };
                if !r.active
                    || !same_identity(&r.frame, &frame)
                    || r.frame.deadline_ns <= now_ns()
                    || r.frame.lease_sequence.checked_add(1) != Some(frame.lease_sequence)
                    || frame.deadline_ns <= r.frame.deadline_ns
                    || control_wire::bounded_deadline(frame.deadline_ns).is_err()
                {
                    return false;
                }
                if !fd::renew_generation(frame.device_generation, frame.deadline_ns) {
                    return false;
                }
                r.frame = frame.clone();
                Self::reply(socket, frame, Opcode::Renewed)
            }
            Opcode::Revoke => {
                if self
                    .terminal
                    .get(&frame.attachment_id)
                    .is_some_and(|old| same_identity(old, &frame))
                {
                    return Self::reply(socket, frame, Opcode::Revoked);
                }
                let Some(r) = self.current.as_ref() else {
                    return false;
                };
                if !same_identity(&r.frame, &frame) {
                    return false;
                }
                if !self.revoke() {
                    return false;
                }
                Self::reply(socket, frame, Opcode::Revoked)
            }
            _ => false,
        }
    }
}
pub fn start() {
    let Some(original) = fd::control_fd() else {
        return;
    };
    let Some(browser) = (unsafe { browser_epoch() }) else {
        return;
    };
    // Before the thread exists, all rights gates and libc fork handlers exist.
    let gate = rights_guard();
    let copy =
        unsafe { libc::syscall(libc::SYS_fcntl, original, libc::F_DUPFD_CLOEXEC, 3) as c_int };
    if copy < 0 {
        return;
    }
    if !fd::register_capability(copy) {
        unsafe {
            libc::syscall(libc::SYS_close, copy);
        }
        return;
    }
    let socket = match ControlSocket::from_owned(unsafe { OwnedFd::from_raw_fd(copy) }) {
        Ok(s) => s,
        Err(_) => return,
    };
    drop(gate);
    let _ = std::thread::Builder::new()
        .name("uhf-control".into())
        .spawn(move || {
            let mut controller = Controller {
                browser,
                hello: None,
                ready: false,
                unavailable_sent: false,
                highwater: 0,
                mode_highwater: 0,
                seen: HashSet::new(),
                gateway_seen: HashSet::new(),
                terminal: Default::default(),
                suspended: false,
                current: None,
            };
            loop {
                if !controller.tick(&socket) {
                    break;
                }
                let received = {
                    let _gate = rights_guard();
                    match socket.receive() {
                        Ok((frame, report)) => {
                            let raw = if let Some(report) = report {
                                if !fd::register_capability(report.as_raw_fd()) {
                                    break;
                                }
                                Some(report.into_raw_fd())
                            } else {
                                None
                            };
                            Ok((frame, raw))
                        }
                        Err(error) => Err(error),
                    }
                };
                match received {
                    Ok((frame, raw)) => {
                        let okay = controller.accept(&socket, frame, raw);
                        // A successfully installed endpoint is generation-owned.
                        if let Some(raw) = raw {
                            if !fd::owns_report(raw) {
                                fd::close_capability(raw);
                            }
                        }
                        if !okay {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        let mut poll = libc::pollfd {
                            fd: socket.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        if unsafe { libc::poll(&mut poll, 1, 10) } < 0 && errno() != libc::EINTR {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            controller.revoke();
            unsafe {
                libc::syscall(libc::SYS_shutdown, socket.as_raw_fd(), libc::SHUT_RDWR);
            }
            fd::close_capability(original);
            // OwnedFd drops outside the fd registry lock.
        });
}
