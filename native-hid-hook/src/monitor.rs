//! Genuine libudev monitor adapter. The public readiness endpoint is a socket,
//! preserving SO_COOKIE identity tracking; a bounded worker forwards readiness,
//! never consumes genuine udev events or authenticator reports.
use super::*;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
type P = *mut c_void;
const LIMIT: usize = 16;
static GATE: Mutex<()> = Mutex::new(());
static LIVE_MONITORS: AtomicUsize = AtomicUsize::new(0);
static KEYS: [AtomicUsize; LIMIT] = [const { AtomicUsize::new(0) }; LIMIT];
static REGISTRY: OnceLock<Mutex<HashMap<usize, Arc<Monitor>>>> = OnceLock::new();
static mut FORK_GUARD: std::mem::MaybeUninit<MutexGuard<'static, ()>> =
    std::mem::MaybeUninit::uninit();
fn gate() -> MutexGuard<'static, ()> {
    GATE.lock().unwrap_or_else(|p| p.into_inner())
}
fn registry() -> MutexGuard<'static, HashMap<usize, Arc<Monitor>>> {
    REGISTRY
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}
pub unsafe fn before_fork() {
    (&raw mut FORK_GUARD).write(std::mem::MaybeUninit::new(gate()));
}
pub unsafe fn after_fork() {
    drop((&raw const FORK_GUARD).read().assume_init());
}
fn child_owned(p: P) -> bool {
    !p.is_null() && KEYS.iter().any(|k| k.load(Ordering::Acquire) == p as usize)
}
struct Resources {
    fds: [c_int; 4],
    identities: [fd::Capability; 4],
    real_fd: c_int,
}
impl Drop for Resources {
    fn drop(&mut self) {
        for identity in self.identities {
            fd::close_captured(identity);
        }
    }
}
struct Details {
    refs: usize,
    filtered: bool,
    hidraw: bool,
    suppress: bool,
    enabled: bool,
    resources: Option<Arc<Resources>>,
    events: VecDeque<(Arc<fd::Generation>, bool)>,
}
struct Monitor {
    pointer: usize,
    context: usize,
    details: Mutex<Details>,
    stopped: AtomicBool,
    failed: AtomicBool,
    pending: AtomicBool,
}
impl Drop for Monitor {
    fn drop(&mut self) {
        // Last Arc only drops outside registry/details locks. The extra real
        // monitor ref keeps its FD stable until its readiness worker exits.
        let monitor_unref = real!("udev_monitor_unref", unsafe extern "C" fn(P) -> P);
        let context_unref = real!("udev_unref", unsafe extern "C" fn(P) -> P);
        unsafe {
            monitor_unref(self.pointer as P);
            context_unref(self.context as P);
        }
        LIVE_MONITORS.fetch_sub(1, Ordering::AcqRel);
    }
}
fn details(m: &Monitor) -> MutexGuard<'_, Details> {
    m.details.lock().unwrap_or_else(|p| p.into_inner())
}
fn qualifies(d: &Details) -> bool {
    d.enabled && !d.suppress && (!d.filtered || d.hidraw)
}
fn token(fd: c_int, b: u8) -> bool {
    unsafe {
        libc::syscall(
            libc::SYS_sendto,
            fd,
            &b,
            1,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            0usize,
            0usize,
        ) == 1
    }
}
fn acknowledge(m: &Monitor, r: &Resources) {
    m.pending.store(false, Ordering::Release);
    let _ = token(r.fds[3], 1);
}
fn failed(m: &Monitor) {
    m.failed.store(true, Ordering::Release);
}
pub fn ready() -> bool {
    if fork_child() {
        return false;
    }
    let _gate = gate();
    registry().values().any(|m| {
        let d = details(m);
        if let Some(r) = &d.resources {
            if !fd::capability_valid(r.identities[0]) {
                failed(m);
            }
        }
        !m.failed.load(Ordering::Acquire) && qualifies(&d)
    })
}
pub fn publish(g: Arc<fd::Generation>, add: bool) -> bool {
    let _gate = gate();
    let mut count = 0;
    for m in registry().values() {
        let mut d = details(m);
        if !qualifies(&d) {
            continue;
        }
        if m.failed.load(Ordering::Acquire) || d.events.len() >= 32 {
            failed(m);
            return false;
        }
        let Some(r) = d.resources.clone() else {
            failed(m);
            return false;
        };
        // Hold the per-monitor lock until both token and event are committed;
        // a consumer cannot observe a synthetic token without its metadata.
        if !token(r.fds[1], b'S') {
            failed(m);
            return false;
        }
        d.events.push_back((g.clone(), add));
        count += 1;
    }
    count != 0
}
unsafe fn resources(real_fd: c_int) -> Option<Arc<Resources>> {
    // Called under RIGHTS -> GATE -> per-monitor lock, before any fd lock.
    let mut values = [-1; 4];
    for offset in [0, 2] {
        if libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
            values.as_mut_ptr().add(offset),
        ) < 0
        {
            for fd in values.into_iter().filter(|fd| *fd >= 0) {
                libc::syscall(libc::SYS_close, fd);
            }
            return None;
        }
    }
    for (index, value) in values.iter().copied().enumerate() {
        if !fd::register_capability(value) {
            for fd in &values[..index] {
                fd::close_capability(*fd);
            }
            for fd in &values[index..] {
                libc::syscall(libc::SYS_close, *fd);
            }
            return None;
        }
    }
    Some(Arc::new(Resources {
        fds: values,
        identities: values
            .map(|fd| fd::capture_capability(fd).expect("fresh registered capability")),
        real_fd,
    }))
}
fn worker(m: Arc<Monitor>, r: Arc<Resources>) {
    while !m.stopped.load(Ordering::Acquire) {
        let mut polls = [
            libc::pollfd {
                fd: if m.pending.load(Ordering::Acquire) {
                    -1
                } else {
                    r.real_fd
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: r.fds[2],
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe { libc::poll(polls.as_mut_ptr(), 2, 100) };
        if result < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            failed(&m);
            break;
        }
        if m.stopped.load(Ordering::Acquire) {
            break;
        }
        if polls
            .iter()
            .any(|p| p.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0)
        {
            failed(&m);
            break;
        }
        if polls[1].revents & libc::POLLIN != 0 {
            let mut bytes = [0u8; 32];
            // A bounded drain is enough: any remaining packet keeps poll ready.
            for _ in 0..32 {
                if unsafe {
                    libc::syscall(
                        libc::SYS_recvfrom,
                        r.fds[2],
                        bytes.as_mut_ptr(),
                        bytes.len(),
                        libc::MSG_DONTWAIT,
                        0usize,
                        0usize,
                    )
                } < 0
                {
                    break;
                }
            }
        }
        if polls[0].revents & libc::POLLIN != 0
            && !m.pending.swap(true, Ordering::AcqRel)
            && !token(r.fds[1], b'R')
        {
            failed(&m);
            break;
        }
    }
    // The worker keeps its extra genuine monitor ref until poll has stopped.
}
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_new_from_netlink(ctx: P, name: *const c_char) -> P {
    let real = real!(
        "udev_monitor_new_from_netlink",
        unsafe extern "C" fn(P, *const c_char) -> P
    );
    if !fd::controlled() {
        return real(ctx, name);
    }
    let _gate = gate();
    let p = real(ctx, name);
    let saved = errno();
    if p.is_null() {
        restore_errno(saved);
        return p;
    }
    let mut registry = registry();
    if registry.len() >= LIMIT || LIVE_MONITORS.load(Ordering::Acquire) >= LIMIT {
        restore_errno(saved);
        return p;
    }
    // The adapter owns an extra real ref, separate from the caller's refs.
    real!("udev_monitor_ref", unsafe extern "C" fn(P) -> P)(p);
    let ctx = real!("udev_ref", unsafe extern "C" fn(P) -> P)(ctx);
    LIVE_MONITORS.fetch_add(1, Ordering::AcqRel);
    let m = Arc::new(Monitor {
        pointer: p as usize,
        context: ctx as usize,
        details: Mutex::new(Details {
            refs: 1,
            filtered: false,
            hidraw: false,
            suppress: false,
            enabled: false,
            resources: None,
            events: VecDeque::new(),
        }),
        stopped: AtomicBool::new(false),
        failed: AtomicBool::new(false),
        pending: AtomicBool::new(false),
    });
    KEYS.iter()
        .find(|k| k.load(Ordering::Relaxed) == 0)
        .unwrap()
        .store(p as usize, Ordering::Release);
    registry.insert(p as usize, m);
    restore_errno(saved);
    p
}
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_enable_receiving(p: P) -> c_int {
    let real = real!(
        "udev_monitor_enable_receiving",
        unsafe extern "C" fn(P) -> c_int
    );
    if fork_child() {
        return if child_owned(p) {
            error(libc::ENODEV)
        } else {
            real(p)
        };
    }
    let _rights = control::rights_guard();
    let _gate = gate();
    let m = registry().get(&(p as usize)).cloned();
    let Some(m) = m else {
        return real(p);
    };
    let mut d = details(&m);
    let result = real(p);
    let saved = errno();
    if result < 0 {
        failed(&m);
        restore_errno(saved);
        return result;
    }
    let real_fd = real!("udev_monitor_get_fd", unsafe extern "C" fn(P) -> c_int)(p);
    if real_fd < 0 {
        failed(&m);
        restore_errno(saved);
        return result;
    }
    if d.resources.is_some() {
        restore_errno(saved);
        return result;
    }
    let flags = libc::syscall(libc::SYS_fcntl, real_fd, libc::F_GETFL) as c_int;
    if flags < 0 || flags & libc::O_NONBLOCK == 0 {
        failed(&m);
        restore_errno(saved);
        return result;
    }
    let Some(r) = resources(real_fd) else {
        failed(&m);
        restore_errno(saved);
        return result;
    };
    d.resources = Some(r.clone());
    let keep = m.clone();
    if std::thread::Builder::new()
        .name("uhf-udev-ready".into())
        .spawn(move || worker(keep, r))
        .is_err()
    {
        failed(&m);
        restore_errno(saved);
        return result;
    }
    d.enabled = true;
    restore_errno(saved);
    result
}
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_get_fd(p: P) -> c_int {
    let real = real!("udev_monitor_get_fd", unsafe extern "C" fn(P) -> c_int);
    if fork_child() {
        return if child_owned(p) {
            error(libc::ENODEV)
        } else {
            real(p)
        };
    }
    let _gate = gate();
    let m = registry().get(&(p as usize)).cloned();
    let Some(m) = m else {
        return real(p);
    };
    let d = details(&m);
    let value = real(p);
    let saved = errno();
    if value < 0 {
        failed(&m);
        restore_errno(saved);
        return value;
    }
    let result = if let Some(r) = &d.resources {
        if d.enabled {
            if value != r.real_fd {
                failed(&m);
                m.stopped.store(true, Ordering::Release);
                let _ = token(r.fds[3], 1);
                return error(libc::ENODEV);
            }
            if fd::pin_capability(r.identities[0]).is_none() {
                failed(&m);
                return error(libc::ENODEV);
            }
            r.fds[0]
        } else {
            value
        }
    } else {
        value
    };
    restore_errno(saved);
    result
}
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_ref(p: P) -> P {
    let real = real!("udev_monitor_ref", unsafe extern "C" fn(P) -> P);
    if fork_child() {
        if child_owned(p) {
            error(libc::ENODEV);
            return std::ptr::null_mut();
        }
        return real(p);
    }
    let _gate = gate();
    let m = registry().get(&(p as usize)).cloned();
    let Some(m) = m else {
        return real(p);
    };
    let mut d = details(&m);
    let result = real(p);
    if !result.is_null() {
        d.refs = d.refs.saturating_add(1);
    }
    result
}
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_unref(p: P) -> P {
    let real = real!("udev_monitor_unref", unsafe extern "C" fn(P) -> P);
    if fork_child() {
        if child_owned(p) {
            return std::ptr::null_mut();
        }
        return real(p);
    }
    let _gate = gate();
    let m = registry().get(&(p as usize)).cloned();
    let Some(m) = m else {
        return real(p);
    };
    let mut d = details(&m);
    let result = real(p);
    let saved = errno();
    d.refs -= 1;
    if d.refs == 0 {
        m.stopped.store(true, Ordering::Release);
        if let Some(r) = &d.resources {
            let _ = token(r.fds[3], 1);
        }
        for k in &KEYS {
            if k.load(Ordering::Relaxed) == p as usize {
                k.store(0, Ordering::Release);
            }
        }
        // Keep `m` alive until after the registry and per-monitor locks drop.
        registry().remove(&(p as usize));
    }
    let result = if d.refs == 0 {
        std::ptr::null_mut()
    } else {
        result
    };
    drop(d);
    restore_errno(saved);
    result
}
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_receive_device(p: P) -> P {
    let real = real!("udev_monitor_receive_device", unsafe extern "C" fn(P) -> P);
    if fork_child() {
        if child_owned(p) {
            error(libc::ENODEV);
            return std::ptr::null_mut();
        }
        return real(p);
    }
    let _gate = gate();
    let m = registry().get(&(p as usize)).cloned();
    let Some(m) = m else {
        return real(p);
    };
    let mut d = details(&m);
    let Some(r) = d.resources.clone() else {
        return real(p);
    };
    let Some(pin) = fd::pin_capability(r.identities[0]) else {
        failed(&m);
        error(libc::ENODEV);
        return std::ptr::null_mut();
    };
    // A terminal synthetic failure must not leave permanently-readable null
    // notifications. Drain at most the bounded synthetic queue, then keep
    // forwarding genuine readiness/events through the same public endpoint.
    for _ in 0..33 {
        let mut value = 0u8;
        let n = libc::syscall(
            libc::SYS_recvfrom,
            pin.fd,
            &mut value,
            1,
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            0usize,
            0usize,
        );
        if n == 1 && value == b'S' {
            let Some((g, add)) = d.events.pop_front() else {
                failed(&m);
                continue;
            };
            if m.failed.load(Ordering::Acquire) {
                continue;
            }
            drop(d);
            return udev::new_tree(
                m.context as P,
                0,
                Some(g),
                Some(if add { b"add\0" } else { b"remove\0" }),
            );
        }
        if n > 0 && (n != 1 || value != b'R') {
            failed(&m);
            continue;
        }
        if n < 0 && errno() != libc::EAGAIN {
            return std::ptr::null_mut();
        }
        break;
    }
    let result = real(p);
    let saved = errno();
    acknowledge(&m, &r);
    restore_errno(saved);
    result
}
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_filter_add_match_subsystem_devtype(
    p: P,
    sub: *const c_char,
    typ: *const c_char,
) -> c_int {
    let real = real!(
        "udev_monitor_filter_add_match_subsystem_devtype",
        unsafe extern "C" fn(P, *const c_char, *const c_char) -> c_int
    );
    if fork_child() {
        return if child_owned(p) {
            error(libc::ENODEV)
        } else {
            real(p, sub, typ)
        };
    }
    let _gate = gate();
    let m = registry().get(&(p as usize)).cloned();
    let Some(m) = m else {
        return real(p, sub, typ);
    };
    let mut d = details(&m);
    let result = real(p, sub, typ);
    if result == 0 {
        d.filtered = true;
        d.hidraw |= eq(sub, b"hidraw") && (typ.is_null() || eq(typ, b""));
    }
    result
}
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_filter_add_match_tag(p: P, tag: *const c_char) -> c_int {
    let real = real!(
        "udev_monitor_filter_add_match_tag",
        unsafe extern "C" fn(P, *const c_char) -> c_int
    );
    if fork_child() {
        return if child_owned(p) {
            error(libc::ENODEV)
        } else {
            real(p, tag)
        };
    }
    let _gate = gate();
    let m = registry().get(&(p as usize)).cloned();
    let Some(m) = m else {
        return real(p, tag);
    };
    let mut d = details(&m);
    let result = real(p, tag);
    if result == 0 {
        d.suppress = true;
    }
    result
}
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_filter_remove(p: P) -> c_int {
    let real = real!(
        "udev_monitor_filter_remove",
        unsafe extern "C" fn(P) -> c_int
    );
    if fork_child() {
        return if child_owned(p) {
            error(libc::ENODEV)
        } else {
            real(p)
        };
    }
    let _gate = gate();
    let m = registry().get(&(p as usize)).cloned();
    let Some(m) = m else {
        return real(p);
    };
    let mut d = details(&m);
    let result = real(p);
    if result == 0 {
        d.filtered = false;
        d.hidraw = false;
        d.suppress = false;
    }
    result
}
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_filter_update(p: P) -> c_int {
    let real = real!(
        "udev_monitor_filter_update",
        unsafe extern "C" fn(P) -> c_int
    );
    if fork_child() {
        return if child_owned(p) {
            error(libc::ENODEV)
        } else {
            real(p)
        };
    }
    // This call does not read or mutate adapter state. Some libudev versions
    // call this exported symbol through the PLT from enable_receiving, while
    // our outer enable wrapper already owns GATE and the monitor details lock.
    // Taking either lock here would deadlock on that legitimate reentry.
    // Keep the genuine API's lifetime/concurrency contract: callers retain their
    // monitor reference and serialize mutations; this passthrough adds no ref
    // or unlock window to the outer wrapper and preserves its error/errno.
    real(p)
}
