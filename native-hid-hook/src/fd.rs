use super::*;
use libc::{mode_t, size_t, ssize_t};
use std::{
    collections::HashMap,
    sync::{atomic::AtomicU64, Arc, Mutex, MutexGuard, Weak},
};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    cookie: u64,
}
unsafe fn identity(fd: c_int) -> Option<Identity> {
    let mut st: libc::stat = std::mem::zeroed();
    if libc::syscall(libc::SYS_fstat, fd, &mut st) != 0 {
        return None;
    }
    let mut cookie: u64 = 0;
    let mut len = std::mem::size_of_val(&cookie) as libc::socklen_t;
    if libc::syscall(
        libc::SYS_getsockopt,
        fd,
        libc::SOL_SOCKET,
        libc::SO_COOKIE,
        &mut cookie,
        &mut len,
    ) != 0
        || len as usize != std::mem::size_of_val(&cookie)
    {
        return None;
    }
    Some(Identity {
        dev: st.st_dev,
        ino: st.st_ino,
        cookie,
    })
}
struct Config {
    fd: c_int,
    identity: Identity,
    controlled: bool,
}
static CONFIG: OnceLock<Option<Config>> = OnceLock::new();
fn config() -> Option<&'static Config> {
    // Environment parsing and mutation are confined to the loader constructor.
    // Interposed calls before it runs must not initialize a different owner.
    CONFIG.get().and_then(Option::as_ref)
}
unsafe fn positive_decimal(s: *const c_char) -> Option<c_int> {
    if s.is_null() {
        return None;
    }
    let raw = std::ffi::CStr::from_ptr(s).to_str().ok()?;
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: c_int = raw.parse().ok()?;
    (value > 0).then_some(value)
}
// Constructor only. Preserve an inherited marker even when it is invalid:
// allowing a different PID to replace it would re-enable a fork/exec child.
// This is cooperative process ownership, not an anti-tampering boundary.
// Same-PID exec with intentionally retained aliases, environment manipulation,
// and untracked raw duplication are outside this ownership contract.
unsafe fn claim_owner() -> bool {
    let name = c(b"UHF_OWNER_PID\0");
    let pid = libc::getpid();
    let existing = libc::getenv(name);
    if !existing.is_null() {
        return positive_decimal(existing) == Some(pid);
    }
    let mut value = [0u8; 12];
    let mut start = value.len() - 1;
    let mut remaining = pid as u32;
    loop {
        start -= 1;
        value[start] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    // setenv may allocate, which is permitted here before main, never in the
    // atfork callbacks. Never overwrite even if another constructor set it.
    libc::setenv(name, value.as_ptr().add(start).cast(), 0) == 0
        && positive_decimal(libc::getenv(name)) == Some(pid)
}
unsafe fn initial_config() -> Option<Config> {
    if !eq(libc::getenv(c(b"UHF_ENABLE\0")), b"1") {
        return None;
    }
    let relay = libc::getenv(c(b"UHF_RELAY_FD\0"));
    let control = libc::getenv(c(b"UHF_CONTROL_FD\0"));
    if !relay.is_null() && !control.is_null() {
        return None;
    }
    let controlled = !control.is_null();
    if controlled && super::control::browser_epoch().is_none() {
        return None;
    }
    let fd = positive_decimal(if controlled { control } else { relay })?;
    if fd < 3 {
        return None;
    }
    let mut kind: c_int = 0;
    let mut n = std::mem::size_of_val(&kind) as libc::socklen_t;
    if libc::getsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_TYPE,
        (&mut kind as *mut c_int).cast(),
        &mut n,
    ) != 0
        || kind != libc::SOCK_SEQPACKET
    {
        return None;
    }
    let mut addr: libc::sockaddr_storage = std::mem::zeroed();
    let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
    if libc::getpeername(
        fd,
        (&mut addr as *mut libc::sockaddr_storage).cast(),
        &mut len,
    ) != 0
        || addr.ss_family as c_int != libc::AF_UNIX
    {
        return None;
    }
    let identity = identity(fd)?;
    if !claim_owner() {
        return None;
    }
    // The launcher intentionally retains the relay across the initial exec.
    // Once loaded, the original must not survive another ordinary exec. This
    // does not change the caller-requested CLOEXEC flags of virtual aliases.
    let flags = libc::syscall(libc::SYS_fcntl, fd, libc::F_GETFD) as c_int;
    if flags < 0 || libc::syscall(libc::SYS_fcntl, fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0
    {
        return None;
    }
    if controlled {
        let flags = libc::syscall(libc::SYS_fcntl, fd, libc::F_GETFL) as c_int;
        if flags < 0
            || libc::syscall(libc::SYS_fcntl, fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0
        {
            return None;
        }
    }
    Some(Config {
        fd,
        identity,
        controlled,
    })
}
pub fn enabled() -> bool {
    !fork_child() && config().is_some()
}
pub fn initialize() {
    let saved = errno();
    let _ = CONFIG.set(unsafe { initial_config() });
    let _unused = state();
    restore_errno(saved);
}
pub fn control_fd() -> Option<c_int> {
    config().filter(|c| c.controlled).map(|c| c.fd)
}
pub fn controlled() -> bool {
    !fork_child() && control_fd().is_some()
}

/// Generation metadata is immutable and stays alive with udev and FD handles.
/// No owned descriptor Drop runs while the registry mutex is held.
pub struct Generation {
    pub number: u64,
    pub paths: [std::ffi::CString; 3],
    pub node: std::ffi::CString,
    pub descriptor: std::ffi::CString,
    pub unique: std::ffi::CString,
    fd: c_int,
    identity: Identity,
    live: AtomicBool,
    deadline: AtomicU64,
}
impl Generation {
    pub fn live(&self) -> bool {
        self.live.load(Ordering::Acquire)
            && super::control::now_ns() < self.deadline.load(Ordering::Acquire)
    }
}
pub fn visible_generation() -> Option<Arc<Generation>> {
    if !controlled() {
        return None;
    }
    let s = state();
    s.generation
        .as_ref()
        .filter(|g| s.visible && g.live())
        .cloned()
}
pub fn register_capability(fd: c_int) -> bool {
    let mut s = state();
    sweep(&mut s);
    let Some(identity) = (unsafe { identity(fd) }) else {
        return false;
    };
    let Some(slot) = capability_slot(&s, Some(fd)) else {
        return false;
    };
    s.capabilities[slot] = Some(PinIdentity { fd, identity });
    true
}
pub fn close_capability(fd: c_int) {
    let mut s = state();
    if let Some(expected) = unsafe { capability_identity(&s, fd) } {
        unsafe {
            close_matching(fd, expected);
        }
    }
    forget_capability(&mut s, fd);
}
pub fn install_generation(
    fd: c_int,
    number: u64,
    deadline: u64,
    gateway: &[u8; 16],
    attachment: &[u8; 16],
) -> bool {
    let mut s = state();
    if s.generation.is_some() {
        return false;
    }
    let Some(identity) = (unsafe { capability_identity(&s, fd) }) else {
        return false;
    };
    let key = gateway
        .iter()
        .chain(attachment.iter())
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let base = format!("/sys/devices/virtual/userland-fido/{key}/g{number}/usb0");
    let g = Arc::new(Generation {
        number,
        paths: [
            format!("{base}/hid0/hidraw0"),
            format!("{base}/hid0"),
            base.clone(),
        ]
        .map(|p| std::ffi::CString::new(p).unwrap()),
        node: std::ffi::CString::new(format!("/dev/userland-fido-{key}-g{number}")).unwrap(),
        descriptor: std::ffi::CString::new(format!("{base}/hid0/report_descriptor")).unwrap(),
        unique: std::ffi::CString::new(format!("userspace-{key}-generation-{number}")).unwrap(),
        fd,
        identity,
        live: AtomicBool::new(true),
        deadline: AtomicU64::new(deadline),
    });
    s.generation = Some(g);
    s.visible = false;
    true
}
pub fn owns_report(fd: c_int) -> bool {
    state().generation.as_ref().is_some_and(|g| g.fd == fd)
}
pub fn generation_disconnected() -> bool {
    let s = state();
    let Some(g) = &s.generation else {
        return false;
    };
    if unsafe { identity(g.fd) } != Some(g.identity) {
        return true;
    }
    let mut p = libc::pollfd {
        fd: g.fd,
        events: libc::POLLHUP | libc::POLLRDHUP,
        revents: 0,
    };
    unsafe {
        libc::poll(&mut p, 1, 0) < 0
            || p.revents & (libc::POLLHUP | libc::POLLRDHUP | libc::POLLERR | libc::POLLNVAL) != 0
    }
}
pub fn activate_generation(number: u64) -> Option<Arc<Generation>> {
    let mut s = state();
    let g = s.generation.as_ref()?.clone();
    if g.number != number || !g.live() || s.visible {
        return None;
    }
    s.visible = true;
    Some(g)
}
pub fn renew_generation(number: u64, deadline: u64) -> bool {
    let s = state();
    let Some(g) = s.generation.as_ref() else {
        return false;
    };
    if g.number != number || !g.live() || !s.visible {
        return false;
    }
    g.deadline.store(deadline, Ordering::Release);
    true
}
pub fn revoke_generation() -> Option<Arc<Generation>> {
    let mut s = state();
    let g = s.generation.take()?;
    // Retained udev trees and HID aliases may outlive this registry entry.
    // Their shared terminal marker must flip before the endpoint is released.
    g.live.store(false, Ordering::Release);
    unsafe {
        // Shutdown wakes already-started operations and makes retained raw
        // aliases unusable; hooked aliases also retain the terminal marker.
        if identity(g.fd) == Some(g.identity) {
            libc::syscall(libc::SYS_shutdown, g.fd, libc::SHUT_RDWR);
            close_matching(g.fd, g.identity);
        }
    }
    for slot in &mut s.capabilities {
        if slot.is_some_and(|p| p.fd == g.fd && p.identity == g.identity) {
            *slot = None;
        }
    }
    s.active = Weak::new();
    let was_visible = std::mem::replace(&mut s.visible, false);
    was_visible.then_some(g)
}
struct Session {
    identity: Identity,
    access: c_int,
    rx: Mutex<()>,
    generation: Option<Arc<Generation>>,
}
const MAX_PINS: usize = 256;
const MAX_CAPABILITY_ALIASES: usize = 256;
#[derive(Clone, Copy)]
struct PinIdentity {
    fd: c_int,
    identity: Identity,
}
struct State {
    fds: HashMap<c_int, Arc<Session>>,
    active: Weak<Session>,
    generation: Option<Arc<Generation>>,
    visible: bool,
    // No growth or allocation is required to inspect in-flight operations in
    // the child. Each occupied slot remains owned until its Pinned is dropped.
    pins: [Option<PinIdentity>; MAX_PINS],
    // Ordinary libc duplicates of the original relay remain ordinary sockets,
    // but their inherited capabilities must also be closed in fork children.
    capabilities: [Option<PinIdentity>; MAX_CAPABILITY_ALIASES],
}
impl Default for State {
    fn default() -> Self {
        Self {
            fds: HashMap::new(),
            active: Weak::new(),
            generation: None,
            visible: false,
            pins: [None; MAX_PINS],
            capabilities: [None; MAX_CAPABILITY_ALIASES],
        }
    }
}
static STATE: OnceLock<Mutex<State>> = OnceLock::new();
fn state() -> MutexGuard<'static, State> {
    STATE
        .get_or_init(|| Mutex::new(State::default()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}
// Freeze the registries at libc fork so the child never inherits a half-
// modified map. Child callbacks close only identity-matching owned sockets,
// then release the already-held guards without freeing any registry contents.
static mut FORK_GUARD: std::mem::MaybeUninit<MutexGuard<'static, State>> =
    std::mem::MaybeUninit::uninit();
pub unsafe fn before_fork() {
    (&raw mut FORK_GUARD).write(std::mem::MaybeUninit::new(state()));
}
pub unsafe fn after_fork() {
    drop((&raw const FORK_GUARD).read().assume_init());
}
pub unsafe fn close_child_fds() {
    let saved = errno();
    let guard = &raw const FORK_GUARD;
    let s = (*guard).assume_init_ref();
    if let Some(cfg) = config() {
        close_matching(cfg.fd, cfg.identity);
    }
    for (&fd, session) in &s.fds {
        close_matching(fd, session.identity);
    }
    for pin in s.pins.iter().flatten() {
        close_matching(pin.fd, pin.identity);
    }
    for alias in s.capabilities.iter().flatten() {
        close_matching(alias.fd, alias.identity);
    }
    // Keep all entries and Arc ownership untouched: other parent threads may
    // have held the only live Pinned/session references at the fork snapshot.
    restore_errno(saved);
}
unsafe fn child_virtual(fd: c_int) -> bool {
    // Only a libc-fork child has a consistent, unlocked map snapshot. The
    // launcher's original relay FD is never an opened virtual device alias.
    // Raw clone/fork is unsupported; do not lock inherited state in that case.
    if PROCESS.load(Ordering::Acquire) != libc::getpid() {
        return false;
    }
    let saved = errno();
    let result = {
        let s = state();
        s.fds
            .get(&fd)
            .is_some_and(|session| identity(fd) == Some(session.identity))
    };
    restore_errno(saved);
    result
}
unsafe fn raw_close(fd: c_int) {
    libc::syscall(libc::SYS_close, fd);
}
unsafe fn close_matching(fd: c_int, expected: Identity) {
    if identity(fd) == Some(expected) {
        raw_close(fd);
    }
}
unsafe fn raw_dup(fd: c_int, min: c_int) -> c_int {
    libc::syscall(libc::SYS_fcntl, fd, libc::F_DUPFD_CLOEXEC, min) as c_int
}
fn sweep(s: &mut State) {
    let saved = errno();
    s.fds
        .retain(|fd, session| unsafe { identity(*fd) == Some(session.identity) });
    for alias in &mut s.capabilities {
        if alias.is_some_and(|alias| unsafe { identity(alias.fd) != Some(alias.identity) }) {
            *alias = None;
        }
    }
    restore_errno(saved);
}
unsafe fn capability_identity(s: &State, fd: c_int) -> Option<Identity> {
    let expected = config()
        .filter(|cfg| cfg.fd == fd)
        .map(|cfg| cfg.identity)
        .or_else(|| {
            s.capabilities
                .iter()
                .flatten()
                .find(|alias| alias.fd == fd)
                .map(|alias| alias.identity)
        })?;
    let saved = errno();
    let matches = identity(fd) == Some(expected);
    restore_errno(saved);
    matches.then_some(expected)
}
fn capability_slot(s: &State, target: Option<c_int>) -> Option<usize> {
    // A targeted replacement may reuse its current slot even at the cap.
    target
        .and_then(|fd| {
            s.capabilities
                .iter()
                .position(|alias| alias.is_some_and(|alias| alias.fd == fd))
        })
        .or_else(|| s.capabilities.iter().position(Option::is_none))
}
fn forget_capability(s: &mut State, fd: c_int) {
    for alias in &mut s.capabilities {
        if alias.is_some_and(|alias| alias.fd == fd) {
            *alias = None;
        }
    }
}
struct Pinned {
    fd: c_int,
    slot: usize,
    session: Arc<Session>,
}
impl Drop for Pinned {
    fn drop(&mut self) {
        let e = errno();
        // Raw fork/clone is unsupported. Never acquire a possibly inherited
        // locked registry following an unobserved process change.
        if PROCESS.load(Ordering::Acquire) != unsafe { libc::getpid() } {
            return;
        }
        let mut s = state();
        unsafe {
            if let Some(pin) = s.pins[self.slot].take() {
                close_matching(pin.fd, pin.identity);
            }
        }
        restore_errno(e);
    }
}
// Duplicate first, then inspect the duplicate: a raw close/reuse between lookup
// and dup cannot cause us to apply FIDO semantics to an unrelated descriptor.
unsafe fn pin(fd: c_int) -> Result<Option<Pinned>, ()> {
    if fork_child() {
        if child_virtual(fd) {
            error(libc::ENODEV);
            return Err(());
        }
        return Ok(None);
    }
    let saved = errno();
    let mut s = state();
    let Some(session) = s.fds.get(&fd).cloned() else {
        return Ok(None);
    };
    let copy = raw_dup(fd, 3);
    if copy < 0 {
        if errno() == libc::EBADF {
            s.fds.remove(&fd);
            restore_errno(saved);
            return Ok(None);
        }
        return Err(());
    }
    if identity(copy) != Some(session.identity) {
        raw_close(copy);
        s.fds.remove(&fd);
        restore_errno(saved);
        return Ok(None);
    }
    if session.generation.as_ref().is_some_and(|g| !g.live()) {
        raw_close(copy);
        error(libc::ENODEV);
        return Err(());
    }
    let Some(slot) = s.pins.iter().position(Option::is_none) else {
        // Check capacity only after identifying the duplicate, so a stale
        // alias reused for an unrelated descriptor still passes through. The
        // transient duplicate cannot cross fork while this guard is held.
        raw_close(copy);
        error(libc::EMFILE);
        return Err(());
    };
    s.pins[slot] = Some(PinIdentity {
        fd: copy,
        identity: session.identity,
    });
    restore_errno(saved);
    Ok(Some(Pinned {
        fd: copy,
        slot,
        session,
    }))
}
unsafe fn virtual_open(flags: c_int, wanted: Option<u64>) -> c_int {
    let Some(cfg) = config() else {
        return error(libc::ENODEV);
    };
    if flags
        & !(libc::O_ACCMODE
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | libc::O_NOCTTY
            | libc::O_LARGEFILE)
        != 0
    {
        return error(libc::EINVAL);
    }
    let access = flags & libc::O_ACCMODE;
    if access != libc::O_RDONLY && access != libc::O_RDWR {
        return error(libc::EACCES);
    }
    let mut s = state();
    sweep(&mut s);
    if s.active.upgrade().is_some() {
        return error(libc::EBUSY);
    }
    if s.fds.len() >= 256 {
        return error(libc::EMFILE);
    }
    let generation = if cfg.controlled {
        let Some(g) = s
            .generation
            .as_ref()
            .filter(|g| s.visible && g.live() && Some(g.number) == wanted)
            .cloned()
        else {
            return error(libc::ENODEV);
        };
        Some(g)
    } else {
        None
    };
    let (source_fd, source_identity) = generation
        .as_ref()
        .map_or((cfg.fd, cfg.identity), |g| (g.fd, g.identity));
    let copy = raw_dup(source_fd, 3);
    if copy < 0 {
        return -1;
    }
    if identity(copy) != Some(source_identity) {
        raw_close(copy);
        return error(libc::ENODEV);
    }
    let fdflags = if flags & libc::O_CLOEXEC != 0 {
        libc::FD_CLOEXEC
    } else {
        0
    };
    if libc::syscall(libc::SYS_fcntl, copy, libc::F_SETFD, fdflags) < 0 {
        let e = errno();
        raw_close(copy);
        return error(e);
    }
    // The supplied socket's open-file flags are shared by duplicates. Changing
    // O_NONBLOCK is explicit in this virtual open and Chromium later F_SETFL.
    let current = libc::syscall(libc::SYS_fcntl, copy, libc::F_GETFL) as c_int;
    if current < 0
        || libc::syscall(
            libc::SYS_fcntl,
            copy,
            libc::F_SETFL,
            (current & !libc::O_NONBLOCK) | (flags & libc::O_NONBLOCK),
        ) < 0
    {
        let e = errno();
        raw_close(copy);
        return error(e);
    }
    let session = Arc::new(Session {
        identity: source_identity,
        access,
        rx: Mutex::new(()),
        generation,
    });
    s.active = Arc::downgrade(&session);
    s.fds.insert(copy, session);
    copy
}
unsafe fn descriptor_open(flags: c_int) -> c_int {
    if flags & !(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_LARGEFILE) != 0 {
        return error(libc::EACCES);
    }
    let fd = libc::syscall(
        libc::SYS_memfd_create,
        c(b"uhf-fido-descriptor\0"),
        libc::MFD_ALLOW_SEALING
            | if flags & libc::O_CLOEXEC != 0 {
                libc::MFD_CLOEXEC
            } else {
                0
            },
    ) as c_int;
    if fd < 0 {
        return fd;
    }
    if libc::syscall(libc::SYS_write, fd, DESCRIPTOR.as_ptr(), DESCRIPTOR.len())
        != DESCRIPTOR.len() as libc::c_long
        || libc::syscall(
            libc::SYS_fcntl,
            fd,
            libc::F_ADD_SEALS,
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE,
        ) < 0
        || libc::syscall(libc::SYS_lseek, fd, 0, libc::SEEK_SET) < 0
    {
        let e = errno();
        raw_close(fd);
        return error(e);
    }
    // Reopen the sealed anonymous file read-only; callers get genuine kernel
    // read-only/seek/stat semantics, not a writable FD with emulated errors.
    let path = std::ffi::CString::new(format!("/proc/self/fd/{fd}")).unwrap();
    let readonly = libc::syscall(
        libc::SYS_openat,
        libc::AT_FDCWD,
        path.as_ptr(),
        libc::O_RDONLY | (flags & libc::O_CLOEXEC),
        0,
    ) as c_int;
    let saved = errno();
    raw_close(fd);
    restore_errno(saved);
    readonly
}
#[no_mangle]
pub unsafe extern "C" fn uh_open(
    path: *const c_char,
    flags: c_int,
    mode: mode_t,
    dirfd: c_int,
    which: c_int,
) -> c_int {
    if controlled() && (path as usize) >= 4096 {
        let bytes = std::ffi::CStr::from_ptr(path).to_bytes();
        if bytes.starts_with(b"/dev/userland-fido")
            || bytes.starts_with(b"/sys/devices/virtual/userland-fido/")
        {
            if let Some(g) = visible_generation() {
                if bytes == g.node.as_bytes() {
                    return virtual_open(flags, Some(g.number));
                }
                if bytes == g.descriptor.as_bytes() {
                    return descriptor_open(flags);
                }
            }
            return error(libc::ENODEV);
        }
    }
    if enabled()
        && !controlled()
        && (path as usize) >= 4096
        && (eq(path, &NODE[..NODE.len() - 1]) || eq(path, DESC_PATH))
    {
        if eq(path, DESC_PATH) {
            return descriptor_open(flags);
        }
        return virtual_open(flags, None);
    }
    match which {
        0 => real!(
            "open",
            unsafe extern "C" fn(*const c_char, c_int, mode_t) -> c_int
        )(path, flags, mode),
        1 => real!(
            "open64",
            unsafe extern "C" fn(*const c_char, c_int, mode_t) -> c_int
        )(path, flags, mode),
        2 => real!(
            "openat",
            unsafe extern "C" fn(c_int, *const c_char, c_int, mode_t) -> c_int
        )(dirfd, path, flags, mode),
        _ => real!(
            "openat64",
            unsafe extern "C" fn(c_int, *const c_char, c_int, mode_t) -> c_int
        )(dirfd, path, flags, mode),
    }
}
macro_rules! fortified_open {
    ($name:ident,$orig:literal,$which:expr) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name(path: *const c_char, flags: c_int) -> c_int {
            if flags & libc::O_CREAT != 0 || flags & libc::O_TMPFILE == libc::O_TMPFILE {
                return real!($orig, unsafe extern "C" fn(*const c_char, c_int) -> c_int)(
                    path, flags,
                );
            }
            uh_open(path, flags, 0, libc::AT_FDCWD, $which)
        }
    };
}
fortified_open!(__open_2, "__open_2", 0);
fortified_open!(__open64_2, "__open64_2", 1);
macro_rules! fortified_openat {
    ($name:ident,$orig:literal,$which:expr) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
            if flags & libc::O_CREAT != 0 || flags & libc::O_TMPFILE == libc::O_TMPFILE {
                return real!(
                    $orig,
                    unsafe extern "C" fn(c_int, *const c_char, c_int) -> c_int
                )(dirfd, path, flags);
            }
            uh_open(path, flags, 0, dirfd, $which)
        }
    };
}
fortified_openat!(__openat_2, "__openat_2", 2);
fortified_openat!(__openat64_2, "__openat64_2", 3);
#[no_mangle]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, n: size_t) -> ssize_t {
    let p = match pin(fd) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return real!(
                "read",
                unsafe extern "C" fn(c_int, *mut c_void, size_t) -> ssize_t
            )(fd, buf, n)
        }
        Err(()) => return -1,
    };
    if n == 0 {
        return 0;
    }
    if n < 64 {
        return error(libc::EMSGSIZE) as ssize_t;
    }
    if (buf as usize) < 4096 {
        return error(libc::EFAULT) as ssize_t;
    }
    let _guard = p.session.rx.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(generation) = &p.session.generation {
        loop {
            let s = state();
            if !generation.live() {
                return error(libc::ENODEV) as ssize_t;
            }
            let mut bytes = [0u8; 64];
            let actual = libc::syscall(
                libc::SYS_recvfrom,
                p.fd,
                bytes.as_mut_ptr(),
                64,
                libc::MSG_TRUNC | libc::MSG_DONTWAIT,
                0usize,
                0usize,
            ) as ssize_t;
            if actual >= 0 {
                if actual != 64 {
                    return error(if actual == 0 {
                        libc::ENODEV
                    } else {
                        libc::EPROTO
                    }) as ssize_t;
                }
                if !generation.live() {
                    return error(libc::ENODEV) as ssize_t;
                }
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast(), 64);
                return 64;
            }
            let e = errno();
            let flags = libc::syscall(libc::SYS_fcntl, p.fd, libc::F_GETFL) as c_int;
            drop(s);
            if e != libc::EAGAIN || flags < 0 || flags & libc::O_NONBLOCK != 0 {
                return error(e) as ssize_t;
            }
            let mut poll = libc::pollfd {
                fd: p.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            if libc::poll(&mut poll, 1, 10) < 0 {
                return -1;
            }
        }
    }
    let mut bytes = [0u8; 64];
    let size = libc::syscall(
        libc::SYS_recvfrom,
        p.fd,
        bytes.as_mut_ptr(),
        64,
        libc::MSG_PEEK | libc::MSG_TRUNC,
        0usize,
        0usize,
    ) as ssize_t;
    if size < 0 {
        return size;
    }
    if size != 64 {
        libc::syscall(
            libc::SYS_recvfrom,
            p.fd,
            bytes.as_mut_ptr(),
            64,
            libc::MSG_TRUNC | libc::MSG_DONTWAIT,
            0usize,
            0usize,
        );
        return error(if size == 0 {
            libc::ENODEV
        } else {
            libc::EPROTO
        }) as ssize_t;
    }
    let actual = libc::syscall(
        libc::SYS_recvfrom,
        p.fd,
        buf,
        64,
        libc::MSG_TRUNC,
        0usize,
        0usize,
    ) as ssize_t;
    if actual >= 0 && actual != 64 {
        return error(libc::EPROTO) as ssize_t;
    }
    actual
}
#[no_mangle]
pub unsafe extern "C" fn __read_chk(
    fd: c_int,
    buf: *mut c_void,
    n: size_t,
    capacity: size_t,
) -> ssize_t {
    if n > capacity {
        return real!(
            "__read_chk",
            unsafe extern "C" fn(c_int, *mut c_void, size_t, size_t) -> ssize_t
        )(fd, buf, n, capacity);
    }
    read(fd, buf, n)
}
#[no_mangle]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, n: size_t) -> ssize_t {
    let p = match pin(fd) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return real!(
                "write",
                unsafe extern "C" fn(c_int, *const c_void, size_t) -> ssize_t
            )(fd, buf, n)
        }
        Err(()) => return -1,
    };
    if p.session.access != libc::O_RDWR {
        return error(libc::EBADF) as ssize_t;
    }
    if n != 65 {
        return error(libc::EMSGSIZE) as ssize_t;
    }
    if (buf as usize) < 4096 {
        return error(libc::EFAULT) as ssize_t;
    }
    if *(buf as *const u8) != 0 {
        return error(libc::EINVAL) as ssize_t;
    }
    let _generation_guard = p.session.generation.as_ref().map(|_| state());
    if p.session.generation.as_ref().is_some_and(|g| !g.live()) {
        return error(libc::ENODEV) as ssize_t;
    }
    let result = libc::syscall(
        libc::SYS_sendto,
        p.fd,
        (buf as *const u8).add(1),
        64,
        libc::MSG_NOSIGNAL
            | if p.session.generation.is_some() {
                libc::MSG_DONTWAIT
            } else {
                0
            },
        0usize,
        0usize,
    ) as ssize_t;
    if result == 64 {
        65
    } else if result < 0 {
        result
    } else {
        error(libc::EIO) as ssize_t
    }
}
#[no_mangle]
pub unsafe extern "C" fn writev(fd: c_int, iov: *const libc::iovec, count: c_int) -> ssize_t {
    match pin(fd) {
        Ok(Some(_)) => error(libc::EOPNOTSUPP) as ssize_t,
        Ok(None) => real!(
            "writev",
            unsafe extern "C" fn(c_int, *const libc::iovec, c_int) -> ssize_t
        )(fd, iov, count),
        Err(()) => -1,
    }
}
#[no_mangle]
pub unsafe extern "C" fn readv(fd: c_int, iov: *const libc::iovec, count: c_int) -> ssize_t {
    match pin(fd) {
        Ok(Some(_)) => error(libc::EOPNOTSUPP) as ssize_t,
        Ok(None) => real!(
            "readv",
            unsafe extern "C" fn(c_int, *const libc::iovec, c_int) -> ssize_t
        )(fd, iov, count),
        Err(()) => -1,
    }
}
#[no_mangle]
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    let original = real!("close", unsafe extern "C" fn(c_int) -> c_int);
    if fork_child() {
        return original(fd);
    }
    let mut s = state();
    s.fds.remove(&fd);
    forget_capability(&mut s, fd);
    original(fd)
}
unsafe fn dup_impl(old: c_int, new: c_int, flags: c_int, which: c_int) -> c_int {
    let original_dup = real!("dup", unsafe extern "C" fn(c_int) -> c_int);
    let original_dup2 = real!("dup2", unsafe extern "C" fn(c_int, c_int) -> c_int);
    let original_dup3 = real!("dup3", unsafe extern "C" fn(c_int, c_int, c_int) -> c_int);
    if fork_child() {
        if child_virtual(old) {
            return error(libc::ENODEV);
        }
        return match which {
            1 => original_dup(old),
            2 => original_dup2(old, new),
            _ => original_dup3(old, new, flags),
        };
    }
    let mut s = state();
    sweep(&mut s);
    if which == 3 && (old == new || flags & !libc::O_CLOEXEC != 0) {
        return original_dup3(old, new, flags);
    }
    if which == 2 && old == new {
        return original_dup2(old, new);
    }
    let grows = which == 1 || !s.fds.contains_key(&new);
    if s.fds.contains_key(&old) && s.fds.len() >= 256 && grows {
        return error(libc::EMFILE);
    }
    let session = s.fds.get(&old).cloned();
    let capability = if session.is_none() {
        capability_identity(&s, old)
    } else {
        None
    };
    // Restoring/replacing the original number needs no additional alias slot:
    // Config already owns that number whenever its socket identity matches.
    let targets_original = which != 1
        && capability.is_some_and(|expected| {
            config().is_some_and(|cfg| cfg.fd == new && cfg.identity == expected)
        });
    let slot =
        capability.and_then(|_| capability_slot(&s, if which == 1 { None } else { Some(new) }));
    if capability.is_some() && !targets_original && slot.is_none() && (which == 1 || new >= 0) {
        return error(libc::EMFILE);
    }
    let result = match which {
        1 => original_dup(old),
        2 => original_dup2(old, new),
        _ => original_dup3(old, new, flags),
    };
    if result >= 0 {
        let saved = errno();
        s.fds.remove(&result);
        forget_capability(&mut s, result);
        if let Some(session) = session {
            if identity(result) == Some(session.identity) {
                s.fds.insert(result, session);
            }
        } else if let (Some(expected), Some(slot)) = (capability, slot) {
            if !targets_original && identity(result) == Some(expected) {
                s.capabilities[slot] = Some(PinIdentity {
                    fd: result,
                    identity: expected,
                });
            }
        }
        restore_errno(saved);
    }
    result
}
#[no_mangle]
pub unsafe extern "C" fn dup(fd: c_int) -> c_int {
    dup_impl(fd, -1, 0, 1)
}
#[no_mangle]
pub unsafe extern "C" fn dup2(old: c_int, new: c_int) -> c_int {
    dup_impl(old, new, 0, 2)
}
#[no_mangle]
pub unsafe extern "C" fn dup3(old: c_int, new: c_int, flags: c_int) -> c_int {
    dup_impl(old, new, flags, 3)
}
unsafe fn fcntl_impl(fd: c_int, cmd: c_int, arg: usize, is64: bool) -> c_int {
    let original = if is64 {
        real!(
            "fcntl64",
            unsafe extern "C" fn(c_int, c_int, usize) -> c_int
        )
    } else {
        real!("fcntl", unsafe extern "C" fn(c_int, c_int, usize) -> c_int)
    };
    if fork_child() {
        return if child_virtual(fd) {
            error(libc::ENODEV)
        } else {
            original(fd, cmd, arg)
        };
    }
    if cmd == libc::F_DUPFD || cmd == libc::F_DUPFD_CLOEXEC {
        let mut s = state();
        sweep(&mut s);
        let session = s.fds.get(&fd).cloned();
        if session.is_some() && s.fds.len() >= 256 && (arg as c_int) >= 0 {
            return error(libc::EMFILE);
        }
        let capability = if session.is_none() {
            capability_identity(&s, fd)
        } else {
            None
        };
        let slot = capability.and_then(|_| capability_slot(&s, None));
        if capability.is_some() && slot.is_none() && (arg as c_int) >= 0 {
            return error(libc::EMFILE);
        }
        let result = original(fd, cmd, arg);
        if result >= 0 {
            let saved = errno();
            s.fds.remove(&result);
            forget_capability(&mut s, result);
            if let Some(session) = session {
                if identity(result) == Some(session.identity) {
                    s.fds.insert(result, session);
                }
            } else if let (Some(expected), Some(slot)) = (capability, slot) {
                if identity(result) == Some(expected) {
                    s.capabilities[slot] = Some(PinIdentity {
                        fd: result,
                        identity: expected,
                    });
                }
            }
            restore_errno(saved);
        }
        return result;
    }
    let p = match pin(fd) {
        Ok(Some(p)) => p,
        Ok(None) => return original(fd, cmd, arg),
        Err(()) => return -1,
    };
    match cmd {
        libc::F_GETFL => {
            let result = original(p.fd, cmd, arg);
            if result < 0 {
                result
            } else {
                (result & !libc::O_ACCMODE) | p.session.access
            }
        }
        libc::F_SETFL => original(p.fd, cmd, arg),
        libc::F_GETFD | libc::F_SETFD => {
            drop(p);
            let _s = state();
            original(fd, cmd, arg)
        }
        _ => error(libc::EOPNOTSUPP),
    }
}
#[no_mangle]
pub unsafe extern "C" fn uh_fcntl(fd: c_int, cmd: c_int, arg: usize) -> c_int {
    fcntl_impl(fd, cmd, arg, false)
}
#[no_mangle]
pub unsafe extern "C" fn uh_fcntl64(fd: c_int, cmd: c_int, arg: usize) -> c_int {
    fcntl_impl(fd, cmd, arg, true)
}
#[no_mangle]
pub unsafe extern "C" fn uh_ioctl(fd: c_int, request: libc::c_ulong, arg: usize) -> c_int {
    let _p = match pin(fd) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return real!(
                "ioctl",
                unsafe extern "C" fn(c_int, libc::c_ulong, usize) -> c_int
            )(fd, request, arg)
        }
        Err(()) => return -1,
    };
    // Read-only HID descriptor/info ioctls for native diagnostics. Feature
    // reports and all other ioctls are unsupported for this one collection.
    if !matches!(request, 0x80044801 | 0x90044802 | 0x80084803) {
        return error(libc::ENOTTY);
    }
    if arg < 4096 {
        return error(libc::EFAULT);
    }
    match request {
        0x80044801 => {
            std::ptr::write_unaligned(arg as *mut c_int, DESCRIPTOR.len() as c_int);
            0
        }
        0x90044802 => {
            let n = std::ptr::read_unaligned(arg as *const u32) as usize;
            if n > 4096 {
                return error(libc::EINVAL);
            }
            std::ptr::copy_nonoverlapping(
                DESCRIPTOR.as_ptr(),
                (arg as *mut u8).add(4),
                n.min(DESCRIPTOR.len()),
            );
            0
        }
        0x80084803 => {
            std::ptr::write_unaligned(arg as *mut u32, 3);
            std::ptr::write_unaligned((arg as *mut u8).add(4) as *mut u16, 0x1209);
            std::ptr::write_unaligned((arg as *mut u8).add(6) as *mut u16, 0xf1d0);
            0
        }
        _ => error(libc::ENOTTY),
    }
}
unsafe fn fopen_impl(path: *const c_char, mode: *const c_char, is64: bool) -> *mut libc::FILE {
    let control_path = if controlled() && (path as usize) >= 4096 {
        Some(std::ffi::CStr::from_ptr(path).to_bytes())
    } else {
        None
    };
    let generation = visible_generation();
    let controlled_descriptor = control_path.is_some_and(|b| {
        generation
            .as_ref()
            .is_some_and(|g| b == g.descriptor.as_bytes())
    });
    if enabled()
        && (path as usize) >= 4096
        && (controlled_descriptor || (!controlled() && eq(path, DESC_PATH)))
    {
        if !eq(mode, b"r") && !eq(mode, b"rb") && !eq(mode, b"re") && !eq(mode, b"rbe") {
            error(libc::EACCES);
            return std::ptr::null_mut();
        }
        let fd = descriptor_open(
            libc::O_RDONLY
                | if std::ffi::CStr::from_ptr(mode).to_bytes().contains(&b'e') {
                    libc::O_CLOEXEC
                } else {
                    0
                },
        );
        if fd < 0 {
            return std::ptr::null_mut();
        }
        let result = libc::fdopen(fd, mode);
        if result.is_null() {
            let e = errno();
            raw_close(fd);
            restore_errno(e);
        }
        return result;
    }
    if control_path.is_some_and(|b| {
        b.starts_with(b"/dev/userland-fido")
            || b.starts_with(b"/sys/devices/virtual/userland-fido/")
    }) {
        error(libc::ENODEV);
        return std::ptr::null_mut();
    }
    if enabled() && (path as usize) >= 4096 && eq(path, &NODE[..NODE.len() - 1]) {
        error(libc::EOPNOTSUPP);
        return std::ptr::null_mut();
    }
    if is64 {
        real!(
            "fopen64",
            unsafe extern "C" fn(*const c_char, *const c_char) -> *mut libc::FILE
        )(path, mode)
    } else {
        real!(
            "fopen",
            unsafe extern "C" fn(*const c_char, *const c_char) -> *mut libc::FILE
        )(path, mode)
    }
}
#[no_mangle]
pub unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut libc::FILE {
    fopen_impl(path, mode, false)
}
#[no_mangle]
pub unsafe extern "C" fn fopen64(path: *const c_char, mode: *const c_char) -> *mut libc::FILE {
    fopen_impl(path, mode, true)
}

/// Captured capability identity, never rebound to a reused numeric descriptor.
#[cfg(not(feature = "simulation"))]
#[derive(Clone, Copy)]
pub struct Capability {
    pub fd: c_int,
    identity: Identity,
}
#[cfg(not(feature = "simulation"))]
pub fn capture_capability(fd: c_int) -> Option<Capability> {
    let s = state();
    unsafe { capability_identity(&s, fd) }.map(|identity| Capability { fd, identity })
}
#[cfg(not(feature = "simulation"))]
pub fn capability_valid(capability: Capability) -> bool {
    let s = state();
    (unsafe { capability_identity(&s, capability.fd) }) == Some(capability.identity)
}
#[cfg(not(feature = "simulation"))]
pub fn close_captured(capability: Capability) {
    let mut s = state();
    unsafe {
        close_matching(capability.fd, capability.identity);
    }
    for slot in &mut s.capabilities {
        if slot.is_some_and(|p| p.fd == capability.fd && p.identity == capability.identity) {
            *slot = None;
        }
    }
}
/// Identity-checked use of a public monitor endpoint. Its duplicate is pinned
/// before unlocking, protecting both raw reuse and standard-fork inheritance.
#[cfg(not(feature = "simulation"))]
pub struct CapabilityPin {
    pub fd: c_int,
    slot: usize,
}
#[cfg(not(feature = "simulation"))]
impl Drop for CapabilityPin {
    fn drop(&mut self) {
        let saved = errno();
        let mut s = state();
        if let Some(pin) = s.pins[self.slot].take() {
            unsafe {
                close_matching(pin.fd, pin.identity);
            }
        }
        restore_errno(saved);
    }
}
#[cfg(not(feature = "simulation"))]
pub fn pin_capability(capability: Capability) -> Option<CapabilityPin> {
    if fork_child() {
        return None;
    }
    let mut s = state();
    if unsafe { capability_identity(&s, capability.fd) } != Some(capability.identity) {
        return None;
    }
    let slot = s.pins.iter().position(Option::is_none)?;
    let copy = unsafe { raw_dup(capability.fd, 3) };
    if copy < 0 {
        return None;
    }
    if unsafe { identity(copy) } != Some(capability.identity) {
        unsafe {
            raw_close(copy);
        }
        return None;
    }
    s.pins[slot] = Some(PinIdentity {
        fd: copy,
        identity: capability.identity,
    });
    Some(CapabilityPin { fd: copy, slot })
}
