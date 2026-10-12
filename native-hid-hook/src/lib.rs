//! Source-informed Linux x86_64 FIDO-only ABI experiment. Not a USB emulator.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use libc::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::OnceLock;

macro_rules! real {
    ($name:literal, $ty:ty) => {{
        // An atomic address cache has no in-progress OnceLock for a child to
        // inherit. Concurrent initial lookups may duplicate dlsym safely.
        static SYMBOL: AtomicUsize = AtomicUsize::new(0);
        let mut address = SYMBOL.load(Ordering::Acquire);
        if address == 0 {
            let p = unsafe { libc::dlsym(libc::RTLD_NEXT, concat!($name, "\0").as_ptr().cast()) };
            if p.is_null() {
                unsafe {
                    libc::abort();
                }
            }
            address = p as usize;
            SYMBOL.store(address, Ordering::Release);
        }
        unsafe { std::mem::transmute::<usize, $ty>(address) }
    }};
}
static PROCESS: AtomicI32 = AtomicI32::new(0);
static FORK_CHILD: AtomicBool = AtomicBool::new(false);
fn fork_child() -> bool {
    FORK_CHILD.load(Ordering::Acquire)
        || PROCESS.load(Ordering::Acquire) != unsafe { libc::getpid() }
}
unsafe extern "C" fn before_fork() {
    control::before_fork();
    #[cfg(not(feature = "simulation"))]
    monitor::before_fork();
    fd::before_fork();
    udev::before_fork();
}
unsafe extern "C" fn after_fork_parent() {
    udev::after_fork();
    fd::after_fork();
    #[cfg(not(feature = "simulation"))]
    monitor::after_fork();
    control::after_fork();
}
unsafe extern "C" fn after_fork_child() {
    FORK_CHILD.store(true, Ordering::Release);
    PROCESS.store(libc::getpid(), Ordering::Release);
    // Registries are still frozen. This only borrows their snapshots and uses
    // raw identity checks/close; it allocates, frees, and resolves nothing.
    fd::close_child_fds();
    after_fork_parent();
}
unsafe extern "C" fn initialize() {
    PROCESS.store(libc::getpid(), Ordering::Release);
    fd::initialize();
    if libc::pthread_atfork(
        Some(before_fork),
        Some(after_fork_parent),
        Some(after_fork_child),
    ) != 0
    {
        libc::abort();
    }
    control::start();
}
#[used]
#[link_section = ".init_array"]
static INITIALIZER: unsafe extern "C" fn() = initialize;
fn error(e: c_int) -> c_int {
    unsafe {
        *libc::__errno_location() = e;
    }
    -1
}
fn errno() -> c_int {
    unsafe { *libc::__errno_location() }
}
fn restore_errno(e: c_int) {
    unsafe {
        *libc::__errno_location() = e;
    }
}
unsafe fn eq(p: *const c_char, s: &[u8]) -> bool {
    !p.is_null() && std::ffi::CStr::from_ptr(p).to_bytes() == s
}
fn c(s: &'static [u8]) -> *const c_char {
    s.as_ptr().cast()
}
mod control;
#[allow(dead_code)]
#[path = "../../src/fido-relay/src/control.rs"]
mod control_wire;
mod fd;
#[cfg(not(feature = "simulation"))]
mod monitor;
mod udev;

// Opaque bytes only. One FIDO Application collection, 64-byte input/output,
// no report IDs and no feature reports. No keyboard or general USB usages.
pub const DESCRIPTOR: &[u8] = &[
    0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xc0,
];
pub const USB: &[u8] = b"/sys/devices/virtual/userland-fido/usb0\0";
pub const HID: &[u8] = b"/sys/devices/virtual/userland-fido/usb0/hid0\0";
pub const RAW: &[u8] = b"/sys/devices/virtual/userland-fido/usb0/hid0/hidraw0\0";
pub const DESC_PATH: &[u8] = b"/sys/devices/virtual/userland-fido/usb0/hid0/report_descriptor";
pub const NODE: &[u8] = b"/dev/userland-fido-hidraw0\0";
pub const PRODUCT: &[u8] = b"Userspace FIDO transport prototype\0";

macro_rules! trampoline {
    ($name:ident, $target:literal) => {
        /// # Safety
        /// Invoke only with the named Linux x86_64 libc symbol's actual ABI.
        /// This entry point preserves registers and tail-jumps to that ABI;
        /// it must not be called using this Rust placeholder signature.
        #[allow(invalid_runtime_symbol_definitions)]
        #[unsafe(naked)]
        #[no_mangle]
        pub unsafe extern "C" fn $name() {
            std::arch::naked_asm!(concat!("jmp ", $target));
        }
    };
}
trampoline!(open, "uh_c_open");
trampoline!(open64, "uh_c_open64");
trampoline!(openat, "uh_c_openat");
trampoline!(openat64, "uh_c_openat64");
trampoline!(fcntl, "uh_fcntl");
trampoline!(fcntl64, "uh_fcntl64");
trampoline!(ioctl, "uh_ioctl");
