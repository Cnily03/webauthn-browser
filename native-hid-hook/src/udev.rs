//! Real libudev objects stay real. Only our registry-owned pointers are handled
//! here; foreign pointers are never dereferenced or tagged to identify them.
use super::*;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};
type P = *mut c_void;
#[derive(Default)]
struct Enumeration {
    refs: usize,
    filtered: bool,
    hidraw: bool,
    suppress: bool,
    scanned: bool,
    token: Box<u64>,
    generation: Option<Arc<fd::Generation>>,
}
struct Tree {
    storage: Box<[u64; 3]>,
    context: usize,
    refs: usize,
    generation: Option<Arc<fd::Generation>>,
    action: Option<&'static [u8]>,
}
#[derive(Clone, Copy)]
struct Node {
    tree: usize,
    kind: usize,
    refs: usize,
}
#[derive(Default)]
struct State {
    enums: HashMap<usize, Enumeration>,
    lists: HashMap<usize, (usize, Option<Arc<fd::Generation>>)>,
    trees: HashMap<usize, Tree>,
    nodes: HashMap<usize, Node>,
    #[cfg(feature = "simulation")]
    monitors: HashMap<usize, SimMonitor>,
}
static STATE: OnceLock<Mutex<State>> = OnceLock::new();
fn state() -> MutexGuard<'static, State> {
    STATE
        .get_or_init(|| Mutex::new(State::default()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}
static mut FORK_GUARD: std::mem::MaybeUninit<MutexGuard<'static, State>> =
    std::mem::MaybeUninit::uninit();
pub unsafe fn before_fork() {
    (&raw mut FORK_GUARD).write(std::mem::MaybeUninit::new(state()));
}
pub unsafe fn after_fork() {
    drop((&raw const FORK_GUARD).read().assume_init());
}
#[derive(Clone)]
struct Info {
    kind: usize,
    root: usize,
    context: usize,
    generation: Option<Arc<fd::Generation>>,
    action: Option<&'static [u8]>,
}
fn info(p: P) -> Option<Info> {
    if PROCESS.load(Ordering::Acquire) != unsafe { libc::getpid() } {
        return None;
    }
    let s = state();
    let n = s.nodes.get(&(p as usize))?;
    let t = s.trees.get(&n.tree)?;
    Some(Info {
        kind: n.kind,
        root: t.storage.as_ptr() as usize,
        context: t.context,
        generation: t.generation.clone(),
        action: t.action,
    })
}
fn pointer(i: &Info, kind: usize) -> P {
    (i.root + kind * std::mem::size_of::<u64>()) as P
}
fn str_value(i: &Info, field: &str) -> *const c_char {
    if field == "action" {
        return i.action.map_or(std::ptr::null(), c);
    }
    if let Some(g) = &i.generation {
        match field {
            "syspath" => return g.paths[i.kind].as_ptr(),
            "devpath" => return unsafe { g.paths[i.kind].as_ptr().add(4) },
            "devnode" => {
                return if i.kind == 0 {
                    g.node.as_ptr()
                } else {
                    std::ptr::null()
                }
            }
            _ => {}
        }
    }
    match field {
        "subsystem" => c(match i.kind {
            0 => b"hidraw\0",
            1 => b"hid\0",
            _ => b"usb\0",
        }),
        "syspath" => c(match i.kind {
            0 => RAW,
            1 => HID,
            _ => USB,
        }),
        "devpath" => {
            let bytes = match i.kind {
                0 => RAW,
                1 => HID,
                _ => USB,
            };
            unsafe { bytes.as_ptr().add(4).cast() }
        }
        "devnode" => {
            if i.kind == 0 {
                c(NODE)
            } else {
                std::ptr::null()
            }
        }
        "devtype" => {
            if i.kind == 2 {
                c(b"usb_device\0")
            } else {
                std::ptr::null()
            }
        }
        "sysname" => c(match i.kind {
            0 => b"hidraw0\0",
            1 => b"hid0\0",
            _ => b"usb0\0",
        }),
        "sysnum" => c(b"0\0"),
        _ => std::ptr::null(),
    }
}
#[no_mangle]
pub unsafe extern "C" fn udev_enumerate_new(ctx: P) -> P {
    let real = real!("udev_enumerate_new", unsafe extern "C" fn(P) -> P);
    let result = real(ctx);
    if !result.is_null() && fd::enabled() {
        let mut s = state();
        if s.enums.len() < 64 {
            s.enums.insert(
                result as usize,
                Enumeration {
                    refs: 1,
                    ..Default::default()
                },
            );
        }
    }
    result
}
#[no_mangle]
pub unsafe extern "C" fn udev_enumerate_ref(p: P) -> P {
    let result = real!("udev_enumerate_ref", unsafe extern "C" fn(P) -> P)(p);
    if !result.is_null() {
        if let Some(e) = state().enums.get_mut(&(p as usize)) {
            e.refs = e.refs.saturating_add(1);
        }
    }
    result
}
#[no_mangle]
pub unsafe extern "C" fn udev_enumerate_unref(p: P) -> P {
    let real = real!("udev_enumerate_unref", unsafe extern "C" fn(P) -> P);
    {
        let mut s = state();
        let remove = if let Some(e) = s.enums.get_mut(&(p as usize)) {
            e.refs -= 1;
            e.refs == 0
        } else {
            false
        };
        if remove {
            if let Some(e) = s.enums.remove(&(p as usize)) {
                s.lists.remove(&((&*e.token) as *const u64 as usize));
            }
        }
    }
    real(p)
}
#[no_mangle]
pub unsafe extern "C" fn udev_enumerate_scan_devices(p: P) -> c_int {
    let result = real!(
        "udev_enumerate_scan_devices",
        unsafe extern "C" fn(P) -> c_int
    )(p);
    if let Some(e) = state().enums.get_mut(&(p as usize)) {
        e.scanned = result == 0;
    }
    result
}
#[no_mangle]
pub unsafe extern "C" fn udev_enumerate_scan_subsystems(p: P) -> c_int {
    if let Some(e) = state().enums.get_mut(&(p as usize)) {
        e.suppress = true;
    }
    real!(
        "udev_enumerate_scan_subsystems",
        unsafe extern "C" fn(P) -> c_int
    )(p)
}
#[no_mangle]
pub unsafe extern "C" fn udev_enumerate_get_list_entry(p: P) -> P {
    let first = real!(
        "udev_enumerate_get_list_entry",
        unsafe extern "C" fn(P) -> P
    )(p);
    let generation = fd::visible_generation();
    if fd::controlled() && generation.is_none() {
        return first;
    }
    let mut s = state();
    let Some(e) = s.enums.get_mut(&(p as usize)) else {
        return first;
    };
    if !e.scanned || e.suppress || (e.filtered && !e.hidraw) {
        return first;
    }
    e.generation = generation.clone();
    let token = (&*e.token) as *const u64 as usize;
    s.lists.insert(token, (first as usize, generation));
    token as P
}
#[no_mangle]
pub unsafe extern "C" fn udev_list_entry_get_name(p: P) -> *const c_char {
    if let Some((_, g)) = state().lists.get(&(p as usize)) {
        return g.as_ref().map_or(c(RAW), |g| g.paths[0].as_ptr());
    }
    real!(
        "udev_list_entry_get_name",
        unsafe extern "C" fn(P) -> *const c_char
    )(p)
}
#[no_mangle]
pub unsafe extern "C" fn udev_list_entry_get_value(p: P) -> *const c_char {
    if state().lists.contains_key(&(p as usize)) {
        return std::ptr::null();
    }
    real!(
        "udev_list_entry_get_value",
        unsafe extern "C" fn(P) -> *const c_char
    )(p)
}
#[no_mangle]
pub unsafe extern "C" fn udev_list_entry_get_next(p: P) -> P {
    if let Some((next, _)) = state().lists.get(&(p as usize)) {
        return *next as P;
    }
    real!("udev_list_entry_get_next", unsafe extern "C" fn(P) -> P)(p)
}
#[no_mangle]
pub unsafe extern "C" fn udev_list_entry_get_by_name(p: P, name: *const c_char) -> P {
    let next = state().lists.get(&(p as usize)).cloned();
    if let Some((next, g)) = next {
        if eq(
            name,
            g.as_ref()
                .map_or(&RAW[..RAW.len() - 1], |g| g.paths[0].as_bytes()),
        ) {
            return p;
        }
        return real!(
            "udev_list_entry_get_by_name",
            unsafe extern "C" fn(P, *const c_char) -> P
        )(next as P, name);
    }
    real!(
        "udev_list_entry_get_by_name",
        unsafe extern "C" fn(P, *const c_char) -> P
    )(p, name)
}
#[no_mangle]
pub unsafe extern "C" fn udev_enumerate_add_match_subsystem(p: P, name: *const c_char) -> c_int {
    let result = real!(
        "udev_enumerate_add_match_subsystem",
        unsafe extern "C" fn(P, *const c_char) -> c_int
    )(p, name);
    if result == 0 {
        if let Some(e) = state().enums.get_mut(&(p as usize)) {
            e.filtered = true;
            e.hidraw |= eq(name, b"hidraw") || eq(name, b"*");
        }
    }
    result
}
#[no_mangle]
pub unsafe extern "C" fn udev_enumerate_add_nomatch_subsystem(p: P, name: *const c_char) -> c_int {
    let result = real!(
        "udev_enumerate_add_nomatch_subsystem",
        unsafe extern "C" fn(P, *const c_char) -> c_int
    )(p, name);
    if result == 0 && !name.is_null() {
        let bytes = std::ffi::CStr::from_ptr(name).to_bytes();
        if eq(name, b"hidraw") || bytes.iter().any(|b| b"*?[".contains(b)) {
            if let Some(e) = state().enums.get_mut(&(p as usize)) {
                e.suppress = true;
            }
        }
    }
    result
}
fn suppress(p: P) {
    if let Some(e) = state().enums.get_mut(&(p as usize)) {
        e.suppress = true;
    }
}
macro_rules! filter_one {
    ($name:ident,$str:literal) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name(p: P, arg: *const c_char) -> c_int {
            suppress(p);
            real!($str, unsafe extern "C" fn(P, *const c_char) -> c_int)(p, arg)
        }
    };
}
macro_rules! filter_two {
    ($name:ident,$str:literal) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name(p: P, a: *const c_char, b: *const c_char) -> c_int {
            suppress(p);
            real!(
                $str,
                unsafe extern "C" fn(P, *const c_char, *const c_char) -> c_int
            )(p, a, b)
        }
    };
}
filter_one!(
    udev_enumerate_add_match_sysname,
    "udev_enumerate_add_match_sysname"
);
filter_one!(udev_enumerate_add_match_tag, "udev_enumerate_add_match_tag");
filter_one!(udev_enumerate_add_syspath, "udev_enumerate_add_syspath");
filter_two!(
    udev_enumerate_add_match_property,
    "udev_enumerate_add_match_property"
);
filter_two!(
    udev_enumerate_add_match_sysattr,
    "udev_enumerate_add_match_sysattr"
);
filter_two!(
    udev_enumerate_add_nomatch_sysattr,
    "udev_enumerate_add_nomatch_sysattr"
);
#[no_mangle]
pub unsafe extern "C" fn udev_enumerate_add_match_is_initialized(p: P) -> c_int {
    suppress(p);
    real!(
        "udev_enumerate_add_match_is_initialized",
        unsafe extern "C" fn(P) -> c_int
    )(p)
}
#[no_mangle]
pub unsafe extern "C" fn udev_enumerate_add_match_parent(p: P, parent: P) -> c_int {
    suppress(p);
    if info(parent).is_some() {
        return -libc::EOPNOTSUPP;
    }
    real!(
        "udev_enumerate_add_match_parent",
        unsafe extern "C" fn(P, P) -> c_int
    )(p, parent)
}
#[no_mangle]
pub unsafe extern "C" fn udev_device_new_from_syspath(ctx: P, path: *const c_char) -> P {
    if !fd::enabled() {
        return real!(
            "udev_device_new_from_syspath",
            unsafe extern "C" fn(P, *const c_char) -> P
        )(ctx, path);
    }
    let generation = fd::visible_generation();
    let kind = if fd::controlled() {
        if path.is_null() {
            None
        } else {
            generation
                .as_ref()
                .and_then(|g| g.paths.iter().position(|p| eq(path, p.as_bytes())))
        }
    } else if eq(path, &RAW[..RAW.len() - 1]) {
        Some(0)
    } else if eq(path, &HID[..HID.len() - 1]) {
        Some(1)
    } else if eq(path, &USB[..USB.len() - 1]) {
        Some(2)
    } else {
        None
    };
    let Some(kind) = kind else {
        if fd::controlled()
            && !path.is_null()
            && std::ffi::CStr::from_ptr(path)
                .to_bytes()
                .starts_with(b"/sys/devices/virtual/userland-fido/")
        {
            error(libc::ENODEV);
            return std::ptr::null_mut();
        }
        return real!(
            "udev_device_new_from_syspath",
            unsafe extern "C" fn(P, *const c_char) -> P
        )(ctx, path);
    };
    new_tree(ctx, kind, generation, None)
}
pub(crate) unsafe fn new_tree(
    ctx: P,
    kind: usize,
    generation: Option<Arc<fd::Generation>>,
    action: Option<&'static [u8]>,
) -> P {
    if ctx.is_null() {
        error(libc::EINVAL);
        return std::ptr::null_mut();
    }
    let retain = real!("udev_ref", unsafe extern "C" fn(P) -> P);
    let release = real!("udev_unref", unsafe extern "C" fn(P) -> P);
    let ctx = retain(ctx);
    let mut s = state();
    if s.trees.len() >= 128 {
        drop(s);
        release(ctx);
        error(libc::ENOSPC);
        return std::ptr::null_mut();
    }
    let mut t = Tree {
        storage: Box::new([0; 3]),
        context: ctx as usize,
        refs: 1,
        generation,
        action,
    };
    let root = t.storage.as_mut_ptr() as usize;
    for k in 0..3 {
        s.nodes.insert(
            root + k * 8,
            Node {
                tree: root,
                kind: k,
                refs: usize::from(k == kind),
            },
        );
    }
    s.trees.insert(root, t);
    (root + kind * 8) as P
}
#[no_mangle]
pub unsafe extern "C" fn udev_device_ref(p: P) -> P {
    {
        let mut s = state();
        if let Some(n) = s.nodes.get_mut(&(p as usize)) {
            n.refs = n.refs.saturating_add(1);
            let id = n.tree;
            s.trees.get_mut(&id).unwrap().refs += 1;
            return p;
        }
    }
    real!("udev_device_ref", unsafe extern "C" fn(P) -> P)(p)
}
#[no_mangle]
pub unsafe extern "C" fn udev_device_unref(p: P) -> P {
    let mut context = None;
    let mut handled = false;
    {
        let mut s = state();
        if let Some(n) = s.nodes.get_mut(&(p as usize)) {
            handled = true;
            if n.refs > 0 {
                n.refs -= 1;
                let id = n.tree;
                let t = s.trees.get_mut(&id).unwrap();
                t.refs -= 1;
                if t.refs == 0 {
                    let t = s.trees.remove(&id).unwrap();
                    for k in 0..3 {
                        s.nodes.remove(&(id + k * 8));
                    }
                    context = Some(t.context);
                }
            }
        }
    }
    if let Some(ctx) = context {
        real!("udev_unref", unsafe extern "C" fn(P) -> P)(ctx as P);
    }
    if handled {
        std::ptr::null_mut()
    } else {
        real!("udev_device_unref", unsafe extern "C" fn(P) -> P)(p)
    }
}
macro_rules! str_getter {
    ($name:ident,$str:literal,$field:literal) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name(p: P) -> *const c_char {
            if let Some(i) = info(p) {
                return str_value(&i, $field);
            }
            real!($str, unsafe extern "C" fn(P) -> *const c_char)(p)
        }
    };
}
str_getter!(
    udev_device_get_subsystem,
    "udev_device_get_subsystem",
    "subsystem"
);
str_getter!(
    udev_device_get_syspath,
    "udev_device_get_syspath",
    "syspath"
);
str_getter!(
    udev_device_get_devpath,
    "udev_device_get_devpath",
    "devpath"
);
str_getter!(
    udev_device_get_devnode,
    "udev_device_get_devnode",
    "devnode"
);
str_getter!(
    udev_device_get_devtype,
    "udev_device_get_devtype",
    "devtype"
);
str_getter!(
    udev_device_get_sysname,
    "udev_device_get_sysname",
    "sysname"
);
str_getter!(udev_device_get_sysnum, "udev_device_get_sysnum", "sysnum");
str_getter!(udev_device_get_action, "udev_device_get_action", "action");
str_getter!(udev_device_get_driver, "udev_device_get_driver", "");
#[no_mangle]
pub unsafe extern "C" fn udev_device_get_udev(p: P) -> P {
    if let Some(i) = info(p) {
        return i.context as P;
    }
    real!("udev_device_get_udev", unsafe extern "C" fn(P) -> P)(p)
}
#[no_mangle]
pub unsafe extern "C" fn udev_device_get_parent(p: P) -> P {
    if let Some(i) = info(p) {
        return if i.kind < 2 {
            pointer(&i, i.kind + 1)
        } else {
            std::ptr::null_mut()
        };
    }
    real!("udev_device_get_parent", unsafe extern "C" fn(P) -> P)(p)
}
#[no_mangle]
pub unsafe extern "C" fn udev_device_get_parent_with_subsystem_devtype(
    p: P,
    subsystem: *const c_char,
    devtype: *const c_char,
) -> P {
    if let Some(i) = info(p) {
        for kind in (i.kind + 1)..3 {
            let candidate = Info { kind, ..i.clone() };
            let sub = str_value(&candidate, "subsystem");
            let typ = str_value(&candidate, "devtype");
            if !subsystem.is_null()
                && std::ffi::CStr::from_ptr(subsystem) == std::ffi::CStr::from_ptr(sub)
                && (devtype.is_null()
                    || (!typ.is_null()
                        && std::ffi::CStr::from_ptr(devtype) == std::ffi::CStr::from_ptr(typ)))
            {
                return pointer(&i, kind);
            }
        }
        return std::ptr::null_mut();
    }
    real!(
        "udev_device_get_parent_with_subsystem_devtype",
        unsafe extern "C" fn(P, *const c_char, *const c_char) -> P
    )(p, subsystem, devtype)
}
#[no_mangle]
pub unsafe extern "C" fn udev_device_get_property_value(p: P, key: *const c_char) -> *const c_char {
    if let Some(i) = info(p) {
        return if i.kind == 1 && eq(key, b"HID_ID") {
            c(b"0003:00001209:0000F1D0\0")
        } else if i.kind == 1 && eq(key, b"HID_NAME") {
            c(PRODUCT)
        } else if i.kind == 1 && eq(key, b"HID_UNIQ") {
            i.generation
                .as_ref()
                .map_or(c(b"userspace-prototype\0"), |g| g.unique.as_ptr())
        } else {
            std::ptr::null()
        };
    }
    real!(
        "udev_device_get_property_value",
        unsafe extern "C" fn(P, *const c_char) -> *const c_char
    )(p, key)
}
#[no_mangle]
pub unsafe extern "C" fn udev_device_get_sysattr_value(p: P, key: *const c_char) -> *const c_char {
    if let Some(i) = info(p) {
        return if i.kind == 2 && eq(key, b"product") {
            c(PRODUCT)
        } else {
            std::ptr::null()
        };
    }
    real!(
        "udev_device_get_sysattr_value",
        unsafe extern "C" fn(P, *const c_char) -> *const c_char
    )(p, key)
}
#[no_mangle]
pub unsafe extern "C" fn udev_device_set_sysattr_value(
    p: P,
    key: *const c_char,
    value: *const c_char,
) -> c_int {
    if info(p).is_some() {
        return -libc::EROFS;
    }
    real!(
        "udev_device_set_sysattr_value",
        unsafe extern "C" fn(P, *const c_char, *const c_char) -> c_int
    )(p, key, value)
}
macro_rules! empty_getter {
    ($name:ident,$str:literal,$ty:ty,$value:expr) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name(p: P) -> $ty {
            if info(p).is_some() {
                return $value;
            }
            real!($str, unsafe extern "C" fn(P) -> $ty)(p)
        }
    };
}
empty_getter!(
    udev_device_get_properties_list_entry,
    "udev_device_get_properties_list_entry",
    P,
    std::ptr::null_mut()
);
empty_getter!(
    udev_device_get_devlinks_list_entry,
    "udev_device_get_devlinks_list_entry",
    P,
    std::ptr::null_mut()
);
empty_getter!(
    udev_device_get_tags_list_entry,
    "udev_device_get_tags_list_entry",
    P,
    std::ptr::null_mut()
);
empty_getter!(
    udev_device_get_current_tags_list_entry,
    "udev_device_get_current_tags_list_entry",
    P,
    std::ptr::null_mut()
);
empty_getter!(
    udev_device_get_sysattr_list_entry,
    "udev_device_get_sysattr_list_entry",
    P,
    std::ptr::null_mut()
);
empty_getter!(
    udev_device_get_devnum,
    "udev_device_get_devnum",
    libc::dev_t,
    0
);
empty_getter!(
    udev_device_get_seqnum,
    "udev_device_get_seqnum",
    libc::c_ulonglong,
    0
);
empty_getter!(
    udev_device_get_usec_since_initialized,
    "udev_device_get_usec_since_initialized",
    libc::c_ulonglong,
    0
);
empty_getter!(
    udev_device_get_is_initialized,
    "udev_device_get_is_initialized",
    c_int,
    1
);
#[no_mangle]
pub unsafe extern "C" fn udev_device_has_tag(p: P, tag: *const c_char) -> c_int {
    if info(p).is_some() {
        return 0;
    }
    real!(
        "udev_device_has_tag",
        unsafe extern "C" fn(P, *const c_char) -> c_int
    )(p, tag)
}
#[no_mangle]
pub unsafe extern "C" fn udev_device_has_current_tag(p: P, tag: *const c_char) -> c_int {
    if info(p).is_some() {
        return 0;
    }
    real!(
        "udev_device_has_current_tag",
        unsafe extern "C" fn(P, *const c_char) -> c_int
    )(p, tag)
}

// The real libudev monitor adapter is deliberately unavailable in production.
// This build-only constructor creates a native simulation endpoint, never a
// fake kernel device or a replacement for udev_monitor_new_from_netlink.
#[cfg(feature = "simulation")]
static SIM_KEYS: [AtomicUsize; 16] = [const { AtomicUsize::new(0) }; 16];
#[cfg(feature = "simulation")]
fn child_simulated(p: P) -> bool {
    !p.is_null()
        && SIM_KEYS
            .iter()
            .any(|key| key.load(Ordering::Acquire) == p as usize)
}
#[cfg(feature = "simulation")]
struct SimMonitor {
    _token: Box<u64>,
    context: usize,
    refs: usize,
    read_fd: c_int,
    write_fd: c_int,
    enabled: bool,
    failed: bool,
    events: std::collections::VecDeque<(Arc<fd::Generation>, bool)>,
}
pub fn monitor_ready() -> bool {
    #[cfg(feature = "simulation")]
    {
        !fork_child() && state().monitors.values().any(|m| m.enabled && !m.failed)
    }
    #[cfg(not(feature = "simulation"))]
    {
        super::monitor::ready()
    }
}
pub fn publish(generation: Arc<fd::Generation>, add: bool) -> bool {
    #[cfg(feature = "simulation")]
    {
        let mut s = state();
        let mut count = 0;
        for m in s.monitors.values_mut().filter(|m| m.enabled) {
            if m.failed || m.events.len() >= 32 {
                m.failed = true;
                return false;
            }
            let value = [1u8];
            let n = unsafe {
                libc::syscall(
                    libc::SYS_sendto,
                    m.write_fd,
                    value.as_ptr(),
                    1,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    0usize,
                    0usize,
                )
            };
            if n != 1 {
                m.failed = true;
                return false;
            }
            m.events.push_back((generation.clone(), add));
            count += 1;
        }
        count != 0
    }
    #[cfg(not(feature = "simulation"))]
    {
        super::monitor::publish(generation, add)
    }
}
#[cfg(feature = "simulation")]
#[no_mangle]
pub unsafe extern "C" fn uhf_simulation_monitor_new(ctx: P) -> P {
    if !fd::controlled() || ctx.is_null() {
        error(libc::ENODEV);
        return std::ptr::null_mut();
    }
    let _gate = control::rights_guard();
    let mut fds = [-1; 2];
    if libc::socketpair(
        libc::AF_UNIX,
        libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        0,
        fds.as_mut_ptr(),
    ) < 0
    {
        return std::ptr::null_mut();
    }
    let first = fd::register_capability(fds[0]);
    let second = first && fd::register_capability(fds[1]);
    if !second {
        if first {
            fd::close_capability(fds[0]);
        } else {
            libc::syscall(libc::SYS_close, fds[0]);
        }
        libc::syscall(libc::SYS_close, fds[1]);
        error(libc::EMFILE);
        return std::ptr::null_mut();
    }
    let context = real!("udev_ref", unsafe extern "C" fn(P) -> P)(ctx);
    let mut s = state();
    if s.monitors.len() >= 16 {
        drop(s);
        fd::close_capability(fds[0]);
        fd::close_capability(fds[1]);
        real!("udev_unref", unsafe extern "C" fn(P) -> P)(context);
        error(libc::ENOSPC);
        return std::ptr::null_mut();
    }
    let token = Box::new(0u64);
    let key = (&*token) as *const u64 as usize;
    SIM_KEYS
        .iter()
        .find(|slot| slot.load(Ordering::Relaxed) == 0)
        .unwrap()
        .store(key, Ordering::Release);
    s.monitors.insert(
        key,
        SimMonitor {
            _token: token,
            context: context as usize,
            refs: 1,
            read_fd: fds[0],
            write_fd: fds[1],
            enabled: false,
            failed: false,
            events: Default::default(),
        },
    );
    key as P
}
#[cfg(feature = "simulation")]
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_enable_receiving(p: P) -> c_int {
    if fork_child() {
        return if child_simulated(p) {
            error(libc::ENODEV)
        } else {
            real!(
                "udev_monitor_enable_receiving",
                unsafe extern "C" fn(P) -> c_int
            )(p)
        };
    }
    if let Some(m) = state().monitors.get_mut(&(p as usize)) {
        if fork_child() || m.failed {
            return error(libc::ENODEV);
        }
        m.enabled = true;
        return 0;
    }
    real!(
        "udev_monitor_enable_receiving",
        unsafe extern "C" fn(P) -> c_int
    )(p)
}
#[cfg(feature = "simulation")]
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_get_fd(p: P) -> c_int {
    if fork_child() {
        return if child_simulated(p) {
            error(libc::ENODEV)
        } else {
            real!("udev_monitor_get_fd", unsafe extern "C" fn(P) -> c_int)(p)
        };
    }
    if let Some(m) = state().monitors.get(&(p as usize)) {
        return if fork_child() || m.failed {
            error(libc::ENODEV)
        } else {
            m.read_fd
        };
    }
    real!("udev_monitor_get_fd", unsafe extern "C" fn(P) -> c_int)(p)
}
#[cfg(feature = "simulation")]
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_ref(p: P) -> P {
    if fork_child() {
        if child_simulated(p) {
            error(libc::ENODEV);
            return std::ptr::null_mut();
        }
        return real!("udev_monitor_ref", unsafe extern "C" fn(P) -> P)(p);
    }
    if let Some(m) = state().monitors.get_mut(&(p as usize)) {
        m.refs = m.refs.saturating_add(1);
        return p;
    }
    real!("udev_monitor_ref", unsafe extern "C" fn(P) -> P)(p)
}
#[cfg(feature = "simulation")]
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_unref(p: P) -> P {
    if fork_child() {
        if child_simulated(p) {
            return std::ptr::null_mut();
        }
        return real!("udev_monitor_unref", unsafe extern "C" fn(P) -> P)(p);
    }
    let removed = {
        let mut s = state();
        if let Some(m) = s.monitors.get_mut(&(p as usize)) {
            m.refs -= 1;
            if m.refs != 0 {
                return std::ptr::null_mut();
            }
            for key in &SIM_KEYS {
                if key.load(Ordering::Relaxed) == p as usize {
                    key.store(0, Ordering::Release);
                }
            }
            s.monitors.remove(&(p as usize))
        } else {
            None
        }
    };
    if let Some(m) = removed {
        fd::close_capability(m.read_fd);
        fd::close_capability(m.write_fd);
        real!("udev_unref", unsafe extern "C" fn(P) -> P)(m.context as P);
        return std::ptr::null_mut();
    }
    real!("udev_monitor_unref", unsafe extern "C" fn(P) -> P)(p)
}
#[cfg(feature = "simulation")]
#[no_mangle]
pub unsafe extern "C" fn udev_monitor_receive_device(p: P) -> P {
    if fork_child() {
        if child_simulated(p) {
            error(libc::ENODEV);
            return std::ptr::null_mut();
        }
        return real!("udev_monitor_receive_device", unsafe extern "C" fn(P) -> P)(p);
    }
    let event = {
        let mut s = state();
        if let Some(m) = s.monitors.get_mut(&(p as usize)) {
            if fork_child() || !m.enabled || m.failed {
                error(libc::ENODEV);
                return std::ptr::null_mut();
            }
            let mut wake = [0u8];
            if libc::syscall(
                libc::SYS_recvfrom,
                m.read_fd,
                wake.as_mut_ptr(),
                1,
                libc::MSG_DONTWAIT,
                0usize,
                0usize,
            ) != 1
            {
                return std::ptr::null_mut();
            }
            let Some((g, add)) = m.events.pop_front() else {
                m.failed = true;
                error(libc::EPROTO);
                return std::ptr::null_mut();
            };
            Some((m.context, g, add))
        } else {
            None
        }
    };
    if let Some((ctx, g, add)) = event {
        return new_tree(
            ctx as P,
            0,
            Some(g),
            Some(if add { b"add\0" } else { b"remove\0" }),
        );
    }
    real!("udev_monitor_receive_device", unsafe extern "C" fn(P) -> P)(p)
}
