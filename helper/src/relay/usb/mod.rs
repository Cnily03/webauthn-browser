//! Physical USB adapter; UI defaults enabled, gated by live exact-Origin approval.
//! One selected FIDO interface, strict unnumbered 64-byte reports; no arbitrary HID.

#[cfg(any(target_os = "linux", target_os = "windows", test))]
mod backend;
#[cfg(any(target_os = "linux", target_os = "windows", test))]
mod descriptor;
mod lifetime;
mod selection;
mod supervisor;
mod wire;
mod worker;
use crate::Handle;
use selection::Selection;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use wire::{Device, Reply, Request};
pub use worker::entry as worker_entry;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub message: String,
    pub choices: Vec<Choice>,
    /// Physical endpoint attached; browser report readiness is a separate state.
    pub attached: bool,
    pub cleanup_unconfirmed: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
    pub id: String,
    pub label: String,
}
#[derive(Clone, PartialEq, Eq)]
struct Binding {
    request: String,
    session: String,
    origin: String,
    epoch: u64,
}
impl Binding {
    async fn current(handle: &Handle) -> Option<Self> {
        let inner = handle.app.inner.lock().await;
        let pairing = inner.pairing.as_ref()?;
        let request = pairing.request_id.as_ref()?;
        if inner.stopping
            || inner.cleanup_failed
            || !inner.connected
            || pairing.token.is_some()
            || pairing.expires <= Instant::now()
            || !inner.connection_owned_by(request, inner.epoch)
        {
            return None;
        }
        Some(Self {
            request: request.clone(),
            session: pairing.session_id.clone()?,
            origin: pairing.origin.clone(),
            epoch: inner.epoch,
        })
    }
}
struct Running {
    cancel: watch::Sender<bool>,
    select: mpsc::Sender<String>,
    task: tokio::task::JoinHandle<bool>,
    binding: Binding,
}
/// UI-owned controller. Discovery only begins while enabled and bound to a live approved Origin.
/// CLI/Desktop enable it by default; a bare library controller remains disabled.
/// A failed/detached device is never silently retried on the same connection.
pub struct Controller {
    #[cfg(feature = "test-support")]
    test_worker: Option<std::path::PathBuf>,
    enabled: bool,
    suspended: bool,
    selection: Selection,
    attempted: Option<Binding>,
    running: Option<Running>,
    status: Arc<Mutex<Status>>,
    blocked: bool,
}
impl Default for Controller {
    fn default() -> Self {
        Self {
            #[cfg(feature = "test-support")]
            test_worker: None,
            enabled: false,
            suspended: false,
            selection: Selection::default(),
            attempted: None,
            running: None,
            status: Arc::new(Mutex::new(Status::default())),
            blocked: false,
        }
    }
}
impl Controller {
    /// Fake-process fixture injection, available only with the test-support feature.
    #[cfg(feature = "test-support")]
    pub fn with_test_worker(executable: std::path::PathBuf) -> Self {
        let mut controller = Self::default();
        controller.test_worker = Some(executable);
        controller
    }

    pub fn status(&self) -> Status {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn set_enabled(&mut self, enabled: bool) {
        if self.enabled != enabled {
            self.cancel();
            self.suspended = false;
            self.selection.reset();
            self.attempted = None;
        }
        self.enabled = enabled;
    }
    /// Cancel current work without latching a user detach or clearing device selection.
    pub fn cancel(&mut self) {
        if let Some(running) = &self.running {
            running.cancel.send_replace(true);
            let current = self.status();
            if current.attached {
                set_status(&self.status, "USB: stopping", true, false);
            }
        }
    }
    /// Explicit user detachment survives automatic helper lease rotation.
    pub fn detach(&mut self) {
        self.suspended = true;
        self.cancel();
    }
    /// Retry explicitly, preserving the selected device for this backend session/Origin.
    pub fn retry(&mut self) {
        self.suspended = false;
        self.cancel();
        self.attempted = None;
    }
    pub fn select(&self, id: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.status().choices.iter().any(|choice| choice.id == id),
            "Select an identifier from the current USB device list."
        );
        self.running
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("USB discovery is not active."))?
            .select
            .try_send(id.into())
            .map_err(|_| anyhow::anyhow!("USB selection is no longer active."))
    }
    pub async fn tick(&mut self, handle: Option<&Handle>) {
        let binding = match handle {
            Some(handle) => Binding::current(handle).await,
            None => None,
        };
        if self
            .running
            .as_ref()
            .is_some_and(|r| !self.enabled || binding.as_ref() != Some(&r.binding))
        {
            self.cancel();
        }
        // Reap before allowing replacement. An unconfirmed child cleanup remains
        // blocked even if consent or the browser binding changes afterward.
        if self.running.as_ref().is_some_and(|r| r.task.is_finished()) {
            let running = self.running.take().unwrap();
            self.blocked = !matches!(running.task.await, Ok(true));
            if self.blocked {
                set_status(
                    &self.status,
                    "USB cleanup unconfirmed; restart the helper before another attachment.",
                    false,
                    true,
                );
            }
        }
        if self.running.is_some() || self.blocked {
            return;
        }
        if !self.enabled {
            set_status(&self.status, "USB: disabled", false, false);
            return;
        }
        if self.suspended {
            set_status(&self.status, "USB: detached; retry to resume", false, false);
            return;
        }
        if !cfg!(any(target_os = "linux", target_os = "windows")) {
            set_status(
                &self.status,
                "USB: physical adapter is available only on Linux and Windows",
                false,
                false,
            );
            return;
        }
        let Some(binding) = binding else {
            set_status(
                &self.status,
                "USB: waiting for approved browser",
                false,
                false,
            );
            return;
        };
        // The socket binding rotates on re-pairing; device memory is broader,
        // pinned to backend session + Origin so rotation cannot switch keys.
        self.selection.for_binding(&binding);
        if self.attempted.as_ref() == Some(&binding) {
            return;
        }
        self.attempted = Some(binding.clone());
        let handle = handle.unwrap().clone();
        let (cancel, canceled) = watch::channel(false);
        let (select, selected) = mpsc::channel(1);
        let status = self.status.clone();
        let task_binding = binding.clone();
        let selection = self.selection.clone();
        #[cfg(feature = "test-support")]
        let test_worker = self.test_worker.clone();
        let task = tokio::spawn(async move {
            run(
                handle,
                task_binding,
                status,
                canceled,
                selected,
                selection,
                #[cfg(feature = "test-support")]
                test_worker,
            )
            .await
        });
        self.running = Some(Running {
            cancel,
            select,
            task,
            binding,
        });
    }
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        self.cancel();
        if let Some(mut running) = self.running.take() {
            self.blocked = !matches!(
                tokio::time::timeout(Duration::from_secs(3), &mut running.task).await,
                Ok(Ok(true))
            );
            if self.blocked {
                running.task.abort();
            }
        }
        anyhow::ensure!(
            !self.blocked,
            "USB cleanup unconfirmed. Restart the helper before attaching another device."
        );
        Ok(())
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.cancel();
    }
}
fn set_status(
    status: &Arc<Mutex<Status>>,
    message: &str,
    attached: bool,
    cleanup_unconfirmed: bool,
) {
    publish_status(
        status,
        Status {
            message: message.into(),
            attached,
            cleanup_unconfirmed,
            choices: vec![],
        },
    );
}
fn transport_state(status: &Status) -> crate::diagnostics::UsbState {
    use crate::diagnostics::UsbState::*;
    if status.cleanup_unconfirmed {
        return CleanupFailed;
    }
    if !status.choices.is_empty() {
        return Selecting;
    }
    match status.message.as_str() {
        "USB: disabled" => Disabled,
        "USB: finding device" => Finding,
        "USB: ready" if status.attached => Ready,
        "USB: stopping" => Stopping,
        _ if status.attached => Waiting,
        message
            if message.contains("unavailable")
                || message.contains("could not start")
                || message.contains("only on Linux") =>
        {
            Unavailable
        }
        _ => Disconnected,
    }
}
fn publish_status(status: &Arc<Mutex<Status>>, next: Status) {
    let mut previous = status.lock().unwrap_or_else(|e| e.into_inner());
    let phase = transport_state(&next);
    let changed = transport_state(&previous) != phase;
    let quiet_start = previous.message.is_empty()
        && matches!(
            phase,
            crate::diagnostics::UsbState::Disabled | crate::diagnostics::UsbState::Disconnected
        );
    *previous = next;
    drop(previous);
    if changed && !quiet_start {
        crate::diagnostics::usb(phase);
    }
}
fn candidates(devices: Vec<Device>) -> Result<Vec<(Choice, Device)>, ()> {
    if devices.len() > 16
        || devices.iter().any(|d| !d.valid())
        || devices
            .iter()
            .enumerate()
            .any(|(n, d)| devices[..n].iter().any(|x| x.path == d.path))
    {
        return Err(());
    }
    Ok(devices
        .into_iter()
        .map(|d| {
            (
                Choice {
                    id: crate::pairing::protocol::random_secret(),
                    label: d.label(),
                },
                d,
            )
        })
        .collect())
}
async fn run(
    handle: Handle,
    binding: Binding,
    status: Arc<Mutex<Status>>,
    mut cancel: watch::Receiver<bool>,
    mut selected: mpsc::Receiver<String>,
    selection: Selection,
    #[cfg(feature = "test-support")] test_worker: Option<std::path::PathBuf>,
) -> bool {
    set_status(&status, "USB: finding device", false, false);
    if *cancel.borrow() || Binding::current(&handle).await.as_ref() != Some(&binding) {
        return true;
    }
    #[cfg(feature = "test-support")]
    let child = match test_worker {
        Some(executable) => {
            let mut command = tokio::process::Command::new(executable);
            command.arg("--fixture-device");
            supervisor::ChildIo::spawn(&mut command)
        }
        None => supervisor::ChildIo::start(),
    };
    #[cfg(not(feature = "test-support"))]
    let child = supervisor::ChildIo::start();
    let Ok(mut child) = child else {
        set_status(&status, "USB worker could not start.", false, false);
        return true;
    };
    let result = session(
        &mut child,
        &handle,
        &binding,
        &status,
        &mut cancel,
        &mut selected,
        &selection,
    )
    .await;
    let clean = child.stop().await;
    if clean {
        set_status(
            &status,
            if result.is_ok() || *cancel.borrow() {
                "USB: detached"
            } else {
                "USB: unavailable"
            },
            false,
            false,
        );
    }
    clean
}
async fn session(
    child: &mut supervisor::ChildIo,
    handle: &Handle,
    binding: &Binding,
    status: &Arc<Mutex<Status>>,
    cancel: &mut watch::Receiver<bool>,
    selected: &mut mpsc::Receiver<String>,
    selection: &Selection,
) -> Result<(), ()> {
    let Reply::Devices { devices } = child.request(Request::Discover, cancel).await? else {
        return Err(());
    };
    let mut devices = candidates(devices)?;
    let device = if let Some(remembered) = selection.recalled(binding)? {
        devices
            .into_iter()
            .find(|(_, device)| device == &remembered)
            .ok_or(())?
            .1
    } else {
        match devices.len() {
            0 => return Err(()),
            1 => devices.remove(0).1,
            _ => {
                publish_status(
                    status,
                    Status {
                        message: "USB: select device".into(),
                        choices: devices.iter().map(|(c, _)| c.clone()).collect(),
                        ..Status::default()
                    },
                );
                let id = tokio::select! { biased; _ = cancel.changed() => return Err(()), id = tokio::time::timeout(Duration::from_secs(30), selected.recv()) => id.map_err(|_| ())?.ok_or(())? };
                devices
                    .into_iter()
                    .find(|(choice, _)| choice.id == id)
                    .ok_or(())?
                    .1
            }
        }
    };
    if *cancel.borrow() || Binding::current(handle).await.as_ref() != Some(binding) {
        return Err(());
    }
    if *cancel.borrow() {
        return Err(());
    }
    selection.remember(binding, &device)?;
    if !matches!(
        child.request(Request::Open { device }, cancel).await?,
        Reply::Opened
    ) {
        return Err(());
    }
    if *cancel.borrow() {
        return Err(());
    }
    let (relay, mut endpoint) = fido_report_relay::endpoint_pair();
    crate::relay::fido::attach_bound(
        &handle.app,
        &binding.session,
        Some((&binding.request, &binding.origin, binding.epoch)),
        relay,
    )
    .await
    .map_err(|_| ())?;
    set_status(status, "USB: waiting for browser transport", true, false);
    let mut transport_opened = false;
    loop {
        if *cancel.borrow()
            || endpoint.is_closed()
            || Binding::current(handle).await.as_ref() != Some(binding)
        {
            return Ok(());
        }
        match crate::relay::fido::device_opened(
            &handle.app,
            &binding.request,
            &binding.origin,
            binding.epoch,
        )
        .await
        {
            None => return Ok(()),
            Some(false) => {
                // Keep the same bounded offer/device while the real native monitor
                // starts. No report read/write or replay before the peer opens it.
                tokio::select! {
                    _ = cancel.changed() => return Ok(()),
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                }
                continue;
            }
            Some(true) => {}
        }
        if !transport_opened {
            transport_opened = true;
            set_status(status, "USB: ready", true, false);
        }
        let outgoing = endpoint.try_receive().map_err(|_| ())?;
        let Reply::Report { report } =
            exchange_guarded(child, handle, binding, cancel, outgoing).await?
        else {
            return Err(());
        };
        // Recheck after OS I/O. Never deliver a report into a changed lease/socket.
        if endpoint.is_closed()
            || *cancel.borrow()
            || Binding::current(handle).await.as_ref() != Some(binding)
        {
            return Ok(());
        }
        if crate::relay::fido::device_deadline(
            &handle.app,
            &binding.request,
            &binding.origin,
            binding.epoch,
        )
        .await
        .is_none()
        {
            return Ok(());
        }
        if let Some(report) = report {
            endpoint.send(report).map_err(|_| ())?;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn exchange_guarded(
    child: &mut supervisor::ChildIo,
    handle: &Handle,
    binding: &Binding,
    cancel: &mut watch::Receiver<bool>,
    report: Option<fido_report_relay::Report>,
) -> Result<Reply, ()> {
    let operation = child.request(Request::Exchange { report }, cancel);
    tokio::pin!(operation);
    let mut guard = tokio::time::interval(Duration::from_millis(10));
    loop {
        tokio::select! {
            biased;
            _ = guard.tick() => {
                if crate::relay::fido::device_deadline(&handle.app, &binding.request, &binding.origin, binding.epoch).await.is_none() { return Err(()); }
            }
            reply = &mut operation => return reply,
        }
    }
}

#[cfg(test)]
mod testing;

#[cfg(test)]
mod tests {
    use super::testing::{device, dummy_binding};
    use super::*;
    #[cfg(unix)]
    use fido_report_relay::Report;
    #[test]
    fn state_logs_are_deduplicated_and_never_include_status_details() {
        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = Capture::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(move || writer.clone())
            .finish();
        let status = Arc::new(Mutex::new(Status::default()));
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..3 {
                set_status(&status, "USB: finding device", false, false);
            }
            set_status(&status, "private-path-serial-report-value", true, false);
            set_status(&status, "different-private-detail", true, false);
            set_status(&status, "USB: ready", true, false);
            set_status(&status, "USB: ready", true, false);
            set_status(&status, "private-close-reason", false, false);
            set_status(&status, "different-close-reason", false, false);
        });
        let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        for word in [
            "finding device",
            "waiting for browser",
            "ready",
            "disconnected",
        ] {
            assert_eq!(logs.matches(&format!("USB: {word}")).count(), 1, "{logs}");
        }
        assert!(!logs.contains("private") && !logs.contains("detail") && !logs.contains("reason"));
    }

    #[test]
    fn discovery_ids_are_unique_ephemeral_and_paths_never_exposed() {
        let choices = candidates(vec![device(1), device(2)]).unwrap();
        assert_ne!(choices[0].0.id, choices[1].0.id);
        assert_ne!(
            choices[0].0.id,
            candidates(vec![device(1)]).unwrap()[0].0.id
        );
        assert!(choices[0].0.label.starts_with("USB FIDO 0001:0002"));
        assert!(candidates(vec![device(1), device(1)]).is_err());
        assert!(candidates((0..17).map(device).collect()).is_err());
        let mut invalid = device(1);
        invalid.path = vec![0];
        assert!(candidates(vec![invalid]).is_err());
    }

    #[tokio::test]
    async fn default_disabled_and_missing_approval_never_spawn_worker() {
        let handle = crate::launch_incoming(None).await.unwrap();
        let mut controller = Controller::default();
        controller.tick(Some(&handle)).await;
        assert!(controller.running.is_none());
        controller.set_enabled(true);
        controller.tick(Some(&handle)).await;
        assert!(controller.running.is_none());
        assert!(
            controller.status().message.starts_with("USB: waiting")
                || controller
                    .status()
                    .message
                    .contains("only on Linux and Windows")
        );
        // Local approval without successful socket authentication cannot open HID either.
        handle
            .approve("https://unconnected.example", &"T".repeat(32))
            .await
            .unwrap();
        controller.tick(Some(&handle)).await;
        assert!(controller.running.is_none());
        controller.tick(None).await;
        assert!(controller.running.is_none());
        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cleanup_unconfirmed_blocks_even_explicit_retry() {
        let mut controller = Controller::default();
        controller.blocked = true;
        controller.set_enabled(true);
        controller.retry();
        controller.tick(None).await;
        assert!(controller.running.is_none());
        assert!(controller.shutdown().await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn usb_opt_out_keeps_active_ble_and_pairing_until_both_are_disabled() {
        let (handle, binding) = fake_paired().await;
        let (scan, scan_state) = watch::channel(true);
        {
            let mut inner = handle.app.inner.lock().await;
            inner.scan = Some(scan);
            inner.ble_state = crate::BleState::Scanning;
        }
        let status = Arc::new(Mutex::new(Status::default()));
        let (cancel, mut canceled) = watch::channel(false);
        let (select, mut selected) = mpsc::channel(1);
        let task_status = status.clone();
        let task_handle = handle.clone();
        let task_binding = binding.clone();
        let task = tokio::spawn(async move {
            let mut child = fake_child("echo");
            let _ = session(
                &mut child,
                &task_handle,
                &task_binding,
                &task_status,
                &mut canceled,
                &mut selected,
                &Selection::default(),
            )
            .await;
            child.stop().await
        });
        let mut controller = Controller::default();
        controller.enabled = true;
        controller.status = status.clone();
        controller.running = Some(Running {
            cancel,
            select,
            task,
            binding,
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            while !status.lock().unwrap().attached {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        controller.set_enabled(false);
        tokio::time::timeout(Duration::from_secs(3), async {
            while controller.running.is_some() {
                controller.tick(Some(&handle)).await;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(*scan_state.borrow());
        assert_eq!(handle.snapshot().await.ble_state, crate::BleState::Scanning);
        assert!(handle.snapshot().await.connected);
        assert!(handle.snapshot().await.withheld_origins.is_empty());
        handle.set_ble_enabled(false).await;
        assert!(!*scan_state.borrow());
        assert!(handle.snapshot().await.connected);
        assert!(handle.snapshot().await.withheld_origins.is_empty());
        finish_fake(handle).await;
    }

    #[cfg(unix)]
    fn fake_child(mode: &str) -> supervisor::ChildIo {
        // Fixture deliberately has no imports or APIs for accessing devices.
        const PROGRAM: &str = r#"
import sys,json,struct,time
mode=sys.argv[1]
def reply(value):
 data=json.dumps(value).encode(); sys.stdout.buffer.write(struct.pack('>I',len(data))+data); sys.stdout.buffer.flush()
while True:
 prefix=sys.stdin.buffer.read(4)
 if len(prefix)!=4: break
 request=json.loads(sys.stdin.buffer.read(struct.unpack('>I',prefix)[0]))
 if request['type']=='discover':
  device={'path':[1],'vendor':1,'product':2,'interface':0,'serial':None}
  devices=[device]
  if mode=='multiple': devices.append(dict(device,path=[2]))
  reply({'type':'devices','devices':devices})
 elif request['type']=='open':
  if mode=='slow_open': time.sleep(0.15)
  reply({'type':'opened'})
 elif request['type']=='exchange':
  if mode=='reject_exchange':
   reply({'type':'failed'}); continue
  if mode=='blocked_write': time.sleep(60)
  reply({'type':'report','report':request['report']})
 else: break
"#;
        let mut command = tokio::process::Command::new("python3");
        command.args(["-c", PROGRAM, mode]);
        supervisor::ChildIo::spawn(&mut command).unwrap()
    }

    #[cfg(unix)]
    async fn fake_paired() -> (Handle, Binding) {
        let handle = crate::launch(None).await.unwrap();
        let binding = Binding {
            request: crate::pairing::protocol::random_secret(),
            session: crate::pairing::protocol::random_secret(),
            origin: "https://usb-fixture.example".into(),
            epoch: 7,
        };
        {
            let mut inner = handle.app.inner.lock().await;
            inner.epoch = binding.epoch;
            inner.connected = true;
            inner.connection_owner = Some((binding.request.clone(), binding.epoch));
            inner.pairing = Some(crate::pairing::state::Pairing {
                explicit_approval: true,
                request_id: Some(binding.request.clone()),
                session_id: Some(binding.session.clone()),
                origin: binding.origin.clone(),
                token: None,
                expires: Instant::now() + Duration::from_secs(20),
            });
        }
        (handle, binding)
    }

    #[cfg(unix)]
    async fn finish_fake(handle: Handle) {
        {
            let mut inner = handle.app.inner.lock().await;
            inner.fido = None;
            inner.connected = false;
        }
        handle.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sole_key_auto_attach_blocked_write_cancellation_reaps_fake_child() {
        let (handle, binding) = fake_paired().await;
        let mut child = fake_child("blocked_write");
        let status = Arc::new(Mutex::new(Status::default()));
        let (cancel, mut canceled) = watch::channel(false);
        let (_select, mut selected) = mpsc::channel(1);
        let selection = Selection::default();
        {
            let operation = session(
                &mut child,
                &handle,
                &binding,
                &status,
                &mut canceled,
                &mut selected,
                &selection,
            );
            tokio::pin!(operation);
            tokio::select! { _ = &mut operation => panic!("must wait for fake write"), _ = async { while !status.lock().unwrap().attached { tokio::time::sleep(Duration::from_millis(5)).await; } } => {} }
            assert!(handle.app.inner.lock().await.fido.is_some());
            let offered = crate::relay::fido::poll(
                &handle.app,
                &binding.request,
                &binding.origin,
                binding.epoch,
            )
            .await;
            let open = serde_json::json!({"type":"fido_open","version":1,"relay_id":offered[0]["relay_id"],"remaining_ms":30000}).to_string();
            let ready = crate::relay::fido::incoming(
                &handle.app,
                &binding.request,
                &binding.origin,
                binding.epoch,
                &open,
            )
            .await
            .unwrap();
            assert_eq!(ready[0]["type"], "fido_ready");
            tokio::select! { _ = &mut operation => panic!("fake Exchange must block"), _ = tokio::time::sleep(Duration::from_millis(30)) => {} }
            cancel.send_replace(true);
            tokio::time::timeout(Duration::from_millis(500), operation)
                .await
                .unwrap()
                .ok();
        }
        assert!(child.stop().await);
        finish_fake(handle).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn old_open_completion_cannot_attach_to_new_connection() {
        let (handle, binding) = fake_paired().await;
        let mut child = fake_child("slow_open");
        let status = Arc::new(Mutex::new(Status::default()));
        let (_cancel, mut canceled) = watch::channel(false);
        let (_select, mut selected) = mpsc::channel(1);
        let selection = Selection::default();
        {
            let operation = session(
                &mut child,
                &handle,
                &binding,
                &status,
                &mut canceled,
                &mut selected,
                &selection,
            );
            tokio::pin!(operation);
            tokio::select! { _ = &mut operation => panic!("must wait for fake open"), _ = tokio::time::sleep(Duration::from_millis(60)) => {} }
            {
                let mut inner = handle.app.inner.lock().await;
                inner.epoch += 1;
                inner.connection_owner = Some((binding.request.clone(), inner.epoch));
            }
            assert!(operation.await.is_err());
        }
        assert!(handle.app.inner.lock().await.fido.is_none());
        assert!(!status.lock().unwrap().attached);
        assert!(child.stop().await);
        finish_fake(handle).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn multiple_keys_require_current_selection_and_stale_choice_never_attaches() {
        let (handle, binding) = fake_paired().await;
        let mut child = fake_child("multiple");
        let status = Arc::new(Mutex::new(Status::default()));
        let (_cancel, mut canceled) = watch::channel(false);
        let (select, mut selected) = mpsc::channel(1);
        let selection = Selection::default();
        {
            let operation = session(
                &mut child,
                &handle,
                &binding,
                &status,
                &mut canceled,
                &mut selected,
                &selection,
            );
            tokio::pin!(operation);
            tokio::select! { _ = &mut operation => panic!("must wait for selection"), _ = async { while status.lock().unwrap().choices.len() != 2 { tokio::time::sleep(Duration::from_millis(5)).await; } } => {} }
            assert!(handle.app.inner.lock().await.fido.is_none());
            select
                .send(crate::pairing::protocol::random_secret())
                .await
                .unwrap();
            assert!(operation.await.is_err());
        }
        assert!(handle.app.inner.lock().await.fido.is_none());
        assert!(child.stop().await);
        finish_fake(handle).await;
    }

    #[cfg(unix)]
    fn blocked_controller() -> (Controller, tokio::sync::oneshot::Receiver<bool>) {
        let mut child = fake_child("blocked_write");
        let (cancel, mut canceled) = watch::channel(false);
        let (select, _selected) = mpsc::channel(1);
        let (done, finished) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            child
                .request(
                    Request::Exchange {
                        report: Some(Report::from_slice(&[1; 64]).unwrap()),
                    },
                    &mut canceled,
                )
                .await
                .ok();
            let clean = child.stop().await;
            done.send(clean).ok();
            clean
        });
        let mut controller = Controller::default();
        controller.running = Some(Running {
            cancel,
            select,
            task,
            binding: dummy_binding(),
        });
        (controller, finished)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn controller_drop_and_shutdown_cancel_blocked_fake_worker() {
        let (controller, finished) = blocked_controller();
        drop(controller);
        assert!(tokio::time::timeout(Duration::from_secs(2), finished)
            .await
            .unwrap()
            .unwrap());
        let (mut controller, finished) = blocked_controller();
        controller.shutdown().await.unwrap();
        assert!(finished.await.unwrap());
        assert!(controller.running.is_none());
    }

    #[tokio::test]
    async fn failed_worker_reap_blocks_replacement_and_marks_status() {
        let (cancel, _canceled) = watch::channel(false);
        let (select, _selected) = mpsc::channel(1);
        let task = tokio::spawn(async { false });
        while !task.is_finished() {
            tokio::task::yield_now().await;
        }
        let mut controller = Controller::default();
        controller.running = Some(Running {
            cancel,
            select,
            task,
            binding: dummy_binding(),
        });
        controller.tick(None).await;
        assert!(controller.blocked);
        assert!(controller.status().cleanup_unconfirmed);
        controller.set_enabled(true);
        controller.retry();
        controller.tick(None).await;
        assert!(controller.running.is_none());
        assert!(controller.status().cleanup_unconfirmed);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn actual_attachment_expiry_interrupts_blocked_io_without_socket_polling() {
        let (handle, binding) = fake_paired().await;
        let mut child = fake_child("blocked_write");
        let status = Arc::new(Mutex::new(Status::default()));
        let (_cancel, mut canceled) = watch::channel(false);
        let (_select, mut selected) = mpsc::channel(1);
        let selection = Selection::default();
        {
            let operation = session(
                &mut child,
                &handle,
                &binding,
                &status,
                &mut canceled,
                &mut selected,
                &selection,
            );
            tokio::pin!(operation);
            tokio::select! { _ = &mut operation => panic!("must wait for fake write"), _ = async { while !status.lock().unwrap().attached { tokio::time::sleep(Duration::from_millis(5)).await; } } => {} }
            let advertised = crate::relay::fido::poll(
                &handle.app,
                &binding.request,
                &binding.origin,
                binding.epoch,
            )
            .await;
            let relay = advertised[0]["relay_id"].as_str().unwrap();
            let open =
            serde_json::json!({"type":"fido_open","version":1,"relay_id":relay,"remaining_ms":100})
                .to_string();
            assert!(crate::relay::fido::incoming(
                &handle.app,
                &binding.request,
                &binding.origin,
                binding.epoch,
                &open
            )
            .await
            .is_some());
            tokio::select! { _ = &mut operation => panic!("fake Exchange must begin before expiry"), _ = tokio::time::sleep(Duration::from_millis(30)) => {} }
            assert!(tokio::time::timeout(Duration::from_millis(500), operation)
                .await
                .unwrap()
                .is_err());
        }
        assert!(child.stop().await);
        finish_fake(handle).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn explicit_detach_survives_new_binding_until_local_retry_or_opt_in_toggle() {
        let (handle, binding) = fake_paired().await;
        let mut controller = Controller::default();
        controller.set_enabled(true);
        controller.detach();
        controller.tick(Some(&handle)).await;
        assert!(controller.running.is_none());
        assert!(controller.suspended);
        {
            let mut inner = handle.app.inner.lock().await;
            inner.epoch += 1;
            let request = crate::pairing::protocol::random_secret();
            inner.connection_owner = Some((request.clone(), inner.epoch));
            inner.pairing.as_mut().unwrap().request_id = Some(request);
        }
        assert!(Binding::current(&handle).await.as_ref() != Some(&binding));
        controller.tick(Some(&handle)).await;
        assert!(controller.running.is_none());
        assert!(controller.status().message.contains("USB: detached"));
        controller.retry();
        assert!(!controller.suspended);
        controller.detach();
        controller.set_enabled(false);
        controller.set_enabled(true);
        assert!(!controller.suspended);
        finish_fake(handle).await;
    }

    #[test]
    fn retry_retains_exact_choice_but_opt_in_toggle_resets_it() {
        let mut controller = Controller::default();
        controller.set_enabled(true);
        controller
            .selection
            .remember(&dummy_binding(), &device(2))
            .unwrap();
        controller.detach();
        controller.retry();
        assert!(controller.selection.recalled(&dummy_binding()).unwrap() == Some(device(2)));
        controller.set_enabled(false);
        controller.set_enabled(true);
        assert!(controller
            .selection
            .recalled(&dummy_binding())
            .unwrap()
            .is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remembered_key_missing_after_repair_never_falls_back_to_other_sole_key() {
        let (handle, binding) = fake_paired().await;
        let mut child = fake_child("single");
        let status = Arc::new(Mutex::new(Status::default()));
        let (_cancel, mut canceled) = watch::channel(false);
        let (_select, mut selected) = mpsc::channel(1);
        let selection = Selection::default();
        let mut previous = binding.clone();
        previous.request = "old-request".into();
        previous.epoch -= 1;
        selection.remember(&previous, &device(2)).unwrap();
        assert!(session(
            &mut child,
            &handle,
            &binding,
            &status,
            &mut canceled,
            &mut selected,
            &selection
        )
        .await
        .is_err());
        assert!(handle.app.inner.lock().await.fido.is_none());
        assert!(selection.recalled(&binding).unwrap() == Some(device(2)));
        assert!(child.stop().await);
        finish_fake(handle).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn helper_repair_reuses_exact_remembered_key_without_new_multi_key_choice() {
        let (handle, binding) = fake_paired().await;
        let mut child = fake_child("multiple");
        let status = Arc::new(Mutex::new(Status::default()));
        let (cancel, mut canceled) = watch::channel(false);
        let (_select, mut selected) = mpsc::channel(1);
        let selection = Selection::default();
        let mut previous = binding.clone();
        previous.request = "old-request".into();
        previous.epoch -= 1;
        selection.remember(&previous, &device(2)).unwrap();
        {
            let operation = session(
                &mut child,
                &handle,
                &binding,
                &status,
                &mut canceled,
                &mut selected,
                &selection,
            );
            tokio::pin!(operation);
            tokio::select! { _ = &mut operation => panic!("expected live fake attachment"), _ = async { while !status.lock().unwrap().attached { tokio::time::sleep(Duration::from_millis(5)).await; } } => {} }
            assert!(status.lock().unwrap().choices.is_empty());
            assert!(selection.recalled(&binding).unwrap() == Some(device(2)));
            cancel.send_replace(true);
            tokio::time::timeout(Duration::from_millis(500), operation)
                .await
                .unwrap()
                .ok();
        }
        assert!(child.stop().await);
        finish_fake(handle).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn waiting_offer_never_exchanges_hid_reports_and_renewal_keeps_same_device() {
        let (handle, binding) = fake_paired().await;
        // This fixture fails immediately if an Exchange arrives; it never opens HIDAPI.
        let mut child = fake_child("reject_exchange");
        let status = Arc::new(Mutex::new(Status::default()));
        let (_cancel, mut canceled) = watch::channel(false);
        let (_select, mut selected) = mpsc::channel(1);
        let selection = Selection::default();
        {
            let operation = session(
                &mut child,
                &handle,
                &binding,
                &status,
                &mut canceled,
                &mut selected,
                &selection,
            );
            tokio::pin!(operation);
            tokio::select! { _ = &mut operation => panic!("must wait before report I/O"), _ = async { while !status.lock().unwrap().attached { tokio::time::sleep(Duration::from_millis(5)).await; } } => {} }
            let available = crate::relay::fido::poll(
                &handle.app,
                &binding.request,
                &binding.origin,
                binding.epoch,
            )
            .await;
            let id = available[0]["relay_id"].as_str().unwrap();
            let request = serde_json::json!({"type":"fido_renew","version":1,"relay_id":id,"lease_sequence":1,"remaining_ms":30000}).to_string();
            let renewed = crate::relay::fido::incoming(
                &handle.app,
                &binding.request,
                &binding.origin,
                binding.epoch,
                &request,
            )
            .await
            .unwrap();
            assert_eq!(renewed[0]["type"], "fido_renewed");
            assert_eq!(renewed[0]["relay_id"], id);
            tokio::select! { _ = &mut operation => panic!("renewed waiting offer must not exchange reports"), _ = tokio::time::sleep(Duration::from_millis(100)) => {} }
            assert!(selection.recalled(&binding).unwrap() == Some(device(1)));
            let request =
            serde_json::json!({"type":"fido_open","version":1,"relay_id":id,"remaining_ms":30000})
                .to_string();
            let ready = crate::relay::fido::incoming(
                &handle.app,
                &binding.request,
                &binding.origin,
                binding.epoch,
                &request,
            )
            .await
            .unwrap();
            assert_eq!(ready[0]["type"], "fido_ready");
            // Only now does the fixture see Exchange and deliberately return Failed.
            assert!(tokio::time::timeout(Duration::from_millis(500), operation)
                .await
                .unwrap()
                .is_err());
        }
        assert!(child.stop().await);
        finish_fake(handle).await;
    }
}
