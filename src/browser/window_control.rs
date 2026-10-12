//! Owner-bound, idempotent browser-window lifecycle operations. Only fixed
//! commands, counts, opaque epochs and tab fingerprints cross these boundaries.
use crate::{
    app::{App, Inner},
    auth::{authorize, cookie, csrf},
};
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    future::Future,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{oneshot, watch, Mutex},
};
use uuid::Uuid;

const MAX_RECEIPTS: usize = 128;
// Keep the extension protocol bounds aligned with browser_window.js. The
// supervisor may report a larger inventory, but it must never reach mutation.
const MAX_EXTENSION_WINDOWS: u32 = 16;
const MAX_EXTENSION_TABS: u32 = 512;
const RPC_LIFETIME: Duration = Duration::from_secs(10);
const OPERATION_LIFETIME: Duration = Duration::from_secs(55);
pub(super) const UNAVAILABLE: Failure = Failure::new(
    StatusCode::SERVICE_UNAVAILABLE,
    "Browser window control is unavailable",
);
const INVALID_REPLY: Failure = Failure::new(
    StatusCode::SERVICE_UNAVAILABLE,
    "Invalid browser window response",
);
const REVOKED: Failure = Failure::new(StatusCode::UNAUTHORIZED, "Browser session changed");

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Action {
    Ensure,
    Restart,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    action: Action,
    request_id: String,
    operation_scope: String,
    operation_sequence: String,
}
impl Input {
    fn validate(&self) -> Result<u64, Failure> {
        if self.request_id.len() != 36 || Uuid::parse_str(&self.request_id).is_err() {
            return Err(Failure::new(
                StatusCode::BAD_REQUEST,
                "request_id must be a UUID",
            ));
        }
        if self.operation_scope.len() != 36 || Uuid::parse_str(&self.operation_scope).is_err() {
            return Err(Failure::new(
                StatusCode::BAD_REQUEST,
                "operation_scope must be a UUID",
            ));
        }
        let sequence = self
            .operation_sequence
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0 && value.to_string() == self.operation_sequence)
            .ok_or(Failure::new(
                StatusCode::BAD_REQUEST,
                "operation_sequence must be a positive decimal u64 string",
            ))?;
        Ok(sequence)
    }
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Failure {
    status: StatusCode,
    message: &'static str,
}
impl Failure {
    const fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }
    fn response(self) -> (StatusCode, String) {
        (self.status, self.message.into())
    }
}
#[derive(Clone, Copy, Debug)]
struct Outcome {
    restarted: bool,
    engine_ready: bool,
}
type Terminal = Result<Outcome, Failure>;

#[derive(Clone, PartialEq, Eq)]
struct Owner {
    csrf: String,
    session: Option<String>,
    epoch: u64,
}
impl Owner {
    fn capture(inner: &Inner, headers: &HeaderMap) -> Result<Self, Failure> {
        authorize(inner, headers, "vnc").map_err(|_| REVOKED)?;
        csrf(inner, headers)
            .map_err(|_| Failure::new(StatusCode::FORBIDDEN, "CSRF token required"))?;
        Ok(Self {
            csrf: cookie(headers, "ab_csrf").ok_or(REVOKED)?.into(),
            session: cookie(headers, "ab_vnc").map(str::to_owned),
            epoch: inner.vnc_epoch,
        })
    }
    fn valid(&self, inner: &Inner) -> bool {
        let now = Instant::now();
        self.epoch == inner.vnc_epoch
            && inner
                .csrf
                .get(&self.csrf)
                .is_some_and(|deadline| *deadline > now)
            && (inner.store.data.vnc_password_hash.is_none()
                || self
                    .session
                    .as_ref()
                    .and_then(|token| inner.sessions.get(token))
                    .is_some_and(|s| s.scope == "vnc" && s.epoch == self.epoch && s.expires > now))
    }
}
async fn check_owner(app: &App, owner: &Owner) -> Result<(), Failure> {
    if owner.valid(&*app.inner.lock().await) {
        Ok(())
    } else {
        Err(REVOKED)
    }
}

struct Entry {
    owner: Owner,
    action: Action,
    sequence: u64,
    terminal: watch::Sender<Option<Terminal>>,
}
struct Ledger {
    receipts: HashMap<String, Entry>,
    next_sequence: Option<u64>,
}
impl Ledger {
    fn trim(&mut self) {
        // Keep recent terminal receipts plus any in-flight operation. The
        // sequence high-water mark is never evicted, even across owner changes.
        loop {
            let terminals: Vec<_> = self
                .receipts
                .iter()
                .filter(|(_, entry)| entry.terminal.borrow().is_some())
                .map(|(id, entry)| (id.clone(), entry.sequence))
                .collect();
            if terminals.len() <= MAX_RECEIPTS {
                return;
            }
            let oldest = terminals
                .into_iter()
                .min_by_key(|(_, sequence)| *sequence)
                .unwrap()
                .0;
            self.receipts.remove(&oldest);
        }
    }
}
pub(crate) struct Controller {
    operation_scope: String,
    entries: Mutex<Ledger>,
    backend: Arc<dyn Backend>,
}
impl Default for Controller {
    fn default() -> Self {
        Self::new(Arc::new(SystemBackend))
    }
}
impl Controller {
    fn new(backend: Arc<dyn Backend>) -> Self {
        Self {
            operation_scope: Uuid::new_v4().to_string(),
            entries: Mutex::new(Ledger {
                receipts: HashMap::new(),
                next_sequence: Some(1),
            }),
            backend,
        }
    }
}

pub(crate) async fn next_operation(
    app: App,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let owner = Owner::capture(&*app.inner.lock().await, &headers).map_err(Failure::response)?;
    let controller = app.window_control.clone();

    // This snapshot does not reserve the sequence; POST admission resolves races.
    let next = controller
        .entries
        .lock()
        .await
        .next_sequence
        .ok_or_else(|| {
            Failure::new(
                StatusCode::CONFLICT,
                "Browser operation sequence is exhausted",
            )
            .response()
        })?;

    check_owner(&app, &owner).await.map_err(Failure::response)?;
    // This is read-only metadata. Merely requesting it never reserves a slot.
    Ok(Json(
        json!({"operation_scope":controller.operation_scope,"operation_sequence":next.to_string()}),
    )
    .into_response())
}

fn transient_conflict(code: &'static str, message: &'static str) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({"ok":false,"code":code,"message":message})),
    )
        .into_response()
}

pub(crate) async fn handle(
    app: App,
    headers: HeaderMap,
    input: Input,
) -> Result<Response, (StatusCode, String)> {
    let owner = Owner::capture(&*app.inner.lock().await, &headers).map_err(Failure::response)?;
    let sequence = input.validate().map_err(Failure::response)?;
    // UUID text case is not a new operation, but responses retain the caller's
    // exact request_id spelling as the public correlation contract requires.
    let request_key = Uuid::parse_str(&input.request_id).unwrap().to_string();
    let controller = app.window_control.clone();
    if input.operation_scope != controller.operation_scope {
        return Ok(transient_conflict(
            "stale_browser_intent",
            "Browser operation scope changed; start a new action",
        ));
    }
    let mut entries = controller.entries.lock().await;
    {
        let inner = app.inner.lock().await;
        if !owner.valid(&inner) {
            return Err(REVOKED.response());
        }
    }
    let (mut terminal, started) = if let Some(entry) = entries.receipts.get(&request_key) {
        if entry.owner != owner || entry.action != input.action || entry.sequence != sequence {
            return Err(Failure::new(
                StatusCode::CONFLICT,
                "request_id belongs to a different browser operation",
            )
            .response());
        }
        (entry.terminal.subscribe(), false)
    } else {
        if entries.next_sequence != Some(sequence) {
            return Ok(transient_conflict(
                "stale_browser_intent",
                "Browser operation is stale; start a new action",
            ));
        }
        let Ok(permit) = app.recovery_slots.clone().try_acquire_owned() else {
            return Ok(transient_conflict(
                "browser_operation_busy",
                "Browser recovery is already in progress",
            ));
        };
        let (sender, receiver) = watch::channel(None);
        entries.next_sequence = sequence.checked_add(1);
        entries.receipts.insert(
            request_key,
            Entry {
                owner: owner.clone(),
                action: input.action,
                sequence,
                terminal: sender.clone(),
            },
        );
        let task_app = app.clone();
        let task_input = input.clone();
        let task_owner = owner.clone();
        let backend = controller.backend.clone();
        // HTTP cancellation must not abandon an uncertain restart and permit a
        // duplicate. The bounded task owns the permit and records its outcome.
        tokio::spawn(async move {
            let _permit = permit;
            let deadline = Instant::now() + OPERATION_LIFETIME;
            let work = AssertUnwindSafe(workflow(
                &task_app,
                &task_owner,
                &task_input,
                backend.as_ref(),
                deadline,
            ))
            .catch_unwind();
            let result = match tokio::time::timeout(OPERATION_LIFETIME, work).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(Failure::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Browser operation failed",
                )),
                Err(_) => Err(Failure::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Browser operation timed out",
                )),
            };
            // Cancel any uncertain extension phase before releasing the global
            // operation permit, including on owner revocation or total timeout.
            task_app.broker.lock().await.cancel_window_control();
            // Publish terminal state and release capacity under the admission
            // lock, so a following exact-next request cannot observe success
            // while the previous operation still owns the mutation slot.
            let mut ledger = task_app.window_control.entries.lock().await;
            sender.send_replace(Some(result));
            ledger.trim();
            drop(_permit);
        });
        (receiver, true)
    };
    drop(entries);
    if started && terminal.borrow().is_none() {
        let _ = tokio::time::timeout(
            OPERATION_LIFETIME + Duration::from_secs(1),
            terminal.changed(),
        )
        .await;
    }
    check_owner(&app, &owner).await.map_err(Failure::response)?;
    let result = *terminal.borrow();
    match result {
        Some(Ok(outcome)) => Ok(Json(json!({"ok":true,"action":input.action,"request_id":input.request_id,
            "restarted":outcome.restarted,"engine_ready":outcome.engine_ready,"window_count":1,
            "operation_scope":input.operation_scope,"operation_sequence":input.operation_sequence})).into_response()),
        Some(Err(error)) => Err(error.response()),
        None => Ok((StatusCode::ACCEPTED, Json(json!({"ok":false,"in_progress":true,"action":input.action,"request_id":input.request_id,
            "operation_scope":input.operation_scope,"operation_sequence":input.operation_sequence}))).into_response()),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum WindowAction {
    Ensure,
    Consolidate,
    Verify,
}
#[derive(Clone, Debug)]
pub(super) struct WindowReply {
    pub window_count: u32,
    pub tab_count: u32,
    pub fingerprint: String,
}
struct PendingRpc {
    nonce: String,
    action: WindowAction,
    deadline: Instant,
    connection: String,
    expected_fingerprint: Option<String>,
    sender: oneshot::Sender<Result<WindowReply, Failure>>,
}
#[derive(Default)]
pub(super) struct WindowRpc {
    connection: Option<String>,
    pending: Option<PendingRpc>,
}
impl WindowRpc {
    pub(super) fn connected(&mut self) {
        self.revoke();
        self.connection = Some(Uuid::new_v4().to_string());
    }
    pub(super) fn connection(&self) -> Option<&str> {
        self.connection.as_deref()
    }
    pub(super) fn cancel(&mut self) -> Option<Value> {
        let pending = self.pending.take()?;
        let cancel = json!({"type":"window_control_cancel","nonce":pending.nonce});
        let _ = pending.sender.send(Err(UNAVAILABLE));
        Some(cancel)
    }
    pub(super) fn revoke(&mut self) {
        let _ = self.cancel();
        self.connection = None;
    }
    pub(super) fn expire(&mut self) -> Option<Value> {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.deadline <= Instant::now() || p.sender.is_closed())
        {
            self.cancel()
        } else {
            None
        }
    }
    pub(super) fn begin(
        &mut self,
        action: WindowAction,
        expected_window_count: u32,
        fingerprint: Option<String>,
        remaining_ms: u64,
    ) -> Result<(Value, oneshot::Receiver<Result<WindowReply, Failure>>), Failure> {
        let _ = self.expire();
        if self.pending.is_some()
            || expected_window_count > MAX_EXTENSION_WINDOWS
            || !(1..=10_000).contains(&remaining_ms)
        {
            return Err(UNAVAILABLE);
        }
        let connection = self.connection.clone().ok_or(UNAVAILABLE)?;
        if (action == WindowAction::Verify) != fingerprint.is_some()
            || fingerprint.as_ref().is_some_and(|s| !valid_fingerprint(s))
        {
            return Err(INVALID_REPLY);
        }
        let nonce = Uuid::new_v4().to_string();
        let (sender, receiver) = oneshot::channel();
        let mut request = json!({"type":"window_control","nonce":nonce,"action":action,
            "remaining_ms":remaining_ms,"expected_window_count":expected_window_count});
        if let Some(value) = &fingerprint {
            request["expected_fingerprint"] = json!(value);
        }
        self.pending = Some(PendingRpc {
            nonce,
            action,
            deadline: Instant::now() + Duration::from_millis(remaining_ms),
            connection,
            expected_fingerprint: fingerprint,
            sender,
        });
        Ok((request, receiver))
    }
    pub(super) fn reply(&mut self, value: Value) -> Result<(), String> {
        let _ = self.expire();
        let pending = self
            .pending
            .as_ref()
            .ok_or("No browser window operation pending")?;
        if value["nonce"].as_str() != Some(&pending.nonce) {
            return Err("Stale browser window response".into());
        }
        let pending = self.pending.take().unwrap();
        let outcome = (|| {
            let response: WireWindowReply =
                serde_json::from_value(value).map_err(|_| INVALID_REPLY)?;
            if response.kind != "window_control_result"
                || response.action != pending.action
                || self.connection.as_deref() != Some(&pending.connection)
                || pending.deadline <= Instant::now()
            {
                return Err(INVALID_REPLY);
            }
            if !response.ok {
                return Err(UNAVAILABLE);
            }
            let window_count = response
                .window_count
                .filter(|v| *v == 1)
                .ok_or(INVALID_REPLY)?;
            let tab_count = response
                .tab_count
                .filter(|v| (1..=MAX_EXTENSION_TABS).contains(v))
                .ok_or(INVALID_REPLY)?;
            let fingerprint = response
                .fingerprint
                .filter(|s| valid_fingerprint(s))
                .ok_or(INVALID_REPLY)?;
            if pending
                .expected_fingerprint
                .as_ref()
                .is_some_and(|expected| expected != &fingerprint)
            {
                return Err(INVALID_REPLY);
            }
            Ok(WindowReply {
                window_count,
                tab_count,
                fingerprint,
            })
        })();
        let success = outcome.is_ok();
        let _ = pending.sender.send(outcome);
        if success {
            Ok(())
        } else {
            Err("Browser window operation failed".into())
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireWindowReply {
    #[serde(rename = "type")]
    kind: String,
    #[allow(dead_code)]
    nonce: String,
    action: WindowAction,
    ok: bool,
    window_count: Option<u32>,
    tab_count: Option<u32>,
    fingerprint: Option<String>,
    // Never relay or log extension-provided diagnostics.
    #[serde(rename = "reason")]
    _reason: Option<String>,
}
fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Command {
    Inspect,
    Ensure,
    Restart,
    Maximize,
}
#[derive(Clone, Debug, Serialize)]
struct SupervisorRequest {
    command: Command,
    request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_epoch: Option<String>,
    remaining_ms: u64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisorReply {
    ok: bool,
    command: Command,
    request_id: String,
    browser_epoch: String,
    process_running: bool,
    window_count: u32,
    engine_ready: bool,
    #[serde(rename = "restarted")]
    _restarted: bool,
    #[serde(rename = "reason")]
    _reason: Option<String>,
}
impl SupervisorReply {
    fn validate(&self, request: &SupervisorRequest) -> Result<(), Failure> {
        if !self.ok {
            return Err(UNAVAILABLE);
        }
        if self.command != request.command
            || self.request_id != request.request_id
            || self.window_count > 64
            || !matches!(self.browser_epoch.len(), 32 | 36)
            || Uuid::parse_str(&self.browser_epoch).is_err()
            || (request.command != Command::Restart
                && request.command != Command::Ensure
                && request
                    .expected_epoch
                    .as_ref()
                    .is_some_and(|epoch| epoch != &self.browser_epoch))
        {
            return Err(INVALID_REPLY);
        }
        Ok(())
    }
}

// A fixed bounded protocol, tested with in-memory streams. Never interpolate
// response text or payloads into an error, log line, or browser-facing response.
async fn exchange<T: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut T,
    request: &SupervisorRequest,
) -> Result<SupervisorReply, Failure> {
    let mut command = serde_json::to_vec(request).map_err(|_| INVALID_REPLY)?;
    if command.len() > 512 {
        return Err(INVALID_REPLY);
    }
    command.push(b'\n');
    connection
        .write_all(&command)
        .await
        .map_err(|_| UNAVAILABLE)?;
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        if connection.read(&mut byte).await.map_err(|_| UNAVAILABLE)? == 0 {
            return Err(INVALID_REPLY);
        }
        if byte[0] == b'\n' {
            break;
        }
        if bytes.len() >= 4096 {
            return Err(INVALID_REPLY);
        }
        bytes.push(byte[0]);
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| INVALID_REPLY)?;
    if value["ok"] == false {
        return Err(UNAVAILABLE);
    }
    let response: SupervisorReply = serde_json::from_value(value).map_err(|_| INVALID_REPLY)?;
    response.validate(request)?;
    Ok(response)
}

type Phase<'a, T> = Pin<Box<dyn Future<Output = Result<T, Failure>> + Send + 'a>>;
#[derive(Clone)]
struct ExtensionRequest {
    action: WindowAction,
    expected_count: u32,
    fingerprint: Option<String>,
    previous_connection: Option<String>,
    deadline: Instant,
}
trait Backend: Send + Sync {
    fn supervisor<'a>(
        &'a self,
        app: &'a App,
        owner: &'a Owner,
        request: SupervisorRequest,
    ) -> Phase<'a, SupervisorReply>;
    fn extension<'a>(
        &'a self,
        app: &'a App,
        owner: &'a Owner,
        request: ExtensionRequest,
    ) -> Phase<'a, WindowReply>;
}
struct SystemBackend;
impl Backend for SystemBackend {
    fn supervisor<'a>(
        &'a self,
        app: &'a App,
        owner: &'a Owner,
        request: SupervisorRequest,
    ) -> Phase<'a, SupervisorReply> {
        Box::pin(async move {
            let deadline = Instant::now() + Duration::from_millis(request.remaining_ms);
            let mut request = request;
            let mut connection = tokio::net::UnixStream::connect("/data/run/reconnect.sock")
                .await
                .map_err(|_| UNAVAILABLE)?;
            check_owner(app, owner).await?;
            request.remaining_ms = remaining(deadline, 25_000)?;
            tokio::time::timeout(
                Duration::from_millis(request.remaining_ms),
                exchange(&mut connection, &request),
            )
            .await
            .map_err(|_| UNAVAILABLE)?
        })
    }
    fn extension<'a>(
        &'a self,
        app: &'a App,
        owner: &'a Owner,
        request: ExtensionRequest,
    ) -> Phase<'a, WindowReply> {
        Box::pin(async move {
            let mut changes = app.broker.lock().await.subscribe();
            let receiver = tokio::time::timeout(
                Duration::from_millis(remaining(request.deadline, 15_000)?),
                async {
                    loop {
                        {
                            let mut broker = app.broker.lock().await;
                            let inner = app.inner.lock().await;
                            if !owner.valid(&inner) {
                                return Err(REVOKED);
                            }
                            if broker.window_connection().is_some_and(|id| {
                                request.previous_connection.as_deref() != Some(id)
                            }) {
                                break broker.begin_window_control(
                                    request.action,
                                    request.expected_count,
                                    request.fingerprint.clone(),
                                    remaining(request.deadline, RPC_LIFETIME.as_millis() as u64)?,
                                );
                            }
                        }
                        changes.changed().await.map_err(|_| UNAVAILABLE)?;
                    }
                },
            )
            .await
            .map_err(|_| UNAVAILABLE)??;
            tokio::time::timeout(
                Duration::from_millis(remaining(
                    request.deadline,
                    RPC_LIFETIME.as_millis() as u64,
                )?),
                receiver,
            )
            .await
            .map_err(|_| UNAVAILABLE)?
            .map_err(|_| UNAVAILABLE)?
        })
    }
}
fn remaining(deadline: Instant, maximum_ms: u64) -> Result<u64, Failure> {
    let millis = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(u128::from(maximum_ms)) as u64;
    if millis == 0 {
        Err(UNAVAILABLE)
    } else {
        Ok(millis)
    }
}

async fn guarded<T>(
    app: &App,
    owner: &Owner,
    work: impl Future<Output = Result<T, Failure>>,
) -> Result<T, Failure> {
    let mut revoked = app.revoked.subscribe();
    check_owner(app, owner).await?;
    tokio::pin!(work);
    loop {
        tokio::select! {
            biased;
            _ = revoked.changed() => { check_owner(app, owner).await?; },
            result = &mut work => { check_owner(app, owner).await?; return result; },
            _ = tokio::time::sleep(Duration::from_millis(250)) => { check_owner(app, owner).await?; },
        }
    }
}
struct Operation<'a> {
    app: &'a App,
    owner: &'a Owner,
    input: &'a Input,
    backend: &'a dyn Backend,
    deadline: Instant,
}
impl Operation<'_> {
    async fn supervisor(
        &self,
        command: Command,
        epoch: Option<&str>,
    ) -> Result<SupervisorReply, Failure> {
        let request = SupervisorRequest {
            command,
            request_id: self.input.request_id.clone(),
            expected_epoch: epoch.map(str::to_owned),
            remaining_ms: remaining(self.deadline, 25_000)?,
        };
        let response = guarded(
            self.app,
            self.owner,
            self.backend
                .supervisor(self.app, self.owner, request.clone()),
        )
        .await?;
        response.validate(&request)?;
        Ok(response)
    }
    async fn extension(
        &self,
        action: WindowAction,
        count: u32,
        fingerprint: Option<String>,
        previous_connection: Option<String>,
    ) -> Result<WindowReply, Failure> {
        if count > MAX_EXTENSION_WINDOWS {
            return Err(UNAVAILABLE);
        }
        let request = ExtensionRequest {
            action,
            expected_count: count,
            fingerprint: fingerprint.clone(),
            previous_connection,
            deadline: self.deadline,
        };
        let reply = guarded(
            self.app,
            self.owner,
            self.backend.extension(self.app, self.owner, request),
        )
        .await?;
        if reply.window_count != 1
            || reply.tab_count == 0
            || reply.tab_count > MAX_EXTENSION_TABS
            || !valid_fingerprint(&reply.fingerprint)
            || fingerprint.is_some_and(|expected| expected != reply.fingerprint)
        {
            return Err(INVALID_REPLY);
        }
        Ok(reply)
    }
}
async fn workflow(
    app: &App,
    owner: &Owner,
    input: &Input,
    backend: &dyn Backend,
    deadline: Instant,
) -> Terminal {
    let operation = Operation {
        app,
        owner,
        input,
        backend,
        deadline,
    };
    // Inspect before choosing a side effect: missing control is not proof of an
    // absent browser, and a living process must not be replaced by initial ensure.
    let mut state = operation.supervisor(Command::Inspect, None).await?;

    if !state.process_running && state.window_count == 0 {
        let previous_epoch = state.browser_epoch.clone();
        state = operation
            .supervisor(Command::Ensure, Some(&previous_epoch))
            .await?;
        if !state.process_running || state.browser_epoch == previous_epoch {
            return Err(INVALID_REPLY);
        }
        if state.window_count != 1 || input.action == Action::Restart {
            operation
                .extension(
                    if state.window_count == 0 {
                        WindowAction::Ensure
                    } else {
                        WindowAction::Consolidate
                    },
                    state.window_count,
                    None,
                    None,
                )
                .await?;
        }
    } else if input.action == Action::Restart {
        // Complete consolidation before irreversible close. The old connection
        // identity also prevents a stale extension from verifying the new process.
        let old_connection = app
            .broker
            .lock()
            .await
            .window_connection()
            .map(str::to_owned)
            .ok_or(UNAVAILABLE)?;
        let prepared = operation
            .extension(
                if state.window_count == 0 {
                    WindowAction::Ensure
                } else {
                    WindowAction::Consolidate
                },
                state.window_count,
                None,
                None,
            )
            .await?;
        // Recheck the process/window generation after the asynchronous tab moves.
        let inspected = operation.supervisor(Command::Inspect, None).await?;
        if inspected.browser_epoch != state.browser_epoch || inspected.window_count != 1 {
            return Err(INVALID_REPLY);
        }
        let restarted_state = operation
            .supervisor(Command::Restart, Some(&state.browser_epoch))
            .await?;
        if restarted_state.browser_epoch == state.browser_epoch || !restarted_state.process_running
        {
            return Err(INVALID_REPLY);
        }
        state = restarted_state;
        operation
            .extension(
                WindowAction::Verify,
                state.window_count,
                Some(prepared.fingerprint),
                Some(old_connection),
            )
            .await?;
    } else if state.window_count != 1 {
        if !state.process_running {
            return Err(UNAVAILABLE);
        }
        operation
            .extension(
                if state.window_count == 0 {
                    WindowAction::Ensure
                } else {
                    WindowAction::Consolidate
                },
                state.window_count,
                None,
                None,
            )
            .await?;
    }
    // Window restoration is a final, separately acknowledged phase; an earlier
    // process launch or tab digest alone is not a maximized-window success.
    let checked = operation.supervisor(Command::Inspect, None).await?;
    if checked.browser_epoch != state.browser_epoch || checked.window_count != 1 {
        return Err(INVALID_REPLY);
    }
    let maximized = operation
        .supervisor(Command::Maximize, Some(&checked.browser_epoch))
        .await?;
    if maximized.window_count != 1 {
        return Err(INVALID_REPLY);
    }
    Ok(Outcome {
        restarted: input.action == Action::Restart,
        engine_ready: maximized.engine_ready,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{browser::broker::Broker, test_support};
    use axum::{
        body::to_bytes,
        http::{header, HeaderValue},
    };
    use std::collections::VecDeque;
    use tokio::sync::{mpsc, Notify};

    const OLD: &str = "0123456789abcdef0123456789abcdef";
    const NEW: &str = "abcdef0123456789abcdef0123456789";
    const CSRF: &str = "window-control-test-csrf";
    fn fingerprint() -> String {
        "ab".repeat(32)
    }
    fn input(action: Action) -> Input {
        Input {
            action,
            request_id: Uuid::new_v4().to_string(),
            operation_scope: Uuid::new_v4().to_string(),
            operation_sequence: "1".into(),
        }
    }
    fn window_reply(request: &Value) -> Value {
        json!({"type":"window_control_result","nonce":request["nonce"],"action":request["action"],
            "ok":true,"window_count":1,"tab_count":3,"fingerprint":fingerprint()})
    }
    fn ready() -> Value {
        let mut ready = crate::browser::broker::tests::test_ready("proxy", true, 0);
        ready["capabilities"]
            .as_array_mut()
            .unwrap()
            .push(json!("window_control"));
        ready
    }

    #[tokio::test]
    async fn rpc_is_optional_nonce_bound_bounded_and_revoked_with_control() {
        let mut broker = Broker::default();
        let (tx, mut outbound) = mpsc::unbounded_channel();
        broker.connected(tx);
        broker
            .on_message(
                crate::browser::broker::tests::test_ready("proxy", true, 0),
                &[],
            )
            .unwrap();
        assert!(broker.window_connection().is_none());
        assert!(broker
            .begin_window_control(WindowAction::Ensure, 0, None, 10000)
            .is_err());
        broker.on_message(ready(), &[]).unwrap();
        let first_connection = broker.window_connection().unwrap().to_owned();
        let mut receiver = broker
            .begin_window_control(WindowAction::Consolidate, 2, None, 10000)
            .unwrap();
        let request = outbound.try_recv().unwrap();
        assert_eq!(request["expected_window_count"], 2);
        assert_eq!(request["remaining_ms"], 10000);
        assert!(broker
            .begin_window_control(WindowAction::Ensure, 0, None, 10000)
            .is_err());
        let mut wrong = window_reply(&request);
        wrong["nonce"] = json!(Uuid::new_v4().to_string());
        assert!(broker.on_message(wrong, &[]).is_err());
        assert!(matches!(
            receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        broker.on_message(window_reply(&request), &[]).unwrap();
        assert_eq!(receiver.await.unwrap().unwrap().fingerprint, fingerprint());
        assert!(broker.on_message(window_reply(&request), &[]).is_err());
        let receiver = broker
            .begin_window_control(WindowAction::Verify, 1, Some(fingerprint()), 10000)
            .unwrap();
        outbound.try_recv().unwrap();
        broker.disconnected();
        assert!(receiver.await.unwrap().is_err());
        let (tx, _outbound) = mpsc::unbounded_channel();
        broker.connected(tx);
        broker.on_message(ready(), &[]).unwrap();
        assert_ne!(broker.window_connection().unwrap(), first_connection);
    }

    #[tokio::test]
    async fn rpc_rejects_malformed_fingerprint_counts_and_action_without_reflecting_payloads() {
        for (field, value) in [
            ("action", json!("ensure")),
            ("window_count", json!(2)),
            ("tab_count", json!(0)),
            ("tab_count", json!(513)),
            (
                "fingerprint",
                json!("https://secret.invalid/?private=TOKEN"),
            ),
            ("raw_url", json!("https://secret.invalid/?private=TOKEN")),
        ] {
            let mut rpc = WindowRpc::default();
            rpc.connected();
            let (request, receiver) = rpc
                .begin(WindowAction::Consolidate, 2, None, 10000)
                .unwrap();
            let mut response = window_reply(&request);
            response[field] = value;
            let error = rpc.reply(response).unwrap_err();
            assert!(!error.contains("TOKEN"));
            assert!(receiver.await.unwrap().is_err());
        }
        let mut rpc = WindowRpc::default();
        rpc.connected();
        let (request, receiver) = rpc
            .begin(WindowAction::Verify, 1, Some("cd".repeat(32)), 10000)
            .unwrap();
        assert!(rpc.reply(window_reply(&request)).is_err());
        assert!(receiver.await.unwrap().is_err());
        assert!(rpc.begin(WindowAction::Ensure, 0, None, 10001).is_err());
        assert!(rpc.begin(WindowAction::Ensure, 0, None, 0).is_err());
    }

    #[tokio::test]
    async fn extension_inventory_bounds_reject_before_enqueue_and_accept_exact_limits() {
        let mut broker = Broker::default();
        let (tx, mut outbound) = mpsc::unbounded_channel();
        broker.connected(tx);
        broker.on_message(ready(), &[]).unwrap();
        for count in [17, 64, u32::MAX] {
            assert!(broker
                .begin_window_control(WindowAction::Consolidate, count, None, 10000)
                .is_err());
            assert!(outbound.try_recv().is_err());
        }
        let receiver = broker
            .begin_window_control(WindowAction::Consolidate, 16, None, 10000)
            .unwrap();
        let request = outbound.try_recv().unwrap();
        assert_eq!(request["expected_window_count"], 16);
        let mut response = window_reply(&request);
        response["tab_count"] = json!(512);
        broker.on_message(response, &[]).unwrap();
        assert_eq!(receiver.await.unwrap().unwrap().tab_count, 512);

        for action in [Action::Ensure, Action::Restart] {
            for count in [17, 64] {
                let fixture =
                    Fixture::new(vec![Step::supervisor(Command::Inspect, OLD, count)]).await;
                assert!(fixture.workflow(action).await.is_err());
                fixture.fake.done().await;
                assert_eq!(fixture.fake.calls.lock().await.len(), 1);
            }
        }
    }

    #[tokio::test]
    async fn abandoned_or_expired_rpc_sends_one_fixed_cancel_and_never_accepts_late_reply() {
        let mut broker = Broker::default();
        let (tx, mut outbound) = mpsc::unbounded_channel();
        broker.connected(tx);
        broker.on_message(ready(), &[]).unwrap();
        let receiver = broker
            .begin_window_control(WindowAction::Consolidate, 2, None, 10000)
            .unwrap();
        let request = outbound.try_recv().unwrap();
        drop(receiver);
        broker.expire();
        assert_eq!(
            outbound.try_recv().unwrap(),
            json!({"type":"window_control_cancel","nonce":request["nonce"]})
        );
        broker.expire();
        assert!(outbound.try_recv().is_err());
        assert!(broker.on_message(window_reply(&request), &[]).is_err());
        let mut rpc = WindowRpc::default();
        rpc.connected();
        let (request, receiver) = rpc.begin(WindowAction::Ensure, 0, None, 10000).unwrap();
        rpc.pending.as_mut().unwrap().deadline = Instant::now();
        assert!(rpc.expire().is_some());
        assert!(rpc.expire().is_none());
        assert!(receiver.await.unwrap().is_err());
        assert!(rpc.reply(window_reply(&request)).is_err());
    }

    #[derive(Clone)]
    struct Step {
        command: Option<Command>,
        action: Option<WindowAction>,
        epoch: &'static str,
        running: bool,
        windows: u32,
        expected_count: u32,
        expected_epoch: Option<&'static str>,
        engine_ready: bool,
        revoke: bool,
        block: Option<Arc<Notify>>,
        failure: bool,
        fingerprint: String,
    }
    impl Step {
        fn supervisor(command: Command, epoch: &'static str, windows: u32) -> Self {
            Self {
                command: Some(command),
                action: None,
                epoch,
                running: true,
                windows,
                expected_count: 0,
                expected_epoch: None,
                engine_ready: false,
                revoke: false,
                block: None,
                failure: false,
                fingerprint: fingerprint(),
            }
        }
        fn extension(action: WindowAction, expected_count: u32) -> Self {
            Self {
                command: None,
                action: Some(action),
                epoch: OLD,
                running: true,
                windows: 1,
                expected_count,
                expected_epoch: None,
                engine_ready: false,
                revoke: false,
                block: None,
                failure: false,
                fingerprint: fingerprint(),
            }
        }
    }
    struct Fake {
        steps: Mutex<VecDeque<Step>>,
        calls: Mutex<Vec<Value>>,
        entered: Notify,
    }
    impl Fake {
        fn new(steps: Vec<Step>) -> Arc<Self> {
            Arc::new(Self {
                steps: Mutex::new(steps.into()),
                calls: Mutex::new(Vec::new()),
                entered: Notify::new(),
            })
        }
        async fn effect(&self, app: &App, step: &Step) {
            self.entered.notify_one();
            if let Some(block) = &step.block {
                block.notified().await;
            }
            if step.revoke {
                app.inner.lock().await.vnc_epoch += 1;
                app.revoked.send_modify(|epoch| *epoch += 1);
            }
        }
        async fn done(&self) {
            assert!(self.steps.lock().await.is_empty());
        }
    }
    impl Backend for Fake {
        fn supervisor<'a>(
            &'a self,
            app: &'a App,
            _: &'a Owner,
            request: SupervisorRequest,
        ) -> Phase<'a, SupervisorReply> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .await
                    .push(serde_json::to_value(&request).unwrap());
                let step = self
                    .steps
                    .lock()
                    .await
                    .pop_front()
                    .expect("unexpected supervisor phase");
                assert_eq!(step.command, Some(request.command));
                assert_eq!(request.expected_epoch.as_deref(), step.expected_epoch);
                assert!((1..=25000).contains(&request.remaining_ms));
                self.effect(app, &step).await;
                if step.failure {
                    return Err(UNAVAILABLE);
                }
                Ok(SupervisorReply {
                    ok: true,
                    command: request.command,
                    request_id: request.request_id,
                    browser_epoch: step.epoch.into(),
                    process_running: step.running,
                    window_count: step.windows,
                    engine_ready: step.engine_ready,
                    _restarted: request.command == Command::Restart,
                    _reason: None,
                })
            })
        }
        fn extension<'a>(
            &'a self,
            app: &'a App,
            _: &'a Owner,
            request: ExtensionRequest,
        ) -> Phase<'a, WindowReply> {
            Box::pin(async move {
                self.calls.lock().await.push(json!({"extension":request.action,"expected_count":request.expected_count,
                    "fingerprint":request.fingerprint,"previous_connection":request.previous_connection}));
                let step = self
                    .steps
                    .lock()
                    .await
                    .pop_front()
                    .expect("unexpected extension phase");
                assert_eq!(step.action, Some(request.action));
                assert_eq!(step.expected_count, request.expected_count);
                if request.action == WindowAction::Verify {
                    assert_eq!(request.fingerprint, Some(fingerprint()));
                    assert!(request.previous_connection.is_some());
                } else {
                    assert!(request.fingerprint.is_none());
                }
                self.effect(app, &step).await;
                if step.failure {
                    return Err(UNAVAILABLE);
                }
                Ok(WindowReply {
                    window_count: step.windows,
                    tab_count: 3,
                    fingerprint: step.fingerprint,
                })
            })
        }
    }
    struct Fixture {
        app: App,
        owner: Owner,
        headers: HeaderMap,
        fake: Arc<Fake>,
        dir: std::path::PathBuf,
        _outbound: mpsc::UnboundedReceiver<Value>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    impl Fixture {
        async fn new(steps: Vec<Step>) -> Self {
            let (mut app, dir) = test_support::app();
            let fake = Fake::new(steps);
            app.window_control = Arc::new(Controller::new(fake.clone()));
            app.inner
                .lock()
                .await
                .csrf
                .insert(CSRF.into(), Instant::now() + Duration::from_secs(3600));
            let mut headers = HeaderMap::new();
            headers.insert(
                header::COOKIE,
                HeaderValue::from_str(&format!("ab_csrf={CSRF}")).unwrap(),
            );
            headers.insert("x-csrf-token", HeaderValue::from_static(CSRF));
            let owner = Owner::capture(&*app.inner.lock().await, &headers).unwrap();
            let (tx, outbound) = mpsc::unbounded_channel();
            {
                let mut broker = app.broker.lock().await;
                broker.connected(tx);
                broker.on_message(ready(), &[]).unwrap();
            }
            Self {
                app,
                owner,
                headers,
                fake,
                dir,
                _outbound: outbound,
            }
        }
        async fn input(&self, action: Action) -> Input {
            let mut input = input(action);
            input.operation_scope = self.app.window_control.operation_scope.clone();
            input.operation_sequence = self
                .app
                .window_control
                .entries
                .lock()
                .await
                .next_sequence
                .unwrap()
                .to_string();
            input
        }
        async fn workflow(&self, action: Action) -> Terminal {
            workflow(
                &self.app,
                &self.owner,
                &input(action),
                self.fake.as_ref(),
                Instant::now() + OPERATION_LIFETIME,
            )
            .await
        }
    }
    fn finish_steps(epoch: &'static str) -> Vec<Step> {
        let mut maximize = Step::supervisor(Command::Maximize, epoch, 1);
        maximize.expected_epoch = Some(epoch);
        vec![Step::supervisor(Command::Inspect, epoch, 1), maximize]
    }

    #[tokio::test]
    async fn ensure_one_identified_window_succeeds_without_extension_or_engine() {
        let mut steps = vec![Step::supervisor(Command::Inspect, OLD, 1)];
        steps.extend(finish_steps(OLD));
        let fixture = Fixture::new(steps).await;
        fixture.app.broker.lock().await.disconnected();
        let result = fixture.workflow(Action::Ensure).await.unwrap();
        assert!(!result.restarted && !result.engine_ready);
        fixture.fake.done().await;
    }

    #[tokio::test]
    async fn ensure_zero_live_windows_uses_extension_and_multiple_windows_consolidate_without_restart(
    ) {
        for count in [0, 2] {
            let mut steps = vec![
                Step::supervisor(Command::Inspect, OLD, count),
                Step::extension(
                    if count == 0 {
                        WindowAction::Ensure
                    } else {
                        WindowAction::Consolidate
                    },
                    count,
                ),
            ];
            steps.extend(finish_steps(OLD));
            let fixture = Fixture::new(steps).await;
            assert!(!fixture.workflow(Action::Ensure).await.unwrap().restarted);
            fixture.fake.done().await;
            assert!(!fixture
                .fake
                .calls
                .lock()
                .await
                .iter()
                .any(|v| v["command"] == "restart" || v["command"] == "ensure"));
        }
    }

    #[tokio::test]
    async fn absent_process_uses_ensure_without_claiming_live_fingerprint_equivalence() {
        for action in [Action::Ensure, Action::Restart] {
            let mut absent = Step::supervisor(Command::Inspect, OLD, 0);
            absent.running = false;
            let mut create = Step::supervisor(Command::Ensure, NEW, 1);
            create.expected_epoch = Some(OLD);
            let mut steps = vec![absent, create];
            if action == Action::Restart {
                steps.push(Step::extension(WindowAction::Consolidate, 1));
            }
            steps.extend(finish_steps(NEW));
            let fixture = Fixture::new(steps).await;
            assert_eq!(
                fixture.workflow(action).await.unwrap().restarted,
                action == Action::Restart
            );
            fixture.fake.done().await;
            assert!(!fixture
                .fake
                .calls
                .lock()
                .await
                .iter()
                .any(|v| v["extension"] == "verify"));
        }
    }

    fn restart_steps(count: u32) -> Vec<Step> {
        let mut restart = Step::supervisor(Command::Restart, NEW, 1);
        restart.expected_epoch = Some(OLD);
        let mut steps = vec![
            Step::supervisor(Command::Inspect, OLD, count),
            Step::extension(
                if count == 0 {
                    WindowAction::Ensure
                } else {
                    WindowAction::Consolidate
                },
                count,
            ),
            Step::supervisor(Command::Inspect, OLD, 1),
            restart,
            Step::extension(WindowAction::Verify, 1),
        ];
        steps.extend(finish_steps(NEW));
        steps
    }
    #[tokio::test]
    async fn restart_preserves_fingerprint_rechecks_epoch_and_verifies_before_maximizing() {
        for count in [0, 1, 3] {
            let fixture = Fixture::new(restart_steps(count)).await;
            assert!(fixture.workflow(Action::Restart).await.unwrap().restarted);
            fixture.fake.done().await;
        }
    }

    #[tokio::test]
    async fn epoch_change_owner_revocation_or_restore_mismatch_stops_later_mutations() {
        let mut steps = restart_steps(2);
        steps[2].epoch = NEW;
        steps.truncate(3);
        let fixture = Fixture::new(steps).await;
        assert!(fixture.workflow(Action::Restart).await.is_err());
        fixture.fake.done().await;
        let mut steps = restart_steps(2);
        steps[1].revoke = true;
        steps.truncate(2);
        let fixture = Fixture::new(steps).await;
        assert_eq!(
            fixture.workflow(Action::Restart).await.unwrap_err().status,
            StatusCode::UNAUTHORIZED
        );
        fixture.fake.done().await;
        let mut steps = restart_steps(2);
        steps[4].fingerprint = "cd".repeat(32);
        steps.truncate(5);
        let fixture = Fixture::new(steps).await;
        assert!(fixture.workflow(Action::Restart).await.is_err());
        fixture.fake.done().await;
    }

    async fn json_body(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
    }
    async fn assert_transient(result: Result<Response, (StatusCode, String)>, code: &str) {
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let value = json_body(response).await;
        assert_eq!(value["ok"], false);
        assert_eq!(value["code"], code);
    }

    #[tokio::test]
    async fn identical_requests_share_terminal_result_and_mismatched_action_or_owner_rejects() {
        let fixture = Fixture::new(restart_steps(1)).await;
        let request = fixture.input(Action::Restart).await;
        let first = json_body(
            handle(
                fixture.app.clone(),
                fixture.headers.clone(),
                request.clone(),
            )
            .await
            .unwrap(),
        )
        .await;
        let second = json_body(
            handle(
                fixture.app.clone(),
                fixture.headers.clone(),
                request.clone(),
            )
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(first, second);
        assert_eq!(first["request_id"], request.request_id);
        assert_eq!(first["action"], "restart");
        assert_eq!(first["restarted"], true);
        assert_eq!(first["window_count"], 1);
        let mut alternate_case = request.clone();
        alternate_case.request_id = alternate_case.request_id.to_uppercase();
        let same = json_body(
            handle(
                fixture.app.clone(),
                fixture.headers.clone(),
                alternate_case.clone(),
            )
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(same["request_id"], alternate_case.request_id);
        assert_eq!(same["restarted"], true);
        fixture.fake.done().await;
        let mut mismatched = request.clone();
        mismatched.action = Action::Ensure;
        assert_eq!(
            handle(fixture.app.clone(), fixture.headers.clone(), mismatched)
                .await
                .unwrap_err()
                .0,
            StatusCode::CONFLICT
        );
        let mut other = fixture.headers.clone();
        fixture.app.inner.lock().await.csrf.insert(
            "another-csrf".into(),
            Instant::now() + Duration::from_secs(100),
        );
        other.insert(
            header::COOKIE,
            HeaderValue::from_static("ab_csrf=another-csrf"),
        );
        other.insert("x-csrf-token", HeaderValue::from_static("another-csrf"));
        assert_eq!(
            handle(fixture.app.clone(), other, request)
                .await
                .unwrap_err()
                .0,
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn concurrent_duplicate_gets_bounded_progress_and_http_drop_does_not_restart_twice() {
        let gate = Arc::new(Notify::new());
        let mut steps = restart_steps(1);
        steps[0].block = Some(gate.clone());
        let fixture = Fixture::new(steps).await;
        let request = fixture.input(Action::Restart).await;
        let app = fixture.app.clone();
        let headers = fixture.headers.clone();
        let task_request = request.clone();
        let first = tokio::spawn(async move { handle(app, headers, task_request).await });
        fixture.fake.entered.notified().await;
        let duplicate = handle(
            fixture.app.clone(),
            fixture.headers.clone(),
            request.clone(),
        )
        .await
        .unwrap();
        assert_eq!(duplicate.status(), StatusCode::ACCEPTED);
        let progress = json_body(duplicate).await;
        assert_eq!(progress["in_progress"], true);
        assert_eq!(progress["request_id"], request.request_id);
        first.abort();
        gate.notify_one();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let response = handle(
                    fixture.app.clone(),
                    fixture.headers.clone(),
                    request.clone(),
                )
                .await
                .unwrap();
                if response.status() == StatusCode::OK {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        fixture.fake.done().await;
        assert_eq!(
            fixture
                .fake
                .calls
                .lock()
                .await
                .iter()
                .filter(|v| v["command"] == "restart")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn uncertain_mutation_error_is_cached_and_never_retried() {
        let mut steps = restart_steps(1);
        steps[3].failure = true;
        steps.truncate(4);
        let fixture = Fixture::new(steps).await;
        let request = fixture.input(Action::Restart).await;
        for _ in 0..2 {
            assert_eq!(
                handle(
                    fixture.app.clone(),
                    fixture.headers.clone(),
                    request.clone()
                )
                .await
                .unwrap_err()
                .0,
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        fixture.fake.done().await;
        assert_eq!(
            fixture
                .fake
                .calls
                .lock()
                .await
                .iter()
                .filter(|v| v["command"] == "restart")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn owner_expiry_or_logout_during_wait_prevents_any_later_phase() {
        for mode in ["csrf", "epoch", "session"] {
            let gate = Arc::new(Notify::new());
            let mut step = Step::supervisor(Command::Inspect, OLD, 1);
            step.block = Some(gate);
            let fixture = Fixture::new(vec![step]).await;
            if mode == "session" {
                let mut inner = fixture.app.inner.lock().await;
                inner.store.data.vnc_password_hash = Some("protected".into());
                inner.sessions.insert(
                    "owner".into(),
                    crate::app::Session {
                        scope: "vnc".into(),
                        epoch: 0,
                        expires: Instant::now() + Duration::from_secs(60),
                    },
                );
            }
            let mut headers = fixture.headers.clone();
            if mode == "session" {
                headers.insert(
                    header::COOKIE,
                    HeaderValue::from_str(&format!("ab_csrf={CSRF}; ab_vnc=owner")).unwrap(),
                );
            }
            let app = fixture.app.clone();
            let request = fixture.input(Action::Ensure).await;
            let task = tokio::spawn(async move { handle(app, headers, request).await });
            fixture.fake.entered.notified().await;
            {
                let mut inner = fixture.app.inner.lock().await;
                match mode {
                    "csrf" => {
                        inner.csrf.remove(CSRF);
                    }
                    "epoch" => inner.vnc_epoch += 1,
                    _ => {
                        inner.sessions.remove("owner");
                    }
                }
            }
            fixture.app.revoked.send_modify(|v| *v += 1);
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap_err()
                    .0,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(fixture.fake.calls.lock().await.len(), 1);
        }
    }

    #[tokio::test]
    async fn supervisor_protocol_is_bounded_fixed_and_rejects_stale_or_secret_responses() {
        let request = SupervisorRequest {
            command: Command::Inspect,
            request_id: Uuid::new_v4().to_string(),
            expected_epoch: None,
            remaining_ms: 5000,
        };
        let valid = json!({"ok":true,"command":"inspect","request_id":request.request_id,"browser_epoch":OLD,
            "process_running":true,"window_count":1,"engine_ready":false,"restarted":false});
        for response in [
            valid.clone(),
            json!({"ok":false,"error":"https://secret.invalid/?token=PRIVATE"}),
            json!({"ok":true}),
            {
                let mut bad = valid.clone();
                bad["request_id"] = json!(Uuid::new_v4().to_string());
                bad
            },
        ] {
            let expected = response == valid;
            let (mut client, mut server) = tokio::io::duplex(8192);
            let sent = request.clone();
            let peer = tokio::spawn(async move {
                let mut bytes = Vec::new();
                loop {
                    let mut byte = [0];
                    server.read_exact(&mut byte).await.unwrap();
                    if byte[0] == b'\n' {
                        break;
                    }
                    bytes.push(byte[0]);
                }
                assert_eq!(
                    serde_json::from_slice::<Value>(&bytes).unwrap(),
                    serde_json::to_value(sent).unwrap()
                );
                let bytes = serde_json::to_vec(&response).unwrap();
                let mid = bytes.len() / 2;
                server.write_all(&bytes[..mid]).await.unwrap();
                tokio::task::yield_now().await;
                server.write_all(&bytes[mid..]).await.unwrap();
                server.write_all(b"\n").await.unwrap();
            });
            let result = exchange(&mut client, &request).await;
            assert_eq!(result.is_ok(), expected);
            if let Err(error) = result {
                assert!(!error.message.contains("PRIVATE"));
            }
            peer.await.unwrap();
        }
        for response in [vec![b'x'; 4097], b"{}".to_vec()] {
            let (mut client, mut server) = tokio::io::duplex(8192);
            let peer = tokio::spawn(async move {
                let mut buf = [0; 512];
                let _ = server.read(&mut buf).await.unwrap();
                server.write_all(&response).await.unwrap();
            });
            assert!(exchange(&mut client, &request).await.is_err());
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn public_schema_rejects_missing_unknown_actions_ids_and_fields() {
        let fixture = Fixture::new(vec![]).await;
        for value in [
            json!({}),
            json!({"action":"kill","request_id":Uuid::new_v4().to_string()}),
            json!({"action":"ensure","request_id":"not-a-uuid"}),
            json!({"action":"restart","request_id":Uuid::new_v4().to_string(),"url":"https://private.invalid"}),
        ] {
            let response = test_support::call(
                &fixture.app,
                "POST",
                "/api/browser/reconnect",
                value,
                &format!("ab_csrf={CSRF}"),
                CSRF,
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        assert!(fixture.fake.calls.lock().await.is_empty());
    }
    #[tokio::test]
    async fn more_than_128_ensure_and_restart_actions_keep_bounded_receipts_and_reject_evicted_replays(
    ) {
        let mut steps = Vec::new();
        for index in 0..260 {
            if index % 2 == 0 {
                steps.push(Step::supervisor(Command::Inspect, OLD, 1));
                steps.extend(finish_steps(OLD));
            } else {
                steps.extend(restart_steps(1));
            }
        }
        let fixture = Fixture::new(steps).await;
        let first = fixture.input(Action::Ensure).await;
        for index in 0..260 {
            let request = if index == 0 {
                first.clone()
            } else {
                fixture
                    .input(if index % 2 == 0 {
                        Action::Ensure
                    } else {
                        Action::Restart
                    })
                    .await
            };
            let response = handle(
                fixture.app.clone(),
                fixture.headers.clone(),
                request.clone(),
            )
            .await
            .unwrap();
            let value = json_body(response).await;
            assert_eq!(value["operation_scope"], request.operation_scope);
            assert_eq!(value["operation_sequence"], request.operation_sequence);
        }
        fixture.fake.done().await;
        {
            let ledger = fixture.app.window_control.entries.lock().await;
            assert_eq!(ledger.next_sequence, Some(261));
            assert_eq!(ledger.receipts.len(), MAX_RECEIPTS);
            assert!(!ledger.receipts.contains_key(&first.request_id));
        }
        let calls = fixture.fake.calls.lock().await.len();
        assert_transient(
            handle(fixture.app.clone(), fixture.headers.clone(), first.clone()).await,
            "stale_browser_intent",
        )
        .await;
        let mut substituted = first;
        substituted.request_id = Uuid::new_v4().to_string();
        assert_transient(
            handle(fixture.app.clone(), fixture.headers.clone(), substituted).await,
            "stale_browser_intent",
        )
        .await;
        assert_eq!(fixture.fake.calls.lock().await.len(), calls);
    }

    #[tokio::test]
    async fn metadata_does_not_reserve_sequence_and_rejects_future_or_prior_boot_intents() {
        let fixture = Fixture::new(vec![]).await;
        let first = json_body(
            next_operation(fixture.app.clone(), fixture.headers.clone())
                .await
                .unwrap(),
        )
        .await;
        let second = json_body(
            next_operation(fixture.app.clone(), fixture.headers.clone())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(first, second);
        assert_eq!(first["operation_sequence"], "1");
        let mut ahead = fixture.input(Action::Ensure).await;
        ahead.operation_sequence = "2".into();
        assert_transient(
            handle(fixture.app.clone(), fixture.headers.clone(), ahead).await,
            "stale_browser_intent",
        )
        .await;
        let old = fixture.input(Action::Restart).await;
        let mut rebooted = fixture.app.clone();
        rebooted.window_control = Arc::new(Controller::new(fixture.fake.clone()));
        assert_ne!(rebooted.window_control.operation_scope, old.operation_scope);
        assert_transient(
            handle(rebooted, fixture.headers.clone(), old).await,
            "stale_browser_intent",
        )
        .await;
        assert!(fixture.fake.calls.lock().await.is_empty());
        assert_eq!(
            next_operation(fixture.app.clone(), HeaderMap::new())
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn verification_waits_for_fresh_control_identity_and_bounds_remaining_budget() {
        let fixture = Fixture::new(vec![]).await;
        let previous = fixture
            .app
            .broker
            .lock()
            .await
            .window_connection()
            .unwrap()
            .to_owned();
        let app = fixture.app.clone();
        let owner = fixture.owner.clone();
        let worker = tokio::spawn(async move {
            SystemBackend
                .extension(
                    &app,
                    &owner,
                    ExtensionRequest {
                        action: WindowAction::Verify,
                        expected_count: 1,
                        fingerprint: Some(fingerprint()),
                        previous_connection: Some(previous),
                        deadline: Instant::now() + Duration::from_secs(3),
                    },
                )
                .await
        });
        tokio::task::yield_now().await;
        fixture
            .app
            .broker
            .lock()
            .await
            .on_message(ready(), &[])
            .unwrap();
        tokio::task::yield_now().await;
        assert!(!worker.is_finished());
        let (tx, mut new_output) = mpsc::unbounded_channel();
        {
            let mut broker = fixture.app.broker.lock().await;
            broker.connected(tx);
            broker.on_message(ready(), &[]).unwrap();
        }
        let request = tokio::time::timeout(Duration::from_secs(2), new_output.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request["action"], "verify");
        assert!(request["remaining_ms"]
            .as_u64()
            .is_some_and(|ms| (1..=3000).contains(&ms)));
        fixture
            .app
            .broker
            .lock()
            .await
            .on_message(window_reply(&request), &[])
            .unwrap();
        assert_eq!(worker.await.unwrap().unwrap().fingerprint, fingerprint());
        assert!(remaining(Instant::now(), 25_000).is_err());
    }
    #[tokio::test]
    async fn sequence_schema_is_exact_and_failed_admission_does_not_consume_next() {
        let fixture = Fixture::new(vec![]).await;
        let valid = json!({"action":"ensure", "request_id":Uuid::new_v4().to_string(),
            "operation_scope":fixture.app.window_control.operation_scope,"operation_sequence":"1"});
        for invalid in [
            json!(1),
            json!("0"),
            json!("01"),
            json!("-1"),
            json!("1.0"),
            json!("1e0"),
            json!("18446744073709551616"),
        ] {
            let mut value = valid.clone();
            value["operation_sequence"] = invalid;
            let response = test_support::call(
                &fixture.app,
                "POST",
                "/api/browser/reconnect",
                value,
                &format!("ab_csrf={CSRF}"),
                CSRF,
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        let mut malformed = valid.clone();
        malformed["operation_scope"] = json!("not-a-scope");
        assert_eq!(
            test_support::call(
                &fixture.app,
                "POST",
                "/api/browser/reconnect",
                malformed,
                &format!("ab_csrf={CSRF}"),
                CSRF,
                None
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let slot = fixture.app.recovery_slots.acquire().await.unwrap();
        assert_transient(
            handle(
                fixture.app.clone(),
                fixture.headers.clone(),
                fixture.input(Action::Ensure).await,
            )
            .await,
            "browser_operation_busy",
        )
        .await;
        drop(slot);
        assert_eq!(
            fixture
                .app
                .window_control
                .entries
                .lock()
                .await
                .next_sequence,
            Some(1)
        );
        assert!(fixture.fake.calls.lock().await.is_empty());
        let response = test_support::call(
            &fixture.app,
            "GET",
            "/api/browser/reconnect",
            Value::Null,
            &format!("ab_csrf={CSRF}"),
            CSRF,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["operation_sequence"], "1");
    }

    #[tokio::test]
    async fn pending_supervisor_exchange_is_cancelable_without_resending_the_command() {
        let request = SupervisorRequest {
            command: Command::Inspect,
            request_id: Uuid::new_v4().to_string(),
            expected_epoch: None,
            remaining_ms: 5000,
        };
        let (mut client, mut server) = tokio::io::duplex(1024);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), exchange(&mut client, &request))
                .await
                .is_err()
        );
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0];
            server.read_exact(&mut byte).await.unwrap();
            if byte[0] == b'\n' {
                break;
            }
            bytes.push(byte[0]);
        }
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            serde_json::to_value(request).unwrap()
        );
        let mut extra = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), server.read(&mut extra))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn concurrent_ensure_intents_get_typed_stale_and_busy_without_consuming_new_sequence() {
        let gate = Arc::new(Notify::new());
        let mut inspect = Step::supervisor(Command::Inspect, OLD, 1);
        inspect.block = Some(gate.clone());
        let mut steps = vec![inspect];
        steps.extend(finish_steps(OLD));
        steps.push(Step::supervisor(Command::Inspect, OLD, 1));
        steps.extend(finish_steps(OLD));
        let fixture = Fixture::new(steps).await;
        let first = fixture.input(Action::Ensure).await;
        let simultaneous = fixture.input(Action::Ensure).await;
        let app = fixture.app.clone();
        let headers = fixture.headers.clone();
        let task = tokio::spawn(async move { handle(app, headers, first).await });
        fixture.fake.entered.notified().await;
        assert_transient(
            handle(fixture.app.clone(), fixture.headers.clone(), simultaneous).await,
            "stale_browser_intent",
        )
        .await;
        let fresh = fixture.input(Action::Ensure).await;
        assert_eq!(fresh.operation_sequence, "2");
        assert_transient(
            handle(fixture.app.clone(), fixture.headers.clone(), fresh.clone()).await,
            "browser_operation_busy",
        )
        .await;
        assert_eq!(
            fixture
                .app
                .window_control
                .entries
                .lock()
                .await
                .next_sequence,
            Some(2)
        );
        gate.notify_one();
        assert_eq!(task.await.unwrap().unwrap().status(), StatusCode::OK);
        assert_eq!(
            handle(fixture.app.clone(), fixture.headers.clone(), fresh)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        fixture.fake.done().await;
        assert_eq!(
            fixture
                .app
                .window_control
                .entries
                .lock()
                .await
                .next_sequence,
            Some(3)
        );
    }
}
