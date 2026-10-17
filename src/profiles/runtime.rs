//! Private manager IPC. Runtime responses never imply native engine readiness.
use crate::relay::fido_launcher::Launcher;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Endpoints {
    pub runtime_dir: PathBuf,
    pub control_path: PathBuf,
    pub proxy_path: PathBuf,
    pub clipboard_path: PathBuf,
    pub ble_path: PathBuf,
    pub status_path: PathBuf,
    pub vnc_port: u16,
    pub runtime_epoch: Option<String>,
}
impl Endpoints {
    pub(crate) fn for_profile(id: &str) -> Self {
        let root = PathBuf::from("/data/run/profiles").join(id);
        Self {
            control_path: root.join("reconnect.sock"),
            proxy_path: root.join("webauthn.sock"),
            clipboard_path: root.join("clipboard.sock"),
            ble_path: root.join("ble.sock"),
            status_path: root.join("runtime.json"),
            runtime_dir: root,
            vnc_port: 5900,
            runtime_epoch: None,
        }
    }
    pub(crate) fn legacy() -> Self {
        let root = PathBuf::from("/data/run");
        Self {
            control_path: root.join("reconnect.sock"),
            proxy_path: std::env::var("AUTH_BROWSER_PROXY_SOCKET")
                .map(PathBuf::from)
                .unwrap_or(root.join("webauthn.sock")),
            clipboard_path: std::env::var("AUTH_BROWSER_CLIPBOARD_SOCKET")
                .map(PathBuf::from)
                .unwrap_or(root.join("clipboard.sock")),
            ble_path: std::env::var("AUTH_BROWSER_BLE_SOCKET")
                .map(PathBuf::from)
                .unwrap_or(root.join("ble.sock")),
            status_path: root.join("runtime.json"),
            runtime_dir: root,
            vnc_port: 5900,
            runtime_epoch: None,
        }
    }
}
/// A private manager receipt proves only the listed resource generations stopped.
/// Counts are informational; they never substitute for a matching receipt.
#[derive(Debug, Deserialize)]
pub(crate) struct CleanupReport {
    pub cleaned: usize,
    pub pending: usize,
    pub skipped: usize,
    pub results: Vec<CleanupReceipt>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CleanupReceipt {
    pub profile_id: String,
    pub runtime_epoch: Option<String>,
    pub stopped: bool,
    #[serde(default)]
    pub error: Option<String>,
}
impl CleanupReport {
    fn parse(reply: serde_json::Value) -> Result<Self, ()> {
        if reply["results"].as_array().is_none_or(|results| {
            results
                .iter()
                .any(|receipt| receipt.get("runtime_epoch").is_none())
        }) {
            return Err(());
        }
        let report: Self = serde_json::from_value(reply).map_err(|_| ())?;
        if report.results.len() > 32
            || report.skipped > 16
            || report.cleaned != report.results.iter().filter(|r| r.stopped).count()
            || report.pending != report.results.iter().filter(|r| !r.stopped).count()
        {
            return Err(());
        }
        let mut profiles = std::collections::HashSet::new();
        for receipt in &report.results {
            if receipt.error.as_ref().is_some_and(|code| {
                code.is_empty()
                    || code.len() > 96
                    || !code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            }) || !crate::storage::profiles::valid_id(&receipt.profile_id)
                || !profiles.insert(&receipt.profile_id)
                || receipt
                    .runtime_epoch
                    .as_deref()
                    .is_some_and(|e| parse_epoch(e).is_none())
            {
                return Err(());
            }
        }
        Ok(report)
    }
}
#[derive(Serialize)]
pub(crate) struct CleanupIntent {
    pub profile_id: String,
    pub runtime_epoch: Option<String>,
}
pub(crate) struct CachedFailure {
    pub cleanup_confirmed: bool,
}
pub(crate) struct Manager {
    pub(crate) token: Option<String>,
    path: PathBuf,
}
impl Manager {
    #[cfg(test)]
    pub(super) fn unavailable(path: PathBuf) -> Self {
        Self {
            token: Some("a".repeat(64)),
            path,
        }
    }
    pub(crate) fn from_environment() -> Self {
        Self {
            token: std::env::var("AUTH_BROWSER_PROFILE_CONTROL_TOKEN").ok(),
            path: std::env::var("AUTH_BROWSER_PROFILE_CONTROL_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/data/run/profiles-control.sock")),
        }
    }
    pub(crate) async fn health(&self) -> bool {
        if self.token.is_none() {
            return true;
        }
        matches!(self.request("health","default",1,None).await,Ok((value,None)) if value["manager_ready"]==true && value["profiles_alive"]==true)
    }
    pub(crate) async fn cached(
        &self,
        id: &str,
        revision: u64,
        expected: &Endpoints,
    ) -> Result<(), CachedFailure> {
        let unconfirmed = || CachedFailure {
            cleanup_confirmed: false,
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        let request = request_value(
            self.checked_token().map_err(|_| unconfirmed())?,
            &request_id,
            "ensure",
            id,
            revision,
            None,
        );
        let (reply, fd) = self
            .exchange_request(request)
            .await
            .map_err(|_| unconfirmed())?;
        if validate_reply(&reply, &request_id, id, revision).is_err() {
            return Err(CachedFailure {
                cleanup_confirmed: fd.is_none()
                    && confirmed_failure(
                        &reply,
                        &request_id,
                        id,
                        revision,
                        expected.runtime_epoch.as_deref(),
                    ),
            });
        }
        if fd.is_some()
            || reply.get("fido_gateway_epoch").is_some()
            || &parse_endpoints(id, &reply).map_err(|_| unconfirmed())? != expected
        {
            return Err(unconfirmed());
        }
        Ok(())
    }
    pub(crate) async fn ensure(
        &self,
        id: &str,
        revision: u64,
    ) -> Result<(Endpoints, Arc<Launcher>), ()> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut request = request_value(
            self.checked_token()?,
            &request_id,
            "ensure",
            id,
            revision,
            None,
        );
        // A fresh gateway context must obtain its own control offer even when
        // an earlier caller abandoned the initial offer for this same worker.
        request["attach_gateway"] = serde_json::json!(true);
        let (reply, fd) = self.send_request(request).await?;
        let expected = parse_endpoints(id, &reply)?;
        let launcher = match (reply.get("fido_gateway_epoch"), fd) {
            (None, None) => Launcher::disabled(),
            (Some(epoch), Some(fd)) => Launcher::from_control(
                fido_report_relay::control::ControlSocket::from_owned(fd).map_err(|_| ())?,
                parse_epoch(epoch.as_str().ok_or(())?).ok_or(())?,
            )
            .map_err(|_| ())?,
            _ => return Err(()),
        };
        Ok((expected, launcher))
    }
    pub(crate) async fn stop(
        &self,
        id: &str,
        revision: u64,
        epoch: Option<&str>,
    ) -> Result<(), ()> {
        let (reply, fd) = self.request("stop", id, revision, epoch).await?;
        if fd.is_some() || reply["stopped"] != true {
            return Err(());
        }
        Ok(())
    }
    pub(crate) async fn forget_deleted(&self, id: &str, revision: u64) -> Result<(), ()> {
        if id == "default" || !crate::storage::profiles::valid_id(id) {
            return Err(());
        }
        let (reply, fd) = self.request("forget_deleted", id, revision, None).await?;
        if fd.is_some() || reply["forgotten"] != true {
            return Err(());
        }
        Ok(())
    }
    pub(crate) async fn delete_data(&self, id: &str, revision: u64) -> Result<(), String> {
        if id == "default" || !crate::storage::profiles::valid_id(id) || revision == 0 {
            return Err("invalid_request".into());
        }
        let request_id = uuid::Uuid::new_v4().to_string();
        let request = request_value(
            self.checked_token().map_err(|_| "runtime_unavailable")?,
            &request_id,
            "delete_data",
            id,
            revision,
            None,
        );
        let (reply, fd) = self
            .exchange_request(request)
            .await
            .map_err(|_| "runtime_unavailable")?;
        if reply["version"] == 1
            && reply["request_id"] == request_id
            && reply["profile_id"] == id
            && reply["ok"] == false
        {
            return Err(reply["error"]
                .as_str()
                .filter(|code| {
                    code.len() <= 96 && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                })
                .unwrap_or("runtime_unavailable")
                .to_owned());
        }
        validate_reply(&reply, &request_id, id, revision).map_err(|_| "invalid_reply")?;
        validate_delete_receipt(&reply, fd).map_err(|_| "invalid_reply".to_owned())
    }
    pub(crate) async fn cleanup(
        &self,
        revision: u64,
        profiles: &[String],
        intents: &[CleanupIntent],
    ) -> Result<CleanupReport, ()> {
        self.cleanup_request("cleanup", revision, profiles, intents)
            .await
    }
    pub(crate) async fn cleanup_startup(
        &self,
        revision: u64,
        profiles: &[String],
        intents: &[CleanupIntent],
    ) -> Result<CleanupReport, ()> {
        self.cleanup_request("cleanup_startup", revision, profiles, intents)
            .await
    }
    pub(crate) async fn cleanup_status(
        &self,
        revision: u64,
        profiles: &[String],
    ) -> Result<CleanupReport, ()> {
        self.cleanup_request("cleanup_status", revision, profiles, &[])
            .await
    }
    async fn cleanup_request(
        &self,
        action: &str,
        revision: u64,
        profiles: &[String],
        intents: &[CleanupIntent],
    ) -> Result<CleanupReport, ()> {
        if profiles.len() > 16
            || intents.len() > 16
            || intents.iter().any(|intent| {
                !profiles.contains(&intent.profile_id)
                    || intent
                        .runtime_epoch
                        .as_deref()
                        .is_some_and(|epoch| parse_epoch(epoch).is_none())
            })
            || profiles
                .iter()
                .any(|id| !crate::storage::profiles::valid_id(id))
        {
            return Err(());
        }
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut request = request_value(
            self.checked_token()?,
            &request_id,
            action,
            "default",
            revision,
            None,
        );
        request["cleanup_profiles"] = serde_json::json!(profiles);
        if !intents.is_empty() {
            request["cleanup_stop_profiles"] = serde_json::json!(intents);
        }
        let (reply, fd) = self.send_request(request).await?;
        if fd.is_some() {
            return Err(());
        }
        CleanupReport::parse(reply)
    }
    fn checked_token(&self) -> Result<&str, ()> {
        self.token
            .as_deref()
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or(())
    }
    async fn request(
        &self,
        action: &str,
        id: &str,
        revision: u64,
        epoch: Option<&str>,
    ) -> Result<(serde_json::Value, Option<std::os::fd::OwnedFd>), ()> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let request = request_value(
            self.checked_token()?,
            &request_id,
            action,
            id,
            revision,
            epoch,
        );
        self.send_request(request).await
    }
    async fn send_request(
        &self,
        request: serde_json::Value,
    ) -> Result<(serde_json::Value, Option<std::os::fd::OwnedFd>), ()> {
        let request_id = request["request_id"].as_str().ok_or(())?.to_owned();
        let id = request["profile_id"].as_str().ok_or(())?.to_owned();
        let revision = request["revision"].as_u64().ok_or(())?;
        let (reply, fd) = self.exchange_request(request).await?;
        validate_reply(&reply, &request_id, &id, revision)?;
        Ok((reply, fd))
    }
    async fn exchange_request(
        &self,
        request: serde_json::Value,
    ) -> Result<(serde_json::Value, Option<std::os::fd::OwnedFd>), ()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || exchange(&path, &request))
            .await
            .map_err(|_| ())?
    }
}
fn validate_delete_receipt(
    reply: &serde_json::Value,
    fd: Option<std::os::fd::OwnedFd>,
) -> Result<(), ()> {
    if fd.is_some() || reply["browser_data_deleted"] != true {
        return Err(());
    }
    Ok(())
}
fn request_value(
    token: &str,
    request_id: &str,
    action: &str,
    id: &str,
    revision: u64,
    epoch: Option<&str>,
) -> serde_json::Value {
    let mut value = serde_json::json!({"version":1,"token":token,"request_id":request_id,"action":action,"profile_id":id,"revision":revision});
    if let Some(epoch) = epoch {
        value["runtime_epoch"] = epoch.into();
    }
    value
}
fn validate_reply(
    reply: &serde_json::Value,
    request_id: &str,
    id: &str,
    revision: u64,
) -> Result<(), ()> {
    if reply["ok"] != true
        || reply["version"] != 1
        || reply["request_id"] != request_id
        || reply["profile_id"] != id
        || reply["revision"] != revision
    {
        return Err(());
    }
    Ok(())
}
fn confirmed_failure(
    reply: &serde_json::Value,
    request_id: &str,
    id: &str,
    revision: u64,
    epoch: Option<&str>,
) -> bool {
    reply["ok"] == false
        && reply["version"] == 1
        && reply["request_id"] == request_id
        && reply["profile_id"] == id
        && reply["revision"] == revision
        && reply["cleanup_confirmed"] == true
        && epoch.is_some_and(|expected| {
            parse_epoch(expected).is_some() && reply["runtime_epoch"] == expected
        })
}
fn parse_endpoints(id: &str, reply: &serde_json::Value) -> Result<Endpoints, ()> {
    let mut expected = Endpoints::for_profile(id);
    for (field, path) in [
        ("runtime_dir", &expected.runtime_dir),
        ("control_path", &expected.control_path),
        ("proxy_path", &expected.proxy_path),
        ("clipboard_path", &expected.clipboard_path),
        ("ble_path", &expected.ble_path),
        ("status_path", &expected.status_path),
    ] {
        if reply[field].as_str() != path.to_str() {
            return Err(());
        }
    }
    let epoch = reply["runtime_epoch"]
        .as_str()
        .filter(|s| parse_epoch(s).is_some())
        .ok_or(())?;
    let port = reply["vnc_port"]
        .as_u64()
        .filter(|p| (5900..5916).contains(p))
        .ok_or(())? as u16;
    if reply["display"].as_str() != Some(format!(":{}", 99 + port - 5900).as_str()) {
        return Err(());
    }
    if reply["engine_ready"] != false {
        return Err(());
    }
    expected.vnc_port = port;
    expected.runtime_epoch = Some(epoch.into());
    Ok(expected)
}
fn parse_epoch(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut bytes = [0; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}
fn exchange(
    path: &std::path::Path,
    request: &serde_json::Value,
) -> Result<(serde_json::Value, Option<std::os::fd::OwnedFd>), ()> {
    use std::os::unix::net::UnixStream;
    let stream = UnixStream::connect(path).map_err(|_| ())?;
    exchange_connected(stream, request)
}
fn response_timeout(action: &str) -> std::time::Duration {
    // Stop may consume a 45s worker response wait plus a 12s confirmed reap.
    // Leave room for the manager's bounded final write; startup/health retain
    // their existing budgets. Failed ensure may need one 20s cleanup pass
    // after a 45s worker response. A timeout never substitutes for a stop ACK.
    std::time::Duration::from_secs(match action {
        "health" | "cleanup_status" | "forget_deleted" => 1,
        "stop" | "cleanup" | "cleanup_startup" => 60,
        "ensure" => 70,
        _ => 55,
    })
}
fn exchange_connected(
    mut stream: std::os::unix::net::UnixStream,
    request: &serde_json::Value,
) -> Result<(serde_json::Value, Option<std::os::fd::OwnedFd>), ()> {
    use std::{
        io::Write,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        time::Duration,
    };
    let timeout = response_timeout(request["action"].as_str().ok_or(())?);
    stream.set_read_timeout(Some(timeout)).map_err(|_| ())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ())?;
    let mut bytes = serde_json::to_vec(request).map_err(|_| ())?;
    bytes.push(b'\n');
    if bytes.len() > 8192 {
        return Err(());
    }
    stream.write_all(&bytes).map_err(|_| ())?;
    let deadline = std::time::Instant::now() + timeout;
    let mut response = Vec::new();
    let mut rights = Vec::<OwnedFd>::new();
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or(())?;
        stream.set_read_timeout(Some(remaining)).map_err(|_| ())?;
        let mut data = [0u8; 4096];
        let mut ancillary = [0usize; 32];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&ancillary);
        let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(());
        }
        let mut invalid = false;
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&message);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let length = (*c).cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize);
                    if !length.is_multiple_of(std::mem::size_of::<i32>()) {
                        invalid = true;
                    }
                    for i in 0..length / std::mem::size_of::<i32>() {
                        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<i32>().add(i));
                        if fd >= 0 {
                            rights.push(OwnedFd::from_raw_fd(fd));
                        } else {
                            invalid = true;
                        }
                    }
                } else {
                    invalid = true;
                }
                c = libc::CMSG_NXTHDR(&message, c);
            }
        }
        if invalid
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || rights.len() > 1
            || n == 0
        {
            return Err(());
        }
        response.extend_from_slice(&data[..n as usize]);
        if response.len() > 8192 {
            return Err(());
        }
        if let Some(end) = response.iter().position(|b| *b == b'\n') {
            if end + 1 != response.len() {
                return Err(());
            }
            let value = serde_json::from_slice(&response[..end]).map_err(|_| ())?;
            return Ok((value, rights.pop()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read},
        os::fd::{AsRawFd, OwnedFd},
        os::unix::net::{UnixListener, UnixStream},
        time::Duration,
    };
    #[test]
    fn cleanup_receipts_are_bounded_and_require_exact_counts_and_valid_ownership() {
        let valid = serde_json::json!({"cleaned":1,"pending":0,"skipped":1,"results":[{
            "profile_id":"default","runtime_epoch":"ab".repeat(16),"stopped":true}]});
        assert!(CleanupReport::parse(valid.clone()).is_ok());
        for (field, value) in [
            ("cleaned", serde_json::json!(0)),
            ("pending", serde_json::json!(1)),
            ("skipped", serde_json::json!(17)),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert!(CleanupReport::parse(changed).is_err());
        }
        for (field, value) in [
            ("profile_id", serde_json::json!("../unsafe")),
            ("runtime_epoch", serde_json::json!("invalid")),
            ("stopped", serde_json::json!(1)),
            ("error", serde_json::json!("")),
            ("error", serde_json::json!("untrusted/path")),
            ("error", serde_json::json!("x".repeat(97))),
        ] {
            let mut changed = valid.clone();
            changed["results"][0][field] = value;
            assert!(CleanupReport::parse(changed).is_err());
        }
        let mut duplicate = valid.clone();
        duplicate["cleaned"] = serde_json::json!(2);
        duplicate["results"] = serde_json::json!([valid["results"][0], valid["results"][0]]);
        assert!(CleanupReport::parse(duplicate).is_err());
        assert_eq!(response_timeout("cleanup").as_secs(), 60);
    }

    #[test]
    fn cached_failure_cleanup_proof_requires_correlation_and_current_epoch() {
        let epoch = "ab".repeat(16);
        let valid = serde_json::json!({"ok":false,"version":1,"request_id":"request",
            "profile_id":"default","revision":7,"cleanup_confirmed":true,"runtime_epoch":epoch});
        assert!(confirmed_failure(
            &valid,
            "request",
            "default",
            7,
            Some(&epoch)
        ));
        for (field, value) in [
            ("request_id", serde_json::json!("foreign")),
            ("profile_id", serde_json::json!("foreign")),
            ("revision", serde_json::json!(8)),
            ("runtime_epoch", serde_json::json!("cd".repeat(16))),
            ("cleanup_confirmed", serde_json::json!(false)),
            ("ok", serde_json::json!(true)),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert!(!confirmed_failure(
                &changed,
                "request",
                "default",
                7,
                Some(&epoch)
            ));
        }
        assert!(!confirmed_failure(&valid, "request", "default", 7, None));
    }
    #[test]
    fn shared_python_manager_contract_matches_production_requests_and_replies() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/profile_manager_protocol.json"
        ))
        .unwrap();
        let timing = &fixture["timing_seconds"];
        for action in ["stop", "ensure", "health"] {
            assert_eq!(
                response_timeout(action).as_secs(),
                timing[action].as_u64().unwrap()
            );
        }
        assert!(
            response_timeout("stop").as_secs()
                > timing["worker_reply"].as_u64().unwrap()
                    + timing["worker_exit"].as_u64().unwrap()
                    + timing["manager_send"].as_u64().unwrap()
        );
        for case in fixture["cleanup_cases"].as_array().unwrap() {
            let request = &case["request"];
            let action = request["action"].as_str().unwrap();
            let request_id = request["request_id"].as_str().unwrap();
            let revision = request["revision"].as_u64().unwrap();
            let mut encoded = request_value(
                fixture["token"].as_str().unwrap(),
                request_id,
                action,
                "default",
                revision,
                None,
            );
            encoded["cleanup_profiles"] = request["cleanup_profiles"].clone();
            if let Some(intents) = request.get("cleanup_stop_profiles") {
                encoded["cleanup_stop_profiles"] = intents.clone();
            }
            assert_eq!(encoded, *request);
            assert_eq!(
                response_timeout(action).as_secs(),
                timing[action].as_u64().unwrap()
            );
            validate_reply(&case["reply"], request_id, "default", revision).unwrap();
            CleanupReport::parse(case["reply"].clone()).unwrap();
            assert_eq!(case["fd_count"], 0);
        }
        let mut cached = None;
        for case in fixture["cases"].as_array().unwrap() {
            let r = &case["request"];
            let action = r["action"].as_str().unwrap();
            let id = r["profile_id"].as_str().unwrap();
            let request_id = r["request_id"].as_str().unwrap();
            let revision = r["revision"].as_u64().unwrap();
            assert_eq!(
                request_value(
                    fixture["token"].as_str().unwrap(),
                    request_id,
                    action,
                    id,
                    revision,
                    r["runtime_epoch"].as_str()
                ),
                *r
            );
            if let Some(reply) = case.get("reply") {
                validate_reply(reply, request_id, id, revision).unwrap();
                match action {
                    "ensure" => {
                        assert!(r.get("runtime_epoch").is_none());
                        assert_eq!(case["fd_count"], 0);
                        assert!(reply.get("fido_gateway_epoch").is_none());
                        let parsed = parse_endpoints(id, reply).unwrap();
                        if let Some(expected) = &cached {
                            assert!(&parsed == expected);
                        }
                        cached = Some(parsed);
                    }
                    "health" => assert_eq!(reply["profiles_alive"], case["setup"] != "dead"),
                    "stop" => assert_eq!(reply["stopped"], true),
                    _ => panic!("unexpected fixture action"),
                }
            } else {
                let reply = serde_json::json!({"ok":false,"error":case["error"]});
                assert!(validate_reply(&reply, request_id, id, revision).is_err());
            }
        }
        let stale = parse_endpoints("default", &fixture["stale_cached_reply"]).unwrap();
        assert!(Some(stale) != cached);
    }
    fn send(stream: &UnixStream, body: &[u8], rights: &[OwnedFd]) {
        let mut iov = libc::iovec {
            iov_base: body.as_ptr().cast_mut().cast(),
            iov_len: body.len(),
        };
        let mut ancillary = vec![0usize; 64];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        if !rights.is_empty() {
            message.msg_control = ancillary.as_mut_ptr().cast();
            message.msg_controllen = unsafe {
                libc::CMSG_SPACE(std::mem::size_of_val(
                    rights
                        .iter()
                        .map(|r| r.as_raw_fd())
                        .collect::<Vec<_>>()
                        .as_slice(),
                ) as u32)
            } as usize;
            unsafe {
                let c = libc::CMSG_FIRSTHDR(&message);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len =
                    libc::CMSG_LEN((rights.len() * std::mem::size_of::<i32>()) as u32) as usize;
                for (i, fd) in rights.iter().enumerate() {
                    std::ptr::write_unaligned(
                        libc::CMSG_DATA(c).cast::<i32>().add(i),
                        fd.as_raw_fd(),
                    );
                }
            }
        }
        assert_eq!(
            unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) },
            body.len() as isize
        );
    }
    #[test]
    fn deletion_receipt_requires_explicit_erasure_and_no_descriptor() {
        for value in [
            serde_json::json!({"stopped":true}),
            serde_json::json!({"browser_data_deleted":false}),
        ] {
            assert!(validate_delete_receipt(&value, None).is_err());
        }
        let value = serde_json::json!({"browser_data_deleted":true});
        assert!(validate_delete_receipt(&value, None).is_ok());
        let (fd, mut peer) = UnixStream::pair().unwrap();
        assert!(validate_delete_receipt(&value, Some(OwnedFd::from(fd))).is_err());
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    }
    #[tokio::test]
    async fn deletion_rejects_default_invalid_ids_and_unavailable_manager() {
        let manager = Manager::unavailable(
            std::env::temp_dir().join(format!("absent-{}", uuid::Uuid::new_v4())),
        );
        for id in ["default", "../profile", "invalid"] {
            assert!(manager.delete_data(id, 1).await.is_err());
        }
        assert!(manager
            .delete_data(&uuid::Uuid::new_v4().to_string(), 1)
            .await
            .is_err());
    }
    fn fixture(
        rights: Vec<OwnedFd>,
        reply: impl FnOnce(serde_json::Value) -> serde_json::Value + Send + 'static,
    ) -> (Manager, std::thread::JoinHandle<()>, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("profile-manager-fixture-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("manager.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let task = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            let request = serde_json::from_str(&line).unwrap();
            let mut bytes = serde_json::to_vec(&reply(request)).unwrap();
            bytes.push(b'\n');
            send(&stream, &bytes, &rights);
        });
        (
            Manager {
                token: Some("a".repeat(64)),
                path,
            },
            task,
            dir,
        )
    }
    fn reply(request: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"ok":true,"version":1,"request_id":request["request_id"],"profile_id":request["profile_id"],"revision":request["revision"],"stopped":true,"manager_ready":true,"profiles_alive":true})
    }
    #[tokio::test]
    #[ignore = "requires named AF_UNIX listener binding; current environment returns EPERM; run only in a permitted environment"]
    async fn health_and_stop_require_exact_correlation_without_descriptors() {
        let (m, t, d) = fixture(vec![], reply);
        assert!(m.health().await);
        t.join().unwrap();
        std::fs::remove_dir_all(d).unwrap();
        let (m, t, d) = fixture(vec![], |r| {
            let mut v = reply(r);
            v["profile_id"] = "foreign".into();
            v
        });
        assert!(m.stop("default", 1, None).await.is_err());
        t.join().unwrap();
        std::fs::remove_dir_all(d).unwrap();
    }
    #[tokio::test]
    #[ignore = "requires named AF_UNIX listener binding; current environment returns EPERM; run only in a permitted environment"]
    async fn rejected_single_and_multiple_rights_are_closed() {
        for count in [1, 2, 70] {
            let mut rights = Vec::new();
            let mut peers = Vec::new();
            for _ in 0..count {
                let (a, b) = UnixStream::pair().unwrap();
                rights.push(OwnedFd::from(a));
                peers.push(b);
            }
            let (m, t, d) = fixture(rights, reply);
            assert!(m.stop("default", 1, None).await.is_err());
            t.join().unwrap();
            for mut peer in peers {
                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0);
            }
            std::fs::remove_dir_all(d).unwrap();
        }
    }
    #[tokio::test]
    #[ignore = "requires named AF_UNIX listener binding; current environment returns EPERM; run only in a permitted environment"]
    async fn ensure_rejects_foreign_runtime_paths_and_missing_fido_right() {
        let (m, t, d) = fixture(vec![], |r| {
            let mut v = reply(r);
            v["runtime_dir"] = "/data/run/profiles/foreign".into();
            v
        });
        assert!(m.ensure("default", 1).await.is_err());
        t.join().unwrap();
        std::fs::remove_dir_all(d).unwrap();
        let (m, t, d) = fixture(vec![], |r| {
            let mut v = reply(r);
            let ep = Endpoints::for_profile("default");
            for (n, p) in [
                ("runtime_dir", ep.runtime_dir),
                ("control_path", ep.control_path),
                ("proxy_path", ep.proxy_path),
                ("clipboard_path", ep.clipboard_path),
                ("ble_path", ep.ble_path),
                ("status_path", ep.status_path),
            ] {
                v[n] = p.to_str().unwrap().into();
            }
            v["runtime_epoch"] = "ab".repeat(16).into();
            v["fido_gateway_epoch"] = "cd".repeat(16).into();
            v["vnc_port"] = 5900.into();
            v["display"] = ":99".into();
            v["engine_ready"] = false.into();
            v
        });
        assert!(m.ensure("default", 1).await.is_err());
        t.join().unwrap();
        std::fs::remove_dir_all(d).unwrap();
    }
    #[tokio::test]
    #[ignore = "requires named AF_UNIX listener binding; current environment returns EPERM; run only in a permitted environment"]
    async fn canceled_manager_wait_drops_a_late_received_descriptor() {
        let (a, mut peer) = UnixStream::pair().unwrap();
        let (ready, received) = std::sync::mpsc::channel();
        let (proceed, go) = std::sync::mpsc::channel();
        let (m, t, d) = fixture(vec![OwnedFd::from(a)], move |r| {
            ready.send(()).unwrap();
            go.recv().unwrap();
            reply(r)
        });
        let task = tokio::spawn(async move { m.request("ensure", "default", 1, None).await });
        tokio::task::spawn_blocking(move || received.recv().unwrap())
            .await
            .unwrap();
        task.abort();
        let _ = task.await;
        proceed.send(()).unwrap();
        t.join().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(
            tokio::task::spawn_blocking(move || peer.read(&mut [0u8; 1]).unwrap())
                .await
                .unwrap(),
            0
        );
        std::fs::remove_dir_all(d).unwrap();
    }
    #[tokio::test]
    async fn anonymous_codec_closes_multiple_and_truncated_rights() {
        for count in [2, 70] {
            let (client, server) = UnixStream::pair().unwrap();
            let mut rights = Vec::new();
            let mut peers = Vec::new();
            for _ in 0..count {
                let (a, b) = UnixStream::pair().unwrap();
                rights.push(OwnedFd::from(a));
                peers.push(b);
            }
            let task = std::thread::spawn(move || {
                let mut line = String::new();
                BufReader::new(&server).read_line(&mut line).unwrap();
                send(&server, b"{\"ok\":true}\n", &rights);
            });
            assert!(tokio::task::spawn_blocking(move || exchange_connected(
                client,
                &serde_json::json!({"action":"health"})
            ))
            .await
            .unwrap()
            .is_err());
            task.join().unwrap();
            for mut peer in peers {
                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
            }
        }
    }
    #[tokio::test]
    async fn anonymous_codec_rejects_trailing_records_and_releases_received_right() {
        let (client, server) = UnixStream::pair().unwrap();
        let (a, mut peer) = UnixStream::pair().unwrap();
        let task = std::thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(&server).read_line(&mut line).unwrap();
            send(&server, b"{}\n{}\n", &[OwnedFd::from(a)]);
        });
        assert!(tokio::task::spawn_blocking(move || exchange_connected(
            client,
            &serde_json::json!({"action":"health"})
        ))
        .await
        .unwrap()
        .is_err());
        task.join().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    }
    #[tokio::test]
    async fn abandoned_anonymous_codec_result_closes_late_right() {
        let (client, server) = UnixStream::pair().unwrap();
        let (a, mut peer) = UnixStream::pair().unwrap();
        let (ready, received) = std::sync::mpsc::channel();
        let (proceed, go) = std::sync::mpsc::channel();
        let sender = std::thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(&server).read_line(&mut line).unwrap();
            ready.send(()).unwrap();
            go.recv().unwrap();
            send(&server, b"{}\n", &[OwnedFd::from(a)]);
        });
        let task = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                exchange_connected(client, &serde_json::json!({"action":"health"}))
            })
            .await
        });
        tokio::task::spawn_blocking(move || received.recv().unwrap())
            .await
            .unwrap();
        task.abort();
        let _ = task.await;
        proceed.send(()).unwrap();
        sender.join().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(
            tokio::task::spawn_blocking(move || peer.read(&mut [0; 1]).unwrap())
                .await
                .unwrap(),
            0
        );
    }
}
