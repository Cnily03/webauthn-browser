//! Experimental report plumbing. Authorization belongs to the existing native
//! helper session; this module does not create an alternative login or signer.
use crate::{
    app::App,
    auth::{authorize, csrf},
    http::error::{fail, ApiResult},
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use fido_report_relay::{Endpoint, Frame, Sequence, MAX_BATCH, MAX_LEASE_MS, VERSION};
use serde::Deserialize;
use serde_json::json;
use std::time::{Duration, Instant};

pub(crate) struct Relay {
    attachment_id: String,
    endpoint: Endpoint,
    generation: u64,
    deadline: Instant,
    id: Option<String>,
    helper_connection: Option<String>,
    incoming: Sequence,
    outgoing: Sequence,
    exchange_sequence: u64,
    window: Instant,
    calls: u32,
    native: Option<crate::relay::fido_launcher::Lease>,
    lease_sequence: u64,
    renewing: bool,
}
impl Relay {
    pub(crate) fn available(&self) -> bool {
        self.deadline > Instant::now()
            && !self.endpoint.is_closed()
            && self.native.as_ref().is_none_or(|lease| lease.live())
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        if let Some(lease) = &self.native {
            lease.cancel();
        }
    }
}
pub(crate) struct Pending {
    nonce: String,
    relay_id: String,
    helper_connection: String,
    cancel: tokio::sync::watch::Sender<bool>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
    }
}
fn conflict() -> (StatusCode, String) {
    fail(
        StatusCode::CONFLICT,
        "Experimental FIDO relay unavailable, changed, or expired",
    )
}

/// Internal supplied-endpoint adapter for an explicitly enabled launcher. No
/// production startup calls this yet: do not advertise attachment on env alone.
#[allow(dead_code)]
pub(crate) async fn attach_native(
    app: &App,
    session_id: &str,
    generation: u64,
    endpoint: Endpoint,
) -> Result<(), (StatusCode, String)> {
    attach(
        app,
        session_id,
        generation,
        endpoint,
        std::env::var("AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY").as_deref() == Ok("1"),
    )
    .await
}
pub(crate) async fn attach(
    app: &App,
    session_id: &str,
    generation: u64,
    endpoint: Endpoint,
    enabled: bool,
) -> Result<(), (StatusCode, String)> {
    if !enabled {
        return Err(fail(
            StatusCode::FORBIDDEN,
            "Experimental FIDO relay is disabled",
        ));
    }
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    broker.validate_helper_owner(&inner);
    broker.expire();
    if !broker.native_qr_mode || broker.mode_generation != generation {
        return Err(conflict());
    }
    let session = broker
        .helper
        .as_mut()
        .filter(|session| session.id == session_id && session.valid_owner(&inner))
        .ok_or_else(conflict)?;
    if session.fido.is_some() || session.fido_pending.is_some() || endpoint.is_closed() {
        return Err(conflict());
    }
    let now = Instant::now();
    let deadline = session
        .deadline
        .min(now + Duration::from_millis(MAX_LEASE_MS));
    let attachment_id = crate::auth::token();
    session.fido = Some(Relay {
        attachment_id: attachment_id.clone(),
        endpoint,
        generation,
        deadline,
        id: None,
        helper_connection: None,
        incoming: Sequence::default(),
        outgoing: Sequence::default(),
        exchange_sequence: 0,
        window: now,
        calls: 0,
        native: None,
        lease_sequence: 0,
        renewing: false,
    });
    drop(inner);
    drop(broker);
    expire_attachment(app, session_id, generation, attachment_id);
    Ok(())
}
fn expire_attachment(app: &App, session_id: &str, generation: u64, attachment_id: String) {
    // Independently expire the supplied endpoint even if its webpage stops
    // polling, stalls a response, or never opens the relay.
    let app = app.clone();
    let session_id = session_id.to_owned();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut broker = app.broker.lock().await;
            let inner = app.inner.lock().await;
            broker.validate_helper_owner(&inner);
            broker.expire();
            if broker.mode_generation != generation || !broker.native_qr_mode {
                return;
            }
            let Some(session) = broker.helper.as_mut().filter(|s| s.id == session_id) else {
                return;
            };
            let Some(relay) = session.fido.as_ref() else {
                return;
            };
            // An old expiry task cannot affect a replacement attachment.
            if relay.generation != generation || relay.attachment_id != attachment_id {
                return;
            }
            if !relay.available() {
                session.fido = None;
                return;
            }
        }
    });
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Open {
    session_id: String,
    generation: u64,
    helper_connection_id: String,
    relay_id: String,
}
pub async fn open(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Open>,
) -> ApiResult {
    let provisioned = provision(&app, &headers, &input).await?;
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    broker.validate_helper_owner(&inner);
    authorize(&inner, &headers, "vnc")?;
    csrf(&inner, &headers)?;
    broker.expire();
    if !broker.native_qr_mode
        || broker.mode_generation != input.generation
        || !fido_report_relay::valid_id(&input.helper_connection_id)
        || !fido_report_relay::valid_id(&input.relay_id)
    {
        return Err(conflict());
    }
    let session = broker
        .helper
        .as_mut()
        .filter(|s| s.id == input.session_id && s.owned(&inner, &headers))
        .ok_or_else(conflict)?;
    let relay = session
        .fido
        .as_mut()
        .filter(|relay| relay.available() && relay.generation == input.generation)
        .ok_or_else(conflict)?;
    if relay.id.is_some()
        && (!provisioned
            || relay.id.as_deref() != Some(&input.relay_id)
            || relay.helper_connection.as_deref() != Some(&input.helper_connection_id))
    {
        return Err(conflict());
    }
    let id = input.relay_id;
    relay.id = Some(id.clone());
    relay.helper_connection = Some(input.helper_connection_id);
    Ok(Json(
        json!({"version":VERSION,"relay_id":id,"remaining_ms":relay.deadline.saturating_duration_since(Instant::now()).as_millis() as u64}),
    ))
}
// Preparation never grants authorization: recheck the existing owner and
// pairing token before activation and again before publishing the endpoint.
async fn provision(
    app: &App,
    headers: &HeaderMap,
    input: &Open,
) -> Result<bool, (StatusCode, String)> {
    let (nonce, token, deadline, mut canceled) = {
        let mut broker = app.broker.lock().await;
        let inner = app.inner.lock().await;
        broker.validate_helper_owner(&inner);
        authorize(&inner, headers, "vnc")?;
        csrf(&inner, headers)?;
        broker.expire();
        if !broker.native_qr_mode
            || broker.mode_generation != input.generation
            || !fido_report_relay::valid_id(&input.relay_id)
            || !fido_report_relay::valid_id(&input.helper_connection_id)
        {
            return Err(conflict());
        }
        let session = broker
            .helper
            .as_mut()
            .filter(|s| s.id == input.session_id && s.owned(&inner, headers))
            .ok_or_else(conflict)?;
        if session.fido.is_some() {
            return Ok(false);
        }
        if session.fido_pending.is_some() || !app.fido_launcher.available() {
            return Err(conflict());
        }
        let (cancel, canceled) = tokio::sync::watch::channel(false);
        let nonce = crate::auth::token();
        session.fido_pending = Some(Pending {
            nonce: nonce.clone(),
            relay_id: input.relay_id.clone(),
            helper_connection: input.helper_connection_id.clone(),
            cancel,
        });
        (
            nonce,
            session.token.clone(),
            session
                .deadline
                .min(Instant::now() + Duration::from_millis(MAX_LEASE_MS)),
            canceled,
        )
    };
    // A dropped HTTP future cannot strand a reservation indefinitely.
    let cleanup_app = app.clone();
    let cleanup_session = input.session_id.clone();
    let cleanup_nonce = nonce.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        clear_pending(&cleanup_app, &cleanup_session, &cleanup_nonce).await;
    });
    let result = async {
        let prepared=tokio::select! { biased;
            _=canceled.changed()=>return Err(conflict()),
            result=app.fido_launcher.prepare(input.generation,deadline)=>result.map_err(|_|conflict())?,
        };
        check_pending(app,headers,input,&nonce,&token).await?;
        tokio::select! { biased;
            _=canceled.changed()=>return Err(conflict()),
            result=prepared.lease.activate()=>result.map_err(|_|conflict())?,
        }
        let mut broker=app.broker.lock().await;
        let inner=app.inner.lock().await;
        broker.validate_helper_owner(&inner); broker.expire();
        authorize(&inner,headers,"vnc")?; csrf(&inner,headers)?;
        if !broker.native_qr_mode || broker.mode_generation!=input.generation {return Err(conflict());}
        let session=broker.helper.as_mut().filter(|s|s.id==input.session_id && s.owned(&inner,headers) && s.token==token).ok_or_else(conflict)?;
        if !session.fido_pending.as_ref().is_some_and(|p|p.nonce==nonce) || session.fido.is_some()
            || !prepared.lease.live() || prepared.endpoint.is_closed() || Instant::now()>=prepared.deadline {return Err(conflict());}
        let attachment_id=crate::auth::token();
        session.fido=Some(Relay{attachment_id:attachment_id.clone(),endpoint:prepared.endpoint,generation:input.generation,
            deadline:prepared.deadline.min(session.deadline),id:Some(input.relay_id.clone()),helper_connection:Some(input.helper_connection_id.clone()),incoming:Sequence::default(),outgoing:Sequence::default(),
            exchange_sequence:0,window:Instant::now(),calls:0,native:Some(prepared.lease),lease_sequence:0,renewing:false});
        session.fido_pending=None;
        drop(inner); drop(broker);
        expire_attachment(app,&input.session_id,input.generation,attachment_id);
        Ok(true)
    }.await;
    clear_pending(app, &input.session_id, &nonce).await;
    result
}
async fn clear_pending(app: &App, session_id: &str, nonce: &str) {
    let mut broker = app.broker.lock().await;
    if let Some(session) = broker.helper.as_mut().filter(|s| s.id == session_id) {
        if session
            .fido_pending
            .as_ref()
            .is_some_and(|p| p.nonce == nonce)
        {
            session.fido_pending = None;
        }
    }
}
async fn check_pending(
    app: &App,
    headers: &HeaderMap,
    input: &Open,
    nonce: &str,
    token: &str,
) -> Result<(), (StatusCode, String)> {
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    broker.validate_helper_owner(&inner);
    broker.expire();
    authorize(&inner, headers, "vnc")?;
    csrf(&inner, headers)?;
    if !broker.native_qr_mode || broker.mode_generation != input.generation {
        return Err(conflict());
    }
    let session = broker
        .helper
        .as_ref()
        .filter(|s| s.id == input.session_id && s.owned(&inner, headers) && s.token == token)
        .ok_or_else(conflict)?;
    if !session
        .fido_pending
        .as_ref()
        .is_some_and(|p| p.nonce == nonce)
    {
        return Err(conflict());
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Renew {
    session_id: String,
    generation: u64,
    relay_id: String,
    helper_connection_id: String,
    lease_sequence: u64,
    remaining_ms: u64,
}
pub async fn renew(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Renew>,
) -> ApiResult {
    let (attachment, token, native, deadline, old_deadline) = {
        let mut broker = app.broker.lock().await;
        let inner = app.inner.lock().await;
        broker.validate_helper_owner(&inner);
        authorize(&inner, &headers, "vnc")?;
        csrf(&inner, &headers)?;
        broker.expire();
        if !broker.native_qr_mode || broker.mode_generation != input.generation {
            return Err(conflict());
        }
        let session = broker
            .helper
            .as_mut()
            .filter(|s| s.id == input.session_id && s.owned(&inner, &headers))
            .ok_or_else(conflict)?;
        let relay = session
            .fido
            .as_mut()
            .filter(|r| {
                r.generation == input.generation
                    && r.id.as_deref() == Some(&input.relay_id)
                    && r.helper_connection.as_deref() == Some(&input.helper_connection_id)
            })
            .ok_or_else(conflict)?;
        let deadline = Instant::now() + Duration::from_millis(input.remaining_ms.min(MAX_LEASE_MS));
        let deadline = deadline.min(session.deadline);
        if !relay.available()
            || relay.renewing
            || input.lease_sequence == 0
            || relay.lease_sequence.checked_add(1) != Some(input.lease_sequence)
            || input.remaining_ms == 0
            || input.remaining_ms > MAX_LEASE_MS
            || deadline <= relay.deadline
        {
            session.fido = None;
            return Err(conflict());
        }
        relay.renewing = true;
        (
            relay.attachment_id.clone(),
            session.token.clone(),
            relay.native.clone(),
            deadline,
            relay.deadline,
        )
    };
    let acknowledged = match native.as_ref() {
        Some(lease) => lease.renew(input.lease_sequence, deadline).await.is_ok(),
        None => true,
    };
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    broker.validate_helper_owner(&inner);
    broker.expire();
    let mode_valid = broker.native_qr_mode && broker.mode_generation == input.generation;
    let Some(session) = broker.helper.as_mut().filter(|s| s.id == input.session_id) else {
        if let Some(l) = native {
            l.cancel();
        }
        return Err(conflict());
    };
    let valid_owner = session.owned(&inner, &headers)
        && session.token == token
        && authorize(&inner, &headers, "vnc").is_ok()
        && csrf(&inner, &headers).is_ok();
    let Some(relay) = session
        .fido
        .as_mut()
        .filter(|r| r.attachment_id == attachment)
    else {
        if let Some(l) = native {
            l.cancel();
        }
        return Err(conflict());
    };
    if !acknowledged
        || !mode_valid
        || !valid_owner
        || !relay.available()
        || Instant::now() >= deadline
        || relay.deadline != old_deadline
        || !relay.renewing
        || relay.id.as_deref() != Some(&input.relay_id)
        || relay.helper_connection.as_deref() != Some(&input.helper_connection_id)
    {
        session.fido = None;
        return Err(conflict());
    }
    relay.deadline = deadline;
    relay.lease_sequence = input.lease_sequence;
    relay.renewing = false;
    Ok(Json(
        json!({"version":VERSION,"relay_id":input.relay_id,"lease_sequence":input.lease_sequence,
        "remaining_ms":deadline.saturating_duration_since(Instant::now()).as_millis() as u64}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exchange {
    session_id: String,
    generation: u64,
    relay_id: String,
    helper_connection_id: String,
    exchange_sequence: u64,
    reports: Vec<Frame>,
}
pub async fn exchange(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Exchange>,
) -> ApiResult {
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    broker.validate_helper_owner(&inner);
    authorize(&inner, &headers, "vnc")?;
    csrf(&inner, &headers)?;
    broker.expire();
    if !broker.native_qr_mode || broker.mode_generation != input.generation {
        return Err(conflict());
    }
    let session = broker
        .helper
        .as_mut()
        .filter(|s| s.id == input.session_id && s.owned(&inner, &headers))
        .ok_or_else(conflict)?;
    let relay = session
        .fido
        .as_mut()
        .filter(|relay| {
            relay.available()
                && relay.generation == input.generation
                && relay.id.as_deref() == Some(&input.relay_id)
                && relay.helper_connection.as_deref() == Some(&input.helper_connection_id)
        })
        .ok_or_else(conflict)?;
    let mut failure = None;
    if input.reports.len() > MAX_BATCH || relay.exchange_sequence != input.exchange_sequence {
        failure = Some(StatusCode::CONFLICT);
    }
    if relay.window.elapsed() >= Duration::from_secs(1) {
        relay.window = Instant::now();
        relay.calls = 0;
    }
    if relay.calls >= 100 {
        failure = Some(StatusCode::TOO_MANY_REQUESTS);
    }
    relay.calls += 1;
    if let Some(status) = failure {
        session.fido = None;
        return Err(fail(
            status,
            "Experimental FIDO relay protocol or rate limit exceeded",
        ));
    }
    let Some(next) = relay.exchange_sequence.checked_add(1) else {
        session.fido = None;
        return Err(conflict());
    };
    relay.exchange_sequence = next;
    let mut incoming = relay.incoming.clone();
    if input
        .reports
        .iter()
        .any(|frame| incoming.accept(frame.sequence).is_err())
    {
        session.fido = None;
        return Err(conflict());
    }
    relay.incoming = incoming;
    for frame in input.reports {
        if relay.endpoint.send(frame.data).is_err() {
            session.fido = None;
            return Err(conflict());
        }
    }
    let mut outgoing = Vec::with_capacity(MAX_BATCH);
    for _ in 0..MAX_BATCH {
        match relay.endpoint.try_receive() {
            Ok(Some(report)) => match relay.outgoing.frame(report) {
                Ok(frame) => outgoing.push(frame),
                Err(_) => {
                    session.fido = None;
                    return Err(conflict());
                }
            },
            Ok(None) => break,
            Err(_) => {
                session.fido = None;
                return Err(conflict());
            }
        }
    }
    Ok(Json(
        json!({"version":VERSION,"relay_id":input.relay_id,"exchange_sequence":input.exchange_sequence,"reports":outgoing,"remaining_ms":relay.deadline.saturating_duration_since(Instant::now()).as_millis() as u64}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cancel {
    session_id: String,
    generation: u64,
    relay_id: String,
    helper_connection_id: String,
}
pub async fn cancel(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Cancel>,
) -> ApiResult {
    let mut broker = app.broker.lock().await;
    let inner = app.inner.lock().await;
    broker.validate_helper_owner(&inner);
    authorize(&inner, &headers, "vnc")?;
    csrf(&inner, &headers)?;
    broker.expire();
    if broker.mode_generation != input.generation {
        return Err(conflict());
    }
    let session = broker
        .helper
        .as_mut()
        .filter(|s| s.id == input.session_id && s.owned(&inner, &headers))
        .ok_or_else(conflict)?;
    if session.fido_pending.as_ref().is_some_and(|p| {
        p.relay_id == input.relay_id && p.helper_connection == input.helper_connection_id
    }) {
        session.fido_pending = None;
        return Ok(Json(json!({"ok":true})));
    }
    if !session.fido.as_ref().is_some_and(|relay| {
        relay.id.as_deref() == Some(&input.relay_id)
            && relay.helper_connection.as_deref() == Some(&input.helper_connection_id)
    }) {
        return Err(conflict());
    }
    session.fido = None;
    Ok(Json(json!({"ok":true})))
}

#[cfg(test)]
mod tests {
    use crate::{
        app::App,
        relay::fido_relay,
        test_support::{app, call, proxy_fixture, value},
    };
    use futures_util::{SinkExt, StreamExt};

    use axum::http::StatusCode;
    use fido_report_relay::{endpoint_pair, Report, QUEUE_CAPACITY};
    use serde_json::{json, Value};
    use std::time::{Duration, Instant};

    async fn native_fixture(app: &App) -> (String, String, String, u64) {
        let (cookies, csrf, mut output) = proxy_fixture(app).await;
        let generation = app.broker.lock().await.mode_generation;
        let started = value(
            call(
                app,
                "POST",
                "/api/browser/mode",
                json!({"mode":"native","expected_generation":generation}),
                &cookies,
                &csrf,
                None,
            )
            .await,
        )
        .await;
        let session = started["session_id"].as_str().unwrap().to_owned();
        let mode = output.try_recv().unwrap();
        let generation = mode["generation"].as_u64().unwrap();
        let mut acknowledgement =
            crate::browser::broker::tests::test_ready("native", false, 120000);
        acknowledgement["type"] = json!("mode_ready");
        acknowledgement["generation"] = json!(generation);
        app.broker
            .lock()
            .await
            .on_message(acknowledgement, &[])
            .unwrap();
        (cookies, csrf, session, generation)
    }
    fn open_body(session: &str, generation: u64, id: &str) -> Value {
        json!({"session_id":session,"generation":generation,"relay_id":id,"helper_connection_id":"connection_connection_connection_01"})
    }
    fn exchange_body(
        session: &str,
        generation: u64,
        id: &str,
        exchange: u64,
        reports: Value,
    ) -> Value {
        let mut value = open_body(session, generation, id);
        value["exchange_sequence"] = json!(exchange);
        value["reports"] = reports;
        value
    }
    const RELAY_ID: &str = "relay_relay_relay_relay_relay_0001";
    #[tokio::test]
    async fn experimental_fido_requires_actual_endpoint_and_existing_owner() {
        let (app, dir) = app();
        let (cookies, csrf, session, generation) = native_fixture(&app).await;
        let status = value(
            call(
                &app,
                "GET",
                "/api/helper/status",
                Value::Null,
                &cookies,
                "",
                None,
            )
            .await,
        )
        .await;
        assert_eq!(status["experimental_fido_available"], false);
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/open",
                open_body(&session, generation, RELAY_ID),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let (endpoint, peer) = endpoint_pair();
        assert!(
            fido_relay::attach(&app, &session, generation, endpoint, false)
                .await
                .is_err()
        );
        assert!(peer.is_closed());
        let (endpoint, peer) = endpoint_pair();
        fido_relay::attach(&app, &session, generation, endpoint, true)
            .await
            .unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/open",
                open_body(&session, generation, RELAY_ID),
                &cookies,
                "",
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let other = value(call(&app, "GET", "/api/status", Value::Null, "", "", None).await).await;
        let other = other["csrf_token"].as_str().unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/open",
                open_body(&session, generation, RELAY_ID),
                &format!("ab_csrf={other}"),
                other,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert!(!peer.is_closed());
        let opened = value(
            call(
                &app,
                "POST",
                "/api/helper/fido/open",
                open_body(&session, generation, RELAY_ID),
                &cookies,
                &csrf,
                None,
            )
            .await,
        )
        .await;
        assert_eq!(opened["relay_id"], RELAY_ID);
        assert_eq!(opened["version"], 1);
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/open",
                open_body(&session, generation, RELAY_ID),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        app.broker.lock().await.stop_helper();
        assert!(peer.is_closed());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn actual_packet_endpoint_http_roundtrip_and_cancel() {
        let (app, dir) = app();
        let (cookies, csrf, session, generation) = native_fixture(&app).await;
        let (native, socket) = fido_report_relay::packet::pair().unwrap();
        let native = tokio::io::unix::AsyncFd::new(native).unwrap();
        let (endpoint, adapter) = endpoint_pair();
        let task = tokio::spawn(fido_report_relay::packet::bridge(socket, adapter));
        fido_relay::attach(&app, &session, generation, endpoint, true)
            .await
            .unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/open",
                open_body(&session, generation, RELAY_ID),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        let outgoing = Report::from_slice(&[0xab; 64]).unwrap();
        fido_report_relay::packet::send(&native, &outgoing)
            .await
            .unwrap();
        let mut sequence = 0;
        let report = loop {
            let response = value(
                call(
                    &app,
                    "POST",
                    "/api/helper/fido/exchange",
                    exchange_body(&session, generation, RELAY_ID, sequence, json!([])),
                    &cookies,
                    &csrf,
                    None,
                )
                .await,
            )
            .await;
            sequence += 1;
            if !response["reports"].as_array().unwrap().is_empty() {
                break response["reports"][0].clone();
            }
            assert!(sequence < 20);
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(report["sequence"], 0);
        assert!(serde_json::from_value::<Report>(report["data"].clone()).unwrap() == outgoing);
        let incoming = Report::from_slice(&[0x71; 64]).unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/exchange",
                exchange_body(
                    &session,
                    generation,
                    RELAY_ID,
                    sequence,
                    json!([{"sequence":0,"data":incoming}])
                ),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                fido_report_relay::packet::receive(&native)
            )
            .await
            .unwrap()
            .unwrap()
                == incoming
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/cancel",
                open_body(&session, generation, RELAY_ID),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert!(tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(app.broker.lock().await.native_qr_mode);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn fido_sequence_batch_overflow_and_repair_do_not_replay() {
        let (app, dir) = app();
        let (cookies, csrf, session, generation) = native_fixture(&app).await;
        let (endpoint, mut peer) = endpoint_pair();
        fido_relay::attach(&app, &session, generation, endpoint, true)
            .await
            .unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/open",
                open_body(&session, generation, RELAY_ID),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        let report = Report::from_slice(&[0; 64]).unwrap();
        let valid = exchange_body(
            &session,
            generation,
            RELAY_ID,
            0,
            json!([{"sequence":0,"data":report}]),
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/exchange",
                valid.clone(),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert!(peer.receive().await.is_ok());
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/exchange",
                valid,
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert!(peer.is_closed());
        let (endpoint, new_peer) = endpoint_pair();
        fido_relay::attach(&app, &session, generation, endpoint, true)
            .await
            .unwrap();
        let new_id = "relay_relay_relay_relay_relay_0002";
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/open",
                open_body(&session, generation, new_id),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/cancel",
                open_body(&session, generation, RELAY_ID),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert!(!new_peer.is_closed());
        let too_many = vec![json!({"sequence":0,"data":report}); 9];
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/exchange",
                exchange_body(&session, generation, new_id, 0, json!(too_many)),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert!(new_peer.is_closed());
        let (endpoint, peer) = endpoint_pair();
        fido_relay::attach(&app, &session, generation, endpoint, true)
            .await
            .unwrap();
        for _ in 0..QUEUE_CAPACITY {
            peer.send(report.clone()).unwrap();
        }
        assert!(peer.send(report).is_err());
        assert!(peer.is_closed());
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(app
            .broker
            .lock()
            .await
            .helper
            .as_ref()
            .unwrap()
            .fido
            .is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn fido_token_rotation_authorization_loss_and_deadline_cancel_endpoints() {
        for kind in 0..3 {
            let (app, dir) = app();
            let (cookies, csrf, session, generation) = native_fixture(&app).await;
            let (endpoint, peer) = endpoint_pair();
            fido_relay::attach(&app, &session, generation, endpoint, true)
                .await
                .unwrap();
            match kind {
                0 => {
                    let token = app
                        .broker
                        .lock()
                        .await
                        .helper
                        .as_ref()
                        .unwrap()
                        .token
                        .clone();
                    assert_eq!(
                        call(
                            &app,
                            "POST",
                            "/api/helper/refresh",
                            json!({"session_id":session,"previous_token":token}),
                            &cookies,
                            &csrf,
                            None
                        )
                        .await
                        .status(),
                        StatusCode::OK
                    );
                }
                1 => {
                    app.inner.lock().await.vnc_epoch += 1;
                }
                _ => {
                    app.broker.lock().await.helper.as_mut().unwrap().deadline = Instant::now();
                }
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
            assert!(peer.is_closed());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    async fn complete_adapter_path(preload: Option<std::path::PathBuf>) {
        use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
        let (app, dir) = app();
        let (cookies, csrf, session, generation) = native_fixture(&app).await;
        let (native, socket) = fido_report_relay::packet::pair().unwrap();
        let (endpoint, adapter) = endpoint_pair();
        let bridge = tokio::spawn(fido_report_relay::packet::bridge(socket, adapter));
        fido_relay::attach(&app, &session, generation, endpoint, true)
            .await
            .unwrap();
        let helper = webauthn_helper::launch(None).await.unwrap();
        let token = app
            .broker
            .lock()
            .await
            .helper
            .as_ref()
            .unwrap()
            .token
            .clone();
        helper
            .approve("http://localhost:8080", &token)
            .await
            .unwrap();
        let mut ws_request = helper.websocket_url().into_client_request().unwrap();
        ws_request
            .headers_mut()
            .insert("origin", "http://localhost:8080".parse().unwrap());
        let (mut socket, _) = tokio_tungstenite::connect_async(ws_request).await.unwrap();
        socket
            .send(Message::Text(
                json!({"type":"pair","token":token,"session_id":session}).to_string(),
            ))
            .await
            .unwrap();
        let paired: Value =
            serde_json::from_str(&socket.next().await.unwrap().unwrap().into_text().unwrap())
                .unwrap();
        assert_eq!(paired["state"], "paired");
        let (local, mut authenticator) = endpoint_pair();
        helper
            .attach_experimental_fido(&session, local)
            .await
            .unwrap();
        let available: Value = serde_json::from_str(
            &tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(available["type"], "fido_available");
        let relay = available["relay_id"].as_str().unwrap();
        let connection = available["helper_connection_id"].as_str().unwrap();
        let owner = json!({"session_id":session,"generation":generation,"relay_id":relay,"helper_connection_id":connection});
        let opened = value(
            call(
                &app,
                "POST",
                "/api/helper/fido/open",
                owner.clone(),
                &cookies,
                &csrf,
                None,
            )
            .await,
        )
        .await;
        assert_eq!(opened["relay_id"], relay);
        socket.send(Message::Text(json!({"type":"fido_open","version":1,"relay_id":relay,"remaining_ms":opened["remaining_ms"]}).to_string())).await.unwrap();
        let ready: Value =
            serde_json::from_str(&socket.next().await.unwrap().unwrap().into_text().unwrap())
                .unwrap();
        assert_eq!(ready["type"], "fido_ready");
        let native = tokio::io::unix::AsyncFd::new(native).unwrap();
        let mut child = None;
        if let Some(preload) = preload {
            use std::os::{fd::AsRawFd, unix::process::CommandExt};
            let executable = dir.join("fido-hid-probe");
            assert!(std::process::Command::new("cc")
                .args([
                    "-std=c11",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "tests/fido_hid_probe.c",
                    "-o"
                ])
                .arg(&executable)
                .status()
                .unwrap()
                .success());
            let raw = native.as_raw_fd();
            let mut command = std::process::Command::new(executable);
            command
                .env("LD_PRELOAD", preload)
                .env("UHF_ENABLE", "1")
                .env("UHF_RELAY_FD", "198");
            unsafe {
                command.pre_exec(move || {
                    if raw != 198 && libc::dup2(raw, 198) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::fcntl(198, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            child = Some(command.spawn().unwrap());
        } else {
            fido_report_relay::packet::send(&native, &Report::from_slice(&[0xa5; 64]).unwrap())
                .await
                .unwrap();
        }
        let mut sequence = 0;
        let request_report = loop {
            let mut body = owner.clone();
            body["exchange_sequence"] = json!(sequence);
            body["reports"] = json!([]);
            let response = value(
                call(
                    &app,
                    "POST",
                    "/api/helper/fido/exchange",
                    body,
                    &cookies,
                    &csrf,
                    None,
                )
                .await,
            )
            .await;
            sequence += 1;
            if let Some(report) = response["reports"].as_array().unwrap().first() {
                break report.clone();
            }
            assert!(sequence < 50);
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        socket.send(Message::Text(json!({"type":"fido_report","version":1,"relay_id":relay,"sequence":request_report["sequence"],"data":request_report["data"]}).to_string())).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), authenticator.receive())
                .await
                .unwrap()
                .unwrap()
                == Report::from_slice(&[0xa5; 64]).unwrap()
        );
        authenticator
            .send(Report::from_slice(&[0x5a; 64]).unwrap())
            .unwrap();
        let response: Value = serde_json::from_str(
            &tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response["type"], "fido_report");
        let mut body = owner.clone();
        body["exchange_sequence"] = json!(sequence);
        body["reports"] = json!([{"sequence":response["sequence"],"data":response["data"]}]);
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/exchange",
                body,
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        if let Some(mut child) = child {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("Native opaque probe timed out");
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        } else {
            assert!(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    fido_report_relay::packet::receive(&native)
                )
                .await
                .unwrap()
                .unwrap()
                    == Report::from_slice(&[0x5a; 64]).unwrap()
            );
        }
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/cancel",
                owner,
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        socket
            .send(Message::Text(
                json!({"type":"fido_close","version":1,"relay_id":relay}).to_string(),
            ))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !authenticator.is_closed() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        socket.close(None).await.unwrap();
        helper.shutdown().await.unwrap();
        assert!(bridge.await.unwrap().is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn packet_backend_http_helper_websocket_complete_adapter_path() {
        complete_adapter_path(None).await;
    }
    #[tokio::test]
    #[ignore = "Explicit optional sibling Linux LD_PRELOAD prototype; not Chromium/WebAuthn acceptance"]
    async fn preload_backend_http_helper_websocket_complete_adapter_path() {
        let path = std::env::var_os("AUTH_BROWSER_TEST_HID_PRELOAD")
            .expect("Supply the explicitly built prototype library path");
        let path = std::fs::canonicalize(path).unwrap();
        complete_adapter_path(Some(path)).await;
    }

    async fn control_receive(
        socket: &tokio::io::unix::AsyncFd<fido_report_relay::control::ControlSocket>,
    ) -> (
        fido_report_relay::control::Frame,
        Option<std::os::fd::OwnedFd>,
    ) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let mut ready = socket.readable().await.unwrap();
                if let Ok(result) = ready.try_io(|s| s.get_ref().receive()) {
                    return result.unwrap();
                }
            }
        })
        .await
        .unwrap()
    }
    async fn launcher_fixture(
        app: &mut App,
    ) -> tokio::io::unix::AsyncFd<fido_report_relay::control::ControlSocket> {
        use fido_report_relay::control::{
            ControlSocket, Frame, Opcode, FLAG_GENUINE_MONITOR, FLAG_SIMULATED,
        };
        let (gateway, peer) = ControlSocket::pair().unwrap();
        app.fido_launcher =
            crate::relay::fido_launcher::Launcher::simulated(gateway, [1; 16]).unwrap();
        let mut frame = Frame {
            opcode: Opcode::Hello,
            flags: 0,
            gateway_epoch: [1; 16],
            browser_epoch: [2; 16],
            attachment_id: [0; 16],
            device_generation: 0,
            mode_generation: 0,
            deadline_ns: 0,
            lease_sequence: 0,
        };
        peer.send(&frame, None).unwrap();
        frame.opcode = Opcode::Ready;
        frame.flags = FLAG_GENUINE_MONITOR | FLAG_SIMULATED;
        peer.send(&frame, None).unwrap();
        for _ in 0..100 {
            if app.fido_launcher.available() {
                return tokio::io::unix::AsyncFd::new(peer).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("simulated launcher readiness timed out")
    }
    fn control_ack(
        socket: &tokio::io::unix::AsyncFd<fido_report_relay::control::ControlSocket>,
        frame: &fido_report_relay::control::Frame,
        opcode: fido_report_relay::control::Opcode,
    ) {
        let mut response = frame.clone();
        response.opcode = opcode;
        response.flags = if matches!(
            opcode,
            fido_report_relay::control::Opcode::Prepared
                | fido_report_relay::control::Opcode::Active
                | fido_report_relay::control::Opcode::Renewed
        ) {
            129
        } else {
            0
        };
        socket.get_ref().send(&response, None).unwrap();
    }
    #[tokio::test]
    async fn launcher_owned_open_reports_renew_replay_and_replacement() {
        use fido_report_relay::control::Opcode;
        let (mut app, dir) = app();
        let control = launcher_fixture(&mut app).await;
        let (cookies, csrf, session, generation) = native_fixture(&app).await;
        let status = value(
            call(
                &app,
                "GET",
                "/api/helper/status",
                Value::Null,
                &cookies,
                "",
                None,
            )
            .await,
        )
        .await;
        assert_eq!(status["experimental_fido_launcher_ready"], true);
        assert_eq!(status["experimental_fido_available"], false);
        let a = app.clone();
        let c = cookies.clone();
        let x = csrf.clone();
        let body = open_body(&session, generation, RELAY_ID);
        let opening = tokio::spawn(async move {
            call(&a, "POST", "/api/helper/fido/open", body, &c, &x, None).await
        });
        let (prepared, fd) = control_receive(&control).await;
        assert_eq!(prepared.opcode, Opcode::Prepare);
        control_ack(&control, &prepared, Opcode::Prepared);
        let (activate, none) = control_receive(&control).await;
        assert!(none.is_none());
        assert_eq!(activate.opcode, Opcode::Activate);
        control_ack(&control, &activate, Opcode::Active);
        assert_eq!(opening.await.unwrap().status(), StatusCode::OK);
        // Real packet endpoint connects native controller to the authenticated HTTP exchange.
        let packet = tokio::io::unix::AsyncFd::new(fd.unwrap()).unwrap();
        fido_report_relay::packet::send(&packet, &Report::from_slice(&[0x31; 64]).unwrap())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let response = value(
            call(
                &app,
                "POST",
                "/api/helper/fido/exchange",
                exchange_body(&session, generation, RELAY_ID, 0, json!([])),
                &cookies,
                &csrf,
                None,
            )
            .await,
        )
        .await;
        assert_eq!(
            response["reports"][0]["data"],
            serde_json::to_value(Report::from_slice(&[0x31; 64]).unwrap()).unwrap()
        );
        let report = serde_json::to_value(Report::from_slice(&[0x42; 64]).unwrap()).unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/exchange",
                exchange_body(
                    &session,
                    generation,
                    RELAY_ID,
                    1,
                    json!([{ "sequence":0,"data":report }])
                ),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert!(
            fido_report_relay::packet::receive(&packet).await.unwrap()
                == Report::from_slice(&[0x42; 64]).unwrap()
        );
        let mut renew = open_body(&session, generation, RELAY_ID);
        renew["lease_sequence"] = json!(1);
        renew["remaining_ms"] = json!(30000);
        let a = app.clone();
        let c = cookies.clone();
        let x = csrf.clone();
        let body = renew.clone();
        let renewing = tokio::spawn(async move {
            call(&a, "POST", "/api/helper/fido/renew", body, &c, &x, None).await
        });
        let (renewed, none) = control_receive(&control).await;
        assert!(none.is_none());
        assert_eq!(renewed.opcode, Opcode::Renew);
        assert_eq!(renewed.attachment_id, prepared.attachment_id);
        assert_eq!(renewed.device_generation, prepared.device_generation);
        control_ack(&control, &renewed, Opcode::Renewed);
        assert_eq!(renewing.await.unwrap().status(), StatusCode::OK);
        // Wrong identity cannot terminate the live replacement; matching replay does.
        let mut wrong = renew.clone();
        wrong["helper_connection_id"] = json!("other_connection_connection_00001");
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/renew",
                wrong,
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert!(app
            .broker
            .lock()
            .await
            .helper
            .as_ref()
            .unwrap()
            .fido
            .as_ref()
            .unwrap()
            .available());
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/renew",
                renew,
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let (revoke, _) = control_receive(&control).await;
        assert_eq!(revoke.opcode, Opcode::Revoke);
        assert!(app
            .broker
            .lock()
            .await
            .helper
            .as_ref()
            .unwrap()
            .fido
            .is_none());
        let replacement_id = "replacement_relay_relay_relay_0001";
        let a = app.clone();
        let c = cookies.clone();
        let x = csrf.clone();
        let body = open_body(&session, generation, replacement_id);
        let replacement = tokio::spawn(async move {
            call(&a, "POST", "/api/helper/fido/open", body, &c, &x, None).await
        });
        let (new_prepare, new_fd) = control_receive(&control).await;
        assert_eq!(new_prepare.opcode, Opcode::Prepare);
        assert!(new_prepare.device_generation > prepared.device_generation);
        assert_ne!(new_prepare.attachment_id, prepared.attachment_id);
        // Late old completion does not acknowledge or cancel the new reservation.
        control_ack(&control, &renewed, Opcode::Renewed);
        control_ack(&control, &new_prepare, Opcode::Prepared);
        let (new_activate, _) = control_receive(&control).await;
        assert_eq!(new_activate.attachment_id, new_prepare.attachment_id);
        control_ack(&control, &new_activate, Opcode::Active);
        assert_eq!(replacement.await.unwrap().status(), StatusCode::OK);
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/fido/cancel",
                open_body(&session, generation, replacement_id),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        let (new_revoke, _) = control_receive(&control).await;
        assert_eq!(new_revoke.attachment_id, new_prepare.attachment_id);
        drop(new_fd);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn launcher_prepare_cancellation_and_pairing_rotation_are_terminal() {
        use fido_report_relay::control::Opcode;
        for rotate in [false, true] {
            let (mut app, dir) = app();
            let control = launcher_fixture(&mut app).await;
            let (cookies, csrf, session, generation) = native_fixture(&app).await;
            let a = app.clone();
            let c = cookies.clone();
            let x = csrf.clone();
            let body = open_body(&session, generation, RELAY_ID);
            let opening = tokio::spawn(async move {
                call(&a, "POST", "/api/helper/fido/open", body, &c, &x, None).await
            });
            let (prepare, fd) = control_receive(&control).await;
            assert_eq!(prepare.opcode, Opcode::Prepare);
            if rotate {
                let token = app
                    .broker
                    .lock()
                    .await
                    .helper
                    .as_ref()
                    .unwrap()
                    .token
                    .clone();
                assert_eq!(
                    call(
                        &app,
                        "POST",
                        "/api/helper/refresh",
                        json!({"session_id":session,"previous_token":token}),
                        &cookies,
                        &csrf,
                        None
                    )
                    .await
                    .status(),
                    StatusCode::OK
                );
            } else {
                assert_eq!(
                    call(
                        &app,
                        "POST",
                        "/api/helper/fido/cancel",
                        open_body(&session, generation, RELAY_ID),
                        &cookies,
                        &csrf,
                        None
                    )
                    .await
                    .status(),
                    StatusCode::OK
                );
            }
            control_ack(&control, &prepare, Opcode::Prepared);
            assert_eq!(opening.await.unwrap().status(), StatusCode::CONFLICT);
            let (revoke, _) = control_receive(&control).await;
            assert_eq!(revoke.opcode, Opcode::Revoke);
            assert!(app
                .broker
                .lock()
                .await
                .helper
                .as_ref()
                .unwrap()
                .fido
                .is_none());
            drop(fd);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[tokio::test]
    async fn launcher_active_ack_after_authorization_loss_never_attaches() {
        use fido_report_relay::control::Opcode;
        let (mut app, dir) = app();
        let control = launcher_fixture(&mut app).await;
        let (cookies, csrf, session, generation) = native_fixture(&app).await;
        let a = app.clone();
        let c = cookies.clone();
        let x = csrf.clone();
        let body = open_body(&session, generation, RELAY_ID);
        let opening = tokio::spawn(async move {
            call(&a, "POST", "/api/helper/fido/open", body, &c, &x, None).await
        });
        let (prepare, fd) = control_receive(&control).await;
        control_ack(&control, &prepare, Opcode::Prepared);
        let (activate, _) = control_receive(&control).await;
        assert_eq!(activate.opcode, Opcode::Activate);
        app.inner.lock().await.csrf.clear();
        control_ack(&control, &activate, Opcode::Active);
        assert_ne!(opening.await.unwrap().status(), StatusCode::OK);
        let (revoke, _) = control_receive(&control).await;
        assert_eq!(revoke.opcode, Opcode::Revoke);
        assert!(app.broker.lock().await.helper.is_none());
        drop(fd);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn launcher_renewed_ack_after_owner_rotation_cannot_extend_or_replay() {
        use fido_report_relay::control::Opcode;
        let (mut app, dir) = app();
        let control = launcher_fixture(&mut app).await;
        let (cookies, csrf, session, generation) = native_fixture(&app).await;
        let a = app.clone();
        let c = cookies.clone();
        let x = csrf.clone();
        let body = open_body(&session, generation, RELAY_ID);
        let opening = tokio::spawn(async move {
            call(&a, "POST", "/api/helper/fido/open", body, &c, &x, None).await
        });
        let (prepare, fd) = control_receive(&control).await;
        control_ack(&control, &prepare, Opcode::Prepared);
        let (activate, _) = control_receive(&control).await;
        control_ack(&control, &activate, Opcode::Active);
        assert_eq!(opening.await.unwrap().status(), StatusCode::OK);
        tokio::time::sleep(Duration::from_millis(5)).await;
        let mut body = open_body(&session, generation, RELAY_ID);
        body["lease_sequence"] = json!(1);
        body["remaining_ms"] = json!(30000);
        let a = app.clone();
        let c = cookies.clone();
        let x = csrf.clone();
        let renewing = tokio::spawn(async move {
            call(&a, "POST", "/api/helper/fido/renew", body, &c, &x, None).await
        });
        let (renew, _) = control_receive(&control).await;
        assert_eq!(renew.opcode, Opcode::Renew);
        let token = app
            .broker
            .lock()
            .await
            .helper
            .as_ref()
            .unwrap()
            .token
            .clone();
        assert_eq!(
            call(
                &app,
                "POST",
                "/api/helper/refresh",
                json!({"session_id":session,"previous_token":token}),
                &cookies,
                &csrf,
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        control_ack(&control, &renew, Opcode::Renewed);
        assert_eq!(renewing.await.unwrap().status(), StatusCode::CONFLICT);
        let (revoke, _) = control_receive(&control).await;
        assert_eq!(revoke.opcode, Opcode::Revoke);
        assert_eq!(revoke.attachment_id, prepare.attachment_id);
        assert!(app
            .broker
            .lock()
            .await
            .helper
            .as_ref()
            .unwrap()
            .fido
            .is_none());
        drop(fd);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
