//! Shared application state and process lifecycle; no HTTP/domain handlers.
use crate::{
    browser::{broker::Broker, control, window_control},
    http,
    relay::{fido_launcher, native_proxy},
    storage::{restore, store::Store},
};
use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::{watch, Mutex, Semaphore};

#[derive(Clone)]
pub(crate) struct App {
    pub(crate) inner: Arc<Mutex<Inner>>,
    pub(crate) broker: Arc<Mutex<Broker>>,
    pub(crate) revoked: watch::Sender<u64>,
    pub(crate) operations: Arc<Mutex<()>>,
    pub(crate) stream_slots: Arc<Semaphore>,
    pub(crate) restore: Arc<Mutex<restore::Pending>>,
    pub(crate) recovery_slots: Arc<Semaphore>,
    pub(crate) window_control: Arc<window_control::Controller>,
    pub(crate) fido_launcher: Arc<fido_launcher::Launcher>,
}
pub(crate) struct Inner {
    pub(crate) store: Store,
    pub(crate) sessions: HashMap<String, Session>,
    pub(crate) csrf: HashMap<String, Instant>,
    pub(crate) vnc_epoch: u64,
    pub(crate) settings_epoch: u64,
    pub(crate) engine_connected: bool,
    pub(crate) engine_message: String,
    pub(crate) attempts: HashMap<String, (Instant, u32)>,
}
pub(crate) struct Session {
    pub(crate) scope: String,
    pub(crate) epoch: u64,
    pub(crate) expires: Instant,
}
pub(crate) async fn run() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--native-proxy") {
        return native_proxy::run_host().await;
    }
    let store = Store::open(
        std::env::var("AUTH_BROWSER_STORE").unwrap_or_else(|_| "/data/auth-browser.json".into()),
    )?;
    let (revoked, _) = watch::channel(0);
    let app = App {
        inner: Arc::new(Mutex::new(Inner {
            store,
            sessions: HashMap::new(),
            csrf: HashMap::new(),
            vnc_epoch: 0,
            settings_epoch: 0,
            engine_connected: false,
            engine_message: "Connecting to Chromium".into(),
            attempts: HashMap::new(),
        })),
        broker: Arc::new(Mutex::new(Broker::default())),
        revoked,
        operations: Arc::new(Mutex::new(())),
        stream_slots: Arc::new(Semaphore::new(64)),
        restore: Arc::new(Mutex::new(restore::Pending::default())),
        recovery_slots: Arc::new(Semaphore::new(1)),
        window_control: Arc::new(crate::browser::window_control::Controller::default()),
        fido_launcher: fido_launcher::Launcher::from_environment(),
    };
    control::start_proxy(app.clone()).await?;
    let router = http::router(app.clone());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    eprintln!("WebAuthn Browser HTTP listening on :8080");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown(app))
        .await?;
    Ok(())
}
async fn shutdown(app: App) {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}
    {
        let mut i = app.inner.lock().await;
        i.vnc_epoch += 1;
        app.revoked.send_modify(|v| *v += 1);
    }
    app.broker.lock().await.cancel_all("Service shutting down");
    if let Err(error) = app.inner.lock().await.store.save() {
        eprintln!("CRITICAL: final credential checkpoint failed: {error}");
    }
}
