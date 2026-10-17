//! Shared application state and process lifecycle; no HTTP/domain handlers.
use crate::{
    browser::{broker::Broker, window_control},
    http,
    relay::{fido_launcher, native_proxy},
    storage::{restore, store::Store},
};
use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::{watch, Mutex, Semaphore};

#[derive(Clone)]
pub(crate) struct App {
    pub(crate) profile_scope: bool,
    pub(crate) profile_id: Arc<str>,
    pub(crate) profile_name: Option<Arc<str>>,
    pub(crate) endpoints: Arc<crate::profiles::runtime::Endpoints>,
    pub(crate) profiles: Option<Arc<crate::profiles::Registry>>,
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
impl App {
    pub(crate) async fn cancel_brokers(&self, reason: &str) {
        self.broker.lock().await.cancel_all(reason);
        if let Some(registry) = &self.profiles {
            for app in registry.all() {
                if !Arc::ptr_eq(&app.broker, &self.broker) {
                    app.broker.lock().await.cancel_all(reason);
                }
            }
        }
    }
}
pub(crate) struct Inner {
    pub(crate) profile_viewers: HashMap<String, crate::profiles::viewer::Viewers>,
    pub(crate) viewer_tickets: HashMap<String, crate::profiles::viewer::Ticket>,
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
    let mut app = App {
        profile_scope: false,
        profile_name: None,
        profile_id: std::sync::Arc::from("default"),
        endpoints: std::sync::Arc::new(crate::profiles::runtime::Endpoints::legacy()),
        profiles: None,
        inner: Arc::new(Mutex::new(Inner {
            profile_viewers: std::collections::HashMap::new(),
            viewer_tickets: std::collections::HashMap::new(),
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
    app.profiles = Some(crate::profiles::Registry::new());
    tokio::spawn(crate::profiles::cleanup::recover(app.clone()));
    let maintenance = app.clone();
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(std::time::Duration::from_millis(250));
        loop {
            timer.tick().await;
            if let Some(registry) = &maintenance.profiles {
                for mut context in registry.all() {
                    context.profiles = Some(registry.clone());
                    crate::profiles::viewer::expire(&context).await;
                }
            }
        }
    });
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
    {
        app.inner.lock().await.profile_viewers.clear();
    }
    app.cancel_brokers("Service shutting down").await;
    if let Some(registry) = &app.profiles {
        for context in registry.all() {
            context.revoked.send_modify(|n| *n = n.wrapping_add(1));
        }
    }
    if let Err(error) = app.inner.lock().await.store.save() {
        eprintln!("CRITICAL: final credential checkpoint failed: {error}");
    }
}
