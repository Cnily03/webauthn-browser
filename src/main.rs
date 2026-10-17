//! Process entry point. State, HTTP composition and domain logic live in named modules.
mod app;
mod auth;
mod authenticator;
mod browser;
mod http;
mod profiles;
mod relay;
mod settings;
mod storage;
#[cfg(test)]
mod test_support;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    app::run().await
}
