//! Loopback listener and local capability/HTTP boundary.
mod handle;
pub(crate) mod http;
mod listener;
pub(crate) mod websocket;
pub use handle::Handle;
pub use listener::{
    launch, launch_desktop, launch_incoming, launch_incoming_with_session, DEFAULT_PORT,
};
