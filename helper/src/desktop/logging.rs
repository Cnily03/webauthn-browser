//! Optional console diagnostics; never creates a console, log file or GUI log window.
use std::io::{self, IsTerminal};

pub(super) fn init() {
    // Embedders may already own a subscriber; preserve it, with plain lifecycle
    // words unless our matching trusted formatter actually installs.
    let color = io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let _ = webauthn_helper::logging::install(
        io::stderr,
        color,
        module_path!().rsplit_once("::").unwrap().0,
    );
}
