//! Private device workers enter before the terminal, logging, or async runtime.
pub(super) fn dispatch(worker: impl FnOnce() -> bool, application: impl FnOnce()) {
    if !worker() {
        application();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_dispatch_never_initializes_application_runtime() {
        let mut output = Vec::new();
        dispatch(
            || {
                output.extend_from_slice(b"private pipe frame");
                true
            },
            || panic!("worker must not initialize Tokio/CLI"),
        );
        assert_eq!(output, b"private pipe frame");
        let started = std::cell::Cell::new(false);
        dispatch(|| false, || started.set(true));
        assert!(started.get());
    }
}
