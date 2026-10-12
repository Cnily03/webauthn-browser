// Standalone, test-only fake child. No HID/device API or production test hook.
#[path = "../../src/cli/bootstrap.rs"]
mod bootstrap;
fn main() {
    bootstrap::dispatch(
        || {
            use std::io::{Read, Write};
            let mut size = [0; 4];
            std::io::stdin().read_exact(&mut size).unwrap();
            assert_eq!(u32::from_be_bytes(size), 4);
            let mut report = [0; 4];
            std::io::stdin().read_exact(&mut report).unwrap();
            assert_eq!(&report, b"FAKE");
            std::io::stdout().write_all(&size).unwrap();
            std::io::stdout().write_all(&report).unwrap();
            true
        },
        || panic!("private worker entered application/runtime initialization"),
    );
}
