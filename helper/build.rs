fn main() {
    for (binary, plist) in [
        ("webauthn-helper", "Info.plist"),
        ("webauthn-helper-desktop", "Info-desktop.plist"),
    ] {
        println!("cargo:rerun-if-changed={plist}");
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
            let path =
                std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join(plist);
            println!(
                "cargo:rustc-link-arg-bin={binary}=-Wl,-sectcreate,__TEXT,__info_plist,{}",
                path.display()
            );
        }
    }
}
