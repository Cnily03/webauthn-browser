use std::{env, path::PathBuf, process::Command};
fn main() {
    assert_eq!(env::var("CARGO_CFG_TARGET_OS").unwrap(), "linux");
    assert_eq!(env::var("CARGO_CFG_TARGET_ARCH").unwrap(), "x86_64");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("abi.o");
    assert!(Command::new("cc")
        .args([
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fPIC",
            "-fvisibility=hidden",
            "-c",
            "native/abi.c",
            "-o"
        ])
        .arg(&out)
        .status()
        .unwrap()
        .success());
    println!("cargo:rustc-link-arg={}", out.display());
    println!("cargo:rerun-if-changed=native/abi.c");
}
