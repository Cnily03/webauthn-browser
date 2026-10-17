//! Read-only downloads rooted in an opened directory. Symlinks and nested paths are never followed.
use axum::{
    body::{Body, Bytes},
    extract::{OriginalUri, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use percent_encoding::{percent_decode_str, percent_encode, NON_ALPHANUMERIC};
use ring::digest::{digest, SHA256};
use rustix::fs::{open, openat, Dir, Mode, OFlags};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::Path as FsPath;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{ffi::OsStr, fs::File, io, os::unix::ffi::OsStrExt, path::PathBuf};
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
const MAX_BINARY: u64 = 64 * 1024 * 1024;
const TARGETS: &[(&str, &str, &str, &str)] = &[
    ("webauthn-helper-linux-x86_64", "Linux", "cli", "x86_64"),
    (
        "webauthn-helper-desktop-linux-x86_64",
        "Linux",
        "desktop",
        "x86_64",
    ),
    (
        "webauthn-helper-windows-x86_64.exe",
        "Windows",
        "cli",
        "x86_64",
    ),
    (
        "webauthn-helper-desktop-windows-x86_64.exe",
        "Windows",
        "desktop",
        "x86_64",
    ),
    (
        "webauthn-helper-macos-universal",
        "macOS",
        "cli",
        "universal",
    ),
    (
        "webauthn-helper-desktop-macos-universal",
        "macOS",
        "desktop",
        "universal",
    ),
];
struct Entry {
    filename: &'static str,
    platform: &'static str,
    mode: &'static str,
    arch: &'static str,
    bytes: Bytes,
    hash: String,
}

#[derive(Debug, Serialize)]
struct DownloadFile {
    name: String,
    url: String,
    size: u64,
    created_at: Option<String>,
}

fn binary_header_valid(bytes: &[u8], platform: &str, arch: &str) -> bool {
    match platform {
        "Linux" => {
            bytes.len() >= 64
                && bytes.starts_with(b"\x7fELF")
                && bytes[4] == 2
                && bytes[5] == 1
                && bytes[18..20] == [62, 0]
        }
        "Windows" => {
            if bytes.len() < 64 || !bytes.starts_with(b"MZ") {
                return false;
            }
            let offset = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
            bytes.get(offset..offset.saturating_add(6)) == Some(&b"PE\0\0\x64\x86"[..])
        }
        "macOS" if arch == "universal" => universal_macos_header(bytes),
        "macOS" => {
            bytes.len() >= 32
                && bytes[..4] == [0xcf, 0xfa, 0xed, 0xfe]
                && bytes[4..8]
                    == if arch == "aarch64" {
                        [12, 0, 0, 1]
                    } else {
                        [7, 0, 0, 1]
                    }
        }
        _ => false,
    }
}
fn universal_macos_header(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let wide = bytes[..4] == [0xca, 0xfe, 0xba, 0xbf];
    if !wide && bytes[..4] != [0xca, 0xfe, 0xba, 0xbe] {
        return false;
    }
    let count = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
    if !(2..=8).contains(&count) {
        return false;
    }
    let record = if wide { 32 } else { 20 };
    if bytes.len() < 8 + count * record {
        return false;
    }
    let mut seen_arm = false;
    let mut seen_intel = false;
    for index in 0..count {
        let start = 8 + index * record;
        let cpu = u32::from_be_bytes(bytes[start..start + 4].try_into().unwrap());
        let (offset, size) = if wide {
            (
                u64::from_be_bytes(bytes[start + 8..start + 16].try_into().unwrap()),
                u64::from_be_bytes(bytes[start + 16..start + 24].try_into().unwrap()),
            )
        } else {
            (
                u32::from_be_bytes(bytes[start + 8..start + 12].try_into().unwrap()) as u64,
                u32::from_be_bytes(bytes[start + 12..start + 16].try_into().unwrap()) as u64,
            )
        };
        if offset < (8 + count * record) as u64
            || size < 32
            || offset
                .checked_add(size)
                .is_none_or(|end| end > bytes.len() as u64)
        {
            return false;
        }
        let arch = match cpu {
            0x0100000c => "aarch64",
            0x01000007 => "x86_64",
            _ => continue,
        };
        if !binary_header_valid(
            &bytes[offset as usize..(offset + size) as usize],
            "macOS",
            arch,
        ) {
            return false;
        }
        if arch == "aarch64" {
            seen_arm = true;
        } else {
            seen_intel = true;
        }
    }
    seen_arm && seen_intel
}
fn downloads_directory() -> PathBuf {
    std::env::var_os("AUTH_BROWSER_DOWNLOADS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("downloads"))
}
fn open_directory(directory: &FsPath) -> io::Result<File> {
    Ok(open(
        directory,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into())
}
fn valid_filename(filename: &[u8]) -> bool {
    !filename.is_empty()
        && filename != b"."
        && filename != b".."
        && !filename.iter().any(|b| matches!(b, b'/' | 0))
}
fn open_file(directory: &File, filename: &[u8]) -> io::Result<File> {
    if !valid_filename(filename) {
        return Err(io::ErrorKind::NotFound.into());
    }
    // A single name, relative to the held directory descriptor. NOFOLLOW closes
    // the symlink replacement race; NONBLOCK prevents a replaced FIFO hanging.
    let file: File = openat(
        directory,
        OsStr::from_bytes(filename),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?
    .into();
    if !file.metadata()?.is_file() {
        return Err(io::ErrorKind::NotFound.into());
    }
    Ok(file)
}
fn load_catalog(directory: &FsPath) -> Vec<Entry> {
    let Ok(directory) = open_directory(directory) else {
        return vec![];
    };
    TARGETS
        .iter()
        .filter_map(|&(filename, platform, mode, arch)| {
            let file = open_file(&directory, filename.as_bytes()).ok()?;
            let size = file.metadata().ok()?.len();
            if size == 0 || size > MAX_BINARY {
                return None;
            }
            let mut bytes = Vec::new();
            use std::io::Read;
            file.take(MAX_BINARY + 1).read_to_end(&mut bytes).ok()?;
            if bytes.len() as u64 != size || !binary_header_valid(&bytes, platform, arch) {
                return None;
            }
            let hash = digest(&SHA256, &bytes)
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            Some(Entry {
                filename,
                platform,
                mode,
                arch,
                bytes: Bytes::from(bytes),
                hash,
            })
        })
        .collect()
}
async fn catalog() -> Vec<Entry> {
    tokio::task::spawn_blocking(|| load_catalog(&downloads_directory()))
        .await
        .unwrap_or_default()
}
fn encoded_name(name: &[u8]) -> String {
    percent_encode(name, NON_ALPHANUMERIC).to_string()
}

fn creation_time(created: io::Result<SystemTime>) -> Option<String> {
    // A birth timestamp may be unavailable on the backing filesystem. Never
    // substitute mtime/ctime: either would mislabel a different event as creation.
    let timestamp = match created.ok()?.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()).ok()?,
        Err(error) => -i128::try_from(error.duration().as_nanos()).ok()?,
    };
    let date = time::OffsetDateTime::from_unix_timestamp_nanos(timestamp).ok()?;
    if !(0..=9999).contains(&date.year()) {
        return None;
    }
    // RFC 3339, UTC with nanosecond precision. Components come from time's
    // checked calendar conversion; no optional formatting feature is required.
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        date.year(),
        date.month() as u8,
        date.day(),
        date.hour(),
        date.minute(),
        date.second(),
        date.nanosecond()
    ))
}

fn directory_files(directory: &FsPath) -> io::Result<Vec<DownloadFile>> {
    let mut entries = vec![];
    match open_directory(directory) {
        Ok(directory) => {
            for entry in Dir::read_from(&directory)? {
                let entry = entry?;
                let name = entry.file_name().to_bytes();
                // Recheck the opened object, never trusting the directory-entry
                // type. Metadata and bytes use the same no-follow file boundary.
                if let Ok(file) = open_file(&directory, name) {
                    let metadata = file.metadata()?;
                    entries.push((
                        name.to_vec(),
                        DownloadFile {
                            name: String::from_utf8_lossy(name).into_owned(),
                            url: format!("/downloads/{}", encoded_name(name)),
                            size: metadata.len(),
                            created_at: creation_time(metadata.created()),
                        },
                    ));
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // Sort by the original filename bytes. Distinct non-UTF-8 names may have the
    // same display label, but retain distinct lossless download URLs.
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries.into_iter().map(|(_, file)| file).collect())
}

pub async fn list() -> Response {
    match tokio::task::spawn_blocking(|| directory_files(&downloads_directory())).await {
        Ok(Ok(files)) => Json(json!({"files": files})).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Download directory unavailable",
        )
            .into_response(),
    }
}
pub async fn manifest(State(app): State<crate::app::App>) -> Json<Value> {
    let entries = catalog().await;
    Json(json!({
        "downloads": entries.iter().map(|e| json!({"filename":e.filename,"platform":e.platform,"mode":e.mode,"arch":e.arch,"size":e.bytes.len(),"sha256":e.hash,"url":format!("{}/download/{}",if app.profile_scope{format!("/p/{}",app.profile_name.as_deref().unwrap_or("default"))}else{String::new()},e.filename)})).collect::<Vec<_>>(),
        "unavailable":TARGETS.iter().filter(|(filename,_,_,_)| !entries.iter().any(|e| e.filename == *filename)).map(|(_,platform,mode,arch)| json!({"platform":platform,"mode":mode,"arch":arch,"reason":"此版本未提供已构建的可执行文件"})).collect::<Vec<_>>()
    }))
}
pub async fn download(OriginalUri(uri): OriginalUri) -> Response {
    let raw = uri
        .path()
        .strip_prefix("/downloads/")
        .or_else(|| uri.path().strip_prefix("/download/"))
        .unwrap_or("");
    let filename = percent_decode_str(raw).collect::<Vec<u8>>();
    let name = filename.clone();
    let opened = tokio::task::spawn_blocking(move || {
        let directory = open_directory(&downloads_directory())?;
        let file = open_file(&directory, &name)?;
        let size = file.metadata()?.len();
        Ok::<_, io::Error>((file, size))
    })
    .await;
    let Ok(Ok((file, size))) = opened else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let stream = ReaderStream::new(tokio::fs::File::from_std(file).take(size));
    let mut response = Response::new(Body::from_stream(stream));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    // Always download, including HTML/SVG. The safe ASCII fallback and encoded
    // RFC 5987 value cannot inject headers, quotes or executable markup.
    let disposition = if std::str::from_utf8(&filename).is_ok() {
        format!(
            "attachment; filename=\"download\"; filename*=UTF-8''{}",
            encoded_name(&filename)
        )
    } else {
        "attachment; filename=\"download\"".to_owned()
    };
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition).unwrap(),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&size.to_string()).unwrap(),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox; default-src 'none'"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::Session,
        test_support::{app, call, value},
    };

    use axum::{
        body::to_bytes,
        http::{header, StatusCode},
    };
    use serde_json::Value;
    use std::time::{Duration, Instant};

    #[test]
    fn platform_headers_reject_wrong_arch_and_text() {
        assert!(!binary_header_valid(b"not a binary", "Linux", "x86_64"));
        let mut elf = vec![0; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[18] = 62;
        assert!(binary_header_valid(&elf, "Linux", "x86_64"));
        elf[18] = 183;
        assert!(!binary_header_valid(&elf, "Linux", "x86_64"));
        let mut pe = vec![0; 70];
        pe[..2].copy_from_slice(b"MZ");
        pe[60] = 64;
        pe[64..70].copy_from_slice(b"PE\0\0\x64\x86");
        assert!(binary_header_valid(&pe, "Windows", "x86_64"));
        pe[60] = 255;
        assert!(!binary_header_valid(&pe, "Windows", "x86_64"));
        let mut mac = vec![0; 32];
        mac[..8].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe, 12, 0, 0, 1]);
        assert!(binary_header_valid(&mac, "macOS", "aarch64"));
        assert!(!binary_header_valid(&mac, "macOS", "x86_64"));
    }
    #[test]
    fn universal_macos_requires_both_real_slices() {
        let mut bytes = vec![0; 128];
        bytes[..8].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]);
        for (index, cpu, offset) in [(0usize, 0x0100000cu32, 64u32), (1, 0x01000007, 96)] {
            let start = 8 + index * 20;
            bytes[start..start + 4].copy_from_slice(&cpu.to_be_bytes());
            bytes[start + 8..start + 12].copy_from_slice(&offset.to_be_bytes());
            bytes[start + 12..start + 16].copy_from_slice(&32u32.to_be_bytes());
            bytes[offset as usize..offset as usize + 4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
            bytes[offset as usize + 4..offset as usize + 8].copy_from_slice(&cpu.to_le_bytes());
        }
        assert!(binary_header_valid(&bytes, "macOS", "universal"));
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        assert!(!binary_header_valid(&bytes, "macOS", "universal"));
        bytes[4..8].copy_from_slice(&2u32.to_be_bytes());
        bytes[36..40].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(!binary_header_valid(&bytes, "macOS", "universal"));
    }
    #[test]
    fn catalog_is_allowlisted_and_rejects_symlinks() {
        let root = std::env::temp_dir().join(format!("helper-downloads-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let mut elf = vec![0; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[18] = 62;
        std::fs::write(root.join(TARGETS[0].0), &elf).unwrap();
        std::fs::write(root.join("secret.txt"), b"private").unwrap();
        let entries = load_catalog(&root);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hash.len(), 64);
        std::fs::remove_file(root.join(TARGETS[0].0)).unwrap();
        std::os::unix::fs::symlink(root.join("secret.txt"), root.join(TARGETS[0].0)).unwrap();
        assert!(load_catalog(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("downloads-directory-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn filenames_reject_paths_but_preserve_unix_filename_bytes() {
        for name in [b"".as_slice(), b".", b"..", b"../outside", b"a/b", b"a\0b"] {
            assert!(!valid_filename(name), "accepted {name:?}");
        }
        for name in [
            b"file.txt".as_slice(),
            b".hidden",
            b"..literal",
            b"%2e%2e",
            b"quotes\"'&<>",
            b"new\nline",
            b"raw-\xff",
            b"a\\b",
        ] {
            assert!(valid_filename(name), "rejected {name:?}");
            assert_eq!(
                percent_decode_str(&encoded_name(name)).collect::<Vec<_>>(),
                name
            );
        }
        assert_eq!(encoded_name(b"a /?%#\xff"), "a%20%2F%3F%25%23%FF");
    }

    #[test]
    fn creation_time_is_rfc3339_or_null_without_fabricating_metadata() {
        use std::time::Duration;
        assert_eq!(creation_time(Err(io::ErrorKind::Unsupported.into())), None);
        assert_eq!(
            creation_time(Err(io::ErrorKind::PermissionDenied.into())),
            None
        );
        assert_eq!(
            creation_time(Ok(UNIX_EPOCH)).as_deref(),
            Some("1970-01-01T00:00:00.000000000Z")
        );
        assert_eq!(
            creation_time(Ok(UNIX_EPOCH + Duration::new(1, 123_456_789))).as_deref(),
            Some("1970-01-01T00:00:01.123456789Z")
        );
        assert_eq!(
            creation_time(Ok(UNIX_EPOCH - Duration::from_nanos(1))).as_deref(),
            Some("1969-12-31T23:59:59.999999999Z")
        );
        // RFC 3339 cannot represent a five-digit year.
        assert_eq!(
            creation_time(Ok(UNIX_EPOCH + Duration::from_secs(253_402_300_800))),
            None
        );
    }

    #[test]
    fn directory_creation_time_does_not_follow_backdated_mtime() {
        let root = TestDirectory::new();
        let file = File::create(root.0.join("file")).unwrap();
        let before = creation_time(file.metadata().unwrap().created());
        let modified = UNIX_EPOCH + std::time::Duration::from_secs(946_684_800);
        file.set_modified(modified).unwrap();
        assert_eq!(file.metadata().unwrap().modified().unwrap(), modified);
        let files = directory_files(&root.0).unwrap();
        assert_eq!(files[0].created_at, before);
        if let Some(created) = &files[0].created_at {
            assert_ne!(Some(created.clone()), creation_time(Ok(modified)));
        }
    }

    #[test]
    fn directory_lists_regular_file_metadata_with_lossless_urls() {
        let root = TestDirectory::new();
        let html_name = b"\"><script>alert(1)<script>&'.html";
        let raw_name = b"raw-\xff.bin";
        let unicode_name = "下载 文件.txt";
        std::fs::write(root.0.join("empty.txt"), b"").unwrap();
        std::fs::write(root.0.join("README.md"), b"arbitrary document").unwrap();
        std::fs::write(root.0.join(OsStr::from_bytes(html_name)), b"html").unwrap();
        std::fs::write(root.0.join(OsStr::from_bytes(raw_name)), b"raw").unwrap();
        std::fs::write(root.0.join(unicode_name), b"unicode").unwrap();
        std::fs::write(root.0.join(TARGETS[0].0), b"not an executable").unwrap();
        let large = File::create(root.0.join("large.bin")).unwrap();
        large.set_len(MAX_BINARY + 1).unwrap();
        std::fs::create_dir(root.0.join("nested")).unwrap();
        std::fs::write(root.0.join("nested/hidden.txt"), b"nested").unwrap();
        std::os::unix::fs::symlink("README.md", root.0.join("linked-file")).unwrap();
        std::os::unix::fs::symlink("nested", root.0.join("linked-directory")).unwrap();

        let files = directory_files(&root.0).unwrap();
        assert_eq!(files.len(), 7);
        for name in [
            b"empty.txt".as_slice(),
            b"README.md",
            html_name,
            raw_name,
            unicode_name.as_bytes(),
            TARGETS[0].0.as_bytes(),
            b"large.bin",
        ] {
            let file = files
                .iter()
                .find(|file| file.url == format!("/downloads/{}", encoded_name(name)))
                .unwrap();
            let metadata = std::fs::metadata(root.0.join(OsStr::from_bytes(name))).unwrap();
            assert_eq!(file.name, String::from_utf8_lossy(name));
            assert_eq!(file.size, metadata.len());
            assert_eq!(file.created_at, creation_time(metadata.created()));
        }
        assert_eq!(files[0].name, String::from_utf8_lossy(html_name));
        let serialized = serde_json::to_value(&files).unwrap();
        for file in serialized.as_array().unwrap() {
            assert_eq!(file.as_object().unwrap().len(), 4);
            assert!(file["name"].is_string());
            assert!(file["size"].is_u64());
            assert!(file["created_at"].is_null() || file["created_at"].is_string());
        }
        assert!(
            load_catalog(&root.0).is_empty(),
            "the legacy manifest must retain executable validation"
        );
    }

    #[test]
    fn file_open_rejects_symlinks_directories_and_fifo_without_waiting() {
        let root = TestDirectory::new();
        let outside = TestDirectory::new();
        std::fs::write(outside.0.join("secret"), b"outside secret").unwrap();
        std::fs::write(root.0.join("file"), b"inside").unwrap();
        std::fs::create_dir(root.0.join("nested")).unwrap();
        std::os::unix::fs::symlink(outside.0.join("secret"), root.0.join("linked")).unwrap();
        std::os::unix::fs::symlink(&outside.0, root.0.join("linked-directory")).unwrap();
        let directory = open_directory(&root.0).unwrap();
        rustix::fs::mkfifoat(&directory, "fifo", Mode::RUSR | Mode::WUSR).unwrap();
        for name in [
            b"linked".as_slice(),
            b"linked-directory",
            b"nested",
            b"fifo",
            b"../secret",
            b"nested/file",
            b"missing",
        ] {
            assert!(open_file(&directory, name).is_err(), "opened {name:?}");
        }
        assert!(open_file(&directory, b"file").is_ok());
        let files = directory_files(&root.0).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "file");
    }

    #[test]
    fn held_directory_and_open_file_do_not_follow_replacements() {
        use std::io::Read;
        let root = TestDirectory::new();
        let downloads = root.0.join("downloads");
        let moved = root.0.join("original");
        let replacement = root.0.join("replacement");
        std::fs::create_dir(&downloads).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        std::fs::write(downloads.join("file"), b"original contents").unwrap();
        std::fs::write(replacement.join("file"), b"outside contents").unwrap();
        let directory = open_directory(&downloads).unwrap();
        std::fs::rename(&downloads, &moved).unwrap();
        std::os::unix::fs::symlink(&replacement, &downloads).unwrap();
        assert!(open_directory(&downloads).is_err());
        assert!(directory_files(&downloads).is_err());
        let mut file = open_file(&directory, b"file").unwrap();
        std::fs::remove_file(moved.join("file")).unwrap();
        std::os::unix::fs::symlink(replacement.join("file"), moved.join("file")).unwrap();
        assert!(open_file(&directory, b"file").is_err());
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "original contents");
    }

    #[test]
    fn missing_directory_is_an_empty_list_and_additions_are_visible() {
        let root = TestDirectory::new();
        let missing = root.0.join("missing");
        assert!(directory_files(&missing).unwrap().is_empty());
        assert!(load_catalog(&missing).is_empty());
        std::fs::create_dir(&missing).unwrap();
        std::fs::write(missing.join("new.txt"), b"new").unwrap();
        assert_eq!(directory_files(&missing).unwrap()[0].name, "new.txt");
        std::fs::remove_file(missing.join("new.txt")).unwrap();
        assert!(directory_files(&missing).unwrap().is_empty());
    }

    // Route-level regression for the shared React shell, metadata and byte stream.

    #[tokio::test]
    async fn downloads_shell_metadata_and_files_are_public_but_legacy_routes_stay_protected() {
        let (app, dir) = app();
        let list = call(&app, "GET", "/api/downloads", Value::Null, "", "", None).await;
        assert_eq!(list.status(), StatusCode::OK);
        assert_eq!(list.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(list.headers()[header::CACHE_CONTROL], "no-store");
        let list = value(list).await;
        assert_eq!(list.as_object().unwrap().len(), 1);
        assert!(list["files"].is_array());

        let routes = [
            ("/api/downloads", StatusCode::OK),
            ("/downloads/file.bin", StatusCode::NOT_FOUND),
            ("/download/file.bin", StatusCode::UNAUTHORIZED),
            ("/api/helper/downloads", StatusCode::UNAUTHORIZED),
        ];
        {
            let mut inner = app.inner.lock().await;
            inner.store.data.vnc_password_hash = Some("enabled".into());
            for scope in ["vnc", "settings"] {
                inner.sessions.insert(
                    scope.into(),
                    Session {
                        scope: scope.into(),
                        epoch: 0,
                        expires: Instant::now() + Duration::from_secs(60),
                    },
                );
            }
        }
        for cookies in ["", "ab_settings=settings"] {
            for (route, expected) in routes {
                assert_eq!(
                    call(&app, "GET", route, Value::Null, cookies, "", None)
                        .await
                        .status(),
                    expected,
                    "{route}"
                );
            }
        }
        assert_eq!(
            call(
                &app,
                "GET",
                "/api/downloads",
                Value::Null,
                "ab_vnc=vnc",
                "",
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        for route in ["/downloads", "/downloads/"] {
            let shell = call(&app, "GET", route, Value::Null, "", "", None).await;
            let status = shell.status();
            let body = String::from_utf8(
                to_bytes(shell.into_body(), 1_000_000)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            // A source-only cargo test need not have built web assets. Either result
            // must come from index(), never the removed standalone directory HTML.
            if status == StatusCode::OK {
                assert!(body.contains("<div id=\"root\"></div>"));
                assert!(body.contains("/assets/"));
            } else {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(body, "UI assets unavailable");
            }
        }
        app.inner.lock().await.vnc_epoch += 1;
        assert_eq!(
            call(
                &app,
                "GET",
                "/api/downloads",
                Value::Null,
                "ab_vnc=vnc",
                "",
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
