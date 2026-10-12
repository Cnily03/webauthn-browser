use std::{
    io::Write,
    process::{Command, Stdio},
};
fn run(args: &[&str], input: &str) -> (std::process::Output, std::path::PathBuf) {
    let config = std::env::temp_dir().join(format!(
        "helper-cli-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&config).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_webauthn-helper"))
        .args(args)
        .env("XDG_CONFIG_HOME", &config)
        .env("APPDATA", &config)
        .env("HOME", &config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    (child.wait_with_output().unwrap(), config)
}
#[test]
fn terminal_commands_revoke_switch_port_without_saving_or_printing_input() {
    let token = "UniquePrivatePairingToken0123456789";
    let input = format!("{token}\nstatus\nstart\nstop\nrevoke\nport 18020\nstatus\nhelp\nquit\n");
    let (out, config) = run(&[], &input);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    assert!(text.contains("Listening: ws://127.0.0.1:"));
    assert!(text.contains("Commands:"));
    assert!(text.contains("Connect an approved, unexpired webpage first."));
    assert!(text.contains("(this process only)"));
    assert_eq!(std::fs::read_dir(&config).unwrap().count(), 0);
    assert!(text.contains("connected=false scanning=false"));
    assert!(!text.contains("Helper stopped."));
    assert!(!text.contains(token));
    assert!(!text.contains("Local controls:"));
    assert!(!text.contains("/#"));
    std::fs::remove_dir_all(config).unwrap();
}
#[test]
fn occupied_listen_prints_actual_fallback_and_eof_exits() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let requested = held.local_addr().unwrap().to_string();
    let (out, config) = run(&["--listen", &requested], "");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    let actual = text
        .lines()
        .find_map(|l| l.split_once("Listening: ").map(|(_, address)| address))
        .unwrap();
    assert_ne!(actual, format!("ws://{requested}"));
    assert!(actual.starts_with("ws://127.0.0.1:"));
    assert!(!actual.contains("/bridge"));
    assert_eq!(text.lines().count(), 1);
    assert!(out.stderr.is_empty());
    assert!(!text.contains("Helper stopped."));
    std::fs::remove_dir_all(config).unwrap();
}

struct InteractiveCli {
    child: tokio::process::Child,
    stdin: Option<tokio::process::ChildStdin>,
    stdout: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
    output: String,
    url: String,
    config: std::path::PathBuf,
}
impl InteractiveCli {
    async fn launch() -> Self {
        use tokio::io::AsyncBufReadExt;
        let config =
            std::env::temp_dir().join(format!("helper-incoming-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&config).unwrap();
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_webauthn-helper"))
            .env("XDG_CONFIG_HOME", &config)
            .env("APPDATA", &config)
            .env("HOME", &config)
            .env(
                "DBUS_SYSTEM_BUS_ADDRESS",
                "unix:path=/nonexistent-helper-test-bus",
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let mut cli = Self {
            child,
            stdin,
            stdout,
            output: String::new(),
            url: String::new(),
            config,
        };
        cli.url = cli
            .until("Listening: ")
            .await
            .split_once("Listening: ")
            .unwrap()
            .1
            .into();
        assert_eq!(cli.output.lines().count(), 1);
        assert!(cli.output.contains(" INFO "));
        assert!(!cli.output.contains('\x1b'));
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(200),
            cli.stdout.next_line()
        )
        .await
        .is_err());
        cli
    }
    async fn until(&mut self, needle: &str) -> String {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let line = self
                    .stdout
                    .next_line()
                    .await
                    .unwrap()
                    .expect("CLI ended before expected output");
                self.output.push_str(&line);
                self.output.push('\n');
                if line.contains(needle) {
                    return line;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("Waiting for {needle}; output: {}", self.output))
    }
    async fn write(&mut self, text: &str) {
        use tokio::io::AsyncWriteExt;
        self.stdin
            .as_mut()
            .unwrap()
            .write_all(text.as_bytes())
            .await
            .unwrap();
    }
    async fn socket(
        &self,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        self.socket_with(
            "https://example.test:8443",
            "NeverLogIncomingToken0123456789ABCD",
        )
        .await
    }
    async fn socket_with(
        &self,
        origin: &str,
        token: &str,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
        let mut request = self.url.clone().into_client_request().unwrap();
        request
            .headers_mut()
            .insert("origin", origin.parse().unwrap());
        let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        socket
            .send(Message::Text(
                serde_json::json!({"type":"pair","token":token}).to_string(),
            ))
            .await
            .unwrap();
        socket
    }
    async fn finish(mut self) {
        self.stdin.take();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), self.child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(result.success());
        while let Some(line) = self.stdout.next_line().await.unwrap() {
            self.output.push_str(&line);
            self.output.push('\n');
        }
        assert!(!self.output.contains("NeverLogIncomingToken0123456789ABCD"));
        assert!(!self.output.contains("Approved:"));
        assert!(!self.output.contains("scanning=true"));
        std::fs::remove_dir_all(&self.config).unwrap();
    }
}
#[tokio::test]
async fn non_tty_confirmation_rejects_without_prompt_or_waiting_forever() {
    use futures_util::StreamExt;
    let mut cli = InteractiveCli::launch().await;
    let mut socket = cli.socket().await;
    cli.until("without an interactive terminal; rejecting this request.")
        .await;
    cli.until("Rejected: https://example.test:8443").await;
    let frame = tokio::time::timeout(std::time::Duration::from_secs(3), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(frame.into_text().unwrap().contains("closed"));
    assert!(!cli.output.contains("[ Approve ]"));
    assert!(!cli.output.contains("Approved:"));
    assert!(!cli.output.contains("Connected:"));
    cli.finish().await;
}
#[tokio::test]
async fn piped_yes_enter_and_fake_choice_cannot_approve() {
    use futures_util::StreamExt;
    let mut cli = InteractiveCli::launch().await;
    cli.write("yes\n\napprove\n").await;
    let mut socket = cli.socket().await;
    cli.until("Rejected: https://example.test:8443").await;
    let frame = tokio::time::timeout(std::time::Duration::from_secs(3), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(frame.into_text().unwrap().contains("closed"));
    assert!(!cli.output.contains("Approved:"));
    cli.finish().await;
}

#[test]
fn generated_help_and_version_exit_without_listener_or_errors() {
    for flag in ["--help", "-h", "--version", "-V"] {
        let (out, config) = run(&[flag], "");
        assert!(out.status.success());
        assert!(out.stderr.is_empty());
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(!text.contains("Listening:"));
        assert!(text.contains("webauthn-helper"));
        assert!(!text.contains("webauthn-helper-cli"));
        if flag.ends_with("help") || flag == "-h" {
            assert!(text.contains("Usage:"));
            assert!(text.contains("--listen <ADDRESS>"));
            assert!(text.contains("--help"));
            assert!(text.contains("--version"));
        } else {
            assert!(text.contains(env!("CARGO_PKG_VERSION")));
        }
        std::fs::remove_dir_all(config).unwrap();
    }
}
#[test]
fn invalid_arguments_report_errors_only_on_stderr() {
    for args in [
        vec!["--invalid"],
        vec!["--listen", "0.0.0.0:10233"],
        vec!["--listen", "127.0.0.1:80"],
    ] {
        let (out, config) = run(&args, "");
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("error:"));
        std::fs::remove_dir_all(config).unwrap();
    }
}
#[test]
fn new_process_ignores_all_saved_port_paths_even_when_invalid() {
    let config =
        std::env::temp_dir().join(format!("helper-ignored-port-{}", rand::random::<u64>()));
    // Preserve legacy configuration bytes while enforcing process-only preferences.
    for name in [
        "webauthn-helper",
        "webauthn-browser-companion",
        "auth-browser-companion",
    ] {
        let folder = config.join(name);
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("port"), "invalid legacy configuration").unwrap();
    }
    for _ in 0..2 {
        let out = Command::new(env!("CARGO_BIN_EXE_webauthn-helper"))
            .env("XDG_CONFIG_HOME", &config)
            .env("APPDATA", &config)
            .env("HOME", &config)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8(out.stdout).unwrap();
        let port: u16 = stdout.trim().rsplit(':').next().unwrap().parse().unwrap();
        assert!((10233..10253).contains(&port), "{stdout}");
    }
    for name in [
        "webauthn-helper",
        "webauthn-browser-companion",
        "auth-browser-companion",
    ] {
        assert_eq!(
            std::fs::read_to_string(config.join(name).join("port")).unwrap(),
            "invalid legacy configuration"
        );
    }
    std::fs::remove_dir_all(config).unwrap();
}

#[test]
fn private_worker_dispatch_preserves_clean_framing_without_runtime_initialization() {
    let folder = std::env::temp_dir().join(format!("helper-bootstrap-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&folder).unwrap();
    let binary = folder.join(format!("worker-fixture{}", std::env::consts::EXE_SUFFIX));
    let built = Command::new("rustc")
        .args(["--edition=2021", "--crate-name", "helper_bootstrap_fixture"])
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/worker_bootstrap.rs"),
        )
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let mut child = Command::new(&binary)
        .env("TOKIO_WORKER_THREADS", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"\0\0\0\x04FAKE")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"\0\0\0\x04FAKE");
    assert!(output.stderr.is_empty());
    std::fs::remove_dir_all(folder).unwrap();
}
