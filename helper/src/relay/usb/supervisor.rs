//! Killable child lifetime. All pipe operations and process reaping are bounded.
use super::wire::{Reply, Request, MAX_FRAME};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout},
    sync::watch,
};

pub(super) struct ChildIo {
    child: Child,
    _lifetime: super::lifetime::Guard,
    input: ChildStdin,
    output: ChildStdout,
}
impl ChildIo {
    pub fn start() -> Result<Self, ()> {
        let mut command = tokio::process::Command::new(std::env::current_exe().map_err(|_| ())?);
        command.arg("--internal-fido-worker");
        Self::spawn(&mut command)
    }
    pub(super) fn spawn(command: &mut tokio::process::Command) -> Result<Self, ()> {
        // No inherited console, log stream or network endpoint. This is process
        // isolation for cancellation, not an OS security sandbox.
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let lifetime = super::lifetime::prepare(command)?;
        let mut child = command.spawn().map_err(|_| ())?;
        if lifetime.attach(&child).is_err() {
            // No Discover/Open has been issued, so this child owns no device.
            let _ = child.start_kill();
            return Err(());
        }
        Ok(Self {
            input: child.stdin.take().ok_or(())?,
            output: child.stdout.take().ok_or(())?,
            child,
            _lifetime: lifetime,
        })
    }
    pub async fn request(
        &mut self,
        request: Request,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<Reply, ()> {
        if *cancel.borrow() {
            return Err(());
        }
        tokio::select! {
            biased;
            _ = cancel.changed() => Err(()),
            result = tokio::time::timeout(Duration::from_secs(2), self.exchange(request)) => result.map_err(|_| ())?,
        }
    }
    async fn exchange(&mut self, request: Request) -> Result<Reply, ()> {
        let bytes = serde_json::to_vec(&request).map_err(|_| ())?;
        if bytes.len() > MAX_FRAME {
            return Err(());
        }
        self.input
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .map_err(|_| ())?;
        self.input.write_all(&bytes).await.map_err(|_| ())?;
        self.input.flush().await.map_err(|_| ())?;
        let size = self.output.read_u32().await.map_err(|_| ())? as usize;
        if size == 0 || size > MAX_FRAME {
            return Err(());
        }
        let mut bytes = vec![0; size];
        self.output.read_exact(&mut bytes).await.map_err(|_| ())?;
        serde_json::from_slice(&bytes).map_err(|_| ())
    }
    pub async fn stop(&mut self) -> bool {
        if self.child.try_wait().ok().flatten().is_some() {
            return true;
        }
        let _ = self.child.start_kill();
        matches!(
            tokio::time::timeout(Duration::from_millis(750), self.child.wait()).await,
            Ok(Ok(_))
        )
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn blocked_fake_worker_is_killed_on_cancel() {
        let mut command = tokio::process::Command::new("python3");
        command.args(["-c", "import time; time.sleep(60)"]);
        let mut child = ChildIo::spawn(&mut command).unwrap();
        let (tx, mut cancel) = watch::channel(false);
        {
            let request = child.request(Request::Discover, &mut cancel);
            tokio::pin!(request);
            tokio::select! { _ = &mut request => panic!("fake worker should block"), _ = tokio::time::sleep(Duration::from_millis(30)) => {} }
            tx.send_replace(true);
            assert!(request.await.is_err());
        }
        assert!(child.stop().await);
    }
    #[tokio::test]
    async fn oversized_fake_frame_fails_closed_and_reaps() {
        let mut command = tokio::process::Command::new("python3");
        command.args(["-c", "import sys,time; sys.stdout.buffer.write(b'\\xff'*4); sys.stdout.buffer.flush(); time.sleep(60)"]);
        let mut child = ChildIo::spawn(&mut command).unwrap();
        let (_tx, mut cancel) = watch::channel(false);
        assert!(child.request(Request::Discover, &mut cancel).await.is_err());
        assert!(child.stop().await);
    }

    #[cfg(target_os = "linux")]
    mod parent_death_tests {
        use super::*;
        // This test is also a subprocess fixture. It never invokes HIDAPI.
        #[test]
        fn fake_parent_fixture() {
            if std::env::var_os("WEBAUTHN_FAKE_PARENT_FIXTURE").is_none() {
                return;
            }
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let mut command = tokio::process::Command::new("python3");
                command.args(["-c", "import time; time.sleep(60)"]);
                let child = ChildIo::spawn(&mut command).unwrap();
                println!("FAKE_CHILD_PID={}", child.child.id().unwrap());
                use std::io::Write;
                std::io::stdout().flush().unwrap();
                std::future::pending::<()>().await;
            });
        }
        #[tokio::test]
        async fn abrupt_parent_death_kills_fake_device_worker() {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut parent = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    concat!(module_path!(), "::fake_parent_fixture")
                        .split_once("::")
                        .unwrap()
                        .1,
                    "--nocapture",
                ])
                .env("WEBAUTHN_FAKE_PARENT_FIXTURE", "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut lines = BufReader::new(parent.stdout.take().unwrap()).lines();
            let pid: u32 = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let line = lines.next_line().await.unwrap().unwrap();
                    if let Some((_, pid)) = line.split_once("FAKE_CHILD_PID=") {
                        break pid.trim().parse().unwrap();
                    }
                }
            })
            .await
            .unwrap();
            parent.kill().await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
                    if stat.as_ref().is_err()
                        || stat.as_ref().ok().is_some_and(|s| {
                            s.split_once(") ")
                                .is_some_and(|(_, tail)| tail.starts_with('Z'))
                        })
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
    }
}
