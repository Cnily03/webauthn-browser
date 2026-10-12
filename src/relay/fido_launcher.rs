//! Private, opt-in supervisor control. Readiness is not a USB connection claim.
use fido_report_relay::{
    control::{self, ControlSocket, Frame, Opcode},
    endpoint_pair, packet, Endpoint,
};
use std::{
    io,
    os::fd::{AsFd, FromRawFd, OwnedFd},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::unix::AsyncFd,
    sync::{mpsc, oneshot, watch},
};

const OP_TIMEOUT: Duration = Duration::from_secs(2);
type Result<T> = std::result::Result<T, ()>;
type Reply = oneshot::Sender<Result<Frame>>;

pub(crate) struct Launcher {
    commands: Option<mpsc::Sender<Command>>,
    ready: watch::Receiver<bool>,
}
#[derive(Clone)]
pub(crate) struct Lease(Arc<LeaseInner>);
struct LeaseInner {
    key: Frame,
    commands: mpsc::Sender<Command>,
    canceled: watch::Receiver<bool>,
    cancel: watch::Sender<bool>,
}
impl Drop for LeaseInner {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
    }
}
impl Lease {
    pub(crate) fn cancel(&self) {
        self.0.cancel.send_replace(true);
    }
    pub(crate) fn live(&self) -> bool {
        !*self.0.canceled.borrow()
    }
    pub(crate) async fn activate(&self) -> Result<()> {
        self.request(None).await.map(|_| ())
    }
    pub(crate) async fn renew(&self, sequence: u64, deadline: Instant) -> Result<()> {
        self.request(Some((sequence, wire_deadline(deadline)?)))
            .await
            .map(|_| ())
    }
    async fn request(&self, renewal: Option<(u64, u64)>) -> Result<Frame> {
        if !self.live() {
            return Err(());
        }
        let (reply, response) = oneshot::channel();
        let command = match renewal {
            Some((sequence, deadline)) => Command::Renew {
                key: self.0.key.clone(),
                sequence,
                deadline,
                reply,
            },
            None => Command::Activate {
                key: self.0.key.clone(),
                reply,
            },
        };
        if self.0.commands.try_send(command).is_err() {
            self.cancel();
            return Err(());
        }
        let mut canceled = self.0.canceled.clone();
        let outcome = tokio::select! { biased;
            _ = canceled.changed() => Err(()),
            result = tokio::time::timeout(OP_TIMEOUT, response) => result.map_err(|_|()).and_then(|v|v.map_err(|_|())).and_then(|v|v),
        };
        if outcome.is_err() {
            self.cancel();
        }
        outcome
    }
}
pub(crate) struct Prepared {
    pub endpoint: Endpoint,
    pub lease: Lease,
    pub deadline: Instant,
}
struct CancelOnDrop(Option<watch::Sender<bool>>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(c) = &self.0 {
            c.send_replace(true);
        }
    }
}

enum Command {
    Prepare {
        fd: OwnedFd,
        mode: u64,
        deadline: u64,
        cancel: watch::Sender<bool>,
        canceled: watch::Receiver<bool>,
        reply: Reply,
    },
    Activate {
        key: Frame,
        reply: Reply,
    },
    Renew {
        key: Frame,
        sequence: u64,
        deadline: u64,
        reply: Reply,
    },
}
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Preparing,
    Prepared,
    Activating,
    Active,
    Renewing,
}
struct Pending {
    expected: Frame,
    reply: Reply,
    timeout: Instant,
}
struct Current {
    frame: Frame,
    phase: Phase,
    cancel: watch::Sender<bool>,
    canceled: watch::Receiver<bool>,
    pending: Option<Pending>,
}
impl Drop for Current {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
        if let Some(p) = self.pending.take() {
            let _ = p.reply.send(Err(()));
        }
    }
}
impl Launcher {
    pub(crate) fn disabled() -> Arc<Self> {
        let (_tx, ready) = watch::channel(false);
        Arc::new(Self {
            commands: None,
            ready,
        })
    }
    pub(crate) fn from_environment() -> Arc<Self> {
        if std::env::var("AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY").as_deref() != Ok("1") {
            return Self::disabled();
        }
        let imported = (|| -> io::Result<(ControlSocket, [u8; 16])> {
            let epoch = parse_epoch(
                &std::env::var("AUTH_BROWSER_FIDO_GATEWAY_EPOCH")
                    .map_err(|_| io::ErrorKind::InvalidInput)?,
            )?;
            let raw = std::env::var("AUTH_BROWSER_FIDO_CONTROL_FD")
                .map_err(|_| io::ErrorKind::InvalidInput)?;
            if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let fd: i32 = raw.parse().map_err(|_| io::ErrorKind::InvalidInput)?;
            if fd < 3 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if copy < 0 {
                return Err(io::Error::last_os_error());
            }
            let socket = ControlSocket::from_owned(unsafe { OwnedFd::from_raw_fd(copy) })?;
            // This exact descriptor was explicitly handed to this process by
            // the supervisor; keep one owning copy, not an invisible extra.
            drop(unsafe { OwnedFd::from_raw_fd(fd) });
            Ok((socket, epoch))
        })();
        match imported {
            Ok((socket, epoch)) => {
                Self::start(socket, epoch, false).unwrap_or_else(|_| Self::disabled())
            }
            Err(_) => {
                eprintln!(
                    "Experimental FIDO launcher unavailable: invalid private control endpoint"
                );
                Self::disabled()
            }
        }
    }
    pub(crate) fn available(&self) -> bool {
        self.commands.is_some() && *self.ready.borrow()
    }
    fn start(socket: ControlSocket, gateway: [u8; 16], simulation: bool) -> io::Result<Arc<Self>> {
        let socket = AsyncFd::new(socket)?;
        let (commands, receiver) = mpsc::channel(8);
        let (status, ready) = watch::channel(false);
        tokio::spawn(run(socket, gateway, simulation, receiver, status));
        Ok(Arc::new(Self {
            commands: Some(commands),
            ready,
        }))
    }
    #[cfg(test)]
    pub(crate) fn simulated(socket: ControlSocket, gateway: [u8; 16]) -> io::Result<Arc<Self>> {
        Self::start(socket, gateway, true)
    }
    pub(crate) async fn prepare(&self, mode: u64, deadline: Instant) -> Result<Prepared> {
        if !self.available() {
            return Err(());
        }
        let commands = self.commands.as_ref().ok_or(())?.clone();
        let (fd, socket) = packet::pair().map_err(|_| ())?;
        let (endpoint, bridge) = endpoint_pair();
        let (cancel, canceled) = watch::channel(false);
        let mut guard = CancelOnDrop(Some(cancel.clone()));
        let mut bridge_cancel = canceled.clone();
        let bridge_failed = cancel.clone();
        tokio::spawn(async move {
            tokio::select! { biased;
                _ = bridge_cancel.changed() => {},
                _ = packet::bridge(socket,bridge) => {},
            }
            bridge_failed.send_replace(true);
        });
        let (reply, response) = oneshot::channel();
        commands
            .try_send(Command::Prepare {
                fd,
                mode,
                deadline: wire_deadline(deadline)?,
                cancel,
                canceled: canceled.clone(),
                reply,
            })
            .map_err(|_| ())?;
        let key = tokio::time::timeout(OP_TIMEOUT, response)
            .await
            .map_err(|_| ())?
            .map_err(|_| ())??;
        let lease = Lease(Arc::new(LeaseInner {
            key,
            commands,
            canceled,
            cancel: guard.0.take().unwrap(),
        }));
        Ok(Prepared {
            endpoint,
            lease,
            deadline,
        })
    }
}
fn parse_epoch(value: &str) -> io::Result<[u8; 16]> {
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut result = [0; 16];
    for (i, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        result[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
            .map_err(|_| io::ErrorKind::InvalidInput)?;
    }
    if result == [0; 16] {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(result)
}
fn wire_deadline(deadline: Instant) -> Result<u64> {
    let now = control::monotonic_now_ns().map_err(|_| ())?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let duration = u64::try_from(remaining.as_nanos()).map_err(|_| ())?;
    let target = now.checked_add(duration).ok_or(())?;
    control::validate_deadline_at(target, now).map_err(|_| ())?;
    Ok(target)
}
fn identity(a: &Frame, b: &Frame) -> bool {
    a.gateway_epoch == b.gateway_epoch
        && a.browser_epoch == b.browser_epoch
        && a.attachment_id == b.attachment_id
        && a.device_generation == b.device_generation
        && a.mode_generation == b.mode_generation
}
fn scope(a: &Frame, b: &Frame) -> bool {
    a.gateway_epoch == b.gateway_epoch && a.browser_epoch == b.browser_epoch
}
fn expected(a: &Frame, b: &Frame) -> bool {
    identity(a, b)
        && a.deadline_ns == b.deadline_ns
        && a.lease_sequence == b.lease_sequence
        && a.opcode == b.opcode
}
fn send(
    socket: &AsyncFd<ControlSocket>,
    frame: &Frame,
    fd: Option<std::os::fd::BorrowedFd<'_>>,
) -> Result<()> {
    socket.get_ref().send(frame, fd).map_err(|_| ())
}
fn revoke(socket: &AsyncFd<ControlSocket>, current: &mut Option<Current>) -> Result<()> {
    if let Some(c) = current.take() {
        let mut frame = c.frame.clone();
        frame.opcode = Opcode::Revoke;
        frame.flags = 0;
        let result = send(socket, &frame, None);
        drop(c);
        result
    } else {
        Ok(())
    }
}
async fn receive(socket: &AsyncFd<ControlSocket>) -> io::Result<(Frame, Option<OwnedFd>)> {
    loop {
        let mut ready = socket.readable().await?;
        if let Ok(result) = ready.try_io(|inner| inner.get_ref().receive()) {
            return result;
        }
    }
}
async fn run(
    socket: AsyncFd<ControlSocket>,
    gateway: [u8; 16],
    simulation: bool,
    mut commands: mpsc::Receiver<Command>,
    status: watch::Sender<bool>,
) {
    let mut hello: Option<Frame> = None;
    let mut serial = 0u64;
    let mut current: Option<Current> = None;
    let mut interval = tokio::time::interval(Duration::from_millis(20));
    loop {
        tokio::select! { biased;
            _=interval.tick()=> {
                let now=match control::monotonic_now_ns(){Ok(v)=>v,Err(_)=>break};
                if current.as_ref().is_some_and(|c| *c.canceled.borrow() || now>=c.frame.deadline_ns || c.pending.as_ref().is_some_and(|p|p.timeout<=Instant::now() || p.reply.is_closed()))
                    && revoke(&socket,&mut current).is_err() {break;}
            },
            input=receive(&socket)=> {
                let (frame,fd)=match input {Ok(v)=>v,Err(_)=>break};
                if fd.is_some() {drop(fd);break;}
                if frame.gateway_epoch!=gateway {break;}
                if frame.flags & control::FLAG_SIMULATED != 0 && !simulation {break;}
                if frame.opcode==Opcode::Hello {
                    if revoke(&socket,&mut current).is_err(){break;}
                    status.send_replace(false); hello=Some(frame); continue;
                }
                let Some(h)=hello.as_ref() else {break};
                if !scope(h,&frame) {continue;}
                if frame.opcode==Opcode::Ready { status.send_replace(true);continue; }
                if frame.opcode==Opcode::Unavailable {status.send_replace(false); if revoke(&socket,&mut current).is_err(){break;} continue;}
                let Some(c)=current.as_mut() else {
                    if frame.device_generation<=serial {continue;} break;
                };
                if !identity(&c.frame,&frame) {if frame.device_generation<c.frame.device_generation{continue;}break;}
                if matches!(frame.opcode,Opcode::Revoke|Opcode::Revoked) {drop(current.take());continue;}
                if *c.canceled.borrow() || control::monotonic_now_ns().map_or(true,|n|n>=c.frame.deadline_ns) {if revoke(&socket,&mut current).is_err(){break;}continue;}
                let Some(p)=c.pending.as_ref() else {break};
                if !expected(&p.expected,&frame){break;}
                let p=c.pending.take().unwrap();
                c.phase=match frame.opcode {Opcode::Prepared=>Phase::Prepared,Opcode::Active|Opcode::Renewed=>Phase::Active,_=>break};
                c.frame=frame.clone();
                if p.reply.send(Ok(frame)).is_err() && revoke(&socket,&mut current).is_err(){break;}
            },
            command=commands.recv()=> {
                let Some(command)=command else {break};
                match command {
                    Command::Prepare{fd,mode,deadline,cancel,canceled,reply}=> {
                        if !*status.borrow() || current.is_some() || control::bounded_deadline(deadline).is_err() || mode==0 || *canceled.borrow() {let _=reply.send(Err(()));continue;}
                        let Some(h)=hello.as_ref() else {let _=reply.send(Err(()));continue;};
                        let Some(next)=serial.checked_add(1) else {break}; serial=next;
                        let mut frame=h.clone(); frame.opcode=Opcode::Prepare;frame.flags=0;
                        frame.attachment_id = *uuid::Uuid::new_v4().as_bytes();frame.device_generation=serial;frame.mode_generation=mode;frame.deadline_ns=deadline;
                        if send(&socket,&frame,Some(fd.as_fd())).is_err(){break;}
                        drop(fd);
                        let mut response=frame.clone();response.opcode=Opcode::Prepared;
                        current=Some(Current{frame,phase:Phase::Preparing,cancel,canceled,pending:Some(Pending{expected:response,reply,timeout:Instant::now()+OP_TIMEOUT})});
                    },
                    Command::Activate{key,reply}=> {
                        let Some(c)=current.as_mut().filter(|c|identity(&c.frame,&key) && c.phase==Phase::Prepared && c.pending.is_none() && !*c.canceled.borrow()) else {let _=reply.send(Err(()));continue;};
                        if control::monotonic_now_ns().map_or(true,|n|n>=c.frame.deadline_ns) {let _=reply.send(Err(()));if revoke(&socket,&mut current).is_err(){break;}continue;}
                        let mut frame=c.frame.clone();frame.opcode=Opcode::Activate;frame.flags=0;
                        if send(&socket,&frame,None).is_err(){break;}
                        frame.opcode=Opcode::Active;c.phase=Phase::Activating;
                        c.pending=Some(Pending{expected:frame,reply,timeout:Instant::now()+OP_TIMEOUT});
                    },
                    Command::Renew{key,sequence,deadline,reply}=> {
                        let Some(c)=current.as_mut().filter(|c|identity(&c.frame,&key) && c.phase==Phase::Active && c.pending.is_none() && !*c.canceled.borrow()) else {let _=reply.send(Err(()));continue;};
                        let valid=control::monotonic_now_ns().is_ok_and(|n|n<c.frame.deadline_ns && control::validate_deadline_at(deadline,n).is_ok())
                            && sequence==c.frame.lease_sequence.saturating_add(1) && sequence>c.frame.lease_sequence && deadline>c.frame.deadline_ns;
                        if !valid {let _=reply.send(Err(()));if revoke(&socket,&mut current).is_err(){break;}continue;}
                        let mut frame=c.frame.clone();frame.opcode=Opcode::Renew;frame.flags=0;frame.lease_sequence=sequence;frame.deadline_ns=deadline;
                        if send(&socket,&frame,None).is_err(){break;}
                        frame.opcode=Opcode::Renewed;c.phase=Phase::Renewing;
                        c.pending=Some(Pending{expected:frame,reply,timeout:Instant::now()+OP_TIMEOUT});
                    },
                }
            },
        }
    }
    status.send_replace(false);
    let _ = revoke(&socket, &mut current);
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido_report_relay::{RelayError, Report};
    use std::future::Future;
    use tokio::task::JoinHandle;

    // These are protocol simulations over real anonymous Linux packet sockets.
    // FLAG_SIMULATED is always retained on positive fake-monitor responses. No
    // Chromium, authenticator device, listener, or external network is involved.
    const GATEWAY: [u8; 16] = [0x31; 16];
    const BROWSER: [u8; 16] = [0x42; 16];
    const TEST_WAIT: Duration = Duration::from_secs(4);

    struct Peer {
        socket: AsyncFd<ControlSocket>,
        hello: Frame,
    }

    impl Peer {
        fn new(simulation: bool) -> (Arc<Launcher>, Self) {
            let (client, peer) = ControlSocket::pair().unwrap();
            let launcher = Launcher::start(client, GATEWAY, simulation).unwrap();
            let peer = Self {
                socket: AsyncFd::new(peer).unwrap(),
                hello: Frame {
                    opcode: Opcode::Hello,
                    flags: 0,
                    gateway_epoch: GATEWAY,
                    browser_epoch: BROWSER,
                    attachment_id: [0; 16],
                    device_generation: 0,
                    mode_generation: 0,
                    deadline_ns: 0,
                    lease_sequence: 0,
                },
            };
            (launcher, peer)
        }

        fn send(&self, frame: &Frame) {
            self.socket.get_ref().send(frame, None).unwrap();
        }

        fn reply(&self, request: &Frame, opcode: Opcode) -> Frame {
            let mut response = request.clone();
            response.opcode = opcode;
            response.flags = match opcode {
                Opcode::Ready | Opcode::Prepared | Opcode::Active | Opcode::Renewed => {
                    control::FLAG_GENUINE_MONITOR | control::FLAG_SIMULATED
                }
                Opcode::Unavailable => control::FLAG_SIMULATED,
                _ => 0,
            };
            self.send(&response);
            response
        }

        async fn receive(&self) -> (Frame, Option<OwnedFd>) {
            within(receive(&self.socket)).await.unwrap()
        }

        async fn expect(&self, opcode: Opcode) -> Frame {
            let (frame, fd) = self.receive().await;
            assert_eq!(frame.opcode, opcode);
            assert_eq!(frame.flags, 0);
            assert!(
                fd.is_none(),
                "Only Prepare may transfer a report descriptor"
            );
            frame
        }

        async fn quiet(&self) {
            assert!(
                tokio::time::timeout(Duration::from_millis(80), receive(&self.socket))
                    .await
                    .is_err(),
                "Unexpected control traffic or connection closure"
            );
        }

        async fn closed(&self) {
            assert!(within(receive(&self.socket)).await.is_err());
        }
    }

    async fn within<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(TEST_WAIT, future)
            .await
            .expect("Simulated launcher operation did not settle")
    }

    async fn eventually(mut condition: impl FnMut() -> bool) {
        within(async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await;
    }

    async fn ready_peer() -> (Arc<Launcher>, Peer) {
        let (launcher, peer) = Peer::new(true);
        assert!(!launcher.available());
        peer.send(&peer.hello);
        peer.reply(&peer.hello, Opcode::Ready);
        eventually(|| launcher.available()).await;
        (launcher, peer)
    }

    fn begin_prepare(
        launcher: &Arc<Launcher>,
        mode: u64,
        deadline: Instant,
    ) -> JoinHandle<Result<Prepared>> {
        let launcher = launcher.clone();
        tokio::spawn(async move { launcher.prepare(mode, deadline).await })
    }

    async fn prepared(
        launcher: &Arc<Launcher>,
        peer: &Peer,
        mode: u64,
        deadline: Instant,
    ) -> (Prepared, Frame, AsyncFd<OwnedFd>) {
        let pending = begin_prepare(launcher, mode, deadline);
        let (request, fd) = peer.receive().await;
        assert_eq!(request.opcode, Opcode::Prepare);
        assert_eq!(request.flags, 0);
        assert_eq!(request.gateway_epoch, peer.hello.gateway_epoch);
        assert_eq!(request.browser_epoch, peer.hello.browser_epoch);
        assert_eq!(request.mode_generation, mode);
        assert_eq!(request.lease_sequence, 0);
        assert_ne!(request.attachment_id, [0; 16]);
        let reports = AsyncFd::new(fd.expect("Prepare must transfer one report endpoint")).unwrap();
        peer.reply(&request, Opcode::Prepared);
        let prepared = within(pending).await.unwrap().unwrap();
        assert_eq!(prepared.deadline, deadline);
        assert!(prepared.lease.live());
        (prepared, request, reports)
    }

    async fn activate(peer: &Peer, prepared: &Prepared, key: &Frame) {
        let lease = prepared.lease.clone();
        let pending = tokio::spawn(async move { lease.activate().await });
        let request = peer.expect(Opcode::Activate).await;
        assert!(identity(&request, key));
        assert_eq!(request.deadline_ns, key.deadline_ns);
        assert_eq!(request.lease_sequence, 0);
        peer.reply(&request, Opcode::Active);
        assert!(within(pending).await.unwrap().is_ok());
    }

    async fn assert_revoked(peer: &Peer, prepared: &mut Prepared, key: &Frame) -> Frame {
        let revoke = peer.expect(Opcode::Revoke).await;
        assert!(identity(&revoke, key));
        eventually(|| !prepared.lease.live() && prepared.endpoint.is_closed()).await;
        assert_eq!(
            within(prepared.endpoint.receive()).await.err(),
            Some(RelayError::Closed)
        );
        revoke
    }

    #[tokio::test]
    async fn disabled_unready_and_invalid_prepare_do_not_transfer_a_descriptor() {
        let disabled = Launcher::disabled();
        assert!(!disabled.available());
        assert!(disabled
            .prepare(1, Instant::now() + Duration::from_secs(1))
            .await
            .is_err());

        let (launcher, peer) = Peer::new(true);
        assert!(launcher
            .prepare(1, Instant::now() + Duration::from_secs(1))
            .await
            .is_err());
        peer.quiet().await;
        peer.send(&peer.hello);
        peer.reply(&peer.hello, Opcode::Ready);
        eventually(|| launcher.available()).await;
        assert!(launcher
            .prepare(0, Instant::now() + Duration::from_secs(1))
            .await
            .is_err());
        assert!(launcher
            .prepare(1, Instant::now() - Duration::from_secs(1))
            .await
            .is_err());
        assert!(launcher
            .prepare(1, Instant::now() + Duration::from_secs(31))
            .await
            .is_err());
        peer.quiet().await;
    }

    #[tokio::test]
    async fn production_launcher_rejects_simulated_monitor_readiness() {
        let (launcher, peer) = Peer::new(false);
        peer.send(&peer.hello);
        peer.reply(&peer.hello, Opcode::Ready);
        peer.closed().await;
        assert!(!launcher.available());
        assert!(launcher
            .prepare(1, Instant::now() + Duration::from_secs(1))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn production_launcher_rejects_simulated_prepared_even_after_genuine_ready() {
        let (launcher, peer) = Peer::new(false);
        peer.send(&peer.hello);
        let mut ready = peer.hello.clone();
        ready.opcode = Opcode::Ready;
        ready.flags = control::FLAG_GENUINE_MONITOR;
        peer.send(&ready);
        eventually(|| launcher.available()).await;
        let pending = begin_prepare(&launcher, 1, Instant::now() + Duration::from_secs(5));
        let (request, fd) = peer.receive().await;
        assert_eq!(request.opcode, Opcode::Prepare);
        let reports = AsyncFd::new(fd.unwrap()).unwrap();
        peer.reply(&request, Opcode::Prepared);
        assert!(within(pending).await.unwrap().is_err());
        let revoke = peer.expect(Opcode::Revoke).await;
        assert!(identity(&request, &revoke));
        peer.closed().await;
        assert!(!launcher.available());
        assert!(within(packet::receive(&reports)).await.is_err());
    }

    #[tokio::test]
    async fn repeated_generations_roundtrip_opaque_reports_and_confirm_renewals() {
        let (launcher, peer) = ready_peer().await;
        let mut previous: Option<Frame> = None;
        for mode in [3, 4, 9] {
            let (mut attachment, key, reports) = prepared(
                &launcher,
                &peer,
                mode,
                Instant::now() + Duration::from_secs(5),
            )
            .await;
            assert_eq!(
                key.device_generation,
                previous.as_ref().map_or(1, |old| old.device_generation + 1)
            );
            if let Some(old) = &previous {
                assert_ne!(key.attachment_id, old.attachment_id);
                // An old generation's late completion must not cancel the new one.
                peer.reply(old, Opcode::Prepared);
                peer.reply(old, Opcode::Active);
            }
            activate(&peer, &attachment, &key).await;

            let to_browser =
                Report::from_slice(&std::array::from_fn::<_, 64, _>(|i| i as u8)).unwrap();
            attachment.endpoint.send(to_browser.clone()).unwrap();
            assert!(within(packet::receive(&reports)).await.unwrap() == to_browser);
            let to_helper =
                Report::from_slice(&std::array::from_fn::<_, 64, _>(|i| 255 - i as u8)).unwrap();
            within(packet::send(&reports, &to_helper)).await.unwrap();
            assert!(within(attachment.endpoint.receive()).await.unwrap() == to_helper);

            let lease = attachment.lease.clone();
            let pending = tokio::spawn(async move {
                lease
                    .renew(1, Instant::now() + Duration::from_secs(8))
                    .await
            });
            let renewal = peer.expect(Opcode::Renew).await;
            assert!(identity(&renewal, &key));
            assert_eq!(renewal.lease_sequence, 1);
            assert!(renewal.deadline_ns > key.deadline_ns);
            peer.reply(&renewal, Opcode::Renewed);
            assert!(within(pending).await.unwrap().is_ok());
            attachment.lease.cancel();
            let revoke = assert_revoked(&peer, &mut attachment, &key).await;
            assert_eq!(revoke.lease_sequence, 1);
            assert_eq!(revoke.deadline_ns, renewal.deadline_ns);
            assert!(within(packet::receive(&reports)).await.is_err());
            assert!(launcher.available());
            previous = Some(key);
        }
    }

    #[tokio::test]
    async fn second_prepare_is_rejected_without_disturbing_current_attachment() {
        let (launcher, peer) = ready_peer().await;
        let (mut attachment, key, _reports) =
            prepared(&launcher, &peer, 1, Instant::now() + Duration::from_secs(5)).await;
        assert!(launcher
            .prepare(2, Instant::now() + Duration::from_secs(5))
            .await
            .is_err());
        peer.quiet().await;
        assert!(attachment.lease.live());
        activate(&peer, &attachment, &key).await;
        attachment.lease.cancel();
        assert_revoked(&peer, &mut attachment, &key).await;
    }

    #[tokio::test]
    async fn dropping_prepare_future_revokes_descriptor_and_ignores_late_prepared() {
        let (launcher, peer) = ready_peer().await;
        let pending = begin_prepare(&launcher, 1, Instant::now() + Duration::from_secs(5));
        let (key, fd) = peer.receive().await;
        assert_eq!(key.opcode, Opcode::Prepare);
        let reports = AsyncFd::new(fd.unwrap()).unwrap();
        pending.abort();
        assert!(within(pending).await.err().unwrap().is_cancelled());
        let revoke = peer.expect(Opcode::Revoke).await;
        assert!(identity(&revoke, &key));
        assert!(within(packet::receive(&reports)).await.is_err());
        peer.reply(&key, Opcode::Prepared);
        peer.quiet().await;
        let (mut next, next_key, _reports) =
            prepared(&launcher, &peer, 2, Instant::now() + Duration::from_secs(5)).await;
        assert!(next_key.device_generation > key.device_generation);
        next.lease.cancel();
        assert_revoked(&peer, &mut next, &next_key).await;
    }

    #[tokio::test]
    async fn cancellation_during_activation_rejects_late_active() {
        let (launcher, peer) = ready_peer().await;
        let (mut attachment, key, _reports) =
            prepared(&launcher, &peer, 1, Instant::now() + Duration::from_secs(5)).await;
        let lease = attachment.lease.clone();
        let pending = tokio::spawn(async move { lease.activate().await });
        let request = peer.expect(Opcode::Activate).await;
        attachment.lease.cancel();
        assert!(within(pending).await.unwrap().is_err());
        assert_revoked(&peer, &mut attachment, &key).await;
        peer.reply(&request, Opcode::Active);
        peer.quiet().await;
        assert!(!attachment.lease.live());
        assert!(attachment.lease.activate().await.is_err());
    }

    #[tokio::test]
    async fn cancellation_during_renewal_rejects_late_renewed() {
        let (launcher, peer) = ready_peer().await;
        let (mut attachment, key, _reports) =
            prepared(&launcher, &peer, 1, Instant::now() + Duration::from_secs(5)).await;
        activate(&peer, &attachment, &key).await;
        let lease = attachment.lease.clone();
        let pending = tokio::spawn(async move {
            lease
                .renew(1, Instant::now() + Duration::from_secs(8))
                .await
        });
        let renewal = peer.expect(Opcode::Renew).await;
        attachment.lease.cancel();
        assert!(within(pending).await.unwrap().is_err());
        let revoke = assert_revoked(&peer, &mut attachment, &key).await;
        assert_eq!(revoke.deadline_ns, key.deadline_ns);
        assert_eq!(revoke.lease_sequence, 0);
        peer.reply(&renewal, Opcode::Renewed);
        peer.quiet().await;
        assert!(attachment
            .lease
            .renew(2, Instant::now() + Duration::from_secs(9))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn dropping_renewal_future_cancels_the_live_lease() {
        let (launcher, peer) = ready_peer().await;
        let (mut attachment, key, _reports) =
            prepared(&launcher, &peer, 1, Instant::now() + Duration::from_secs(5)).await;
        activate(&peer, &attachment, &key).await;
        let lease = attachment.lease.clone();
        let pending = tokio::spawn(async move {
            lease
                .renew(1, Instant::now() + Duration::from_secs(8))
                .await
        });
        peer.expect(Opcode::Renew).await;
        pending.abort();
        assert!(within(pending).await.err().unwrap().is_cancelled());
        assert_revoked(&peer, &mut attachment, &key).await;
        peer.quiet().await;
    }

    #[tokio::test]
    async fn pending_renewal_does_not_extend_the_confirmed_expiry() {
        let (launcher, peer) = ready_peer().await;
        let (mut attachment, key, _reports) = prepared(
            &launcher,
            &peer,
            1,
            Instant::now() + Duration::from_millis(250),
        )
        .await;
        activate(&peer, &attachment, &key).await;
        let lease = attachment.lease.clone();
        let pending = tokio::spawn(async move {
            lease
                .renew(1, Instant::now() + Duration::from_secs(8))
                .await
        });
        let renewal = peer.expect(Opcode::Renew).await;
        let revoke = assert_revoked(&peer, &mut attachment, &key).await;
        assert_eq!(revoke.deadline_ns, key.deadline_ns);
        assert_eq!(revoke.lease_sequence, 0);
        assert!(within(pending).await.unwrap().is_err());
        peer.reply(&renewal, Opcode::Renewed);
        peer.quiet().await;
    }

    #[tokio::test]
    async fn active_lease_expires_without_renewal_or_report_replay() {
        let (launcher, peer) = ready_peer().await;
        let (mut attachment, key, reports) = prepared(
            &launcher,
            &peer,
            1,
            Instant::now() + Duration::from_millis(250),
        )
        .await;
        activate(&peer, &attachment, &key).await;
        let revoke = assert_revoked(&peer, &mut attachment, &key).await;
        assert_eq!(revoke.deadline_ns, key.deadline_ns);
        assert!(within(packet::receive(&reports)).await.is_err());
        peer.quiet().await;
    }

    #[tokio::test]
    async fn prepare_timeout_revokes_once_and_never_retries_uncertain_prepare() {
        let (launcher, peer) = ready_peer().await;
        let pending = begin_prepare(&launcher, 1, Instant::now() + Duration::from_secs(10));
        let (key, fd) = peer.receive().await;
        assert_eq!(key.opcode, Opcode::Prepare);
        let reports = AsyncFd::new(fd.unwrap()).unwrap();
        assert!(within(pending).await.unwrap().is_err());
        let revoke = peer.expect(Opcode::Revoke).await;
        assert!(identity(&revoke, &key));
        assert!(within(packet::receive(&reports)).await.is_err());
        peer.reply(&key, Opcode::Prepared);
        peer.quiet().await;
        assert!(launcher.available());
    }

    #[tokio::test]
    async fn activation_timeout_revokes_once_and_never_retries_uncertain_activation() {
        let (launcher, peer) = ready_peer().await;
        let (mut attachment, key, _reports) = prepared(
            &launcher,
            &peer,
            1,
            Instant::now() + Duration::from_secs(10),
        )
        .await;
        let lease = attachment.lease.clone();
        let pending = tokio::spawn(async move { lease.activate().await });
        let activation = peer.expect(Opcode::Activate).await;
        assert!(within(pending).await.unwrap().is_err());
        assert_revoked(&peer, &mut attachment, &key).await;
        peer.reply(&activation, Opcode::Active);
        peer.quiet().await;
    }

    #[tokio::test]
    async fn renewal_timeout_revokes_once_and_never_retries_uncertain_renewal() {
        let (launcher, peer) = ready_peer().await;
        let (mut attachment, key, _reports) = prepared(
            &launcher,
            &peer,
            1,
            Instant::now() + Duration::from_secs(10),
        )
        .await;
        activate(&peer, &attachment, &key).await;
        let lease = attachment.lease.clone();
        let pending = tokio::spawn(async move {
            lease
                .renew(1, Instant::now() + Duration::from_secs(15))
                .await
        });
        let renewal = peer.expect(Opcode::Renew).await;
        assert!(within(pending).await.unwrap().is_err());
        assert_revoked(&peer, &mut attachment, &key).await;
        peer.reply(&renewal, Opcode::Renewed);
        peer.quiet().await;
    }

    #[tokio::test]
    async fn wrong_attachment_identity_fails_closed() {
        let (launcher, peer) = ready_peer().await;
        let pending = begin_prepare(&launcher, 1, Instant::now() + Duration::from_secs(5));
        let (key, _reports) = peer.receive().await;
        let mut wrong = key.clone();
        wrong.attachment_id = [0x53; 16];
        peer.reply(&wrong, Opcode::Prepared);
        assert!(within(pending).await.unwrap().is_err());
        let revoke = peer.expect(Opcode::Revoke).await;
        assert!(identity(&revoke, &key));
        peer.closed().await;
        assert!(!launcher.available());
    }

    #[tokio::test]
    async fn new_browser_epoch_revokes_old_lease_and_ignores_old_ready_and_completion() {
        let (launcher, mut peer) = ready_peer().await;
        let (mut attachment, key, _reports) =
            prepared(&launcher, &peer, 1, Instant::now() + Duration::from_secs(5)).await;
        activate(&peer, &attachment, &key).await;
        let old_hello = peer.hello.clone();
        peer.hello.browser_epoch = [0x64; 16];
        peer.send(&peer.hello);
        assert_revoked(&peer, &mut attachment, &key).await;
        assert!(!launcher.available());
        peer.reply(&old_hello, Opcode::Ready);
        peer.reply(&key, Opcode::Active);
        peer.quiet().await;
        assert!(!launcher.available());
        peer.reply(&peer.hello, Opcode::Ready);
        eventually(|| launcher.available()).await;
        let (mut next, next_key, _reports) =
            prepared(&launcher, &peer, 2, Instant::now() + Duration::from_secs(5)).await;
        assert!(next_key.device_generation > key.device_generation);
        assert_ne!(next_key.browser_epoch, key.browser_epoch);
        next.lease.cancel();
        assert_revoked(&peer, &mut next, &next_key).await;
    }

    #[tokio::test]
    async fn unavailable_revokes_current_attachment_until_another_ready() {
        let (launcher, peer) = ready_peer().await;
        let (mut attachment, key, _reports) =
            prepared(&launcher, &peer, 1, Instant::now() + Duration::from_secs(5)).await;
        activate(&peer, &attachment, &key).await;
        peer.reply(&peer.hello, Opcode::Unavailable);
        assert_revoked(&peer, &mut attachment, &key).await;
        assert!(!launcher.available());
        assert!(launcher
            .prepare(2, Instant::now() + Duration::from_secs(5))
            .await
            .is_err());
        peer.reply(&peer.hello, Opcode::Ready);
        eventually(|| launcher.available()).await;
    }

    #[tokio::test]
    async fn control_eof_during_prepare_fails_pending_call_and_closes_report_endpoint() {
        let (launcher, peer) = ready_peer().await;
        let pending = begin_prepare(&launcher, 1, Instant::now() + Duration::from_secs(5));
        let (request, fd) = peer.receive().await;
        assert_eq!(request.opcode, Opcode::Prepare);
        let reports = AsyncFd::new(fd.unwrap()).unwrap();
        drop(peer);
        assert!(within(pending).await.unwrap().is_err());
        eventually(|| !launcher.available()).await;
        assert!(within(packet::receive(&reports)).await.is_err());
    }

    #[tokio::test]
    async fn control_eof_during_renewal_cancels_lease_and_pending_call() {
        let (launcher, peer) = ready_peer().await;
        let (mut attachment, key, reports) =
            prepared(&launcher, &peer, 1, Instant::now() + Duration::from_secs(5)).await;
        activate(&peer, &attachment, &key).await;
        let lease = attachment.lease.clone();
        let pending = tokio::spawn(async move {
            lease
                .renew(1, Instant::now() + Duration::from_secs(8))
                .await
        });
        peer.expect(Opcode::Renew).await;
        drop(peer);
        assert!(within(pending).await.unwrap().is_err());
        eventually(|| {
            !launcher.available() && !attachment.lease.live() && attachment.endpoint.is_closed()
        })
        .await;
        assert_eq!(
            within(attachment.endpoint.receive()).await.err(),
            Some(RelayError::Closed)
        );
        assert!(within(packet::receive(&reports)).await.is_err());
        assert!(attachment.lease.activate().await.is_err());
    }

    #[test]
    fn epoch_parser_requires_exact_nonzero_hex_identity() {
        assert_eq!(
            parse_epoch("31313131313131313131313131313131").unwrap(),
            GATEWAY
        );
        assert_eq!(
            parse_epoch("AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa").unwrap(),
            [0xaa; 16]
        );
        for invalid in [
            "",
            "0",
            "00000000000000000000000000000000",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            " 31313131313131313131313131313131",
            "31313131313131313131313131313131 ",
        ] {
            assert!(parse_epoch(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn report_peer_eof_revokes_lease_without_waiting_for_an_http_exchange() {
        let (launcher, peer) = ready_peer().await;
        let (mut attachment, key, reports) = prepared(
            &launcher,
            &peer,
            1,
            Instant::now() + Duration::from_secs(10),
        )
        .await;
        activate(&peer, &attachment, &key).await;
        drop(reports);
        assert_revoked(&peer, &mut attachment, &key).await;
        assert!(launcher.available());
        peer.quiet().await;
    }

    #[tokio::test]
    async fn dropping_the_last_lease_clone_revokes_and_closes_reports() {
        let (launcher, peer) = ready_peer().await;
        let (attachment, key, reports) =
            prepared(&launcher, &peer, 1, Instant::now() + Duration::from_secs(5)).await;
        activate(&peer, &attachment, &key).await;
        let Prepared {
            mut endpoint,
            lease,
            ..
        } = attachment;
        let last = lease.clone();
        drop(lease);
        peer.quiet().await;
        assert!(last.live());
        drop(last);
        let revoke = peer.expect(Opcode::Revoke).await;
        assert!(identity(&revoke, &key));
        assert_eq!(
            within(endpoint.receive()).await.err(),
            Some(RelayError::Closed)
        );
        assert!(within(packet::receive(&reports)).await.is_err());
    }

    #[tokio::test]
    async fn nonconsecutive_renewal_revokes_instead_of_transmitting_a_new_grant() {
        let (launcher, peer) = ready_peer().await;
        let (mut attachment, key, _reports) =
            prepared(&launcher, &peer, 1, Instant::now() + Duration::from_secs(5)).await;
        activate(&peer, &attachment, &key).await;
        assert!(attachment
            .lease
            .renew(2, Instant::now() + Duration::from_secs(8))
            .await
            .is_err());
        assert_revoked(&peer, &mut attachment, &key).await;
        peer.quiet().await;
    }

    #[tokio::test]
    async fn malformed_report_packet_revokes_only_the_matching_generation() {
        use std::os::fd::AsRawFd;

        let (launcher, peer) = ready_peer().await;
        for size in [63usize, 65] {
            let (mut attachment, key, reports) = prepared(
                &launcher,
                &peer,
                size as u64,
                Instant::now() + Duration::from_secs(10),
            )
            .await;
            activate(&peer, &attachment, &key).await;
            let malformed = vec![0u8; size];
            let sent = unsafe {
                libc::send(
                    reports.get_ref().as_raw_fd(),
                    malformed.as_ptr().cast(),
                    malformed.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            assert_eq!(sent, size as isize);
            assert_revoked(&peer, &mut attachment, &key).await;
            assert!(within(packet::receive(&reports)).await.is_err());
            assert!(launcher.available());
        }
    }
}
