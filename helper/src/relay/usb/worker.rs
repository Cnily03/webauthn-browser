//! Child has no listener, network client, logger, consent state, or auto-reopen.

#[cfg(any(target_os = "linux", target_os = "windows", test))]
use super::{
    backend::Backend,
    wire::{self, Reply, Request},
};

#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub(super) fn serve(
    backend: &mut impl Backend,
    reader: &mut impl std::io::Read,
    writer: &mut impl std::io::Write,
) {
    // One discovery and one open per child. A protocol/backend failure ends the
    // worker rather than reopening a device or retrying an uncertain report.
    let (mut discovered, mut opened) = (false, false);
    while let Ok(request) = wire::read(reader) {
        let result = match request {
            Request::Discover if !discovered && !opened => {
                discovered = true;
                backend.devices().map(|devices| Reply::Devices { devices })
            }
            Request::Open { device } if discovered && !opened => {
                opened = true;
                backend.open(&device).map(|_| Reply::Opened)
            }
            Request::Exchange { report } if opened => backend
                .exchange(report)
                .map(|report| Reply::Report { report }),
            _ => Err(()),
        };
        let failed = result.is_err();
        if wire::write(writer, &result.unwrap_or(Reply::Failed)).is_err() || failed {
            break;
        }
    }
}

/// Called before CLI parsing or desktop/runtime initialization. This private mode
/// accepts bounded commands on inherited pipes only; errors contain no device data.
/// Never invoke this entry point in tests: use `serve` with a fake backend instead.
pub fn entry() -> bool {
    if std::env::args_os().nth(1).as_deref() != Some(std::ffi::OsStr::new("--internal-fido-worker"))
    {
        return false;
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    if let Ok(mut backend) = super::backend::Physical::new() {
        serve(
            &mut backend,
            &mut std::io::stdin().lock(),
            &mut std::io::stdout().lock(),
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::super::{
        backend,
        testing::device,
        wire::{self, Device},
    };
    use super::*;
    use fido_report_relay::Report;
    use std::io::Cursor;
    struct Fake {
        devices: Vec<Device>,
        opened: bool,
        opens: usize,
        writes: usize,
        disconnected: bool,
    }
    impl backend::Backend for Fake {
        fn devices(&mut self) -> Result<Vec<Device>, ()> {
            Ok(self.devices.clone())
        }
        fn open(&mut self, selected: &Device) -> Result<(), ()> {
            self.opens += 1;
            if self.opened || self.devices.iter().filter(|d| *d == selected).count() != 1 {
                return Err(());
            }
            self.opened = true;
            Ok(())
        }
        fn exchange(&mut self, outgoing: Option<Report>) -> Result<Option<Report>, ()> {
            if !self.opened || self.disconnected {
                return Err(());
            }
            self.writes += usize::from(outgoing.is_some());
            Ok(outgoing)
        }
    }
    fn fake() -> Fake {
        Fake {
            devices: vec![device(1)],
            opened: false,
            opens: 0,
            writes: 0,
            disconnected: false,
        }
    }
    fn execute(backend: &mut Fake, requests: &[Request]) -> Vec<Reply> {
        let mut input = Vec::new();
        for request in requests {
            wire::write(&mut input, request).unwrap();
        }
        let mut output = Vec::new();
        serve(backend, &mut Cursor::new(input), &mut output);
        let mut reader = Cursor::new(output);
        let mut replies = vec![];
        while let Ok(reply) = wire::read(&mut reader) {
            replies.push(reply);
        }
        replies
    }
    #[test]
    fn worker_state_machine_opens_once_and_forwards_opaque_report() {
        let mut fake = fake();
        let replies = execute(
            &mut fake,
            &[
                Request::Discover,
                Request::Open { device: device(1) },
                Request::Exchange {
                    report: Some(Report::from_slice(&[0x5a; 64]).unwrap()),
                },
                Request::Open { device: device(1) },
                Request::Exchange { report: None },
            ],
        );
        assert_eq!(replies.len(), 4);
        assert!(
            matches!(&replies[2], Reply::Report { report: Some(report) } if report.bytes() == &[0x5a; 64])
        );
        assert!(matches!(replies[3], Reply::Failed));
        assert_eq!(fake.opens, 1);
        assert_eq!(fake.writes, 1);
    }

    #[test]
    fn selected_device_disappearance_has_no_fallback_or_write() {
        let mut fake = fake();
        fake.devices = vec![device(2)];
        let replies = execute(
            &mut fake,
            &[
                Request::Discover,
                Request::Open { device: device(1) },
                Request::Exchange {
                    report: Some(Report::from_slice(&[3; 64]).unwrap()),
                },
            ],
        );
        assert!(matches!(replies[1], Reply::Failed));
        assert_eq!(replies.len(), 2);
        assert_eq!(fake.writes, 0);
    }

    #[test]
    fn duplicate_identity_and_unplug_fail_closed() {
        let mut duplicate = fake();
        duplicate.devices.push(device(1));
        assert!(matches!(
            execute(
                &mut duplicate,
                &[Request::Discover, Request::Open { device: device(1) }]
            )[1],
            Reply::Failed
        ));
        let mut unplug = fake();
        unplug.disconnected = true;
        let replies = execute(
            &mut unplug,
            &[
                Request::Discover,
                Request::Open { device: device(1) },
                Request::Exchange { report: None },
                Request::Exchange { report: None },
            ],
        );
        assert_eq!(replies.len(), 3);
        assert!(matches!(replies[2], Reply::Failed));
    }

    #[test]
    fn reports_before_open_and_malformed_frames_do_not_reach_backend() {
        let mut fake = fake();
        assert!(matches!(
            execute(&mut fake, &[Request::Exchange { report: None }])[0],
            Reply::Failed
        ));
        let mut output = Vec::new();
        serve(&mut fake, &mut Cursor::new([255; 4]), &mut output);
        assert!(output.is_empty());
        assert_eq!(fake.opens, 0);
        assert_eq!(fake.writes, 0);
    }
}
