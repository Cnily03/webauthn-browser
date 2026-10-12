//! Only this module may call HIDAPI. Production calls run in the disposable child.

#[cfg(any(target_os = "linux", target_os = "windows"))]
use super::descriptor;
use super::wire::Device;
use fido_report_relay::Report;

pub(super) trait Backend {
    fn devices(&mut self) -> Result<Vec<Device>, ()>;
    fn open(&mut self, selected: &Device) -> Result<(), ()>;
    fn exchange(&mut self, outgoing: Option<Report>) -> Result<Option<Report>, ()>;
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(super) struct Physical {
    api: hidapi::HidApi,
    device: Option<hidapi::HidDevice>,
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
impl Physical {
    pub(super) fn new() -> Result<Self, ()> {
        hidapi::HidApi::disable_device_discovery();
        Ok(Self {
            api: hidapi::HidApi::new().map_err(|_| ())?,
            device: None,
        })
    }
    fn metadata(info: &hidapi::DeviceInfo) -> Option<Device> {
        if info.usage_page() != 0xf1d0
            || info.usage() != 1
            || !matches!(info.bus_type(), hidapi::BusType::Usb)
        {
            return None;
        }
        let device = Device {
            path: info.path().to_bytes().to_vec(),
            vendor: info.vendor_id(),
            product: info.product_id(),
            interface: info.interface_number(),
            serial: info.serial_number().map(str::to_owned),
        };
        device.valid().then_some(device)
    }
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
impl Backend for Physical {
    fn devices(&mut self) -> Result<Vec<Device>, ()> {
        self.api.refresh_devices().map_err(|_| ())?;
        let devices: Vec<_> = self
            .api
            .device_list()
            .filter_map(Self::metadata)
            .take(17)
            .collect();
        if devices.len() > 16
            || devices
                .iter()
                .enumerate()
                .any(|(n, d)| devices[..n].iter().any(|other| other.path == d.path))
        {
            return Err(());
        }
        Ok(devices)
    }
    fn open(&mut self, selected: &Device) -> Result<(), ()> {
        if self.device.is_some() || !selected.valid() {
            return Err(());
        }
        // Exact discovery identity must still exist. Never choose a replacement.
        let current = self.devices()?;
        if current.iter().filter(|d| *d == selected).count() != 1 {
            return Err(());
        }
        let path = std::ffi::CString::new(selected.path.clone()).map_err(|_| ())?;
        let device = self.api.open_path(&path).map_err(|_| ())?;
        if Self::metadata(&device.get_device_info().map_err(|_| ())?).as_ref() != Some(selected) {
            return Err(());
        }
        let mut bytes = [0u8; 4096];
        let count = device.get_report_descriptor(&mut bytes).map_err(|_| ())?;
        if count >= bytes.len() || !descriptor::validate(&bytes[..count]) {
            return Err(());
        }
        self.device = Some(device);
        Ok(())
    }
    fn exchange(&mut self, outgoing: Option<Report>) -> Result<Option<Report>, ()> {
        let device = self.device.as_ref().ok_or(())?;
        if let Some(report) = outgoing {
            let bytes = output(&report);
            if device.write(&bytes).map_err(|_| ())? != bytes.len() {
                return Err(());
            }
        }
        // Extra byte prevents silently accepting a numbered/oversized report.
        let mut bytes = [0u8; 65];
        let count = device.read_timeout(&mut bytes, 10).map_err(|_| ())?;
        input(&bytes[..count])
    }
}

// HIDAPI writes require a leading zero report ID even for an unnumbered device;
// that API framing byte is never part of the canonical 64-byte relay report.
pub(super) fn output(report: &Report) -> [u8; 65] {
    let mut bytes = [0u8; 65];
    bytes[1..].copy_from_slice(report.bytes());
    bytes
}
pub(super) fn input(bytes: &[u8]) -> Result<Option<Report>, ()> {
    if bytes.is_empty() {
        return Ok(None);
    }
    Report::from_slice(bytes).map(Some).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_id_framing_is_exact() {
        let report = Report::from_slice(&[0xa5; 64]).unwrap();
        let bytes = output(&report);
        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[1..], report.bytes());
        assert!(input(&[]).unwrap().is_none());
        assert!(input(&[1; 63]).is_err());
        assert!(input(&[0; 65]).is_err());
        assert!(input(&[1; 64]).unwrap().is_some());
    }
}
