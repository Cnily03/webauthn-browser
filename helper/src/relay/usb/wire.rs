//! Bounded private child pipe frames. No Debug for device identities or reports.
use fido_report_relay::Report;
use serde::{Deserialize, Serialize};
pub(super) const MAX_FRAME: usize = 16384;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Device {
    pub path: Vec<u8>,
    pub vendor: u16,
    pub product: u16,
    pub interface: i32,
    pub serial: Option<String>,
}
impl Device {
    pub fn valid(&self) -> bool {
        !self.path.is_empty()
            && self.path.len() <= 1024
            && !self.path.contains(&0)
            && self
                .serial
                .as_ref()
                .is_none_or(|serial| serial.len() <= 256)
    }
    pub fn label(&self) -> String {
        format!(
            "USB FIDO {:04x}:{:04x} interface {}",
            self.vendor, self.product, self.interface
        )
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Discover,
    Open { device: Device },
    Exchange { report: Option<Report> },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Reply {
    Devices { devices: Vec<Device> },
    Opened,
    Report { report: Option<Report> },
    Failed,
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub(super) fn read<T: serde::de::DeserializeOwned>(
    reader: &mut impl std::io::Read,
) -> Result<T, ()> {
    let mut size = [0; 4];
    reader.read_exact(&mut size).map_err(|_| ())?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(());
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes).map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}
#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub(super) fn write<T: Serialize>(writer: &mut impl std::io::Write, value: &T) -> Result<(), ()> {
    let bytes = serde_json::to_vec(value).map_err(|_| ())?;
    if bytes.len() > MAX_FRAME {
        return Err(());
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(|_| ())?;
    writer.write_all(&bytes).map_err(|_| ())?;
    writer.flush().map_err(|_| ())
}
