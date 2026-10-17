//! Incremental client RFB framing. Standbys may negotiate and request pixels,
//! but cannot inject input, clipboard contents or desktop geometry.
pub(crate) struct Filter {
    buffer: Vec<u8>,
    phase: u8,
}
impl Filter {
    pub(crate) fn new() -> Self {
        Self {
            buffer: Vec::new(),
            phase: 0,
        }
    }
    pub(crate) fn push(&mut self, bytes: &[u8], owner: bool) -> Result<(Vec<u8>, bool), ()> {
        if self.buffer.len() + bytes.len() > 4 * 1024 * 1024 {
            return Err(());
        }
        self.buffer.extend_from_slice(bytes);
        let mut output = Vec::new();
        let mut active = false;
        loop {
            let (size, input) = if self.phase == 0 {
                (12, false)
            } else if self.phase < 3 {
                (1, false)
            } else {
                let Some(kind) = self.buffer.first() else {
                    break;
                };
                match *kind {
                    0 => (20, false),
                    2 => {
                        if self.buffer.len() < 4 {
                            break;
                        }
                        (
                            4 + u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as usize * 4,
                            false,
                        )
                    }
                    3 => (10, false),
                    4 => (8, true),
                    5 => (6, true),
                    6 => {
                        if self.buffer.len() < 8 {
                            break;
                        }
                        let n = i32::from_be_bytes(self.buffer[4..8].try_into().unwrap())
                            .unsigned_abs() as usize;
                        (8 + n, true)
                    }
                    150 => (10, false),
                    248 => {
                        if self.buffer.len() < 9 {
                            break;
                        }
                        (9 + self.buffer[8] as usize, false)
                    }
                    251 => {
                        if self.buffer.len() < 8 {
                            break;
                        }
                        (8 + self.buffer[6] as usize * 16, true)
                    }
                    _ => return Err(()),
                }
            };
            if size > 4 * 1024 * 1024 {
                return Err(());
            }
            if self.buffer.len() < size {
                break;
            }
            let frame: Vec<_> = self.buffer.drain(..size).collect();
            if self.phase < 3 {
                self.phase += 1;
            }
            if frame.first() != Some(&251) && (!input || owner) {
                output.extend_from_slice(&frame);
                active |= input;
            }
        }
        Ok((output, active))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_input_is_removed_for_standby_without_counting_pixel_poll() {
        let mut f = Filter::new();
        assert_eq!(f.push(b"RFB 003.008\n\x01\x01", false).unwrap().0.len(), 14);
        assert!(f.push(&[4, 1, 0], false).unwrap().0.is_empty());
        assert!(f.push(&[0, 0, 0, 0, 65], false).unwrap().0.is_empty());
        let request = [3, 1, 0, 0, 0, 0, 0, 10, 0, 10];
        let (out, active) = f.push(&request, false).unwrap();
        assert_eq!(out, request);
        assert!(!active);
        assert!(f.push(&[4, 1, 0, 0, 0, 0, 0, 65], true).unwrap().1);
    }
    #[test]
    fn coalesced_geometry_and_keepalives_never_resize_or_extend_owner_activity() {
        let mut f = Filter::new();
        f.push(b"RFB 003.008\n\x01\x01", true).unwrap();
        let resize = [251, 0, 3, 32, 2, 88, 0, 0];
        let update = [3, 1, 0, 0, 0, 0, 0, 10, 0, 10];
        let mut bytes = resize.to_vec();
        bytes.extend_from_slice(&update);
        let (out, active) = f.push(&bytes, true).unwrap();
        assert_eq!(out, update);
        assert!(!active);
    }
    #[test]
    fn clipboard_length_overflow_and_unknown_client_messages_fail_closed() {
        let mut f = Filter::new();
        f.push(b"RFB 003.008\n\x01\x01", true).unwrap();
        assert!(f.push(&[6, 0, 0, 0, 0x80, 0, 0, 0], true).is_err());
        let mut f = Filter::new();
        f.push(b"RFB 003.008\n\x01\x01", false).unwrap();
        assert!(f.push(&[99], false).is_err());
    }
}
