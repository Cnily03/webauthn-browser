//! Conservative initial FIDO-only, unnumbered, 64-byte descriptor profile.
//! Unsupported descriptors are rejected rather than guessed or rewritten.
pub(super) fn validate(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > 4096 {
        return false;
    }
    let (mut page, mut usage, mut size, mut count) = (0u32, None, 0u32, 0u32);
    let (mut min, mut max) = (None, None);
    let (mut collection, mut finished, mut input, mut output) = (false, false, false, false);
    let mut index = 0;
    while index < bytes.len() {
        let tag = bytes[index];
        index += 1;
        let length = match tag & 3 {
            3 => 4,
            n => n as usize,
        };
        if tag == 0xfe || index + length > bytes.len() {
            return false;
        }
        let mut raw = [0; 4];
        raw[..length].copy_from_slice(&bytes[index..index + length]);
        index += length;
        let value = u32::from_le_bytes(raw);
        match tag & 0xfc {
            0x04 if !finished => {
                if value != 0xf1d0 {
                    return false;
                }
                page = value;
            }
            0x08 if !finished => {
                if usage.replace(value).is_some() {
                    return false;
                }
            }
            0x14 if collection => min = Some(value),
            0x24 if collection => max = Some(value),
            0x74 if collection => size = value,
            0x94 if collection => count = value,
            0xa0 if !collection
                && !finished
                && page == 0xf1d0
                && usage.take() == Some(1)
                && value == 1 =>
            {
                collection = true
            }
            0x80 | 0x90
                if collection
                    && value == 2
                    && size == 8
                    && count == 64
                    && min == Some(0)
                    && max == Some(255) =>
            {
                let target = if tag & 0xfc == 0x80 {
                    &mut input
                } else {
                    &mut output
                };
                let expected = if tag & 0xfc == 0x80 { 0x20 } else { 0x21 };
                if *target || usage.take() != Some(expected) {
                    return false;
                }
                *target = true;
            }
            0xc0 if collection && length == 0 && usage.is_none() => {
                collection = false;
                finished = true;
            }
            // Report IDs, features, nested/mixed collections, ranges, global
            // push/pop and vendor fields are deliberately outside this profile.
            _ => return false,
        }
    }
    finished && !collection && input && output
}

#[cfg(test)]
pub(super) const FIDO: &[u8] = &[
    0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x95, 0x40, 0x91, 0x02, 0xc0,
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_fido_profile() {
        assert!(validate(FIDO));
    }
    #[test]
    fn rejects_numbered_composite_short_and_feature_descriptors() {
        for suffix in [&[0x85, 1][..], FIDO, &[0xb1, 2][..]] {
            let mut d = FIDO.to_vec();
            d.extend_from_slice(suffix);
            assert!(!validate(&d));
        }
        for index in 0..FIDO.len() {
            assert!(!validate(&FIDO[..index]));
        }
        for (index, value) in [(1, 1), (17, 63), (15, 7), (9, 1), (19, 3)] {
            let mut d = FIDO.to_vec();
            d[index] = value;
            assert!(!validate(&d));
        }
    }
}
