//! Z21 LAN UDP record detector.

/// One Z21 LAN record (`DataLen | Header | Data`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Z21Record {
    /// 16-bit header (little-endian on wire).
    pub header: u16,
    /// X-BUS sub-header when `header == 0x0040`, else 0.
    pub xheader: u8,
    /// Full DataLen field (includes 4-byte header).
    pub data_len: u16,
    /// Data bytes (DataLen - 4).
    pub data: Vec<u8>,
}

/// Split a UDP payload into Z21 records. Stops on truncated/invalid data.
#[must_use]
pub fn detect_z21_records(payload: &[u8]) -> Vec<Z21Record> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= payload.len() {
        let data_len = u16::from_le_bytes([payload[off], payload[off + 1]]);
        let header = u16::from_le_bytes([payload[off + 2], payload[off + 3]]);
        if data_len < 4 {
            break;
        }
        let total = data_len as usize;
        if off + total > payload.len() {
            break;
        }
        let data = payload[off + 4..off + total].to_vec();
        let xheader = if header == 0x0040 {
            data.first().copied().unwrap_or(0)
        } else {
            0
        };
        out.push(Z21Record {
            header,
            xheader,
            data_len,
            data,
        });
        off += total;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_record() {
        // DataLen=4, Header=0x10 (LAN_GET_SERIAL_NUMBER style empty)
        let p = [0x04, 0x00, 0x10, 0x00];
        let r = detect_z21_records(&p);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].header, 0x0010);
        assert!(r[0].data.is_empty());
    }

    #[test]
    fn multi_record_with_xbus() {
        // Record1: DataLen=7, Header=0x40, data=[0xE4, 0x01, 0x02]
        // Record2: DataLen=4, Header=0x10
        let mut p = vec![0x07, 0x00, 0x40, 0x00, 0xE4, 0x01, 0x02];
        p.extend_from_slice(&[0x04, 0x00, 0x10, 0x00]);
        let r = detect_z21_records(&p);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].header, 0x0040);
        assert_eq!(r[0].xheader, 0xE4);
        assert_eq!(r[1].header, 0x0010);
    }

    #[test]
    fn truncated_stops() {
        let p = [0x10, 0x00, 0x40, 0x00, 0xE4]; // claims 16 bytes, only 5 present
        let r = detect_z21_records(&p);
        assert!(r.is_empty());
    }
}
