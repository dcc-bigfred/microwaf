//! WebSocket frame header detector (RFC6455, first packet only).

/// Parsed WebSocket frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsFrameHeader {
    /// FIN bit.
    pub fin: bool,
    /// Opcode (0..=15).
    pub opcode: u8,
    /// Payload length.
    pub payload_len: u64,
    /// Masked bit.
    pub masked: bool,
}

/// Detect a WS frame header at the start of `payload`.
#[must_use]
pub fn detect_ws_frame(payload: &[u8]) -> Option<WsFrameHeader> {
    if payload.len() < 2 {
        return None;
    }
    let b0 = payload[0];
    let b1 = payload[1];
    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0f;
    let masked = b1 & 0x80 != 0;
    let len7 = b1 & 0x7f;
    let (payload_len, hdr_len) = match len7 {
        126 => {
            if payload.len() < 4 {
                return None;
            }
            let len = u16::from_be_bytes([payload[2], payload[3]]) as u64;
            (len, 4usize)
        }
        127 => {
            if payload.len() < 10 {
                return None;
            }
            let len = u64::from_be_bytes(payload[2..10].try_into().ok()?);
            // Reject reserved MSB
            if len & (1u64 << 63) != 0 {
                return None;
            }
            (len, 10usize)
        }
        n => (u64::from(n), 2usize),
    };
    let need = hdr_len + if masked { 4 } else { 0 };
    if payload.len() < need {
        return None;
    }
    // Sanity: opcode should be a known type (0-2, 8-10) for detection confidence
    if !matches!(opcode, 0..=2 | 8..=10) {
        return None;
    }
    Some(WsFrameHeader {
        fin,
        opcode,
        payload_len,
        masked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmasked_text() {
        // FIN + text, len=5, payload "hello"
        let mut p = vec![0x81, 0x05];
        p.extend_from_slice(b"hello");
        let h = detect_ws_frame(&p).unwrap();
        assert!(h.fin);
        assert_eq!(h.opcode, 0x1);
        assert_eq!(h.payload_len, 5);
        assert!(!h.masked);
    }

    #[test]
    fn masked_short() {
        let mut p = vec![0x81, 0x85, 0x01, 0x02, 0x03, 0x04];
        p.extend_from_slice(&[0x00; 5]);
        let h = detect_ws_frame(&p).unwrap();
        assert!(h.masked);
        assert_eq!(h.payload_len, 5);
    }

    #[test]
    fn truncated() {
        assert!(detect_ws_frame(&[0x81]).is_none());
    }
}
