//! WiThrottle line-oriented TCP detector.

/// One WiThrottle command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithrottleLine {
    /// Command family prefix (e.g. `M0A`, `PTA`, `*`).
    pub prefix: String,
    /// MultiThrottle id char, or empty.
    pub throttle: String,
    /// Full trimmed command line.
    pub command: String,
}

/// Split a TCP payload into WiThrottle lines.
#[must_use]
pub fn detect_withrottle_lines(payload: &[u8]) -> Vec<WithrottleLine> {
    let Ok(text) = std::str::from_utf8(payload) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for raw in text.split(['\n', '\r']) {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        // LNWI ESP8266 noise
        if line.starts_with("AT+CIPSENDBUF=") {
            continue;
        }
        let (prefix, throttle) = parse_prefix(line);
        out.push(WithrottleLine {
            prefix,
            throttle,
            command: line.to_string(),
        });
    }
    out
}

fn parse_prefix(line: &str) -> (String, String) {
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        return (String::new(), String::new());
    }
    // Heartbeat / time
    if bytes[0] == b'*' {
        return ("*".into(), String::new());
    }
    // MultiThrottle: M <id> <cmd>...
    if bytes[0] == b'M' && bytes.len() >= 3 {
        let throttle = (bytes[1] as char).to_string();
        let prefix: String = line.chars().take(3).collect();
        return (prefix, throttle);
    }
    // Typical 3-letter command (PTA, PPA, PRT, …) or 2-letter (HC, …)
    let prefix_len = if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1].is_ascii_alphabetic()
        && bytes[2].is_ascii_alphabetic()
    {
        3
    } else if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1].is_ascii_alphabetic() {
        2
    } else {
        1
    };
    (line.chars().take(prefix_len).collect(), String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m0a_and_pta() {
        let p = b"M0A123<;>\nPTA2L456\n*\n";
        let lines = detect_withrottle_lines(p);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].prefix, "M0A");
        assert_eq!(lines[0].throttle, "0");
        assert_eq!(lines[1].prefix, "PTA");
        assert_eq!(lines[2].prefix, "*");
    }

    #[test]
    fn strips_lnwi_noise() {
        let p = b"AT+CIPSENDBUF=12\nM0A1<;>\n";
        let lines = detect_withrottle_lines(p);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].prefix, "M0A");
    }
}
