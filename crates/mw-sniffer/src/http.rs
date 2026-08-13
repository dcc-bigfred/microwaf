//! HTTP request-line + header detector (first-packet inspection).

/// Parsed HTTP request (request line + selected headers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestLine {
    /// Method (e.g. GET, POST).
    pub method: String,
    /// Path without query.
    pub path: String,
    /// Raw query string (without `?`).
    pub query: String,
    /// True if `Upgrade: websocket` present.
    pub upgrade_ws: bool,
    /// Headers as (lowercase-name, value).
    pub headers: Vec<(String, String)>,
}

/// Detect an HTTP request in a TCP payload. Returns `None` for TLS or non-HTTP.
#[must_use]
pub fn detect_http_request(payload: &[u8]) -> Option<HttpRequestLine> {
    if payload.is_empty() {
        return None;
    }
    // TLS ClientHello / Handshake
    if payload.len() >= 2 && payload[0] == 0x16 && payload[1] == 0x03 {
        return None;
    }
    // Must start with printable ASCII method letter
    if !payload[0].is_ascii_alphabetic() {
        return None;
    }
    let text = std::str::from_utf8(payload).ok()?;
    let (head, rest) = text.split_once("\r\n").or_else(|| text.split_once('\n'))?;
    let mut parts = head.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    if !method.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.split('#').next().unwrap_or(q).to_string()),
        None => (target.split('#').next().unwrap_or(target).to_string(), String::new()),
    };

    let mut headers = Vec::new();
    let mut upgrade_ws = false;
    for line in rest.split("\r\n").flat_map(|l| l.split('\n')) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if name == "upgrade" && value.eq_ignore_ascii_case("websocket") {
            upgrade_ws = true;
        }
        headers.push((name, value));
    }

    Some(HttpRequestLine {
        method,
        path,
        query,
        upgrade_ws,
        headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_get() {
        let p = b"GET /api/login?x=1 HTTP/1.1\r\nHost: a\r\n\r\n";
        let r = detect_http_request(p).unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/api/login");
        assert_eq!(r.query, "x=1");
        assert!(!r.upgrade_ws);
    }

    #[test]
    fn parse_ws_upgrade() {
        let p = b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let r = detect_http_request(p).unwrap();
        assert!(r.upgrade_ws);
    }

    #[test]
    fn reject_tls() {
        let p = [0x16, 0x03, 0x01, 0x00, 0x05];
        assert!(detect_http_request(&p).is_none());
    }
}
