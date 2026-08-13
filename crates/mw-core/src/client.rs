//! Client identity: MAC + IP.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Unique client key: L2 MAC + L3 IP (handles router-MAC + original client IP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientId {
    /// Ethernet MAC.
    pub mac: [u8; 6],
    /// Client IP (IPv4 or IPv6).
    pub ip: IpAddr,
}

impl ClientId {
    /// Construct a client id.
    #[must_use]
    pub fn new(mac: [u8; 6], ip: IpAddr) -> Self {
        Self { mac, ip }
    }

    /// Format MAC as `aa:bb:cc:dd:ee:ff`.
    #[must_use]
    pub fn mac_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
        )
    }

    /// Redis / wire key: `mac@ip`.
    #[must_use]
    pub fn storage_key(&self) -> String {
        format!("{}@{}", self.mac_string(), self.ip)
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.storage_key())
    }
}

/// Parse `aa:bb:cc:dd:ee:ff` or `aa:bb:cc:dd:ee:ff@1.2.3.4`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRefParseError(pub String);

impl fmt::Display for ClientRefParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid client ref: {}", self.0)
    }
}

impl std::error::Error for ClientRefParseError {}

impl FromStr for ClientId {
    type Err = ClientRefParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (mac_s, ip_s) = match s.split_once('@') {
            Some((m, i)) => (m, Some(i)),
            None => (s, None),
        };
        let mac = parse_mac(mac_s).ok_or_else(|| ClientRefParseError(s.into()))?;
        let ip = match ip_s {
            Some(i) => IpAddr::from_str(i).map_err(|_| ClientRefParseError(s.into()))?,
            None => IpAddr::from([0, 0, 0, 0]),
        };
        Ok(Self { mac, ip })
    }
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_mac_only() {
        let c: ClientId = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!(c.mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(c.ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn parse_mac_ip() {
        let c: ClientId = "aa:bb:cc:dd:ee:ff@10.0.0.1".parse().unwrap();
        assert_eq!(c.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(c.storage_key(), "aa:bb:cc:dd:ee:ff@10.0.0.1");
    }
}
