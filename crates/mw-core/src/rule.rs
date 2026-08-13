//! Rule model and engine.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::cel_match::CompiledMatch;
use crate::error::ConfigError;
use crate::window::RuleWindows;

/// Maximum number of rules in a RuleSet.
pub const MAX_RULES: usize = 256;

/// Rule identifier.
pub type RuleId = String;

/// L7 / L4 protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTP over TCP.
    Http,
    /// WebSocket over TCP.
    #[serde(rename = "websocket")]
    WebSocket,
    /// Z21 LAN over UDP.
    Z21,
    /// WiThrottle over TCP.
    Withrottle,
    /// Generic UDP.
    Udp,
    /// Generic TCP.
    Tcp,
}

impl Protocol {
    /// True if this is a parsed (L7) protocol requiring ports.
    #[must_use]
    pub fn is_parsed(self) -> bool {
        !matches!(self, Self::Udp | Self::Tcp)
    }

    /// Wire / config string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::WebSocket => "websocket",
            Self::Z21 => "z21",
            Self::Withrottle => "withrottle",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "http" => Ok(Self::Http),
            "websocket" | "ws" => Ok(Self::WebSocket),
            "z21" => Ok(Self::Z21),
            "withrottle" | "wt" => Ok(Self::Withrottle),
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            other => Err(ConfigError::InvalidValue(format!("protocol `{other}`"))),
        }
    }
}

/// What to count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Metric {
    /// Parsed units (requests/records/lines/frames).
    Requests,
    /// Payload bytes.
    Bytes,
    /// New flows (udp/tcp only).
    Connections,
}

impl Metric {
    /// Wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requests => "requests",
            Self::Bytes => "bytes",
            Self::Connections => "connections",
        }
    }

    /// Whether this metric is valid for `protocol`.
    #[must_use]
    pub fn valid_for(self, protocol: Protocol) -> bool {
        match protocol {
            Protocol::Udp | Protocol::Tcp => matches!(self, Self::Connections | Self::Bytes),
            _ => matches!(self, Self::Requests | Self::Bytes),
        }
    }
}

impl std::str::FromStr for Metric {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "requests" => Ok(Self::Requests),
            "bytes" => Ok(Self::Bytes),
            "connections" => Ok(Self::Connections),
            other => Err(ConfigError::InvalidValue(format!("metric `{other}`"))),
        }
    }
}

/// Sliding-window length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Window {
    /// Last 1 second.
    #[serde(rename = "per-second")]
    PerSecond,
    /// Last 60 seconds.
    #[serde(rename = "per-minute")]
    PerMinute,
}

impl Window {
    /// Seconds covered.
    #[must_use]
    pub fn secs(self) -> usize {
        match self {
            Self::PerSecond => 1,
            Self::PerMinute => 60,
        }
    }

    /// Wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PerSecond => "per-second",
            Self::PerMinute => "per-minute",
        }
    }
}

impl std::str::FromStr for Window {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "per-second" | "per_second" | "second" | "1s" => Ok(Self::PerSecond),
            "per-minute" | "per_minute" | "minute" | "60s" => Ok(Self::PerMinute),
            other => Err(ConfigError::InvalidValue(format!("window `{other}`"))),
        }
    }
}

/// Action applied when a rule is violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Action {
    /// Drop a percentage of packets.
    #[serde(rename = "throttle")]
    Throttle {
        /// Drop rate 0..=100.
        #[serde(rename = "dropRate")]
        drop_rate: u8,
    },
    /// Drop all packets.
    #[serde(rename = "block")]
    Block,
}

/// A compiled rule.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Unique id.
    pub id: RuleId,
    /// Protocol selector.
    pub protocol: Protocol,
    /// Destination ports (None = all for udp/tcp; Some required for parsed).
    pub ports: Option<Vec<u16>>,
    /// Metric.
    pub metric: Metric,
    /// Window.
    pub window: Window,
    /// Max allowed sum within window.
    pub limit: u64,
    /// Action on violation.
    pub action: Action,
    /// Floor for `top`.
    pub min_threshold: u64,
    /// Optional CEL program.
    pub r#match: Option<CompiledMatch>,
    /// Original CEL source (for listRules).
    pub match_src: Option<String>,
}

impl Rule {
    /// True if `port` matches this rule's port selector.
    #[must_use]
    pub fn matches_port(&self, port: u16) -> bool {
        match &self.ports {
            None => true,
            Some(ports) => ports.contains(&port),
        }
    }

    /// Validate metric/ports constraints.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.protocol.is_parsed() && self.ports.as_ref().is_none_or(|p| p.is_empty()) {
            return Err(ConfigError::PortsRequired(
                self.id.clone(),
                self.protocol.as_str().into(),
            ));
        }
        if !self.metric.valid_for(self.protocol) {
            return Err(ConfigError::InvalidMetric(
                self.id.clone(),
                self.metric.as_str().into(),
                self.protocol.as_str().into(),
            ));
        }
        if let Action::Throttle { drop_rate } = self.action {
            if drop_rate > 100 {
                return Err(ConfigError::InvalidDropRate(self.id.clone(), drop_rate));
            }
        }
        Ok(())
    }
}

/// Immutable set of rules.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    /// Rules in load order.
    pub rules: Vec<Arc<Rule>>,
}

impl RuleSet {
    /// Build from validated rules.
    pub fn new(rules: Vec<Rule>) -> Result<Self, ConfigError> {
        if rules.len() > MAX_RULES {
            return Err(ConfigError::TooManyRules {
                count: rules.len(),
                max: MAX_RULES,
            });
        }
        let mut seen = std::collections::HashSet::new();
        for r in &rules {
            r.validate()?;
            if !seen.insert(r.id.clone()) {
                return Err(ConfigError::DuplicateRuleId(r.id.clone()));
            }
        }
        Ok(Self {
            rules: rules.into_iter().map(Arc::new).collect(),
        })
    }

    /// Rules matching protocol + port.
    pub fn matching(&self, protocol: Protocol, port: u16) -> impl Iterator<Item = &Arc<Rule>> {
        self.rules
            .iter()
            .filter(move |r| r.protocol == protocol && r.matches_port(port))
    }

    /// Find by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Arc<Rule>> {
        self.rules.iter().find(|r| r.id == id)
    }
}

/// A rule violation for one client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Rule id.
    pub rule_id: RuleId,
    /// Observed value.
    pub value: u64,
    /// Limit.
    pub limit: u64,
    /// Action.
    pub action: Action,
}

/// Evaluates rules against per-(client, rule) windows.
#[derive(Debug, Clone)]
pub struct RuleEngine {
    /// Live rule set.
    pub rules: Arc<RuleSet>,
}

impl RuleEngine {
    /// Construct.
    #[must_use]
    pub fn new(rules: Arc<RuleSet>) -> Self {
        Self { rules }
    }

    /// Evaluate all rules for one client's windows.
    #[must_use]
    pub fn evaluate(&self, per_rule: &RuleWindows) -> Vec<Violation> {
        self.rules
            .rules
            .iter()
            .filter_map(|r| {
                let secs = r.window.secs();
                let value = per_rule.sum(&r.id, r.metric, secs);
                (value > r.limit).then_some(Violation {
                    rule_id: r.id.clone(),
                    value,
                    limit: r.limit,
                    action: r.action,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_rule(id: &str) -> Rule {
        Rule {
            id: id.into(),
            protocol: Protocol::Http,
            ports: Some(vec![80]),
            metric: Metric::Requests,
            window: Window::PerSecond,
            limit: 10,
            action: Action::Throttle { drop_rate: 50 },
            min_threshold: 5,
            r#match: None,
            match_src: None,
        }
    }

    #[test]
    fn connections_invalid_for_http() {
        let mut r = base_rule("x");
        r.metric = Metric::Connections;
        assert!(r.validate().is_err());
    }

    #[test]
    fn ports_required_for_http() {
        let mut r = base_rule("x");
        r.ports = None;
        assert!(r.validate().is_err());
    }

    #[test]
    fn udp_allows_no_ports() {
        let r = Rule {
            id: "u".into(),
            protocol: Protocol::Udp,
            ports: None,
            metric: Metric::Bytes,
            window: Window::PerSecond,
            limit: 1000,
            action: Action::Block,
            min_threshold: 0,
            r#match: None,
            match_src: None,
        };
        assert!(r.validate().is_ok());
    }
}
