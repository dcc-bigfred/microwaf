//! YAML config types and rule loading helpers.

use serde::{Deserialize, Serialize};

use crate::cel_match::{compile_match, CompiledMatch};
use crate::enforcer::Mode;
use crate::error::ConfigError;
use crate::rule::{Action, Metric, Protocol, Rule, RuleSet, Window, MAX_RULES};

/// `daemon.yaml` contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonConfig {
    /// Run mode (startup only).
    #[serde(default)]
    pub mode: Mode,
    /// NIC interface (`any` = all NICs). Default when omitted: `any`.
    #[serde(default = "default_interface")]
    pub interface: Option<String>,
    /// Auto-policy cooldown seconds.
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
    /// Stats snapshot interval seconds.
    #[serde(default = "default_snapshot")]
    pub stats_snapshot_secs: u64,
    /// SO_PEERCRED allowlist usernames.
    #[serde(default = "default_allow_users")]
    pub allow_users: Vec<String>,
}

fn default_cooldown() -> u64 {
    30
}
fn default_snapshot() -> u64 {
    5
}
fn default_allow_users() -> Vec<String> {
    vec!["root".into(), "bigfred".into(), "bigfred-wizard".into()]
}
fn default_interface() -> Option<String> {
    Some("any".into())
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Enforce,
            interface: default_interface(),
            cooldown_secs: default_cooldown(),
            stats_snapshot_secs: default_snapshot(),
            allow_users: default_allow_users(),
        }
    }
}

/// Named sets for CEL (`sets.yaml`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetsConfig {
    /// Flattened map of set name → string members (CIDRs, IPs, paths, …).
    #[serde(flatten)]
    pub sets: std::collections::BTreeMap<String, Vec<String>>,
}

/// One rule as written in YAML.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigRule {
    /// Id.
    pub id: String,
    /// Protocol.
    pub protocol: String,
    /// Ports.
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    /// Metric.
    pub metric: String,
    /// Window.
    pub window: String,
    /// Limit.
    pub limit: u64,
    /// Action.
    pub action: ConfigAction,
    /// Min threshold.
    #[serde(default)]
    pub min_threshold: u64,
    /// Optional CEL expression.
    #[serde(default, rename = "match")]
    pub r#match: Option<String>,
}

/// Action in YAML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ConfigAction {
    /// Throttle.
    #[serde(rename = "throttle")]
    Throttle {
        /// Drop rate.
        #[serde(rename = "dropRate")]
        drop_rate: u8,
    },
    /// Block.
    #[serde(rename = "block")]
    Block,
}

impl From<ConfigAction> for Action {
    fn from(a: ConfigAction) -> Self {
        match a {
            ConfigAction::Throttle { drop_rate } => Action::Throttle { drop_rate },
            ConfigAction::Block => Action::Block,
        }
    }
}

impl ConfigRule {
    /// Compile into a runtime [`Rule`].
    pub fn compile(&self) -> Result<Rule, ConfigError> {
        let protocol: Protocol = self.protocol.parse()?;
        let metric: Metric = self.metric.parse()?;
        let window: Window = self.window.parse()?;
        let compiled: Option<CompiledMatch> = match &self.r#match {
            Some(src) if !src.is_empty() => {
                Some(compile_match(src).map_err(|e| ConfigError::CelCompile(self.id.clone(), e))?)
            }
            _ => None,
        };
        let rule = Rule {
            id: self.id.clone(),
            protocol,
            ports: self.ports.clone(),
            metric,
            window,
            limit: self.limit,
            action: self.action.clone().into(),
            min_threshold: self.min_threshold,
            r#match: compiled,
            match_src: self.r#match.clone(),
        };
        rule.validate()?;
        Ok(rule)
    }
}

/// Parse a YAML document that is either a list of rules or a single rule.
pub fn parse_rules_yaml(text: &str) -> Result<Vec<ConfigRule>, ConfigError> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
    if value.is_sequence() {
        serde_yaml::from_value(value).map_err(|e| ConfigError::Parse(e.to_string()))
    } else if value.is_mapping() {
        let one: ConfigRule =
            serde_yaml::from_value(value).map_err(|e| ConfigError::Parse(e.to_string()))?;
        Ok(vec![one])
    } else {
        Err(ConfigError::Parse(
            "rules file must be a list or a single mapping".into(),
        ))
    }
}

/// Compile many config rules into a [`RuleSet`].
pub fn compile_ruleset(configs: Vec<ConfigRule>) -> Result<RuleSet, ConfigError> {
    if configs.len() > MAX_RULES {
        return Err(ConfigError::TooManyRules {
            count: configs.len(),
            max: MAX_RULES,
        });
    }
    let mut rules = Vec::with_capacity(configs.len());
    for c in configs {
        rules.push(c.compile()?);
    }
    RuleSet::new(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_rule() {
        let yaml = r#"
- id: http-rps-100
  protocol: http
  ports: [80, 443]
  metric: requests
  window: per-second
  limit: 100
  action: { kind: throttle, dropRate: 50 }
  minThreshold: 50
"#;
        let cfgs = parse_rules_yaml(yaml).unwrap();
        let set = compile_ruleset(cfgs).unwrap();
        assert_eq!(set.rules.len(), 1);
        assert_eq!(set.rules[0].protocol, Protocol::Http);
    }

    #[test]
    fn reject_http_without_ports() {
        let yaml = r#"
- id: bad
  protocol: http
  metric: requests
  window: per-second
  limit: 10
  action: { kind: block }
"#;
        let cfgs = parse_rules_yaml(yaml).unwrap();
        assert!(compile_ruleset(cfgs).is_err());
    }
}
