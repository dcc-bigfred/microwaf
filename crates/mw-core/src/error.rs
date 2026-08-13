//! Typed errors for mw-core.

use thiserror::Error;

/// Configuration / rule-load errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Duplicate rule id across files.
    #[error("duplicate rule id `{0}`")]
    DuplicateRuleId(String),
    /// Too many rules.
    #[error("too many rules: {count} > {max}")]
    TooManyRules {
        /// Actual count.
        count: usize,
        /// Max allowed.
        max: usize,
    },
    /// Parsed protocol missing ports.
    #[error("rule `{0}`: ports are mandatory for protocol `{1}`")]
    PortsRequired(String, String),
    /// Metric invalid for protocol.
    #[error("rule `{0}`: metric `{1}` is not valid for protocol `{2}`")]
    InvalidMetric(String, String, String),
    /// Drop rate out of range.
    #[error("rule `{0}`: dropRate must be 0..=100, got {1}")]
    InvalidDropRate(String, u8),
    /// CEL compile failure.
    #[error("rule `{0}`: CEL compile error: {1}")]
    CelCompile(String, String),
    /// YAML / IO parse error.
    #[error("config parse error: {0}")]
    Parse(String),
    /// Unknown protocol / metric / window string.
    #[error("invalid value: {0}")]
    InvalidValue(String),
}

/// Generic core error.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Config error.
    #[error(transparent)]
    Config(#[from] ConfigError),
}
