//! Pure MicroWAF rule engine, policy merge, and config types (no I/O).

#![forbid(unsafe_code)]

pub mod cel_match;
pub mod client;
pub mod config;
pub mod counters;
pub mod enforcer;
pub mod error;
pub mod policy;
pub mod rule;
pub mod store;
pub mod window;

pub use cel_match::{compile_match, eval_match, MatchContext};
pub use client::ClientId;
pub use config::{ConfigRule, DaemonConfig, SetsConfig};
pub use counters::{CounterKey, CounterStore, CumulativeCounters};
pub use enforcer::{Enforcer, Mode, PermissiveEnforcer, PermissiveLog};
pub use error::{ConfigError, CoreError};
pub use policy::{
    merge_policy, AutoPolicy, ClientPolicy, EffectiveAction, ManualPolicy, StoredManualPolicy,
};
pub use rule::{
    Action, Metric, Protocol, Rule, RuleEngine, RuleId, RuleSet, Violation, Window, MAX_RULES,
};
pub use store::{ClientStatsStore, ManualPolicyStore, StoredClientStats};
pub use window::{Bucket, RuleWindows, SlidingWindow};
