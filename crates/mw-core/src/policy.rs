//! Manual / auto policy and merge.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::rule::{Action, RuleId};

/// Manual policy set via CLI (persisted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualPolicy {
    /// Optional drop rate.
    pub throttle: Option<u8>,
    /// Blocked flag.
    pub blocked: bool,
    /// Expiry; None = permanent.
    pub until: Option<Instant>,
}

impl ManualPolicy {
    /// Expired?
    #[must_use]
    pub fn is_expired(&self, now: Instant) -> bool {
        self.until.is_some_and(|u| now >= u)
    }
}

/// Serializable manual policy for Redis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredManualPolicy {
    /// Drop rate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throttle: Option<u8>,
    /// Blocked.
    #[serde(default)]
    pub blocked: bool,
    /// Unix expiry seconds; None = permanent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_unix_secs: Option<u64>,
}

impl StoredManualPolicy {
    /// Convert to runtime policy using `now`.
    #[must_use]
    pub fn to_runtime(&self, now: Instant) -> ManualPolicy {
        let until = self.until_unix_secs.map(|secs| {
            let target = UNIX_EPOCH + Duration::from_secs(secs);
            let now_sys = SystemTime::now();
            match target.duration_since(now_sys) {
                Ok(d) => now + d,
                Err(_) => now, // already expired
            }
        });
        ManualPolicy {
            throttle: self.throttle,
            blocked: self.blocked,
            until,
        }
    }

    /// From runtime.
    #[must_use]
    pub fn from_runtime(p: &ManualPolicy, now: Instant) -> Self {
        let until_unix_secs = p.until.map(|u| {
            let delta = u.saturating_duration_since(now);
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_add(delta.as_secs())
        });
        Self {
            throttle: p.throttle,
            blocked: p.blocked,
            until_unix_secs,
        }
    }
}

/// Auto policy from rule engine (cooldown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoPolicy {
    /// Drop rate (0 if block).
    pub drop_rate: u8,
    /// Blocked.
    pub blocked: bool,
    /// Causing rule.
    pub rule_id: RuleId,
    /// Cooldown expiry.
    pub until: Instant,
}

impl AutoPolicy {
    /// From a violation action + cooldown.
    #[must_use]
    pub fn from_action(rule_id: RuleId, action: Action, now: Instant, cooldown: Duration) -> Self {
        match action {
            Action::Block => Self {
                drop_rate: 100,
                blocked: true,
                rule_id,
                until: now + cooldown,
            },
            Action::Throttle { drop_rate } => Self {
                drop_rate,
                blocked: false,
                rule_id,
                until: now + cooldown,
            },
        }
    }

    /// Expired?
    #[must_use]
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.until
    }
}

/// Combined per-client policy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientPolicy {
    /// Manual overlay.
    pub manual: Option<ManualPolicy>,
    /// Auto from rules.
    pub auto: Option<AutoPolicy>,
}

/// Effective enforcement action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveAction {
    /// Pass all.
    None,
    /// Drop fraction.
    Throttle {
        /// Drop rate.
        drop_rate: u8,
    },
    /// Drop all.
    Block,
}

impl EffectiveAction {
    /// Wire-ish drop rate (100 for block).
    #[must_use]
    pub fn drop_rate(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Throttle { drop_rate } => drop_rate,
            Self::Block => 100,
        }
    }

    /// True if blocked.
    #[must_use]
    pub fn is_blocked(self) -> bool {
        matches!(self, Self::Block)
    }
}

/// Merge manual + auto: manual wins when present and not expired; else auto.
/// Block beats throttle. Highest drop_rate wins among throttles.
#[must_use]
pub fn merge_policy(policy: &ClientPolicy, now: Instant) -> EffectiveAction {
    let manual = policy.manual.as_ref().filter(|m| !m.is_expired(now));
    let auto = policy.auto.as_ref().filter(|a| !a.is_expired(now));

    if let Some(m) = manual {
        if m.blocked {
            return EffectiveAction::Block;
        }
        if let Some(rate) = m.throttle {
            // Manual throttle still combines with auto block
            if auto.is_some_and(|a| a.blocked) {
                return EffectiveAction::Block;
            }
            let auto_rate = auto.map(|a| a.drop_rate).unwrap_or(0);
            return EffectiveAction::Throttle {
                drop_rate: rate.max(auto_rate),
            };
        }
    }

    if let Some(a) = auto {
        if a.blocked {
            return EffectiveAction::Block;
        }
        if a.drop_rate > 0 {
            return EffectiveAction::Throttle {
                drop_rate: a.drop_rate,
            };
        }
    }

    EffectiveAction::None
}

/// Helper: apply violation list → strongest auto policy.
#[must_use]
pub fn strongest_auto(
    violations: &[crate::rule::Violation],
    now: Instant,
    cooldown: Duration,
) -> Option<AutoPolicy> {
    let mut best: Option<AutoPolicy> = None;
    for v in violations {
        let cand = AutoPolicy::from_action(v.rule_id.clone(), v.action, now, cooldown);
        best = Some(match best {
            None => cand,
            Some(prev) => {
                if cand.blocked && !prev.blocked {
                    cand
                } else if prev.blocked && !cand.blocked {
                    prev
                } else if cand.drop_rate > prev.drop_rate {
                    cand
                } else {
                    prev
                }
            }
        });
    }
    best
}

/// Re-export for callers that need ClientId in policy maps.
pub type PolicyMap = std::collections::HashMap<ClientId, ClientPolicy>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_block_wins() {
        let now = Instant::now();
        let p = ClientPolicy {
            manual: Some(ManualPolicy {
                throttle: None,
                blocked: true,
                until: None,
            }),
            auto: Some(AutoPolicy {
                drop_rate: 50,
                blocked: false,
                rule_id: "r".into(),
                until: now + Duration::from_secs(30),
            }),
        };
        assert_eq!(merge_policy(&p, now), EffectiveAction::Block);
    }

    #[test]
    fn auto_throttle() {
        let now = Instant::now();
        let p = ClientPolicy {
            manual: None,
            auto: Some(AutoPolicy {
                drop_rate: 40,
                blocked: false,
                rule_id: "r".into(),
                until: now + Duration::from_secs(30),
            }),
        };
        assert_eq!(
            merge_policy(&p, now),
            EffectiveAction::Throttle { drop_rate: 40 }
        );
    }
}
