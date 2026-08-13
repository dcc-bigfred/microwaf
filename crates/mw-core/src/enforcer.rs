//! Enforcement abstraction (real BPF vs permissive log).

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::policy::EffectiveAction;

/// Daemon run mode (startup only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Real enforcement via eBPF.
    #[default]
    Enforce,
    /// Detect/log only.
    Permissive,
}

impl std::str::FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "enforce" => Ok(Self::Enforce),
            "permissive" => Ok(Self::Permissive),
            other => Err(format!(
                "invalid mode `{other}` (expected enforce|permissive)"
            )),
        }
    }
}

impl Mode {
    /// Wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Permissive => "permissive",
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Applies effective policy to a client (or records would-be action).
pub trait Enforcer: Send + Sync {
    /// Apply policy for `client`.
    fn apply(&self, client: ClientId, action: EffectiveAction);
    /// Clear policy for `client`.
    fn clear(&self, client: ClientId);
}

/// Records would-be actions without enforcing.
#[derive(Debug, Default)]
pub struct PermissiveLog {
    /// Last would-be action per client.
    inner: Mutex<HashMap<ClientId, EffectiveAction>>,
}

impl PermissiveLog {
    /// Snapshot of would-be actions.
    #[must_use]
    pub fn snapshot(&self) -> HashMap<ClientId, EffectiveAction> {
        self.inner.lock().expect("lock").clone()
    }

    /// Get one client.
    #[must_use]
    pub fn get(&self, client: &ClientId) -> Option<EffectiveAction> {
        self.inner.lock().expect("lock").get(client).copied()
    }
}

/// Permissive enforcer: writes to [`PermissiveLog`] only.
#[derive(Debug, Default)]
pub struct PermissiveEnforcer {
    /// Shared log.
    pub log: PermissiveLog,
}

impl Enforcer for PermissiveEnforcer {
    fn apply(&self, client: ClientId, action: EffectiveAction) {
        self.log.inner.lock().expect("lock").insert(client, action);
    }

    fn clear(&self, client: ClientId) {
        self.log.inner.lock().expect("lock").remove(&client);
    }
}

/// In-memory fake enforcer for tests.
#[derive(Debug, Default)]
pub struct FakeEnforcer {
    /// Applied actions.
    pub applied: Mutex<HashMap<ClientId, EffectiveAction>>,
}

impl Enforcer for FakeEnforcer {
    fn apply(&self, client: ClientId, action: EffectiveAction) {
        self.applied.lock().expect("lock").insert(client, action);
    }

    fn clear(&self, client: ClientId) {
        self.applied.lock().expect("lock").remove(&client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn permissive_records() {
        let e = PermissiveEnforcer::default();
        let c = ClientId::new([1, 2, 3, 4, 5, 6], Ipv4Addr::LOCALHOST.into());
        e.apply(c, EffectiveAction::Throttle { drop_rate: 30 });
        assert_eq!(
            e.log.get(&c),
            Some(EffectiveAction::Throttle { drop_rate: 30 })
        );
        e.clear(c);
        assert_eq!(e.log.get(&c), None);
    }
}
