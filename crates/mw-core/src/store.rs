//! Persistence traits (implemented by mw-store).

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::counters::CumulativeCounters;
use crate::policy::StoredManualPolicy;
use crate::rule::{Metric, RuleId};

/// Snapshot of one rule's sliding window for Redis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleWindowSnapshot {
    /// Rule id.
    pub rule_id: RuleId,
    /// Metric the window tracks.
    pub metric: Metric,
    /// 60 bucket values for that metric.
    pub buckets: Vec<u64>,
    /// Cursor index.
    pub cursor: usize,
    /// Last advance unix seconds.
    pub last_advance_unix_secs: u64,
}

/// Persisted client stats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredClientStats {
    /// Cumulative counters.
    pub cumulative: CumulativeCounters,
    /// Window snapshots.
    #[serde(default)]
    pub windows: Vec<RuleWindowSnapshot>,
    /// Updated at.
    pub updated_unix_secs: u64,
}

/// Store error.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Backend failure.
    #[error("store error: {0}")]
    Backend(String),
}

/// Manual policy persistence.
pub trait ManualPolicyStore: Send + Sync {
    /// Load all policies at startup.
    ///
    /// # Errors
    /// Backend failures.
    fn load_all(&self) -> Result<Vec<(ClientId, StoredManualPolicy)>, StoreError>;
    /// Upsert one policy.
    ///
    /// # Errors
    /// Backend failures.
    fn put(&self, client: &ClientId, policy: &StoredManualPolicy) -> Result<(), StoreError>;
    /// Remove one policy.
    ///
    /// # Errors
    /// Backend failures.
    fn remove(&self, client: &ClientId) -> Result<(), StoreError>;
}

/// Client stats persistence.
pub trait ClientStatsStore: Send + Sync {
    /// Load all stats at startup.
    ///
    /// # Errors
    /// Backend failures.
    fn load_all(&self) -> Result<Vec<(ClientId, StoredClientStats)>, StoreError>;
    /// Batch upsert.
    ///
    /// # Errors
    /// Backend failures.
    fn put_batch(&self, stats: &[(ClientId, StoredClientStats)]) -> Result<(), StoreError>;
}
