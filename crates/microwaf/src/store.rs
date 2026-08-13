//! Store wiring (hydrate at startup, snapshot at runtime).

use anyhow::{Context, Result};
use tracing::info;

use mw_core::policy::StoredManualPolicy;
use mw_core::store::{ClientStatsStore, ManualPolicyStore};
use mw_store::RedisStore;

use crate::state::DaemonState;

/// Open Redis store.
pub fn open_redis(url: &str) -> Result<RedisStore> {
    RedisStore::connect(url).map_err(|e| anyhow::anyhow!(e))
}

/// Hydrate in-memory state from store (read-once).
pub fn hydrate(state: &DaemonState, store: &impl ManualPolicyStore) -> Result<()> {
    let policies = store.load_all().map_err(|e| anyhow::anyhow!(e))?;
    let now = std::time::Instant::now();
    let mut map = state.policies.lock();
    for (client, stored) in policies {
        map.insert(client, mw_core::policy::ClientPolicy {
            manual: Some(stored.to_runtime(now)),
            auto: None,
        });
    }
    info!(count = map.len(), "hydrated manual policies from store");
    Ok(())
}

/// Persist a manual policy mutation.
pub fn persist_manual(
    store: &dyn ManualPolicyStore,
    client: &mw_core::ClientId,
    policy: Option<&StoredManualPolicy>,
) -> Result<()> {
    match policy {
        Some(p) => store.put(client, p).map_err(|e| anyhow::anyhow!(e))?,
        None => store.remove(client).map_err(|e| anyhow::anyhow!(e))?,
    }
    Ok(())
}

/// Snapshot client stats (best-effort).
pub fn snapshot_stats(state: &DaemonState, store: &dyn ClientStatsStore) -> Result<()> {
    let clients = state.counters.snapshot_clients();
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let batch: Vec<_> = clients
        .into_iter()
        .map(|(client, cumulative)| {
            (
                client,
                mw_core::store::StoredClientStats {
                    cumulative,
                    windows: vec![],
                    updated_unix_secs: now_unix,
                },
            )
        })
        .collect();
    if !batch.is_empty() {
        store
            .put_batch(&batch)
            .map_err(|e| anyhow::anyhow!(e))
            .context("stats snapshot")?;
    }
    Ok(())
}
