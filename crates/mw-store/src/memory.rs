//! In-memory fake store for tests.

use std::collections::HashMap;
use std::sync::Mutex;

use mw_core::client::ClientId;
use mw_core::policy::StoredManualPolicy;
use mw_core::store::{ClientStatsStore, ManualPolicyStore, StoreError, StoredClientStats};

/// In-memory implementation of both store traits.
#[derive(Debug, Default)]
pub struct MemoryStore {
    policies: Mutex<HashMap<String, StoredManualPolicy>>,
    stats: Mutex<HashMap<String, StoredClientStats>>,
}

impl ManualPolicyStore for MemoryStore {
    fn load_all(&self) -> Result<Vec<(ClientId, StoredManualPolicy)>, StoreError> {
        let m = self.policies.lock().expect("lock");
        let mut out = Vec::new();
        for (k, v) in m.iter() {
            let client: ClientId =
                k.parse()
                    .map_err(|e: mw_core::client::ClientRefParseError| {
                        StoreError::Backend(e.to_string())
                    })?;
            out.push((client, v.clone()));
        }
        Ok(out)
    }

    fn put(&self, client: &ClientId, policy: &StoredManualPolicy) -> Result<(), StoreError> {
        self.policies
            .lock()
            .expect("lock")
            .insert(client.storage_key(), policy.clone());
        Ok(())
    }

    fn remove(&self, client: &ClientId) -> Result<(), StoreError> {
        self.policies
            .lock()
            .expect("lock")
            .remove(&client.storage_key());
        Ok(())
    }
}

impl ClientStatsStore for MemoryStore {
    fn load_all(&self) -> Result<Vec<(ClientId, StoredClientStats)>, StoreError> {
        let m = self.stats.lock().expect("lock");
        let mut out = Vec::new();
        for (k, v) in m.iter() {
            let client: ClientId =
                k.parse()
                    .map_err(|e: mw_core::client::ClientRefParseError| {
                        StoreError::Backend(e.to_string())
                    })?;
            out.push((client, v.clone()));
        }
        Ok(out)
    }

    fn put_batch(&self, stats: &[(ClientId, StoredClientStats)]) -> Result<(), StoreError> {
        let mut m = self.stats.lock().expect("lock");
        for (c, s) in stats {
            m.insert(c.storage_key(), s.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mw_core::counters::CumulativeCounters;
    use std::net::Ipv4Addr;

    #[test]
    fn policy_round_trip() {
        let store = MemoryStore::default();
        let c = ClientId::new([1, 2, 3, 4, 5, 6], Ipv4Addr::LOCALHOST.into());
        let p = StoredManualPolicy {
            throttle: Some(50),
            blocked: false,
            until_unix_secs: None,
        };
        store.put(&c, &p).unwrap();
        let all = ManualPolicyStore::load_all(&store).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].1.throttle, Some(50));
        store.remove(&c).unwrap();
        assert!(ManualPolicyStore::load_all(&store).unwrap().is_empty());
    }

    #[test]
    fn stats_batch() {
        let store = MemoryStore::default();
        let c = ClientId::new([1, 2, 3, 4, 5, 6], Ipv4Addr::LOCALHOST.into());
        let s = StoredClientStats {
            cumulative: CumulativeCounters {
                requests: 10,
                bytes: 20,
                connections: 1,
                ws_connections: 0,
            },
            windows: vec![],
            updated_unix_secs: 1,
        };
        store.put_batch(&[(c, s)]).unwrap();
        assert_eq!(
            ClientStatsStore::load_all(&store).unwrap()[0]
                .1
                .cumulative
                .requests,
            10
        );
    }
}
