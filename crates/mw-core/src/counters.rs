//! Userspace monotonic counter store (per client, per rule).

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::rule::RuleId;

/// Cumulative diagnostic counters (per client).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CumulativeCounters {
    /// Requests.
    pub requests: u64,
    /// Bytes.
    pub bytes: u64,
    /// Connections.
    pub connections: u64,
    /// WS handshakes.
    pub ws_connections: u64,
}

/// Key for a per-rule counter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CounterKey {
    /// Client.
    pub client: ClientId,
    /// Rule id.
    pub rule_id: RuleId,
}

/// Thread-safe monotonic counters.
#[derive(Debug, Default)]
pub struct CounterStore {
    /// Per (client, rule) metric counters: (requests, bytes, connections).
    by_rule: Mutex<HashMap<CounterKey, (u64, u64, u64)>>,
    /// Per-client diagnostics.
    by_client: Mutex<HashMap<ClientId, CumulativeCounters>>,
}

impl CounterStore {
    /// Increment requests for a rule.
    pub fn add_requests(&self, client: ClientId, rule_id: &str, n: u64) {
        self.add(client, rule_id, n, 0, 0);
    }

    /// Increment bytes for a rule.
    pub fn add_bytes(&self, client: ClientId, rule_id: &str, n: u64) {
        self.add(client, rule_id, 0, n, 0);
    }

    /// Increment connections for a rule.
    pub fn add_connections(&self, client: ClientId, rule_id: &str, n: u64) {
        self.add(client, rule_id, 0, 0, n);
    }

    /// Increment WS handshake diagnostic.
    pub fn add_ws_connection(&self, client: ClientId) {
        let mut m = self.by_client.lock().expect("lock");
        let e = m.entry(client).or_default();
        e.ws_connections = e.ws_connections.saturating_add(1);
    }

    fn add(&self, client: ClientId, rule_id: &str, req: u64, bytes: u64, conn: u64) {
        {
            let mut m = self.by_rule.lock().expect("lock");
            let e = m
                .entry(CounterKey {
                    client,
                    rule_id: rule_id.to_string(),
                })
                .or_insert((0, 0, 0));
            e.0 = e.0.saturating_add(req);
            e.1 = e.1.saturating_add(bytes);
            e.2 = e.2.saturating_add(conn);
        }
        {
            let mut m = self.by_client.lock().expect("lock");
            let e = m.entry(client).or_default();
            e.requests = e.requests.saturating_add(req);
            e.bytes = e.bytes.saturating_add(bytes);
            e.connections = e.connections.saturating_add(conn);
        }
    }

    /// Snapshot all per-rule counters.
    #[must_use]
    pub fn snapshot_rules(&self) -> HashMap<CounterKey, (u64, u64, u64)> {
        self.by_rule.lock().expect("lock").clone()
    }

    /// Snapshot per-client diagnostics.
    #[must_use]
    pub fn snapshot_clients(&self) -> HashMap<ClientId, CumulativeCounters> {
        self.by_client.lock().expect("lock").clone()
    }

    /// Get one rule counter.
    #[must_use]
    pub fn get_rule(&self, client: ClientId, rule_id: &str) -> (u64, u64, u64) {
        self.by_rule
            .lock()
            .expect("lock")
            .get(&CounterKey {
                client,
                rule_id: rule_id.to_string(),
            })
            .copied()
            .unwrap_or((0, 0, 0))
    }
}
