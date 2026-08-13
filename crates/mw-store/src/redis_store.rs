//! Redis-backed store (write-only at runtime; read-once at startup).

use parking_lot::Mutex;
use redis::Commands;

use mw_core::client::ClientId;
use mw_core::policy::StoredManualPolicy;
use mw_core::store::{ClientStatsStore, ManualPolicyStore, StoreError, StoredClientStats};

use crate::SCHEMA_VERSION;

const KEY_SCHEMA: &str = "microwaf:schema_version";
const PREFIX_POLICY: &str = "microwaf:policy:manual:";
const PREFIX_STATS: &str = "microwaf:stats:";

/// Redis store.
pub struct RedisStore {
    conn: Mutex<redis::Connection>,
}

impl RedisStore {
    /// Connect and ensure schema version (discard on mismatch).
    ///
    /// # Errors
    /// Connection or Redis command failures.
    pub fn connect(url: &str) -> Result<Self, StoreError> {
        let client = redis::Client::open(url).map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut conn = client
            .get_connection()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        ensure_schema(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

fn ensure_schema(conn: &mut redis::Connection) -> Result<(), StoreError> {
    let current: Option<String> = conn
        .get(KEY_SCHEMA)
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    match current {
        None => {
            let _: () = conn
                .set(KEY_SCHEMA, SCHEMA_VERSION.to_string())
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        Some(v) => {
            let parsed: u32 = v.parse().unwrap_or(0);
            if parsed != SCHEMA_VERSION {
                tracing::warn!(
                    old = parsed,
                    new = SCHEMA_VERSION,
                    "microwaf Redis schema mismatch — discarding all microwaf:* keys"
                );
                let keys: Vec<String> = redis::cmd("KEYS")
                    .arg("microwaf:*")
                    .query(conn)
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                if !keys.is_empty() {
                    let _: () = redis::cmd("DEL")
                        .arg(&keys)
                        .query(conn)
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                }
                let _: () = conn
                    .set(KEY_SCHEMA, SCHEMA_VERSION.to_string())
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
            }
        }
    }
    Ok(())
}

fn policy_key(client: &ClientId) -> String {
    format!("{PREFIX_POLICY}{}", client.storage_key())
}

fn stats_key(client: &ClientId) -> String {
    format!("{PREFIX_STATS}{}", client.storage_key())
}

fn parse_client_from_key(key: &str, prefix: &str) -> Result<ClientId, StoreError> {
    let rest = key
        .strip_prefix(prefix)
        .ok_or_else(|| StoreError::Backend(format!("bad key {key}")))?;
    rest.parse()
        .map_err(|e: mw_core::client::ClientRefParseError| StoreError::Backend(e.to_string()))
}

impl ManualPolicyStore for RedisStore {
    fn load_all(&self) -> Result<Vec<(ClientId, StoredManualPolicy)>, StoreError> {
        let mut conn = self.conn.lock();
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{PREFIX_POLICY}*"))
            .query(&mut *conn)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut out = Vec::new();
        for key in keys {
            let raw: String = conn
                .get(&key)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let policy: StoredManualPolicy =
                serde_json::from_str(&raw).map_err(|e| StoreError::Backend(e.to_string()))?;
            let client = parse_client_from_key(&key, PREFIX_POLICY)?;
            out.push((client, policy));
        }
        Ok(out)
    }

    fn put(&self, client: &ClientId, policy: &StoredManualPolicy) -> Result<(), StoreError> {
        let raw = serde_json::to_string(policy).map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut conn = self.conn.lock();
        let key = policy_key(client);
        if let Some(secs) = policy.until_unix_secs {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let ttl = secs.saturating_sub(now).max(1);
            let _: () = conn
                .set_ex(key, raw, ttl)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        } else {
            let _: () = conn
                .set(key, raw)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        Ok(())
    }

    fn remove(&self, client: &ClientId) -> Result<(), StoreError> {
        let mut conn = self.conn.lock();
        let _: () = conn
            .del(policy_key(client))
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl ClientStatsStore for RedisStore {
    fn load_all(&self) -> Result<Vec<(ClientId, StoredClientStats)>, StoreError> {
        let mut conn = self.conn.lock();
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("{PREFIX_STATS}*"))
            .query(&mut *conn)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut out = Vec::new();
        for key in keys {
            let raw: String = conn
                .get(&key)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let stats: StoredClientStats =
                serde_json::from_str(&raw).map_err(|e| StoreError::Backend(e.to_string()))?;
            let client = parse_client_from_key(&key, PREFIX_STATS)?;
            out.push((client, stats));
        }
        Ok(out)
    }

    fn put_batch(&self, stats: &[(ClientId, StoredClientStats)]) -> Result<(), StoreError> {
        let mut conn = self.conn.lock();
        for (client, s) in stats {
            let raw = serde_json::to_string(s).map_err(|e| StoreError::Backend(e.to_string()))?;
            let _: () = conn
                .set(stats_key(client), raw)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        Ok(())
    }
}
