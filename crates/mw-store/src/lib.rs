//! Redis + in-memory persistence for MicroWAF.

#![forbid(unsafe_code)]

mod memory;
mod redis_store;

pub use memory::MemoryStore;
pub use redis_store::RedisStore;

/// Schema version stamped in Redis. Mismatch → discard all `microwaf:*` keys.
pub const SCHEMA_VERSION: u32 = 1;

pub use mw_core::store::{ClientStatsStore, ManualPolicyStore, StoreError, StoredClientStats};
