//! Shared daemon state.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use parking_lot::Mutex;

use mw_core::client::ClientId;
use mw_core::config::{DaemonConfig, SetsConfig};
use mw_core::counters::{CounterKey, CounterStore};
use mw_core::enforcer::{Enforcer, Mode};
use mw_core::policy::{EffectiveAction, ClientPolicy};
use mw_core::rule::RuleSet;
use mw_core::window::RuleWindows;

use crate::config::LiveConfig;

/// Process-wide daemon state.
pub struct DaemonState {
    /// Run mode (immutable after start).
    pub mode: Mode,
    /// Interface name.
    pub interface: String,
    /// Live rules + daemon knobs + sets.
    pub live: ArcSwap<LiveConfig>,
    /// Per-client policies.
    pub policies: Mutex<HashMap<ClientId, ClientPolicy>>,
    /// Per-client sliding windows.
    pub windows: Mutex<HashMap<ClientId, RuleWindows>>,
    /// Sniffer counters.
    pub counters: CounterStore,
    /// Last counter snapshot for deltas.
    pub last_counters: Mutex<HashMap<CounterKey, (u64, u64, u64)>>,
    /// Would-be actions in permissive mode.
    pub would_be: Mutex<HashMap<ClientId, EffectiveAction>>,
    /// Active enforcer.
    enforcer: Mutex<Option<Arc<dyn Enforcer>>>,
    /// Started at (reserved for uptime in `info`).
    #[allow(dead_code)]
    pub started: Instant,
}

impl DaemonState {
    /// Construct.
    #[must_use]
    pub fn new(mode: Mode, interface: String, live: LiveConfig) -> Self {
        Self {
            mode,
            interface,
            live: ArcSwap::from_pointee(live),
            policies: Mutex::new(HashMap::new()),
            windows: Mutex::new(HashMap::new()),
            counters: CounterStore::default(),
            last_counters: Mutex::new(HashMap::new()),
            would_be: Mutex::new(HashMap::new()),
            enforcer: Mutex::new(None),
            started: Instant::now(),
        }
    }

    /// Set enforcer.
    pub fn set_enforcer(&self, e: Arc<dyn Enforcer>) {
        *self.enforcer.lock() = Some(e);
    }

    /// Apply via enforcer (and record would-be in permissive mode).
    pub fn apply(&self, client: ClientId, action: EffectiveAction) {
        if self.mode == Mode::Permissive {
            self.would_be.lock().insert(client, action);
        }
        if let Some(e) = self.enforcer.lock().as_ref() {
            e.apply(client, action);
        }
    }

    /// Clear enforcement.
    pub fn clear(&self, client: ClientId) {
        self.would_be.lock().remove(&client);
        if let Some(e) = self.enforcer.lock().as_ref() {
            e.clear(client);
        }
    }

    /// Current rule set.
    #[must_use]
    pub fn rules(&self) -> Arc<RuleSet> {
        Arc::clone(&self.live.load().rules)
    }

    /// Current sets.
    #[must_use]
    pub fn sets(&self) -> SetsConfig {
        self.live.load().sets.clone()
    }

    /// Daemon config snapshot.
    #[must_use]
    pub fn daemon_cfg(&self) -> DaemonConfig {
        self.live.load().daemon.clone()
    }

    /// Allow users.
    #[must_use]
    pub fn allow_users(&self) -> Vec<String> {
        self.daemon_cfg().allow_users
    }

    /// Swap live config.
    pub fn swap_live(&self, live: LiveConfig) {
        self.live.store(Arc::new(live));
    }
}
