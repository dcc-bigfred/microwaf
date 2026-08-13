//! Decision loop: counters → windows → RuleEngine → Enforcer.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use mw_core::policy::{merge_policy, strongest_auto, EffectiveAction};
use mw_core::rule::{Metric, RuleEngine};

use crate::cli::daemon::StoreBackend;
use crate::state::DaemonState;
use crate::store;

/// Run the decision loop until process exit.
pub fn run(state: Arc<DaemonState>, store: StoreBackend) {
    let mut last_snapshot = Instant::now();
    loop {
        let tick_start = Instant::now();
        tick(&state);

        let snapshot_secs = state.daemon_cfg().stats_snapshot_secs.max(1);
        if last_snapshot.elapsed() >= Duration::from_secs(snapshot_secs) {
            if let Err(e) = store::snapshot_stats(&state, store.as_stats()) {
                warn!(error = %e, "stats snapshot failed");
            }
            last_snapshot = Instant::now();
        }

        let sleep = Duration::from_secs(1).saturating_sub(tick_start.elapsed());
        std::thread::sleep(sleep);
    }
}

fn tick(state: &DaemonState) {
    let now = Instant::now();
    let rules = state.rules();
    let engine = RuleEngine::new(Arc::clone(&rules));
    let cooldown = Duration::from_secs(state.daemon_cfg().cooldown_secs.max(1));

    let snapshot = state.counters.snapshot_rules();
    let mut last = state.last_counters.lock();
    let mut windows = state.windows.lock();
    let mut policies = state.policies.lock();

    // Collect clients touched this tick
    let mut clients: std::collections::HashSet<_> = snapshot.keys().map(|k| k.client).collect();
    clients.extend(policies.keys().copied());

    for client in clients {
        let win = windows.entry(client).or_default();
        win.advance_all(now);

        // Apply deltas for this client's rules
        for (key, &(req, bytes, conn)) in &snapshot {
            if key.client != client {
                continue;
            }
            let prev = last.get(key).copied().unwrap_or((0, 0, 0));
            let d_req = req.saturating_sub(prev.0);
            let d_bytes = bytes.saturating_sub(prev.1);
            let d_conn = conn.saturating_sub(prev.2);
            if d_req > 0 {
                win.add(&key.rule_id, Metric::Requests, d_req, now);
            }
            if d_bytes > 0 {
                win.add(&key.rule_id, Metric::Bytes, d_bytes, now);
            }
            if d_conn > 0 {
                win.add(&key.rule_id, Metric::Connections, d_conn, now);
            }
        }

        let violations = engine.evaluate(win);
        let policy = policies.entry(client).or_default();
        if let Some(auto) = strongest_auto(&violations, now, cooldown) {
            policy.auto = Some(auto);
        } else if policy.auto.as_ref().is_some_and(|a| a.is_expired(now)) {
            policy.auto = None;
        }
        if policy.manual.as_ref().is_some_and(|m| m.is_expired(now)) {
            policy.manual = None;
        }

        let effective = merge_policy(policy, now);
        match effective {
            EffectiveAction::None => state.clear(client),
            other => {
                debug!(%client, ?other, "apply policy");
                state.apply(client, other);
            }
        }
    }

    *last = snapshot;
}
