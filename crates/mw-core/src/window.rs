//! Sliding windows per (client, rule).

use std::collections::HashMap;
use std::time::Instant;

use crate::rule::{Metric, RuleId};

/// One 1-second bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bucket {
    /// Requests / records / frames / lines.
    pub requests: u64,
    /// Bytes.
    pub bytes: u64,
    /// Connections / flows.
    pub connections: u64,
}

impl Bucket {
    /// Metric value.
    #[must_use]
    pub fn get(self, metric: Metric) -> u64 {
        match metric {
            Metric::Requests => self.requests,
            Metric::Bytes => self.bytes,
            Metric::Connections => self.connections,
        }
    }

    /// Add delta for a metric.
    pub fn add(&mut self, metric: Metric, delta: u64) {
        match metric {
            Metric::Requests => self.requests = self.requests.saturating_add(delta),
            Metric::Bytes => self.bytes = self.bytes.saturating_add(delta),
            Metric::Connections => self.connections = self.connections.saturating_add(delta),
        }
    }
}

/// 60×1s sliding window for one (client, rule).
#[derive(Debug, Clone)]
pub struct SlidingWindow {
    /// Buckets.
    pub buckets: [Bucket; 60],
    /// Current cursor.
    pub cursor: usize,
    /// Last advance time.
    pub last_advance: Instant,
}

impl SlidingWindow {
    /// New window starting at `now`.
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self {
            buckets: [Bucket::default(); 60],
            cursor: 0,
            last_advance: now,
        }
    }

    /// Advance empty buckets for elapsed whole seconds.
    pub fn advance(&mut self, now: Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_advance)
            .as_secs() as usize;
        if elapsed == 0 {
            return;
        }
        let steps = elapsed.min(60);
        for _ in 0..steps {
            self.cursor = (self.cursor + 1) % 60;
            self.buckets[self.cursor] = Bucket::default();
        }
        self.last_advance = now;
    }

    /// Add a delta into the current bucket.
    pub fn add(&mut self, metric: Metric, delta: u64, now: Instant) {
        self.advance(now);
        self.buckets[self.cursor].add(metric, delta);
    }

    /// Sum metric over the last `secs` buckets (1..=60).
    #[must_use]
    pub fn sum(&self, metric: Metric, secs: usize) -> u64 {
        let n = secs.clamp(1, 60);
        let mut total = 0u64;
        for i in 0..n {
            let idx = (self.cursor + 60 - i) % 60;
            total = total.saturating_add(self.buckets[idx].get(metric));
        }
        total
    }
}

/// Per-rule windows for one client.
#[derive(Debug, Clone, Default)]
pub struct RuleWindows {
    /// Lazily created windows.
    pub by_rule: HashMap<RuleId, SlidingWindow>,
}

impl RuleWindows {
    /// Ensure window exists and add delta.
    pub fn add(&mut self, rule_id: &str, metric: Metric, delta: u64, now: Instant) {
        self.by_rule
            .entry(rule_id.to_string())
            .or_insert_with(|| SlidingWindow::new(now))
            .add(metric, delta, now);
    }

    /// Sum for a rule (0 if absent).
    #[must_use]
    pub fn sum(&self, rule_id: &str, metric: Metric, secs: usize) -> u64 {
        self.by_rule
            .get(rule_id)
            .map_or(0, |w| w.sum(metric, secs))
    }

    /// Advance all windows.
    pub fn advance_all(&mut self, now: Instant) {
        for w in self.by_rule.values_mut() {
            w.advance(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn sum_one_second() {
        let now = Instant::now();
        let mut w = SlidingWindow::new(now);
        w.add(Metric::Requests, 5, now);
        assert_eq!(w.sum(Metric::Requests, 1), 5);
        assert_eq!(w.sum(Metric::Bytes, 1), 0);
    }

    #[test]
    fn advance_zeros_old_bucket() {
        let now = Instant::now();
        let mut w = SlidingWindow::new(now);
        w.add(Metric::Requests, 7, now);
        let later = now + Duration::from_secs(1);
        w.advance(later);
        assert_eq!(w.sum(Metric::Requests, 1), 0);
        assert_eq!(w.sum(Metric::Requests, 2), 7);
    }
}
