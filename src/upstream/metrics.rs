use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use iroh_metrics::Counter;

use crate::parse::ProxyTargetId;

#[derive(Debug, Default)]
pub struct Metrics {
    targets: RwLock<BTreeMap<ProxyTargetId, Arc<TargetMetrics>>>,
    pub(super) connections_accepted: Counter,
    pub(super) connections_completed: Counter,
    pub(super) requests_accepted: Counter,
    pub(super) requests_denied: Counter,
    pub(super) requests_completed: Counter,
}

impl Metrics {
    pub fn denied_requests(&self) -> u64 {
        self.requests_denied.get()
    }

    pub fn accepted_requests(&self) -> u64 {
        self.requests_accepted.get()
    }

    pub fn active_requests(&self) -> u64 {
        self.requests_accepted.get() - self.requests_completed.get()
    }

    pub fn active_iroh_connections(&self) -> u64 {
        self.connections_accepted.get() - self.connections_completed.get()
    }

    pub fn total_iroh_connections(&self) -> u64 {
        self.connections_accepted.get()
    }

    pub fn get(&self, target: &ProxyTargetId) -> Option<Arc<TargetMetrics>> {
        let inner = self.targets.read().expect("poisoned");
        inner.get(target).cloned()
    }

    pub(super) fn get_or_insert(&self, target: ProxyTargetId) -> Arc<TargetMetrics> {
        {
            let inner = self.targets.read().expect("poisoned");
            if let Some(value) = inner.get(&target) {
                return value.clone();
            }
        }
        let mut inner = self.targets.write().expect("poisoned");
        let value = inner.entry(target).or_default();
        value.clone()
    }

    pub fn iter(&self, f: impl Fn(&ProxyTargetId, &TargetMetrics)) {
        let inner = self.targets.read().expect("poisoned");
        for (k, v) in inner.iter() {
            f(k, v);
        }
    }
}

/// Counters for individual targets.
///
/// Each request increments:
/// - either `requests_accepted` or `requests_denied`
/// - either `requests_failed` or `requests_completed`
#[derive(Default, Debug)]
pub struct TargetMetrics {
    pub(super) requests_accepted: Counter,
    pub(super) requests_denied: Counter,
    pub(super) requests_completed: Counter,
    pub(super) requests_failed: Counter,
    pub(super) bytes_to_origin: Counter,
    pub(super) bytes_from_origin: Counter,
}

impl TargetMetrics {
    pub fn denied_requests(&self) -> u64 {
        self.requests_denied.get()
    }

    pub fn accepted_requests(&self) -> u64 {
        self.requests_accepted.get()
    }

    pub fn failed_requests(&self) -> u64 {
        self.requests_failed.get()
    }

    pub fn active_requests(&self) -> u64 {
        self.requests_accepted.get() - self.requests_completed.get() - self.requests_failed.get()
    }

    pub fn bytes_to_origin(&self) -> u64 {
        self.bytes_to_origin.get()
    }

    pub fn bytes_from_origin(&self) -> u64 {
        self.bytes_from_origin.get()
    }
}
