use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use iroh_metrics::Counter;

use crate::Authority;

/// Aggregate metrics for an [`super::UpstreamProxy`] instance.
///
/// Tracks connection and request counts across all targets, and provides
/// access to per-target metrics via [`Metrics::get`] and [`Metrics::for_each`].
#[derive(Debug, Default)]
pub struct UpstreamMetrics {
    targets: RwLock<BTreeMap<Authority, Arc<TargetMetrics>>>,
    pub(super) connections_accepted: Counter,
    pub(super) connections_completed: Counter,
    pub(super) requests_accepted: Counter,
    pub(super) requests_denied: Counter,
    pub(super) requests_completed: Counter,
    pub(super) requests_failed: Counter,
}

impl UpstreamMetrics {
    /// Returns the total number of denied requests across all targets.
    pub fn denied_requests(&self) -> u64 {
        self.requests_denied.get()
    }

    /// Returns the total number of accepted requests across all targets.
    pub fn accepted_requests(&self) -> u64 {
        self.requests_accepted.get()
    }

    /// Returns the estimated number of currently in-flight requests.
    ///
    /// Uses saturating arithmetic since counters are read non-atomically.
    pub fn active_requests(&self) -> u64 {
        self.requests_accepted
            .get()
            .saturating_sub(self.requests_completed.get())
            .saturating_sub(self.requests_failed.get())
    }

    /// Returns the estimated number of currently open iroh connections.
    ///
    /// Uses saturating arithmetic since counters are read non-atomically.
    pub fn active_iroh_connections(&self) -> u64 {
        self.connections_accepted
            .get()
            .saturating_sub(self.connections_completed.get())
    }

    /// Returns the total number of iroh connections ever accepted.
    pub fn total_iroh_connections(&self) -> u64 {
        self.connections_accepted.get()
    }

    /// Returns the per-target metrics for `target`, if any requests have been made to it.
    pub fn get(&self, target: &Authority) -> Option<Arc<TargetMetrics>> {
        let inner = self.targets.read().expect("poisoned");
        inner.get(target).cloned()
    }

    pub(super) fn get_or_insert(&self, target: Authority) -> Arc<TargetMetrics> {
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

    /// Calls `f` for each tracked target and its metrics.
    ///
    /// Holds a read lock on the target map for the duration of the call.
    pub fn for_each(&self, f: impl Fn(&Authority, &TargetMetrics)) {
        let inner = self.targets.read().expect("poisoned");
        for (k, v) in inner.iter() {
            f(k, v);
        }
    }
}

/// Per-target metrics tracked by the upstream proxy.
///
/// Each request increments:
/// - either `requests_accepted` or `requests_denied`
/// - on completion: either `requests_failed` or `requests_completed`
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
    /// Returns the number of requests denied by the auth handler for this target.
    pub fn denied_requests(&self) -> u64 {
        self.requests_denied.get()
    }

    /// Returns the number of requests accepted by the auth handler for this target.
    pub fn accepted_requests(&self) -> u64 {
        self.requests_accepted.get()
    }

    /// Returns the number of requests that failed (connection error, origin unreachable, etc.).
    pub fn failed_requests(&self) -> u64 {
        self.requests_failed.get()
    }

    /// Returns the estimated number of currently in-flight requests for this target.
    ///
    /// Uses saturating arithmetic since counters are read non-atomically.
    pub fn active_requests(&self) -> u64 {
        self.requests_accepted
            .get()
            .saturating_sub(self.requests_completed.get())
            .saturating_sub(self.requests_failed.get())
    }

    /// Returns the total bytes sent to the origin server for this target.
    pub fn bytes_to_origin(&self) -> u64 {
        self.bytes_to_origin.get()
    }

    /// Returns the total bytes received from the origin server for this target.
    pub fn bytes_from_origin(&self) -> u64 {
        self.bytes_from_origin.get()
    }
}
