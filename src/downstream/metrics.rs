use iroh_metrics::{Counter, MetricsGroup};

#[derive(Debug, MetricsGroup)]
#[non_exhaustive]
#[metrics(name = "proxy-downstream", default)]
pub struct DownstreamMetrics {
    /// Total number of downstream requests that began processing (HTTP or TCP).
    pub requests_accepted: Counter,

    /// TCP-only requests (proxy is operating in `ProxyMode::Tcp`).
    pub requests_accepted_tcp: Counter,
    /// HTTP/1 requests that reached the downstream proxy.
    pub requests_accepted_h1: Counter,
    /// HTTP/2 requests that reached the downstream proxy.
    pub requests_accepted_h2: Counter,

    /// HTTP/1 CONNECT requests, i.e. e2e tunnels.
    pub requests_accepted_h1_connect: Counter,
    /// HTTP/1 upgrade requests (WebSocket, etc.) that were forwarded.
    pub requests_accepted_h1_upgrade: Counter,

    /// HTTP/2 CONNECT requests (excluding extended CONNECT), i.e. e2e tunnels.
    pub requests_accepted_h2_connect: Counter,
    /// HTTP/2 extended CONNECT requests (RFC 8441), i.e. WebSocket over HTTP/2.
    pub requests_accepted_h2_extended_connect: Counter,

    /// Requests rejected by the `RequestHandler` before opening an upstream tunnel.
    pub requests_denied: Counter,
    /// Requests that successfully finished and were proxied upstream.
    pub requests_completed: Counter,
    /// Requests that failed after being accepted (upstream or network error).
    pub requests_failed: Counter,

    /// Number of QUIC connections opened toward upstream iroh nodes.
    pub iroh_connections_opened: Counter,
    /// Connections that closed cleanly from the local side (pool dropped conn after idle timeout)
    pub iroh_connections_closed_idle: Counter,
    /// Connections that terminated with an error (timeouts, transport errors, resets).
    pub iroh_connections_closed_error: Counter,

    /// Bytes written to the upstream proxy (downstream ➜ upstream).
    pub bytes_to_upstream: Counter,
    /// Bytes read from the upstream proxy (upstream ➜ downstream).
    pub bytes_from_upstream: Counter,
}

impl DownstreamMetrics {
    /// Returns the number of requests currently in flight.
    ///
    /// Calculated as `accepted - completed - failed` using saturating arithmetic.
    pub fn active_requests(&self) -> u64 {
        self.requests_accepted
            .get()
            .saturating_sub(self.requests_completed.get())
            .saturating_sub(self.requests_failed.get())
    }

    /// Returns the total number of opened QUIC connections.
    pub fn total_iroh_connections(&self) -> u64 {
        self.iroh_connections_opened.get()
    }

    /// Returns the estimated number of currently open QUIC connections.
    pub fn active_iroh_connections(&self) -> u64 {
        self.iroh_connections_opened
            .get()
            .saturating_sub(self.iroh_connections_closed_idle.get())
            .saturating_sub(self.iroh_connections_closed_error.get())
    }
}
