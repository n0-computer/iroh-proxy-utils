//! Utilities for HTTP proxying over iroh connections.

/// Downstream proxying from TCP clients to iroh endpoints.
pub mod downstream;
mod parse;
/// Upstream proxying from iroh streams to TCP origins.
pub mod upstream;
mod util;

pub use parse::{
    Authority, HttpOriginRequest, HttpProxyRequest, HttpProxyRequestKind, HttpRequest,
    HttpRequestKind, HttpResponse,
};

/// How much data to read for the CONNECT handshake before it's considered invalid.
pub(crate) const HEADER_SECTION_MAX_LENGTH: usize = 8192;

/// HTTP header used to carry iroh destination metadata.
pub const IROH_DESTINATION_HEADER: &str = "Iroh-Destination";
/// ALPN identifier for the iroh HTTP proxy protocol.
pub const ALPN: &[u8] = b"iroh-http-proxy";

#[cfg(test)]
mod tests;
