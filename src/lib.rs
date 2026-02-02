//! HTTP proxy utilities for [iroh](https://github.com/n0-computer/iroh) connections.
//!
//! This crate provides building blocks for HTTP proxies that bridge TCP traffic over
//! iroh's peer-to-peer QUIC connections. It supports both forward and reverse proxy
//! modes, with pluggable request routing and authorization.
//!
//! # Architecture
//!
//! The proxy operates in two layers:
//!
//! - **Downstream proxy** ([`downstream::DownstreamProxy`]): Accepts TCP connections from
//!   clients and forwards them over iroh to an upstream proxy.
//! - **Upstream proxy** ([`upstream::UpstreamProxy`]): Receives proxied streams from iroh
//!   and forwards them to origin TCP servers.
//!
//! # Protocol
//!
//! Communication between downstream and upstream uses HTTP/1.1 over QUIC bidirectional
//! streams. The protocol supports:
//!
//! - **CONNECT tunneling** (RFC 9110 §9.3.6): For opaque TCP tunnels
//! - **Absolute-form requests** (RFC 9110 §7.1): For HTTP forward proxying
//!
//! # Example
//!
//! See the `examples/` directory for complete usage examples.

/// Downstream proxying from TCP clients to iroh endpoints.
pub mod downstream;
mod parse;
/// Upstream proxying from iroh streams to TCP origins.
pub mod upstream;
mod util;

pub use parse::{
    Authority, HttpProxyRequest, HttpProxyRequestKind, HttpRequest, HttpRequestKind, HttpResponse,
};

/// Maximum bytes to buffer when reading HTTP header sections.
///
/// Requests or responses with header sections exceeding this limit are rejected
/// to prevent memory exhaustion attacks.
pub(crate) const HEADER_SECTION_MAX_LENGTH: usize = 8192;

/// HTTP header for routing requests to specific iroh endpoints.
///
/// When using dynamic routing, downstream proxies can read this header to
/// determine which upstream endpoint should handle the request.
pub const IROH_DESTINATION_HEADER: &str = "Iroh-Destination";

/// ALPN protocol identifier for iroh HTTP proxy connections.
///
/// Both downstream and upstream proxies must use this ALPN to establish
/// compatible QUIC connections.
pub const ALPN: &[u8] = b"iroh-http-proxy/1";

#[cfg(test)]
mod tests;
