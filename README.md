# iroh-proxy-utils

![CI](https://github.com/n0-computer/iroh-proxy-utils/actions/workflows/ci.yml/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/iroh-proxy-utils.svg)](https://crates.io/crates/iroh-proxy-utils)
[![Documentation](https://docs.rs/iroh-proxy-utils/badge.svg)](https://docs.rs/redb)
[![License](https://img.shields.io/crates/l/iroh-proxy-utils)](https://crates.io/crates/redb)

Primitives for TCP and HTTP proxying over [iroh](https://github.com/n0-computer/iroh) connections.

## Status

Work in progress. API subject to change.

## Overview

This crate provides two main components for building HTTP proxies that bridge TCP and HTTP over iroh:

* The **DownstreamProxy** accepts TCP connections and forwards them over iroh. Supports both forward proxy mode (client specifies destination via absolute-form requests or HTTP `CONNECT`) and reverse proxy mode (destination extracted from origin-form requests). For all modes, the upstream proxy's iroh endpoint id is either set statically in the proxy configuration, or extracted from the HTTP request. Destination extraction is provided via a trait that must be implemented by user code.

* The **UpstreamProxy** implements an iroh `ProtocolHandler` that accepts proxied streams from iroh connections, authorizes them via a pluggable `AuthHandler`, and forwards to TCP origins. Handles both CONNECT tunneling and absolute-form HTTP requests.

## Protocol

The downstream and upstream proxy establish iroh connections with the ALPN identifier `iroh-http-proxy/1`. On each connections, the downstream proxy can open any number of bidirectional streams. Each bidirectional stream contains a HTTP/1.1 connection. Each of these may either be a `CONNECT` request to establish a tunnel to an origin from the upstream proxy, or a absolute-form request which is forwarded to its origin by the upstream proxy.

## License

Copyright 2025 N0, INC.

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
