use std::{net::SocketAddr, str::FromStr};

use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version,
    header::{self, InvalidHeaderValue},
    uri::{Scheme, Uri},
};
use n0_error::{Result, StackResultExt, StdResultExt, anyerr, ensure_any};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::util::Prebuffered;

/// Hop-by-hop headers that MUST NOT be forwarded by proxies per RFC 9110 Section 7.6.1.
const HOP_BY_HOP_HEADERS: &[HeaderName] = &[
    header::CONNECTION,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

/// Headers listed in the Connection header should also be removed.
const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");

/// Removes hop-by-hop headers from a HeaderMap per RFC 9110 Section 7.6.1.
///
/// This removes:
/// - Connection and headers listed in the Connection header value
/// - Proxy-Authenticate, Proxy-Authorization
/// - TE, Trailer, Transfer-Encoding, Upgrade
/// - Keep-Alive
pub fn filter_hop_by_hop_headers(headers: &mut HeaderMap<HeaderValue>) {
    // First, collect any header names listed in the Connection header
    let connection_headers: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|name| name.trim().parse::<HeaderName>().ok())
        .collect();

    // Remove the standard hop-by-hop headers
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }

    // Remove Keep-Alive (not in http crate's header constants)
    headers.remove(&KEEP_ALIVE);

    // Remove any headers that were listed in the Connection header
    for name in connection_headers {
        headers.remove(&name);
    }
}

/// Host and port authority parsed from HTTP request targets.
#[derive(Debug, Clone, derive_more::Display)]
#[display("{host}:{port}")]
pub struct Authority {
    /// Hostname or IP literal without scheme.
    pub host: String,
    /// Port number in host byte order.
    pub port: u16,
}

impl FromStr for Authority {
    type Err = n0_error::AnyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_authority_str(s)
    }
}

impl Authority {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }

    /// Parses an authority-form URI with no scheme and no path.
    ///
    /// Note: the URI must include a port.
    pub fn from_authority_uri(uri: &Uri) -> Result<Self> {
        ensure_any!(uri.scheme().is_none(), "Expected URI without scheme");
        ensure_any!(uri.path_and_query().is_none(), "Expected URI without path");
        let authority = uri.authority().context("Expected URI with authority")?;
        let host = authority.host();
        let port = authority.port_u16().context("Expected URI with port")?;
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }

    /// Parses an absolute-form URI and infers the port from the scheme.
    ///
    /// Note: if no port is present, only `http` and `https` schemes are accepted.
    pub fn from_absolute_uri(uri: &Uri) -> Result<Self> {
        let authority = uri.authority().context("Expected URI with authority")?;
        let host = authority.host();
        let port = match authority.port_u16() {
            Some(port) => port,
            None => match uri.scheme() {
                Some(scheme) if *scheme == Scheme::HTTP => 80,
                Some(scheme) if *scheme == Scheme::HTTPS => 443,
                _ => Err(anyerr!("Expected URI to with port or http(s) scheme"))?,
            },
        };
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }

    /// Parses an authority-form request target from a string.
    pub fn from_authority_str(s: &str) -> Result<Self> {
        Self::from_authority_uri(&Uri::from_str(s).std_context("Invalid authority string")?)
    }

    /// Parses an absolute-form request target from a string.
    pub fn from_absolute_uri_str(s: &str) -> Result<Self> {
        Self::from_absolute_uri(&Uri::from_str(s).std_context("Invalid authority string")?)
    }

    pub(super) fn to_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub(crate) fn to_connect_request(&self) -> String {
        let host = &self.host;
        let port = &self.port;
        format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n")
    }
}

#[derive(Debug)]
pub struct HttpRequest {
    pub version: Version,
    pub headers: HeaderMap<HeaderValue>,
    pub uri: Uri,
    pub method: Method,
}

const X_FORWARDED_FOR: &str = "x-forwarded-for";
const X_FORWARDED_HOST: &str = "x-forwarded-host";

impl HttpRequest {
    pub fn from_parts(parts: http::request::Parts) -> Self {
        Self {
            version: parts.version,
            headers: parts.headers,
            method: parts.method,
            uri: parts.uri,
        }
    }

    /// Parses a request from a buffer and returns `None` when incomplete.
    ///
    /// Returns the length of the header section and the request.
    pub fn parse_with_len(buf: &[u8]) -> Result<Option<(usize, Self)>> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(buf).std_context("Invalid HTTP request")? {
            httparse::Status::Partial => Ok(None),
            httparse::Status::Complete(header_len) => {
                Self::from_parsed_request(req).map(|req| Some((header_len, req)))
            }
        }
    }

    pub fn from_parsed_request(req: httparse::Request) -> Result<Self> {
        let method_str = req.method.context("Missing HTTP method")?;
        let method = method_str.parse().std_context("Invalid HTTP method")?;
        let path = req.path.context("Missing request target")?;
        let uri = Uri::from_str(path).std_context("Invalid request target")?;
        let headers = HeaderMap::from_iter(req.headers.iter_mut().flat_map(|h| {
            let value = HeaderValue::from_bytes(h.value).ok()?;
            let name = http::HeaderName::from_bytes(h.name.as_bytes()).ok()?;
            Some((name, value))
        }));
        let version = if req.version == Some(1) {
            http::Version::HTTP_11
        } else {
            http::Version::HTTP_10
        };
        Ok(Self {
            version,
            headers,
            uri,
            method,
        })
    }

    /// Reads and parses the request line and header section.
    ///
    /// Does not remove the header section from `reader`.
    /// Returns the length of the header section and the request.
    /// Returns [`io::ErrorKind::OutOfMemory`] if the header section exceeds the buffer limit.
    pub async fn peek(reader: &mut Prebuffered<impl AsyncRead + Unpin>) -> Result<(usize, Self)> {
        while !reader.is_full() {
            reader.buffer_more().await?;
            tracing::debug!(l=reader.buffer().len(), s=%String::from_utf8_lossy(reader.buffer()), "HttpRequest::peek");
            if let Some(request) = Self::parse_with_len(reader.buffer())? {
                return Ok(request);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "Buffer size limit reached before end of request header section",
        )
        .into())
    }

    /// Reads and parses the request line and header section.
    ///
    /// Removes the header section from `reader`.
    /// Returns [`io::ErrorKind::OutOfMemory`] if the header section exceeds the buffer limit.
    pub async fn read(reader: &mut Prebuffered<impl AsyncRead + Unpin>) -> Result<Self> {
        let (len, response) = Self::peek(reader).await?;
        reader.discard(len);
        Ok(response)
    }

    /// Parses a request from a buffer and returns `None` when incomplete.
    ///
    /// Returns the length of the header section and the request.
    pub fn parse(buf: &[u8]) -> Result<Option<Self>> {
        Ok(Self::parse_with_len(buf)?.map(|(_len, req)| req))
    }

    /// Converts to a proxy request when the target is authority-form or absolute-form.
    ///
    /// Note: origin-form requests return an error.
    pub fn try_into_proxy_request(self) -> Result<HttpProxyRequest> {
        let kind = match self.method {
            Method::CONNECT => {
                let target = Authority::from_authority_uri(&self.uri)?;
                HttpProxyRequestKind::Tunnel { target }
            }
            _ => {
                if self.uri.scheme().is_none() || self.uri.authority().is_none() {
                    return Err(anyerr!("Missing absolute-form request target"));
                }
                let target = self.uri.to_string();
                HttpProxyRequestKind::Absolute {
                    target,
                    method: self.method,
                }
            }
        };
        Ok(HttpProxyRequest {
            headers: self.headers,
            kind,
        })
    }

    pub fn host(&self) -> Option<&str> {
        self.headers
            .get(http::header::HOST)
            .and_then(|x| x.to_str().ok())
    }

    /// Classify into a kind based on the request kind.
    ///
    /// Returns an error for invalid combinations:
    /// - CONNECT request without authority-form target
    pub fn classify(&self) -> Result<HttpRequestKind> {
        match self.method {
            Method::CONNECT => {
                if self.uri.scheme().is_some()
                    || self.uri.path_and_query().is_some()
                    || self.uri.authority().is_none()
                    || self.uri.authority().and_then(|a| a.port_u16()).is_none()
                {
                    Err(anyerr!("Invalid request-target form for CONNECT request"))
                } else {
                    Ok(HttpRequestKind::Tunnel)
                }
            }
            _ => {
                // Absolute-form requests are only support for HTTP/1. In HTTP/2, absolute-form and origin-form
                // requests are indistinguishable, so we always report origin-form.
                if self.uri.scheme().is_some() && self.version < Version::HTTP_2 {
                    Ok(HttpRequestKind::Absolute)
                } else {
                    Ok(HttpRequestKind::Origin)
                }
            }
        }
    }

    pub fn set_forwarded_for(&mut self, src_addr: SocketAddr) -> &mut Self {
        self.headers.append(
            X_FORWARDED_FOR,
            HeaderValue::from_str(&src_addr.to_string()).expect("valid header value"),
        );
        self
    }

    pub fn set_via(
        &mut self,
        pseudonym: impl std::fmt::Display,
    ) -> Result<&mut Self, InvalidHeaderValue> {
        self.headers.append(
            header::VIA,
            HeaderValue::from_str(&format!("{:?} {}", self.version, pseudonym))?,
        );
        Ok(self)
    }

    pub fn set_target(&mut self, target: Uri) -> Result<&mut Self, InvalidHeaderValue> {
        if let Some(original_host) = self.headers.remove(header::HOST) {
            self.headers.insert(X_FORWARDED_HOST, original_host);
        }
        if let Some(authority) = target.authority() {
            self.headers
                .insert(header::HOST, HeaderValue::from_str(authority.as_str())?);
        }
        self.uri = target;
        Ok(self)
    }

    pub fn set_absolute_http_authority(&mut self, authority: Authority) -> Result<&mut Self> {
        let mut parts = self.uri.clone().into_parts();
        parts.authority = Some(authority.to_string().parse().anyerr()?);
        parts.scheme = Some(Scheme::HTTP);
        let uri = Uri::from_parts(parts).anyerr()?;
        self.set_target(uri).anyerr()?;
        Ok(self)
    }

    pub(crate) async fn write(
        self,
        writer: &mut (impl AsyncWrite + Send + Unpin),
    ) -> io::Result<()> {
        let Self {
            method,
            uri,
            headers,
            ..
        } = self;
        writer.write_all(method.as_str().as_bytes()).await?;
        writer.write_all(b" ").await?;
        if let Some(s) = uri.scheme() {
            writer.write_all(s.as_str().as_bytes()).await?;
            writer.write_all(b"://").await?;
        }
        if let Some(s) = uri.authority() {
            writer.write_all(s.as_str().as_bytes()).await?;
        }
        writer.write_all(uri.path().as_bytes()).await?;
        if let Some(s) = uri.query() {
            writer.write_all(b"?").await?;
            writer.write_all(s.as_bytes()).await?;
        }
        writer.write_all(b" HTTP/1.1\r\n").await?;
        for (key, value) in headers.iter() {
            writer.write_all(key.as_str().as_bytes()).await?;
            writer.write_all(b": ").await?;
            writer.write_all(value.as_bytes()).await?;
            writer.write_all(b"\r\n").await?;
        }
        writer.write_all(b"\r\n").await?;
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum HttpRequestKind {
    Tunnel,
    Absolute,
    Origin,
}

/// Proxy request targets per RFC 9110.
#[derive(Debug)]
pub enum HttpProxyRequestKind {
    /// Tunnel CONNECT request with authority-form request target.
    Tunnel { target: Authority },
    /// Forward-proxy request with absolute-form request target.
    Absolute { target: String, method: Method },
}

/// Parsed HTTP proxy request with headers.
#[derive(derive_more::Debug)]
pub struct HttpProxyRequest {
    /// Parsed proxy request target.
    pub kind: HttpProxyRequestKind,
    /// Raw header map as received.
    pub headers: HeaderMap<http::HeaderValue>,
}

/// Parsed HTTP response with status, reason, and headers.
#[derive(derive_more::Debug)]
pub struct HttpResponse {
    /// Status code from the response line.
    pub status: StatusCode,
    /// Reason phrase if present.
    pub reason: Option<String>,
    /// Raw header map as received.
    pub headers: HeaderMap<http::HeaderValue>,
}

impl HttpResponse {
    pub(crate) fn new(status: StatusCode) -> Self {
        Self {
            status,
            reason: None,
            headers: HeaderMap::new(),
        }
    }

    pub(crate) fn with_reason(status: StatusCode, reason: impl ToString) -> Self {
        Self {
            status,
            reason: Some(reason.to_string()),
            headers: HeaderMap::new(),
        }
    }

    pub(crate) fn no_body(mut self) -> Self {
        self.headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str("0").unwrap(),
        );
        self
    }

    pub(crate) async fn write(
        &self,
        writer: &mut (impl AsyncWrite + Send + Unpin),
        finalize: bool,
    ) -> io::Result<()> {
        writer.write_all(self.status_line().as_bytes()).await?;
        for (key, value) in self.headers.iter() {
            writer.write_all(key.as_str().as_bytes()).await?;
            writer.write_all(b": ").await?;
            writer.write_all(value.as_bytes()).await?;
            writer.write_all(b"\r\n").await?;
        }
        if finalize {
            writer.write_all(b"\r\n").await?;
        }
        Ok(())
    }

    /// Returns the reason phrase or a canonical reason if available.
    pub fn reason(&self) -> &str {
        self.reason
            .as_deref()
            .or(self.status.canonical_reason())
            .unwrap_or("")
    }

    /// Formats a status line suitable for an HTTP/1.x response.
    pub fn status_line(&self) -> String {
        format!(
            "HTTP/1.1 {} {}\r\n",
            self.status.as_u16(),
            self.reason
                .as_deref()
                .or(self.status.canonical_reason())
                .unwrap_or("")
        )
    }

    /// Parses a response from a buffer and returns `None` when incomplete.
    pub fn parse(buf: &[u8]) -> Result<Option<Self>> {
        Ok(Self::parse_with_len(buf)?.map(|(_len, res)| res))
    }

    /// Parses a response from a buffer and returns `None` when incomplete.
    ///
    /// Returns the length of the header section and the response.
    pub fn parse_with_len(buf: &[u8]) -> Result<Option<(usize, Self)>> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut res = httparse::Response::new(&mut headers);
        match res
            .parse(buf)
            .std_context("Failed to parse HTTP response")?
        {
            httparse::Status::Partial => Ok(None),
            httparse::Status::Complete(header_len) => {
                let code = res.code.context("Missing response status code")?;
                let status =
                    StatusCode::from_u16(code).std_context("Invalid response status code")?;
                let reason = res.reason.map(ToOwned::to_owned);
                let headers = HeaderMap::from_iter(res.headers.iter().flat_map(|h| {
                    let value = HeaderValue::from_bytes(h.value).ok()?;
                    let name = http::HeaderName::from_bytes(h.name.as_bytes()).ok()?;
                    Some((name, value))
                }));
                Ok(Some((
                    header_len,
                    HttpResponse {
                        status,
                        reason,
                        headers,
                    },
                )))
            }
        }
    }

    /// Reads and parses the response status line and header section.
    ///
    /// Does not remove the header section from `reader`.
    /// Returns [`io::ErrorKind::OutOfMemory`] if the header section exceeds the buffer limit.
    pub async fn peek(reader: &mut Prebuffered<impl AsyncRead + Unpin>) -> Result<(usize, Self)> {
        while !reader.is_full() {
            reader.buffer_more().await?;
            tracing::info!(
                len = reader.buffer().len(),
                b = %String::from_utf8_lossy(reader.buffer()),
                "Response::peek"
            );
            if let Some(response) = Self::parse_with_len(reader.buffer())? {
                return Ok(response);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "Buffer size limit reached before end of response header section",
        )
        .into())
    }

    /// Reads and parses the response status line and header section.
    ///
    /// Removes the header section from the reader.
    pub async fn read(reader: &mut Prebuffered<impl AsyncRead + Unpin>) -> Result<Self> {
        let (len, response) = Self::peek(reader).await?;
        reader.discard(len);
        Ok(response)
    }
}
