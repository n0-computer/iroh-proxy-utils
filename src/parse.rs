use std::str::FromStr;

use http::{
    HeaderValue, Method, StatusCode,
    uri::{Scheme, Uri},
};
use n0_error::{Result, StackResultExt, StdResultExt, anyerr, ensure_any};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::util::Prebuffered;

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

/// Parsed request target classification per RFC 9110.
#[derive(Debug)]
pub enum HttpRequestKind {
    /// CONNECT authority-form or absolute-form proxy request.
    Proxy(HttpProxyRequestKind),
    /// Direct origin request with origin-form request target.
    Origin {
        /// Origin-form path component.
        path: String,
        /// HTTP method from the request line.
        method: Method,
    },
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
    pub headers: http::HeaderMap<http::HeaderValue>,
}

/// Parsed HTTP request with headers and request target classification.
#[derive(Debug)]
pub enum HttpRequest {
    Forward(HttpProxyRequest),
    Origin(HttpOriginRequest),
}

#[derive(Debug)]
pub struct HttpOriginRequest {
    /// Origin-form path component.
    pub path: String,
    /// HTTP method from the request line.
    pub method: Method,
    /// Raw header map as received.
    pub headers: http::HeaderMap<http::HeaderValue>,
}

impl HttpOriginRequest {
    pub fn host(&self) -> Option<&str> {
        self.headers.get("host").and_then(|x| x.to_str().ok())
    }
}

impl HttpRequest {
    /// Reads and parses the request line and header section.
    ///
    /// Does not remove the header section from `reader`.
    /// Returns the length of the header section and the request.
    /// Returns [`io::ErrorKind::OutOfMemory`] if the header section exceeds the buffer limit.
    pub async fn peek(reader: &mut Prebuffered<impl AsyncRead + Unpin>) -> Result<(usize, Self)> {
        while !reader.is_full() {
            reader.buffer_more().await?;
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

    /// Parses a request from a buffer and returns `None` when incomplete.
    ///
    /// Returns the length of the header section and the request.
    pub fn parse_with_len(buf: &[u8]) -> Result<Option<(usize, Self)>> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(buf).std_context("Invalid HTTP request")? {
            httparse::Status::Partial => Ok(None),
            httparse::Status::Complete(header_len) => {
                Self::from_request(req).map(|req| Some((header_len, req)))
            }
        }
    }

    fn from_request(req: httparse::Request) -> Result<Self> {
        let method_str = req.method.context("Missing HTTP method")?;
        let method = method_str.parse().std_context("Invalid HTTP method")?;
        let path = req.path.context("Missing request target")?;
        let uri = Uri::from_str(path).std_context("Invalid request target")?;
        let headers = http::HeaderMap::from_iter(req.headers.iter_mut().flat_map(|h| {
            let value = HeaderValue::from_bytes(h.value).ok()?;
            let name = http::HeaderName::from_bytes(h.name.as_bytes()).ok()?;
            Some((name, value))
        }));
        let request = match method {
            Method::CONNECT => {
                let authority = Authority::from_authority_uri(&uri)?;
                Self::Forward(HttpProxyRequest {
                    kind: HttpProxyRequestKind::Tunnel { target: authority },
                    headers,
                })
            }
            _ => {
                if uri.scheme().is_some() {
                    Self::Forward(HttpProxyRequest {
                        kind: HttpProxyRequestKind::Absolute {
                            target: path.to_string(),
                            method,
                        },
                        headers,
                    })
                } else {
                    Self::Origin(HttpOriginRequest {
                        path: path.to_string(),
                        method,
                        headers,
                    })
                }
            }
        };
        Ok(request)
    }

    /// Converts to a proxy request when the target is authority-form or absolute-form.
    ///
    /// Note: origin-form requests return an error.
    pub fn try_into_proxy_request(self) -> Result<HttpProxyRequest> {
        match self {
            Self::Forward(inner) => Ok(inner),
            Self::Origin(_) => Err(anyerr!("Request is origin-form and not a proxy request")),
        }
    }
}

/// Parsed HTTP response with status, reason, and headers.
#[derive(derive_more::Debug)]
pub struct HttpResponse {
    /// Status code from the response line.
    pub status: StatusCode,
    /// Reason phrase if present.
    pub reason: Option<String>,
    /// Raw header map as received.
    pub headers: http::HeaderMap<http::HeaderValue>,
}

impl HttpResponse {
    pub(crate) fn new(status: StatusCode) -> Self {
        Self {
            status,
            reason: None,
            headers: http::HeaderMap::new(),
        }
    }

    pub(crate) fn with_reason(status: StatusCode, reason: impl ToString) -> Self {
        Self {
            status,
            reason: Some(reason.to_string()),
            headers: http::HeaderMap::new(),
        }
    }

    pub(crate) async fn write(
        &self,
        writer: &mut (impl AsyncWrite + Send + Unpin),
    ) -> io::Result<()> {
        writer.write_all(self.status_line().as_bytes()).await?;
        writer.write_all(b"\r\n").await?;
        for (key, value) in self.headers.iter() {
            writer.write_all(key.as_str().as_bytes()).await?;
            writer.write_all(b": ").await?;
            writer.write_all(value.as_bytes()).await?;
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
                let headers = http::HeaderMap::from_iter(res.headers.iter().flat_map(|h| {
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
    pub async fn read(reader: &mut Prebuffered<impl AsyncRead + Unpin>) -> Result<Self> {
        let (len, response) = Self::peek(reader).await?;
        reader.discard(len);
        Ok(response)
    }
}
