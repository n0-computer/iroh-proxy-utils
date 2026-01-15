use std::str::FromStr;

use http::{
    HeaderValue, Method, StatusCode,
    uri::{Scheme, Uri},
};
use n0_error::{Result, StackResultExt, StdResultExt, anyerr, ensure_any};
use tokio::io::{self, AsyncRead};

use crate::util::{Prebuffered, status_line};

#[derive(Debug, Clone, derive_more::Display)]
#[display("{host}:{port}")]
pub struct Authority {
    pub host: String,
    pub port: u16,
}

impl FromStr for Authority {
    type Err = n0_error::AnyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_authority_str(s)
    }
}

impl Authority {
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

    pub fn from_authority_str(s: &str) -> Result<Self> {
        Self::from_authority_uri(&Uri::from_str(s).std_context("Invalid authority string")?)
    }

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
pub enum HttpRequestKind {
    /// Tunnel or forward-proxy request.
    Proxy(HttpProxyRequestKind),
    /// Direct origin request with origin-form request target.
    Origin {
        path: String,
        host: Option<String>,
        method: Method,
    },
}

#[derive(Debug)]
pub enum HttpProxyRequestKind {
    /// Tunnel CONNECT request with authority-form request target.
    Tunnel { target: Authority },
    /// Forward-proxy request with absolute-form request target.
    Absolute { target: String, method: Method },
}

#[derive(derive_more::Debug)]
pub struct HttpProxyRequest {
    pub kind: HttpProxyRequestKind,
    pub headers: http::HeaderMap<http::HeaderValue>,
}

#[derive(derive_more::Debug)]
pub struct HttpRequest {
    pub kind: HttpRequestKind,
    pub headers: http::HeaderMap<http::HeaderValue>,
    pub(crate) header_section_len: usize,
}

impl HttpRequest {
    pub async fn read(reader: &mut Prebuffered<impl AsyncRead + Unpin>) -> Result<Self> {
        while !reader.is_full() {
            reader.buffer_more().await?;
            if let Some(request) = Self::parse(reader.buffer())? {
                return Ok(request);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "Buffer size limit reached before end of request header section",
        )
        .into())
    }

    pub fn parse(buf: &[u8]) -> Result<Option<Self>> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf[..]).std_context("Invalid HTTP request")? {
            httparse::Status::Partial => Ok(None),
            httparse::Status::Complete(body_offset) => {
                Self::from_request(req, body_offset).map(Some)
            }
        }
    }

    fn from_request<'a>(req: httparse::Request, header_section_len: usize) -> Result<Self> {
        let method_str = req.method.context("Missing HTTP method")?;
        let method = method_str.parse().std_context("Invalid HTTP method")?;
        let path = req.path.context("Missing request target")?;
        let uri = Uri::from_str(path).std_context("Invalid request target")?;
        let headers = http::HeaderMap::from_iter(req.headers.into_iter().flat_map(|h| {
            let value = HeaderValue::from_bytes(h.value).ok()?;
            let name = http::HeaderName::from_bytes(h.name.as_bytes()).ok()?;
            Some((name, value))
        }));
        let kind = match method {
            Method::CONNECT => {
                let authority = Authority::from_authority_uri(&uri)?;
                HttpRequestKind::Proxy(HttpProxyRequestKind::Tunnel { target: authority })
            }
            _ => {
                if uri.scheme().is_some() {
                    HttpRequestKind::Proxy(HttpProxyRequestKind::Absolute {
                        target: path.to_string(),
                        method,
                    })
                } else {
                    let host = headers
                        .get("host")
                        .and_then(|x| Some(x.to_str().ok()?.to_string()));
                    HttpRequestKind::Origin {
                        path: path.to_string(),
                        host,
                        method,
                    }
                }
            }
        };
        Ok(Self {
            kind,
            headers,
            header_section_len,
        })
    }

    pub fn try_into_proxy_request(self) -> Result<HttpProxyRequest> {
        match self.kind {
            HttpRequestKind::Proxy(kind) => Ok(HttpProxyRequest {
                kind,
                headers: self.headers,
            }),
            HttpRequestKind::Origin { .. } => {
                Err(anyerr!("Request is origin-form and not a proxy request"))
            }
        }
    }
}

#[derive(derive_more::Debug)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub reason: Option<String>,
    pub(crate) header_section_len: usize,
}

impl HttpResponse {
    pub fn reason(&self) -> &str {
        self.reason
            .as_deref()
            .or(self.status.canonical_reason())
            .unwrap_or("")
    }

    pub fn status_line(&self) -> String {
        status_line(self.status, self.reason.as_deref())
    }

    pub async fn read(reader: &mut Prebuffered<impl AsyncRead + Unpin>) -> Result<Self> {
        while !reader.is_full() {
            reader.buffer_more().await?;

            let mut headers = [httparse::EMPTY_HEADER; 0];
            let mut res = httparse::Response::new(&mut headers);

            match res
                .parse(&reader.buffer())
                .std_context("Failed to parse HTTP request")?
            {
                httparse::Status::Partial => continue,
                httparse::Status::Complete(header_section_len) => {
                    let code = res.code.context("Missing response status code")?;
                    let status =
                        StatusCode::from_u16(code).std_context("Invalid response status code")?;
                    let reason = res.reason.map(ToOwned::to_owned);
                    return Ok(HttpResponse {
                        status,
                        reason,
                        header_section_len,
                    });
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "Buffer size limit reached before end of respones header section",
        )
        .into())
    }
}
