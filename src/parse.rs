use std::str::FromStr;

use bytes::{Bytes, BytesMut};
use http::{HeaderValue, StatusCode, uri::Scheme};
use n0_error::{Result, StackResultExt, StdResultExt};
use tokio::io::{self, AsyncRead, AsyncReadExt};

#[derive(Debug, Clone, derive_more::Display)]
#[display("{host}:{port}")]
pub struct Authority {
    pub host: String,
    pub port: u16,
}

impl FromStr for Authority {
    type Err = n0_error::AnyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_host_str(s)
    }
}

impl Authority {
    pub fn from_host_str(authority: &str) -> Result<Self> {
        // Split into host and port
        let (host, port_str) = authority.rsplit_once(':').ok_or_else(|| {
            n0_error::AnyError::from_string("Invalid CONNECT path, expected host:port".to_string())
        })?;
        let host = host
            .strip_prefix("https://")
            .or_else(|| host.strip_prefix("http://"))
            .unwrap_or(host);

        let port: u16 = port_str
            .trim_end_matches('/')
            .parse()
            .map_err(|e| {
                n0_error::AnyError::from_string(format!("Invalid port number {port_str}: {}", e))
            })
            .anyerr()?;
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }

    pub fn from_uri(uri: &str) -> Result<Self> {
        let uri = http::uri::Uri::from_str(uri).std_context("Invalid URI")?;
        let host = uri.host().context("Missing host")?.to_string();
        let port = match uri.port_u16() {
            Some(port) => port,
            None => match uri.scheme().context("Missing scheme")? {
                x if x == &Scheme::HTTP => 80,
                x if x == &Scheme::HTTPS => 443,
                _ => n0_error::bail_any!("Invalid scheme"),
            },
        };
        Ok(Self { host, port })
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
pub enum RequestKind {
    Connect {
        authority: Authority,
    },
    Http {
        method: http::Method,
        path: String,
        authority_from_path: Option<Authority>,
    },
}

#[derive(derive_more::Debug)]
pub struct HttpRequest {
    pub kind: RequestKind,
    pub headers: http::HeaderMap<http::HeaderValue>,
}

#[derive(Debug, Clone)]
pub struct InitialData {
    pub(crate) data: Bytes,
    body_offset: usize,
}

impl InitialData {
    fn new(buf: BytesMut, offset: usize) -> Self {
        Self {
            data: buf.freeze(),
            body_offset: offset,
        }
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn full(self) -> Bytes {
        self.data
    }

    pub fn end_of_header_section(&self) -> usize {
        self.body_offset
    }

    pub fn after_header_section(mut self) -> Bytes {
        self.data.split_off(self.body_offset)
    }
}

impl HttpRequest {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        if req
            .parse(&buf[..])
            .std_context("Failed to parse HTTP request")?
            .is_partial()
        {
            n0_error::bail_any!("Incomplete HTTP request");
        }
        Self::from_request(req)
    }

    pub async fn read(
        mut reader: impl AsyncRead + Unpin,
        max_len: usize,
    ) -> Result<(InitialData, Self)> {
        let mut buf = BytesMut::new();
        while buf.len() < max_len {
            let n = reader.read_buf(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "Header section longer than memory limit",
                )
                .into());
            }

            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);

            match req
                .parse(&buf[..])
                .std_context("Failed to parse HTTP request")?
            {
                httparse::Status::Partial => continue,
                httparse::Status::Complete(body_offset) => {
                    let request = Self::from_request(req)?;
                    let initial_data = InitialData::new(buf, body_offset);
                    return Ok((initial_data, request));
                }
            }
        }

        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF").into())
    }

    fn from_request<'a>(req: httparse::Request) -> Result<Self> {
        let method = req
            .method
            .context("Invalid HTTP request: Missing HTTP method")?;
        let method = method
            .parse()
            .std_context("Invalid HTTP request: Invalid method")?;
        let kind = match method {
            http::Method::CONNECT => {
                let authority = req
                    .path
                    .context("Invalid HTTP CONNECT request: Missing authority")?
                    .to_string();
                let authority = Authority::from_host_str(&authority)
                    .context("Invalid HTTP CONNECT request: Invalid authority string")?;
                RequestKind::Connect { authority }
            }
            _ => {
                let path = req.path.unwrap_or_default().to_string();
                let authority_from_path = Authority::from_uri(&path).ok();
                RequestKind::Http {
                    method,
                    path: path.to_string(),
                    authority_from_path,
                }
            }
        };
        let headers = http::HeaderMap::from_iter(req.headers.into_iter().flat_map(|h| {
            let value = HeaderValue::from_bytes(h.value).ok()?;
            let name = http::HeaderName::from_bytes(h.name.as_bytes()).ok()?;
            Some((name, value))
        }));
        Ok(Self { kind, headers })
    }
}

#[derive(derive_more::Debug)]
pub struct HttpResponse {
    pub status: StatusCode,
}

impl HttpResponse {
    pub async fn read(
        reader: &mut (impl AsyncRead + Unpin),
        max_len: usize,
    ) -> Result<(InitialData, Self)> {
        let mut buf = BytesMut::new();
        while buf.len() < max_len {
            let n = reader.read_buf(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "Header section longer than memory limit",
                )
                .into());
            }

            let mut headers = [httparse::EMPTY_HEADER; 0];
            let mut res = httparse::Response::new(&mut headers);

            match res
                .parse(&buf[..])
                .std_context("Failed to parse HTTP request")?
            {
                httparse::Status::Partial => continue,
                httparse::Status::Complete(body_offset) => {
                    let status = http::StatusCode::from_u16(res.code.unwrap_or(500))
                        .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
                    let response = HttpResponse { status };
                    let initial_data = InitialData::new(buf, body_offset);
                    return Ok((initial_data, response));
                }
            }
        }

        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF").into())
    }
}
