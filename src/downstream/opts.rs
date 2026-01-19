use std::{io, sync::Arc, time::Duration};

use dynosaur::dynosaur;
use http::StatusCode;
use iroh::EndpointId;
use iroh_blobs::util::connection_pool;
use n0_error::{Result, anyerr, stack_error};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::{
    HttpOriginRequest, HttpProxyRequest,
    downstream::{EndpointAuthority, ProxyError},
    parse::HttpResponse,
};

/// Options for the downstream connection pool.
#[derive(Debug, Clone)]
pub struct PoolOpts {
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for PoolOpts {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(5),
        }
    }
}

impl From<PoolOpts> for connection_pool::Options {
    fn from(opts: PoolOpts) -> Self {
        connection_pool::Options {
            connect_timeout: opts.connect_timeout,
            idle_timeout: opts.idle_timeout,
            ..Default::default()
        }
    }
}

/// Determines how the proxy deals with incoming TCP connections.
#[derive(derive_more::Debug, Clone)]
pub enum ProxyMode {
    /// TCP mode blindly forwards all incoming TCP connections over a tunnel to a fixed remote authority.
    Tcp(EndpointAuthority),
    /// HTTP mode reads the header section of the HTTP request on incoming TCP connections, and thus
    /// can use the request data to decide over the destination.
    Http(HttpProxyOpts),
}

/// Policy for handling forward and reverse proxy requests.
#[derive(derive_more::Debug, Default, Clone)]
pub struct HttpProxyOpts {
    /// Forward-proxy mode for CONNECT authority-form and absolute-form requests.
    forward: Option<ForwardProxyMode>,
    /// Reverse-proxy mode for origin-form requests.
    reverse: Option<ReverseProxyMode>,
    #[debug("{:?}", response_writer.as_ref().map(|_| "DynWriteErrorResponse"))]
    response_writer: Option<Arc<DynWriteErrorResponse<'static>>>,
}

impl HttpProxyOpts {
    /// Enables forward-proxy handling for CONNECT authority-form and absolute-form requests.
    ///
    /// Note: origin-form requests will be rejected by the proxy with
    /// `400 Bad Request` when this is the only mode configured.
    pub fn forward(mut self, mode: impl Into<ForwardProxyMode>) -> Self {
        self.forward = Some(mode.into());
        self
    }

    /// Enables reverse-proxy handling for origin-form requests.
    ///
    /// Note: CONNECT and absolute-form requests will be rejected by the
    /// proxy with `400 Bad Request` when this is the only mode configured.
    pub fn reverse(mut self, mode: impl Into<ReverseProxyMode>) -> Self {
        self.reverse = Some(mode.into());
        self
    }

    /// Installs a custom error response writer for downstream-facing responses.
    ///
    /// Note: if not set, a minimal `text/plain` response is emitted.
    pub fn error_response_writer(mut self, writer: impl WriteErrorResponse + 'static) -> Self {
        self.response_writer = Some(DynWriteErrorResponse::new_arc(writer));
        self
    }

    pub(crate) fn as_forward(&self) -> Result<&ForwardProxyMode, ProxyError> {
        self.forward.as_ref().ok_or_else(|| {
            ProxyError::new(
                Some(StatusCode::BAD_REQUEST),
                anyerr!("Forward proxy mode is not configured"),
            )
        })
    }

    pub(crate) fn as_reverse(&self) -> Result<&ReverseProxyMode, ProxyError> {
        self.reverse.as_ref().ok_or_else(|| {
            ProxyError::new(
                Some(StatusCode::BAD_REQUEST),
                anyerr!("Reverse proxy mode is not configured"),
            )
        })
    }

    pub(crate) async fn write_error_response(
        &self,
        response: &HttpResponse,
        writer: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> io::Result<()> {
        let response_writer: &DynWriteErrorResponse = match self.response_writer.as_ref() {
            Some(writer) => writer.as_ref(),
            None => DynWriteErrorResponse::from_ref(&DefaultResponseWriter),
        };
        response_writer
            .write_error_response(response, writer)
            .await?;
        Ok(())
    }
}

/// Forward-proxy routing for CONNECT authority-form and absolute-form requests.
#[derive(derive_more::Debug, Clone)]
pub enum ForwardProxyMode {
    /// Always forward to the fixed endpoint.
    Static(EndpointId),
    /// Resolve the endpoint dynamically from the request.
    #[debug("DynForwardProxyResolver")]
    Dynamic(Arc<DynForwardProxyResolver<'static>>),
}

impl ForwardProxyMode {
    /// Resolves the destination endpoint for a proxy request.
    ///
    /// Note: extractor failures map to HTTP error status codes via `ExtractError`.
    pub async fn destination(&self, req: &HttpProxyRequest) -> Result<EndpointId, ExtractError> {
        match self {
            Self::Static(destination) => Ok(*destination),
            Self::Dynamic(extractor) => extractor.destination(req).await,
        }
    }
}

impl<T: ForwardProxyResolver + 'static> From<T> for ForwardProxyMode {
    fn from(value: T) -> Self {
        Self::Dynamic(DynForwardProxyResolver::new_arc(value))
    }
}

/// Reverse-proxy routing for origin-form requests.
#[derive(derive_more::Debug, Clone)]
pub enum ReverseProxyMode {
    /// Always forward to the fixed endpoint and authority.
    Static(EndpointAuthority),
    /// Resolve the endpoint and authority dynamically from the request.
    #[debug("DynReverseProxyResolver")]
    Dynamic(Arc<DynReverseProxyResolver<'static>>),
}

impl ReverseProxyMode {
    /// Resolves the destination endpoint and authority for an origin-form request.
    ///
    /// Note: extractor failures map to HTTP error status codes via `ExtractError`.
    pub async fn destination(
        &self,
        req: &HttpOriginRequest,
    ) -> Result<EndpointAuthority, ExtractError> {
        match self {
            Self::Static(destination) => Ok(destination.clone()),
            Self::Dynamic(extractor) => extractor.destination(req).await,
        }
    }
}

impl<T: ReverseProxyResolver + 'static> From<T> for ReverseProxyMode {
    fn from(value: T) -> Self {
        Self::Dynamic(DynReverseProxyResolver::new_arc(value))
    }
}

impl From<EndpointAuthority> for ReverseProxyMode {
    fn from(value: EndpointAuthority) -> Self {
        Self::Static(value)
    }
}

#[dynosaur(DynForwardProxyResolver = dyn(box) ForwardProxyResolver)]
/// Extracts an iroh endpoint from a proxy request.
pub trait ForwardProxyResolver: Send + Sync {
    /// Returns the destination endpoint or an application error.
    fn destination<'a>(
        &'a self,
        req: &'a HttpProxyRequest,
    ) -> impl Future<Output = Result<EndpointId, ExtractError>> + Send + 'a;
}

#[dynosaur(DynReverseProxyResolver = dyn(box) ReverseProxyResolver)]
/// Extracts an iroh endpoint and authority from an origin-form request.
pub trait ReverseProxyResolver: Send + Sync {
    /// Returns the destination endpoint and authority or an application error.
    fn destination<'a>(
        &'a self,
        req: &'a HttpOriginRequest,
    ) -> impl Future<Output = Result<EndpointAuthority, ExtractError>> + Send + 'a;
}

#[dynosaur(DynWriteErrorResponse = dyn(box) WriteErrorResponse)]
/// Writes an HTTP error response to a downstream TCP stream.
pub trait WriteErrorResponse: Send + Sync {
    /// Emits a complete HTTP/1.x response for a proxy error.
    fn write_error_response<'a>(
        &'a self,
        res: &'a HttpResponse,
        writer: &'a mut (dyn AsyncWrite + Send + Unpin),
    ) -> impl Future<Output = io::Result<()>> + Send + 'a;
}

pub(crate) struct DefaultResponseWriter;
impl WriteErrorResponse for DefaultResponseWriter {
    async fn write_error_response<'a>(
        &'a self,
        res: &'a HttpResponse,
        writer: &'a mut (dyn AsyncWrite + Send + Unpin),
    ) -> io::Result<()> {
        writer.write_all(res.status_line().as_bytes()).await?;
        let content = format!("{} {}", res.status.as_u16(), res.reason());
        writer
            .write_all("Content-Type: text/plain\r\n".to_string().as_bytes())
            .await?;
        writer
            .write_all(format!("Content-Length: {}\r\n\r\n", content.len()).as_bytes())
            .await?;
        writer.write_all(content.as_bytes()).await?;
        Ok(())
    }
}

/// Error classification for endpoint extraction and authorization.
#[stack_error(derive)]
pub enum ExtractError {
    /// A required service is not available.
    ServiceUnavailable,
    /// Authentication is required or failed.
    Unauthorized,
    /// The requested resource does not exist.
    NotFound,
    /// The request is malformed or unsupported.
    BadRequest,
    /// An internal error occurred during extraction.
    InternalError,
}

impl ExtractError {
    /// Returns the corresponding HTTP status code.
    pub fn response_status(&self) -> StatusCode {
        match self {
            ExtractError::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ExtractError::Unauthorized => StatusCode::UNAUTHORIZED,
            ExtractError::NotFound => StatusCode::NOT_FOUND,
            ExtractError::BadRequest => StatusCode::BAD_REQUEST,
            ExtractError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
