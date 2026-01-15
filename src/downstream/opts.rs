use std::{io, sync::Arc, time::Duration};

use dynosaur::dynosaur;
use http::StatusCode;
use iroh::EndpointId;
use iroh_blobs::util::connection_pool;
use n0_error::{Result, anyerr, stack_error};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::{
    downstream::{EndpointAuthority, ProxyError},
    parse::{HttpRequest, HttpResponse},
};

#[derive(Debug, Clone)]
pub struct PoolOpts {
    connect_timeout: Duration,
    idle_timeout: Duration,
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

#[derive(derive_more::Debug, Clone)]
pub struct ProxyOpts {
    /// Forward-proxy mode: Accepts CONNECT or forward-proxy requests.
    forward: Option<ForwardProxyMode>,
    /// Reverse-proxy mode: Accepts regular origin HTTP requests.
    reverse: Option<ReverseProxyMode>,
    #[debug("{:?}", response_writer.as_ref().map(|_| "DynWriteErrorResponse"))]
    response_writer: Option<Arc<DynWriteErrorResponse<'static>>>,
}

impl ProxyOpts {
    /// Forward-proxy mode: Accepts CONNECT or forward-proxy requests.
    pub fn forward_only(mode: impl Into<ForwardProxyMode>) -> Self {
        Self {
            forward: Some(mode.into()),
            reverse: None,
            response_writer: None,
        }
    }

    /// Reverse-proxy mode: Accepts regular origin HTTP requests.
    pub fn reverse_only(mode: impl Into<ReverseProxyMode>) -> Self {
        Self {
            forward: None,
            reverse: Some(mode.into()),
            response_writer: None,
        }
    }

    /// Accepts both regular origin HTTP requests and CONNECT or forward-proxy requests.
    pub fn forward_and_reverse(
        forward: impl Into<ForwardProxyMode>,
        reverse: impl Into<ReverseProxyMode>,
    ) -> Self {
        Self {
            forward: Some(forward.into()),
            reverse: Some(reverse.into()),
            response_writer: None,
        }
    }

    pub fn with_error_response_writer(mut self, writer: impl WriteErrorResponse + 'static) -> Self {
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

#[derive(derive_more::Debug, Clone)]
pub enum ForwardProxyMode {
    Static(EndpointId),
    #[debug("DynExtractEndpoint")]
    Dynamic(Arc<DynExtractEndpoint<'static>>),
}

impl ForwardProxyMode {
    pub async fn extact_endpoint(&self, req: &HttpRequest) -> Result<EndpointId, ExtractError> {
        match self {
            Self::Static(destination) => Ok(destination.clone()),
            Self::Dynamic(extractor) => extractor.extract_endpoint(req).await,
        }
    }
}

impl<T: ExtractEndpoint + 'static> From<T> for ForwardProxyMode {
    fn from(value: T) -> Self {
        Self::Dynamic(DynExtractEndpoint::new_arc(value))
    }
}

#[derive(derive_more::Debug, Clone)]
pub enum ReverseProxyMode {
    Static(EndpointAuthority),
    #[debug("DynExtractEndpointAuthority")]
    Dynamic(Arc<DynExtractEndpointAuthority<'static>>),
}

impl ReverseProxyMode {
    pub async fn extact_endpoint_authority(
        &self,
        req: &HttpRequest,
    ) -> Result<EndpointAuthority, ExtractError> {
        match self {
            Self::Static(destination) => Ok(destination.clone()),
            Self::Dynamic(extractor) => extractor.extract_endpoint_authority(req).await,
        }
    }
}

impl<T: ExtractEndpointAuthority + 'static> From<T> for ReverseProxyMode {
    fn from(value: T) -> Self {
        Self::Dynamic(DynExtractEndpointAuthority::new_arc(value))
    }
}

#[dynosaur(DynExtractEndpoint = dyn(box) ExtractEndpoint)]
pub trait ExtractEndpoint: Send + Sync {
    fn extract_endpoint<'a>(
        &'a self,
        req: &'a HttpRequest,
    ) -> impl Future<Output = Result<EndpointId, ExtractError>> + Send + 'a;
}

#[dynosaur(DynExtractEndpointAuthority = dyn(box) ExtractEndpointAuthority)]
pub trait ExtractEndpointAuthority: Send + Sync {
    fn extract_endpoint_authority<'a>(
        &'a self,
        req: &'a HttpRequest,
    ) -> impl Future<Output = Result<EndpointAuthority, ExtractError>> + Send + 'a;
}

#[dynosaur(DynWriteErrorResponse = dyn(box) WriteErrorResponse)]
pub trait WriteErrorResponse: Send + Sync {
    fn write_error_response<'a>(
        &'a self,
        res: &'a HttpResponse,
        writer: &'a mut (dyn AsyncWrite + Send + Unpin),
    ) -> impl Future<Output = io::Result<()>> + Send + 'a;
}

struct DefaultResponseWriter;
impl WriteErrorResponse for DefaultResponseWriter {
    async fn write_error_response<'a>(
        &'a self,
        res: &'a HttpResponse,
        writer: &'a mut (dyn AsyncWrite + Send + Unpin),
    ) -> io::Result<()> {
        writer.write_all(res.status_line().as_bytes()).await?;
        let content = format!("{} {}", res.status.as_u16(), res.reason());
        writer
            .write_all(format!("Content-Type: text/plain\r\n").as_bytes())
            .await?;
        writer
            .write_all(format!("Content-Length: {}\r\n\r\n", content.len()).as_bytes())
            .await?;
        writer.write_all(content.as_bytes()).await?;
        Ok(())
    }
}

#[stack_error(derive)]
pub enum ExtractError {
    Unauthorized,
    NotFound,
    InternalError,
}

impl ExtractError {
    pub fn response_status(&self) -> StatusCode {
        match self {
            ExtractError::Unauthorized => StatusCode::UNAUTHORIZED,
            ExtractError::NotFound => StatusCode::NOT_FOUND,
            ExtractError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
