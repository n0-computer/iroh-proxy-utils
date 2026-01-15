use std::{future::Future, sync::Arc};

use dynosaur::dynosaur;
use http::StatusCode;
use iroh::EndpointId;
use n0_error::{anyerr, stack_error};

use crate::{Authority, http_connect::ProxyError, parse::HttpRequest};

#[derive(Debug, Clone)]
pub struct ProxyMode {
    /// Forward-proxy mode: Accepts CONNECT or forward-proxy requests.
    pub forward: Option<ForwardProxyMode>,
    /// Reverse-proxy mode: Accepts regular origin HTTP requests.
    pub reverse: Option<ReverseProxyMode>,
}

impl ProxyMode {
    pub fn forward_only(mode: impl Into<ForwardProxyMode>) -> Self {
        Self {
            forward: Some(mode.into()),
            reverse: None,
        }
    }

    pub fn reverse_only(mode: impl Into<ReverseProxyMode>) -> Self {
        Self {
            forward: None,
            reverse: Some(mode.into()),
        }
    }

    pub fn as_forward(&self) -> Result<&ForwardProxyMode, ProxyError> {
        self.forward.as_ref().ok_or_else(|| {
            ProxyError::new(
                Some(StatusCode::BAD_REQUEST),
                anyerr!("Forward proxy mode is not configured"),
            )
        })
    }

    pub fn as_reverse(&self) -> Result<&ReverseProxyMode, ProxyError> {
        self.reverse.as_ref().ok_or_else(|| {
            ProxyError::new(
                Some(StatusCode::BAD_REQUEST),
                anyerr!("Reverse proxy mode is not configured"),
            )
        })
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

#[derive(Debug, Clone)]
pub struct EndpointAuthority {
    pub endpoint_id: EndpointId,
    pub authority: Authority,
}

#[dynosaur(pub DynExtractEndpoint = dyn(box) ExtractEndpoint)]
pub trait ExtractEndpoint: Send + Sync {
    fn extract_endpoint<'a>(
        &'a self,
        req: &'a HttpRequest,
    ) -> impl Future<Output = Result<EndpointId, ExtractError>> + Send + 'a;
}

#[dynosaur(pub DynExtractEndpointAuthority = dyn(box) ExtractEndpointAuthority)]
pub trait ExtractEndpointAuthority: Send + Sync {
    fn extract_endpoint_authority<'a>(
        &'a self,
        req: &'a HttpRequest,
    ) -> impl Future<Output = Result<EndpointAuthority, ExtractError>> + Send + 'a;
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
