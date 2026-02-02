use std::{net::SocketAddr, sync::Arc, time::Duration};

use dynosaur::dynosaur;
use http::{HeaderValue, Method, StatusCode, header::InvalidHeaderValue};
use http_body_util::BodyExt;
use iroh::EndpointId;
use iroh_blobs::util::connection_pool;
use n0_error::{AnyError, Result};
use tracing::debug;

use crate::{
    downstream::{EndpointAuthority, HyperBody},
    parse::HttpRequest,
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
#[derive(derive_more::Debug, Clone)]
pub struct HttpProxyOpts {
    #[debug("DynRequestHandler")]
    pub(crate) request_handler: Arc<DynRequestHandler<'static>>,
    // /// Forward-proxy mode for CONNECT authority-form and absolute-form requests.
    // forward: Option<ForwardProxyMode>,
    // /// Reverse-proxy mode for origin-form requests.
    // reverse: Option<ReverseProxyMode>,
    #[debug("{:?}", response_writer.as_ref().map(|_| "DynWriteErrorResponse"))]
    response_writer: Option<Arc<DynErrorResponder<'static>>>,
}

impl HttpProxyOpts {
    pub fn new(request_handler: impl RequestHandler + 'static) -> Self {
        Self {
            request_handler: DynRequestHandler::new_arc(request_handler),
            response_writer: None,
        }
    }

    /// Installs a custom error response writer for downstream-facing responses.
    ///
    /// Note: if not set, a minimal `text/plain` response is emitted.
    pub fn error_responder(mut self, writer: impl ErrorResponder + 'static) -> Self {
        self.response_writer = Some(DynErrorResponder::new_arc(writer));
        self
    }

    pub(crate) async fn error_response<'a>(
        &'a self,
        status: StatusCode,
    ) -> hyper::Response<HyperBody> {
        let response_writer: &DynErrorResponder = match self.response_writer.as_ref() {
            Some(writer) => writer.as_ref(),
            None => DynErrorResponder::from_ref(&DefaultResponseWriter),
        };
        response_writer.error_response(status).await
    }
}

#[dynosaur(DynErrorResponder = dyn(box) ErrorResponder)]
/// Writes an HTTP error response to a downstream TCP stream.
pub trait ErrorResponder: Send + Sync {
    /// Emits a complete HTTP/1.x response for a proxy error.
    fn error_response<'a>(
        &'a self,
        status: StatusCode,
    ) -> impl Future<Output = hyper::Response<HyperBody>> + Send + 'a;
}

pub(crate) struct DefaultResponseWriter;
impl ErrorResponder for DefaultResponseWriter {
    async fn error_response<'a>(&'a self, status: StatusCode) -> hyper::Response<HyperBody> {
        let body = http_body_util::Empty::new().map_err(|_| unreachable!("infallible"));
        let mut res = hyper::Response::builder().status(status);
        res.headers_mut().unwrap().insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str("0").unwrap(),
        );
        res.body(body.boxed()).unwrap()
    }
}

#[dynosaur(DynRequestHandler = dyn(box) RequestHandler)]
pub trait RequestHandler: Send + Sync {
    fn handle_request(
        &self,
        _src_addr: SocketAddr,
        _req: &mut HttpRequest,
    ) -> impl Future<Output = Result<EndpointId, Deny>> + Send;
}

pub struct StaticForwardProxy(pub EndpointId);

impl RequestHandler for StaticForwardProxy {
    async fn handle_request(
        &self,
        src_addr: SocketAddr,
        req: &mut HttpRequest,
    ) -> Result<EndpointId, Deny> {
        if req.method == Method::CONNECT {
            if req.uri.authority().is_none()
                || req.uri.scheme().is_some()
                || req.uri.path_and_query().is_some()
            {
                return Err(Deny::bad_request(
                    "invalid request target for CONNECT request",
                ));
            }
        } else {
            if req.uri.authority().is_none() || req.uri.scheme().is_none() {
                return Err(Deny::bad_request("missing absolute-form request target"));
            }
        }
        req.set_forwarded_for(src_addr).set_via("iroh-proxy")?;
        Ok(self.0)
    }
}

pub struct StaticReverseProxy(pub EndpointAuthority);

impl RequestHandler for StaticReverseProxy {
    async fn handle_request(
        &self,
        src_addr: SocketAddr,
        req: &mut HttpRequest,
    ) -> Result<EndpointId, Deny> {
        if req.method == Method::CONNECT {
            return Err(Deny::new(
                StatusCode::BAD_REQUEST,
                "CONNECT requests are not supported",
            ));
        }
        if req.version < http::Version::HTTP_2 && req.uri.scheme().is_some() {
            return Err(Deny::new(
                StatusCode::BAD_REQUEST,
                "Absolute-form request targets are not supported",
            ));
        }
        req.set_forwarded_for(src_addr)
            .set_via("iroh-proxy")?
            .set_http_authority(self.0.authority.clone())
            .map_err(|err| Deny::new(StatusCode::INTERNAL_SERVER_ERROR, err))?;
        Ok(self.0.endpoint_id)
    }
}

#[derive(Default)]
pub struct RequestHandlerChain(Vec<Box<DynRequestHandler<'static>>>);

impl RequestHandlerChain {
    pub fn push(mut self, handler: impl RequestHandler + 'static) -> Self {
        self.0.push(DynRequestHandler::new_box(handler));
        self
    }
}

impl RequestHandler for RequestHandlerChain {
    async fn handle_request(
        &self,
        src_addr: SocketAddr,
        req: &mut HttpRequest,
    ) -> Result<EndpointId, Deny> {
        let mut last_err = None;
        for handler in self.0.iter() {
            match handler.handle_request(src_addr, req).await {
                Ok(destination) => return Ok(destination),
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }
        Err(last_err.expect("err is set"))
    }
}

pub struct Deny {
    pub reason: AnyError,
    pub code: StatusCode,
}

impl Deny {
    pub fn bad_request(reason: impl Into<AnyError>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, reason)
    }

    pub fn new(code: StatusCode, reason: impl Into<AnyError>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }
}

impl From<InvalidHeaderValue> for Deny {
    fn from(_value: InvalidHeaderValue) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid header value")
    }
}
