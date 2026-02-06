use std::{sync::Arc, time::Duration};

use dynosaur::dynosaur;
use http::{HeaderValue, Method, StatusCode, header::InvalidHeaderValue};
use http_body_util::BodyExt;
use iroh::EndpointId;
use iroh_blobs::util::connection_pool;
use n0_error::{AnyError, Result};

use crate::{
    downstream::{EndpointAuthority, HyperBody, SrcAddr},
    parse::HttpRequest,
};

/// Configuration for the upstream connection pool.
///
/// Controls timeouts for establishing new connections and keeping idle
/// connections alive.
#[derive(Debug, Clone)]
pub struct PoolOpts {
    /// Maximum time to wait when establishing a new connection.
    pub connect_timeout: Duration,
    /// How long to keep idle connections open before closing them.
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

/// Operating mode for the downstream proxy.
#[derive(derive_more::Debug, Clone)]
pub enum ProxyMode {
    /// TCP tunneling mode.
    ///
    /// All incoming connections are tunneled to a fixed upstream endpoint and
    /// authority without any HTTP parsing. Suitable for non-HTTP protocols or
    /// when dynamic routing is not needed.
    Tcp(EndpointAuthority),
    /// HTTP-aware proxy mode.
    ///
    /// Parses HTTP requests to enable dynamic routing based on request content.
    /// Supports both HTTP/1.1 and HTTP/2, including CONNECT tunneling.
    Http(HttpProxyOpts),
}

/// Configuration for HTTP proxy mode.
///
/// Specifies how requests are routed and how errors are reported to clients.
#[derive(derive_more::Debug, Clone)]
pub struct HttpProxyOpts {
    #[debug("DynRequestHandler")]
    pub(crate) request_handler: Arc<DynRequestHandler<'static>>,
    #[debug("{:?}", response_writer.as_ref().map(|_| "DynWriteErrorResponse"))]
    response_writer: Option<Arc<DynErrorResponder<'static>>>,
}

impl HttpProxyOpts {
    /// Creates HTTP proxy options with the given request handler.
    pub fn new(request_handler: impl RequestHandler + 'static) -> Self {
        Self {
            request_handler: DynRequestHandler::new_arc(request_handler),
            response_writer: None,
        }
    }

    /// Sets a custom error response generator.
    ///
    /// When proxy errors occur, this responder generates the HTTP response
    /// sent to the client. If not set, a minimal empty response is used.
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
/// Generates HTTP error responses for proxy failures.
///
/// Implement this trait to customize error pages shown to clients when
/// proxy operations fail.
pub trait ErrorResponder: Send + Sync {
    /// Generates an HTTP response for the given error status code.
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
/// Routes HTTP requests to upstream iroh endpoints.
///
/// Implement this trait to control how requests are routed. The handler
/// receives the client address and request, and may modify the request
/// (e.g., adding headers) before returning the destination endpoint.
pub trait RequestHandler: Send + Sync {
    /// Determines the upstream endpoint for this request.
    ///
    /// May modify `req` to add proxy headers or transform the request.
    /// Return [`Deny`] to reject the request with an error response.
    fn handle_request(
        &self,
        src_addr: SrcAddr,
        req: &mut HttpRequest,
    ) -> impl Future<Output = Result<EndpointId, Deny>> + Send;
}

/// Forward proxy handler that routes all requests to a fixed endpoint.
///
/// Validates that requests use proper forward-proxy form:
/// - CONNECT requests must use authority-form (`host:port`)
/// - Other requests must use absolute-form (`http://host/path`)
///
/// Adds `X-Forwarded-For` and `Via` headers to forwarded requests.
pub struct StaticForwardProxy(pub EndpointId);

impl RequestHandler for StaticForwardProxy {
    async fn handle_request(
        &self,
        src_addr: SrcAddr,
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
        req.set_forwarded_for_if_tcp(src_addr)
            .set_via("iroh-proxy")?;
        Ok(self.0)
    }
}

/// Reverse proxy handler that routes all requests to a fixed backend.
///
/// Validates that requests use origin-form (`/path`) and rejects:
/// - CONNECT requests (not supported in reverse proxy mode)
/// - Absolute-form requests in HTTP/1.x (forward proxy requests)
///
/// Transforms requests to absolute-form for forwarding to the upstream proxy,
/// and adds `X-Forwarded-For` and `Via` headers.
pub struct StaticReverseProxy(pub EndpointAuthority);

impl RequestHandler for StaticReverseProxy {
    async fn handle_request(
        &self,
        src_addr: SrcAddr,
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
        req.set_forwarded_for_if_tcp(src_addr)
            .set_via("iroh-proxy")?
            .set_absolute_http_authority(self.0.authority.clone())
            .map_err(|err| Deny::new(StatusCode::INTERNAL_SERVER_ERROR, err))?;
        Ok(self.0.endpoint_id)
    }
}

/// Chains multiple request handlers, trying each in order.
///
/// Returns the first successful result, or the last error if all handlers fail.
/// Useful for supporting both forward and reverse proxy modes simultaneously.
///
/// # Example
///
/// ```ignore
/// let handler = RequestHandlerChain::default()
///     .push(StaticForwardProxy(upstream_id))
///     .push(StaticReverseProxy(destination));
/// ```
#[derive(Default)]
pub struct RequestHandlerChain(Vec<Box<DynRequestHandler<'static>>>);

impl RequestHandlerChain {
    /// Appends a handler to the chain.
    pub fn push(mut self, handler: impl RequestHandler + 'static) -> Self {
        self.0.push(DynRequestHandler::new_box(handler));
        self
    }
}

impl RequestHandler for RequestHandlerChain {
    async fn handle_request(
        &self,
        src_addr: SrcAddr,
        req: &mut HttpRequest,
    ) -> Result<EndpointId, Deny> {
        let mut last_err = None;
        for handler in self.0.iter() {
            match handler.handle_request(src_addr.clone(), req).await {
                Ok(destination) => return Ok(destination),
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }
        Err(last_err.expect("err is set"))
    }
}

/// Request rejection with HTTP status code and reason.
///
/// Returned by [`RequestHandler`] to reject a request. The proxy will
/// send an error response to the client with the specified status code.
pub struct Deny {
    /// Human-readable explanation (for logging, not sent to client).
    pub reason: AnyError,
    /// HTTP status code to return to the client.
    pub code: StatusCode,
}

impl From<AnyError> for Deny {
    fn from(value: AnyError) -> Self {
        Self::bad_request(value)
    }
}

impl Deny {
    /// Creates a 400 Bad Request denial.
    pub fn bad_request(reason: impl Into<AnyError>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, reason)
    }

    /// Creates a denial with the specified status code and reason.
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
