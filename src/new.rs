use std::{path::Path, sync::Arc};

use dynosaur::dynosaur;
use http::Method;
use iroh::{EndpointId, protocol::ProtocolHandler};
use iroh_blobs::util::connection_pool::ConnectionPool;
use tokio::net::{TcpListener, TcpStream};

use crate::{AuthError, Authority};

/// Forwards incoming iroh streams to TCP destinations.
#[derive(derive_more::Debug)]
pub struct IrohToTcpProxy {
    #[debug("Arc<dyn OutboundAuth>")]
    auth: Arc<DynAuthHandler<'static>>,
}

impl ProtocolHandler for IrohToTcpProxy {
    fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> impl Future<Output = Result<(), iroh::protocol::AcceptError>> + Send {
        async { todo!() }
    }
}

#[dynosaur(DynAuthHandler = dyn(box) AuthHandler)]
pub trait AuthHandler: Send + Sync {
    fn authorize<'a>(
        &'a self,
        remote_id: EndpointId,
        req: &'a HttpRequest,
    ) -> impl Future<Output = Result<(), AuthError>> + Send + 'a;
}

/// Forwards incoming TCP connections to iroh destinations.
pub struct TcpToIrohProxy {
    pool: ConnectionPool,
}

impl TcpToIrohProxy {
    pub async fn create_tunnel(&self, destination: EndpointAuthority) {}
    pub async fn forward_tcp_stream(&self, tcp_stream: TcpStream, mode: &ProxyMode) {}
    pub async fn forward_tcp_listener(&self, tcp_listener: TcpListener, mode: &ProxyMode) {}
}

#[derive(Debug)]
pub struct HttpRequest {
    pub kind: HttpRequestKind,
    pub headers: http::HeaderMap<http::HeaderValue>,
}

#[derive(Debug)]
pub enum HttpRequestKind {
    /// Tunnel CONNECT request with authority-form request target.
    Tunnel { authority: Authority },
    /// Forward-proxy request with absolute-form request target.
    Absolute { target: String, method: Method },
    /// Direct origin request with origin-form request target.
    Origin {
        path: String,
        host: Option<String>,
        method: Method,
    },
}

pub enum ProxyRequestKind {
    /// Tunnel CONNECT request with authority-form request target.
    Tunnel { authority: Authority },
    /// Forward-proxy request with absolute-form request target.
    Absolute { target: String, method: Method },
}

#[derive(Debug, Clone)]
struct ProxyMode {
    /// Forward-proxy mode: Accepts CONNECT or forward-proxy requests.
    forward: Option<ForwardProxyMode>,
    /// Reverse-proxy mode: Accepts regular origin HTTP requests.
    reverse: Option<ReverseProxyMode>,
}

#[derive(derive_more::Debug, Clone)]
enum ForwardProxyMode {
    Static(EndpointId),
    #[debug("DynExtractEndpoint")]
    Dynamic(Arc<DynExtractEndpoint<'static>>),
}

impl<T: ExtractEndpoint + 'static> From<T> for ForwardProxyMode {
    fn from(value: T) -> Self {
        Self::Dynamic(DynExtractEndpoint::new_arc(value))
    }
}

#[derive(derive_more::Debug, Clone)]
enum ReverseProxyMode {
    Static(EndpointAuthority),
    #[debug("DynExtractEndpointAuthority")]
    Dynamic(Arc<DynExtractEndpointAuthority<'static>>),
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

#[dynosaur(DynExtractEndpoint = dyn(box) ExtractEndpoint)]
trait ExtractEndpoint: Send + Sync {
    fn extract_endpoint<'a>(
        &'a self,
        req: &'a HttpRequest,
    ) -> impl Future<Output = Result<EndpointId, ExtractError>> + Send + 'a;
}

#[dynosaur(DynExtractEndpointAuthority = dyn(box) ExtractEndpointAuthority)]
trait ExtractEndpointAuthority: Send + Sync {
    fn extract_endpoint_authority<'a>(
        &'a self,
        req: &'a HttpRequest,
    ) -> impl Future<Output = Result<EndpointAuthority, ExtractError>> + Send + 'a;
}

enum ExtractError {
    Unauthorized,
    NotFound,
    InternalError,
}
