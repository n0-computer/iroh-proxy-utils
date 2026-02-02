use std::{convert::Infallible, fmt::Debug, io, net::SocketAddr};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Empty, StreamBody, combinators::BoxBody};
use hyper::{
    Request, Response,
    body::{Frame, Incoming},
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{RecvStream, SendStream},
};
use iroh_blobs::util::connection_pool::{ConnectionPool, ConnectionRef};
use n0_error::{AnyError, Result, StdResultExt, anyerr, stack_error};
use n0_future::TryStreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error_span, warn};

pub use self::opts::{
    Deny, ErrorResponder, HttpProxyOpts, PoolOpts, ProxyMode, RequestHandler, RequestHandlerChain,
    StaticForwardProxy, StaticReverseProxy,
};
use crate::{
    ALPN, Authority, HEADER_SECTION_MAX_LENGTH,
    parse::{HttpRequest, HttpResponse},
    util::{Prebuffered, forward_bidi, recv_to_stream},
};

pub(crate) mod opts;

/// Proxy that accepts TCP connections and forwards them over iroh.
///
/// The downstream proxy is the client-facing component that receives incoming
/// TCP connections (typically HTTP requests) and routes them to upstream proxies
/// via iroh's peer-to-peer QUIC connections.
///
/// # Modes
///
/// - **TCP mode**: Blindly tunnels all traffic to a fixed upstream destination.
/// - **HTTP mode**: Parses HTTP requests to enable dynamic routing and supports
///   both forward proxy (absolute-form) and reverse proxy (origin-form) requests.
///
/// # Connection Pooling
///
/// Maintains a pool of iroh connections to upstream endpoints for efficiency.
/// Multiple requests to the same endpoint share a single QUIC connection.
#[derive(Clone, Debug)]
pub struct DownstreamProxy {
    pool: ConnectionPool,
}

impl DownstreamProxy {
    /// Creates a downstream proxy with the given endpoint and pool options.
    pub fn new(endpoint: Endpoint, opts: PoolOpts) -> Self {
        let pool = ConnectionPool::new(endpoint, ALPN, opts.into());
        Self { pool }
    }

    /// Opens a CONNECT tunnel to the upstream proxy and returns the client streams.
    ///
    /// Note: any non-`200 OK` response from upstream is returned as a `ProxyError`.
    pub async fn create_tunnel(
        &self,
        destination: &EndpointAuthority,
    ) -> Result<TunnelClientStreams, ProxyError> {
        let mut conn = self
            .connect(destination.endpoint_id)
            .await
            .map_err(ProxyError::gateway_timeout)?;
        conn.send
            .write_all(destination.authority.to_connect_request().as_bytes())
            .await?;
        let response = HttpResponse::read(&mut conn.recv)
            .await
            .map_err(ProxyError::bad_gateway)?;
        debug!(status=%response.status, "response from upstream");
        if response.status != StatusCode::OK {
            Err(ProxyError::new(
                Some(response.status),
                anyerr!("Upstream gateway returned error response"),
            ))
        } else {
            Ok(conn)
        }
    }

    /// Accepts TCP connections from the listener and forwards each in a new task.
    ///
    /// Runs indefinitely until the listener errors or the task is cancelled.
    pub async fn forward_tcp_listener(&self, listener: TcpListener, mode: ProxyMode) -> Result<()> {
        let cancel_token = CancellationToken::new();
        let _cancel_guard = cancel_token.clone().drop_guard();
        let mut id = 0;
        loop {
            let (client_stream, client_addr) = listener.accept().await?;
            let this = self.clone();
            let mode = mode.clone();
            tokio::spawn(
                cancel_token
                    .child_token()
                    .run_until_cancelled_owned(async move {
                        debug!(%client_addr, "accepted TCP connection");
                        if let Err(err) = this
                            .forward_tcp_stream(client_addr, client_stream, &mode)
                            .await
                        {
                            warn!("Failed to handle TCP connection: {err:#}");
                        }
                    })
                    .instrument(error_span!("tcp-accept", id)),
            );
            id += 1;
        }
    }

    /// Forwards a single TCP stream.
    ///
    /// For [`ProxyMode::Http`], this parses the first HTTP request from the stream, and then forwards or rejects according
    /// to the configured [`HttpProxyOpts`].
    /// For [`ProxyMode::Tcp`], this creates a CONNECT tunnel to the configured upstream and authority, and forwards the TCP
    /// stream without parsing anything.
    async fn forward_tcp_stream(
        &self,
        src_addr: SocketAddr,
        mut tcp_stream: TcpStream,
        mode: &ProxyMode,
    ) -> Result<()> {
        match mode {
            ProxyMode::Tcp(destination) => {
                let (mut tcp_recv, mut tcp_send) = tcp_stream.split();
                let mut conn = self.create_tunnel(destination).await?;
                debug!(endpoint_id=%conn.conn.remote_id().fmt_short(), "tunnel established");
                forward_bidi(&mut tcp_recv, &mut tcp_send, &mut conn.recv, &mut conn.send)
                    .await
                    .map_err(ProxyError::io)?;
                Ok(())
            }
            ProxyMode::Http(opts) => {
                let io = TokioIo::new(tcp_stream);
                let service = service_fn(|req| {
                    let this = self.clone();
                    let opts = opts.clone();
                    async move {
                        let res = match this.handle_hyper_request(src_addr, req, &opts).await {
                            Ok(res) => res,
                            Err(err) => {
                                warn!("Error while forwarding HTTP/2 request: {err:#}");
                                let status =
                                    err.response_status().unwrap_or(StatusCode::BAD_GATEWAY);
                                opts.error_response(status).await
                            }
                        };
                        Ok::<_, Infallible>(res)
                    }
                });
                let mut builder = auto::Builder::new(TokioExecutor::new());
                builder
                    .http2()
                    .initial_stream_window_size(1 << 20)
                    .initial_connection_window_size(1 << 20)
                    .max_concurrent_streams(1024);
                builder.serve_connection_with_upgrades(io, service).await?;
                Ok(())
            }
        }
    }

    async fn connect(&self, destination: EndpointId) -> Result<TunnelClientStreams, ProxyError> {
        let conn = self
            .pool
            .get_or_connect(destination)
            .await
            .map_err(|err| ProxyError::gateway_timeout(anyerr!(err)))?;
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|err| ProxyError::bad_gateway(anyerr!(err)))?;
        let recv = Prebuffered::new(recv, HEADER_SECTION_MAX_LENGTH);
        Ok(TunnelClientStreams { send, recv, conn })
    }

    async fn handle_hyper_request(
        &self,
        src_addr: SocketAddr,
        mut request: Request<Incoming>,
        opts: &HttpProxyOpts,
    ) -> Result<Response<HyperBody>, ProxyError> {
        debug!(?request, "incoming");

        let is_connect = request.method() == Method::CONNECT;

        // Handle upgrade for CONNECT requests over HTTP/1.
        let upgrade = if is_connect && request.version() < http::Version::HTTP_2 {
            Some(hyper::upgrade::on(&mut request))
        } else {
            None
        };

        let (parts, body) = request.into_parts();
        let mut request = HttpRequest::from_parts(parts);

        let destination = opts
            .request_handler
            .handle_request(src_addr, &mut request)
            .await?;

        debug!(destination=%destination.fmt_short(), ?request, "pipe request to upstream");

        // Connect to upstream.
        let mut conn = self.connect(destination).await?;

        debug!("connected to upstream");

        // Forward the request header section.
        request.write(&mut conn.send).await?;

        let (response, body) = if is_connect {
            // For CONNECT requests, we first read the upstream response, and afterwards pipe the body.
            let response = read_response(&mut conn.recv).await?;
            debug!(?response, "pipe response to client");

            if !response.status.is_success() {
                (response, None)
            } else if let Some(upgrade_fut) = upgrade {
                spawn(forward_hyper_upgrade(upgrade_fut, conn));
                (response, None)
            } else {
                spawn(forward_hyper_body(body, conn.send));
                (response, Some(conn.recv))
            }
        } else {
            // For non-CONNECT requests, we pipe the body and read the response concurrently.
            spawn(forward_hyper_body(body, conn.send));
            // Read the response from upstream.
            let response = read_response(&mut conn.recv).await?;
            (response, Some(conn.recv))
        };

        debug!(?response, "pipe response to client");
        response_to_hyper(response, body)
    }
}

/// Bidirectional QUIC streams for an established tunnel.
///
/// Returned by [`DownstreamProxy::create_tunnel`] after a successful CONNECT
/// handshake with the upstream proxy. Use these streams for bidirectional
/// data transfer through the tunnel.
pub struct TunnelClientStreams {
    /// Send stream toward the upstream proxy.
    pub send: SendStream,
    /// Receive stream from the upstream proxy (with read-ahead buffer).
    pub recv: Prebuffered<RecvStream>,
    /// Connection reference that keeps the QUIC connection alive.
    pub conn: ConnectionRef,
}

/// Routing destination combining an iroh endpoint and target authority.
///
/// Specifies both the upstream proxy to connect to (via `endpoint_id`) and
/// the origin server to reach through that proxy (via `authority`).
#[derive(Debug, Clone)]
pub struct EndpointAuthority {
    /// Iroh endpoint identifier of the upstream proxy.
    pub endpoint_id: EndpointId,
    /// Target authority for the CONNECT request (host:port).
    pub authority: Authority,
}

impl EndpointAuthority {
    /// Creates a new endpoint-authority pair.
    pub fn new(endpoint_id: EndpointId, authority: Authority) -> Self {
        Self {
            endpoint_id,
            authority,
        }
    }

    /// Returns a short string representation for logging.
    pub fn fmt_short(&self) -> String {
        format!("{}->{}", self.endpoint_id.fmt_short(), self.authority)
    }
}

/// Error from downstream proxy operations.
#[stack_error(add_meta, derive)]
pub struct ProxyError {
    response_status: Option<StatusCode>,
    #[error(source)]
    source: AnyError,
}

impl From<Deny> for ProxyError {
    #[track_caller]
    fn from(value: Deny) -> Self {
        ProxyError::new(Some(value.code), value.reason)
    }
}

impl From<io::Error> for ProxyError {
    fn from(value: io::Error) -> Self {
        Self::io(value)
    }
}

impl From<iroh::endpoint::WriteError> for ProxyError {
    fn from(value: iroh::endpoint::WriteError) -> Self {
        Self::io(anyerr!(value))
    }
}

impl ProxyError {
    /// Returns the HTTP status code to surface to the client, if any.
    pub fn response_status(&self) -> Option<StatusCode> {
        self.response_status
    }

    fn gateway_timeout(source: impl Into<AnyError>) -> Self {
        Self::new(Some(StatusCode::GATEWAY_TIMEOUT), source.into())
    }

    fn bad_gateway(source: impl Into<AnyError>) -> Self {
        Self::new(Some(StatusCode::BAD_GATEWAY), source.into())
    }

    fn io(source: impl Into<AnyError>) -> Self {
        Self::new(None, source.into())
    }
}

type HyperBody = BoxBody<Bytes, io::Error>;

fn response_to_hyper(
    response: HttpResponse,
    body: Option<Prebuffered<RecvStream>>,
) -> Result<Response<HyperBody>, ProxyError> {
    let mut builder = Response::builder().status(response.status);
    let headers = builder.headers_mut().unwrap();
    *headers = response.headers;
    let body = match body {
        Some(body) => StreamBody::new(recv_to_stream(body).map_ok(Frame::data)).boxed(),
        None => Empty::new().map_err(infallible_to_io).boxed(),
    };
    builder
        .body(body)
        .map_err(|err| ProxyError::bad_gateway(anyerr!(err)))
}

async fn forward_hyper_body(mut body: Incoming, mut send: SendStream) -> Result<()> {
    while let Some(frame) = body.frame().await {
        let frame = frame.anyerr()?;
        // TODO: Add support for trailers.
        if let Ok(data) = frame.into_data() {
            send.write_all(&data).await.anyerr()?;
        }
    }
    send.finish().anyerr()?;
    Ok(())
}

async fn forward_hyper_upgrade(
    upgrade_fut: hyper::upgrade::OnUpgrade,
    mut conn: TunnelClientStreams,
) -> Result<()> {
    let upgraded = upgrade_fut.await.std_context("HTTP/1 upgrade failed")?;
    let upgraded = TokioIo::new(upgraded);
    // Split the upgraded connection for bidirectional copy
    let (mut client_read, mut client_write) = tokio::io::split(upgraded);
    forward_bidi(
        &mut client_read,
        &mut client_write,
        &mut conn.recv,
        &mut conn.send,
    )
    .await?;
    Ok(())
}

async fn read_response(recv: &mut Prebuffered<RecvStream>) -> Result<HttpResponse, ProxyError> {
    HttpResponse::read(recv)
        .await
        .map_err(ProxyError::bad_gateway)
}

fn infallible_to_io(err: Infallible) -> io::Error {
    match err {}
}

fn spawn<F, T>(fut: F) -> tokio::task::JoinHandle<()>
where
    F: Future<Output = Result<T>> + Send + 'static,
{
    tokio::spawn(
        async move {
            if let Err(err) = fut.await {
                warn!("{err:#}")
            }
        }
        .instrument(tracing::Span::current()),
    )
}
