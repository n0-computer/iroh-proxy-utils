use std::{convert::Infallible, fmt::Debug, io, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http::{Method, StatusCode, Version, header};
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
    endpoint::{ConnectionError, RecvStream, SendStream},
};
use iroh_blobs::util::connection_pool::{self, ConnectionPool, ConnectionRef};
use n0_error::{AnyError, Result, StdResultExt, anyerr, stack_error};
use n0_future::TryStreamExt;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::{io::ReaderStream, sync::CancellationToken};
use tracing::{Instrument, debug, error_span, warn};

pub use self::opts::{
    Deny, ErrorResponder, HttpProxyOpts, PoolOpts, ProxyMode, RequestHandler, RequestHandlerChain,
    StaticForwardProxy, StaticReverseProxy,
};
use crate::{
    ALPN, Authority, HEADER_SECTION_MAX_LENGTH, inc_by_delta,
    parse::{HttpRequest, HttpResponse},
    util::{
        Prebufferable, Prebuffered, StreamEvent, TrackedRead, TrackedStream, TrackedWrite,
        forward_bidi, nores,
    },
};

pub(crate) mod metrics;
pub use self::metrics::DownstreamMetrics;
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
    metrics: Arc<DownstreamMetrics>,
}

impl DownstreamProxy {
    /// Creates a downstream proxy with the given endpoint and pool options.
    pub fn new(endpoint: Endpoint, pool_opts: PoolOpts) -> Self {
        let metrics = Arc::new(DownstreamMetrics::default());
        let opts: connection_pool::Options = pool_opts.into();

        // Track connection open/close metrics.
        let pool_opts = opts.with_on_connected({
            let metrics = metrics.clone();
            // This conn clone is *not* protected by a pool guard, so by awaiting its close method
            // we don't keep the connection alive post-idle.
            move |_endpoint, unguarded_conn| {
                let metrics = metrics.clone();
                async move {
                    metrics.iroh_connections_opened.inc();
                    let metrics = metrics.clone();
                    tokio::spawn(async move {
                        let reason = unguarded_conn.closed().await;
                        match reason {
                            ConnectionError::LocallyClosed => {
                                metrics.iroh_connections_closed_idle.inc();
                            }
                            // It's always us that closes connections gracefully.
                            _ => {
                                metrics.iroh_connections_closed_error.inc();
                            }
                        }
                    });
                    Ok(())
                }
            }
        });

        let pool = ConnectionPool::new(endpoint, ALPN, pool_opts);
        Self { pool, metrics }
    }

    /// Returns the downstream metrics tracker.
    pub fn metrics(&self) -> &Arc<DownstreamMetrics> {
        &self.metrics
    }

    /// Opens a CONNECT tunnel to the upstream proxy and returns the client streams.
    ///
    /// Note: any non-`200 OK` response from upstream is returned as a `ProxyError`.
    pub async fn create_tunnel(
        &self,
        destination: &EndpointAuthority,
    ) -> Result<TunnelClientStreams, ProxyError> {
        let (conn, mut send, recv) = self
            .connect(destination.endpoint_id)
            .await
            .map_err(ProxyError::gateway_timeout)?;
        send.write_all(destination.authority.to_connect_request().as_bytes())
            .await?;
        let mut recv = Prebuffered::new(recv, HEADER_SECTION_MAX_LENGTH);
        let response = HttpResponse::read(&mut recv)
            .await
            .map_err(ProxyError::bad_gateway)?;
        debug!(status=%response.status, "response from upstream");
        if response.status != StatusCode::OK {
            Err(ProxyError::new(
                Some(response.status),
                anyerr!("Upstream gateway returned error response"),
            ))
        } else {
            Ok(TunnelClientStreams { send, recv, conn })
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
            let (stream, addr) = listener.accept().await?;
            let span = error_span!("tcp-accept", id);
            let addr = SrcAddr::Tcp(addr);
            self.spawn_forward_stream(addr, stream, mode.clone(), span, cancel_token.child_token());
            id += 1;
        }
    }

    /// Accepts UDS connections from the Unix Domain Socket and forwards each in a new task.
    ///
    /// Runs indefinitely until the listener errors or the task is cancelled.
    #[cfg(unix)]
    pub async fn forward_uds_listener(
        &self,
        listener: tokio::net::UnixListener,
        mode: ProxyMode,
    ) -> Result<()> {
        let cancel_token = CancellationToken::new();
        let _cancel_guard = cancel_token.clone().drop_guard();
        let mut id = 0;
        loop {
            let (stream, addr) = listener.accept().await?;
            let addr = SrcAddr::Unix(addr.into());
            let span = error_span!("uds-accept", id);
            self.spawn_forward_stream(addr, stream, mode.clone(), span, cancel_token.child_token());
            id += 1;
        }
    }

    fn spawn_forward_stream(
        &self,
        client_addr: SrcAddr,
        stream: impl SplittableStream,
        mode: ProxyMode,
        span: tracing::Span,
        cancel_token: CancellationToken,
    ) {
        let this = self.clone();
        tokio::spawn(
            cancel_token
                .child_token()
                .run_until_cancelled_owned(async move {
                    debug!(%client_addr, "accepted connection");
                    if let Err(err) = this.forward_stream(client_addr, stream, &mode).await {
                        warn!("Failed to handle connection: {err:#}");
                    }
                })
                .instrument(span),
        );
    }

    /// Forwards a single TCP stream.
    ///
    /// For [`ProxyMode::Http`], this parses the first HTTP request from the stream, and then forwards or rejects according
    /// to the configured [`HttpProxyOpts`].
    /// For [`ProxyMode::Tcp`], this creates a CONNECT tunnel to the configured upstream and authority, and forwards the TCP
    /// stream without parsing anything.
    async fn forward_stream(
        &self,
        src_addr: SrcAddr,
        mut stream: impl SplittableStream + 'static,
        mode: &ProxyMode,
    ) -> Result<()> {
        match mode {
            ProxyMode::Tcp(destination) => {
                self.metrics.requests_accepted.inc();
                self.metrics.requests_accepted_tcp.inc();
                let (tcp_recv, tcp_send) = stream.split();
                let mut conn = self.create_tunnel(destination).await?;
                debug!(endpoint_id=%conn.conn.remote_id().fmt_short(), "tunnel established");
                let metrics = self.metrics.clone();
                let mut tcp_recv =
                    TrackedRead::new(tcp_recv, inc_by_delta!(metrics, bytes_to_upstream));
                let mut tcp_send =
                    TrackedWrite::new(tcp_send, inc_by_delta!(metrics, bytes_from_upstream));
                let res =
                    forward_bidi(&mut tcp_recv, &mut tcp_send, &mut conn.recv, &mut conn.send)
                        .await
                        .map_err(ProxyError::io);
                match res {
                    Ok(_) => {
                        self.metrics.requests_completed.inc();
                        Ok(())
                    }
                    Err(err) => {
                        self.metrics.requests_failed.inc();
                        Err(err.into())
                    }
                }
            }
            ProxyMode::Http(opts) => {
                let io = TokioIo::new(stream);
                let service = service_fn(|req| {
                    let this = self.clone();
                    let opts = opts.clone();
                    let src_addr = src_addr.clone();
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
                    .max_concurrent_streams(1024)
                    .enable_connect_protocol();
                builder.serve_connection_with_upgrades(io, service).await?;
                Ok(())
            }
        }
    }

    async fn connect(
        &self,
        destination: EndpointId,
    ) -> Result<(ConnectionRef, SendStream, RecvStream), ProxyError> {
        let conn = self
            .pool
            .get_or_connect(destination)
            .await
            .map_err(|err| ProxyError::gateway_timeout(anyerr!(err)))?;
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|err| ProxyError::bad_gateway(anyerr!(err)))?;
        Ok((conn, send, recv))
    }

    async fn handle_hyper_request(
        &self,
        src_addr: SrcAddr,
        mut request: Request<Incoming>,
        opts: &HttpProxyOpts,
    ) -> Result<Response<HyperBody>, ProxyError> {
        debug!(?request, "incoming");

        let original_version = request.version();
        let is_upgrade = request.headers().contains_key(header::UPGRADE);
        let is_connect = request.method() == Method::CONNECT;
        let is_h2_extended_connect = convert_h2_extended_connect_to_upgrade(&mut request);
        let upgrade = if is_connect || is_upgrade {
            Some(hyper::upgrade::on(&mut request))
        } else {
            None
        };

        let (parts, body) = request.into_parts();
        let mut request = HttpRequest::from_parts(parts);

        let metrics = self.metrics.clone();

        let destination = match opts
            .request_handler
            .handle_request(src_addr, &mut request)
            .await
        {
            Ok(destination) => destination,
            Err(deny) => {
                metrics.requests_denied.inc();
                return Err(ProxyError::from(deny));
            }
        };

        // track metrics.
        metrics.requests_accepted.inc();
        if original_version == Version::HTTP_2 {
            metrics.requests_accepted_h2.inc();
            if is_connect {
                if is_h2_extended_connect {
                    metrics.requests_accepted_h2_extended_connect.inc();
                } else {
                    metrics.requests_accepted_h2_connect.inc();
                }
            }
        } else {
            metrics.requests_accepted_h1.inc();
            if is_connect {
                metrics.requests_accepted_h1_connect.inc();
            }
            if is_upgrade {
                metrics.requests_accepted_h1_upgrade.inc();
            }
        }

        // We always forward as HTTP/1.1.
        request.version = Version::HTTP_11;
        // Now we shouldn't mutate the request anymore.
        let request = request;

        debug!(destination=%destination.fmt_short(), ?request, is_connect, is_h2_extended_connect, is_upgrade, "pipe request to upstream");

        // Connect to upstream.
        let (conn, send, recv) = self.connect(destination).await?;
        debug!(endpoint_id=%conn.remote_id().fmt_short(), "connected to upstream");

        // We need to keep `conn` alive until the request is fully processed in both directions.
        // `conn` is a `ConnectionRef` guard handed out from the connection pool. Once it is dropped,
        // the connection is marked as idle, and will be closed after the idle timeout.
        let conn_guard = Arc::new(conn);

        // We want to track bytes written to/from upstream. And we store the `conn_guard` into the streams.
        // Once both streams are dropped, the request is fully done, and we can drop the conn ref safely.
        let mut upstream_send = TrackedWrite::new(send, inc_by_delta!(metrics, bytes_to_upstream))
            .with_guard(conn_guard.clone());
        let upstream_recv = TrackedRead::new(recv, inc_by_delta!(metrics, bytes_from_upstream))
            .with_guard(conn_guard.clone());
        // We need to prebuffer for reading the response before passing it on.
        let mut upstream_recv = Prebuffered::new(upstream_recv, HEADER_SECTION_MAX_LENGTH);

        // Send request headers.
        request.write(&mut upstream_send).await?;

        let response = if let Some(upgrade_fut) = upgrade {
            // For upgrade requests: First read the response to see if the upgrade was accepted.
            // Only then forward the request body as upgrade stream.
            let mut response = match read_response(&mut upstream_recv).await {
                Ok(response) => response,
                Err(err) => {
                    metrics.requests_failed.inc();
                    return Err(err.into());
                }
            };
            debug!(?response, "read connect response");

            if is_h2_extended_connect && response.status == StatusCode::SWITCHING_PROTOCOLS {
                response.status = StatusCode::OK;
                response.headers.remove(header::UPGRADE);
                response.headers.remove(header::CONNECTION);
            }

            let is_ok = is_connect && response.status == StatusCode::OK
                || is_upgrade && response.status == StatusCode::SWITCHING_PROTOCOLS;

            if is_ok {
                spawn(forward_hyper_upgrade(
                    upgrade_fut,
                    upstream_recv,
                    upstream_send,
                ));
                response_to_hyper::<tokio::io::Empty>(response, None, metrics)?
            } else if request.method == Method::CONNECT {
                response_to_hyper::<tokio::io::Empty>(response, None, metrics)?
            } else {
                spawn(forward_hyper_body_and_finish(body, upstream_send));
                response_to_hyper(response, Some(upstream_recv), metrics)?
            }
        } else {
            // For non-upgrade requests: Forward the body and read the response concurrently.
            spawn(forward_hyper_body_and_finish(body, upstream_send));
            let response = match read_response(&mut upstream_recv).await {
                Ok(response) => response,
                Err(err) => {
                    metrics.requests_failed.inc();
                    return Err(err.into());
                }
            };
            debug!(
                status = %response.status,
                "received response header from upstream"
            );
            response_to_hyper(response, Some(upstream_recv), metrics)?
        };

        Ok(response)
    }
}

fn convert_h2_extended_connect_to_upgrade(request: &mut Request<Incoming>) -> bool {
    if request.version() != Version::HTTP_2 {
        return false;
    }
    // Handle HTTP/2 extended CONNECT (RFC 8441) - convert to upgrade-style request.
    // Extended CONNECT uses :protocol pseudo-header instead of Upgrade header.
    let extended_connect_protocol = request
        .extensions()
        .get::<hyper::ext::Protocol>()
        .map(|p| p.as_str().to_string());
    if let Some(protocol) = extended_connect_protocol {
        debug!(%protocol, "extended CONNECT request, converting to upgrade request");
        *request.method_mut() = Method::GET;
        request
            .headers_mut()
            .insert(header::UPGRADE, protocol.parse().unwrap());
        request
            .headers_mut()
            .insert(header::CONNECTION, "upgrade".parse().unwrap());
        true
    } else {
        false
    }
}

trait SplittableStream: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {
    fn split<'a>(
        &'a mut self,
    ) -> (
        impl AsyncRead + Send + Unpin + 'a,
        impl AsyncWrite + Send + Unpin + 'a,
    );
}

impl SplittableStream for TcpStream {
    fn split<'a>(
        &'a mut self,
    ) -> (
        impl AsyncRead + Send + Unpin + 'a,
        impl AsyncWrite + Send + Unpin + 'a,
    ) {
        TcpStream::split(self)
    }
}

#[cfg(unix)]
impl SplittableStream for tokio::net::UnixStream {
    fn split<'a>(
        &'a mut self,
    ) -> (
        impl AsyncRead + Send + Unpin + 'a,
        impl AsyncWrite + Send + Unpin + 'a,
    ) {
        tokio::net::UnixStream::split(self)
    }
}

/// Source address for downstream client streams.
#[derive(derive_more::From, Debug, Clone, derive_more::Display)]
pub enum SrcAddr {
    /// TCP source address
    #[display("{_0}")]
    Tcp(SocketAddr),
    /// UDS source address
    #[cfg(unix)]
    #[display("Unix({_0:?})")]
    Unix(std::os::unix::net::SocketAddr),
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

fn response_to_hyper<R>(
    response: HttpResponse,
    body: Option<R>,
    metrics: Arc<DownstreamMetrics>,
) -> Result<Response<HyperBody>, ProxyError>
where
    R: AsyncRead + Send + Sync + Unpin + 'static,
{
    let mut builder = Response::builder().status(response.status);
    let headers = builder.headers_mut().unwrap();
    *headers = response.headers;
    let body = match body {
        Some(body) => {
            let stream = ReaderStream::new(body);
            let stream = TrackedStream::new(stream, move |ev| match ev {
                StreamEvent::Done(Ok(())) => nores(metrics.requests_completed.inc()),
                StreamEvent::Done(Err(_)) => nores(metrics.requests_failed.inc()),
                _ => {}
            });
            StreamBody::new(stream.map_ok(Frame::data)).boxed()
        }
        None => Empty::new().map_err(infallible_to_io).boxed(),
    };
    builder
        .body(body)
        .map_err(|err| ProxyError::bad_gateway(anyerr!(err)))
}

async fn forward_hyper_body_and_finish<F, G: Unpin>(
    body: Incoming,
    mut send: TrackedWrite<SendStream, F, G>,
) -> Result<()>
where
    F: Fn(u64) + Unpin + Send + 'static,
{
    forward_hyper_body(body, &mut send).await?;
    send.into_inner().finish().anyerr()?;
    Ok(())
}

/// Forwards hyper body to send stream without finishing.
/// Used for upgrade requests where we may need to continue using the stream.
async fn forward_hyper_body(
    mut body: Incoming,
    send: &mut (impl AsyncWrite + Unpin),
) -> Result<()> {
    while let Some(frame) = body.frame().await {
        let frame = frame.anyerr()?;
        // TODO: Add support for trailers.
        if let Ok(data) = frame.into_data() {
            send.write_all(&data).await.anyerr()?;
        }
    }
    Ok(())
}

async fn forward_hyper_upgrade(
    upgrade_fut: hyper::upgrade::OnUpgrade,
    mut upstream_recv: impl AsyncRead + Send + Unpin,
    mut upstream_send: impl AsyncWrite + Send + Unpin,
) -> Result<()> {
    let upgraded = upgrade_fut.await.std_context("HTTP/1 upgrade failed")?;
    let upgraded = TokioIo::new(upgraded);
    // Split the upgraded connection for bidirectional copy
    let (mut client_read, mut client_write) = tokio::io::split(upgraded);
    forward_bidi(
        &mut client_read,
        &mut client_write,
        &mut upstream_recv,
        &mut upstream_send,
    )
    .await?;
    Ok(())
}

async fn read_response(recv: &mut impl Prebufferable) -> Result<HttpResponse, ProxyError> {
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
