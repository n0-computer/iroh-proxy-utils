use std::{convert::Infallible, fmt::Debug, io, net::SocketAddr};

use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode};
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
use n0_error::{AnyError, Result, anyerr, stack_error};
use n0_future::{TryStreamExt, stream::Stream};
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

/// Accepts TCP streams and forwards them to upstream iroh destinations.
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
                        this.forward_tcp_stream(client_addr, client_stream, &mode)
                            .await
                            .ok();
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
        tcp_stream: TcpStream,
        mode: &ProxyMode,
    ) -> Result<()> {
        match mode {
            ProxyMode::Tcp(destination) => {
                if let Err(err) = self
                    .forward_tcp_stream_to_tunnel(tcp_stream, destination)
                    .await
                {
                    warn!("Error while forwarding TCP stream: {err:#}");
                }
            }
            ProxyMode::Http(opts) => {
                let this = self.clone();
                let io = TokioIo::new(tcp_stream);
                let service = service_fn(move |req| {
                    let this = this.clone();
                    let opts = opts.clone();
                    async move {
                        match this.handle_hyper_request(src_addr, req, &opts).await {
                            Ok(res) => Ok::<_, Infallible>(res),
                            Err(err) => {
                                warn!("Error while forwarding HTTP/2 request: {err:#}");
                                let status =
                                    err.response_status().unwrap_or(StatusCode::BAD_GATEWAY);
                                let res = opts.error_response(status).await;
                                Ok(res)
                            }
                        }
                    }
                });
                // Enable upgrades for HTTP/1.1 CONNECT support
                let mut builder = auto::Builder::new(TokioExecutor::new());
                builder
                    .http2()
                    .initial_stream_window_size(1 << 20)
                    .initial_connection_window_size(1 << 20)
                    .max_concurrent_streams(1024);
                if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
                    debug!(?err, "http connection closed with error");
                }
            }
        }
        Ok(())
    }

    pub async fn forward_tcp_stream_to_tunnel(
        &self,
        mut tcp_stream: TcpStream,
        destination: &EndpointAuthority,
    ) -> Result<(), ProxyError> {
        let (mut tcp_recv, mut tcp_send) = tcp_stream.split();
        let mut conn = self.create_tunnel(destination).await?;
        debug!(endpoint_id=%conn.conn.remote_id().fmt_short(), "tunnel established");
        forward_bidi(&mut tcp_recv, &mut tcp_send, &mut conn.recv, &mut conn.send)
            .await
            .map_err(ProxyError::io)?;
        Ok(())
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
        mut req: Request<Incoming>,
        opts: &HttpProxyOpts,
    ) -> Result<Response<HyperBody>, ProxyError> {
        debug!("handling request: {req:?}");

        if req.method() == Method::CONNECT {
            let upgrade = if req.version() < http::Version::HTTP_2 {
                Some(hyper::upgrade::on(&mut req))
            } else {
                None
            };

            let (parts, body) = req.into_parts();
            let mut request = HttpRequest::from_parts(parts);

            let destination = opts
                .request_handler
                .handle_request(src_addr, &mut request)
                .await?;
            // Connect to upstream and send the CONNECT request
            let mut conn = self.connect(destination).await?;
            request.write(&mut conn.send).await?;
            // Read the response from upstream
            let response = HttpResponse::read(&mut conn.recv)
                .await
                .map_err(ProxyError::bad_gateway)?;
            debug!(?response, "upstream CONNECT response");

            if response.status != StatusCode::OK {
                // Forward the error response from upstream
                return Ok(h2_error_response(response.status));
            }

            // For HTTP/1.1, use the upgrade mechanism
            // For HTTP/2, use the body streams
            if let Some(upgrade_fut) = upgrade {
                // HTTP/1.1 path: after returning 200 OK, the connection is upgraded
                // Spawn a task that waits for the upgrade and then handles bidirectional copy
                tokio::spawn(async move {
                    forward_upgrade(&mut conn, upgrade_fut).await;
                });

                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Empty::new().map_err(infallible_to_io).boxed())
                    .unwrap())
            } else {
                // HTTP/2 path: request body and response body are the bidirectional tunnel
                tokio::spawn(async move {
                    if let Err(err) = forward_hyper_body(body, &mut conn.send).await {
                        debug!("CONNECT client->upstream pipe ended: {err:#}");
                    }
                });
                http1_response_to_hyper(response, conn.recv)
            }
        } else {
            let (parts, body) = req.into_parts();
            let mut request = HttpRequest::from_parts(parts);

            debug!(?request, "get destination for");
            let destination = opts
                .request_handler
                .handle_request(src_addr, &mut request)
                .await?;
            debug!("destination: {destination}");
            let mut conn = self.connect(destination).await?;
            request.write(&mut conn.send).await?;
            tokio::spawn(async move {
                if let Err(err) = forward_hyper_body(body, &mut conn.send).await {
                    warn!("failed to forward request body to upstream: {err:#}");
                }
            });
            let response = read_http1_response_to_hyper(conn.recv).await?;
            Ok(response)
        }
    }
}

async fn forward_upgrade(conn: &mut TunnelClientStreams, upgrade_fut: hyper::upgrade::OnUpgrade) {
    match upgrade_fut.await {
        Ok(upgraded) => {
            let upgraded = TokioIo::new(upgraded);
            // Split the upgraded connection for bidirectional copy
            let (mut client_read, mut client_write) = tokio::io::split(upgraded);
            if let Err(err) = forward_bidi(
                &mut client_read,
                &mut client_write,
                &mut conn.recv,
                &mut conn.send,
            )
            .await
            {
                debug!("CONNECT bidi copy ended: {err:#}");
            }
        }
        Err(err) => {
            warn!("CONNECT upgrade failed: {err:#}");
        }
    }
}

/// Bidirectional streams for a single iroh tunnel.
pub struct TunnelClientStreams {
    /// QUIC send stream toward the upstream proxy.
    pub send: SendStream,
    /// QUIC recv stream from the upstream proxy.
    pub recv: Prebuffered<RecvStream>,
    /// Connection handle kept alive for the tunnel lifetime.
    pub conn: ConnectionRef,
}

#[derive(Debug, Clone)]
/// Endpoint identifier paired with the target authority.
pub struct EndpointAuthority {
    /// Destination iroh endpoint identifier.
    pub endpoint_id: EndpointId,
    /// Target authority for the CONNECT request.
    pub authority: Authority,
}

impl EndpointAuthority {
    /// Constructs an `EndpointAuthority` from its components.
    pub fn new(endpoint_id: EndpointId, authority: Authority) -> Self {
        Self {
            endpoint_id,
            authority,
        }
    }

    pub fn fmt_short(&self) -> String {
        format!("{}->{}", self.endpoint_id.fmt_short(), self.authority)
    }
}

/// Error type for downstream proxy failures.
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

async fn read_http1_response_to_hyper(
    mut recv: Prebuffered<RecvStream>,
) -> Result<Response<HyperBody>, ProxyError> {
    let response = HttpResponse::read(&mut recv)
        .await
        .map_err(ProxyError::bad_gateway)?;
    tracing::info!(?response, "downstream read response");
    http1_response_to_hyper(response, recv)
}

fn http1_response_to_hyper(
    response: HttpResponse,
    recv: Prebuffered<RecvStream>,
) -> Result<Response<HyperBody>, ProxyError> {
    let mut builder = Response::builder().status(response.status);
    let headers = builder.headers_mut().unwrap();
    for (name, value) in response.headers.iter() {
        //     if should_drop_response_header(name) {
        //         continue;
        //     }
        headers.append(name, value.clone());
    }
    let body = recv_to_stream_body(recv).boxed();
    builder
        .body(body)
        .map_err(|err| ProxyError::bad_gateway(anyerr!(err)))
}

// fn should_drop_request_header(name: &http::HeaderName) -> bool {
//     matches!(
//         name.as_str(),
//         "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade" | "te"
//     )
// }

// fn should_drop_response_header(name: &http::HeaderName) -> bool {
//     matches!(
//         name.as_str(),
//         "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade" | "te"
//     )
// }

fn recv_to_stream_body(
    recv: Prebuffered<RecvStream>,
) -> StreamBody<impl Stream<Item = io::Result<Frame<Bytes>>>> {
    StreamBody::new(recv_to_stream(recv).map_ok(Frame::data))
}

fn h2_error_response(status: StatusCode) -> Response<HyperBody> {
    // let reason = status.canonical_reason().unwrap_or("");
    // let content = format!("{} {}", status.as_u16(), reason);
    let body = Empty::new().map_err(infallible_to_io);
    let mut res = Response::builder().status(status);
    res.headers_mut().unwrap().insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str("0").unwrap(),
    );
    res.body(body.boxed()).unwrap()
    // .unwrap_or_else(|_| {
    //     Response::new(Full::new(Bytes::new()).map_err(infallible_to_io).boxed())
    // })
}

async fn forward_hyper_body(mut body: Incoming, send: &mut SendStream) -> Result<(), ProxyError> {
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|err| ProxyError::io(anyerr!(err)))?;
        // TODO: Add support for trailers.
        if let Ok(data) = frame.into_data() {
            send.write_all(&data).await?;
        }
    }
    send.finish()
        .map_err(io::Error::from)
        .map_err(ProxyError::io)?;
    Ok(())
}

fn infallible_to_io(err: Infallible) -> io::Error {
    match err {}
}
