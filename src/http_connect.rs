use std::{fmt::Debug, sync::Arc, time::Duration};

use bytes::Bytes;
use http::StatusCode;
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
};
use iroh_blobs::util::connection_pool::{self, ConnectionPool, ConnectionRef};
use n0_error::{AnyError, Result, StdResultExt, anyerr, stack_error};
use n0_future::stream::StreamExt;
use quinn::ConnectionError;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error_span, instrument, warn};

use crate::{
    auth::{AuthHandler, DynAuthHandler},
    gateway::{EndpointAuthority, ExtractError, ProxyMode},
    parse::{HttpProxyRequestKind, HttpRequest, HttpRequestKind, HttpResponse},
    util::{forward_bidi, write_http_response_message},
};

/// how much data to read for the CONNECT handshake before it's considered invalid
/// 8KB should be plenty.
pub(crate) const HEADER_SECTION_MAX_LENGTH: usize = 8192;

/// HTTP header for iroh addressing info
pub const IROH_DESTINATION_HEADER: &str = "Iroh-Destination";
// /// The ALPN that we're using for iroh connections
pub const ALPN: &[u8] = b"iroh-http-proxy";

/// The `UpstreamProxy` accepts iroh streams and forwards them to upstream TCP destinations.
///
/// It implements [`ProtocolHandler`] and is intended to be mounted onto a [`Router`].
///
/// [`Router`]: iroh::protocol::Router
#[derive(derive_more::Debug)]
pub struct UpstreamProxy {
    #[debug("Arc<dyn AuthHandler>")]
    auth: Arc<DynAuthHandler<'static>>,
}

impl ProtocolHandler for UpstreamProxy {
    #[instrument("accept", skip_all, fields(remote=%connection.remote_id().fmt_short()))]
    async fn accept(
        &self,
        connection: Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        self.handle_connection(connection)
            .await
            .map_err(AcceptError::from_err)
    }
}

impl UpstreamProxy {
    pub fn new(auth: impl AuthHandler + 'static) -> Result<Self> {
        Ok(Self {
            auth: DynAuthHandler::new_arc(auth),
        })
    }

    async fn handle_connection(&self, connection: Connection) -> Result<()> {
        let remote_id = connection.remote_id();
        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(ConnectionError::ApplicationClosed(_)) => return Ok(()),
                Err(err) => return Err(err).std_context("connection closed"),
            };
            let auth = self.auth.clone();
            tokio::spawn(
                async move {
                    if let Err(err) = Self::handle_remote_streams(auth, remote_id, send, recv).await
                    {
                        warn!("Failed to handle streams: {err:#}");
                    }
                }
                .instrument(tracing::Span::current()),
            );
        }
    }

    async fn handle_remote_streams(
        auth: Arc<DynAuthHandler<'static>>,
        remote_id: EndpointId,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        let (initial_data, req) = HttpRequest::read(&mut recv, HEADER_SECTION_MAX_LENGTH).await?;

        debug!(?req, "incoming request");

        match auth.authorize(remote_id, &req).await {
            Ok(()) => debug!("request is authorized, continue"),
            Err(err) => {
                debug!("request is not authorized, abort");
                return Err(err.into());
            }
        };

        match req.kind {
            HttpRequestKind::Proxy(HttpProxyRequestKind::Tunnel { target: authority }) => {
                match TcpStream::connect(authority.to_addr()).await {
                    Err(err) => {
                        warn!("Failed to connect to upstream server: {err:#}");
                        write_http_response_message(&mut send, http::StatusCode::BAD_GATEWAY, None)
                            .await?;
                        send.finish().anyerr()?;
                    }
                    Ok(tcp_stream) => {
                        debug!(?authority, "connected to upstream");
                        write_http_response_message(
                            &mut send,
                            http::StatusCode::OK,
                            Some("Connection established"),
                        )
                        .await?;
                        let (mut tcp_recv, mut tcp_send) = tcp_stream.into_split();
                        let initial_request_data = &initial_data.after_header_section();
                        tcp_send.write_all(&initial_request_data).await?;
                        forward_bidi(&mut tcp_recv, &mut tcp_send, &mut recv, &mut send).await?;
                    }
                }
            }
            HttpRequestKind::Proxy(HttpProxyRequestKind::Absolute { method, target }) => {
                // TODO: Filter out headers that should not be forwarded to upstream.
                let client = reqwest::Client::new();
                let res = client
                    .request(method, target)
                    .headers(req.headers)
                    .send()
                    .await
                    .anyerr()?;

                write_header_section(&res, &mut send).await?;
                let mut body = res.bytes_stream();
                while let Some(bytes) = body.next().await {
                    let bytes = bytes.anyerr()?;
                    send.write_chunk(bytes).await.anyerr()?;
                }
                send.finish().anyerr()?;
            }
            HttpRequestKind::Origin { .. } => {
                warn!("Received origin-form HTTP request without reverse-proxy context");
                return Err(anyerr!(
                    "Invalid request: Received origin-form HTTP request without reverse-proxy context"
                ));
            }
        }
        Ok(())
    }
}

/// The `DownstreamProxy` accepts TCP streams and forwards them to upstream iroh destinations.
#[derive(Clone, Debug)]
pub struct DownstreamProxy {
    pool: ConnectionPool,
}

impl DownstreamProxy {
    pub fn new(endpoint: Endpoint, opts: PoolOptions) -> Self {
        let pool = ConnectionPool::new(endpoint, ALPN, opts.into());
        Self { pool }
    }

    async fn connect(&self, destination: EndpointId) -> Result<TunnelClientStreams> {
        let conn = self
            .pool
            .get_or_connect(destination)
            .await
            .std_context("failed to connect to remote")?;
        let (send, recv) = conn
            .open_bi()
            .await
            .std_context("failed to open streams to remote")?;
        Ok(TunnelClientStreams { send, recv, conn })
    }

    pub async fn forward_tcp_listener(&self, listener: TcpListener, mode: ProxyMode) -> Result<()> {
        let cancel_token = CancellationToken::new();
        let _cancel_guard = cancel_token.clone().drop_guard();
        loop {
            let (client_stream, client_addr) = listener.accept().await?;
            let this = self.clone();
            let mode = mode.clone();
            tokio::spawn(
                cancel_token
                    .child_token()
                    .run_until_cancelled_owned(async move {
                        this.forward_tcp_stream(client_stream, &mode).await
                    })
                    .instrument(error_span!("tcp-conn", client=%client_addr)),
            );
        }
    }

    pub async fn create_tunnel(
        &self,
        destination: EndpointAuthority,
    ) -> Result<(Bytes, TunnelClientStreams), ProxyError> {
        let mut conn = self
            .connect(destination.endpoint_id)
            .await
            .map_err(|err| ProxyError::gateway_timeout(err))?;
        conn.send
            .write_all(destination.authority.to_connect_request().as_bytes())
            .await?;
        debug!("created tunnel");
        let (initial_data, response) = HttpResponse::read(&mut conn.recv, 1024)
            .await
            .map_err(|err| ProxyError::bad_gateway(err))?;
        debug!(?response, "got proxy response");
        if response.status != StatusCode::OK {
            return Err(ProxyError::new(
                Some(response.status),
                anyerr!("Upstream gateway returned error response"),
            ));
        }
        Ok((initial_data.after_header_section(), conn))
    }

    pub async fn forward_tcp_stream(&self, mut conn: TcpStream, mode: &ProxyMode) {
        if let Err(err) = self.forward_tcp_stream_inner(&mut conn, mode).await {
            warn!("Forwarding TCP stream closed with error: {err:#}");
            if let Some(status) = err.response_status() {
                let _ = write_http_response_message(&mut conn, status, None).await;
            }
        } else {
            debug!("Connection closed")
        }
    }

    async fn forward_tcp_stream_inner(
        &self,
        conn: &mut TcpStream,
        mode: &ProxyMode,
    ) -> Result<(), ProxyError> {
        let (mut tcp_recv, mut tcp_send) = conn.split();
        let (initial_data, request) = HttpRequest::read(&mut tcp_recv, HEADER_SECTION_MAX_LENGTH)
            .await
            .map_err(|err| ProxyError::bad_request(err))?;
        debug!(initial_data_len = initial_data.len(), "read request");
        let mut conn = match &request.kind {
            HttpRequestKind::Proxy(_) => {
                let forward = mode.as_forward()?;
                let endpoint_id = forward.extact_endpoint(&request).await?;
                let mut conn = self
                    .connect(endpoint_id)
                    .await
                    .map_err(|err| ProxyError::gateway_timeout(err))?;
                conn.send.write_chunk(initial_data.full()).await?;
                conn
            }
            HttpRequestKind::Origin { .. } => {
                let reverse = mode.as_reverse()?;
                let destination = reverse.extact_endpoint_authority(&request).await?;
                let (initial_response_data, mut conn) = self.create_tunnel(destination).await?;
                tcp_send.write_all(&initial_response_data).await?;
                conn.send.write_all(&initial_data.full()).await?;
                conn
            }
        };
        debug!("connected to remote");

        forward_bidi(&mut tcp_recv, &mut tcp_send, &mut conn.recv, &mut conn.send)
            .await
            .map_err(ProxyError::io)?;
        debug!("closed");
        Ok(())
    }
}

pub struct TunnelClientStreams {
    pub send: SendStream,
    pub recv: RecvStream,
    pub conn: ConnectionRef,
}

impl From<ExtractError> for ProxyError {
    #[track_caller]
    fn from(value: ExtractError) -> Self {
        ProxyError::new(Some(value.response_status()), value.into())
    }
}

#[stack_error(add_meta, derive)]
pub struct ProxyError {
    response_status: Option<StatusCode>,
    #[error(source)]
    source: AnyError,
}

impl From<std::io::Error> for ProxyError {
    fn from(value: std::io::Error) -> Self {
        Self::io(value)
    }
}

impl From<iroh::endpoint::WriteError> for ProxyError {
    fn from(value: iroh::endpoint::WriteError) -> Self {
        Self::io(anyerr!(value))
    }
}

impl ProxyError {
    pub fn response_status(&self) -> Option<StatusCode> {
        self.response_status
    }

    fn bad_request(source: impl Into<AnyError>) -> Self {
        Self::new(Some(StatusCode::BAD_REQUEST), source.into())
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

#[derive(Debug, Clone)]
pub struct PoolOptions {
    connect_timeout: Duration,
    idle_timeout: Duration,
}

impl Default for PoolOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(5),
        }
    }
}

impl From<PoolOptions> for connection_pool::Options {
    fn from(opts: PoolOptions) -> Self {
        connection_pool::Options {
            connect_timeout: opts.connect_timeout,
            idle_timeout: opts.idle_timeout,
            ..Default::default()
        }
    }
}

async fn write_header_section(res: &reqwest::Response, send: &mut SendStream) -> Result<()> {
    let status_line = format!(
        "{:?} {} {}\r\n",
        res.version(),
        res.status().as_u16(),
        res.status().canonical_reason().unwrap_or_default()
    );
    send.write_all(status_line.as_bytes()).await.anyerr()?;
    for (name, value) in res.headers() {
        send.write_all(name.as_str().as_bytes()).await.anyerr()?;
        send.write_all(b": ").await.anyerr()?;
        send.write_all(value.as_bytes()).await.anyerr()?;
        send.write_all(b"\r\n").await.anyerr()?;
    }
    send.write_all(b"\r\n").await.anyerr()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use iroh::{Endpoint, protocol::Router};
    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;
    use tokio::net::TcpListener;

    use crate::{ALPN, AcceptAll, DownstreamProxy, ForwardProxyMode, ProxyMode, UpstreamProxy};

    #[tokio::test]
    #[traced_test]
    async fn gw_reqwest_end_to_end() -> Result {
        let gw_ep = Endpoint::bind().await?;
        println!("gateway: {}", gw_ep.id());
        let gw_proxy = DownstreamProxy::new(gw_ep, Default::default());
        let gw_listener = TcpListener::bind("localhost:0").await?;
        let gw_addr = gw_listener.local_addr()?;

        let proxy_router = Router::builder(Endpoint::bind().await?)
            .accept(ALPN, UpstreamProxy::new(AcceptAll)?)
            .spawn();
        proxy_router.endpoint().online().await;
        let proxy_id = proxy_router.endpoint().id();
        println!("upstream: {proxy_id}");

        let gw_mode = ProxyMode::forward_only(ForwardProxyMode::Static(proxy_id));
        let gw_task =
            tokio::spawn(async move { gw_proxy.forward_tcp_listener(gw_listener, gw_mode).await });

        let upstream_tcp_listener = TcpListener::bind("localhost:0").await?;
        let upstream_tcp_addr = upstream_tcp_listener.local_addr()?;
        let upstream_task = tokio::spawn(self::hyper::run(upstream_tcp_listener));

        let client_proxy = reqwest::Proxy::http(format!("http://{}", gw_addr)).unwrap();
        let client = reqwest::Client::builder()
            .proxy(client_proxy)
            .build()
            .unwrap();
        let res = client
            .get(format!("http://{}", upstream_tcp_addr))
            .send()
            .await
            .anyerr()?;
        assert_eq!(res.status(), StatusCode::OK);
        let text = res.text().await.anyerr()?;
        assert_eq!(text, "Hello, world!");

        proxy_router.shutdown().await.anyerr()?;
        gw_task.abort();
        upstream_task.abort();
        Ok(())
    }

    mod hyper {
        use std::convert::Infallible;

        use http_body_util::Full;
        use hyper::{Request, Response, body::Bytes, server::conn::http1, service::service_fn};
        use hyper_util::rt::TokioIo;
        use tokio::net::TcpListener;

        async fn hello(
            _req: Request<hyper::body::Incoming>,
        ) -> Result<Response<Full<Bytes>>, Infallible> {
            Ok(Response::new(Full::new(Bytes::from("Hello, world!"))))
        }

        pub(super) async fn run(
            listener: TcpListener,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            loop {
                let (stream, _) = listener.accept().await?;
                let io = TokioIo::new(stream);
                tokio::task::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service_fn(hello))
                        .await
                    {
                        eprintln!("Error serving connection: {:?}", err);
                    }
                });
            }
        }
    }
}
