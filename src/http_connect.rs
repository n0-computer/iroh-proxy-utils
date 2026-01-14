use std::{fmt::Debug, sync::Arc, time::Duration};

use bytes::Bytes;
use http::StatusCode;
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
};
use iroh_blobs::util::connection_pool::{self, ConnectionPool, ConnectionRef};
use n0_error::{AnyError, Result, StackResultExt, StdResultExt, anyerr, e, stack_error};
use n0_future::stream::StreamExt;
use quinn::ConnectionError;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error_span, instrument, warn};

use crate::{
    auth::AuthHandler,
    gateway::{ExtractDestination, ForwardMode},
    parse::{Authority, HttpRequest, HttpResponse, RequestKind},
    util::{forward_bidi, send_error_response},
};

/// how much data to read for the CONNECT handshake before it's considered invalid
/// 8KB should be plenty.
pub(crate) const HEADER_SECTION_MAX_LENGTH: usize = 8192;

/// HTTP header for iroh addressing info
pub const IROH_DESTINATION_HEADER: &str = "Iroh-Destination";
// /// The ALPN that we're using for iroh connections
pub const ALPN: &[u8] = b"iroh-http-proxy";

/// Listeners are the "Server" side of a tunnel construction. Building a tunnel
/// requires a listener first be constructed & attached to an endpoint as a
/// protocol handler.
#[derive(Debug)]
pub struct TunnelListener {
    auth: Arc<dyn AuthHandler>,
}

impl TunnelListener {
    pub fn new(auth: impl AuthHandler + 'static) -> Result<Self> {
        Ok(Self {
            auth: Arc::new(auth),
        })
    }

    async fn handle_remote_streams(
        auth: Arc<dyn AuthHandler>,
        remote_id: EndpointId,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        let (initial_data, req) = HttpRequest::read(&mut recv, HEADER_SECTION_MAX_LENGTH).await?;

        debug!(?req, "incoming request");

        if let RequestKind::Http {
            authority_from_path,
            ..
        } = &req.kind
            && authority_from_path.is_none()
        {
            warn!("Received regular HTTP request with non-authority path");
            return Err(anyerr!("Invalid request"));
        }

        match auth.authorize(remote_id, &req).await {
            Ok(()) => debug!("request is authorized, continue"),
            Err(err) => {
                debug!("request is not authorized, abort");
                return Err(err.into());
            }
        };

        match req.kind {
            RequestKind::Connect { authority } => {
                match TcpStream::connect(authority.to_addr()).await {
                    Err(err) => {
                        warn!("Failed to connect to upstream server: {err:#}");
                        send_error_response(&mut send, http::StatusCode::BAD_GATEWAY).await?;
                        send.finish().anyerr()?;
                    }
                    Ok(tcp_stream) => {
                        debug!(?authority, "connected to upstream");
                        let status_line = b"HTTP/1.1 200 Connection established\r\n\r\n";
                        send.write_all(status_line).await.anyerr()?;
                        let (mut tcp_recv, mut tcp_send) = tcp_stream.into_split();
                        let initial_request_data = &initial_data.after_header_section();
                        tcp_send.write_all(&initial_request_data).await?;
                        forward_bidi(&mut tcp_recv, &mut tcp_send, &mut recv, &mut send).await?;
                    }
                }
            }
            RequestKind::Http { method, path, .. } => {
                // TODO: Filter out headers that should not be forwarded to upstream.
                let client = reqwest::Client::new();
                let res = client
                    .request(method, path)
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
        }
        Ok(())
    }

    async fn handle_connection(&self, connection: Connection) -> Result<()> {
        let remote_id = connection.remote_id();
        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(ConnectionError::ApplicationClosed(_)) => return Ok(()),
                Err(err) => return Err(err).std_context("connection closed"),
            };
            tokio::spawn({
                let auth = self.auth.clone();
                async move {
                    if let Err(err) = Self::handle_remote_streams(auth, remote_id, send, recv).await
                    {
                        warn!("Failed to handle streams: {err:#}");
                    }
                }
                .instrument(tracing::Span::current())
            });
        }
    }
}

impl ProtocolHandler for TunnelListener {
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

#[derive(Clone, Debug)]
pub struct TunnelClientPool {
    pool: ConnectionPool,
}

impl TunnelClientPool {
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

    async fn connect_and_send_initial_data(
        &self,
        destination: EndpointId,
        initial_data: &[u8],
    ) -> Result<TunnelClientStreams> {
        let mut conn = self.connect(destination).await?;
        conn.send
            .write_all(&initial_data)
            .await
            .std_context("failed to send initial data")?;
        Ok(conn)
    }

    pub async fn forward_from_local_listener(
        &self,
        destination: EndpointId,
        authority: Authority,
        local_listener: TcpListener,
    ) -> Result<()> {
        let authority = Arc::new(authority);
        let cancel_token = CancellationToken::new();
        let _cancel_guard = cancel_token.clone().drop_guard();
        loop {
            let (mut client_stream, client_addr) = local_listener.accept().await?;
            let this = self.clone();
            let authority = authority.clone();
            let cancel_token = cancel_token.child_token();
            let fut = async move {
                if let Err(err) = this
                    .forward_tcp_through_tunnel(destination, &authority, &mut client_stream)
                    .await
                {
                    warn!("Handling connection closed with error: {err:#}");
                    if let Some(status) = err.should_reply() {
                        send_error_response(&mut client_stream, status).await.ok();
                    }
                } else {
                    debug!("Connection closed")
                }
            };
            tokio::spawn(
                cancel_token
                    .run_until_cancelled_owned(fut)
                    .instrument(error_span!("tcp-conn", client=%client_addr)),
            );
        }
    }

    async fn create_tunnel(
        &self,
        destination: EndpointId,
        authority: &Authority,
    ) -> Result<(Bytes, TunnelClientStreams), ProxyError> {
        let initial_data = authority.to_connect_request();
        let mut conn = self
            .connect_and_send_initial_data(destination, &initial_data.as_bytes())
            .await
            .map_err(|err| e!(ProxyError::FailedToConnect, err))?;
        debug!("created tunnel");
        let (initial_data, response) = HttpResponse::read(&mut conn.recv, 1024)
            .await
            .map_err(|err| e!(ProxyError::RemoteMisbehaved, err))?;
        debug!(?response, "got proxy response");
        let status = response.status;
        if status != StatusCode::OK {
            n0_error::bail!(ProxyError::RemoteAborted { status });
        }
        Ok((initial_data.after_header_section(), conn))
    }

    async fn forward_tcp_through_tunnel(
        &self,
        destination: EndpointId,
        authority: &Authority,
        tcp_conn: &mut TcpStream,
    ) -> Result<(), ProxyError> {
        let (tcp_recv, mut tcp_send) = tcp_conn.split();
        let (initial_response_data, mut conn) = self.create_tunnel(destination, authority).await?;
        tcp_send
            .write_all(&initial_response_data)
            .await
            .map_err(|err| e!(ProxyError::Io, err.into()))?;
        forward_bidi(tcp_recv, tcp_send, &mut conn.recv, &mut conn.send)
            .await
            .map_err(|err| e!(ProxyError::Io, err))?;
        Ok(())
    }

    pub async fn forward_http_connection(
        &self,
        conn: &mut TcpStream,
        extract_destination: &ExtractDestination,
    ) -> Result<(), ProxyError> {
        let (mut tcp_recv, mut tcp_send) = conn.split();
        let (initial_data, request) = HttpRequest::read(&mut tcp_recv, HEADER_SECTION_MAX_LENGTH)
            .await
            .map_err(|err| e!(ProxyError::BadRequest, err))?;
        debug!(initial_data_len = initial_data.len(), "read request");
        let destination = extract_destination.extract(&request).await;
        debug!(?destination, "extracted destination");
        let destination = destination
            .context("Failed to parse iroh destination from HTTP request")
            .map_err(|err| e!(ProxyError::BadRequest, err))?;

        let mut conn = match destination.mode {
            ForwardMode::Unchanged => self
                .connect_and_send_initial_data(destination.endpoint_id, &initial_data.full())
                .await
                .map_err(|err| e!(ProxyError::FailedToConnect, err))?,
            ForwardMode::ConnectTunnel(authority) => {
                let (initial_response_data, mut conn) = self
                    .create_tunnel(destination.endpoint_id, &authority)
                    .await?;
                tcp_send
                    .write_all(&initial_response_data)
                    .await
                    .map_err(|err| e!(ProxyError::Io, err.into()))?;
                conn.send
                    .write_all(&initial_data.full())
                    .await
                    .map_err(|err| e!(ProxyError::Io, anyerr!(err)))?;
                conn
            }
        };
        debug!("connected to remote");

        forward_bidi(&mut tcp_recv, &mut tcp_send, &mut conn.recv, &mut conn.send)
            .await
            .map_err(|err| e!(ProxyError::Io, err))?;
        debug!("closed");
        Ok(())
    }
}

pub struct TunnelClientStreams {
    pub send: SendStream,
    pub recv: RecvStream,
    pub conn: ConnectionRef,
}

#[stack_error(add_meta, derive)]
pub enum ProxyError {
    Io { source: AnyError },
    BadRequest { source: AnyError },
    FailedToConnect { source: AnyError },
    RemoteMisbehaved { source: AnyError },
    RemoteAborted { status: StatusCode },
}

impl ProxyError {
    pub fn should_reply(&self) -> Option<StatusCode> {
        match self {
            ProxyError::Io { .. } => None,
            ProxyError::BadRequest { .. } => Some(StatusCode::BAD_REQUEST),
            ProxyError::FailedToConnect { .. } => Some(StatusCode::GATEWAY_TIMEOUT),
            ProxyError::RemoteMisbehaved { .. } => Some(StatusCode::BAD_GATEWAY),
            ProxyError::RemoteAborted { status, .. } => Some(*status),
        }
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
