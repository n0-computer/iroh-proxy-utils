use std::fmt::Debug;
use std::sync::Arc;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointId};
use iroh_blobs::util::connection_pool::{ConnectionPool, ConnectionRef};
use n0_error::{Result, StdResultExt, anyerr};
use n0_future::stream::StreamExt;
use quinn::{RecvStream, SendStream};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error_span, instrument, warn};

use crate::auth::AuthHandler;
use crate::gateway::PoolOptions;
use crate::parse::{Authority, HttpRequest, RequestKind};
use crate::util::{forward_bidi, send_error_response};

/// how much data to read for the CONNECT handshake before it's considered invalid
/// 8KB should be plenty.
pub(crate) const CONNECT_HANDSHAKE_MAX_LENGTH: usize = 8192;

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
        let (initial_data, req) =
            HttpRequest::read(&mut recv, CONNECT_HANDSHAKE_MAX_LENGTH).await?;

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
                        let status_line = b"HTTP/1.1 200 Connection established\r\n\r\n";
                        send.write_all(status_line).await.anyerr()?;
                        let (tcp_recv, mut tcp_send) = tcp_stream.into_split();
                        tcp_send
                            .write_all(&initial_data.after_header_section())
                            .await?;
                        forward_bidi(tcp_recv, tcp_send, recv, send).await?;
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
            let (send, recv) = connection
                .accept_bi()
                .await
                .std_context("error accepting stream")?;
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

    pub async fn connect(
        &self,
        destination: EndpointId,
        authority: &Authority,
    ) -> Result<TunnelClientStreams> {
        let conn = self.pool.get_or_connect(destination).await.anyerr()?;
        let (mut send, recv) = conn
            .open_bi()
            .await
            .std_context("failed to open streams to remote")?;

        let connect_request_header = authority.to_connect_request();
        send.write_all(&connect_request_header.as_bytes())
            .await
            .anyerr()?;
        Ok(TunnelClientStreams { send, recv, conn })
    }

    pub async fn forward_local_listener(
        &self,
        destination: EndpointId,
        authority: Authority,
        local_listener: TcpListener,
    ) -> Result<()> {
        let authority = Arc::new(authority);
        let cancel_token = CancellationToken::new();
        let _cancel_guard = cancel_token.clone().drop_guard();
        loop {
            let (client_stream, client_addr) = local_listener.accept().await?;
            let this = self.clone();
            let authority = authority.clone();
            let cancel_token = cancel_token.child_token();
            let fut = async move {
                if let Err(err) = this
                    .forward_tcp_stream(destination, &authority, client_stream)
                    .await
                {
                    warn!("Handling local connection closed with error: {err:#}")
                } else {
                    warn!("Connection closed")
                }
            };
            tokio::spawn(
                cancel_token.run_until_cancelled_owned(fut)
                    .instrument(error_span!("forward-tcp", destination=%destination.fmt_short(), client=%client_addr))
            );
        }
    }

    async fn forward_tcp_stream(
        &self,
        destination: EndpointId,
        authority: &Authority,
        tcp_conn: TcpStream,
    ) -> Result<()> {
        let (tcp_recv, mut tcp_send) = tcp_conn.into_split();
        let proxy_conn = match self.connect(destination, authority).await {
            Ok(conn) => conn,
            Err(err) => {
                warn!("Failed to connect to remote: {err:#}");
                send_error_response(&mut tcp_send, http::StatusCode::GATEWAY_TIMEOUT).await?;
                return Ok(());
            }
        };
        forward_bidi(tcp_recv, tcp_send, proxy_conn.recv, proxy_conn.send).await?;
        drop(proxy_conn.conn);
        Ok(())
    }
}

pub struct TunnelClientStreams {
    pub send: SendStream,
    pub recv: RecvStream,
    pub conn: ConnectionRef,
}
