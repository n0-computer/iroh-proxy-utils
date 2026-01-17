use std::{fmt::Debug, io};

use http::StatusCode;
use iroh::{
    Endpoint, EndpointId,
    endpoint::{RecvStream, SendStream},
};
use iroh_blobs::util::connection_pool::{ConnectionPool, ConnectionRef};
use n0_error::{AnyError, Result, anyerr, stack_error};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error_span, warn};

use crate::{
    ALPN, Authority, HEADER_SECTION_MAX_LENGTH,
    parse::{HttpRequest, HttpResponse},
    util::{Prebuffered, forward_bidi},
};

pub use self::opts::{
    ExtractError, ForwardProxyMode, ForwardProxyResolver, HttpProxyOpts, PoolOpts, ProxyMode,
    ReverseProxyMode, ReverseProxyResolver, WriteErrorResponse,
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
            .map_err(|err| ProxyError::gateway_timeout(err))?;
        conn.send
            .write_all(destination.authority.to_connect_request().as_bytes())
            .await?;
        debug!("created tunnel");
        let (header_len, response) = HttpResponse::read(&mut conn.recv)
            .await
            .map_err(|err| ProxyError::bad_gateway(err))?;
        debug!(?response, ?header_len, "got proxy response");
        conn.recv.discard(header_len);
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
    /// Note: this runs indefinitely until the listener errors or the task is cancelled.
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
                        this.forward_tcp_stream(client_stream, &mode).await.ok();
                    })
                    .instrument(error_span!("tcp-conn", client=%client_addr)),
            );
        }
    }

    /// Forwards a single TCP stream based on the first HTTP request.
    ///
    /// Note: only the initial request is parsed; subsequent bytes are streamed as-is.
    pub async fn forward_tcp_stream(&self, mut conn: TcpStream, mode: &ProxyMode) -> Result<()> {
        if let Err(err) = self.forward_tcp_stream_inner(&mut conn, mode).await {
            warn!("Forwarding TCP stream closed with error: {err:#}");
            // If this is a HTTP proxy, write an error response if the error is a proxy error.
            if let ProxyMode::Http(opts) = mode {
                if let Some(response) = err.to_response() {
                    let _ = opts.write_error_response(&response, &mut conn).await;
                }
            }
            Err(err.into())
        } else {
            debug!("Forwarded stream closed");
            Ok(())
        }
    }

    async fn forward_tcp_stream_inner(
        &self,
        conn: &mut TcpStream,
        mode: &ProxyMode,
    ) -> Result<(), ProxyError> {
        let (tcp_recv, mut tcp_send) = conn.split();

        // We only need to prebuffer for HTTP mode.
        let prebuffer_max_len = match mode {
            ProxyMode::Tcp(_) => 0,
            ProxyMode::Http(_) => HEADER_SECTION_MAX_LENGTH,
        };
        let mut tcp_recv = Prebuffered::new(tcp_recv, prebuffer_max_len);

        let mut conn = match mode {
            ProxyMode::Tcp(destination) => self.create_tunnel(destination).await?,
            ProxyMode::Http(opts) => {
                let (_header_len, request) = HttpRequest::read(&mut tcp_recv)
                    .await
                    .map_err(|err| ProxyError::bad_request(err))?;
                debug!(?request, "read request");
                match &request {
                    HttpRequest::Forward(request) => {
                        let forward = opts.as_forward()?;
                        let endpoint_id = forward.destination(&request).await?;
                        self.connect(endpoint_id)
                            .await
                            .map_err(|err| ProxyError::gateway_timeout(err))?
                    }
                    HttpRequest::Origin(request) => {
                        let reverse = opts.as_reverse()?;
                        let destination = reverse.destination(request).await?;
                        self.create_tunnel(&destination).await?
                    }
                }
            }
        };

        debug!("connected to remote");

        forward_bidi(&mut tcp_recv, &mut tcp_send, &mut conn.recv, &mut conn.send)
            .await
            .map_err(ProxyError::io)?;
        debug!("closed");
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
}

/// Error type for downstream proxy failures.
#[stack_error(add_meta, derive)]
pub struct ProxyError {
    response_status: Option<StatusCode>,
    #[error(source)]
    source: AnyError,
}

impl From<ExtractError> for ProxyError {
    #[track_caller]
    fn from(value: ExtractError) -> Self {
        ProxyError::new(Some(value.response_status()), value.into())
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

    fn to_response(&self) -> Option<HttpResponse> {
        self.response_status().map(HttpResponse::new)
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
