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
    parse::{HttpRequest, HttpRequestKind, HttpResponse},
    util::{Prebuffered, forward_bidi},
};

pub use self::opts::{
    ExtractEndpoint, ExtractEndpointAuthority, ExtractError, ForwardProxyMode, PoolOpts, ProxyOpts,
    ReverseProxyMode, WriteErrorResponse,
};

mod opts;

/// The `DownstreamProxy` accepts TCP streams and forwards them to upstream iroh destinations.
#[derive(Clone, Debug)]
pub struct DownstreamProxy {
    pool: ConnectionPool,
}

impl DownstreamProxy {
    pub fn new(endpoint: Endpoint, opts: PoolOpts) -> Self {
        let pool = ConnectionPool::new(endpoint, ALPN, opts.into());
        Self { pool }
    }

    pub async fn create_tunnel(
        &self,
        destination: EndpointAuthority,
    ) -> Result<TunnelClientStreams, ProxyError> {
        let mut conn = self
            .connect(destination.endpoint_id)
            .await
            .map_err(|err| ProxyError::gateway_timeout(err))?;
        conn.send
            .write_all(destination.authority.to_connect_request().as_bytes())
            .await?;
        debug!("created tunnel");
        let response = HttpResponse::read(&mut conn.recv)
            .await
            .map_err(|err| ProxyError::bad_gateway(err))?;
        debug!(?response, "got proxy response");
        conn.recv.discard(response.header_section_len);
        if response.status != StatusCode::OK {
            return Err(ProxyError::new(
                Some(response.status),
                anyerr!("Upstream gateway returned error response"),
            ));
        }
        Ok(conn)
    }

    pub async fn forward_tcp_listener(&self, listener: TcpListener, mode: ProxyOpts) -> Result<()> {
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

    pub async fn forward_tcp_stream(&self, mut conn: TcpStream, opts: &ProxyOpts) -> Result<()> {
        if let Err(err) = self.forward_tcp_stream_inner(&mut conn, opts).await {
            warn!("Forwarding TCP stream closed with error: {err:#}");
            if let Some(response) = err.to_response() {
                let _ = opts.write_error_response(&response, &mut conn).await;
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
        opts: &ProxyOpts,
    ) -> Result<(), ProxyError> {
        let (tcp_recv, mut tcp_send) = conn.split();
        let mut tcp_recv = Prebuffered::new(tcp_recv, HEADER_SECTION_MAX_LENGTH);
        let request = HttpRequest::read(&mut tcp_recv)
            .await
            .map_err(|err| ProxyError::bad_request(err))?;
        debug!(?request, "read request");
        let mut conn = match &request.kind {
            HttpRequestKind::Proxy(_) => {
                let forward = opts.as_forward()?;
                let endpoint_id = forward.extact_endpoint(&request).await?;
                self.connect(endpoint_id)
                    .await
                    .map_err(|err| ProxyError::gateway_timeout(err))?
            }
            HttpRequestKind::Origin { .. } => {
                let reverse = opts.as_reverse()?;
                let destination = reverse.extact_endpoint_authority(&request).await?;
                self.create_tunnel(destination).await?
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

pub struct TunnelClientStreams {
    pub send: SendStream,
    pub recv: Prebuffered<RecvStream>,
    pub conn: ConnectionRef,
}

#[derive(Debug, Clone)]
pub struct EndpointAuthority {
    pub endpoint_id: EndpointId,
    pub authority: Authority,
}

impl EndpointAuthority {
    pub fn new(endpoint_id: EndpointId, authority: Authority) -> Self {
        Self {
            endpoint_id,
            authority,
        }
    }
}

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
    pub fn response_status(&self) -> Option<StatusCode> {
        self.response_status
    }

    fn to_response(&self) -> Option<HttpResponse> {
        self.response_status().map(|status| HttpResponse {
            status,
            reason: None,
            header_section_len: 0,
        })
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
