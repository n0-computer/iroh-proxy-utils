use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use http::StatusCode;
use iroh::{
    EndpointId,
    endpoint::{Connection, ConnectionError, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
};
use n0_error::{Result, StackResultExt, StdResultExt};
use n0_future::stream::StreamExt;
use tokio::net::TcpStream;
use tokio_util::{future::FutureExt, sync::CancellationToken, task::TaskTracker};
use tracing::{Instrument, debug, error_span, instrument, warn};

use crate::{
    HEADER_SECTION_MAX_LENGTH, HttpResponse,
    parse::{HttpProxyRequestKind, HttpRequest, filter_hop_by_hop_headers},
    util::{Prebuffered, forward_bidi, recv_to_stream},
};

mod auth;
pub use auth::*;

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Proxy that receives iroh streams and forwards them to origin servers.
///
/// The upstream proxy is the server-side component that accepts connections from
/// downstream proxies over iroh and forwards requests to actual TCP origin servers.
///
/// # Protocol Support
///
/// - **CONNECT tunnels**: Establishes TCP connections to the requested authority
///   and bidirectionally forwards data.
/// - **Absolute-form requests**: Forwards HTTP requests to origin servers using
///   reqwest, with hop-by-hop header filtering per RFC 9110.
///
/// # Authorization
///
/// All requests pass through an [`AuthHandler`] before processing. Unauthorized
/// requests receive a 403 Forbidden response.
///
/// # Usage
///
/// Implements [`ProtocolHandler`] for use with iroh's [`Router`](iroh::protocol::Router):
///
/// ```ignore
/// let proxy = UpstreamProxy::new(AcceptAll)?;
/// let router = Router::builder(endpoint)
///     .accept(ALPN, proxy)
///     .spawn();
/// ```
#[derive(derive_more::Debug)]
pub struct UpstreamProxy {
    #[debug("Arc<dyn AuthHandler>")]
    auth: Arc<DynAuthHandler<'static>>,
    conn_id: Arc<AtomicU64>,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    http_client: reqwest::Client,
}

impl ProtocolHandler for UpstreamProxy {
    #[instrument("accept", level="error", skip_all, fields(id=self.conn_id.fetch_add(1, Ordering::SeqCst)))]
    async fn accept(
        &self,
        connection: Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        debug!(remote_id=%connection.remote_id().fmt_short(), "accepted connection");
        self.handle_connection(connection)
            .await
            .map_err(AcceptError::from_err)
    }

    async fn shutdown(&self) {
        self.shutdown.cancel();
        self.tasks.close();
        debug!("shutting down ({} pending tasks)", self.tasks.len());
        match self.tasks.wait().timeout(GRACEFUL_SHUTDOWN_TIMEOUT).await {
            Ok(_) => debug!("all streams closed cleanly"),
            Err(_) => debug!(
                remaining = self.tasks.len(),
                "not all streams closed in time, abort"
            ),
        }
    }
}

impl UpstreamProxy {
    /// Creates a new upstream proxy with the provided authorization handler.
    pub fn new(auth: impl AuthHandler + 'static) -> Result<Self> {
        Ok(Self {
            auth: DynAuthHandler::new_arc(auth),
            conn_id: Default::default(),
            shutdown: CancellationToken::new(),
            tasks: TaskTracker::new(),
            http_client: reqwest::Client::new(),
        })
    }

    async fn handle_connection(&self, connection: Connection) -> Result<()> {
        let remote_id = connection.remote_id();
        let mut stream_id = 0;
        loop {
            let (send, recv) = match connection
                .accept_bi()
                .with_cancellation_token(&self.shutdown)
                .await
            {
                None => return Ok(()),
                Some(Ok(streams)) => streams,
                Some(Err(ConnectionError::ApplicationClosed(_))) => {
                    debug!("connection closed by downstream remote");
                    return Ok(());
                }
                Some(Err(err)) => {
                    return Err(err).std_context("failed to accept streams");
                }
            };
            let auth = self.auth.clone();
            let shutdown = self.shutdown.clone();
            let http_client = self.http_client.clone();
            self.tasks.spawn(
                // We don't actually shutdown the stream task. If it didn't end by the time we stop waiting at shutdown,
                // the connection will be closed, which causes the task to finish.
                async move {
                    if let Err(err) =
                        Self::handle_remote_streams(auth, remote_id, send, recv, http_client).await
                    {
                        if shutdown.is_cancelled() {
                            debug!("aborted at shutdown: {err:#}");
                        } else {
                            warn!("failed to handle streams: {err:#}");
                        }
                    }
                }
                .instrument(error_span!("stream", id=%stream_id)),
            );
            stream_id += 1;
        }
    }

    async fn handle_remote_streams(
        auth: Arc<DynAuthHandler<'static>>,
        remote_id: EndpointId,
        mut send: SendStream,
        recv: RecvStream,
        http_client: reqwest::Client,
    ) -> Result<()> {
        let mut recv = Prebuffered::new(recv, HEADER_SECTION_MAX_LENGTH);
        let req = HttpRequest::read(&mut recv).await?;

        debug!(?req, "handle request");
        let req = req
            .try_into_proxy_request()
            .context("Received origin-form request but expected proxy request")?;

        match auth.authorize(remote_id, &req).await {
            Ok(()) => debug!("request is authorized, continue"),
            Err(reason) => {
                debug!(?reason, "request is not authorized, abort");
                HttpResponse::new(StatusCode::FORBIDDEN)
                    .no_body()
                    .write(&mut send, true)
                    .await
                    .ok();
                send.finish().anyerr()?;
                return Ok(());
            }
        };

        match req.kind {
            HttpProxyRequestKind::Tunnel { target: authority } => {
                debug!(%authority, "tunnel request: connecting to origin");
                match TcpStream::connect(authority.to_addr()).await {
                    Err(err) => {
                        warn!("Failed to connect to origin server: {err:#}");
                        HttpResponse::with_reason(StatusCode::BAD_GATEWAY, "Origin Is Unreachable")
                            .no_body()
                            .write(&mut send, true)
                            .await
                            .inspect_err(|err| {
                                warn!("Failed to write error response to downstream: {err:#}")
                            })
                            .ok();
                        send.finish().anyerr()?;
                        Ok(())
                    }
                    Ok(tcp_stream) => {
                        debug!(%authority, "connected to origin");
                        HttpResponse::with_reason(StatusCode::OK, "Connection Established")
                            .write(&mut send, true)
                            .await
                            .context("Failed to write CONNECT response to downstream")?;
                        let (mut origin_recv, mut origin_send) = tcp_stream.into_split();
                        let (to_origin, from_origin) =
                            forward_bidi(&mut recv, &mut send, &mut origin_recv, &mut origin_send)
                                .await?;
                        debug!(to_origin, from_origin, "finish");
                        Ok(())
                    }
                }
            }
            HttpProxyRequestKind::Absolute { method, target } => {
                debug!(%target, "origin request: connecting to origin");
                let body = recv_stream_to_body(recv);

                // Filter hop-by-hop headers before forwarding to upstream per RFC 9110.
                let mut headers = req.headers;
                filter_hop_by_hop_headers(&mut headers);

                // Forward the request to the upstream server.
                let mut response = http_client
                    .request(method, target)
                    .headers(headers)
                    .body(body)
                    .send()
                    .await
                    .anyerr()?;
                filter_hop_by_hop_headers(response.headers_mut());
                debug!(?response, "received response from origin");
                write_response_header(&response, &mut send).await?;
                let mut total = 0;
                let mut body = response.bytes_stream();
                while let Some(bytes) = body.next().await {
                    let bytes = bytes.anyerr()?;
                    total += bytes.len();
                    send.write_chunk(bytes).await.anyerr()?;
                }
                send.finish().anyerr()?;
                debug!(response_body_len=%total, "finish");
                Ok(())
            }
        }
    }
}

// Converts a [`Prebuffered`] recv stream into a streaming [`reqwest::Body`].
fn recv_stream_to_body(recv: Prebuffered<RecvStream>) -> reqwest::Body {
    reqwest::Body::wrap_stream(recv_to_stream(recv))
}

async fn write_response_header(res: &reqwest::Response, send: &mut SendStream) -> Result<()> {
    let status_line = format!(
        "{:?} {} {}\r\n",
        res.version(),
        res.status().as_u16(),
        // TODO: get reason phrase as returned from upstream.
        res.status().canonical_reason().unwrap_or_default()
    );
    send.write_all(status_line.as_bytes()).await.anyerr()?;

    for (name, value) in res.headers().iter() {
        send.write_all(name.as_str().as_bytes()).await.anyerr()?;
        send.write_all(b": ").await.anyerr()?;
        send.write_all(value.as_bytes()).await.anyerr()?;
        send.write_all(b"\r\n").await.anyerr()?;
    }
    send.write_all(b"\r\n").await.anyerr()?;
    Ok(())
}
