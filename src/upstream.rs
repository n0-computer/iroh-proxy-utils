use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use http::{StatusCode, Version};
use iroh::{
    EndpointId,
    endpoint::{Connection, ConnectionError, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
};
use n0_error::{Result, StackResultExt, StdResultExt};
use n0_future::stream::StreamExt;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::{future::FutureExt, sync::CancellationToken, task::TaskTracker};
use tracing::{Instrument, debug, error_span, instrument, warn};

use crate::{
    Authority, HEADER_SECTION_MAX_LENGTH, HttpResponse,
    parse::{
        HttpProxyRequestKind, HttpRequest, absolute_target_to_origin_form,
        filter_hop_by_hop_headers,
    },
    util::{
        Prebuffered, StreamEvent, TrackedRead, TrackedStream, TrackedWrite, forward_bidi, nores,
        recv_to_stream,
    },
};

mod auth;
mod metrics;
pub use auth::*;
pub use metrics::*;

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Supported HTTP upgrade protocols. Only these will be forwarded with upgrade support.
const SUPPORTED_UPGRADE_PROTOCOLS: &[&str] = &["websocket"];

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
    metrics: Arc<UpstreamMetrics>,
}

impl ProtocolHandler for UpstreamProxy {
    #[instrument("accept", level="error", skip_all, fields(id=self.conn_id.fetch_add(1, Ordering::SeqCst)))]
    async fn accept(
        &self,
        connection: Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        debug!(remote_id=%connection.remote_id().fmt_short(), "accepted connection");
        self.metrics.connections_accepted.inc();
        let res = self
            .handle_connection(connection)
            .await
            .map_err(AcceptError::from_err);
        self.metrics.connections_completed.inc();
        res
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
            metrics: Default::default(),
        })
    }

    /// Returns the metrics tracker for this upstream proxy.
    pub fn metrics(&self) -> Arc<UpstreamMetrics> {
        self.metrics.clone()
    }

    /// Returns a future that resolves when this upstream proxy begins shutting down.
    pub fn on_shutdown(&self) -> impl Future<Output = ()> + Send + 'static + use<> {
        self.shutdown.clone().cancelled_owned()
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
            let metrics = self.metrics.clone();
            self.tasks.spawn(
                // We don't actually shutdown the stream task. If it didn't end by the time we stop waiting at shutdown,
                // the connection will be closed, which causes the task to finish.
                async move {
                    if let Err(err) = Self::handle_remote_streams(
                        auth,
                        remote_id,
                        send,
                        recv,
                        http_client,
                        metrics,
                    )
                    .await
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
        mut downstream_send: SendStream,
        downstream_recv: RecvStream,
        http_client: reqwest::Client,
        metrics: Arc<UpstreamMetrics>,
    ) -> Result<()> {
        let mut downstream_recv = Prebuffered::new(downstream_recv, HEADER_SECTION_MAX_LENGTH);
        let (request_len, req) = HttpRequest::peek(&mut downstream_recv).await?;
        downstream_recv.discard(request_len);

        debug!(?req, "handle request");
        let req = req
            .try_into_proxy_request()
            .context("Received origin-form request but expected proxy request")?;

        let id = req.kind.authority()?;
        let req_metrics = metrics.get_or_insert(id);
        req_metrics.bytes_to_origin.inc_by(request_len as u64);

        match auth.authorize(remote_id, &req).await {
            Ok(()) => {
                metrics.requests_accepted.inc();
                req_metrics.requests_accepted.inc();
                debug!("request is authorized, continue");
            }
            Err(reason) => {
                metrics.requests_denied.inc();
                req_metrics.requests_denied.inc();
                debug!(?reason, "request is not authorized, abort");
                HttpResponse::new(StatusCode::FORBIDDEN)
                    .no_body()
                    .write(&mut downstream_send, true)
                    .await
                    .ok();
                downstream_send.finish().anyerr()?;
                return Ok(());
            }
        };

        match req.kind {
            HttpProxyRequestKind::Tunnel { target: authority } => {
                debug!(%authority, "tunnel request: connecting to origin");
                match TcpStream::connect(authority.to_addr()).await {
                    Err(err) => {
                        warn!("Failed to connect to origin server: {err:#}");
                        metrics.requests_failed.inc();
                        req_metrics.requests_failed.inc();
                        error_response_and_finish(downstream_send).await?;
                        Ok(())
                    }
                    Ok(tcp_stream) => {
                        debug!(%authority, "connected to origin");
                        HttpResponse::with_reason(StatusCode::OK, "Connection Established")
                            .write(&mut downstream_send, true)
                            .await
                            .context("Failed to write CONNECT response to downstream")?;
                        let (mut origin_recv, mut origin_send) = tcp_stream.into_split();

                        let mut downstream_recv = TrackedRead::new(&mut downstream_recv, |d| {
                            req_metrics.bytes_to_origin.inc_by(d);
                        });
                        let mut downstream_send = TrackedWrite::new(&mut downstream_send, |d| {
                            req_metrics.bytes_from_origin.inc_by(d);
                        });

                        match forward_bidi(
                            &mut downstream_recv,
                            &mut downstream_send,
                            &mut origin_recv,
                            &mut origin_send,
                        )
                        .await
                        {
                            Ok((to_origin, from_origin)) => {
                                metrics.requests_completed.inc();
                                req_metrics.requests_completed.inc();
                                debug!(to_origin, from_origin, "finish");
                                Ok(())
                            }
                            Err(err) => {
                                metrics.requests_failed.inc();
                                req_metrics.requests_failed.inc();
                                Err(err)
                            }
                        }
                    }
                }
            }
            HttpProxyRequestKind::Absolute { method, target } => {
                // Check if this is an upgrade request we should handle specially
                let upgrade_protocol = req
                    .headers
                    .get(http::header::UPGRADE)
                    .and_then(|v| v.to_str().ok())
                    .filter(|proto| {
                        SUPPORTED_UPGRADE_PROTOCOLS
                            .iter()
                            .any(|p| p.eq_ignore_ascii_case(proto))
                    });

                if let Some(protocol) = upgrade_protocol {
                    debug!(%target, %protocol, "upgrade request: connecting to origin");
                    let mut headers = req.headers;
                    filter_hop_by_hop_headers(&mut headers);
                    // Request came in absolute-form over the tunnel; convert to origin-form for the origin.
                    let authority = Authority::from_absolute_uri(&target)?;
                    let origin_form_uri = absolute_target_to_origin_form(&target)?;
                    let request = HttpRequest {
                        version: Version::HTTP_11,
                        headers,
                        uri: origin_form_uri,
                        method,
                    };
                    match Self::handle_upgrade_request(
                        authority,
                        request,
                        downstream_recv,
                        downstream_send,
                        req_metrics.clone(),
                    )
                    .await
                    {
                        Ok(()) => {
                            metrics.requests_completed.inc();
                            req_metrics.requests_completed.inc();
                            Ok(())
                        }
                        Err(err) => {
                            metrics.requests_failed.inc();
                            req_metrics.requests_failed.inc();
                            Err(err)
                        }
                    }
                } else {
                    debug!(%target, "origin request: connecting to origin");
                    let body = {
                        let req_metrics = req_metrics.clone();
                        let body = recv_to_stream(downstream_recv);
                        let body = TrackedStream::new(body, move |ev| match ev {
                            StreamEvent::Data(n) => nores(req_metrics.bytes_to_origin.inc_by(n)),
                            _ => {}
                        });
                        reqwest::Body::wrap_stream(body)
                    };

                    // Filter hop-by-hop headers before forwarding to upstream per RFC 9110.
                    let mut headers = req.headers;
                    filter_hop_by_hop_headers(&mut headers);

                    // Forward the request to the upstream server.
                    let mut response = match http_client
                        .request(method, target.to_string())
                        .headers(headers)
                        .body(body)
                        .send()
                        .await
                    {
                        Ok(response) => response,
                        Err(err) => {
                            error_response_and_finish(downstream_send).await?;
                            metrics.requests_failed.inc();
                            req_metrics.requests_failed.inc();
                            return Err(err).anyerr();
                        }
                    };
                    filter_hop_by_hop_headers(response.headers_mut());
                    debug!(?response, "received response from origin");
                    let res = forward_reqwest_response(
                        response,
                        &mut downstream_send,
                        req_metrics.clone(),
                    )
                    .await;
                    match res {
                        Ok(total) => {
                            debug!(response_body_len=%total, "finish");
                            metrics.requests_completed.inc();
                            req_metrics.requests_completed.inc();
                            Ok(())
                        }
                        Err(err) => {
                            metrics.requests_failed.inc();
                            req_metrics.requests_failed.inc();
                            Err(err)
                        }
                    }
                }
            }
        }
    }

    /// Handle HTTP upgrade requests (e.g., WebSocket) by connecting directly to origin.
    ///
    /// This bypasses reqwest since it doesn't support HTTP upgrades. We send the
    /// request manually over TCP, and if we get 101 Switching Protocols, we pipe
    /// the connection bidirectionally. The request URI should be in origin-form
    /// (path + query only); `authority` is used for the TCP connection.
    async fn handle_upgrade_request(
        authority: Authority,
        request: HttpRequest,
        mut downstream_recv: Prebuffered<RecvStream>,
        mut downstream_send: SendStream,
        req_metrics: Arc<TargetMetrics>,
    ) -> Result<()> {
        // Connect to origin
        let origin = match TcpStream::connect(authority.to_addr()).await {
            Ok(stream) => stream,
            Err(err) => {
                warn!("Failed to connect to origin for upgrade: {err:#}");
                error_response_and_finish(downstream_send).await?;
                return Err(err).anyerr();
            }
        };
        let (origin_recv, mut origin_send) = origin.into_split();

        let mut downstream_recv = TrackedRead::new(&mut downstream_recv, |d| {
            req_metrics.bytes_to_origin.inc_by(d);
        });
        let mut downstream_send = TrackedWrite::new(&mut downstream_send, |d| {
            req_metrics.bytes_from_origin.inc_by(d);
        });

        // Send the HTTP request to origin
        request.write(&mut origin_send).await?;

        // Read and forward the response from origin (expect 101 Switching Protocols)
        let mut origin_recv = Prebuffered::new(origin_recv, HEADER_SECTION_MAX_LENGTH);
        let response = HttpResponse::read(&mut origin_recv).await?;
        debug!(?response, "upgrade response from origin");
        response.write(&mut downstream_send, true).await?;

        if response.status != StatusCode::SWITCHING_PROTOCOLS {
            downstream_send.into_inner().finish().anyerr()?;
            return Ok(());
        }

        // Pipe bidirectionally after successful upgrade
        let (to_origin, from_origin) = forward_bidi(
            &mut downstream_recv,
            &mut downstream_send,
            &mut origin_recv,
            &mut origin_send,
        )
        .await?;
        debug!(to_origin, from_origin, "upgrade connection finished");
        Ok(())
    }
}

async fn forward_reqwest_response(
    response: reqwest::Response,
    send: &mut SendStream,
    req_metrics: Arc<TargetMetrics>,
) -> Result<usize> {
    let mut send = TrackedWrite::new(send, |d| {
        req_metrics.bytes_from_origin.inc_by(d);
    });
    write_response(&response, &mut send).await?;
    let send = send.into_inner();
    let mut total = 0;
    let mut body = response.bytes_stream();
    while let Some(bytes) = body.next().await {
        let bytes = bytes.anyerr()?;
        total += bytes.len();
        req_metrics.bytes_from_origin.inc_by(bytes.len() as u64);
        send.write_chunk(bytes).await.anyerr()?;
    }
    send.finish().anyerr()?;
    Ok(total)
}

async fn error_response_and_finish(mut send: SendStream) -> Result<(), n0_error::AnyError> {
    HttpResponse::with_reason(StatusCode::BAD_GATEWAY, "Origin Is Unreachable")
        .no_body()
        .write(&mut send, true)
        .await
        .inspect_err(|err| warn!("Failed to write error response to downstream: {err:#}"))
        .ok();
    send.finish().anyerr()?;
    Ok(())
}

async fn write_response(
    res: &reqwest::Response,
    send: &mut (impl AsyncWrite + Unpin),
) -> Result<()> {
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
