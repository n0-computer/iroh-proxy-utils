use std::{io, sync::Arc};

use bytes::Bytes;
use http::StatusCode;
use iroh::{
    EndpointId,
    endpoint::{Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
};
use n0_error::{Result, StackResultExt, StdResultExt};
use n0_future::stream::{self, StreamExt};
use quinn::ConnectionError;
use tokio::net::TcpStream;
use tracing::{Instrument, debug, instrument, warn};

use crate::{
    HEADER_SECTION_MAX_LENGTH,
    parse::{HttpProxyRequestKind, HttpRequest},
    util::{Prebuffered, forward_bidi, write_http_response, write_reqwest_response},
};

mod auth;
pub use auth::*;

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
    /// Creates a new upstream proxy with the provided authorization handler.
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
        recv: RecvStream,
    ) -> Result<()> {
        let mut recv = Prebuffered::new(recv, HEADER_SECTION_MAX_LENGTH);
        let (header_section_len, req) = HttpRequest::read(&mut recv).await?;

        debug!(?req, "incoming request");
        let req = req
            .try_into_proxy_request()
            .context("Received origin-form request but expected proxy request")?;

        match auth.authorize(remote_id, &req).await {
            Ok(()) => debug!("request is authorized, continue"),
            Err(err) => {
                debug!("request is not authorized, abort");
                return Err(err.into());
            }
        };

        match req.kind {
            HttpProxyRequestKind::Tunnel { target: authority } => {
                // Remove the CONNECT request from the recv stream, because it is not forwarded to the origin server.
                recv.discard(header_section_len);
                match TcpStream::connect(authority.to_addr()).await {
                    Err(err) => {
                        warn!("Failed to connect to upstream server: {err:#}");
                        write_http_response(&mut send, StatusCode::BAD_GATEWAY, None).await?;
                        send.finish().anyerr()?;
                    }
                    Ok(tcp_stream) => {
                        debug!(?authority, "connected to upstream");
                        write_http_response(
                            &mut send,
                            StatusCode::OK,
                            Some("Connection established"),
                        )
                        .await?;
                        let (mut tcp_recv, mut tcp_send) = tcp_stream.into_split();
                        forward_bidi(&mut tcp_recv, &mut tcp_send, &mut recv, &mut send).await?;
                    }
                }
                Ok(())
            }
            HttpProxyRequestKind::Absolute { method, target } => {
                let client = reqwest::Client::new();

                // Convert the Prebuffered<RecvStream> into a stream of Result<Bytes, std::io::Error>
                let (init, recv) = recv.into_parts();
                let body = stream::unfold((Some(init), recv), async |(mut init, mut recv)| {
                    let item: io::Result<Bytes> = if let Some(init) = init.take() {
                        Ok(init)
                    } else {
                        match recv.read_chunk(8192, true).await {
                            Err(err) => Err(err.into()),
                            Ok(None) => return None,
                            Ok(Some(chunk)) => Ok(chunk.bytes),
                        }
                    };
                    Some((item, (None, recv)))
                });

                // Forward the request to the upstream server.
                let res = client
                    .request(method, target)
                    // TODO: Filter out into_proxy_requestinto_proxy_requestheaders that should not be forwarded to upstream.
                    .headers(req.headers)
                    .body(reqwest::Body::wrap_stream(body))
                    .send()
                    .await
                    .anyerr()?;

                write_reqwest_response(&res, &mut send).await?;
                let mut body = res.bytes_stream();
                while let Some(bytes) = body.next().await {
                    let bytes = bytes.anyerr()?;
                    send.write_chunk(bytes).await.anyerr()?;
                }
                send.finish().anyerr()?;
                Ok(())
            }
        }
    }
}
