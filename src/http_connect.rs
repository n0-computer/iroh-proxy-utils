use std::fmt::Debug;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use httparse::{self, Header};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId, PublicKey};
use n0_error::{AnyError, Result, StackResultExt, StdResultExt, anyerr, ensure_any};
use n0_future::stream::StreamExt;
use quinn::{RecvStream, SendStream, VarInt};
use reqwest::Url;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, error_span, info, instrument, trace, warn};

use crate::error::AuthError;
use crate::http_connect::parse::{Authority, HttpRequest, RequestKind};
use crate::util::forward_bidi;

mod parse;

/// how much data to read for the CONNECT handshake before it's considered invalid
/// 8KB should be plenty.
const CONNECT_HANDSHAKE_MAX_LENGTH: usize = 8192;
/// HTTP header for iroh addressing info
const IROH_DESTINATION_HEADER: &str = "Iroh-Destination";
/// The ALPN that we're using for iroh connections, defaults to HTTP/2
// TODO - do we use HTTP/3 here? this ALPN is only ever used over iroh
pub const IROH_HTTP_CONNECT_ALPN: &[u8] = b"h2";
/// Handshake to distinguish a stream construction
const STREAM_OPEN_HANDSHAKE: &[u8] = b"OPEN";
/// If a stream sends this message, we'll gacefully close the connection
const CLIENT_CLOSE_MESSAGE: &[u8] = b"DONE";

pub trait AuthHandler: Send + Sync + Debug {
    // fn authorize_connection<'a>(
    //     &'a self,
    //     _remote_id: EndpointId,
    // ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>> {
    //     Box::pin(async { Ok(true) })
    // }

    fn authorize<'a>(
        &'a self,
        req: &'a Request,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>>;
}

/// NoAuthHandler rejects all requests
#[derive(Debug)]
pub struct NoAuthHandler;

impl AuthHandler for NoAuthHandler {
    fn authorize<'a>(
        &'a self,
        _req: &'a Request,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>> {
        Box::pin(async move { Err(AuthError::Forbidden) })
    }
}

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

    async fn accept_data_stream(
        connection: &Connection,
    ) -> Result<Option<(SendStream, RecvStream)>> {
        let (endpoint_send, mut endpoint_recv) = connection
            .accept_bi()
            .await
            .std_context("error accepting stream 2")?;

        // TODO - we're relying on the fact that the length of open & done messages are equal here
        let mut buf = [0u8; STREAM_OPEN_HANDSHAKE.len()];
        endpoint_recv.read_exact(&mut buf).await.anyerr()?;
        if buf == CLIENT_CLOSE_MESSAGE {
            return Ok(None);
        }
        ensure_any!(buf == STREAM_OPEN_HANDSHAKE, "invalid handshake");
        Ok(Some((endpoint_send, endpoint_recv)))
    }

    #[instrument(skip_all, fields(target=%format!("{}:{}", req.host, req.port)))]
    async fn handle_connect_request(
        connection: Connection,
        mut s: SendStream,
        req: ProxyConnectRequest,
    ) -> std::result::Result<(), AcceptError> {
        s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|_| {
                n0_error::AnyError::from_string("sending connect success response".to_string())
            })?;
        s.finish()
            .std_context("finishing tunnel construction stream")?;

        // loop to construct one TCP stream per data request, this allows multiple
        // TCP connections to use the same tunnel
        loop {
            let conn = connection.clone();
            let Some((proxied_send, proxied_recv)) = Self::accept_data_stream(&conn).await? else {
                // if accept_data_stream returns None, it's time to close the tunnel
                break;
            };
            trace!("got data stream");

            // open a TCP stream to the specified target
            let target_stream = req.tcp_stream().await?;
            trace!("got target tcp stream");
            let (tcp_recv, tcp_send) = target_stream.into_split();
            let remote_endpoint_id = conn.remote_id();
            tokio::task::spawn(
                async move {
                    let res: n0_error::Result<()> = async {
                    debug!("forwarding TCP stream data to bidi QUIC stream");
                    forward_bidi(tcp_recv, tcp_send, proxied_recv.into(), proxied_send.into())
                        .await?;

                    info!(remote_node_id = %remote_endpoint_id.fmt_short(), "connection completed");

                    Ok(())
                }
                .await;

                    if let Err(err) = res {
                        warn!("connection close error: {:?}", err);
                    }
                }
                .instrument(error_span!("tcp-stream",)),
            );
        }
        trace!("closing tunnel listener");
        Ok(())
    }

    async fn handle_http_request(
        connection: Connection,
        mut s: SendStream,
        req: ProxyHttpRequest,
    ) -> std::result::Result<(), AcceptError> {
        // close the initial stream, we don't need to ACK.
        s.finish().anyerr()?;

        let Some((mut proxied_send, _)) = Self::accept_data_stream(&connection).await? else {
            debug!("tunnel connection closed");
            return Ok(());
        };

        let client = reqwest::Client::new();
        let method = reqwest::Method::from_str(&req.method).map_err(|_| {
            n0_error::AnyError::from_string("invalid HTTP request method".to_string())
        })?;
        let res = client.request(method, req.path).send().await.anyerr()?;
        // TODO - pipe the response instead of buffering
        let body = res.bytes().await.anyerr()?;
        proxied_send.write_all(&body).await.anyerr()?;
        proxied_send.finish().anyerr()?;
        Ok(())
    }

    async fn handle_streams(
        auth: Arc<dyn AuthHandler>,
        remote_id: EndpointId,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        let header_names = [IROH_DESTINATION_HEADER];
        let req = HttpRequest::read(&mut recv, header_names, 8192).await?;
        // TODO: Validate that the request is for us.
        // TODO: Authenticate
        match req.kind {
            RequestKind::Connect { authority } => {
                let authority = Authority::parse(&authority)?;
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
                        tcp_send.write_all(&req.initial_data).await?;
                        forward_bidi(tcp_recv, tcp_send, recv, send).await?;
                    }
                }
            }
            RequestKind::Http {
                method,
                host: _,
                path,
            } => {
                // TODO: Authenticate
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
        todo!()
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
                    if let Err(err) = Self::handle_streams(auth, remote_id, send, recv).await {
                        warn!("Failed to handle streams: {err:#}");
                    }
                }
                .instrument(tracing::Span::current())
            });
        }
    }
}

async fn send_error_response(
    writer: &mut (impl AsyncWrite + Unpin),
    status: http::StatusCode,
) -> Result<()> {
    let status_line = format!(
        "HTTP/1.1 {} {}\r\n\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    );
    writer.write_all(status_line.as_bytes()).await?;
    Ok(())
}

impl ProtocolHandler for TunnelListener {
    #[instrument("accept", skip_all, fields(remote=%connection.remote_id().fmt_short()))]
    async fn accept(
        &self,
        connection: Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        let remote_endpoint_id = &connection.remote_id();
        debug!(remote_node_id = %remote_endpoint_id.fmt_short(), "got connection");

        // accept a bidi stream to do the HTTP CONNECT handshake
        let (s, mut r) = connection
            .accept_bi()
            .await
            .std_context("error accepting stream")?;
        trace!("accepted bidi stream from {}", remote_endpoint_id);

        let mut buffer = vec![0u8; CONNECT_HANDSHAKE_MAX_LENGTH];
        r.read(&mut buffer).await.std_context("reading handshake")?;
        let req = Request::parse(&buffer)?;
        debug!(?req, "read handshake");
        trace!(
            "buffer: {}",
            std::str::from_utf8(&buffer).unwrap_or_default()
        );

        // TODO - make errors real
        self.auth
            .authorize(&req)
            .await
            .map_err(|_| n0_error::AnyError::from_string("unauthorized".to_string()))?;

        trace!("client is authorized");

        match req {
            Request::Connect(req) => Self::handle_connect_request(connection, s, req).await,
            Request::Http(req) => Self::handle_http_request(connection, s, req).await,
        }
    }
}

#[derive(Debug)]
pub struct HttpConnectClientHandle {
    listen_on: Vec<SocketAddr>,
    endpoint: Endpoint,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl HttpConnectClientHandle {
    pub async fn connect(
        endpoint: Endpoint,
        listen: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<Self> {
        let listen = listen.into_iter().collect::<Vec<_>>();
        let tcp_listener = match tokio::net::TcpListener::bind(listen.as_slice()).await {
            Ok(tcp_listener) => tcp_listener,
            Err(cause) => {
                tracing::error!("error binding tcp socket to {:?}: {}", listen, cause);
                return Err(anyerr!(
                    "error binding tcp socket to {:?}: {}",
                    listen,
                    cause
                ));
            }
        };
        tracing::info!("tcp listening on {:?}", listen);

        let endpoint_2 = endpoint.clone();
        let cancel = CancellationToken::new();
        let cancel_2 = cancel.clone();
        let handle = tokio::spawn(async move {
            loop {
                let next = tokio::select! {
                    stream = tcp_listener.accept() => stream,
                    _ = cancel_2.cancelled() => {
                        tracing::debug!("received close signal");
                        break;
                    }
                };

                tracing::debug!(next = ?next, "accepted connect request");

                let endpoint = endpoint_2.clone();
                tokio::spawn(async move {
                    let res = async {
                        let (client_stream, client_addr) = next.std_context("accepting tcp connection")?;

                        let (tcp_stream, req, raw_handshake) =
                            handle_connect_handshake(client_stream).await.std_context("handling CONNECT handshake")?;
                        tracing::debug!(req = ?req, client_addr = ?client_addr, "HTTP CONNECT request has valid headers");

                        let addr = match req {
                            Request::Connect(req) => req.endpoint_addr,
                            Request::Http(req) => req.endpoint_addr,
                        };

                        match addr {
                            Some(addr) => {
                                let (tcp_recv, mut tcp_send) = tcp_stream.into_split();
                                let remote_ep_id = addr.id;
                                let connection = endpoint
                                    .connect(addr, IROH_HTTP_CONNECT_ALPN)
                                    .await
                                    .std_context(format!("error connecting to {remote_ep_id}"))?;
                                let (mut endpoint_send, mut endpoint_recv) = connection
                                    .open_bi()
                                    .await
                                    .std_context(format!("error opening bidi stream to {remote_ep_id}"))?;

                                endpoint_send.write_all(&raw_handshake).await.anyerr()?;

                                let data = endpoint_recv.read_to_end(1000).await.anyerr()?;
                                tcp_send.write_all(&data).await.map_err(|_| {
                                    n0_error::AnyError::from_string("sending connect success response".to_string())
                                })?;

                                let (mut endpoint_send_2, endpoint_recv_2) =
                                    connection.open_bi().await.std_context("opening bidi stream")?;
                                endpoint_send_2
                                    .write(STREAM_OPEN_HANDSHAKE)
                                    .await
                                    .map_err(|_| {
                                        n0_error::AnyError::from_string(
                                            "sending connect handshake response".to_string(),
                                        )
                                    })?;

                                tracing::debug!("forwarding bidi stream to local TCP port");
                                forward_bidi(
                                    tcp_recv,
                                    tcp_send,
                                    endpoint_recv_2.into(),
                                    endpoint_send_2.into(),
                                )
                                .await
                                .unwrap();
                                // .map_err(anyhow::Error::into_boxed_dyn_error)?;
                            }
                            None => {
                                // todo!("Implement local proxy functionality");
                                //
                                // // no iroh header present, just do a local proxy. Useless? Maybe?
                                // // might be helpful if the listening address is outside-dialable.
                                // // regardless, it's more compliant with the notion of a normal
                                // // HTTP CONNECT proxy
                                // let mut target_stream = req.tcp_stream().await?;
                                // tracing::debug!(req.host, req.port, "opened local TCP stream");

                                // // Bidirectional copy between client and target
                                // let (from_client, from_server) =
                                //     tokio::io::copy_bidirectional(&mut tcp_stream, &mut target_stream)
                                //         .await
                                //         .context("forwarding data")?;
                                // tracing::debug!(from_client, from_server, "Tunnel closed");
                            }
                        }
                        Ok::<(), n0_error::AnyError>(())
                    }
                    .await;

                    if let Err(err) = res {
                        tracing::error!("Error handling CONNECT request: {}", err);
                    }
                });
            }
        });

        Ok(Self {
            listen_on: listen,
            endpoint,
            cancel,
            handle,
        })
    }

    pub fn listening_addrs(&self) -> &Vec<SocketAddr> {
        &self.listen_on
    }

    pub fn forwarding(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn close(&self) {
        self.cancel.cancel();
        // TODO - graceful cleanup
        self.handle.abort();
    }
}

#[derive(Debug)]
pub struct TunnelClientStreams {
    conn: Connection,
}

impl TunnelClientStreams {
    pub async fn connect(
        local: &Endpoint,
        remote: impl Into<EndpointAddr>,
        host: String,
        port: u16,
    ) -> Result<Self> {
        let addr = remote.into();
        let remote_ep_id = addr.id;
        let conn = local
            .connect(addr, IROH_HTTP_CONNECT_ALPN)
            .await
            .std_context(format!("error connecting to {remote_ep_id}"))?;
        Self::from_connection(conn, host, port).await
    }

    pub async fn from_connection(conn: Connection, host: String, port: u16) -> Result<Self> {
        let remote_id = conn.remote_id();
        let handshake_bytes = Request::Connect(ProxyConnectRequest {
            host,
            port,
            endpoint_addr: None,
        })
        .serialize_handshake();
        // open a stream to send the HTTP CONNECT handshake
        let (mut connect_handshake_tx, mut connect_handshake_rx) = conn
            .open_bi()
            .await
            .std_context(format!("error opening bidi stream to {remote_id}"))?;
        connect_handshake_tx
            .write_all(&handshake_bytes)
            .await
            .anyerr()?;

        let data = connect_handshake_rx.read_to_end(1000).await.anyerr()?;
        // TODO - need to examine response & make sure it's ok, right now we're assuming it's ok :/
        debug!(
            "http connect response: {:?}",
            String::from_utf8_lossy(&data)
        );

        // At this point the tunnel is ready. users of this struct should call `new_streams`
        // for an owned set of streams that actually send data. Each stream pair maps to a TCP stream

        Ok(Self { conn })
    }

    pub fn remote_id(&self) -> EndpointId {
        self.conn.remote_id()
    }

    pub async fn new_streams(&self) -> Result<(SendStream, RecvStream)> {
        let (mut tunnel_send, tunnel_recv) = self
            .conn
            .open_bi()
            .await
            .std_context("opening bidi stream")?;
        tunnel_send
            .write(STREAM_OPEN_HANDSHAKE)
            .await
            .map_err(|_| {
                n0_error::AnyError::from_string("sending connect handshake response".to_string())
            })?;

        debug!("created new streams * completed handshake");

        Ok((tunnel_send, tunnel_recv))
    }

    pub fn close(&self) {
        self.conn.close(VarInt::from_u32(0), b"byebye");
    }

    pub async fn wrap_tcp(
        &self,
        listen: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<JoinHandle<()>> {
        let listen = listen.into_iter().collect::<Vec<_>>();
        let tcp_listener = match tokio::net::TcpListener::bind(listen.as_slice()).await {
            Ok(tcp_listener) => tcp_listener,
            Err(cause) => {
                tracing::error!("error binding tcp socket to {:?}: {}", listen, cause);
                return Err(anyerr!(
                    "error binding tcp socket to {:?}: {}",
                    listen,
                    cause
                ));
            }
        };
        info!("tcp listening on {:?}", listen);

        let conn = self.conn.clone();
        let cancel = CancellationToken::new();
        let cancel_2 = cancel.clone();
        let handle = tokio::spawn(async move {
            loop {
                let next = tokio::select! {
                    stream = tcp_listener.accept() => stream,
                    _ = cancel_2.cancelled() => {
                        tracing::debug!("received close signal");
                        break;
                    }
                };
                tracing::debug!(next = ?next, "accepted connect request");
                let conn2 = conn.clone();
                tokio::spawn(async move {
                    let res: Result<_, AnyError> = async {
                        let (client_stream, _client_addr) =
                            next.std_context("accepting tcp connection")?;
                        let (tcp_recv, tcp_send) = client_stream.into_split();
                        let (mut tunnel_send, tunnel_recv) =
                            conn2.open_bi().await.std_context("opening bidi stream")?;

                        tunnel_send
                            .write(STREAM_OPEN_HANDSHAKE)
                            .await
                            .map_err(|_| {
                                n0_error::AnyError::from_string(
                                    "sending connect handshake response".to_string(),
                                )
                            })?;

                        forward_bidi(tcp_recv, tcp_send, tunnel_recv.into(), tunnel_send.into())
                            .await?;

                        Ok(())
                    }
                    .await;

                    if let Err(err) = res {
                        error!(error = %err, "error forwarding tcp-wrapped streams");
                    }
                });
            }
        });
        Ok(handle)
    }
}

#[derive(Debug)]
pub enum Request {
    Connect(ProxyConnectRequest),
    Http(ProxyHttpRequest),
}

#[derive(Debug)]
pub struct ProxyConnectRequest {
    pub host: String,
    pub port: u16,
    pub endpoint_addr: Option<EndpointAddr>,
}

impl ProxyConnectRequest {
    async fn tcp_stream(&self) -> Result<TcpStream> {
        let addr = format!("{}:{}", self.host, self.port);
        tracing::debug!(host = self.host, addr, "opening connect request TCP stream");
        TcpStream::connect(addr)
            .await
            .std_context("opening connect request TCP stream")
    }
}

#[derive(Debug)]
pub struct ProxyHttpRequest {
    pub method: String,
    pub path: String,
    pub endpoint_addr: Option<EndpointAddr>,
}

impl Request {
    pub fn parse(buffer: &[u8]) -> Result<Self> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        match req
            .parse(buffer)
            .std_context("Failed to parse HTTP request")?
        {
            httparse::Status::Complete(_bytes_parsed) => {
                let method = req.method.ok_or_else(|| {
                    n0_error::AnyError::from_string("Missing method in CONNECT request".to_string())
                })?;

                let endpoint_addr = req
                    .headers
                    .iter()
                    .find(|h| h.name == IROH_DESTINATION_HEADER)
                    .map(|h| std::str::from_utf8(h.value).unwrap_or_default());

                let endpoint_addr = match endpoint_addr {
                    Some(s) => {
                        let key = PublicKey::from_str(s)?;
                        // TODO - accept tickets here
                        let id = EndpointAddr::from(key);
                        Some(id)
                    }
                    None => None,
                };

                match method {
                    "CONNECT" => Self::from_connect_request(req, endpoint_addr),
                    "GET" | "PUT" | "POST" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE" | "PATCH" => {
                        let path = req.path.ok_or_else(|| {
                            n0_error::AnyError::from_string(
                                "missing path value for HTTP request".to_string(),
                            )
                        })?;
                        Ok(Self::Http(ProxyHttpRequest {
                            method: method.to_string(),
                            path: path.to_string(),
                            endpoint_addr,
                        }))
                    }
                    _ => Err(n0_error::AnyError::from_string(format!(
                        "Invalid request method: {}",
                        method
                    ))),
                }
            }
            httparse::Status::Partial => Err(n0_error::AnyError::from_string(
                "Incomplete HTTP request".to_string(),
            )),
        }
    }

    fn from_connect_request(
        req: httparse::Request,
        endpoint_addr: Option<EndpointAddr>,
    ) -> Result<Self> {
        // Parse the path which should be "host:port"
        let path = req.path.ok_or_else(|| {
            n0_error::AnyError::from_string("Missing path in CONNECT request".to_string())
        })?;

        // Split into host and port
        let (host, port_str) = path.rsplit_once(':').ok_or_else(|| {
            n0_error::AnyError::from_string("Invalid CONNECT path, expected host:port".to_string())
        })?;

        // Strip scheme and end slashes if present.
        // non-standard but some clients like curl do it
        let host = host
            .strip_prefix("https://")
            .or_else(|| host.strip_prefix("http://"))
            .unwrap_or(host);

        let port: u16 = port_str
            .trim_end_matches('/')
            .parse()
            .map_err(|e| {
                n0_error::AnyError::from_string(format!("Invalid port number {port_str}: {}", e))
            })
            .anyerr()?;

        Ok(Self::Connect(ProxyConnectRequest {
            host: host.to_string(),
            port,
            endpoint_addr,
        }))
    }

    fn serialize_handshake(&self) -> Vec<u8> {
        match self {
            Request::Connect(ProxyConnectRequest {
                host,
                port,
                endpoint_addr,
            }) => match endpoint_addr {
                Some(addr) => {
                    let id = addr.id.to_string();
                    format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nIroh-Destination: {id}\r\n\r\n").as_bytes().to_vec()
                }
                None => format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n")
                    .as_bytes()
                    .to_vec(),
            },
            Request::Http(_) => todo!(),
        }
    }
}

// Send HTTP error response
async fn send_connect_error(stream: &mut TcpStream, status: u16, message: &str) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: 0\r\n\r\n",
        status, message
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|_| n0_error::AnyError::from_string("writing connect response".to_string()))?;
    Ok(())
}

async fn handle_connect_handshake(
    mut client_stream: TcpStream,
) -> Result<(TcpStream, Request, Vec<u8>)> {
    let mut buffer = vec![0u8; CONNECT_HANDSHAKE_MAX_LENGTH];
    let n = client_stream
        .read(&mut buffer)
        .await
        .std_context("Failed to read CONNECT request")?;

    if n == 0 {
        return Err(n0_error::AnyError::from_string(
            "Client closed connection before sending request".to_string(),
        ));
    }

    // Parse the CONNECT request
    let req = match Request::parse(&buffer[..n]) {
        Ok(result) => result,
        Err(e) => {
            // Try to send error response
            let _ = send_connect_error(&mut client_stream, 400, "Bad Request").await;
            return Err(e);
        }
    };

    // Return the stream and destination
    Ok((client_stream, req, buffer[..n].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_request() {
        let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let parsed = Request::parse(request).unwrap();
        let Request::Connect(connect) = parsed else {
            panic!("Expected Connect variant");
        };
        assert_eq!(connect.host, "example.com");
        assert_eq!(connect.port, 443);
    }

    #[test]
    fn test_parse_connect_with_ipv4() {
        let request = b"CONNECT 192.168.1.1:8080 HTTP/1.1\r\nHost: 192.168.1.1:8080\r\n\r\n";
        let parsed = Request::parse(request).unwrap();
        let Request::Connect(connect) = parsed else {
            panic!("Expected Connect variant");
        };
        assert_eq!(connect.host, "192.168.1.1");
        assert_eq!(connect.port, 8080);
    }

    #[test]
    fn test_parse_invalid_method() {
        let request = b"BANANA / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(Request::parse(request).is_err());
    }

    #[test]
    fn test_parse_incomplete_request() {
        let request = b"CONNECT example.com:443 HTTP/1.1\r\n";
        assert!(Request::parse(request).is_err());
    }
}
