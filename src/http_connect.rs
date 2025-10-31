use httparse::{self, Header};
use iroh::endpoint::Connecting;
use iroh::{Endpoint, EndpointAddr, PublicKey};
use n0_snafu::{Result, ResultExt};
use snafu::{FromString, whatever};
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::quinn_util::forward_bidi;

// how much data to read for the CONNECT handshake before it's considered invalid
// 8KB should be plenty.
const CONNECT_HANDSHAKE_MAX_LENGTH: usize = 8192;
// HTTP header for iroh addressing info
const IROH_DESTINATION_HEADER: &str = "Iroh-Destination";
// TODO - do we use HTTP/3 here? this ALPN is only ever used over iroh
pub const IROH_HTTP_CONNECT_ALPN: &[u8] = b"h2";

#[derive(Debug)]
pub struct HttpConnectEntranceHandle {
    listen_on: Vec<SocketAddr>,
    endpoint: Endpoint,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl HttpConnectEntranceHandle {
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

/// Example: HTTP CONNECT proxy server that forwards to arbitrary destinations
/// This is a basic example - in dumbpipe you'd integrate this with iroh tunneling
pub async fn connect_http_connect(
    endpoint: Endpoint,
    listen: impl IntoIterator<Item = SocketAddr>,
) -> Result<HttpConnectEntranceHandle> {
    let listen = listen.into_iter().collect::<Vec<_>>();
    let tcp_listener = match tokio::net::TcpListener::bind(listen.as_slice()).await {
        Ok(tcp_listener) => tcp_listener,
        Err(cause) => {
            tracing::error!("error binding tcp socket to {:?}: {}", listen, cause);
            whatever!("error binding tcp socket to {:?}: {}", listen, cause);
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

            let endpoint = endpoint_2.clone();

            tokio::spawn(async move {
                let res = async {
                    let (client_stream, client_addr) = next.context("error accepting tcp connection")?;
                    let (mut tcp_stream, req, raw_handshake) =
                        handle_connect_handshake(client_stream).await?;
                    tracing::debug!(req = ?req, client_addr = ?client_addr, "handling CONNECT request");

                    match req.endpoint_addr {
                        Some(addr) => {
                            let (tcp_recv, tcp_send) = tcp_stream.into_split();
                            let remote_ep_id = addr.id;
                            let connection = endpoint
                                .connect(addr, IROH_HTTP_CONNECT_ALPN)
                                .await
                                .context(format!("error connecting to {remote_ep_id}"))?;
                            let (mut endpoint_send, mut endpoint_recv) = connection
                                .open_bi()
                                .await
                                .context(format!("error opening bidi stream to {remote_ep_id}"))?;

                            endpoint_send.write_all(&raw_handshake).await.e()?;
                            endpoint_recv.read_to_end(200).await.e()?;

                            let (endpoint_send_2, endpoint_recv_2) = connection
                                .accept_bi()
                                .await
                                .context("accepting bidi stream")?;
                            // TODO - we should make the receiver do the full HTTP dance.
                            // endpoint_recv.read
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
                            // no iroh header present, just do a local proxy. Useless? Maybe?
                            // might be helpful if the listening address is outside-dialable.
                            // regardless, it's more compliant with the notion of a normal
                            // HTTP CONNECT proxy
                            let mut target_stream =
                                TcpStream::connect(format!("{}:{}", req.host, req.port))
                                    .await
                                    .context("opening TCP stream locally")?;
                            tracing::debug!(req.host, req.port, "connected");

                            // Bidirectional copy between client and target
                            let (from_client, from_server) =
                                tokio::io::copy_bidirectional(&mut tcp_stream, &mut target_stream)
                                    .await
                                    .context("forwarding data")?;
                            tracing::debug!(from_client, from_server, "Tunnel closed");
                        }
                    }

                    Ok::<_, n0_snafu::Error>(())
                }
                .await;
                if let Err(err) = res {
                    tracing::error!("Error handling CONNECT request: {}", err);
                }
            });
        }
    });

    Ok(HttpConnectEntranceHandle {
        listen_on: listen,
        endpoint,
        cancel,
        handle,
    })
}

#[derive(Debug)]
struct ConnectRequest {
    host: String,
    port: u16,
    bytes_parsed: usize,
    endpoint_addr: Option<EndpointAddr>,
}

impl ConnectRequest {
    fn parse(buffer: &[u8]) -> Result<Self> {
        let mut headers = [Header {
            name: IROH_DESTINATION_HEADER,
            value: b"",
        }; 32];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(buffer).context("Failed to parse HTTP request")? {
            httparse::Status::Complete(bytes_parsed) => {
                // Verify it's a CONNECT request
                if req.method != Some("CONNECT") {
                    return Err(n0_snafu::Error::without_source(format!(
                        "Expected CONNECT method, got {:?}",
                        req.method
                    )));
                }

                // Parse the path which should be "host:port"
                let path = req.path.ok_or_else(|| {
                    n0_snafu::Error::without_source("Missing path in CONNECT request".to_string())
                })?;

                let addr = req
                    .headers
                    .iter()
                    .find(|h| h.name == IROH_DESTINATION_HEADER)
                    .map(|h| std::str::from_utf8(h.value).unwrap_or_default());
                let endpoint_addr = match addr {
                    Some(s) => {
                        let key = PublicKey::from_str(s)?;
                        // TODO - accept tickets here
                        let id = EndpointAddr::from(key);
                        Some(id)
                    }
                    None => None,
                };

                // Split into host and port
                let (host, port_str) = path.rsplit_once(':').ok_or_else(|| {
                    n0_snafu::Error::without_source(
                        "Invalid CONNECT path, expected host:port".to_string(),
                    )
                })?;

                // TODO - handle unwrap!
                let port: u16 = port_str.parse().unwrap();

                Ok(Self {
                    host: host.to_string(),
                    port,
                    bytes_parsed,
                    endpoint_addr,
                })
            }
            httparse::Status::Partial => Err(n0_snafu::Error::without_source(
                "Incomplete HTTP request".to_string(),
            )),
        }
    }
}

/// Send HTTP 200 Connection Established response
async fn send_connect_success(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|_| {
            n0_snafu::Error::without_source("sending connect success response".to_string())
        })?;
    Ok(())
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
        .map_err(|_| n0_snafu::Error::without_source("writing connect response".to_string()))?;
    Ok(())
}

async fn handle_connect_handshake(
    mut client_stream: TcpStream,
) -> Result<(TcpStream, ConnectRequest, Vec<u8>)> {
    let mut buffer = vec![0u8; CONNECT_HANDSHAKE_MAX_LENGTH];
    let n = client_stream
        .read(&mut buffer)
        .await
        .context("Failed to read CONNECT request")?;

    if n == 0 {
        return Err(n0_snafu::Error::without_source(
            "Client closed connection before sending request".to_string(),
        ));
    }

    // Parse the CONNECT request
    let req = match ConnectRequest::parse(&buffer[..n]) {
        Ok(result) => result,
        Err(e) => {
            // Try to send error response
            let _ = send_connect_error(&mut client_stream, 400, "Bad Request").await;
            return Err(e);
        }
    };

    // Send success response
    send_connect_success(&mut client_stream)
        .await
        .context("Failed to send 200 Connection Established")?;

    // Return the stream and destination
    Ok((client_stream, req, buffer[..n].to_vec()))
}

#[derive(Debug)]
pub struct HttpConnectListenerHandle {
    recv_from: Endpoint,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl HttpConnectListenerHandle {
    pub fn receiving(&self) -> &Endpoint {
        &self.recv_from
    }

    pub fn close(&self) {
        self.cancel.cancel();
        // TODO - wait & close gracefully
        self.handle.abort();
    }
}

/// Listen on an endpoint and forward incoming HTTP CONNECT connections to a a local tcp socket.
pub async fn listen_http_connect(endpoint: Endpoint) -> Result<HttpConnectListenerHandle> {
    // handle a new incoming connection on the endpoint
    async fn handle_endpoint_accept(connecting: Connecting) -> Result<()> {
        let connection = connecting.await.context("error accepting connection")?;
        let remote_node_id = &connection.remote_id()?;
        tracing::info!(remote_node_id = %remote_node_id.fmt_short(), "got connection");
        let (mut s, mut r) = connection
            .accept_bi()
            .await
            .context("error accepting stream")?;
        tracing::debug!("accepted bidi stream from {}", remote_node_id);
        let mut buffer = vec![0u8; CONNECT_HANDSHAKE_MAX_LENGTH];
        r.read(&mut buffer).await.context("reading handshake")?;
        let req = ConnectRequest::parse(&buffer)?;
        tracing::debug!(bytes_read = req.bytes_parsed, "read handshake");

        s.write(b"ok cool thanks")
            .await
            .context("writing response")?;

        // open a TCP stream to the specified target
        let target_stream = TcpStream::connect(format!("{}:{}", req.host, req.port))
            .await
            .context("opening local TCP stream to serve HTTP CONNECT proxy request")?;
        tracing::debug!(req.host, req.port, "connected");

        let (endpoint_send, endpoint_recv) = connection
            .open_bi()
            .await
            .context("error accepting stream 2")?;

        let (tcp_recv, tcp_send) = target_stream.into_split();

        forward_bidi(
            tcp_recv,
            tcp_send,
            endpoint_recv.into(),
            endpoint_send.into(),
        )
        .await?;

        tracing::info!(remote_node_id = %remote_node_id.fmt_short(), "connection completed");
        Ok(())
    }

    let endpoint_2 = endpoint.clone();
    let cancel = CancellationToken::new();
    let cancel_2 = cancel.clone();
    let handle = tokio::spawn(async move {
        loop {
            let incoming = tokio::select! {
                incoming = endpoint_2.accept() => incoming,
                _ = cancel_2.cancelled() => {
                    eprintln!("got ctrl-c, exiting");
                    break;
                }
            };
            let Some(incoming) = incoming else {
                break;
            };
            let Ok(connecting) = incoming.accept() else {
                break;
            };
            tokio::spawn(async move {
                if let Err(cause) = handle_endpoint_accept(connecting).await {
                    // log error at warn level
                    //
                    // we should know about it, but it's not fatal
                    tracing::warn!("error handling connection: {}", cause);
                }
            });
        }
    });

    Ok(HttpConnectListenerHandle {
        cancel,
        recv_from: endpoint,
        handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_request() {
        let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let parsed = ConnectRequest::parse(request).unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn test_parse_connect_with_ipv4() {
        let request = b"CONNECT 192.168.1.1:8080 HTTP/1.1\r\nHost: 192.168.1.1:8080\r\n\r\n";
        let parsed = ConnectRequest::parse(request).unwrap();
        assert_eq!(parsed.host, "192.168.1.1");
        assert_eq!(parsed.port, 8080);
    }

    #[test]
    fn test_parse_invalid_method() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(ConnectRequest::parse(request).is_err());
    }

    #[test]
    fn test_parse_incomplete_request() {
        let request = b"CONNECT example.com:443 HTTP/1.1\r\n";
        assert!(ConnectRequest::parse(request).is_err());
    }
}
