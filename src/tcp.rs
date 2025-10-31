use iroh::{Endpoint, EndpointAddr, endpoint::Connecting};
use n0_snafu::{Result, ResultExt};
use snafu::whatever;
use std::{io, net::SocketAddr};
use tokio_util::sync::CancellationToken;

use crate::quinn_util::forward_bidi;

/// The ALPN for dumbpipe.
///
/// It is basically just passing data through 1:1, except that the connecting
/// side will send a fixed size handshake to make sure the stream is created.
pub const ALPN: &[u8] = b"DUMBPIPEV0";

/// The handshake to send when connecting.
///
/// The side that calls open_bi() first must send this handshake, the side that
/// calls accept_bi() must consume it.
pub const HANDSHAKE: [u8; 5] = *b"hello";

#[derive(Debug)]
pub struct TcpConnectionHandle {
    listen_on: Vec<SocketAddr>,
    forward_to: EndpointAddr,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl TcpConnectionHandle {
    pub fn listening(&self) -> &Vec<SocketAddr> {
        &self.listen_on
    }

    pub fn forwarding(&self) -> &EndpointAddr {
        &self.forward_to
    }

    pub fn close(&self) {
        self.cancel.cancel();
        // TODO - we should send a oneshot on the oneshot that returns once
        // the connection is gracefully closed before aborting the task
        self.handle.abort();
    }
}

/// Open a local tcp port and forward incoming connections to an endpoint.
/// * endpoint - The local sender that will accept data from the local tcp
///              listener and forward it to to the other endpoint
/// * listen   - The addresses to listen on for incoming tcp connections.
///              To listen on all network interfaces, use 0.0.0.0:12345.
/// * forward  - The node to connect to & forward data to
pub async fn connect_tcp(
    endpoint: &Endpoint,
    listen: impl IntoIterator<Item = SocketAddr>,
    forward: EndpointAddr,
) -> Result<TcpConnectionHandle> {
    let listen = listen.into_iter().collect::<Vec<_>>();

    let tcp_listener = match tokio::net::TcpListener::bind(listen.as_slice()).await {
        Ok(tcp_listener) => tcp_listener,
        Err(cause) => {
            tracing::error!("error binding tcp socket to {:?}: {}", listen, cause);
            whatever!("error binding tcp socket to {:?}: {}", listen, cause);
        }
    };
    tracing::info!("tcp listening on {:?}", listen);

    // accept a TCP connection from the listener
    async fn handle_tcp_accept(
        next: io::Result<(tokio::net::TcpStream, SocketAddr)>,
        addr: EndpointAddr,
        endpoint: Endpoint,
        handshake: bool,
        alpn: &[u8],
    ) -> Result<()> {
        let (tcp_stream, tcp_addr) = next.context("error accepting tcp connection")?;
        let (tcp_recv, tcp_send) = tcp_stream.into_split();
        tracing::info!("got tcp connection from {}", tcp_addr);
        let remote_ep_id = addr.id;
        let connection = endpoint
            .connect(addr, alpn)
            .await
            .context(format!("error connecting to {remote_ep_id}"))?;
        let (mut endpoint_send, endpoint_recv) = connection
            .open_bi()
            .await
            .context(format!("error opening bidi stream to {remote_ep_id}"))?;
        // send the handshake unless we are using a custom alpn
        // when using a custom alpn, everything is up to the user
        if handshake {
            // the connecting side must write first. we don't know if there will be something
            // on stdin, so just write a handshake.
            endpoint_send.write_all(&HANDSHAKE).await.e()?;
        }
        forward_bidi(
            tcp_recv,
            tcp_send,
            endpoint_recv.into(),
            endpoint_send.into(),
        )
        .await?;
        Ok::<_, n0_snafu::Error>(())
    }

    let forward_2 = forward.clone();
    let endpoint = endpoint.clone();
    let cancel = CancellationToken::new();
    let cancel_2 = cancel.clone();

    let handle = tokio::spawn(async move {
        loop {
            // also wait for close signal here so we can use it before accepting a connection
            let next = tokio::select! {
                stream = tcp_listener.accept() => stream,
                _ = cancel_2.cancelled() => {
                    tracing::debug!("received close signal");
                    break;
                }
            };

            let endpoint = endpoint.clone();
            let addr = forward_2.clone();
            let handshake = true;
            let alpn = ALPN;
            tokio::spawn(async move {
                if let Err(cause) = handle_tcp_accept(next, addr, endpoint, handshake, &alpn).await
                {
                    // log error at warn level
                    //
                    // we should know about it, but it's not fatal
                    tracing::warn!("error handling connection: {}", cause);
                }
            });
        }
    });
    Ok(TcpConnectionHandle {
        forward_to: forward,
        listen_on: listen,
        cancel,
        handle,
    })
}

#[derive(Debug)]
pub struct TcpListenerHandle {
    forward_to: Vec<SocketAddr>,
    recv_from: Endpoint,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl TcpListenerHandle {
    pub fn forwarding(&self) -> &Vec<SocketAddr> {
        &self.forward_to
    }

    pub fn receiving(&self) -> &Endpoint {
        &self.recv_from
    }

    pub fn close(&self) {
        self.cancel.cancel();
        self.handle.abort();
    }
}

/// Listen on an endpoint and forward incoming connections to a a local tcp socket.
pub async fn listen_tcp(
    endpoint: Endpoint,
    host: impl IntoIterator<Item = SocketAddr>,
) -> Result<TcpListenerHandle> {
    let forward_to = host.into_iter().collect::<Vec<_>>();

    // handle a new incoming connection on the endpoint
    async fn handle_endpoint_accept(
        connecting: Connecting,
        addrs: Vec<SocketAddr>,
        handshake: bool,
    ) -> Result<()> {
        let connection = connecting.await.context("error accepting connection")?;
        let remote_node_id = &connection.remote_id()?;
        tracing::info!("got connection from {}", remote_node_id);
        let (s, mut r) = connection
            .accept_bi()
            .await
            .context("error accepting stream")?;
        tracing::info!("accepted bidi stream from {}", remote_node_id);
        if handshake {
            // read the handshake and verify it
            let mut buf = [0u8; HANDSHAKE.len()];
            r.read_exact(&mut buf).await.e()?;
            snafu::ensure_whatever!(buf == HANDSHAKE, "invalid handshake");
        }
        let connection = tokio::net::TcpStream::connect(addrs.as_slice())
            .await
            .context(format!("error connecting to {addrs:?}"))?;
        let (read, write) = connection.into_split();
        forward_bidi(read, write, r, s).await?;
        Ok(())
    }

    let endpoint_2 = endpoint.clone();
    let forward_to_2 = forward_to.clone();
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
            let addrs = forward_to_2.clone();
            let handshake = true;
            tokio::spawn(async move {
                if let Err(cause) = handle_endpoint_accept(connecting, addrs, handshake).await {
                    // log error at warn level
                    //
                    // we should know about it, but it's not fatal
                    tracing::warn!("error handling connection: {}", cause);
                }
            });
        }
    });

    Ok(TcpListenerHandle {
        forward_to,
        cancel,
        recv_from: endpoint,
        handle,
    })
}
