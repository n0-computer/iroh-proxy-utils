use std::{io, ops::Deref, pin::Pin, str::FromStr, sync::Arc};

use iroh::EndpointId;
use n0_error::AnyError;
use n0_future::FutureExt;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, tcp::OwnedWriteHalf},
};
use tracing::{Instrument, debug, warn, warn_span};

use crate::{IROH_DESTINATION_HEADER, PoolOptions, TunnelClientPool, parse::HttpRequest};

pub trait ResolveDestination: Send + Sync + 'static {
    fn resolve_destination<'a>(
        &'a self,
        req: &'a HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Option<EndpointId>> + Send + 'a>>;
}

pub struct ResolveDestinationFromHeader {
    header_name: String,
}

impl Default for ResolveDestinationFromHeader {
    fn default() -> Self {
        Self::new(IROH_DESTINATION_HEADER.to_string())
    }
}

impl ResolveDestinationFromHeader {
    pub fn new(header_name: String) -> Self {
        Self { header_name }
    }
}

impl ResolveDestination for ResolveDestinationFromHeader {
    fn resolve_destination<'a>(
        &'a self,
        req: &'a HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Option<EndpointId>> + Send + 'a>> {
        async {
            if let Some(value) = req.headers.get(&self.header_name) {
                EndpointId::from_str(value.to_str().ok()?).ok()
            } else {
                None
            }
        }
        .boxed()
    }
}

pub struct ProxyOptions {
    pub pool: PoolOptions,
    pub parse_destination: Arc<dyn ResolveDestination>,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            pool: Default::default(),
            parse_destination: Arc::new(ResolveDestinationFromHeader::default()),
        }
    }
}

#[derive(Clone)]
pub struct GatewayListener {
    pool: TunnelClientPool,
    resolve_destination: Arc<dyn ResolveDestination>,
}

impl GatewayListener {
    pub fn new(pool: TunnelClientPool, resolve_destination: Arc<dyn ResolveDestination>) -> Self {
        Self {
            pool,
            resolve_destination,
        }
    }

    pub async fn listen(&self, listener: TcpListener) {
        let mut conn_id = 0;
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    conn_id += 1;
                    let this = self.clone();
                    tokio::spawn(
                        async move {
                            debug!("New connection from {}", peer_addr);
                            match this
                                .pool
                                .forward_http_connection(stream, this.resolve_destination.deref())
                                .await
                            {
                                Ok(()) => {
                                    debug!("connection closed");
                                }
                                Err(mut err) => {
                                    warn!("proxy request failed: {} {:#}", err.status, err.source);
                                    if let Err(err) = err.finalize().await {
                                        warn!("failed to send error response to client: {err:#}");
                                    }
                                }
                            }
                        }
                        .instrument(warn_span!("gw-conn", %conn_id)),
                    );
                }
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

pub struct ProxyFailure {
    pub tcp_send: OwnedWriteHalf,
    pub status: http::StatusCode,
    pub source: AnyError,
}

impl ProxyFailure {
    pub fn new(tcp_send: OwnedWriteHalf, status: http::StatusCode, source: AnyError) -> Self {
        Self {
            tcp_send,
            status,
            source,
        }
    }
}

impl ProxyFailure {
    pub async fn write_status_line(&mut self) -> io::Result<()> {
        let status_line = format!(
            "HTTP/1.1 {} {}\r\n",
            self.status.as_u16(),
            self.status.canonical_reason().unwrap_or("")
        );
        self.tcp_send.write_all(status_line.as_bytes()).await?;
        Ok(())
    }

    pub async fn finalize_with_body(&mut self, body: &[u8]) -> io::Result<()> {
        self.write_status_line().await?;
        self.tcp_send
            .write_all(format!("Content-Length: {}\r\n", body.len()).as_bytes())
            .await?;
        self.tcp_send.write_all(b"\r\n").await?;
        self.tcp_send.write_all(&body).await?;
        Ok(())
    }

    pub async fn finalize(&mut self) -> io::Result<()> {
        self.write_status_line().await?;
        self.tcp_send.write_all(b"Content-Length: 0\r\n").await?;
        self.tcp_send.write_all(b"\r\n").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http::{HeaderMap, StatusCode};
    use iroh::{Endpoint, protocol::Router};
    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;
    use tokio::net::TcpListener;

    use crate::{
        ALPN, AcceptAll, GatewayListener, ResolveDestinationFromHeader, TunnelClientPool,
        TunnelListener,
    };

    #[tokio::test]
    #[traced_test]
    async fn gw_reqwest_end_to_end() -> Result {
        let gw_ep = Endpoint::bind().await?;
        println!("gateway: {}", gw_ep.id());
        let pool = TunnelClientPool::new(gw_ep, Default::default());
        let gw = GatewayListener::new(pool, Arc::new(ResolveDestinationFromHeader::default()));
        let gw_listener = TcpListener::bind("localhost:0").await?;
        let gw_addr = gw_listener.local_addr()?;
        let gw_task = tokio::spawn(async move { gw.listen(gw_listener).await });

        let upstream_router = {
            let ep = Endpoint::bind().await?;
            Router::builder(ep)
                .accept(ALPN, TunnelListener::new(AcceptAll)?)
                .spawn()
        };
        upstream_router.endpoint().online().await;
        let upstream_id = upstream_router.endpoint().id();
        println!("upstream: {upstream_id}");

        let upstream_tcp_listener = TcpListener::bind("localhost:0").await?;
        let upstream_tcp_addr = upstream_tcp_listener.local_addr()?;
        let upstream_task = tokio::spawn(self::hyper::run(upstream_tcp_listener));

        let client = {
            let mut proxy_headers = HeaderMap::new();
            proxy_headers.insert("iroh-destination", upstream_id.to_string().parse().unwrap());
            let proxy = reqwest::Proxy::http(format!("http://{}", gw_addr))
                .anyerr()?
                .headers(proxy_headers);
            reqwest::Client::builder().proxy(proxy).build().anyerr()?
        };
        let res = client
            .get(format!("http://{}", upstream_tcp_addr))
            .send()
            .await
            .anyerr()?;
        assert_eq!(res.status(), StatusCode::OK);
        let text = res.text().await.anyerr()?;
        assert_eq!(text, "Hello, world!");

        upstream_router.shutdown().await.anyerr()?;
        gw_task.abort();
        upstream_task.abort();

        Ok(())
    }

    mod hyper {
        use std::convert::Infallible;

        use http_body_util::Full;
        use hyper::body::Bytes;
        use hyper::server::conn::http1;
        use hyper::service::service_fn;
        use hyper::{Request, Response};
        use hyper_util::rt::TokioIo;
        use tokio::net::TcpListener;

        async fn hello(
            _req: Request<hyper::body::Incoming>,
        ) -> Result<Response<Full<Bytes>>, Infallible> {
            Ok(Response::new(Full::new(Bytes::from("Hello, world!"))))
        }

        pub(super) async fn run(
            listener: TcpListener,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            // We start a loop to continuously accept incoming connections
            loop {
                let (stream, _) = listener.accept().await?;

                // Use an adapter to access something implementing `tokio::io` traits as if they implement
                // `hyper::rt` IO traits.
                let io = TokioIo::new(stream);

                // Spawn a tokio task to serve multiple connections concurrently
                tokio::task::spawn(async move {
                    // Finally, we bind the incoming connection to our `hello` service
                    if let Err(err) = http1::Builder::new()
                        // `service_fn` converts our function in a `Service`
                        .serve_connection(io, service_fn(hello))
                        .await
                    {
                        eprintln!("Error serving connection: {:?}", err);
                    }
                });
            }
        }
    }
}
