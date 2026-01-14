use std::{pin::Pin, str::FromStr, sync::Arc};

use iroh::EndpointId;
use n0_error::Result;
use tokio::net::TcpListener;
use tracing::{Instrument, debug, warn, warn_span};

use crate::{
    IROH_DESTINATION_HEADER, TunnelClientPool, parse::HttpRequest, util::send_error_response,
};

#[derive(derive_more::Debug, Clone, Default)]
pub enum ExtractDestination {
    #[default]
    DefaultHeader,
    Header(String),
    #[debug("Custom(Arc<dyn ResolveDestination>)")]
    Custom(Arc<dyn ResolveDestination>),
}

impl<T: ResolveDestination> From<T> for ExtractDestination {
    fn from(value: T) -> Self {
        Self::Custom(Arc::new(value))
    }
}

impl<T: ResolveDestination> From<Arc<T>> for ExtractDestination {
    fn from(value: Arc<T>) -> Self {
        Self::Custom(value)
    }
}

impl From<Arc<dyn ResolveDestination>> for ExtractDestination {
    fn from(value: Arc<dyn ResolveDestination>) -> Self {
        Self::Custom(value)
    }
}

impl ExtractDestination {
    pub async fn extract<'a>(&'a self, req: &'a HttpRequest) -> Option<EndpointId> {
        match self {
            ExtractDestination::DefaultHeader => extract_header(req, IROH_DESTINATION_HEADER),
            ExtractDestination::Header(header_name) => extract_header(req, header_name),
            ExtractDestination::Custom(imp) => imp.resolve_destination(req).await,
        }
    }
}

fn extract_header(req: &HttpRequest, header_name: &str) -> Option<EndpointId> {
    if let Some(value) = req.headers.get(header_name) {
        EndpointId::from_str(value.to_str().ok()?).ok()
    } else {
        None
    }
}

/// Trait to extract an [`EndpointId`] from a [`HttpRequest`].
pub trait ResolveDestination: Send + Sync + 'static {
    /// Extract and potentially resolve the iroh destination from an incoming [`HttpRequest`].
    fn resolve_destination<'a>(
        &'a self,
        req: &'a HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Option<EndpointId>> + Send + 'a>>;
}

/// Runs an accept loop on `listener` and forwards incoming connection.
pub async fn gateway_accept_loop(
    pool: TunnelClientPool,
    listener: TcpListener,
    extract_destination: ExtractDestination,
) -> Result<()> {
    let mut conn_id = 0;
    loop {
        let (mut tcp_stream, peer_addr) = listener.accept().await?;
        conn_id += 1;
        let pool = pool.clone();
        let extract_destination = extract_destination.clone();
        tokio::spawn(
            async move {
                debug!("New connection from {}", peer_addr);
                if let Err(err) = pool
                    .forward_http_connection(&mut tcp_stream, &extract_destination)
                    .await
                {
                    warn!("Connection closed with error: {:#}", err);
                    if let Some(status) = err.should_reply() {
                        send_error_response(&mut tcp_stream, status).await.ok();
                    }
                } else {
                    debug!("Connection closed");
                }
            }
            .instrument(warn_span!("gw-conn", id=%conn_id)),
        );
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
    use iroh::{Endpoint, protocol::Router};
    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;
    use tokio::net::TcpListener;

    use crate::{ALPN, AcceptAll, TunnelClientPool, TunnelListener, gateway::gateway_accept_loop};

    #[tokio::test]
    #[traced_test]
    async fn gw_reqwest_end_to_end() -> Result {
        let gw_ep = Endpoint::bind().await?;
        println!("gateway: {}", gw_ep.id());
        let gw_pool = TunnelClientPool::new(gw_ep, Default::default());
        let gw_listener = TcpListener::bind("localhost:0").await?;
        let gw_addr = gw_listener.local_addr()?;
        let gw_task = tokio::spawn(async move {
            gateway_accept_loop(gw_pool, gw_listener, Default::default()).await
        });

        let proxy_router = Router::builder(Endpoint::bind().await?)
            .accept(ALPN, TunnelListener::new(AcceptAll)?)
            .spawn();
        proxy_router.endpoint().online().await;
        let proxy_id = proxy_router.endpoint().id();
        println!("upstream: {proxy_id}");

        let upstream_tcp_listener = TcpListener::bind("localhost:0").await?;
        let upstream_tcp_addr = upstream_tcp_listener.local_addr()?;
        let upstream_task = tokio::spawn(self::hyper::run(upstream_tcp_listener));

        let client_proxy_headers = HeaderMap::from_iter([(
            HeaderName::from_static("iroh-destination"),
            HeaderValue::from_str(&proxy_id.to_string()).unwrap(),
        )]);
        let client_proxy = reqwest::Proxy::http(format!("http://{}", gw_addr))
            .unwrap()
            .headers(client_proxy_headers);
        let client = reqwest::Client::builder()
            .proxy(client_proxy)
            .build()
            .unwrap();
        let res = client
            .get(format!("http://{}", upstream_tcp_addr))
            .send()
            .await
            .anyerr()?;
        assert_eq!(res.status(), StatusCode::OK);
        let text = res.text().await.anyerr()?;
        assert_eq!(text, "Hello, world!");

        proxy_router.shutdown().await.anyerr()?;
        gw_task.abort();
        upstream_task.abort();
        Ok(())
    }

    mod hyper {
        use std::convert::Infallible;

        use http_body_util::Full;
        use hyper::{Request, Response, body::Bytes, server::conn::http1, service::service_fn};
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
            loop {
                let (stream, _) = listener.accept().await?;
                let io = TokioIo::new(stream);
                tokio::task::spawn(async move {
                    if let Err(err) = http1::Builder::new()
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
