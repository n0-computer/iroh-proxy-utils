pub mod downstream;
mod parse;
pub mod upstream;
mod util;

pub use parse::{
    Authority, HttpProxyRequest, HttpProxyRequestKind, HttpRequest, HttpRequestKind, HttpResponse,
};

/// How much data to read for the CONNECT handshake before it's considered invalid.
pub(crate) const HEADER_SECTION_MAX_LENGTH: usize = 8192;

/// HTTP header for iroh addressing info
pub const IROH_DESTINATION_HEADER: &str = "Iroh-Destination";
/// The ALPN that we're using for iroh connections
pub const ALPN: &[u8] = b"iroh-http-proxy";

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use iroh::{Endpoint, protocol::Router};
    use n0_error::{Result, StdResultExt};
    use n0_tracing_test::traced_test;
    use tokio::net::TcpListener;

    use crate::{
        ALPN,
        downstream::{DownstreamProxy, ForwardProxyMode, ProxyOpts},
        upstream::{AcceptAll, UpstreamProxy},
    };

    #[tokio::test]
    #[traced_test]
    async fn gw_reqwest_end_to_end() -> Result {
        let gw_ep = Endpoint::bind().await?;
        println!("gateway: {}", gw_ep.id());
        let gw_proxy = DownstreamProxy::new(gw_ep, Default::default());
        let gw_listener = TcpListener::bind("localhost:0").await?;
        let gw_addr = gw_listener.local_addr()?;

        let proxy_router = Router::builder(Endpoint::bind().await?)
            .accept(ALPN, UpstreamProxy::new(AcceptAll)?)
            .spawn();
        proxy_router.endpoint().online().await;
        let proxy_id = proxy_router.endpoint().id();
        println!("upstream: {proxy_id}");

        let gw_mode = ProxyOpts::forward_only(ForwardProxyMode::Static(proxy_id));
        let gw_task =
            tokio::spawn(async move { gw_proxy.forward_tcp_listener(gw_listener, gw_mode).await });

        let upstream_tcp_listener = TcpListener::bind("localhost:0").await?;
        let upstream_tcp_addr = upstream_tcp_listener.local_addr()?;
        let upstream_task = tokio::spawn(self::hyper::run(upstream_tcp_listener));

        let client_proxy = reqwest::Proxy::http(format!("http://{}", gw_addr)).unwrap();
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
