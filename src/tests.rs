use std::{collections::HashMap, net::SocketAddr, str::FromStr};

use http::StatusCode;
use iroh::{Endpoint, EndpointId, protocol::Router};
use n0_error::{Result, StdResultExt};
use n0_future::task::AbortOnDropHandle;
use n0_tracing_test::traced_test;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

use crate::{
    ALPN, Authority, HttpOriginRequest, HttpProxyRequest, HttpProxyRequestKind, HttpResponse,
    IROH_DESTINATION_HEADER,
    downstream::{
        DownstreamProxy, EndpointAuthority, ExtractError, ForwardProxyMode, ForwardProxyResolver,
        HttpProxyOpts, ProxyMode, ReverseProxyMode, ReverseProxyResolver,
    },
    upstream::{AcceptAll, AuthError, AuthHandler, UpstreamProxy},
};

// -- Test helpers --

/// Spawns an upstream iroh proxy that accepts all requests.
async fn spawn_upstream_proxy() -> Result<(Router, EndpointId)> {
    let router = Router::builder(Endpoint::bind().await?)
        .accept(ALPN, UpstreamProxy::new(AcceptAll)?)
        .spawn();
    router.endpoint().online().await;
    let id = router.endpoint().id();
    Ok((router, id))
}

/// Spawns a downstream proxy with given mode and returns (addr, endpoint_id, task).
async fn spawn_downstream_proxy(
    mode: ProxyMode,
) -> Result<(SocketAddr, EndpointId, AbortOnDropHandle<Result>)> {
    let endpoint = Endpoint::bind().await?;
    let endpoint_id = endpoint.id();
    let proxy = DownstreamProxy::new(endpoint, Default::default());
    let listener = TcpListener::bind("localhost:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move { proxy.forward_tcp_listener(listener, mode).await });
    Ok((addr, endpoint_id, AbortOnDropHandle::new(task)))
}

/// Spawns a simple HTTP origin server that echoes back "{label} {method} {path}".
async fn spawn_origin_server(label: &'static str) -> Result<(SocketAddr, AbortOnDropHandle<()>)> {
    let listener = TcpListener::bind("localhost:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move { origin_server::run(listener, label).await });
    Ok((addr, AbortOnDropHandle::new(task)))
}

/// Spawns a simple TCP echo server.
async fn spawn_echo_server() -> Result<(SocketAddr, AbortOnDropHandle<()>)> {
    let listener = TcpListener::bind("localhost:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    Ok((addr, AbortOnDropHandle::new(task)))
}

/// Reads HTTP response and returns (status_code, body).
async fn read_http_response(stream: &mut TcpStream) -> Result<(u16, String)> {
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    println!("RESPONSE {:#}", String::from_utf8_lossy(&buf));

    let (header_len, response) = HttpResponse::parse_with_len(&buf)?
        .ok_or_else(|| n0_error::anyerr!("Incomplete HTTP response"))?;

    let body = String::from_utf8_lossy(&buf[header_len..]).to_string();
    Ok((response.status.as_u16(), body))
}

// -- Test resolvers --

/// Extracts the endpoint id from Iroh-Destination header.
struct HeaderResolver;

impl ForwardProxyResolver for HeaderResolver {
    async fn destination(&self, req: &HttpProxyRequest) -> Result<EndpointId, ExtractError> {
        let header = req
            .headers
            .get(IROH_DESTINATION_HEADER)
            .ok_or(ExtractError::BadRequest)?;
        let header_str = header.to_str().map_err(|_| ExtractError::BadRequest)?;
        EndpointId::from_str(header_str).map_err(|_| ExtractError::BadRequest)
    }
}

/// Routes based on subdomain in Host header.
struct SubdomainRouter {
    routes: HashMap<String, EndpointAuthority>,
}

impl ReverseProxyResolver for SubdomainRouter {
    async fn destination(
        &self,
        req: &HttpOriginRequest,
    ) -> Result<EndpointAuthority, ExtractError> {
        let host = req.host().ok_or(ExtractError::BadRequest)?;
        let subdomain = host.split('.').next().ok_or(ExtractError::BadRequest)?;
        println!("host {host} subdomain {subdomain} routes {:?}", self.routes);
        self.routes
            .get(subdomain)
            .cloned()
            .ok_or(ExtractError::NotFound)
    }
}

/// Auth handler that allows only specific endpoint IDs.
struct AllowEndpoints(Vec<EndpointId>);

impl AuthHandler for AllowEndpoints {
    async fn authorize(
        &self,
        remote_id: EndpointId,
        _req: &HttpProxyRequest,
    ) -> Result<(), AuthError> {
        if self.0.contains(&remote_id) {
            Ok(())
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

/// Auth handler that allows only specific target authorities.
struct AllowAuthorities(Vec<String>);

impl AuthHandler for AllowAuthorities {
    async fn authorize(
        &self,
        _remote_id: EndpointId,
        req: &HttpProxyRequest,
    ) -> Result<(), AuthError> {
        let target = match &req.kind {
            HttpProxyRequestKind::Tunnel { target } => target.to_string(),
            HttpProxyRequestKind::Absolute { target, .. } => {
                Authority::from_absolute_uri_str(target)
                    .map(|a| a.to_string())
                    .unwrap_or_default()
            }
        };
        if self.0.contains(&target) {
            Ok(())
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

/// Spawns an upstream iroh proxy with a custom auth handler.
async fn spawn_upstream_proxy_with_auth(
    auth: impl AuthHandler + 'static,
) -> Result<(Router, EndpointId)> {
    let router = Router::builder(Endpoint::bind().await?)
        .accept(ALPN, UpstreamProxy::new(auth)?)
        .spawn();
    router.endpoint().online().await;
    let id = router.endpoint().id();
    Ok((router, id))
}

// -- Tests --

/// TCP mode: downstream proxy tunnels raw TCP to a fixed upstream destination.
#[tokio::test]
#[traced_test]
async fn test_tcp_mode() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (echo_addr, _echo_task) = spawn_echo_server().await?;

    let destination = EndpointAuthority::new(
        upstream_id,
        Authority::from_authority_str(&echo_addr.to_string())?,
    );
    let mode = ProxyMode::Tcp(destination);
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    // Connect and send data through the tunnel
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(b"hello tcp").await?;
    stream.shutdown().await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    assert_eq!(buf, b"hello tcp");

    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// HTTP forward proxy with absolute-form requests (e.g. GET http://host/path).
#[tokio::test]
#[traced_test]
async fn test_http_forward_absolute_form() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (origin_addr, _origin_task) = spawn_origin_server("origin").await?;

    let mode =
        ProxyMode::Http(HttpProxyOpts::default().forward(ForwardProxyMode::Static(upstream_id)));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    // Use reqwest with proxy - it uses absolute-form for HTTP
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).anyerr()?)
        .build()
        .anyerr()?;
    let res = client
        .get(format!("http://{origin_addr}/test/path"))
        .send()
        .await
        .anyerr()?;
    assert_eq!(res.status(), StatusCode::OK);
    let text = res.text().await.anyerr()?;
    assert_eq!(text, "origin GET /test/path");

    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// HTTP forward proxy with CONNECT method for tunneling.
#[tokio::test]
#[traced_test]
async fn test_http_forward_connect() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (origin_addr, origin_task) = spawn_origin_server("origin").await?;

    let mode =
        ProxyMode::Http(HttpProxyOpts::default().forward(ForwardProxyMode::Static(upstream_id)));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    // Manually send CONNECT request (reqwest only uses CONNECT for HTTPS)
    let mut stream = TcpStream::connect(proxy_addr).await?;
    let connect_req = format!("CONNECT {origin_addr} HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
    stream.write_all(connect_req.as_bytes()).await?;

    // Read the 200 Connection established response
    let mut reader = BufReader::new(&mut stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await?;
    assert!(
        response_line.starts_with("HTTP/1.1 200"),
        "Expected 200 response, got: {response_line}"
    );
    // Skip remaining headers until empty line
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" {
            break;
        }
    }

    // Now send HTTP request through the tunnel
    let stream = reader.into_inner();
    stream
        .write_all(b"GET /tunnel/test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    assert!(response.contains("200 OK"), "Response: {response}");
    assert!(
        response.contains("origin GET /tunnel/test"),
        "Response: {response}"
    );

    upstream_router.shutdown().await.anyerr()?;
    proxy_task.abort();
    origin_task.abort();
    Ok(())
}

/// HTTP reverse proxy with origin-form requests (e.g. GET /path).
#[tokio::test]
#[traced_test]
async fn test_http_reverse() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (origin_addr, origin_task) = spawn_origin_server("origin").await?;

    let destination = EndpointAuthority::new(
        upstream_id,
        Authority::from_authority_str(&origin_addr.to_string())?,
    );
    let mode =
        ProxyMode::Http(HttpProxyOpts::default().reverse(ReverseProxyMode::Static(destination)));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    // Send origin-form request directly (no proxy configuration in client)
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream
        .write_all(b"GET /reverse/path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    assert!(response.contains("200 OK"), "Response: {response}");
    assert!(
        response.contains("origin GET /reverse/path"),
        "Response: {response}"
    );

    upstream_router.shutdown().await.anyerr()?;
    proxy_task.abort();
    origin_task.abort();
    Ok(())
}

/// HTTP forward proxy with dynamic routing via Iroh-Destination header.
#[tokio::test]
#[traced_test]
async fn test_http_forward_dynamic() -> Result {
    // Two upstreams with differently labeled origins
    let (upstream1_router, upstream1_id) = spawn_upstream_proxy().await?;
    let (origin1_addr, origin1_task) = spawn_origin_server("alpha").await?;

    let (upstream2_router, upstream2_id) = spawn_upstream_proxy().await?;
    let (origin2_addr, origin2_task) = spawn_origin_server("beta").await?;

    let mode = ProxyMode::Http(HttpProxyOpts::default().forward(HeaderResolver));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    // Request routed to upstream1 -> origin1 (alpha)
    let mut stream1 = TcpStream::connect(proxy_addr).await?;
    let req1 = format!(
        "GET http://{origin1_addr}/path1 HTTP/1.1\r\n\
             Host: {origin1_addr}\r\n\
             {IROH_DESTINATION_HEADER}: {upstream1_id}\r\n\
             Connection: close\r\n\r\n"
    );
    stream1.write_all(req1.as_bytes()).await?;
    let (status1, body1) = read_http_response(&mut stream1).await?;
    assert_eq!(status1, 200);
    assert_eq!(body1, "alpha GET /path1");

    // Request routed to upstream2 -> origin2 (beta)
    let mut stream2 = TcpStream::connect(proxy_addr).await?;
    let req2 = format!(
        "GET http://{origin2_addr}/path2 HTTP/1.1\r\n\
             Host: {origin2_addr}\r\n\
             {IROH_DESTINATION_HEADER}: {upstream2_id}\r\n\
             Connection: close\r\n\r\n"
    );
    stream2.write_all(req2.as_bytes()).await?;
    let (status2, body2) = read_http_response(&mut stream2).await?;
    assert_eq!(status2, 200);
    assert_eq!(body2, "beta GET /path2");

    upstream1_router.shutdown().await.anyerr()?;
    upstream2_router.shutdown().await.anyerr()?;
    proxy_task.abort();
    origin1_task.abort();
    origin2_task.abort();
    Ok(())
}

/// HTTP forward proxy fails with 400 when Iroh-Destination header is missing.
#[tokio::test]
#[traced_test]
async fn test_http_forward_dynamic_missing_header() -> Result {
    let mode = ProxyMode::Http(HttpProxyOpts::default().forward(HeaderResolver));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    // Send request without Iroh-Destination header
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream
        .write_all(b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;

    let (status, _body) = read_http_response(&mut stream).await?;
    assert_eq!(status, 400);

    Ok(())
}

/// HTTP reverse proxy with dynamic subdomain-based routing.
#[tokio::test]
#[traced_test]
async fn test_http_reverse_dynamic() -> Result {
    // Two separate upstream proxies with labeled origin servers
    let (upstream1_router, upstream1_id) = spawn_upstream_proxy().await?;
    let (origin1_addr, origin1_task) = spawn_origin_server("server1").await?;

    let (upstream2_router, upstream2_id) = spawn_upstream_proxy().await?;
    let (origin2_addr, origin2_task) = spawn_origin_server("server2").await?;

    let mut routes = HashMap::new();
    routes.insert(
        "proxy1".to_string(),
        EndpointAuthority::new(
            upstream1_id,
            Authority::from_authority_str(&origin1_addr.to_string())?,
        ),
    );
    routes.insert(
        "proxy2".to_string(),
        EndpointAuthority::new(
            upstream2_id,
            Authority::from_authority_str(&origin2_addr.to_string())?,
        ),
    );

    let mode = ProxyMode::Http(HttpProxyOpts::default().reverse(SubdomainRouter { routes }));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    // Request to proxy1.example.com -> should hit server1
    let mut stream1 = TcpStream::connect(proxy_addr).await?;
    stream1
        .write_all(b"GET /path HTTP/1.1\r\nHost: proxy1.example.com\r\nConnection: close\r\n\r\n")
        .await?;
    let (status1, body1) = read_http_response(&mut stream1).await?;
    assert_eq!(status1, 200);
    assert_eq!(body1, "server1 GET /path");

    // Request to proxy2.example.com -> should hit server2
    let mut stream2 = TcpStream::connect(proxy_addr).await?;
    stream2
        .write_all(b"GET /path HTTP/1.1\r\nHost: proxy2.example.com\r\nConnection: close\r\n\r\n")
        .await?;
    let (status2, body2) = read_http_response(&mut stream2).await?;
    assert_eq!(status2, 200);
    assert_eq!(body2, "server2 GET /path");

    upstream1_router.shutdown().await.anyerr()?;
    upstream2_router.shutdown().await.anyerr()?;
    proxy_task.abort();
    origin1_task.abort();
    origin2_task.abort();
    Ok(())
}

/// HTTP reverse proxy fails with 404 for unknown subdomain.
#[tokio::test]
#[traced_test]
async fn test_http_reverse_dynamic_unknown_subdomain() -> Result {
    let routes = HashMap::new(); // Empty routes
    let mode = ProxyMode::Http(HttpProxyOpts::default().reverse(SubdomainRouter { routes }));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    // Request with unknown subdomain
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream
        .write_all(b"GET /path HTTP/1.1\r\nHost: unknown.example.com\r\nConnection: close\r\n\r\n")
        .await?;

    let (status, _body) = read_http_response(&mut stream).await?;
    assert_eq!(status, 404);

    proxy_task.abort();
    Ok(())
}

/// Upstream proxy auth by endpoint ID: allows authorized, rejects unauthorized.
#[tokio::test]
#[traced_test]
async fn test_upstream_auth_endpoint() -> Result {
    let (origin_addr, origin_task) = spawn_origin_server("origin").await?;

    // First spawn downstream to get its endpoint ID
    let mode_placeholder = ProxyMode::Http(HttpProxyOpts::default().forward(HeaderResolver));
    let (proxy_addr, downstream_id, proxy_task) = spawn_downstream_proxy(mode_placeholder).await?;

    // Upstream that only allows this specific downstream
    let (upstream_router, upstream_id) =
        spawn_upstream_proxy_with_auth(AllowEndpoints(vec![downstream_id])).await?;

    // Authorized request should succeed
    let mut stream = TcpStream::connect(proxy_addr).await?;
    let req = format!(
        "GET http://{origin_addr}/test HTTP/1.1\r\n\
         Host: {origin_addr}\r\n\
         {IROH_DESTINATION_HEADER}: {upstream_id}\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let (status, body) = read_http_response(&mut stream).await?;
    assert_eq!(status, 200);
    assert_eq!(body, "origin GET /test");

    // Spawn another downstream (different endpoint ID) - should be rejected
    let (proxy_addr2, _, proxy_task2) = spawn_downstream_proxy(ProxyMode::Http(
        HttpProxyOpts::default().forward(ForwardProxyMode::Static(upstream_id)),
    ))
    .await?;

    let mut stream2 = TcpStream::connect(proxy_addr2).await?;
    let req2 = format!(
        "GET http://{origin_addr}/fail HTTP/1.1\r\n\
         Host: {origin_addr}\r\n\
         Connection: close\r\n\r\n"
    );
    stream2.write_all(req2.as_bytes()).await?;

    // Should fail (error status or connection closed)
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        read_http_response(&mut stream2),
    )
    .await;
    match result {
        Ok(Ok((status, _))) => assert!(status >= 400, "Expected error, got {status}"),
        Ok(Err(_)) | Err(_) => {} // Connection error or timeout is expected
    }

    upstream_router.shutdown().await.anyerr()?;
    proxy_task.abort();
    proxy_task2.abort();
    origin_task.abort();
    Ok(())
}

/// Upstream proxy auth by target authority: allows specific origins, rejects others.
#[tokio::test]
#[traced_test]
async fn test_upstream_auth_authority() -> Result {
    // Two origins - one allowed, one not
    let (allowed_addr, allowed_task) = spawn_origin_server("allowed").await?;
    let (denied_addr, denied_task) = spawn_origin_server("denied").await?;

    // Upstream that only allows connections to allowed_addr
    let (upstream_router, upstream_id) =
        spawn_upstream_proxy_with_auth(AllowAuthorities(vec![allowed_addr.to_string()])).await?;

    // Downstream forward proxy using CONNECT
    let mode =
        ProxyMode::Http(HttpProxyOpts::default().forward(ForwardProxyMode::Static(upstream_id)));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    // CONNECT to allowed origin should succeed
    let mut stream1 = TcpStream::connect(proxy_addr).await?;
    let connect1 = format!("CONNECT {allowed_addr} HTTP/1.1\r\nHost: {allowed_addr}\r\n\r\n");
    stream1.write_all(connect1.as_bytes()).await?;

    let mut reader1 = BufReader::new(&mut stream1);
    let mut line1 = String::new();
    reader1.read_line(&mut line1).await?;
    assert!(
        line1.starts_with("HTTP/1.1 200"),
        "Expected 200, got: {line1}"
    );

    // Skip headers, then send request through tunnel
    loop {
        let mut l = String::new();
        reader1.read_line(&mut l).await?;
        if l == "\r\n" {
            break;
        }
    }
    let stream1 = reader1.into_inner();
    stream1
        .write_all(b"GET /check HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await?;
    let mut resp1 = String::new();
    stream1.read_to_string(&mut resp1).await?;
    assert!(resp1.contains("allowed GET /check"), "Response: {resp1}");

    // CONNECT to denied origin should fail
    let mut stream2 = TcpStream::connect(proxy_addr).await?;
    let connect2 = format!("CONNECT {denied_addr} HTTP/1.1\r\nHost: {denied_addr}\r\n\r\n");
    stream2.write_all(connect2.as_bytes()).await?;

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        read_http_response(&mut stream2),
    )
    .await;
    let (status, _) = result.anyerr()??;
    assert!(status == 403, "Expected error for denied, got {status}");

    upstream_router.shutdown().await.anyerr()?;
    proxy_task.abort();
    allowed_task.abort();
    denied_task.abort();
    Ok(())
}

mod origin_server {
    use std::{convert::Infallible, sync::Arc};

    use http_body_util::Full;
    use hyper::{Request, Response, body::Bytes, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    /// Returns "{label} {METHOD} {PATH}" as response body.
    pub(super) async fn run(listener: TcpListener, label: &'static str) {
        let label = Arc::new(label);
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let io = TokioIo::new(stream);
            let label = label.clone();
            tokio::task::spawn(async move {
                let handler = move |req: Request<hyper::body::Incoming>| {
                    let label = label.clone();
                    async move {
                        let body = format!("{} {} {}", *label, req.method(), req.uri().path());
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                    }
                };
                let _ = http1::Builder::new()
                    .serve_connection(io, service_fn(handler))
                    .await;
            });
        }
    }
}
