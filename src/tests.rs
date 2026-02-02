use std::{collections::HashMap, net::SocketAddr, str::FromStr, sync::OnceLock, time::Duration};

use http::StatusCode;
use iroh::{
    Endpoint, EndpointId, discovery::static_provider::StaticProvider, endpoint::BindError,
    protocol::Router,
};
use n0_error::{AnyError, Result, StdResultExt, stack_error};
use n0_future::task::AbortOnDropHandle;
use n0_tracing_test::traced_test;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::time::FutureExt;
use tracing::debug;

use crate::{
    ALPN, Authority, HttpProxyRequest, HttpProxyRequestKind, HttpRequest, HttpResponse,
    IROH_DESTINATION_HEADER,
    downstream::{
        Deny, DownstreamProxy, EndpointAuthority, HttpProxyOpts, ProxyMode, RequestHandler,
        opts::{RequestHandlerChain, StaticForwardProxy, StaticReverseProxy},
    },
    upstream::{AcceptAll, AuthError, AuthHandler, UpstreamProxy},
    util::Prebuffered,
};

// -- Test helpers --

async fn bind_endpoint() -> Result<Endpoint, BindError> {
    static STATIC_DISCOVERY: OnceLock<StaticProvider> = OnceLock::new();
    let discovery = STATIC_DISCOVERY.get_or_init(StaticProvider::default);
    let endpoint = Endpoint::empty_builder(iroh::RelayMode::Disabled)
        .discovery(discovery.clone())
        .bind()
        .await?;
    discovery.add_endpoint_info(endpoint.addr());
    Ok(endpoint)
}

/// Spawns an upstream iroh proxy that accepts all requests.
async fn spawn_upstream_proxy() -> Result<(Router, EndpointId)> {
    spawn_upstream_proxy_with_auth(AcceptAll).await
}

/// Spawns an upstream iroh proxy with a custom auth handler.
async fn spawn_upstream_proxy_with_auth(
    auth: impl AuthHandler + 'static,
) -> Result<(Router, EndpointId)> {
    let endpoint = bind_endpoint().await?;
    let router = Router::builder(endpoint)
        .accept(ALPN, UpstreamProxy::new(auth)?)
        .spawn();
    let endpoint_id = router.endpoint().id();
    debug!(endpoint_id=%endpoint_id.fmt_short(), "spawned upstream proxy");
    Ok((router, endpoint_id))
}

/// Spawns a downstream proxy with given mode and returns (addr, endpoint_id, task).
async fn spawn_downstream_proxy(
    mode: ProxyMode,
) -> Result<(SocketAddr, EndpointId, AbortOnDropHandle<Result>)> {
    let endpoint = bind_endpoint().await?;
    let endpoint_id = endpoint.id();
    let proxy = DownstreamProxy::new(endpoint, Default::default());
    let listener = TcpListener::bind("localhost:0").await?;
    let tcp_addr = listener.local_addr()?;
    debug!(endpoint_id=%endpoint_id.fmt_short(), %tcp_addr, "spawned downstream proxy");
    let task = tokio::spawn(async move { proxy.forward_tcp_listener(listener, mode).await });
    Ok((tcp_addr, endpoint_id, AbortOnDropHandle::new(task)))
}

/// Spawns a simple HTTP origin server that echoes back "{label} {method} {path}".
async fn spawn_origin_server(label: &'static str) -> Result<(SocketAddr, AbortOnDropHandle<()>)> {
    let listener = TcpListener::bind("localhost:0").await?;
    let tcp_addr = listener.local_addr()?;
    debug!(%label, %tcp_addr, "spawned origin server");
    let task = tokio::spawn(async move { origin_server::run(listener, label).await });
    Ok((tcp_addr, AbortOnDropHandle::new(task)))
}

/// Spawns a simple HTTP origin server that echoes back "{label} {method} {path}: {body}".
async fn spawn_origin_server_echo_body(
    label: &'static str,
) -> Result<(SocketAddr, AbortOnDropHandle<()>)> {
    let listener = TcpListener::bind("localhost:0").await?;
    let tcp_addr = listener.local_addr()?;
    debug!(%label, %tcp_addr, "spawned origin server");
    let task = tokio::spawn(async move { origin_server::run_echo_body(listener, label).await });
    Ok((tcp_addr, AbortOnDropHandle::new(task)))
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

#[stack_error(derive, from_sources)]
enum ConnectError {
    Io(#[error(source)] std::io::Error),
    ReadResponse(#[error(source)] AnyError),
    Status(StatusCode),
}

async fn create_http_connect_tunnel(
    proxy_addr: SocketAddr,
    origin_addr: impl std::fmt::Display,
    destination_header: Option<EndpointId>,
) -> Result<tokio::io::Join<impl AsyncRead + Unpin, impl AsyncWrite + Unpin>, ConnectError> {
    let stream = TcpStream::connect(proxy_addr).await?;
    let (recv, mut send) = stream.into_split();
    let request = {
        let mut request = format!("CONNECT {origin_addr} HTTP/1.1\r\nHost: {origin_addr}\r\n");
        if let Some(destination) = destination_header {
            request.push_str(&format!("{IROH_DESTINATION_HEADER}: {destination}\r\n"));
        }
        request.push_str("\r\n");
        request
    };
    send.write_all(request.as_bytes()).await?;
    let mut recv = Prebuffered::new(recv, 8192);
    let proxy_response = HttpResponse::read(&mut recv).await?;
    if proxy_response.status != StatusCode::OK {
        Err(ConnectError::Status(proxy_response.status))
    } else {
        Ok(tokio::io::join(recv, send))
    }
}

/// Reads HTTP response and returns (status_code, body).
async fn read_http_response(stream: &mut (impl AsyncRead + Unpin)) -> Result<(u16, Vec<u8>)> {
    let mut prebuf = Prebuffered::new(stream, 8192);
    let response = HttpResponse::read(&mut prebuf)
        .timeout(Duration::from_secs(3))
        .await
        .anyerr()??;
    debug!("RESPONSE {:?}", response);

    // Read body based on Content-Length if present
    let content_length = response
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        prebuf
            .read_exact(&mut body)
            .timeout(Duration::from_secs(3))
            .await
            .anyerr()??;
    }
    Ok((response.status.as_u16(), body))
}

// -- Test resolvers --

/// Extracts the endpoint id from Iroh-Destination header.
struct HeaderResolver;

impl RequestHandler for HeaderResolver {
    async fn handle_request(
        &self,
        src_addr: SocketAddr,
        req: &mut HttpRequest,
    ) -> Result<EndpointId, Deny> {
        let header = req
            .headers
            .get(IROH_DESTINATION_HEADER)
            .ok_or_else(|| Deny::bad_request("missing iroh-destination header"))?;
        let header_str = header
            .to_str()
            .std_context("invalid iroh-destination header")
            .map_err(Deny::bad_request)?;
        let destination = EndpointId::from_str(header_str).map_err(Deny::bad_request);
        req.set_forwarded_for(src_addr);
        destination
    }
}

/// Routes based on subdomain in Host header.
struct SubdomainRouter {
    routes: HashMap<String, EndpointAuthority>,
}

impl RequestHandler for SubdomainRouter {
    async fn handle_request(
        &self,
        _src_addr: SocketAddr,
        req: &mut HttpRequest,
    ) -> Result<EndpointId, Deny> {
        let host = req
            .host()
            .ok_or_else(|| Deny::bad_request("missing host header"))?;
        let subdomain = host
            .split('.')
            .next()
            .ok_or_else(|| Deny::bad_request("invalid host header"))?;
        let destination = self
            .routes
            .get(subdomain)
            .cloned()
            .ok_or_else(|| Deny::new(StatusCode::NOT_FOUND, "unknown subdomain"))?;
        req.set_absolute_http_authority(destination.authority)
            .map_err(|err| Deny::new(StatusCode::INTERNAL_SERVER_ERROR, err))?;
        Ok(destination.endpoint_id)
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
        let allowed = self.0.contains(&target);
        debug!(?allowed, ?target, list=?self.0, "AllowAuthorities::authorize");
        if allowed {
            Ok(())
        } else {
            Err(AuthError::Forbidden)
        }
    }
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

    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticForwardProxy(upstream_id)));
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

    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticForwardProxy(upstream_id)));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    let mut stream = create_http_connect_tunnel(proxy_addr, origin_addr, None).await?;

    // Now send HTTP request through the tunnel
    stream
        .write_all(b"GET /tunnel/test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let (status, body) = read_http_response(&mut stream).await?;
    assert_eq!(status, 200);
    assert_eq!(body, b"origin GET /tunnel/test");
    proxy_task.abort();
    upstream_router.shutdown().await.anyerr()?;
    origin_task.abort();
    Ok(())
}

/// HTTP reverse proxy with origin-form requests (e.g. GET /path).
#[tokio::test]
#[traced_test]
async fn test_http_reverse_simple() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (origin_addr, _origin_task) = spawn_origin_server("origin").await?;

    let destination = EndpointAuthority::new(
        upstream_id,
        Authority::from_authority_str(&origin_addr.to_string())?,
    );
    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticReverseProxy(destination)));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    // Direct request to reverse proxy (no proxy config - sends origin-form)
    let client = reqwest::Client::new();
    let res = client
        .get(format!("http://{proxy_addr}/reverse/path"))
        .send()
        .await
        .anyerr()?;
    assert_eq!(res.status(), StatusCode::OK);
    let text = res.text().await.anyerr()?;
    assert_eq!(text, "origin GET /reverse/path");

    drop(proxy_task);
    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// HTTP forward proxy with dynamic routing via Iroh-Destination header.
#[tokio::test]
#[traced_test]
async fn test_http_forward_absolute_dynamic() -> Result {
    // Two upstreams with differently labeled origins
    let (upstream1_router, upstream1_id) = spawn_upstream_proxy().await?;
    let (origin1_addr, _origin1_task) = spawn_origin_server("alpha").await?;

    let (upstream2_router, upstream2_id) = spawn_upstream_proxy().await?;
    let (origin2_addr, _origin2_task) = spawn_origin_server("beta").await?;

    let mode = ProxyMode::Http(HttpProxyOpts::new(HeaderResolver));
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
    assert_eq!(body1, b"alpha GET /path1");

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
    assert_eq!(body2, b"beta GET /path2");

    drop(proxy_task);
    upstream1_router.shutdown().await.anyerr()?;
    upstream2_router.shutdown().await.anyerr()?;
    Ok(())
}

/// HTTP forward proxy fails with 400 when Iroh-Destination header is missing.
#[tokio::test]
#[traced_test]
async fn test_http_forward_dynamic_missing_header() -> Result {
    let mode = ProxyMode::Http(HttpProxyOpts::new(HeaderResolver));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    // Request without Iroh-Destination header should fail
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).anyerr()?)
        .build()
        .anyerr()?;
    let res = client
        .get("http://example.com/path")
        .send()
        .await
        .anyerr()?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// HTTP reverse proxy with dynamic subdomain-based routing.
/// Note: Uses manual TCP to control Host header precisely (reqwest may override it).
#[tokio::test]
#[traced_test]
async fn test_http_reverse_dynamic() -> Result {
    // Two separate upstream proxies with labeled origin servers
    let (upstream1_router, upstream1_id) = spawn_upstream_proxy().await?;
    let (origin1_addr, _origin1_task) = spawn_origin_server("server1").await?;

    let (upstream2_router, upstream2_id) = spawn_upstream_proxy().await?;
    let (origin2_addr, _origin2_task) = spawn_origin_server("server2").await?;

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

    let mode = ProxyMode::Http(HttpProxyOpts::new(SubdomainRouter { routes }));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    // Request with Host: proxy1.example.com -> should hit server1
    let mut stream1 = TcpStream::connect(proxy_addr).await?;
    stream1
        .write_all(b"GET /path HTTP/1.1\r\nHost: proxy1.example.com\r\nConnection: close\r\n\r\n")
        .await?;
    let (status1, body1) = read_http_response(&mut stream1).await?;
    assert_eq!(status1, 200);
    assert_eq!(body1, b"server1 GET /path");

    // Request with Host: proxy2.example.com -> should hit server2
    let mut stream2 = TcpStream::connect(proxy_addr).await?;
    stream2
        .write_all(b"GET /path HTTP/1.1\r\nHost: proxy2.example.com\r\nConnection: close\r\n\r\n")
        .await?;
    let (status2, body2) = read_http_response(&mut stream2).await?;
    assert_eq!(status2, 200);
    assert_eq!(body2, b"server2 GET /path");

    upstream1_router.shutdown().await.anyerr()?;
    upstream2_router.shutdown().await.anyerr()?;
    Ok(())
}

/// HTTP reverse proxy fails with 404 for unknown subdomain.
#[tokio::test]
#[traced_test]
async fn test_http_reverse_dynamic_unknown_subdomain() -> Result {
    let routes = HashMap::new(); // Empty routes
    let mode = ProxyMode::Http(HttpProxyOpts::new(SubdomainRouter { routes }));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    let client = reqwest::Client::new();
    let res = client
        .get(format!("http://{proxy_addr}/path"))
        .header("Host", "unknown.example.com")
        .send()
        .await
        .anyerr()?;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    Ok(())
}

/// Upstream proxy auth by endpoint ID: allows authorized, rejects unauthorized.
#[tokio::test]
#[traced_test]
async fn test_upstream_auth_endpoint() -> Result {
    let (origin_addr, _origin_task) = spawn_origin_server("origin").await?;

    // First spawn downstream to get its endpoint ID
    let mode_placeholder = ProxyMode::Http(HttpProxyOpts::new(HeaderResolver));
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
    assert_eq!(body, b"origin GET /test");

    // Spawn another downstream (different endpoint ID) - should be rejected
    let (proxy_addr2, _, proxy_task2) = spawn_downstream_proxy(ProxyMode::Http(
        HttpProxyOpts::new(StaticForwardProxy(upstream_id)),
    ))
    .await?;

    let mut stream2 = TcpStream::connect(proxy_addr2).await?;
    let req2 = format!(
        "GET http://{origin_addr}/fail HTTP/1.1\r\n\
         Host: {origin_addr}\r\n\
         {IROH_DESTINATION_HEADER}: {upstream_id}\r\n\
         Connection: close\r\n\r\n"
    );
    stream2.write_all(req2.as_bytes()).await?;

    // Should fail (error status or connection closed)
    let (status, body) = read_http_response(&mut stream2).await?;
    assert_eq!(status, 403);
    println!("BODY {}", String::from_utf8_lossy(&body));
    assert!(body.is_empty());

    drop(proxy_task);
    drop(proxy_task2);
    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// Upstream proxy auth by target authority: allows specific origins, rejects others.
#[tokio::test]
#[traced_test]
async fn test_upstream_auth_authority() -> Result {
    // Two origins - one allowed, one not
    let (allowed_addr, _allowed_task) = spawn_origin_server("allowed").await?;
    let (denied_addr, _denied_task) = spawn_origin_server("denied").await?;

    // Upstream that only allows connections to allowed_addr
    let (upstream_router, upstream_id) =
        spawn_upstream_proxy_with_auth(AllowAuthorities(vec![allowed_addr.to_string()])).await?;

    // Downstream forward proxy using CONNECT
    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticForwardProxy(upstream_id)));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    // CONNECT to allowed origin should succeed
    let mut stream = create_http_connect_tunnel(proxy_addr, allowed_addr, None).await?;
    stream
        .write_all(b"GET /check HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await?;
    let (upstream_status, body) = read_http_response(&mut stream).await?;
    assert_eq!(upstream_status, 200);
    assert_eq!(body, b"allowed GET /check");

    // CONNECT to denied origin should fail
    let mut stream = TcpStream::connect(proxy_addr).await?;
    let connect = format!("CONNECT {denied_addr} HTTP/1.1\r\nHost: {denied_addr}\r\n\r\n");
    stream.write_all(connect.as_bytes()).await?;
    let (status, body) = read_http_response(&mut stream).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.is_empty());

    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

// -- Edge case tests --

/// POST request with body is forwarded correctly through absolute-form proxy.
#[tokio::test]
#[traced_test]
async fn test_http_forward_post_with_body() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (origin_addr, _origin_task) = spawn_origin_server_echo_body("origin").await?;

    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticForwardProxy(upstream_id)));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).anyerr()?)
        .build()
        .anyerr()?;
    let res = client
        .post(format!("http://{origin_addr}/upload"))
        .body("hello request body")
        .send()
        .await
        .anyerr()?;
    assert_eq!(res.status(), StatusCode::OK);
    let text = res.text().await.anyerr()?;
    assert_eq!(text, "origin POST /upload: hello request body");

    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// POST request with body through reverse proxy.
#[tokio::test]
#[traced_test]
async fn test_http_reverse_post_with_body() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (origin_addr, _origin_task) = spawn_origin_server_echo_body("origin").await?;

    let destination = EndpointAuthority::new(
        upstream_id,
        Authority::from_authority_str(&origin_addr.to_string())?,
    );
    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticReverseProxy(destination)));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{proxy_addr}/data"))
        .body("post body content")
        .send()
        .await
        .anyerr()?;
    assert_eq!(res.status(), StatusCode::OK);
    let text = res.text().await.anyerr()?;
    assert_eq!(text, "origin POST /data: post body content");

    let res = client
        .post(format!("http://{proxy_addr}/data"))
        .body("post body content 2")
        .send()
        .await
        .anyerr()?;
    assert_eq!(res.status(), StatusCode::OK);
    let text = res.text().await.anyerr()?;
    assert_eq!(text, "origin POST /data: post body content 2");

    drop(proxy_task);
    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// Invalid HTTP request returns 400 Bad Request.
#[tokio::test]
#[traced_test]
async fn test_invalid_http_request() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;

    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticForwardProxy(upstream_id)));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    // Send garbage that's not valid HTTP
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream.write_all(b"NOT VALID HTTP\r\n\r\n").await?;

    let (status, _) = read_http_response(&mut stream).await?;
    assert_eq!(status, 400);

    drop(proxy_task);
    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// Origin-form request to forward-only proxy returns 400.
#[tokio::test]
#[traced_test]
async fn test_origin_form_to_forward_only_proxy() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;

    // Only forward mode configured (no reverse)
    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticForwardProxy(upstream_id)));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    // Send origin-form request (no scheme) - this is what a reverse proxy would handle
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream
        .write_all(b"GET /path HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;

    let (status, _) = read_http_response(&mut stream).await?;
    assert_eq!(status, 400);

    drop(proxy_task);
    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// Forward (absolute-form) request to reverse-only proxy returns 400.
#[tokio::test]
#[traced_test]
async fn test_forward_request_to_reverse_only_proxy() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (origin_addr, _origin_task) = spawn_origin_server("origin").await?;

    let destination = EndpointAuthority::new(
        upstream_id,
        Authority::from_authority_str(&origin_addr.to_string())?,
    );
    // Only reverse mode configured (no forward)
    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticReverseProxy(destination)));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    // Send absolute-form request (with scheme) - this is what a forward proxy would handle
    let mut stream = TcpStream::connect(proxy_addr).await?;
    let req = format!(
        "GET http://{origin_addr}/path HTTP/1.1\r\nHost: {origin_addr}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;

    let (status, _) = read_http_response(&mut stream).await?;
    assert_eq!(status, 400);

    drop(proxy_task);
    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// CONNECT to reverse-only proxy returns 400.
#[tokio::test]
#[traced_test]
async fn test_connect_to_reverse_only_proxy() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (origin_addr, _origin_task) = spawn_origin_server("origin").await?;

    let destination = EndpointAuthority::new(
        upstream_id,
        Authority::from_authority_str(&origin_addr.to_string())?,
    );
    // Only reverse mode configured
    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticReverseProxy(destination)));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    // Send CONNECT request
    let mut stream = TcpStream::connect(proxy_addr).await?;
    let req = "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string();
    stream.write_all(req.as_bytes()).await?;

    let (status, _) = read_http_response(&mut stream).await?;
    assert_eq!(status, 400);

    drop(proxy_task);
    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// CONNECT to unreachable origin returns 502 Bad Gateway.
#[tokio::test]
#[traced_test]
async fn test_connect_unreachable_origin() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;

    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticForwardProxy(upstream_id)));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    // CONNECT to a port that's not listening
    let mut stream = TcpStream::connect(proxy_addr).await?;
    stream
        .write_all(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
        .await?;

    let (status, _) = read_http_response(&mut stream).await?;
    assert_eq!(status, 502);

    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// Multiple concurrent requests through the same proxy.
#[tokio::test]
#[traced_test]
async fn test_concurrent_requests() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (origin_addr, _origin_task) = spawn_origin_server("origin").await?;

    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticForwardProxy(upstream_id)));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).anyerr()?)
        .build()
        .anyerr()?;

    // Spawn multiple concurrent requests
    let mut handles = Vec::new();
    for i in 0..10 {
        let client = client.clone();
        let url = format!("http://{origin_addr}/request/{i}");
        handles.push(tokio::spawn(async move {
            let res = client.get(&url).send().await?;
            let text = res.text().await?;
            Ok::<_, reqwest::Error>(text)
        }));
    }

    // Verify all requests completed successfully
    for (i, handle) in handles.into_iter().enumerate() {
        let text = handle.await.anyerr()?.anyerr()?;
        assert_eq!(text, format!("origin GET /request/{i}"));
    }

    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// Large request body is forwarded correctly.
#[tokio::test]
#[traced_test]
async fn test_large_request_body() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (origin_addr, _origin_task) = spawn_origin_server_echo_body("origin").await?;

    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticForwardProxy(upstream_id)));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).anyerr()?)
        .build()
        .anyerr()?;

    // 1MB body
    let body = "x".repeat(1024 * 1024);
    let res = client
        .post(format!("http://{origin_addr}/large"))
        .body(body.clone())
        .send()
        .await
        .anyerr()?;
    assert_eq!(res.status(), StatusCode::OK);
    let text = res.text().await.anyerr()?;
    assert_eq!(text, format!("origin POST /large: {body}"));

    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// Both forward and reverse modes enabled - routes correctly based on request form.
#[tokio::test]
#[traced_test]
async fn test_forward_and_reverse_combined() -> Result {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (forward_origin_addr, _forward_origin_task) = spawn_origin_server("forward").await?;
    let (reverse_origin_addr, _reverse_origin_task) = spawn_origin_server("reverse").await?;

    let reverse_destination = EndpointAuthority::new(
        upstream_id,
        Authority::from_authority_str(&reverse_origin_addr.to_string())?,
    );
    let handler = RequestHandlerChain::default()
        .push(StaticForwardProxy(upstream_id))
        .push(StaticReverseProxy(reverse_destination));
    let mode = ProxyMode::Http(HttpProxyOpts::new(handler));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(mode).await?;

    // Absolute-form request should go to forward origin
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}")).anyerr()?)
        .build()
        .anyerr()?;
    let res = client
        .get(format!("http://{forward_origin_addr}/forward-path"))
        .send()
        .await
        .anyerr()?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text().await.anyerr()?, "forward GET /forward-path");

    // Origin-form request should go to reverse origin
    let client = reqwest::Client::new();
    let res = client
        .get(format!("http://{proxy_addr}/reverse-path"))
        .send()
        .await
        .anyerr()?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text().await.anyerr()?, "reverse GET /reverse-path");

    drop(proxy_task);
    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// Tests HTTP/2 CONNECT requests over a single connection.
///
/// Note: This test uses absolute-form requests (GET) instead of CONNECT because hyper's
/// HTTP/2 client doesn't support CONNECT with non-empty body directly. The CONNECT method
/// in HTTP/2 requires the extended CONNECT protocol (RFC 8441) for streaming body data.
/// The HTTP/1.1 CONNECT tests (test_http_forward_connect, test_upstream_auth_authority)
/// verify CONNECT functionality.
#[tokio::test]
#[traced_test]
async fn h2_multiple_connect_requests_single_connection() -> Result<()> {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::Request;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (origin_addr, _origin_task) = spawn_origin_server("origin").await?;
    let opts = HttpProxyOpts::new(StaticForwardProxy(upstream_id));
    let (proxy_addr, _, proxy_task) = spawn_downstream_proxy(ProxyMode::Http(opts)).await?;

    let stream = TcpStream::connect(proxy_addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .anyerr()?;
    let conn_task = tokio::spawn(async move { conn.await });

    // Test multiple requests over a single HTTP/2 connection
    let req1 = Request::builder()
        .method(http::Method::GET)
        .uri(format!("http://{}/path1", origin_addr))
        .body(Full::new(Bytes::new()))
        .anyerr()?;
    let res1 = sender.send_request(req1).await.anyerr()?;
    assert_eq!(res1.status(), StatusCode::OK);
    let body1 = res1.into_body().collect().await.anyerr()?.to_bytes();
    assert_eq!(body1.as_ref(), b"origin GET /path1");

    let req2 = Request::builder()
        .method(http::Method::GET)
        .uri(format!("http://{}/path2", origin_addr))
        .body(Full::new(Bytes::new()))
        .anyerr()?;
    let res2 = sender.send_request(req2).await.anyerr()?;
    assert_eq!(res2.status(), StatusCode::OK);
    let body2 = res2.into_body().collect().await.anyerr()?.to_bytes();
    assert_eq!(body2.as_ref(), b"origin GET /path2");

    drop(proxy_task);
    conn_task.abort();
    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// HTTP/2 reverse proxy using reqwest with h2 prior knowledge.
#[tokio::test]
#[traced_test]
async fn h2_reqwest_reverse() -> Result<()> {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (origin_addr, _origin_task) = spawn_origin_server("origin").await?;

    let destination = EndpointAuthority::new(
        upstream_id,
        Authority::from_authority_str(&origin_addr.to_string())?,
    );
    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticReverseProxy(destination)));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .anyerr()?;
    let res = client
        .get(format!("http://{proxy_addr}/reverse/path"))
        .send()
        .await
        .anyerr()?;
    assert_eq!(res.status(), StatusCode::OK);
    let text = res.text().await.anyerr()?;
    assert_eq!(text, "origin GET /reverse/path");

    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// HTTP/2 forward proxy (absolute-form) using reqwest with h2 prior knowledge.
#[tokio::test]
#[traced_test]
async fn h2_reqwest_forward() -> Result<()> {
    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let (origin_addr, _origin_task) = spawn_origin_server("origin").await?;

    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticForwardProxy(upstream_id)));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
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

// -- Bug exposure tests --

/// BUG: Hop-by-hop headers are forwarded to upstream when they shouldn't be.
/// Per RFC 9110 Section 7.6.1, headers like Connection, Proxy-Authorization,
/// Transfer-Encoding should NOT be forwarded.
#[tokio::test]
#[traced_test]
async fn test_hop_by_hop_headers_not_forwarded() -> Result {
    // Spawn an origin server that echoes back all received headers
    let listener = TcpListener::bind("localhost:0").await?;
    let origin_addr = listener.local_addr()?;
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let request = String::from_utf8_lossy(&buf[..n]);

        // Echo back the received headers in the response body
        let body = request.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    let _origin_task = AbortOnDropHandle::new(origin_task);

    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticForwardProxy(upstream_id)));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    // Send request with hop-by-hop headers that should NOT be forwarded
    let mut stream = TcpStream::connect(proxy_addr).await?;
    let req = format!(
        "GET http://{origin_addr}/test HTTP/1.1\r\n\
         Host: {origin_addr}\r\n\
         Connection: keep-alive\r\n\
         Proxy-Authorization: Basic secret\r\n\
         Keep-Alive: timeout=5\r\n\
         \r\n"
    );
    stream.write_all(req.as_bytes()).await?;

    let (status, body) = read_http_response(&mut stream).await?;
    assert_eq!(status, 200);

    let body_str = String::from_utf8_lossy(&body);
    debug!("Origin received: {}", body_str);

    // These hop-by-hop headers should NOT appear in what origin received
    assert!(
        !body_str.to_lowercase().contains("proxy-authorization"),
        "Proxy-Authorization header was forwarded but shouldn't be"
    );
    assert!(
        !body_str.to_lowercase().contains("keep-alive:"),
        "Keep-Alive header was forwarded but shouldn't be"
    );

    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

/// BUG: Response hop-by-hop headers from origin are forwarded to client.
/// The proxy should filter these out in responses as well.
#[tokio::test]
#[traced_test]
async fn test_response_hop_by_hop_headers_filtered() -> Result {
    // Spawn an origin that returns hop-by-hop headers in response
    let listener = TcpListener::bind("localhost:0").await?;
    let origin_addr = listener.local_addr()?;
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _n = stream.read(&mut buf).await.unwrap();

        // Response with hop-by-hop headers that shouldn't be forwarded
        let response = "HTTP/1.1 200 OK\r\n\
            Content-Length: 2\r\n\
            Connection: keep-alive\r\n\
            Keep-Alive: timeout=5\r\n\
            Proxy-Authenticate: Basic\r\n\
            \r\nOK";
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    let _origin_task = AbortOnDropHandle::new(origin_task);

    let (upstream_router, upstream_id) = spawn_upstream_proxy().await?;
    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticForwardProxy(upstream_id)));
    let (proxy_addr, _, _proxy_task) = spawn_downstream_proxy(mode).await?;

    let mut stream = TcpStream::connect(proxy_addr).await?;
    let req = format!(
        "GET http://{origin_addr}/test HTTP/1.1\r\n\
         Host: {origin_addr}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream.write_all(req.as_bytes()).await?;

    // Read raw response to check headers
    let mut response_buf = vec![0u8; 4096];
    let n = stream.read(&mut response_buf).await?;
    let response_str = String::from_utf8_lossy(&response_buf[..n]);
    debug!("Client received response: {}", response_str);

    // These hop-by-hop headers should NOT be forwarded to client
    let response_lower = response_str.to_lowercase();
    assert!(
        !response_lower.contains("proxy-authenticate"),
        "Proxy-Authenticate response header was forwarded but shouldn't be"
    );
    assert!(
        !response_lower.contains("keep-alive:"),
        "Keep-Alive response header was forwarded but shouldn't be"
    );

    upstream_router.shutdown().await.anyerr()?;
    Ok(())
}

mod origin_server {
    use std::{convert::Infallible, sync::Arc};

    use http::HeaderValue;
    use http_body_util::{BodyExt, Full};
    use hyper::{Request, Response, body::Bytes, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;
    use tracing::debug;

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
                    debug!("origin {label}: {req:?}");
                    async move {
                        let body = format!("{} {} {}", *label, req.method(), req.uri().path());
                        let len = body.len();
                        let mut res = Response::new(Full::new(Bytes::from(body)));
                        res.headers_mut().insert(
                            http::header::CONTENT_LENGTH,
                            HeaderValue::from_str(&len.to_string()).unwrap(),
                        );

                        Ok::<_, Infallible>(res)
                    }
                };
                let _ = http1::Builder::new()
                    .serve_connection(io, service_fn(handler))
                    .await;
            });
        }
    }

    /// Returns "{label} {METHOD} {PATH}: {BODY}" as response body.
    pub(super) async fn run_echo_body(listener: TcpListener, label: &'static str) {
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
                        let method = req.method().clone();
                        let path = req.uri().path().to_string();
                        let body_bytes = req.collect().await.unwrap().to_bytes();
                        let body_str = String::from_utf8_lossy(&body_bytes);
                        let response = format!("{} {} {}: {}", *label, method, path, body_str);
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(response))))
                    }
                };
                let _ = http1::Builder::new()
                    .serve_connection(io, service_fn(handler))
                    .await;
            });
        }
    }
}
