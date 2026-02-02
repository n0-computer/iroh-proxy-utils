use std::{
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use clap::Parser;
use iroh::{Endpoint, EndpointId, protocol::Router};
use iroh_proxy_utils::{
    ALPN, Authority, HttpRequest, IROH_DESTINATION_HEADER,
    downstream::{
        Deny, DownstreamProxy, EndpointAuthority, HttpProxyOpts, ProxyMode, RequestHandler,
        StaticForwardProxy, StaticReverseProxy,
    },
    upstream::{AcceptAll, UpstreamProxy},
};
use n0_error::{Result, StdResultExt};
use tokio::net::TcpListener;
use tracing::{Instrument, debug, error_span, info, info_span, warn};

#[derive(Parser, Clone)]
struct BenchOpts {
    /// Number of concurrent requests.
    #[clap(short = 'c', long, default_value_t = 1)]
    concurrency: usize,
    /// Total number of requests per mode.
    #[clap(short = 'n', default_value_t = 100)]
    n: usize,
    /// Use HTTP/2 (requires server support).
    #[clap(long)]
    http2: bool,
    /// Disable keep-alive (HTTP/1.1 only).
    #[clap(long)]
    no_keep_alive: bool,
}

#[derive(Parser)]
enum Cli {
    /// Spawn a local HTTP origin server.
    Origin {
        #[clap(short, long, default_value_t = 0)]
        port: u16,
    },
    /// Spawn an upstream iroh proxy.
    Upstream,
    /// Spawn a reverse proxy that forwards to an origin via an upstream proxy.
    ReverseProxy {
        #[clap(short, long, default_value_t = 0)]
        port: u16,
        /// EndpointId of the upstream proxy.
        upstream: EndpointId,
        /// Origin address (e.g. "127.0.0.1:3000").
        origin: String,
    },
    /// Spawn a forward proxy that routes via the Iroh-Destination header.
    ForwardProxy {
        #[clap(short, long, default_value_t = 0)]
        port: u16,
    },
    /// Spawn all bench servers (origin, upstream, forward proxy, reverse proxy).
    BenchServer {
        #[clap(long, default_value_t = 0)]
        origin_port: u16,
        #[clap(long, default_value_t = 0)]
        forward_port: u16,
        #[clap(long, default_value_t = 0)]
        reverse_port: u16,
    },
    /// Run benchmarks against existing servers.
    BenchClient {
        #[clap(long)]
        origin_host: String,
        #[clap(long)]
        forward_host: String,
        #[clap(long)]
        reverse_host: String,
        #[clap(flatten)]
        opts: BenchOpts,
    },
    /// Spawn servers and run benchmarks in one command.
    Bench {
        #[clap(long, default_value_t = 0)]
        origin_port: u16,
        #[clap(long, default_value_t = 0)]
        forward_port: u16,
        #[clap(long, default_value_t = 0)]
        reverse_port: u16,
        #[clap(flatten)]
        opts: BenchOpts,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli {
        Cli::Origin { port } => cmd_origin(port).await,
        Cli::Upstream => cmd_upstream().await,
        Cli::ReverseProxy {
            port,
            upstream,
            origin,
        } => cmd_reverse_proxy(port, upstream, origin).await,
        Cli::ForwardProxy { port } => cmd_forward_proxy(port).await,
        Cli::BenchServer {
            origin_port,
            forward_port,
            reverse_port,
        } => cmd_bench_server(origin_port, forward_port, reverse_port).await,
        Cli::BenchClient {
            origin_host,
            forward_host,
            reverse_host,
            opts,
        } => cmd_bench_client(origin_host, forward_host, reverse_host, opts).await,
        Cli::Bench {
            origin_port,
            forward_port,
            reverse_port,
            opts,
        } => cmd_bench(origin_port, forward_port, reverse_port, opts).await,
    }
}

// -- Origin --

async fn cmd_origin(port: u16) -> Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    let addr = listener.local_addr()?;
    println!("origin listening on {addr}");
    tokio::select! {
            res = origin_server(listener) => res?,
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}

async fn origin_server(listener: TcpListener) -> Result<()> {
    use std::convert::Infallible;

    use http_body_util::{BodyExt, Full, StreamBody};
    use hyper::{
        Request, Response,
        body::{Bytes, Frame},
        service::service_fn,
    };
    use hyper_util::{
        rt::{TokioExecutor, TokioIo},
        server::conn::auto,
    };

    type BoxBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

    for i in 0.. {
        let (stream, addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        tokio::spawn(
            async move {
                info!("accepted connection from {addr}");
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let path = req.uri().path().to_owned();
                    match path.as_str() {
                        "/hello" => {
                            let body =
                                Full::new(Bytes::from("hello world")).map_err(|e| match e {});
                            Ok::<_, Infallible>(Response::new(BoxBody::new(body)))
                        }
                        "/echo" => {
                            let (tx, rx) =
                                tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
                            let incoming = req.into_body();
                            tokio::spawn(async move {
                                let mut body = incoming;
                                while let Some(Ok(frame)) = body.frame().await {
                                    if tx.send(Ok(frame)).await.is_err() {
                                        break;
                                    }
                                }
                            });
                            let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
                            let body = StreamBody::new(stream);
                            Ok(Response::new(BoxBody::new(body)))
                        }
                        "/download" => {
                            let (tx, rx) =
                                tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
                            tokio::spawn(async move {
                                // 1MB in 1KB chunks
                                let chunk = Bytes::from(vec![b'x'; 1024]);
                                for _ in 0..1024 {
                                    if tx.send(Ok(Frame::data(chunk.clone()))).await.is_err() {
                                        break;
                                    }
                                }
                            });
                            let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
                            let body = StreamBody::new(stream);
                            Ok(Response::new(BoxBody::new(body)))
                        }
                        _ => {
                            let mut res = Response::new(BoxBody::new(
                                Full::new(Bytes::from("not found")).map_err(|e| match e {}),
                            ));
                            *res.status_mut() = http::StatusCode::NOT_FOUND;
                            Ok(res)
                        }
                    }
                });
                if let Err(err) = auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(io, service)
                    .await
                {
                    warn!("handling connection failed: {err:#}");
                }
            }
            .instrument(info_span!("conn", %i)),
        );
    }
    Ok(())
}

// -- Upstream --

async fn cmd_upstream() -> Result<()> {
    let endpoint = Endpoint::builder().bind().await?;
    let endpoint_id = endpoint.id();
    let router = Router::builder(endpoint)
        .accept(ALPN, UpstreamProxy::new(AcceptAll)?)
        .spawn();
    println!("upstream endpoint: {endpoint_id}");
    tokio::signal::ctrl_c().await?;
    router.shutdown().await.anyerr()?;
    Ok(())
}

// -- Reverse proxy --

async fn cmd_reverse_proxy(port: u16, upstream: EndpointId, origin: String) -> Result<()> {
    let endpoint = Endpoint::builder().bind().await?;
    let proxy = DownstreamProxy::new(endpoint, Default::default());
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    let addr = listener.local_addr()?;
    let authority = Authority::from_authority_str(&origin)?;
    let destination = EndpointAuthority::new(upstream, authority);
    let mode = ProxyMode::Http(HttpProxyOpts::new(StaticReverseProxy(destination)));
    println!("reverse proxy listening on {addr}");
    tokio::select! {
        res = proxy.forward_tcp_listener(listener, mode) => res?,
        _ = tokio::signal::ctrl_c() => {}

    }
    Ok(())
}

// -- Forward proxy --

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
        let destination = EndpointId::from_str(header_str).map_err(Deny::bad_request)?;
        req.set_forwarded_for(src_addr);
        Ok(destination)
    }
}

async fn cmd_forward_proxy(port: u16) -> Result<()> {
    let endpoint = Endpoint::builder().bind().await?;
    let proxy = DownstreamProxy::new(endpoint, Default::default());
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    let addr = listener.local_addr()?;
    let mode = ProxyMode::Http(HttpProxyOpts::new(HeaderResolver));
    println!("forward proxy listening on {addr}");
    tokio::select! {
        res = proxy.forward_tcp_listener(listener, mode) => res?,
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}

// -- Bench infrastructure --

struct ServerAddrs {
    origin: SocketAddr,
    forward: SocketAddr,
    reverse: SocketAddr,
}

struct BenchResult {
    total: Duration,
    latencies: Vec<Duration>,
}

async fn spawn_bench_server(
    origin_port: u16,
    forward_port: u16,
    reverse_port: u16,
) -> Result<(ServerAddrs, Router)> {
    // 1. Origin server
    let origin_listener = TcpListener::bind(format!("127.0.0.1:{origin_port}")).await?;
    let origin_addr = origin_listener.local_addr()?;
    tokio::spawn(async move {
        if let Err(e) = origin_server(origin_listener).await {
            eprintln!("origin server error: {e:#}");
        }
    });
    println!("origin listening on {origin_addr}");

    // 2. Upstream proxy (iroh endpoint with AcceptAll)
    let upstream_endpoint = Endpoint::builder().bind().await?;
    let upstream_id = upstream_endpoint.id();
    let router = Router::builder(upstream_endpoint)
        .accept(ALPN, UpstreamProxy::new(AcceptAll)?)
        .spawn();
    router.endpoint().online().await;
    println!("upstream endpoint: {upstream_id}");

    // 3. Forward proxy with ForwardProxyMode::Static
    let forward_endpoint = Endpoint::builder().bind().await?;
    let forward_proxy = DownstreamProxy::new(forward_endpoint.clone(), Default::default());
    let forward_listener = TcpListener::bind(format!("127.0.0.1:{forward_port}")).await?;
    let forward_addr = forward_listener.local_addr()?;
    let forward_mode = ProxyMode::Http(HttpProxyOpts::new(StaticForwardProxy(upstream_id)));
    tokio::spawn(async move {
        if let Err(e) = forward_proxy
            .forward_tcp_listener(forward_listener, forward_mode)
            .await
        {
            eprintln!("forward proxy error: {e:#}");
        }
    });
    println!("forward proxy listening on {forward_addr}");

    // 4. Reverse proxy with ReverseProxyMode::Static
    let reverse_proxy = DownstreamProxy::new(forward_endpoint, Default::default());
    let reverse_listener = TcpListener::bind(format!("127.0.0.1:{reverse_port}")).await?;
    let reverse_addr = reverse_listener.local_addr()?;
    let authority = Authority::from_authority_str(&origin_addr.to_string())?;
    let destination = EndpointAuthority::new(upstream_id, authority);
    let reverse_mode = ProxyMode::Http(HttpProxyOpts::new(StaticReverseProxy(destination)));
    tokio::spawn(async move {
        if let Err(e) = reverse_proxy
            .forward_tcp_listener(reverse_listener, reverse_mode)
            .await
        {
            eprintln!("reverse proxy error: {e:#}");
        }
    });
    println!("reverse proxy listening on {reverse_addr}");

    let addrs = ServerAddrs {
        origin: origin_addr,
        forward: forward_addr,
        reverse: reverse_addr,
    };
    Ok((addrs, router))
}

async fn cmd_bench_server(origin_port: u16, forward_port: u16, reverse_port: u16) -> Result<()> {
    let (addrs, _router) = spawn_bench_server(origin_port, forward_port, reverse_port).await?;
    println!();
    println!("client:");
    println!(
        "cargo run --example cli --release -- bench-client --origin-host {} --forward-host {} --reverse-host {}",
        addrs.origin, addrs.forward, addrs.reverse
    );
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn cmd_bench_client(
    origin_host: String,
    forward_host: String,
    reverse_host: String,
    opts: BenchOpts,
) -> Result<()> {
    let results = run_all_benchmarks(&origin_host, &forward_host, &reverse_host, &opts).await?;
    print_table(&results);
    Ok(())
}

async fn cmd_bench(
    origin_port: u16,
    forward_port: u16,
    reverse_port: u16,
    opts: BenchOpts,
) -> Result<()> {
    let (addrs, _router) = spawn_bench_server(origin_port, forward_port, reverse_port).await?;
    println!();
    println!("client:");
    println!(
        "cargo run --example cli --release -- bench-client --origin-host {} --forward-host {} --reverse-host {}",
        addrs.origin, addrs.forward, addrs.reverse
    );
    println!();

    let origin_host = addrs.origin.to_string();
    let forward_host = addrs.forward.to_string();
    let reverse_host = addrs.reverse.to_string();
    let results = run_all_benchmarks(&origin_host, &forward_host, &reverse_host, &opts).await?;
    print_table(&results);
    Ok(())
}

async fn run_all_benchmarks(
    origin_host: &str,
    forward_host: &str,
    reverse_host: &str,
    opts: &BenchOpts,
) -> Result<Vec<(&'static str, BenchResult)>> {
    let mut results = Vec::new();

    // 1. Direct
    println!(
        "Running: Direct ({} requests, concurrency {})",
        opts.n, opts.concurrency
    );
    let client = build_client(opts, None)?;
    let url = format!("http://{origin_host}/hello");
    let result = run_bench_mode(&client, &url, opts.n, opts.concurrency).await;
    results.push(("Direct", result));

    // 2. Forward proxy
    println!(
        "Running: Forward Proxy ({} requests, concurrency {})",
        opts.n, opts.concurrency
    );
    let proxy_url = format!("http://{forward_host}");
    let client = build_client(opts, Some(&proxy_url))?;
    let url = format!("http://{origin_host}/hello");
    let result = run_bench_mode(&client, &url, opts.n, opts.concurrency).await;
    results.push(("Forward Proxy", result));

    // 3. Reverse proxy
    println!(
        "Running: Reverse Proxy ({} requests, concurrency {})",
        opts.n, opts.concurrency
    );
    let client = build_client(opts, None)?;
    let url = format!("http://{reverse_host}/hello");
    let result = run_bench_mode(&client, &url, opts.n, opts.concurrency).await;
    results.push(("Reverse Proxy", result));

    println!();
    Ok(results)
}

fn build_client(opts: &BenchOpts, proxy: Option<&str>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if let Some(proxy_url) = proxy {
        builder = builder.proxy(reqwest::Proxy::http(proxy_url).anyerr()?);
    }
    if opts.http2 {
        builder = builder.http2_prior_knowledge();
    }
    if opts.no_keep_alive {
        builder = builder.pool_max_idle_per_host(0);
    }
    builder.build().anyerr()
}

async fn run_bench_mode(
    client: &reqwest::Client,
    url: &str,
    n: usize,
    concurrency: usize,
) -> BenchResult {
    // Warmup: 1 request
    let resp = client.get(url).send().await.expect("warmup request failed");
    resp.bytes().await.expect("warmup read failed");

    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut set = tokio::task::JoinSet::new();
    let start = Instant::now();

    for i in 0..n {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let url = url.to_string();
        set.spawn(
            async move {
                debug!("start");
                let req_start = Instant::now();
                let resp = client
                    .get(&url)
                    .send()
                    .await
                    .inspect_err(|err| warn!("{err:#}"))
                    .expect("request failed");
                let _body = resp.bytes().await.expect("read body failed");
                drop(permit);
                let elapsed = req_start.elapsed();
                debug!(?elapsed, "done");
                elapsed
            }
            .instrument(error_span!("req", %i)),
        );
    }

    let mut latencies = Vec::with_capacity(n);
    while let Some(result) = set.join_next().await {
        latencies.push(result.expect("task panicked"));
    }

    let total = start.elapsed();
    latencies.sort();
    BenchResult { total, latencies }
}

fn format_duration(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms >= 1000.0 {
        format!("{:.2}s", d.as_secs_f64())
    } else {
        format!("{:.1}ms", ms)
    }
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn print_table(results: &[(&str, BenchResult)]) {
    println!(
        "{:<18}{:<10}{:<10}{:<10}{:<10}{:<10}{:<10}",
        "Mode", "Total", "Avg", "Req/s", "p50", "p90", "p99"
    );
    println!("{}", "\u{2500}".repeat(78));
    for (name, result) in results {
        let n = result.latencies.len();
        if n == 0 {
            continue;
        }
        let avg = result.total / n as u32;
        let rps = n as f64 / result.total.as_secs_f64();
        let p50 = percentile(&result.latencies, 0.50);
        let p90 = percentile(&result.latencies, 0.90);
        let p99 = percentile(&result.latencies, 0.99);
        println!(
            "{:<18}{:<10}{:<10}{:<10}{:<10}{:<10}{:<10}",
            name,
            format_duration(result.total),
            format_duration(avg),
            format!("{:.1}", rps),
            format_duration(p50),
            format_duration(p90),
            format_duration(p99),
        );
    }
}
