use iroh::endpoint::SendStream;
use n0_error::{Result, StackResultExt, StdResultExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, trace};

pub(crate) use self::prebuffered::Prebuffered;

mod prebuffered;

pub(crate) fn status_line(status: http::StatusCode, reason: Option<&str>) -> String {
    format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_u16(),
        reason.or(status.canonical_reason()).unwrap_or("")
    )
}

pub(crate) async fn write_reqwest_response(
    res: &reqwest::Response,
    send: &mut SendStream,
) -> Result<()> {
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
    Ok(())
}

/// Bidirectionally forward data from a quinn stream and an arbitrary tokio
/// reader/writer pair.
///
/// Calls `finish` on the SendStream once done.
pub(crate) async fn forward_bidi(
    downstream_recv: &mut (impl AsyncRead + Send + Sync + Unpin),
    downstream_send: &mut (impl AsyncWrite + Send + Sync + Unpin),
    upstream_recv: &mut (impl AsyncRead + Send + Sync + Unpin),
    upstream_send: &mut (impl AsyncWrite + Send + Sync + Unpin),
) -> Result<(u64, u64)> {
    let start = n0_future::time::Instant::now();
    let (r1, r2) = tokio::join!(
        async {
            let res = tokio::io::copy(downstream_recv, upstream_send).await;
            upstream_send.shutdown().await.ok();
            trace!(?res, elapsed=?start.elapsed(), "forward bidi down-to-up finished");
            res
        },
        async {
            let res = tokio::io::copy(upstream_recv, downstream_send).await;
            downstream_send.shutdown().await.ok();
            trace!(?res, elapsed=?start.elapsed(), "forward bidi up-to-down finished");
            res
        }
    );
    let r1 = r1.context("failed to copy down-to-up")?;
    let r2 = r2.context("failed to copy up-to-down")?;
    trace!(down_to_up=r1, up_to_down=r2, elapsed=?start.elapsed(), "forward bidi done");
    Ok((r1, r2))
}
