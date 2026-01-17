use iroh::endpoint::SendStream;
use n0_error::{Result, StackResultExt, StdResultExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

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
) -> Result<()> {
    let (r1, r2) = tokio::join!(
        async {
            let res = tokio::io::copy(downstream_recv, upstream_send).await;
            upstream_send.shutdown().await.ok();
            res
        },
        async {
            let res = tokio::io::copy(upstream_recv, downstream_send).await;
            downstream_send.shutdown().await.ok();
            res
        }
    );
    r1.or(r2).context("Failed while copying stream data")?;
    Ok(())
}
