use n0_error::{Result, StackResultExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::trace;

pub(crate) use self::prebuffered::Prebuffered;

mod prebuffered;

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
            trace!(?res, elapsed=?start.elapsed(), "forward down-to-up finished");
            res
        },
        async {
            let res = tokio::io::copy(upstream_recv, downstream_send).await;
            downstream_send.shutdown().await.ok();
            trace!(?res, elapsed=?start.elapsed(), "forward up-to-down finished");
            res
        }
    );
    let r1 = r1.context("failed to copy down-to-up")?;
    let r2 = r2.context("failed to copy up-to-down")?;
    Ok((r1, r2))
}
