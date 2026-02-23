use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use iroh::endpoint::RecvStream;
use n0_error::{Result, StackResultExt};
use n0_future::{Stream, stream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::trace;

pub(crate) use self::prebuffered::Prebuffered;

mod prebuffered;

/// Bidirectionally forward data from a quinn stream and an arbitrary tokio
/// reader/writer pair.
///
/// Calls `finish` on the SendStream once done.
pub(crate) async fn forward_bidi(
    downstream_recv: &mut (impl AsyncRead + Send + Unpin),
    downstream_send: &mut (impl AsyncWrite + Send + Unpin),
    upstream_recv: &mut (impl AsyncRead + Send + Unpin),
    upstream_send: &mut (impl AsyncWrite + Send + Unpin),
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

// Converts a [`Prebuffered`] recv stream into a stream of [`Bytes`].
pub(crate) fn recv_to_stream(
    recv: Prebuffered<RecvStream>,
    inc: impl Fn(u64),
) -> impl Stream<Item = io::Result<Bytes>> {
    let (init, recv) = recv.into_parts();
    stream::unfold(
        (inc, Some(init), recv),
        async |(inc, mut init, mut recv)| {
            let item: io::Result<Bytes> = if let Some(init) = init.take() {
                (inc)(init.len() as u64);
                Ok(init)
            } else {
                match recv.read_chunk(8192, true).await {
                    Err(err) => Err(err.into()),
                    Ok(None) => return None,
                    Ok(Some(chunk)) => {
                        (inc)(chunk.bytes.len() as u64);
                        Ok(chunk.bytes)
                    }
                }
            };
            Some((item, (inc, None, recv)))
        },
    )
}

/// Tracks bytes read and reports them via `inc`.
pub(crate) struct TrackedRead<R, F> {
    inner: R,
    inc: F,
}

impl<R: AsyncRead + Unpin, F: Fn(u64) + Unpin> TrackedRead<R, F> {
    pub(crate) fn new(inner: R, inc: F) -> Self {
        Self { inner, inc }
    }
}

impl<R: AsyncRead + Unpin, F: Fn(u64) + Unpin> AsyncRead for TrackedRead<R, F> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let after = buf.filled().len();
            let diff = after.saturating_sub(before);
            if diff > 0 {
                (this.inc)(diff as u64);
            }
        }
        result
    }
}

/// Tracks bytes written and reports them via `inc`.
pub(crate) struct TrackedWrite<W, F> {
    inner: W,
    inc: F,
}

impl<W: AsyncWrite + Unpin, F: Fn(u64) + Unpin> TrackedWrite<W, F> {
    pub(crate) fn new(inner: W, inc: F) -> Self {
        Self { inner, inc }
    }

    pub(crate) fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin, F: Fn(u64) + Unpin> AsyncWrite for TrackedWrite<W, F> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            if n > 0 {
                (this.inc)(n as u64);
            }
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[macro_export]
macro_rules! inc_by_delta {
    ($metrics:ident, $field:tt) => {{
        let metrics = $metrics.clone();
        move |d| {
            metrics.$field.inc_by(d);
        }
    }};
}
