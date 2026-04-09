use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use iroh::endpoint::RecvStream;
use n0_error::{Result, StackResultExt};
use n0_future::{Stream, stream};
use pin_project::{pin_project, pinned_drop};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::trace;

pub(crate) use self::prebuffered::{Prebufferable, Prebuffered};

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
) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static {
    let (init, recv) = recv.into_parts();
    stream::unfold((Some(init), recv), async |(mut init, mut recv)| {
        let item: io::Result<Bytes> = if let Some(init) = init.take() {
            Ok(init)
        } else {
            match recv.read_chunk(8192).await {
                Err(err) => Err(err.into()),
                Ok(None) => {
                    return None;
                }
                Ok(Some(chunk)) => Ok(chunk.bytes),
            }
        };
        Some((item, (None, recv)))
    })
}

#[pin_project(PinnedDrop)]
#[derive(Debug)]
pub struct TrackedStream<S, F>
where
    F: for<'a> Fn(StreamEvent<'a>) + Unpin + Send + 'static,
{
    #[pin]
    inner: S,
    on_event: Option<F>,
}

#[derive(Debug)]
pub enum StreamEvent<'a> {
    Data(u64),
    Done(Result<(), &'a io::Error>),
}

impl<S, F> TrackedStream<S, F>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send,
    F: for<'a> Fn(StreamEvent<'a>) + Unpin + Send + 'static,
{
    pub fn new(inner: S, on_event: F) -> Self {
        Self {
            inner,
            on_event: Some(on_event),
        }
    }
}

#[pinned_drop]
impl<S, F> PinnedDrop for TrackedStream<S, F>
where
    F: for<'a> Fn(StreamEvent<'a>) + Unpin + Send + 'static,
{
    fn drop(self: Pin<&mut Self>) {
        if let Some(f) = self.project().on_event.take() {
            f(StreamEvent::Done(Ok(())));
        }
    }
}

impl<S, F> Stream for TrackedStream<S, F>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send,
    F: for<'a> Fn(StreamEvent<'a>) + Unpin + Send + 'static,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        match ready!(this.inner.poll_next(cx)) {
            None => {
                if let Some(f) = this.on_event.take() {
                    f(StreamEvent::Done(Ok(())));
                }
                Poll::Ready(None)
            }
            Some(Ok(bytes)) => {
                if let Some(f) = this.on_event.as_ref() {
                    f(StreamEvent::Data(bytes.len() as u64));
                }
                Poll::Ready(Some(Ok(bytes)))
            }
            Some(Err(e)) => {
                if let Some(f) = this.on_event.take() {
                    f(StreamEvent::Done(Err(&e)));
                }
                Poll::Ready(Some(Err(e)))
            }
        }
    }
}

/// Tracks bytes read and reports them via `inc`.
pub(crate) struct TrackedRead<R, F, G = ()> {
    inner: R,
    inc: F,
    _guard: Option<G>,
}

impl<R: AsyncRead + Unpin, F: Fn(u64) + Unpin> TrackedRead<R, F> {
    pub(crate) fn new(inner: R, inc: F) -> Self {
        Self {
            inner,
            inc,
            _guard: None,
        }
    }
}

impl<R: AsyncRead + Unpin, F: Fn(u64) + Unpin, G: Unpin> TrackedRead<R, F, G> {
    // pub(crate) fn into_parts(self) -> (R, F) {
    //     (self.inner, self.inc)
    // }

    pub(crate) fn with_guard<GG>(self, guard: GG) -> TrackedRead<R, F, GG> {
        TrackedRead {
            inner: self.inner,
            inc: self.inc,
            _guard: Some(guard),
        }
    }
}

impl<R: AsyncRead + Unpin + Send, F: Fn(u64) + Unpin + Send, G: Unpin + Send> Prebufferable
    for TrackedRead<Prebuffered<R>, F, G>
{
    fn is_full(&self) -> bool {
        self.inner.is_full()
    }

    fn buffer(&self) -> &[u8] {
        self.inner.buffer()
    }

    fn discard(&mut self, n: usize) {
        self.inner.discard(n)
    }

    async fn buffer_more(&mut self) -> tokio::io::Result<usize> {
        match self.inner.buffer_more().await {
            Ok(n) => {
                (self.inc)(n as u64);
                Ok(n)
            }
            Err(err) => Err(err),
        }
    }
}

impl<R: AsyncRead + Unpin, F: Fn(u64) + Unpin, G: Unpin> AsyncRead for TrackedRead<R, F, G> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
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
pub(crate) struct TrackedWrite<W, F, G = ()> {
    inner: W,
    inc: F,
    _guard: Option<G>,
}

impl<W: AsyncWrite + Unpin, F: Fn(u64) + Unpin> TrackedWrite<W, F> {
    pub(crate) fn new(inner: W, inc: F) -> Self {
        Self {
            inner,
            inc,
            _guard: None,
        }
    }
}
impl<W: AsyncWrite + Unpin, F: Fn(u64) + Unpin, G: Unpin> TrackedWrite<W, F, G> {
    pub(crate) fn into_inner(self) -> W {
        self.inner
    }

    pub(crate) fn with_guard<GG>(self, guard: GG) -> TrackedWrite<W, F, GG> {
        TrackedWrite {
            inner: self.inner,
            inc: self.inc,
            _guard: Some(guard),
        }
    }
}

impl<W: AsyncWrite + Unpin, F: Fn(u64) + Unpin, G: Unpin> AsyncWrite for TrackedWrite<W, F, G> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            if n > 0 {
                (this.inc)(n as u64);
            }
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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

pub(crate) fn nores<T>(_r: T) {}
