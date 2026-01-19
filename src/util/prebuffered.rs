//! A manually controllable prebuffer for Tokio `AsyncRead`.
//!
//! This module provides [`Prebuffered`], a wrapper around an `AsyncRead` that
//! allows explicit buffering, inspection, partial consumption, and seamless
//! fallthrough to the inner reader.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{self, AsyncRead, AsyncReadExt, ReadBuf};

/// Initial capacity for the internal buffer.
const INITIAL_CAPACITY: usize = 4 * 1024;

/// A prebuffering wrapper around an `AsyncRead`.
///
/// `Prebuffered` allows manual accumulation and inspection of input data
/// before continuing to read from the underlying reader as normal.
pub struct Prebuffered<R> {
    inner: R,
    buf: BytesMut,
    max_len: usize,
}

impl<R: AsyncRead + Unpin> Prebuffered<R> {
    /// Creates a new `Prebuffered` wrapper.
    pub(crate) fn new(inner: R, max_len: usize) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(INITIAL_CAPACITY),
            max_len,
        }
    }

    #[cfg(test)]
    pub(crate) fn unlimited(inner: R) -> Self {
        Self::new(inner, usize::MAX)
    }

    /// Returns the unconsumed buffered bytes.
    pub(crate) fn buffer(&self) -> &[u8] {
        &self.buf[..]
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.buf.len() == self.max_len
    }

    /// Discards `n` bytes from the front of the buffer.
    pub(crate) fn discard(&mut self, n: usize) {
        let _ = self.buf.split_to(n);
    }

    /// Buffers more data from the inner reader.
    pub(crate) async fn buffer_more(&mut self) -> io::Result<usize> {
        let max = self.max_len.saturating_sub(self.buf.len());
        let n = (&mut self.inner)
            .take(max as u64)
            .read_buf(&mut self.buf)
            .await?;
        Ok(n)
    }

    /// Returns the buffer and the inner reader.
    pub(crate) fn into_parts(self) -> (Bytes, R) {
        (self.buf.freeze(), self.inner)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Prebuffered<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !out.has_remaining_mut() {
            Poll::Ready(Ok(()))
        } else if !self.buf.is_empty() {
            let n = self.buf.len().min(out.remaining_mut());
            let chunk = self.buf.split_to(n);
            out.put_slice(&chunk);
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.inner).poll_read(cx, out)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use tokio::io::AsyncReadExt;

    use super::*;

    fn cursor(data: &'static [u8]) -> Cursor<&'static [u8]> {
        Cursor::new(data)
    }

    #[tokio::test]
    async fn buffer_more_respects_max() {
        let mut p = Prebuffered::unlimited(cursor(b"abcdefgh"));
        let n = p.buffer_more().await.unwrap();
        assert_eq!(n, 8);
        assert_eq!(p.buffer(), b"abcdefgh");
    }

    #[tokio::test]
    async fn buffer_more_eof() {
        let mut p = Prebuffered::unlimited(cursor(b""));
        let n = p.buffer_more().await.unwrap();
        assert_eq!(n, 0);
        assert_eq!(p.buffer(), b"");
    }

    #[tokio::test]
    async fn discard_beyond_len_is_ok() {
        let mut p = Prebuffered::unlimited(cursor(b"abc"));
        p.buffer_more().await.unwrap();
        p.discard(p.len());
        assert_eq!(p.buffer(), b"");
        assert_eq!(p.buffer_more().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn async_read_fallthrough_from_buffer() {
        let mut p = Prebuffered::new(cursor(b"hello world"), 5);
        p.buffer_more().await.unwrap(); // "hello"
        assert_eq!(p.buffer(), b"hello");
        let mut out = Vec::new();
        p.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
    }

    #[tokio::test]
    async fn async_read_partial_reads_from_buffer_then_inner() {
        let mut p = Prebuffered::new(cursor(b"abcdef"), 4);
        p.buffer_more().await.unwrap();
        assert_eq!(p.buffer(), b"abcd");
        p.discard(2);
        assert_eq!(p.buffer(), b"cd");

        let mut buf = [0u8; 2];
        let n = p.read(&mut buf).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf, b"cd");

        // Remaining should be "ef" (we already consumed "abcd" via buffer/reads).
        let mut rest = Vec::new();
        p.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"ef");
    }

    #[tokio::test]
    async fn buffer_more_does_not_reset_pos() {
        let mut p = Prebuffered::new(cursor(b"abcdefghij"), 4);
        p.buffer_more().await.unwrap();
        assert_eq!(p.buffer(), b"abcd");
        p.discard(3);
        assert_eq!(p.buffer(), b"d");

        p.buffer_more().await.unwrap();
        assert_eq!(p.buffer(), b"defg");
        p.discard(1);
        assert_eq!(p.buffer(), b"efg");
        let mut out = Vec::new();
        p.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"efghij");
        assert_eq!(p.buffer(), b"");
    }

    #[tokio::test]
    async fn read_without_any_buffering() {
        let mut p = Prebuffered::unlimited(cursor(b"xyz"));
        let mut out = Vec::new();
        p.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"xyz");
        assert_eq!(p.buffer(), b"");
    }
}
