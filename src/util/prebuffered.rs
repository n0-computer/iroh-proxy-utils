//! A manually controllable prebuffer for Tokio `AsyncRead`.
//!
//! This module provides [`Prebuffered`], a wrapper around an `AsyncRead` that
//! allows explicit buffering, inspection, partial consumption, and seamless
//! fallthrough to the inner reader.

use bytes::{Buf, Bytes, BytesMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{self, AsyncRead, AsyncReadExt, ReadBuf};

/// Maximum chunk size used by [`Prebuffered::buffer_more`].
///
/// This avoids heap allocations and keeps the implementation simple.
/// Larger reads are handled by calling `buffer_more` repeatedly (as done by
/// [`Prebuffered::fill_exact`] and [`Prebuffered::buffer_until`]).
const CHUNK: usize = 8 * 1024;

/// A prebuffering wrapper around an `AsyncRead`.
///
/// `Prebuffered` allows manual accumulation and inspection of input data
/// before continuing to read from the underlying reader as normal.
pub struct Prebuffered<R> {
    inner: R,
    buf: BytesMut,
    pos: usize,
}

impl<R: AsyncRead + Unpin> Prebuffered<R> {
    /// Creates a new `Prebuffered` wrapper.
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            buf: BytesMut::new(),
            pos: 0,
        }
    }

    /// Returns the unconsumed buffered bytes.
    pub(crate) fn buffer(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// Discards `n` bytes from the front of the buffer.
    pub(crate) fn discard(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.buf.len());
        self.compact();
    }

    /// Buffers more data from the inner reader.
    ///
    /// Reads up to `max` bytes (capped internally to a fixed chunk size to avoid
    /// heap allocation). Returns the number of bytes actually read (0 on EOF).
    ///
    /// This method does not over-read beyond `max`.
    pub(crate) async fn buffer_more(&mut self, max: usize) -> io::Result<usize> {
        if max == 0 {
            return Ok(0);
        }

        // Keep buffer growth at the end of the unconsumed window.
        self.compact();

        let to_read = max.min(CHUNK);
        let mut tmp = [0u8; CHUNK];
        let n = self.inner.read(&mut tmp[..to_read]).await?;
        if n != 0 {
            self.buf.extend_from_slice(&tmp[..n]);
        }
        Ok(n)
    }

    /// Returns the inner reader.
    pub(crate) fn into_parts(mut self) -> (Bytes, R) {
        (self.buf.split_off(self.pos).freeze(), self.inner)
    }

    fn compact(&mut self) {
        if self.pos == 0 {
            return;
        }

        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > self.buf.len() / 2 {
            self.buf.advance(self.pos);
            self.pos = 0;
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Prebuffered<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.buf.len() {
            let available = &self.buf[self.pos..];
            let n = available.len().min(out.remaining());
            out.put_slice(&available[..n]);
            self.pos += n;
            self.compact();
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::AsyncReadExt;

    fn cursor(data: &'static [u8]) -> Cursor<&'static [u8]> {
        Cursor::new(data)
    }

    #[tokio::test]
    async fn buffer_more_respects_max() {
        let mut p = Prebuffered::new(cursor(b"abcdefgh"));
        let n = p.buffer_more(4).await.unwrap();
        assert_eq!(n, 4);
        assert_eq!(p.buffer(), b"abcd");

        let n = p.buffer_more(2).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(p.buffer(), b"abcdef");
    }

    #[tokio::test]
    async fn buffer_more_zero_is_noop() {
        let mut p = Prebuffered::new(cursor(b"abc"));
        let n = p.buffer_more(0).await.unwrap();
        assert_eq!(n, 0);
        assert_eq!(p.buffer(), b"");
    }

    #[tokio::test]
    async fn buffer_more_eof() {
        let mut p = Prebuffered::new(cursor(b""));
        let n = p.buffer_more(10).await.unwrap();
        assert_eq!(n, 0);
        assert_eq!(p.buffer(), b"");
    }

    #[tokio::test]
    async fn discard_beyond_len_is_ok() {
        let mut p = Prebuffered::new(cursor(b"abc"));
        p.buffer_more(3).await.unwrap();
        p.discard(999);
        assert_eq!(p.buffer(), b"");
        assert_eq!(p.buffer_more(1).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn async_read_fallthrough_from_buffer() {
        let mut p = Prebuffered::new(cursor(b"hello world"));
        p.buffer_more(5).await.unwrap(); // "hello"
        let mut out = Vec::new();
        p.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
    }

    #[tokio::test]
    async fn async_read_partial_reads_from_buffer_then_inner() {
        let mut p = Prebuffered::new(cursor(b"abcdef"));
        p.buffer_more(4).await.unwrap(); // "abcd"
        p.discard(2); // "cd"

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
        let mut p = Prebuffered::new(cursor(b"abcdefghij"));
        p.buffer_more(4).await.unwrap();
        assert_eq!(p.buffer(), b"abcd");
        p.discard(3);
        assert_eq!(p.buffer(), b"d");

        p.buffer_more(4).await.unwrap();
        assert_eq!(p.buffer(), b"defgh");
    }

    #[tokio::test]
    async fn read_without_any_buffering() {
        let mut p = Prebuffered::new(cursor(b"xyz"));
        let mut out = Vec::new();
        p.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"xyz");
        assert_eq!(p.buffer(), b"");
    }
}
