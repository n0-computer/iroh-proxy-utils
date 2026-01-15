use iroh::endpoint::SendStream;
use n0_error::{Result, StdResultExt};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::tcp::OwnedWriteHalf,
};

pub(crate) use self::prebuffered::Prebuffered;

mod prebuffered;

pub(crate) fn status_line(status: http::StatusCode, reason: Option<&str>) -> String {
    format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_u16(),
        reason.or(status.canonical_reason()).unwrap_or("")
    )
}

pub(crate) async fn write_http_response(
    writer: &mut (impl AsyncWrite + Unpin),
    status: http::StatusCode,
    reason: Option<&str>,
) -> Result<()> {
    writer
        .write_all(status_line(status, reason).as_bytes())
        .await?;
    writer.write_all(b"\r\n").await?;
    Ok(())
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
    left_recv: &mut (impl AsyncRead + Send + Sync + Unpin),
    left_send: &mut impl FinishAsyncWrite,
    right_recv: &mut (impl AsyncRead + Send + Sync + Unpin),
    right_send: &mut impl FinishAsyncWrite,
) -> Result<()> {
    let (r1, r2) = tokio::join!(
        async {
            let res = tokio::io::copy(left_recv, right_send).await;
            right_send.finish();
            res
        },
        async {
            let res = tokio::io::copy(right_recv, left_send).await;
            left_send.finish();
            res
        }
    );
    r1.anyerr()?;
    r2.anyerr()?;
    Ok(())
}

pub(crate) trait FinishAsyncWrite: AsyncWrite + Send + Sync + Unpin {
    fn finish(&mut self) {}
}

impl FinishAsyncWrite for SendStream {
    fn finish(&mut self) {
        SendStream::finish(self).ok();
    }
}

impl<'a> FinishAsyncWrite for tokio::net::tcp::WriteHalf<'a> {
    fn finish(&mut self) {}
}

impl FinishAsyncWrite for OwnedWriteHalf {
    fn finish(&mut self) {}
}
