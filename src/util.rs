use iroh::endpoint::{RecvStream, SendStream};
use n0_error::{Result, StdResultExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

pub(crate) async fn send_error_response(
    writer: &mut (impl AsyncWrite + Unpin),
    status: http::StatusCode,
) -> Result<()> {
    let status_line = format!(
        "HTTP/1.1 {} {}\r\n\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    );
    writer.write_all(status_line.as_bytes()).await?;
    Ok(())
}

/// Bidirectionally forward data from a quinn stream and an arbitrary tokio
/// reader/writer pair.
///
/// Calls `finish` on the SendStream once done.
pub async fn forward_bidi(
    mut from1: impl AsyncRead + Send + Sync + Unpin,
    mut to1: impl AsyncWrite + Send + Sync + Unpin,
    from2: &mut RecvStream,
    to2: &mut SendStream,
) -> Result<()> {
    let (r1, r2) = tokio::join!(
        async {
            let res = tokio::io::copy(&mut from1, to2).await;
            to2.finish().ok();
            res
        },
        async { tokio::io::copy(from2, &mut to1).await }
    );
    r1.anyerr()?;
    r2.anyerr()?;
    Ok(())
}
