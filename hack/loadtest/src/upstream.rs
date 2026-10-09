//! A mock backend: every request gets the same fixed body, as fast as
//! hyper serves it, so that what the load test measures is the node.

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

/// Serve on `listen` until the process ends, answering every request with
/// `body_bytes` bytes.
pub async fn serve(listen: &str, body_bytes: usize) -> Result<()> {
    let listener = TcpListener::bind(listen).await.context("bind upstream")?;
    eprintln!("mock upstream on {listen}, body {body_bytes}B");
    serve_on(listener, Bytes::from(vec![b'x'; body_bytes])).await
}

/// Answer every request on `listener` with `body`, once the request's
/// own body, if any, has been read in full: a connection whose request
/// was not read to its end cannot carry the next one.
async fn serve_on(listener: TcpListener, body: Bytes) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let body = body.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<Incoming>| {
                let body = body.clone();
                async move {
                    let _ = req.into_body().collect().await;
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(body)))
                }
            });
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}

#[cfg(test)]
#[path = "upstream_test.rs"]
mod tests;
