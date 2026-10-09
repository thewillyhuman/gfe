//! A mock backend: every request gets the same fixed body, as fast as
//! hyper serves it, so that what the load test measures is the node.

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

/// Serve on `listen` until the process ends, answering every request with
/// `body_bytes` bytes.
pub async fn serve(listen: &str, body_bytes: usize) -> Result<()> {
    let body = Bytes::from(vec![b'x'; body_bytes]);
    let listener = TcpListener::bind(listen).await.context("bind upstream")?;
    eprintln!("mock upstream on {listen}, body {body_bytes}B");
    loop {
        let (stream, _) = listener.accept().await?;
        let body = body.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |_req| {
                let body = body.clone();
                async move { Ok::<_, std::convert::Infallible>(Response::new(Full::new(body))) }
            });
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}
