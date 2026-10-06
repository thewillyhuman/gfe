use super::*;
use http::HeaderMap;
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A body that yields the frames it was given, one after the other.
struct Scripted(std::vec::IntoIter<Frame<Bytes>>);

impl Body for Scripted {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.next().map(Ok))
    }
}

/// Every frame of `body`, in order.
async fn frames(mut body: BoxBody) -> Vec<Frame<Bytes>> {
    let mut frames = Vec::new();
    while let Some(frame) = body.frame().await {
        frames.push(frame.unwrap());
    }
    frames
}

#[tokio::test]
async fn an_empty_body_has_no_frame() {
    let body = empty();

    assert!(body.is_end_stream());
    assert!(frames(body).await.is_empty());
}

#[tokio::test]
async fn a_full_body_is_its_bytes() {
    let body = full("hello");

    assert_eq!(body.size_hint().exact(), Some(5));
    let frames = frames(body).await;
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].data_ref().unwrap().as_ref(), b"hello");
}

#[tokio::test]
async fn a_boxed_body_keeps_its_trailers() {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().unwrap());
    let body = Scripted(
        vec![
            Frame::data(Bytes::from_static(b"message")),
            Frame::trailers(trailers.clone()),
        ]
        .into_iter(),
    );

    let frames = frames(boxed(body)).await;

    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].data_ref().unwrap().as_ref(), b"message");
    assert_eq!(frames[1].trailers_ref(), Some(&trailers));
}
