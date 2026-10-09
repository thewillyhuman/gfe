use super::*;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A server that answers one request per connection and says so.
async fn spawn_server_closing_after_each_response() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let response =
                    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
                let _ = stream.write_all(response).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn keepalive_client_reconnects_when_told_to_without_counting_an_error() {
    let server = spawn_server_closing_after_each_response().await;
    let target = Arc::new(parse_target(&format!("http://{server}/")).unwrap());
    let deadline = Instant::now() + Duration::from_millis(200);

    let exchange = Exchange {
        target,
        upload: Bytes::new(),
    };

    let (answered, errors) = worker_keepalive(exchange, None, deadline).await;

    assert_eq!(errors, 0);
    assert!(answered.len() > 1, "{} requests answered", answered.len());
}

#[test]
fn the_mode_names_a_full_handshake_per_request_only_over_tls() {
    let over = |url: &str, reconnect: bool, resume: bool| Scenario {
        target: Arc::new(parse_target(url).unwrap()),
        connections: 1,
        duration: Duration::ZERO,
        reconnect,
        resume,
        label: String::new(),
        cpu_of: None,
        upload: Bytes::new(),
    };

    assert_eq!(over("http://h/", false, true).mode(), "keepalive");
    assert_eq!(over("http://h/", true, false).mode(), "reconnect");
    assert_eq!(over("https://h/", true, true).mode(), "reconnect");
    assert_eq!(over("https://h/", true, false).mode(), "reconnect+full-tls");
}

#[tokio::test]
async fn charges_the_cpu_of_the_named_process_to_the_requests() {
    let server = spawn_server_closing_after_each_response().await;
    let scenario = Scenario {
        target: Arc::new(parse_target(&format!("http://{server}/")).unwrap()),
        connections: 2,
        duration: Duration::from_millis(100),
        reconnect: true,
        resume: true,
        label: "cpu".into(),
        cpu_of: Some(std::process::id()),
        upload: Bytes::new(),
    };

    let outcome = run(&scenario).await.unwrap();

    assert!(outcome.requests > 0);
    assert!(
        outcome.cpu_us_per_request.is_some_and(|cpu| cpu > 0.0),
        "{outcome}"
    );
}

#[tokio::test]
async fn a_process_that_does_not_exist_fails_the_run() {
    let server = spawn_server_closing_after_each_response().await;
    let scenario = Scenario {
        target: Arc::new(parse_target(&format!("http://{server}/")).unwrap()),
        connections: 1,
        duration: Duration::from_millis(10),
        reconnect: false,
        resume: true,
        label: "cpu".into(),
        cpu_of: Some(u32::MAX),
        upload: Bytes::new(),
    };

    assert!(run(&scenario).await.is_err());
}

/// A server that keeps the connection and records each request as its
/// method and the number of body bytes it read; its address and the
/// record.
async fn spawn_server_recording_the_uploads() -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let record = Arc::new(Mutex::new(Vec::new()));
    let served = Arc::clone(&record);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let served = Arc::clone(&served);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let served = Arc::clone(&served);
                        async move {
                            let method = req.method().clone();
                            let read = req.into_body().collect().await.unwrap().to_bytes().len();
                            served.lock().unwrap().push(format!("{method} {read}"));
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                Bytes::from("ok"),
                            )))
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (addr, record)
}

#[tokio::test]
async fn an_upload_is_a_post_carrying_the_whole_body() {
    let (server, record) = spawn_server_recording_the_uploads().await;
    let exchange = Exchange {
        target: Arc::new(parse_target(&format!("http://{server}/up")).unwrap()),
        upload: Bytes::from(vec![b'u'; 300_000]),
    };
    let mut sender = connect_h1(&exchange.target, &None).await.unwrap();

    let reusable = send_one(&mut sender, &exchange).await.unwrap();

    assert!(reusable);
    assert_eq!(*record.lock().unwrap(), ["POST 300000"]);
}

#[tokio::test]
async fn without_an_upload_the_request_is_a_get_without_a_body() {
    let (server, record) = spawn_server_recording_the_uploads().await;
    let exchange = Exchange {
        target: Arc::new(parse_target(&format!("http://{server}/")).unwrap()),
        upload: Bytes::new(),
    };
    let mut sender = connect_h1(&exchange.target, &None).await.unwrap();

    send_one(&mut sender, &exchange).await.unwrap();

    assert_eq!(*record.lock().unwrap(), ["GET 0"]);
}
