//! A runtime that falls behind: what arrived in time is served, however
//! late it is looked at. These tests hold the runtime's only thread, so
//! they run on real time and real sockets.
mod server_support;

use netkit_http::server::Options;
use server_support::*;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Short enough to wait out many times over in a test.
const HEADER_TIMEOUT: Duration = Duration::from_millis(20);

/// How often the race is run: left to chance, the timer would win about
/// every other time.
const ROUNDS: usize = 25;

#[tokio::test]
async fn serves_a_head_that_arrived_in_time_but_was_looked_at_late() {
    for round in 0..ROUNDS {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let options = Options {
            header_timeout: HEADER_TIMEOUT,
            ..options()
        };
        let _serving = spawn_serve(stream, hello(), options);
        // The connection is looked at once: its header timeout starts now.
        tokio::task::yield_now().await;
        client
            .write_all(b"GET / HTTP/1.1\r\nhost: t\r\n\r\n")
            .await
            .unwrap();

        // The head is in the socket, well in time, and the runtime is busy
        // elsewhere until after the timeout.
        std::thread::sleep(HEADER_TIMEOUT * 2);

        let response = read_response(&mut client).await;
        assert!(
            response.head.starts_with("HTTP/1.1 200"),
            "round {round}: {response:?}"
        );
    }
}
