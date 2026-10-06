use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

#[tokio::test]
async fn counts_the_bytes_read() {
    let (mut peer, ours) = duplex(64);
    let mut metered = Metered::new(ours);
    let meter = metered.meter();
    peer.write_all(b"hello").await.unwrap();

    let mut buf = [0u8; 16];
    let read = metered.read(&mut buf).await.unwrap();

    assert_eq!(read, 5);
    assert_eq!(meter.bytes_read(), 5);
    assert_eq!(meter.bytes_written(), 0);
}

#[tokio::test]
async fn counts_the_bytes_written() {
    let (_peer, ours) = duplex(64);
    let mut metered = Metered::new(ours);
    let meter = metered.meter();

    metered.write_all(b"goodbye").await.unwrap();

    assert_eq!(meter.bytes_written(), 7);
    assert_eq!(meter.bytes_read(), 0);
}

#[tokio::test]
async fn the_end_of_the_stream_counts_nothing() {
    let (peer, ours) = duplex(64);
    let mut metered = Metered::new(ours);
    drop(peer);

    let read = metered.read(&mut [0u8; 16]).await.unwrap();

    assert_eq!(read, 0);
    assert_eq!(metered.meter().bytes_read(), 0);
}

#[tokio::test]
async fn the_counts_outlive_the_stream() {
    let (mut peer, ours) = duplex(64);
    let mut metered = Metered::new(ours);
    let meter = metered.meter();
    metered.write_all(b"abc").await.unwrap();
    peer.write_all(b"de").await.unwrap();
    metered.read_exact(&mut [0u8; 2]).await.unwrap();

    drop(metered);

    assert_eq!((meter.bytes_read(), meter.bytes_written()), (2, 3));
}

#[tokio::test]
async fn every_meter_of_a_stream_reads_the_same_counts() {
    let (_peer, ours) = duplex(64);
    let mut metered = Metered::new(ours);
    let first = metered.meter();
    let second = first.clone();

    metered.write_all(b"xy").await.unwrap();

    assert_eq!(first.bytes_written(), 2);
    assert_eq!(second.bytes_written(), 2);
    assert_eq!(metered.meter().bytes_written(), 2);
}
