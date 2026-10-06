use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

/// A tally that adds up what it is told.
#[derive(Debug, Default)]
struct Total {
    read: AtomicU64,
    written: AtomicU64,
}

impl Tally for Total {
    fn read(&self, bytes: u64) {
        self.read.fetch_add(bytes, Ordering::Relaxed);
    }

    fn written(&self, bytes: u64) {
        self.written.fetch_add(bytes, Ordering::Relaxed);
    }
}

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

#[tokio::test]
async fn a_tally_is_told_of_the_bytes_while_the_stream_is_in_use() {
    let (mut peer, ours) = duplex(64);
    let total = Arc::new(Total::default());
    let mut metered = Metered::with_tally(ours, Arc::clone(&total) as Arc<dyn Tally>);
    peer.write_all(b"hello").await.unwrap();

    let mut buf = [0u8; 5];
    metered.read_exact(&mut buf).await.unwrap();
    metered.write_all(b"goodbye").await.unwrap();

    assert_eq!(total.read.load(Ordering::Relaxed), 5);
    assert_eq!(total.written.load(Ordering::Relaxed), 7);
}

#[tokio::test]
async fn a_tally_shared_by_two_streams_is_told_of_both() {
    let total = Arc::new(Total::default());
    let (_first_peer, first) = duplex(64);
    let (_second_peer, second) = duplex(64);
    let mut first = Metered::with_tally(first, Arc::clone(&total) as Arc<dyn Tally>);
    let mut second = Metered::with_tally(second, Arc::clone(&total) as Arc<dyn Tally>);

    first.write_all(b"one").await.unwrap();
    second.write_all(b"three").await.unwrap();

    assert_eq!(total.written.load(Ordering::Relaxed), 8);
    assert_eq!(first.meter().bytes_written(), 3);
    assert_eq!(second.meter().bytes_written(), 5);
}

#[tokio::test]
async fn a_tally_is_not_told_of_the_end_of_the_stream() {
    let (peer, ours) = duplex(64);
    let total = Arc::new(Total::default());
    let mut metered = Metered::with_tally(ours, Arc::clone(&total) as Arc<dyn Tally>);
    drop(peer);

    let mut buf = [0u8; 16];
    let read = metered.read(&mut buf).await.unwrap();

    assert_eq!(read, 0);
    assert_eq!(total.read.load(Ordering::Relaxed), 0);
}
