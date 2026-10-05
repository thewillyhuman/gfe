use super::*;

#[tokio::test]
async fn pause_lasts_its_whole_length_without_shutdown() {
    let (_tx, mut shutdown) = watch::channel(false);
    let started = std::time::Instant::now();

    let shut_down = pause_unless_shut_down(&mut shutdown, Duration::from_millis(50)).await;

    assert!(!shut_down);
    assert!(started.elapsed() >= Duration::from_millis(50));
}

#[tokio::test]
async fn pause_ends_as_soon_as_the_node_shuts_down() {
    let (tx, mut shutdown) = watch::channel(false);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        tx.send(true).unwrap();
    });

    let pause = pause_unless_shut_down(&mut shutdown, Duration::from_secs(60));
    let shut_down = tokio::time::timeout(Duration::from_secs(5), pause).await;

    assert_eq!(shut_down, Ok(true));
}

#[tokio::test]
async fn no_open_connection_is_waited_for_at_once() {
    let open = OpenConnections::new(10);

    let waited = tokio::time::timeout(Duration::from_secs(1), open.all_closed()).await;

    assert!(waited.is_ok());
}

#[tokio::test]
async fn the_last_connection_to_close_ends_the_wait() {
    let open = OpenConnections::new(10);
    let slot = Slot {
        permits: Some((
            open.limit.try_acquire().unwrap(),
            ConcurrencyLimit::new(None).try_acquire().unwrap(),
        )),
        open: Arc::clone(&open),
    };
    assert_eq!(open.count(), 1);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(slot);
    });

    let waited = tokio::time::timeout(Duration::from_secs(5), open.all_closed()).await;

    assert!(waited.is_ok());
    assert_eq!(open.count(), 0);
}

#[tokio::test]
async fn a_cut_is_signalled_when_it_is_sent_and_never_without_a_sender() {
    let (tx, mut cut) = watch::channel(false);
    tx.send_replace(true);
    let signalled = tokio::time::timeout(Duration::from_secs(1), cut_signalled(&mut cut)).await;
    let (tx, mut orphan) = watch::channel(false);
    drop(tx);
    let orphaned =
        tokio::time::timeout(Duration::from_millis(50), cut_signalled(&mut orphan)).await;

    assert!(signalled.is_ok());
    assert!(orphaned.is_err());
}
