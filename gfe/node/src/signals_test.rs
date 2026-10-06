use super::*;
use rustix::process::{Signal, getpid, kill_process};

/// A signal goes to the whole test process, so the tests that send one take
/// turns: one test's signal must not reach another's listener.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The request that `signals`, sent to this process in turn, make of it.
async fn request_made_by(signals: &[Signal]) -> Request {
    let _turn = ONE_AT_A_TIME.lock().await;
    let mut listening = Signals::install().unwrap();
    for &signal in signals {
        kill_process(getpid(), signal).unwrap();
    }
    listening.next().await
}

#[tokio::test]
async fn sigterm_asks_for_a_stop() {
    assert_eq!(request_made_by(&[Signal::TERM]).await, Request::Stop);
}

#[tokio::test]
async fn sigint_asks_for_a_stop() {
    assert_eq!(request_made_by(&[Signal::INT]).await, Request::Stop);
}

#[tokio::test]
async fn sigusr2_asks_for_an_upgrade() {
    assert_eq!(request_made_by(&[Signal::USR2]).await, Request::Upgrade);
}

/// The process being alive to see the next request is the point: by default
/// `SIGHUP` kills it.
#[tokio::test]
async fn sighup_is_waited_past() {
    assert_eq!(
        request_made_by(&[Signal::HUP, Signal::USR2]).await,
        Request::Upgrade
    );
}

#[tokio::test]
async fn sigusr1_is_waited_past() {
    assert_eq!(
        request_made_by(&[Signal::USR1, Signal::USR2]).await,
        Request::Upgrade
    );
}
