use super::*;

#[test]
fn attaching_outside_linux_says_it_needs_linux() {
    assert!(matches!(TcpProbe::attach(1024), Err(Unavailable::NotLinux)));
}
