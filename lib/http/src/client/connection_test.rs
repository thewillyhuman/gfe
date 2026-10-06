use super::*;

#[test]
fn names_a_host_and_port_as_an_authority() {
    assert_eq!(authority("server.test", 8080).unwrap(), "server.test:8080");
    assert_eq!(authority("127.0.0.1", 80).unwrap(), "127.0.0.1:80");
}

#[test]
fn brackets_an_ipv6_address() {
    assert_eq!(authority("::1", 443).unwrap(), "[::1]:443");
    assert_eq!(authority("[::1]", 443).unwrap(), "[::1]:443");
}

#[test]
fn refuses_a_host_that_is_not_one() {
    assert!(authority("not a host", 80).is_err());
}
