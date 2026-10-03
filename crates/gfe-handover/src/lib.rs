//! Passing a node's listening sockets to the process that replaces it.
//!
//! A node that is replaced in place must never close its listening sockets:
//! connections are refused while a socket is closed, and the ones waiting in
//! its queue are reset when it closes. The outgoing node therefore gives its
//! sockets to its successor, over a Unix socket the two share, and stops
//! accepting only once the successor does.
//!
//! The exchange, version 1:
//!
//! ```text
//! outgoing node                        successor
//!   gfe-handover 1               →
//!   listener 0.0.0.0:443         →     one line per socket, the socket
//!   ops 127.0.0.1:9101           →     itself travelling with its line
//!   (closes its sending half)    →
//!                                ←     received 4242     its process id
//!                                ←     ready             once it accepts
//! ```
//!
//! The sockets travel as ancillary data (`SCM_RIGHTS`), which is how a Unix
//! socket carries open file descriptors from one process to another. Unix
//! only: elsewhere this crate is empty.
#![cfg(unix)]

use rustix::io::{fcntl_setfd, retry_on_intr, FdFlags};
use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::net::{Shutdown, SocketAddr, TcpListener};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;

/// The first line of a handover, naming the version of the exchange.
const HEADER: &str = "gfe-handover 1";

/// What the successor answers when it has the sockets, followed by its
/// process id.
const RECEIVED: &str = "received";

/// What the successor answers once it accepts connections.
const READY: &str = "ready";

/// How many sockets travel with one message. Part of the exchange: the
/// receiver makes room for this many, and the kernel carries no more than
/// 253 at a time.
const SOCKETS_PER_MESSAGE: usize = 64;

/// Room for the ancillary data of one message.
const ANCILLARY_SPACE: usize = rustix::cmsg_space!(ScmRights(SOCKETS_PER_MESSAGE));

/// The listening sockets of a node.
#[derive(Debug, Default)]
pub struct Sockets {
    /// The proxy's sockets, each with the address its listener is configured
    /// on (which is what the successor looks it up by).
    pub listeners: Vec<(SocketAddr, TcpListener)>,
    /// The socket of the ops server, with the address it is configured on.
    pub ops: Option<(SocketAddr, TcpListener)>,
}

/// Give `sockets` to the successor at the other end of `channel`. The
/// sockets stay open here too.
pub fn send(mut channel: &UnixStream, sockets: &Sockets) -> io::Result<()> {
    let listeners = sockets
        .listeners
        .iter()
        .map(|(addr, socket)| (format!("listener {addr}\n"), socket.as_fd()));
    let ops = sockets
        .ops
        .iter()
        .map(|(addr, socket)| (format!("ops {addr}\n"), socket.as_fd()));
    let entries: Vec<(String, BorrowedFd<'_>)> = listeners.chain(ops).collect();

    writeln!(channel, "{HEADER}")?;
    for message in entries.chunks(SOCKETS_PER_MESSAGE) {
        let lines: String = message.iter().map(|(line, _)| line.as_str()).collect();
        let fds: Vec<BorrowedFd<'_>> = message.iter().map(|(_, fd)| *fd).collect();
        let mut space = [MaybeUninit::<u8>::uninit(); ANCILLARY_SPACE];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
            return Err(io::Error::other("no room for the sockets of a message"));
        }
        // The sockets travel with the first byte; whatever part of the lines
        // did not fit follows on its own.
        let sent = retry_on_intr(|| {
            sendmsg(
                channel,
                &[IoSlice::new(lines.as_bytes())],
                &mut control,
                SendFlags::empty(),
            )
        })?;
        channel.write_all(&lines.as_bytes()[sent..])?;
    }
    channel.shutdown(Shutdown::Write)
}

/// Take the sockets the outgoing node at the other end of `channel` gives,
/// and tell it which process has them.
pub fn receive(mut channel: &UnixStream) -> io::Result<Sockets> {
    let mut text = Vec::new();
    let mut fds: Vec<OwnedFd> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let mut space = [MaybeUninit::<u8>::uninit(); ANCILLARY_SPACE];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let received = retry_on_intr(|| {
            recvmsg(
                channel,
                &mut [IoSliceMut::new(&mut chunk)],
                &mut control,
                RecvFlags::empty(),
            )
        })?;
        if received.flags.contains(ReturnFlags::CTRUNC) {
            return Err(invalid("sockets were lost on the way"));
        }
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(sockets) = message {
                fds.extend(sockets);
            }
        }
        if received.bytes == 0 {
            break;
        }
        text.extend_from_slice(&chunk[..received.bytes]);
    }

    let text = String::from_utf8(text).map_err(|_| invalid("not text"))?;
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err(invalid("not a handover this version understands"));
    }
    let mut fds = fds.into_iter();
    let mut sockets = Sockets::default();
    for line in lines {
        let (kind, addr) = line
            .split_once(' ')
            .ok_or_else(|| invalid("a line without an address"))?;
        let addr: SocketAddr = addr.parse().map_err(|_| invalid("a malformed address"))?;
        let fd = fds
            .next()
            .ok_or_else(|| invalid("fewer sockets than lines"))?;
        // Descriptors arrive inheritable; nothing this process starts later
        // should get them by accident.
        fcntl_setfd(&fd, FdFlags::CLOEXEC)?;
        let socket = TcpListener::from(fd);
        match kind {
            "listener" => sockets.listeners.push((addr, socket)),
            "ops" => sockets.ops = Some((addr, socket)),
            _ => return Err(invalid("a socket of an unknown kind")),
        }
    }
    if fds.next().is_some() {
        return Err(invalid("more sockets than lines"));
    }
    writeln!(channel, "{RECEIVED} {}", std::process::id())?;
    Ok(sockets)
}

/// Wait until the successor has the sockets; returns its process id.
///
/// Fails if the successor goes away first or, when `channel` has a read
/// timeout, does not answer in time.
pub fn await_receipt(channel: &UnixStream) -> io::Result<u32> {
    let answer = read_line(channel)?;
    answer
        .strip_prefix(RECEIVED)
        .and_then(|pid| pid.trim().parse().ok())
        .ok_or_else(|| invalid("not a receipt"))
}

/// Tell the outgoing node that this process now accepts connections on the
/// sockets it was given.
pub fn confirm(mut channel: &UnixStream) -> io::Result<()> {
    writeln!(channel, "{READY}")
}

/// Wait until the successor confirms that it accepts connections.
///
/// Fails if the successor goes away without confirming or, when `channel`
/// has a read timeout, does not confirm in time.
pub fn await_confirmation(channel: &UnixStream) -> io::Result<()> {
    if read_line(channel)? == READY {
        Ok(())
    } else {
        Err(invalid("not a confirmation"))
    }
}

/// The next line the successor sends, without its line break. Read a byte at
/// a time, so that nothing of the line after it is consumed.
fn read_line(mut channel: &UnixStream) -> io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if channel.read(&mut byte)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the successor went away",
            ));
        }
        if byte[0] == b'\n' {
            return String::from_utf8(line).map_err(|_| invalid("not text"));
        }
        line.push(byte[0]);
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("malformed handover: {what}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{Shutdown, TcpStream};
    use std::time::Duration;

    fn listening() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").unwrap()
    }

    /// What a successor receives when it is sent `sockets`.
    fn handed_over(sockets: &Sockets) -> Sockets {
        let (outgoing, successor) = UnixStream::pair().unwrap();
        send(&outgoing, sockets).unwrap();
        receive(&successor).unwrap()
    }

    #[test]
    fn successor_accepts_on_the_sockets_it_is_given() {
        let socket = listening();
        let addr = socket.local_addr().unwrap();
        let configured_on: SocketAddr = "0.0.0.0:443".parse().unwrap();
        let sent = Sockets {
            listeners: vec![(configured_on, socket)],
            ops: None,
        };

        let mut received = handed_over(&sent);
        let (given_for, given) = received.listeners.pop().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (_, peer) = given.accept().unwrap();

        assert_eq!(given_for, configured_on);
        assert_eq!(peer, client.local_addr().unwrap());
    }

    #[test]
    fn tells_the_ops_socket_from_the_listeners() {
        let ops = listening();
        let ops_addr = ops.local_addr().unwrap();
        let sent = Sockets {
            listeners: vec![("127.0.0.1:80".parse().unwrap(), listening())],
            ops: Some((ops_addr, ops)),
        };

        let received = handed_over(&sent);
        let (given_for, given) = received.ops.unwrap();

        assert_eq!(given_for, ops_addr);
        assert_eq!(given.local_addr().unwrap(), ops_addr);
        assert_eq!(received.listeners.len(), 1);
    }

    #[test]
    fn hands_over_more_sockets_than_one_message_carries() {
        let sockets: Vec<TcpListener> = (0..100).map(|_| listening()).collect();
        let bound: Vec<SocketAddr> = sockets.iter().map(|s| s.local_addr().unwrap()).collect();
        let sent = Sockets {
            listeners: bound.iter().copied().zip(sockets).collect(),
            ops: None,
        };

        let received = handed_over(&sent);

        let given: Vec<SocketAddr> = received
            .listeners
            .iter()
            .map(|(configured_on, socket)| {
                assert_eq!(socket.local_addr().unwrap(), *configured_on);
                *configured_on
            })
            .collect();
        assert_eq!(given, bound);
    }

    #[test]
    fn refuses_a_handover_of_another_version() {
        let (mut outgoing, successor) = UnixStream::pair().unwrap();
        outgoing.write_all(b"gfe-handover 2\n").unwrap();
        outgoing.shutdown(Shutdown::Write).unwrap();

        let received = receive(&successor);

        assert_eq!(received.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn outgoing_node_learns_which_process_received_the_sockets() {
        let (outgoing, successor) = UnixStream::pair().unwrap();
        send(&outgoing, &Sockets::default()).unwrap();

        receive(&successor).unwrap();

        assert_eq!(await_receipt(&outgoing).unwrap(), std::process::id());
    }

    #[test]
    fn confirmation_is_not_lost_when_it_arrives_with_the_receipt() {
        let (outgoing, successor) = UnixStream::pair().unwrap();
        send(&outgoing, &Sockets::default()).unwrap();
        receive(&successor).unwrap();
        confirm(&successor).unwrap();

        await_receipt(&outgoing).unwrap();

        assert!(await_confirmation(&outgoing).is_ok());
    }

    #[test]
    fn outgoing_node_learns_that_the_successor_is_ready() {
        let (outgoing, successor) = UnixStream::pair().unwrap();

        confirm(&successor).unwrap();

        assert!(await_confirmation(&outgoing).is_ok());
    }

    #[test]
    fn outgoing_node_learns_that_the_successor_went_away() {
        let (outgoing, successor) = UnixStream::pair().unwrap();

        drop(successor);

        assert!(await_confirmation(&outgoing).is_err());
    }

    #[test]
    fn outgoing_node_stops_waiting_at_the_read_timeout() {
        let (outgoing, _successor) = UnixStream::pair().unwrap();
        outgoing
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();

        assert!(await_confirmation(&outgoing).is_err());
    }
}
