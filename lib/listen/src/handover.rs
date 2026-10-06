//! Passing a process's listening sockets to the process that replaces it.
//!
//! A process that is replaced in place must never close its listening
//! sockets: connections are refused while a socket is closed, and the ones
//! waiting in its queue are reset when it closes. The outgoing process
//! therefore gives its sockets to its successor, over a Unix socket the two
//! share, and stops accepting only once the successor does.
//!
//! The exchange, for a protocol named `example-handover`, version 1, and
//! sockets in two roles:
//!
//! ```text
//! outgoing process                     successor
//!   example-handover 1           →
//!   listener 0.0.0.0:443         →     one line per socket, the socket
//!   ops 127.0.0.1:9101           →     itself travelling with its line
//!   (closes its sending half)    →
//!                                ←     received 4242     its process id
//!                                ←     ready             once it accepts
//! ```
//!
//! The protocol's name and version, and the roles, are the caller's
//! ([`Protocol`], [`Socket::role`]): a successor refuses a header or a role
//! it does not know. The rest of the exchange is fixed, so that processes of
//! different releases of the same program understand each other.
//!
//! The sockets travel as ancillary data (`SCM_RIGHTS`), which is how a Unix
//! socket carries open file descriptors from one process to another. Unix
//! only: elsewhere this module is not built. Every call blocks; from async
//! code, call it on a blocking thread.

use rustix::io::{FdFlags, fcntl_setfd, retry_on_intr};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::net::{Shutdown, SocketAddr, TcpListener};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

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

/// The exchange both processes speak: its first line is `name version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protocol {
    /// The name of the exchange: one word, without spaces.
    pub name: &'static str,
    /// Its version. A successor refuses any version but its own.
    pub version: u32,
}

impl Protocol {
    fn header(&self) -> String {
        format!("{} {}", self.name, self.version)
    }
}

/// A listening socket being handed over.
#[derive(Debug)]
pub struct Socket {
    /// What the socket is for, as the two processes agree to call it: one
    /// word, without spaces.
    pub role: String,
    /// The address the socket is configured on, which is what the successor
    /// looks it up by. It may differ from the one bound (port 0).
    pub addr: SocketAddr,
    /// The socket itself, bound and listening.
    pub socket: TcpListener,
}

/// Give `sockets` to the successor at the other end of `channel`, speaking
/// `protocol`, then close the sending half of `channel`. The sockets stay
/// open here too.
///
/// Fails without sending anything if the protocol's name or a role is not
/// one word (`InvalidInput`).
pub fn send(mut channel: &UnixStream, protocol: &Protocol, sockets: &[Socket]) -> io::Result<()> {
    if let Some(word) = std::iter::once(protocol.name)
        .chain(sockets.iter().map(|socket| socket.role.as_str()))
        .find(|word| !is_one_word(word))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{word:?} cannot be sent in a handover: it is not one word"),
        ));
    }
    let entries: Vec<(String, BorrowedFd<'_>)> = sockets
        .iter()
        .map(|socket| {
            (
                format!("{} {}\n", socket.role, socket.addr),
                socket.socket.as_fd(),
            )
        })
        .collect();

    writeln!(channel, "{}", protocol.header())?;
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

/// Take the sockets the outgoing process at the other end of `channel`
/// gives, speaking `protocol`, and tell it which process has them. Returns
/// them in the order they were sent.
///
/// Fails (`InvalidData`) on a header other than `protocol`'s, on a socket
/// whose role is not one of `roles`, and on lines and sockets that do not
/// pair up; the outgoing process is then told nothing.
pub fn receive(
    mut channel: &UnixStream,
    protocol: &Protocol,
    roles: &[&str],
) -> io::Result<Vec<Socket>> {
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
    if lines.next() != Some(protocol.header().as_str()) {
        return Err(invalid("not a handover this version understands"));
    }
    let mut fds = fds.into_iter();
    let mut sockets = Vec::new();
    for line in lines {
        let (role, addr) = line
            .split_once(' ')
            .ok_or_else(|| invalid("a line without an address"))?;
        let addr: SocketAddr = addr.parse().map_err(|_| invalid("a malformed address"))?;
        let fd = fds
            .next()
            .ok_or_else(|| invalid("fewer sockets than lines"))?;
        if !roles.contains(&role) {
            return Err(invalid(&format!("a socket of an unknown role, {role:?}")));
        }
        // Descriptors arrive inheritable; nothing this process starts later
        // should get them by accident.
        fcntl_setfd(&fd, FdFlags::CLOEXEC)?;
        sockets.push(Socket {
            role: role.to_string(),
            addr,
            socket: TcpListener::from(fd),
        });
    }
    if fds.next().is_some() {
        return Err(invalid("more sockets than lines"));
    }
    writeln!(channel, "{RECEIVED} {}", std::process::id())?;
    Ok(sockets)
}

/// Wait until the successor has the sockets; returns its process id.
///
/// Fails if the successor goes away first or does not answer by `deadline`
/// (`TimedOut`). The same deadline is meant to be given to
/// [`await_confirmation`] next, so that it bounds the whole exchange.
///
/// Changes the read timeout of `channel`. Shutting `channel` down from
/// another thread ends the wait at once, with an error.
pub fn await_receipt(channel: &UnixStream, deadline: Instant) -> io::Result<u32> {
    let answer = read_line(channel, deadline)?;
    answer
        .strip_prefix(RECEIVED)
        .and_then(|pid| pid.trim().parse().ok())
        .ok_or_else(|| invalid("not a receipt"))
}

/// Tell the outgoing process that this process now accepts connections on
/// the sockets it was given.
pub fn confirm(mut channel: &UnixStream) -> io::Result<()> {
    writeln!(channel, "{READY}")
}

/// Wait until the successor confirms that it accepts connections.
///
/// Fails if the successor goes away without confirming or does not confirm
/// by `deadline` (`TimedOut`).
///
/// Changes the read timeout of `channel`. Shutting `channel` down from
/// another thread ends the wait at once, with an error.
pub fn await_confirmation(channel: &UnixStream, deadline: Instant) -> io::Result<()> {
    if read_line(channel, deadline)? == READY {
        Ok(())
    } else {
        Err(invalid("not a confirmation"))
    }
}

/// Whether `word` can stand in a line of the exchange as one word.
fn is_one_word(word: &str) -> bool {
    !word.is_empty() && !word.contains(char::is_whitespace)
}

/// The next line the successor sends, without its line break, if it is all
/// there by `deadline`. Read a byte at a time, so that nothing of the line
/// after it is consumed.
fn read_line(mut channel: &UnixStream, deadline: Instant) -> io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the successor did not answer in time",
            ));
        }
        channel.set_read_timeout(Some(left))?;
        let read = match channel.read(&mut byte) {
            Ok(read) => read,
            // A signal handled by this thread interrupts a read that has a
            // timeout, and std does not retry it. Nor does a timeout end the
            // wait: only the deadline does, checked above.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        if read == 0 {
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
#[path = "handover_test.rs"]
mod tests;
