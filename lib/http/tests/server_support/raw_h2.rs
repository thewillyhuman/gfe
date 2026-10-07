//! An HTTP/2 client written frame by frame, for what a well-behaved client
//! (hyper's) never does: leave a PING unanswered, open more streams than
//! it was allowed, or show the frames the server sent.
//!
//! Requests are `GET http://test/`, their head encoded with HPACK's static
//! table and one literal, so no HPACK state is needed. Responses are not
//! decoded: frame types and stream ids are what the tests look at.
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DATA: u8 = 0x0;
pub const HEADERS: u8 = 0x1;
pub const RST_STREAM: u8 = 0x3;
pub const SETTINGS: u8 = 0x4;
pub const PING: u8 = 0x6;
pub const GOAWAY: u8 = 0x7;

pub const ACK: u8 = 0x1;
pub const END_STREAM: u8 = 0x1;
pub const END_HEADERS: u8 = 0x4;

pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const REFUSED_STREAM: u32 = 0x7;

/// One frame, as read off the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub flags: u8,
    pub stream: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    /// The value of `id` in a SETTINGS frame, if it carries it. An entry
    /// is a two-byte id and a four-byte value; a trailing partial entry is
    /// not one.
    pub fn setting(&self, id: u16) -> Option<u32> {
        let (entries, _) = self.payload.as_chunks::<6>();
        entries.iter().find_map(|&[id_hi, id_lo, v0, v1, v2, v3]| {
            (u16::from_be_bytes([id_hi, id_lo]) == id).then(|| u32::from_be_bytes([v0, v1, v2, v3]))
        })
    }

    /// The error code of a RST_STREAM frame.
    pub fn error_code(&self) -> u32 {
        u32::from_be_bytes(self.payload[..4].try_into().unwrap())
    }
}

/// A raw HTTP/2 client connection.
pub struct RawH2<S> {
    io: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin> RawH2<S> {
    /// Send the connection preface and empty SETTINGS, then read up to the
    /// server's SETTINGS (returned) and acknowledge them.
    pub async fn handshake(mut io: S) -> (Self, Frame) {
        io.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        let mut client = RawH2 { io };
        client.send(SETTINGS, 0, 0, &[]).await;
        loop {
            let frame = client.read().await.expect("closed before its SETTINGS");
            if frame.kind == SETTINGS && frame.flags & ACK == 0 {
                client.send(SETTINGS, ACK, 0, &[]).await;
                return (client, frame);
            }
        }
    }

    /// Open `stream` with a `GET http://test/` and no body.
    pub async fn get(&mut self, stream: u32) {
        let mut head = vec![
            0x82, // :method GET
            0x86, // :scheme http
            0x84, // :path /
            0x01, // :authority, literal without indexing
            4,
        ];
        head.extend_from_slice(b"test");
        self.send(HEADERS, END_HEADERS | END_STREAM, stream, &head)
            .await;
    }

    /// Send one frame.
    pub async fn send(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
        self.try_send(kind, flags, stream, payload)
            .await
            .expect("server gone");
    }

    /// Send one frame, if the server is still there to take it.
    async fn try_send(
        &mut self,
        kind: u8,
        flags: u8,
        stream: u32,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let length = u32::try_from(payload.len()).unwrap().to_be_bytes();
        let mut frame = Vec::with_capacity(9 + payload.len());
        frame.extend_from_slice(&length[1..]);
        frame.push(kind);
        frame.push(flags);
        frame.extend_from_slice(&stream.to_be_bytes());
        frame.extend_from_slice(payload);
        self.io.write_all(&frame).await
    }

    /// The next frame, or `None` once the server has closed the connection.
    pub async fn read(&mut self) -> Option<Frame> {
        let mut header = [0; 9];
        self.io.read_exact(&mut header).await.ok()?;
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]);
        let mut payload = vec![0; usize::try_from(length).unwrap()];
        self.io.read_exact(&mut payload).await.ok()?;
        Some(Frame {
            kind: header[3],
            flags: header[4],
            stream: u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff,
            payload,
        })
    }

    /// The next frame that is not a PING, acknowledging the PINGs on the
    /// way if `ack_pings`; `None` once the server has closed the connection.
    pub async fn next(&mut self, ack_pings: bool) -> Option<Frame> {
        loop {
            let frame = self.read().await?;
            if frame.kind != PING {
                return Some(frame);
            }
            if ack_pings && frame.flags & ACK == 0 {
                // A server that closed right after its PING is told by the
                // next read, which finds the connection closed.
                let _ = self.try_send(PING, ACK, 0, &frame.payload).await;
            }
        }
    }

    /// Every frame up to the server closing the connection, PINGs
    /// acknowledged and left out.
    pub async fn until_closed(&mut self) -> Vec<Frame> {
        let mut frames = Vec::new();
        while let Some(frame) = self.next(true).await {
            frames.push(frame);
        }
        frames
    }
}
