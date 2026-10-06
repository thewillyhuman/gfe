//! HTTP/1.1 and HTTP/2, serving and requesting, over any byte stream.
//!
//! The wire protocols are hyper's (and, under it, h2's). This crate is the
//! only one that names them: what is built on it sees requests, responses
//! and bodies ([`body`]), and nothing of how they travel. Replacing the
//! implementation of either protocol is then a change to this crate.
//!
//! The vocabulary (methods, status codes, headers, URIs, [`Request`] and
//! [`Response`]) is the `http` crate's, re-exported here as it is: it is
//! what every HTTP library of the ecosystem speaks, and wrapping it would
//! only add a conversion at each of this crate's borders.
pub mod body;

pub use bytes::Bytes;
pub use http::{
    Extensions, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
    Version, header, method, request, response, status, uri,
};
