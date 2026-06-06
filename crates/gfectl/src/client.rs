//! A minimal blocking HTTP/JSON client over the gfe-cp operator API.

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::{connect::HttpConnector, Client as HyperClient};
use hyper_util::rt::TokioExecutor;

/// A thin client bound to a controller base URL.
pub struct Client {
    inner: HyperClient<HttpConnector, Full<Bytes>>,
    base_url: String,
    token: Option<String>,
    rt: tokio::runtime::Runtime,
}

impl Client {
    /// Build a client for `base_url` (e.g. `http://gfe-cp:8080`).
    pub fn new(base_url: String, token: Option<String>) -> Result<Self> {
        Ok(Client {
            inner: HyperClient::builder(TokioExecutor::new()).build_http(),
            base_url,
            token,
            rt: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
        })
    }

    /// `GET path`, returning the response body text.
    pub fn get(&self, path: &str) -> Result<String> {
        self.send(Method::GET, path, None)
    }

    /// `DELETE path`, returning the response body text.
    pub fn delete(&self, path: &str) -> Result<String> {
        self.send(Method::DELETE, path, None)
    }

    /// `POST path` with a JSON body, returning the response body text.
    pub fn post(&self, path: &str, body: &serde_json::Value) -> Result<String> {
        self.send(Method::POST, path, Some(serde_json::to_vec(body)?))
    }

    fn send(&self, method: Method, path: &str, body: Option<Vec<u8>>) -> Result<String> {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("{}{}", self.base_url, path))
            .header(hyper::header::CONTENT_TYPE, "application/json");
        if let Some(token) = &self.token {
            builder = builder.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = builder.body(Full::new(Bytes::from(body.unwrap_or_default())))?;
        self.rt.block_on(async {
            let resp = self.inner.request(request).await?;
            let status = resp.status();
            let bytes = resp.into_body().collect().await?.to_bytes();
            let text = String::from_utf8_lossy(&bytes).into_owned();
            if status.is_success() || status == StatusCode::OK {
                Ok(text)
            } else {
                Err(anyhow!("{status}: {}", text.trim()))
            }
        })
    }
}

/// Pretty-print a JSON response, falling back to the raw text.
pub fn print_json(text: &str) {
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(v) => println!(
            "{}",
            serde_json::to_string_pretty(&v).unwrap_or_else(|_| text.into())
        ),
        Err(_) => {
            let t = text.trim();
            if !t.is_empty() {
                println!("{t}");
            }
        }
    }
}
