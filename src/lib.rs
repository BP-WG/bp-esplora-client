//! An extensible blocking/async Esplora client
//!
//! This library provides an extensible blocking and
//! async Esplora client to query Esplora's backend.
//!
//! The library provides the possibility to build a blocking
//! client using [`minreq`] and an async client using [`reqwest`].
//! The library supports communicating to Esplora via a proxy
//! and also using TLS (SSL) for secure communication.
//!
//!
//! ## Usage
//!
//! You can create a blocking client as follows:
//!
//! ```no_run
//! # #[cfg(feature = "blocking")]
//! # {
//! use esplora::Builder;
//! let builder = Builder::new("https://blockstream.info/testnet/api");
//! let blocking_client = builder.build_blocking();
//! # Ok::<(), esplora::Error>(());
//! # }
//! ```
//!
//! Here is an example of how to create an asynchronous client.
//!
//! ```no_run
//! # #[cfg(all(feature = "async", feature = "tokio"))]
//! # {
//! use esplora::Builder;
//! let builder = Builder::new("https://blockstream.info/testnet/api");
//! let async_client = builder.build_async();
//! # Ok::<(), esplora::Error>(());
//! # }
//! ```
//!
//! ## Features
//!
//! By default the library enables all features. To specify
//! specific features, set `default-features` to `false` in your `Cargo.toml`
//! and specify the features you want. This will look like this:
//!
//! `bp-esplora = { version = "*", default-features = false, features = ["blocking"] }`
//!
//! * `blocking` enables [`minreq`], the blocking client with proxy.
//! * `blocking-https` enables [`minreq`], the blocking client with proxy and TLS (SSL) capabilities
//!   using the default [`minreq`] backend.
//! * `blocking-https-rustls` enables [`minreq`], the blocking client with proxy and TLS (SSL)
//!   capabilities using the `rustls` backend.
//! * `blocking-https-native` enables [`minreq`], the blocking client with proxy and TLS (SSL)
//!   capabilities using the platform's native TLS backend (likely OpenSSL).
//! * `blocking-https-bundled` enables [`minreq`], the blocking client with proxy and TLS (SSL)
//!   capabilities using a bundled OpenSSL library backend.
//! * `blocking-wasm` enables [`minreq`], the blocking client without proxy.
//! * `tokio` enables [`tokio`], the default async runtime.
//! * `async` enables [`reqwest`], the async client with proxy capabilities.
//! * `async-https` enables [`reqwest`], the async client with support for proxying and TLS (SSL)
//!   using the default [`reqwest`] TLS backend.
//! * `async-https-native` enables [`reqwest`], the async client with support for proxying and TLS
//!   (SSL) using the platform's native TLS backend (likely OpenSSL).
//! * `async-https-rustls` enables [`reqwest`], the async client with support for proxying and TLS
//!   (SSL) using the `rustls` TLS backend.
//! * `async-https-rustls-manual-roots` enables [`reqwest`], the async client with support for
//!   proxying and TLS (SSL) using the `rustls` TLS backend without using its the default root
//!   certificates.

#![allow(clippy::result_large_err)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate serde_with;

use std::collections::HashMap;
use std::num::TryFromIntError;
use std::time::Duration;

use amplify::hex;
use bp::Txid;

#[cfg(feature = "async")]
pub use r#async::Sleeper;

pub mod api;
#[cfg(feature = "async")]
pub mod r#async;
#[cfg(feature = "blocking")]
pub mod blocking;

pub use api::*;
#[cfg(feature = "blocking")]
pub use blocking::BlockingClient;
#[cfg(feature = "async")]
pub use r#async::AsyncClient;

/// Response status codes for which the request may be retried.
const RETRYABLE_ERROR_CODES: [u16; 3] = [
    429, // TOO_MANY_REQUESTS
    500, // INTERNAL_SERVER_ERROR
    503, // SERVICE_UNAVAILABLE
];

/// Base backoff in milliseconds.
const BASE_BACKOFF_MILLIS: Duration = Duration::from_millis(256);

/// Default max retries.
const DEFAULT_MAX_RETRIES: usize = 6;

/// Get a fee value in sats/vbytes from the estimates
/// that matches the confirmation target set as parameter.
///
/// Returns `None` if no feerate estimate is found at or below `target`
/// confirmations.
pub fn convert_fee_rate(target: usize, estimates: HashMap<u16, f64>) -> Option<f32> {
    estimates
        .into_iter()
        .filter(|(k, _)| *k as usize <= target)
        .max_by_key(|(k, _)| *k)
        .map(|(_, v)| v as f32)
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Optional URL of the proxy to use to make requests to the Esplora server
    ///
    /// The string should be formatted as: `<protocol>://<user>:<password>@host:<port>`.
    ///
    /// Note that the format of this value and the supported protocols change slightly between the
    /// blocking version of the client (using `ureq`) and the async version (using `reqwest`). For more
    /// details check with the documentation of the two crates. Both of them are compiled with
    /// the `socks` feature enabled.
    ///
    /// The proxy is ignored when targeting `wasm32`.
    pub proxy: Option<String>,
    /// Socket timeout.
    pub timeout: Option<u64>,
    /// Number of times to retry a request.
    pub max_retries: usize,
    /// HTTP headers to set on every request made to Esplora server.
    pub headers: HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            proxy: None,
            timeout: Some(30),
            headers: HashMap::new(),
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Builder {
    /// The URL of the Esplora server.
    pub base_url: String,
    /// Optional URL of the proxy to use to make requests to the Esplora server
    ///
    /// The string should be formatted as:
    /// `<protocol>://<user>:<password>@host:<port>`.
    ///
    /// Note that the format of this value and the supported protocols change
    /// slightly between the blocking version of the client (using `minreq`)
    /// and the async version (using `reqwest`). For more details check with
    /// the documentation of the two crates. Both of them are compiled with
    /// the `socks` feature enabled.
    ///
    /// The proxy is ignored when targeting `wasm32`.
    pub proxy: Option<String>,
    /// Socket timeout.
    pub timeout: Option<u64>,
    /// HTTP headers to set on every request made to Esplora server.
    pub headers: HashMap<String, String>,
    /// Max retries
    pub max_retries: usize,
}

impl Builder {
    /// Instantiate a new builder
    pub fn new(base_url: &str) -> Self {
        Builder {
            base_url: base_url.to_string(),
            proxy: None,
            timeout: None,
            headers: HashMap::new(),
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }

    /// Instantiate a builder from a URL and a config
    pub fn from_config(base_url: &str, config: Config) -> Self {
        Builder {
            base_url: base_url.to_string(),
            proxy: config.proxy,
            timeout: config.timeout,
            headers: config.headers,
            max_retries: config.max_retries,
        }
    }

    /// Set the proxy of the builder
    pub fn proxy(mut self, proxy: &str) -> Self {
        self.proxy = Some(proxy.to_string());
        self
    }

    /// Set the timeout of the builder
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Add a header to set on each request
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Set the maximum number of times to retry a request if the response status
    /// is one of [`RETRYABLE_ERROR_CODES`].
    pub fn max_retries(mut self, count: usize) -> Self {
        self.max_retries = count;
        self
    }

    /// Build a blocking client from builder
    #[cfg(feature = "blocking")]
    pub fn build_blocking(self) -> Result<BlockingClient, Error> {
        BlockingClient::from_builder(self)
    }

    /// Build an asynchronous client from builder
    #[cfg(all(feature = "async", feature = "tokio"))]
    pub fn build_async(self) -> Result<AsyncClient, Error> {
        AsyncClient::from_builder(self)
    }

    /// Build an asynchronous client from builder where the returned client uses a
    /// user-defined [`Sleeper`].
    #[cfg(feature = "async")]
    pub fn build_async_with_sleeper<S: Sleeper>(self) -> Result<AsyncClient<S>, Error> {
        AsyncClient::from_builder(self)
    }
}

/// Errors that can happen during a request to `Esplora` servers.
#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    /// Error during `minreq` HTTP request
    #[cfg(feature = "blocking")]
    #[from]
    Minreq(minreq::Error),

    /// Error during reqwest HTTP request
    #[cfg(feature = "async")]
    #[from]
    Reqwest(reqwest::Error),

    /// HTTP response error {status}: {message}
    #[display(doc_comments)]
    HttpResponse { status: u16, message: String },

    /// The server sent an invalid response
    #[display(doc_comments)]
    InvalidServerData,

    /// Invalid number returned
    #[from]
    Parsing(std::num::ParseIntError),

    /// Invalid status code, unable to convert to `u16`
    #[display(doc_comments)]
    StatusCode(TryFromIntError),

    /// Invalid Bitcoin data returned
    #[display(doc_comments)]
    BitcoinEncoding,

    /// Invalid hex data returned
    #[from]
    Hex(hex::Error),

    /// Transaction {0} not found
    #[display(doc_comments)]
    TransactionNotFound(Txid),

    /// Invalid HTTP Header name specified
    #[display(doc_comments)]
    InvalidHttpHeaderName(String),

    /// Invalid HTTP Header value specified
    #[display(doc_comments)]
    InvalidHttpHeaderValue(String),
}
