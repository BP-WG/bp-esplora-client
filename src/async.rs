// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Esplora by way of `reqwest` HTTP client.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::str::FromStr;

use bp::{BlockHash, BlockHeader, ConsensusDecode, ConsensusEncode, ScriptPubkey, Tx, Txid};
use invoice::Address;

#[allow(unused_imports)]
use log::{debug, error, info, trace};

use amplify::hex::{FromHex, ToHex};
use reqwest::{header, Client, Response};
use sha2::{Digest, Sha256};

use crate::{
    AddressStats, BlockStatus, BlockSummary, Builder, Config, Error, MerkleProof, OutputStatus,
    TxStatus, BASE_BACKOFF_MILLIS, RETRYABLE_ERROR_CODES,
};

#[derive(Debug, Clone)]
pub struct AsyncClient<S = DefaultSleeper> {
    /// The URL of the Esplora Server.
    url: String,
    /// The inner [`reqwest::Client`] to make HTTP requests.
    client: Client,
    /// Number of times to retry a request
    max_retries: usize,

    /// Marker for the type of sleeper used
    marker: PhantomData<S>,
}

impl<S: Sleeper> AsyncClient<S> {
    /// Build an async client from a [`Builder`]
    pub fn from_builder(builder: Builder) -> Result<Self, Error> {
        let mut client_builder = Client::builder();

        #[cfg(not(target_arch = "wasm32"))]
        if let Some(proxy) = &builder.proxy {
            client_builder = client_builder.proxy(reqwest::Proxy::all(proxy)?);
        }

        #[cfg(not(target_arch = "wasm32"))]
        if let Some(timeout) = builder.timeout {
            client_builder = client_builder.timeout(core::time::Duration::from_secs(timeout));
        }

        if !builder.headers.is_empty() {
            let mut headers = header::HeaderMap::new();
            for (k, v) in builder.headers {
                let header_name = header::HeaderName::from_lowercase(k.to_lowercase().as_bytes())
                    .map_err(|_| Error::InvalidHttpHeaderName(k))?;
                let header_value = header::HeaderValue::from_str(&v)
                    .map_err(|_| Error::InvalidHttpHeaderValue(v))?;
                headers.insert(header_name, header_value);
            }
            client_builder = client_builder.default_headers(headers);
        }

        Ok(AsyncClient {
            url: builder.base_url,
            client: client_builder.build()?,
            max_retries: builder.max_retries,
            marker: PhantomData,
        })
    }

    /// Build an async client from a [`Config`]
    pub fn from_config(base_url: &str, config: Config) -> Result<Self, Error> {
        Self::from_builder(Builder::from_config(base_url, config))
    }

    /// Build an async client from the base url and [`Client`]
    pub fn from_client(url: String, client: Client) -> Self {
        AsyncClient {
            url,
            client,
            max_retries: crate::DEFAULT_MAX_RETRIES,
            marker: PhantomData,
        }
    }

    /// Make an HTTP GET request to given URL, deserializing to any `T` that
    /// implement [`bc::ConsensusDecode`].
    ///
    /// It should be used when requesting Esplora endpoints that can be directly
    /// deserialized to native `rust-bitcoin` types, which implements
    /// [`bc::ConsensusDecode`] from `&[u8]`.
    ///
    /// # Errors
    ///
    /// This function will return an error either from the HTTP client, or the
    /// [`bc::ConsensusDecode`] deserialization.
    async fn get_response<T: ConsensusDecode>(&self, path: &str) -> Result<T, Error> {
        let url = format!("{}{}", self.url, path);
        let response = self.get_with_retry(&url).await?;

        if !response.status().is_success() {
            return Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            });
        }

        T::consensus_deserialize(&response.bytes().await?).map_err(|_| Error::InvalidServerData)
    }

    /// Make an HTTP GET request to given URL, deserializing to `Option<T>`.
    ///
    /// It uses [`AsyncEsploraClient::get_response`] internally.
    ///
    /// See [`AsyncEsploraClient::get_response`] above for full documentation.
    async fn get_opt_response<T: ConsensusDecode>(&self, path: &str) -> Result<Option<T>, Error> {
        match self.get_response::<T>(path).await {
            Ok(res) => Ok(Some(res)),
            Err(Error::HttpResponse { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Make an HTTP GET request to given URL, deserializing to any `T` that
    /// implements [`serde::de::DeserializeOwned`].
    ///
    /// It should be used when requesting Esplora endpoints that have a specific
    /// defined API, mostly defined in [`crate::api`].
    ///
    /// # Errors
    ///
    /// This function will return an error either from the HTTP client, or the
    /// [`serde::de::DeserializeOwned`] deserialization.
    async fn get_response_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, Error> {
        let url = format!("{}{}", self.url, path);
        let response = self.get_with_retry(&url).await?;

        if !response.status().is_success() {
            return Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            });
        }

        response.json::<T>().await.map_err(Error::Reqwest)
    }

    /// Make an HTTP GET request to given URL, deserializing to `Option<T>`.
    ///
    /// It uses [`AsyncEsploraClient::get_response_json`] internally.
    ///
    /// See [`AsyncEsploraClient::get_response_json`] above for full
    /// documentation.
    async fn get_opt_response_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<Option<T>, Error> {
        match self.get_response_json(url).await {
            Ok(res) => Ok(Some(res)),
            Err(Error::HttpResponse { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Make an HTTP GET request to given URL, deserializing to any `T` that
    /// implements [`bc::ConsensusDecode`].
    ///
    /// It should be used when requesting Esplora endpoints that are expected
    /// to return a hex string decodable to native `rust-bitcoin` types which
    /// implement [`bc::ConsensusDecode`] from `&[u8]`.
    ///
    /// # Errors
    ///
    /// This function will return an error either from the HTTP client, or the
    /// [`bc::ConsensusDecode`] deserialization.
    async fn get_response_hex<T: ConsensusDecode>(&self, path: &str) -> Result<T, Error> {
        let url = format!("{}{}", self.url, path);
        let response = self.get_with_retry(&url).await?;

        if !response.status().is_success() {
            return Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            });
        }

        let hex_str = response.text().await?;
        T::consensus_deserialize(&Vec::from_hex(&hex_str)?).map_err(|_| Error::BitcoinEncoding)
    }

    /*
    /// Make an HTTP GET request to given URL, deserializing to `Option<T>`.
    ///
    /// It uses [`AsyncEsploraClient::get_response_hex`] internally.
    ///
    /// See [`AsyncEsploraClient::get_response_hex`] above for full
    /// documentation.
    async fn get_opt_response_hex<T: Decodable>(&self, path: &str) -> Result<Option<T>, Error> {
        match self.get_response_hex(path).await {
            Ok(res) => Ok(Some(res)),
            Err(Error::HttpResponse { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }
    */

    /// Make an HTTP GET request to given URL, deserializing to `String`.
    ///
    /// It should be used when requesting Esplora endpoints that can return
    /// `String` formatted data that can be parsed downstream.
    ///
    /// # Errors
    ///
    /// This function will return an error either from the HTTP client.
    async fn get_response_text(&self, path: &str) -> Result<String, Error> {
        let url = format!("{}{}", self.url, path);
        let response = self.get_with_retry(&url).await?;

        if !response.status().is_success() {
            return Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            });
        }

        Ok(response.text().await?)
    }

    /// Make an HTTP GET request to given URL, deserializing to `Option<T>`.
    ///
    /// It uses [`AsyncEsploraClient::get_response_text`] internally.
    ///
    /// See [`AsyncEsploraClient::get_response_text`] above for full documentation.
    async fn get_opt_response_text(&self, path: &str) -> Result<Option<String>, Error> {
        match self.get_response_text(path).await {
            Ok(s) => Ok(Some(s)),
            Err(Error::HttpResponse { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Make an HTTP POST request to given URL, serializing from any `T` that
    /// implement [`bc::ConsensusEncode`].
    ///
    /// It should be used when requesting Esplora endpoints that expected a
    /// native bitcoin type serialized with [`bc::ConsensusEncode`].
    ///
    /// # Errors
    ///
    /// This function will return an error either from the HTTP client, or the
    /// [`bc::ConsensusEncode`] serialization.
    async fn post_request_hex<T: ConsensusEncode>(&self, path: &str, body: T) -> Result<(), Error> {
        let url = format!("{}{}", self.url, path);
        let body = T::consensus_serialize(&body).to_hex();

        let response = self.client.post(url).body(body).send().await?;

        if !response.status().is_success() {
            return Err(Error::HttpResponse {
                status: response.status().as_u16(),
                message: response.text().await?,
            });
        }

        Ok(())
    }

    /// Get a [`Tx`] option given its [`Txid`]
    pub async fn tx(&self, txid: &Txid) -> Result<Option<Tx>, Error> {
        self.get_opt_response(&format!("/tx/{txid}/raw")).await
    }

    /// Get a [`Tx`] given its [`Txid`].
    pub async fn tx_no_opt(&self, txid: &Txid) -> Result<Tx, Error> {
        match self.tx(txid).await {
            Ok(Some(tx)) => Ok(tx),
            Ok(None) => Err(Error::TransactionNotFound(*txid)),
            Err(e) => Err(e),
        }
    }

    /// Get a [`Txid`] of a transaction given its index in a block with a given hash.
    pub async fn txid_at_block_index(
        &self,
        block_hash: &BlockHash,
        index: usize,
    ) -> Result<Option<Txid>, Error> {
        match self
            .get_opt_response_text(&format!("/block/{block_hash}/txid/{index}"))
            .await?
        {
            Some(s) => Ok(Some(Txid::from_str(&s).map_err(Error::Hex)?)),
            None => Ok(None),
        }
    }

    /// Get the status of a [`Tx`] given its [`Txid`].
    pub async fn tx_status(&self, txid: &Txid) -> Result<TxStatus, Error> {
        self.get_response_json(&format!("/tx/{txid}/status")).await
    }

    /// Get transaction info given it's [`Txid`].
    pub async fn tx_info(&self, txid: &Txid) -> Result<Option<crate::Tx>, Error> {
        self.get_opt_response_json(&format!("/tx/{txid}")).await
    }

    /// Get a [`BlockHeader`] given a particular block hash.
    pub async fn header_by_hash(&self, block_hash: &BlockHash) -> Result<BlockHeader, Error> {
        self.get_response_hex(&format!("/block/{block_hash}/header"))
            .await
    }

    /// Get the [`BlockStatus`] given a particular [`BlockHash`].
    pub async fn block_status(&self, block_hash: &BlockHash) -> Result<BlockStatus, Error> {
        self.get_response_json(&format!("/block/{block_hash}/status"))
            .await
    }

    /* TODO: Uncomment once `bp-primitives` will support blocks
    /// Get a [`Block`] given a particular [`BlockHash`].
    pub async fn block_by_hash(&self, block_hash: &BlockHash) -> Result<Option<Block>, Error> {
        self.get_opt_response(&format!("/block/{block_hash}/raw"))
            .await
    }
     */

    /// Get a merkle inclusion proof for a [`Tx`] with the given [`Txid`].
    pub async fn merkle_proof(&self, tx_hash: &Txid) -> Result<Option<MerkleProof>, Error> {
        self.get_opt_response_json(&format!("/tx/{tx_hash}/merkle-proof"))
            .await
    }

    /* TODO: Uncomment once `bp-primitives` will support blocks
    /// Get a [`MerkleBlock`] inclusion proof for a [`Tx`] with the given [`Txid`].
    pub async fn merkle_block(&self, tx_hash: &Txid) -> Result<Option<MerkleBlock>, Error> {
        self.get_opt_response_hex(&format!("/tx/{tx_hash}/merkleblock-proof"))
            .await
    }
     */

    /// Get the spending status of an output given a [`Txid`] and the output index.
    pub async fn output_status(
        &self,
        txid: &Txid,
        index: u64,
    ) -> Result<Option<OutputStatus>, Error> {
        self.get_opt_response_json(&format!("/tx/{txid}/outspend/{index}"))
            .await
    }

    /// Broadcast a [`Tx`] to Esplora
    pub async fn broadcast(&self, transaction: &Tx) -> Result<(), Error> {
        self.post_request_hex("/tx", transaction.clone()).await
    }

    /// Get the current height of the blockchain tip
    pub async fn height(&self) -> Result<u32, Error> {
        self.get_response_text("/blocks/tip/height")
            .await
            .map(|height| u32::from_str(&height).map_err(Error::Parsing))?
    }

    /// Get the [`BlockHash`] of the current blockchain tip.
    pub async fn tip_hash(&self) -> Result<BlockHash, Error> {
        self.get_response_text("/blocks/tip/hash")
            .await
            .map(|block_hash| BlockHash::from_str(&block_hash).map_err(Error::Hex))?
    }

    /// Get the [`BlockHash`] of a specific block height
    pub async fn block_hash(&self, block_height: u32) -> Result<BlockHash, Error> {
        self.get_response_text(&format!("/block-height/{block_height}"))
            .await
            .map(|block_hash| BlockHash::from_str(&block_hash).map_err(Error::Hex))?
    }

    /// Get information about a specific address, includes confirmed balance and transactions in
    /// the mempool.
    pub async fn address_stats(&self, address: &Address) -> Result<AddressStats, Error> {
        let path = format!("/address/{address}");
        self.get_response_json(&path).await
    }

    /// Get transaction history for the specified address/scripthash, sorted with newest first.
    ///
    /// Returns up to 50 mempool transactions plus the first 25 confirmed transactions.
    /// More can be requested by specifying the last txid seen by the previous query.
    pub async fn address_txs(
        &self,
        address: &Address,
        last_seen: Option<Txid>,
    ) -> Result<Vec<crate::Tx>, Error> {
        let path = match last_seen {
            Some(last_seen) => format!("/address/{address}/txs/chain/{last_seen}"),
            None => format!("/address/{address}/txs"),
        };

        self.get_response_json(&path).await
    }

    /// Get confirmed transaction history for the specified address/scripthash,
    /// sorted with newest first. Returns 25 transactions per page.
    /// More can be requested by specifying the last txid seen by the previous query.
    pub async fn scripthash_txs(
        &self,
        script: &ScriptPubkey,
        last_seen: Option<Txid>,
    ) -> Result<Vec<crate::Tx>, Error> {
        let mut hasher = Sha256::default();
        hasher.update(script);
        let script_hash = hasher.finalize();
        let path = match last_seen {
            Some(last_seen) => format!("/scripthash/{:x}/txs/chain/{}", script_hash, last_seen),
            None => format!("/scripthash/{:x}/txs", script_hash),
        };

        self.get_response_json(&path).await
    }

    /// Get unspent transaction outputs for the specified address.
    pub async fn address_utxo(
        &self,
        address: &Address,
    ) -> Result<Vec<crate::Utxo>, Error> {
        let path = format!("/address/{address}/utxo");
        self.get_response_json(&path).await
    }

    /// Get unspent transaction outputs for the specified scripthash.
    pub async fn scripthash_utxo(
        &self,
        script: &ScriptPubkey,
    ) -> Result<Vec<crate::Utxo>, Error> {
        let mut hasher = Sha256::default();
        hasher.update(script);
        let script_hash = hasher.finalize();
        let path = format!("/scripthash/{script_hash:x}/utxo");
        self.get_response_json(&path).await
    }

    /// Get an map where the key is the confirmation target (in number of blocks)
    /// and the value is the estimated feerate (in sat/vB).
    pub async fn fee_estimates(&self) -> Result<HashMap<u16, f64>, Error> {
        self.get_response_json("/fee-estimates").await
    }

    /// Gets some recent block summaries starting at the tip or at `height` if provided.
    ///
    /// The maximum number of summaries returned depends on the backend itself:
    /// esplora returns `10` while [mempool.space](https://mempool.space/docs/api) returns `15`.
    pub async fn blocks(&self, height: Option<u32>) -> Result<Vec<BlockSummary>, Error> {
        let path = match height {
            Some(height) => format!("/blocks/{height}"),
            None => "/blocks".to_string(),
        };
        let blocks: Vec<BlockSummary> = self.get_response_json(&path).await?;
        if blocks.is_empty() {
            return Err(Error::InvalidServerData);
        }
        Ok(blocks)
    }

    /// Get the underlying base URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the underlying [`Client`].
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Sends a GET request to the given `url`, retrying failed attempts
    /// for retryable error codes until max retries hit.
    async fn get_with_retry(&self, url: &str) -> Result<Response, Error> {
        let mut delay = BASE_BACKOFF_MILLIS;
        let mut attempts = 0;

        loop {
            match self.client.get(url).send().await? {
                resp if attempts < self.max_retries && is_status_retryable(resp.status()) => {
                    S::sleep(delay).await;
                    attempts += 1;
                    delay *= 2;
                }
                resp => return Ok(resp),
            }
        }
    }
}

fn is_status_retryable(status: reqwest::StatusCode) -> bool {
    RETRYABLE_ERROR_CODES.contains(&status.as_u16())
}

pub trait Sleeper: 'static {
    type Sleep: std::future::Future<Output = ()>;
    fn sleep(dur: std::time::Duration) -> Self::Sleep;
}

#[derive(Debug, Clone, Copy)]
pub struct DefaultSleeper;

#[cfg(any(test, feature = "tokio"))]
impl Sleeper for DefaultSleeper {
    type Sleep = tokio::time::Sleep;

    fn sleep(dur: std::time::Duration) -> Self::Sleep {
        tokio::time::sleep(dur)
    }
}
