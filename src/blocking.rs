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

//! Esplora by way of `minreq` HTTP client.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::str::FromStr;
use std::thread;

#[allow(unused_imports)]
use log::{debug, error, info, trace};
use sha2::{Digest, Sha256};

use minreq::{Proxy, Request, Response};

use amplify::hex::FromHex;
use bp::{BlockHash, BlockHeader, ConsensusDecode, ScriptPubkey, Tx, Txid};
use invoice::Address;

use crate::{
    AddressStats, BlockStatus, BlockSummary, Builder, Config, Error, MerkleProof, OutputStatus,
    TxStatus, BASE_BACKOFF_MILLIS, RETRYABLE_ERROR_CODES,
};

#[derive(Debug, Clone)]
pub struct BlockingClient {
    /// The URL of the Esplora server.
    url: String,
    /// The proxy is ignored when targeting `wasm32`.
    pub proxy: Option<String>,
    /// Socket timeout.
    pub timeout: Option<u64>,
    /// HTTP headers to set on every request made to Esplora server
    pub headers: HashMap<String, String>,
    /// Number of times to retry a request
    pub max_retries: usize,
}

impl BlockingClient {
    /// Build a blocking client from a [`Builder`]
    pub fn from_builder(builder: Builder) -> Result<Self, Error> {
        Ok(Self {
            url: builder.base_url,
            proxy: builder.proxy,
            timeout: builder.timeout,
            headers: builder.headers,
            max_retries: builder.max_retries,
        })
    }

    /// Build a blocking client from a [`Config`]
    pub fn from_config(base_url: &str, config: Config) -> Result<Self, Error> {
        Self::from_builder(Builder::from_config(base_url, config))
    }

    /// Get the underlying base URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Perform a raw HTTP GET request with the given URI `path`.
    pub fn get_request(&self, path: &str) -> Result<Request, Error> {
        let mut request = minreq::get(format!("{}{}", self.url, path));

        if let Some(proxy) = &self.proxy {
            let proxy = Proxy::new(proxy.as_str())?;
            request = request.with_proxy(proxy);
        }

        if let Some(timeout) = &self.timeout {
            request = request.with_timeout(*timeout);
        }

        if !self.headers.is_empty() {
            for (key, value) in &self.headers {
                request = request.with_header(key, value);
            }
        }

        Ok(request)
    }

    fn get_opt_response<T: ConsensusDecode>(&self, path: &str) -> Result<Option<T>, Error> {
        match self.get_with_retry(path) {
            Ok(resp) if is_status_not_found(resp.status_code) => Ok(None),
            Ok(resp) if !is_status_ok(resp.status_code) => {
                let status = u16::try_from(resp.status_code).map_err(Error::StatusCode)?;
                let message = resp.as_str().unwrap_or_default().to_string();
                Err(Error::HttpResponse { status, message })
            }
            Ok(resp) => Ok(Some(
                T::consensus_deserialize(resp.as_bytes()).map_err(|_| Error::InvalidServerData)?,
            )),
            Err(e) => Err(e),
        }
    }

    fn get_opt_response_txid(&self, path: &str) -> Result<Option<Txid>, Error> {
        match self.get_with_retry(path) {
            Ok(resp) if is_status_not_found(resp.status_code) => Ok(None),
            Ok(resp) if !is_status_ok(resp.status_code) => {
                let status = u16::try_from(resp.status_code).map_err(Error::StatusCode)?;
                let message = resp.as_str().unwrap_or_default().to_string();
                Err(Error::HttpResponse { status, message })
            }
            Ok(resp) => Ok(Some(
                Txid::from_str(resp.as_str().map_err(Error::Minreq)?).map_err(Error::Hex)?,
            )),
            Err(e) => Err(e),
        }
    }

    /*
    fn get_opt_response_hex<T: Decodable>(&self, path: &str) -> Result<Option<T>, Error> {
        match self.get_with_retry(path) {
            Ok(resp) if is_status_not_found(resp.status_code) => Ok(None),
            Ok(resp) if !is_status_ok(resp.status_code) => {
                let status = u16::try_from(resp.status_code).map_err(Error::StatusCode)?;
                let message = resp.as_str().unwrap_or_default().to_string();
                Err(Error::HttpResponse { status, message })
            }
            Ok(resp) => {
                let hex_str = resp.as_str().map_err(Error::Minreq)?;
                let hex_vec = Vec::from_hex(hex_str).unwrap();
                deserialize::<T>(&hex_vec)
                    .map_err(Error::BitcoinEncoding)
                    .map(|r| Some(r))
            }
            Err(e) => Err(e),
        }
    }
     */

    fn get_response_hex<T: ConsensusDecode>(&self, path: &str) -> Result<T, Error> {
        match self.get_with_retry(path) {
            Ok(resp) if !is_status_ok(resp.status_code) => {
                let status = u16::try_from(resp.status_code).map_err(Error::StatusCode)?;
                let message = resp.as_str().unwrap_or_default().to_string();
                Err(Error::HttpResponse { status, message })
            }
            Ok(resp) => {
                let hex_str = resp.as_str().map_err(Error::Minreq)?;
                let hex_vec = Vec::from_hex(hex_str).unwrap();
                T::consensus_deserialize(&hex_vec).map_err(|_| Error::BitcoinEncoding)
            }
            Err(e) => Err(e),
        }
    }

    fn get_response_json<'a, T: serde::de::DeserializeOwned>(
        &'a self,
        path: &'a str,
    ) -> Result<T, Error> {
        let response = self.get_with_retry(path);
        match response {
            Ok(resp) if !is_status_ok(resp.status_code) => {
                let status = u16::try_from(resp.status_code).map_err(Error::StatusCode)?;
                let message = resp.as_str().unwrap_or_default().to_string();
                Err(Error::HttpResponse { status, message })
            }
            Ok(resp) => Ok(resp.json::<T>().map_err(Error::Minreq)?),
            Err(e) => Err(e),
        }
    }

    fn get_opt_response_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Option<T>, Error> {
        match self.get_with_retry(path) {
            Ok(resp) if is_status_not_found(resp.status_code) => Ok(None),
            Ok(resp) if !is_status_ok(resp.status_code) => {
                let status = u16::try_from(resp.status_code).map_err(Error::StatusCode)?;
                let message = resp.as_str().unwrap_or_default().to_string();
                Err(Error::HttpResponse { status, message })
            }
            Ok(resp) => Ok(Some(resp.json::<T>()?)),
            Err(e) => Err(e),
        }
    }

    fn get_response_str(&self, path: &str) -> Result<String, Error> {
        match self.get_with_retry(path) {
            Ok(resp) if !is_status_ok(resp.status_code) => {
                let status = u16::try_from(resp.status_code).map_err(Error::StatusCode)?;
                let message = resp.as_str().unwrap_or_default().to_string();
                Err(Error::HttpResponse { status, message })
            }
            Ok(resp) => Ok(resp.as_str()?.to_string()),
            Err(e) => Err(e),
        }
    }

    /// Get a [`Tx`] option given its [`Txid`]
    pub fn tx(&self, txid: &Txid) -> Result<Option<Tx>, Error> {
        self.get_opt_response(&format!("/tx/{}/raw", txid))
    }

    /// Get a [`Tx`] given its [`Txid`].
    pub fn tx_no_opt(&self, txid: &Txid) -> Result<Tx, Error> {
        match self.tx(txid) {
            Ok(Some(tx)) => Ok(tx),
            Ok(None) => Err(Error::TransactionNotFound(*txid)),
            Err(e) => Err(e),
        }
    }

    /// Get a [`Txid`] of a transaction given its index in a block with a given hash.
    pub fn txid_at_block_index(
        &self,
        block_hash: &BlockHash,
        index: usize,
    ) -> Result<Option<Txid>, Error> {
        self.get_opt_response_txid(&format!("/block/{}/txid/{}", block_hash, index))
    }

    /// Get the status of a [`Tx`] given its [`Txid`].
    pub fn tx_status(&self, txid: &Txid) -> Result<TxStatus, Error> {
        self.get_response_json(&format!("/tx/{}/status", txid))
    }

    /// Get transaction info given it's [`Txid`].
    pub fn tx_info(&self, txid: &Txid) -> Result<Option<crate::Tx>, Error> {
        self.get_opt_response_json(&format!("/tx/{}", txid))
    }

    /// Get a [`BlockHeader`] given a particular block hash.
    pub fn header_by_hash(&self, block_hash: &BlockHash) -> Result<BlockHeader, Error> {
        self.get_response_hex(&format!("/block/{}/header", block_hash))
    }

    /// Get the [`BlockStatus`] given a particular [`BlockHash`].
    pub fn block_status(&self, block_hash: &BlockHash) -> Result<BlockStatus, Error> {
        self.get_response_json(&format!("/block/{}/status", block_hash))
    }

    /* TODO: Uncomment once `bp-primitives` will support blocks
    /// Get a [`Block`] given a particular [`BlockHash`].
    pub fn block_by_hash(&self, block_hash: &BlockHash) -> Result<Option<Block>, Error> {
        self.get_opt_response(&format!("/block/{}/raw", block_hash))
    }
     */

    /// Get a merkle inclusion proof for a [`Tx`] with the given [`Txid`].
    pub fn merkle_proof(&self, txid: &Txid) -> Result<Option<MerkleProof>, Error> {
        self.get_opt_response_json(&format!("/tx/{}/merkle-proof", txid))
    }

    /* TODO: Uncomment once `bp-primitives` will support blocks
    /// Get a [`MerkleBlock`] inclusion proof for a [`Tx`] with the given [`Txid`].
    pub fn merkle_block(&self, txid: &Txid) -> Result<Option<MerkleBlock>, Error> {
        self.get_opt_response_hex(&format!("/tx/{}/merkleblock-proof", txid))
    }
     */

    /// Get the spending status of an output given a [`Txid`] and the output index.
    pub fn output_status(&self, txid: &Txid, index: u64) -> Result<Option<OutputStatus>, Error> {
        self.get_opt_response_json(&format!("/tx/{}/outspend/{}", txid, index))
    }

    /// Broadcast a [`Tx`] to Esplora
    pub fn broadcast(&self, transaction: &Tx) -> Result<(), Error> {
        let mut request = minreq::post(format!("{}/tx", self.url))
            .with_body(format!("{transaction:x}").as_bytes().to_vec());

        if let Some(proxy) = &self.proxy {
            let proxy = Proxy::new(proxy.as_str())?;
            request = request.with_proxy(proxy);
        }

        if let Some(timeout) = &self.timeout {
            request = request.with_timeout(*timeout);
        }

        match request.send() {
            Ok(resp) if !is_status_ok(resp.status_code) => {
                let status = u16::try_from(resp.status_code).map_err(Error::StatusCode)?;
                let message = resp.as_str().unwrap_or_default().to_string();
                Err(Error::HttpResponse { status, message })
            }
            Ok(_resp) => Ok(()),
            Err(e) => Err(Error::Minreq(e)),
        }
    }

    /// Get the height of the current blockchain tip.
    pub fn height(&self) -> Result<u32, Error> {
        self.get_response_str("/blocks/tip/height")
            .map(|s| u32::from_str(s.as_str()).map_err(Error::Parsing))?
    }

    /// Get the [`BlockHash`] of the current blockchain tip.
    pub fn tip_hash(&self) -> Result<BlockHash, Error> {
        self.get_response_str("/blocks/tip/hash")
            .map(|s| BlockHash::from_str(s.as_str()).map_err(Error::Hex))?
    }

    /// Get the [`BlockHash`] of a specific block height
    pub fn block_hash(&self, block_height: u32) -> Result<BlockHash, Error> {
        self.get_response_str(&format!("/block-height/{}", block_height))
            .map(|s| BlockHash::from_str(s.as_str()).map_err(Error::Hex))?
    }

    /// Get an map where the key is the confirmation target (in number of blocks)
    /// and the value is the estimated feerate (in sat/vB).
    pub fn fee_estimates(&self) -> Result<HashMap<u16, f64>, Error> {
        self.get_response_json("/fee-estimates")
    }

    /// Get information about a specific address, includes confirmed balance and transactions in
    /// the mempool.
    pub fn address_stats(&self, address: &Address) -> Result<AddressStats, Error> {
        let path = format!("/address/{address}");
        self.get_response_json(&path)
    }

    /// Get transaction history for the specified address/scripthash, sorted with newest first.
    ///
    /// Returns up to 50 mempool transactions plus the first 25 confirmed transactions.
    /// More can be requested by specifying the last txid seen by the previous query.
    pub fn address_txs(
        &self,
        address: &Address,
        last_seen: Option<Txid>,
    ) -> Result<Vec<crate::Tx>, Error> {
        let path = match last_seen {
            Some(last_seen) => format!("/address/{address}/txs/chain/{last_seen}"),
            None => format!("/address/{address}/txs"),
        };

        self.get_response_json(&path)
    }

    /// Get confirmed transaction history for the specified address/scripthash,
    /// sorted with newest first. Returns 25 transactions per page.
    /// More can be requested by specifying the last txid seen by the previous query.
    pub fn scripthash_txs(
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
        self.get_response_json(&path)
    }

    /// Gets some recent block summaries starting at the tip or at `height` if provided.
    ///
    /// The maximum number of summaries returned depends on the backend itself:
    /// esplora returns `10` while [mempool.space](https://mempool.space/docs/api) returns `15`.
    pub fn blocks(&self, height: Option<u32>) -> Result<Vec<BlockSummary>, Error> {
        let path = match height {
            Some(height) => format!("/blocks/{}", height),
            None => "/blocks".to_string(),
        };
        let blocks: Vec<BlockSummary> = self.get_response_json(&path)?;
        if blocks.is_empty() {
            return Err(Error::InvalidServerData);
        }
        Ok(blocks)
    }

    /// Sends a GET request to the given `url`, retrying failed attempts
    /// for retryable error codes until max retries hit.
    fn get_with_retry(&self, url: &str) -> Result<Response, Error> {
        let mut delay = BASE_BACKOFF_MILLIS;
        let mut attempts = 0;

        loop {
            match self.get_request(url)?.send()? {
                resp if attempts < self.max_retries && is_status_retryable(resp.status_code) => {
                    thread::sleep(delay);
                    attempts += 1;
                    delay *= 2;
                }
                resp => return Ok(resp),
            }
        }
    }
}

fn is_status_ok(status: i32) -> bool {
    status == 200
}

fn is_status_not_found(status: i32) -> bool {
    status == 404
}

fn is_status_retryable(status: i32) -> bool {
    let status = status as u16;
    RETRYABLE_ERROR_CODES.contains(&status)
}
