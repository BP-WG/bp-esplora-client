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
use std::io::Cursor;
use std::str::FromStr;

use bpstd::{BlockHash, ConsensusDecode, ScriptPubkey, Tx, Txid};

#[allow(unused_imports)]
use log::{debug, error, info, trace};

use reqwest::{Client, StatusCode};
use sha2::{Digest, Sha256};

use crate::{BlockStatus, BlockSummary, Builder, Error, OutputStatus, TxStatus};

#[derive(Debug, Clone)]
pub struct AsyncClient {
    url: String,
    client: Client,
}

impl AsyncClient {
    /// build an async client from a builder
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

        Ok(Self::from_client(builder.base_url, client_builder.build()?))
    }

    /// build an async client from the base url and [`Client`]
    pub fn from_client(url: String, client: Client) -> Self {
        AsyncClient { url, client }
    }

    /// Get a [`Transaction`] option given its [`Txid`]
    pub async fn tx(&self, txid: &Txid) -> Result<Option<Tx>, Error> {
        let resp = self
            .client
            .get(&format!("{}/tx/{}/raw", self.url, txid))
            .send()
            .await?;

        if let StatusCode::NOT_FOUND = resp.status() {
            return Ok(None);
        }

        let bytes = resp.error_for_status()?.bytes().await?;
        let tx =
            Tx::consensus_decode(&mut Cursor::new(bytes)).map_err(|_| Error::InvalidServerData)?;
        Ok(Some(tx))
    }

    /// Get a [`Transaction`] given its [`Txid`].
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
        let resp = self
            .client
            .get(&format!("{}/block/{}/txid/{}", self.url, block_hash, index))
            .send()
            .await?;

        if let StatusCode::NOT_FOUND = resp.status() {
            return Ok(None);
        }

        Ok(Some(Txid::from_str(&resp.text().await?)?))
    }

    /// Get the status of a [`Transaction`] given its [`Txid`].
    pub async fn tx_status(&self, txid: &Txid) -> Result<TxStatus, Error> {
        let resp = self
            .client
            .get(&format!("{}/tx/{}/status", self.url, txid))
            .send()
            .await?;

        Ok(resp.error_for_status()?.json().await?)
    }

    /* Uncomment once `bp-primitives` will support consensus serialziation
    /// Get a [`BlockHeader`] given a particular block hash.
    pub async fn header_by_hash(&self, block_hash: &BlockHash) -> Result<BlockHeader, Error> {
        let resp = self
            .client
            .get(&format!("{}/block/{}/header", self.url, block_hash))
            .send()
            .await?;

        let header = deserialize(&Vec::from_hex(&resp.text().await?)?)?;

        Ok(header)
    }
     */

    /// Get the [`BlockStatus`] given a particular [`BlockHash`].
    pub async fn block_status(&self, block_hash: &BlockHash) -> Result<BlockStatus, Error> {
        let resp = self
            .client
            .get(&format!("{}/block/{}/status", self.url, block_hash))
            .send()
            .await?;

        Ok(resp.error_for_status()?.json().await?)
    }

    /* TODO: Uncomment once `bp-primitives` will support blocks
    /// Get a [`Block`] given a particular [`BlockHash`].
    pub async fn block_by_hash(&self, block_hash: &BlockHash) -> Result<Option<Block>, Error> {
        let resp = self
            .client
            .get(&format!("{}/block/{}/raw", self.url, block_hash))
            .send()
            .await?;

        if let StatusCode::NOT_FOUND = resp.status() {
            return Ok(None);
        }
        Ok(Some(deserialize(&resp.error_for_status()?.bytes().await?)?))
    }

    /// Get a merkle inclusion proof for a [`Transaction`] with the given [`Txid`].
    pub async fn merkle_proof(&self, tx_hash: &Txid) -> Result<Option<MerkleProof>, Error> {
        let resp = self
            .client
            .get(&format!("{}/tx/{}/merkle-proof", self.url, tx_hash))
            .send()
            .await?;

        if let StatusCode::NOT_FOUND = resp.status() {
            return Ok(None);
        }

        Ok(Some(resp.error_for_status()?.json().await?))
    }

    /// Get a [`MerkleBlock`] inclusion proof for a [`Transaction`] with the given [`Txid`].
    pub async fn merkle_block(&self, tx_hash: &Txid) -> Result<Option<MerkleBlock>, Error> {
        let resp = self
            .client
            .get(&format!("{}/tx/{}/merkleblock-proof", self.url, tx_hash))
            .send()
            .await?;

        if let StatusCode::NOT_FOUND = resp.status() {
            return Ok(None);
        }

        let merkle_block = deserialize(&Vec::from_hex(&resp.text().await?)?)?;

        Ok(Some(merkle_block))
    }
     */

    /// Get the spending status of an output given a [`Txid`] and the output index.
    pub async fn output_status(
        &self,
        txid: &Txid,
        index: u64,
    ) -> Result<Option<OutputStatus>, Error> {
        let resp = self
            .client
            .get(&format!("{}/tx/{}/outspend/{}", self.url, txid, index))
            .send()
            .await?;

        if let StatusCode::NOT_FOUND = resp.status() {
            return Ok(None);
        }

        Ok(Some(resp.error_for_status()?.json().await?))
    }

    /* Uncomment once `bp-primitives` will support consensus serialziation
    /// Broadcast a [`Transaction`] to Esplora
    pub async fn broadcast(&self, transaction: &Transaction) -> Result<(), Error> {
        self.client
            .post(&format!("{}/tx", self.url))
            .body(serialize(transaction).to_lower_hex_string())
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
     */

    /// Get the current height of the blockchain tip
    pub async fn height(&self) -> Result<u32, Error> {
        let resp = self
            .client
            .get(&format!("{}/blocks/tip/height", self.url))
            .send()
            .await?;

        Ok(resp.error_for_status()?.text().await?.parse()?)
    }

    /// Get the [`BlockHash`] of the current blockchain tip.
    pub async fn tip_hash(&self) -> Result<BlockHash, Error> {
        let resp = self
            .client
            .get(&format!("{}/blocks/tip/hash", self.url))
            .send()
            .await?;

        Ok(BlockHash::from_str(
            &resp.error_for_status()?.text().await?,
        )?)
    }

    /// Get the [`BlockHash`] of a specific block height
    pub async fn block_hash(&self, block_height: u32) -> Result<BlockHash, Error> {
        let resp = self
            .client
            .get(&format!("{}/block-height/{}", self.url, block_height))
            .send()
            .await?;

        if let StatusCode::NOT_FOUND = resp.status() {
            return Err(Error::HeaderHeightNotFound(block_height));
        }

        Ok(BlockHash::from_str(
            &resp.error_for_status()?.text().await?,
        )?)
    }

    /// Get confirmed transaction history for the specified address/scripthash,
    /// sorted with newest first. Returns 25 transactions per page.
    /// More can be requested by specifying the last txid seen by the previous query.
    pub async fn scripthash_txs(
        &self,
        script: &ScriptPubkey,
        last_seen: Option<Txid>,
    ) -> Result<Vec<Tx>, Error> {
        let mut hasher = Sha256::default();
        hasher.update(script);
        let script_hash = hasher.finalize();
        let url = match last_seen {
            Some(last_seen) => format!(
                "{}/scripthash/{:x}/txs/chain/{}",
                self.url, script_hash, last_seen
            ),
            None => format!("{}/scripthash/{:x}/txs", self.url, script_hash),
        };
        Ok(self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<Tx>>()
            .await?)
    }

    /// Get an map where the key is the confirmation target (in number of blocks)
    /// and the value is the estimated feerate (in sat/vB).
    pub async fn fee_estimates(&self) -> Result<HashMap<String, f64>, Error> {
        Ok(self
            .client
            .get(&format!("{}/fee-estimates", self.url,))
            .send()
            .await?
            .error_for_status()?
            .json::<HashMap<String, f64>>()
            .await?)
    }

    /// Gets some recent block summaries starting at the tip or at `height` if provided.
    ///
    /// The maximum number of summaries returned depends on the backend itself: esplora returns `10`
    /// while [mempool.space](https://mempool.space/docs/api) returns `15`.
    pub async fn blocks(&self, height: Option<u32>) -> Result<Vec<BlockSummary>, Error> {
        let url = match height {
            Some(height) => format!("{}/blocks/{}", self.url, height),
            None => format!("{}/blocks", self.url),
        };

        Ok(self
            .client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Get the underlying base URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the underlying [`Client`].
    pub fn client(&self) -> &Client {
        &self.client
    }
}
