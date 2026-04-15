// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

#[derive(Debug, Clone)]
pub struct BitstringStatusList {
    size: usize,
    bitstring: Vec<u8>,
    cache_ttl_seconds: u64,
    revocation_reasons: HashMap<usize, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusListCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    pub issuer: StatusListIssuer,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: StatusListSubject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusListIssuer {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusListSubject {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "statusPurpose")]
    pub status_purpose: String,
    #[serde(rename = "encodedList")]
    pub encoded_list: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationCheckResult {
    pub index: usize,
    pub revoked: bool,
    pub reason: String,
    pub credential_url: String,
    pub cached: bool,
}

impl BitstringStatusList {
    pub fn new(size: usize, cache_ttl_seconds: u64) -> Self {
        assert!(size % 8 == 0, "Size must be a multiple of 8");
        Self {
            size,
            bitstring: vec![0u8; size / 8],
            cache_ttl_seconds,
            revocation_reasons: HashMap::new(),
        }
    }

    pub fn with_default_size() -> Self {
        Self::new(131072, 300)
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn cache_ttl_seconds(&self) -> u64 {
        self.cache_ttl_seconds
    }

    pub fn set_status(&mut self, index: usize, revoked: bool, reason: &str) -> Result<(), String> {
        if index >= self.size {
            return Err(format!("Index {index} out of range [0, {})", self.size));
        }
        let byte_index = index / 8;
        let bit_index = index % 8;
        if revoked {
            self.bitstring[byte_index] |= 1 << (7 - bit_index);
            if !reason.is_empty() {
                self.revocation_reasons.insert(index, reason.to_string());
            }
        } else {
            self.bitstring[byte_index] &= !(1 << (7 - bit_index));
            self.revocation_reasons.remove(&index);
        }
        Ok(())
    }

    pub fn get_status(&self, index: usize) -> Result<bool, String> {
        if index >= self.size {
            return Err(format!("Index {index} out of range [0, {})", self.size));
        }
        let byte_index = index / 8;
        let bit_index = index % 8;
        Ok((self.bitstring[byte_index] & (1 << (7 - bit_index))) != 0)
    }

    pub fn get_revocation_reason(&self, index: usize) -> &str {
        self.revocation_reasons
            .get(&index)
            .map(|s| s.as_str())
            .unwrap_or("")
    }

    pub fn encode(&self) -> String {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&self.bitstring).unwrap();
        let compressed = encoder.finish().unwrap();
        URL_SAFE_NO_PAD.encode(&compressed)
    }

    pub fn decode(encoded: &str, size: usize) -> Result<Self, String> {
        let compressed = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| format!("Base64 decode error: {e}"))?;
        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let mut raw = Vec::new();
        decoder
            .read_to_end(&mut raw)
            .map_err(|e| format!("Zlib decompress error: {e}"))?;
        let expected_bytes = size / 8;
        if raw.len() < expected_bytes {
            raw.resize(expected_bytes, 0);
        }
        Ok(Self {
            size,
            bitstring: raw[..expected_bytes].to_vec(),
            cache_ttl_seconds: 300,
            revocation_reasons: HashMap::new(),
        })
    }

    pub fn to_status_list_credential(
        &self,
        credential_id: &str,
        issuer_did: &str,
    ) -> StatusListCredential {
        StatusListCredential {
            context: vec!["https://www.w3.org/ns/credentials/v2".into()],
            id: credential_id.to_string(),
            type_: vec![
                "VerifiableCredential".into(),
                "BitstringStatusListCredential".into(),
            ],
            issuer: StatusListIssuer {
                id: issuer_did.to_string(),
            },
            credential_subject: StatusListSubject {
                id: format!("{credential_id}#list"),
                type_: "BitstringStatusList".into(),
                status_purpose: "revocation".into(),
                encoded_list: self.encode(),
            },
        }
    }

    pub fn check_revocation(&self, index: usize) -> Result<RevocationCheckResult, String> {
        let revoked = self.get_status(index)?;
        let reason = self.get_revocation_reason(index).to_string();
        Ok(RevocationCheckResult {
            index,
            revoked,
            reason,
            credential_url: String::new(),
            cached: false,
        })
    }
}
