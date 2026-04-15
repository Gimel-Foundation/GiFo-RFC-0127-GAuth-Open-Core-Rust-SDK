// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtResult {
    pub compact: String,
    pub disclosures: Vec<String>,
    pub sd_digests: Vec<String>,
    pub holder_binding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtVerificationResult {
    pub valid: bool,
    pub jwt_payload: serde_json::Value,
    pub disclosed_claims: HashMap<String, serde_json::Value>,
    pub sd_digests_verified: Vec<String>,
    pub warnings: Vec<String>,
}

fn create_disclosure(
    claim_name: &str,
    claim_value: &serde_json::Value,
) -> (String, String) {
    let salt = uuid::Uuid::new_v4().to_string();
    let disclosure_array = serde_json::json!([salt, claim_name, claim_value]);
    let disclosure_json = serde_json::to_string(&disclosure_array).unwrap();
    let encoded = URL_SAFE_NO_PAD.encode(disclosure_json.as_bytes());
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(encoded.as_bytes()));
    (encoded, digest)
}

pub fn create_sd_jwt(
    vc_payload: &serde_json::Value,
    redacted_claims: &[&str],
) -> SdJwtResult {
    let mut disclosures = Vec::new();
    let mut sd_digests = Vec::new();

    let credential_subject = vc_payload
        .get("credentialSubject")
        .or_else(|| {
            vc_payload
                .get("vc")
                .and_then(|vc| vc.get("credentialSubject"))
        })
        .cloned()
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    if let Some(obj) = credential_subject.as_object() {
        for (key, value) in obj {
            if redacted_claims.contains(&key.as_str()) {
                let (encoded, digest) = create_disclosure(key, value);
                disclosures.push(encoded);
                sd_digests.push(digest);
            }
        }
    }

    let mut issuer_payload = vc_payload.clone();
    if !redacted_claims.is_empty() {
        if let Some(cs) = credential_subject.as_object() {
            let redacted_subject: serde_json::Map<String, serde_json::Value> = cs
                .iter()
                .filter(|(k, _)| !redacted_claims.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            if issuer_payload.get("credentialSubject").is_some() {
                issuer_payload["credentialSubject"] =
                    serde_json::Value::Object(redacted_subject);
            } else if let Some(vc) = issuer_payload.get_mut("vc") {
                vc["credentialSubject"] = serde_json::Value::Object(redacted_subject);
            }
        }

        if !sd_digests.is_empty() {
            issuer_payload["_sd"] = serde_json::json!(sd_digests);
            issuer_payload["_sd_alg"] = serde_json::json!("sha-256");
        }
    }

    let header = URL_SAFE_NO_PAD
        .encode(serde_json::json!({"alg": "ES256", "typ": "vc+sd-jwt"}).to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&issuer_payload).unwrap().as_bytes());
    let sig_placeholder = URL_SAFE_NO_PAD.encode(b"stub-signature");
    let compact_jwt = format!("{header}.{payload_b64}.{sig_placeholder}");

    let mut sd_jwt_compact = compact_jwt;
    for d in &disclosures {
        sd_jwt_compact = format!("{sd_jwt_compact}~{d}");
    }
    sd_jwt_compact.push('~');

    SdJwtResult {
        compact: sd_jwt_compact,
        disclosures,
        sd_digests,
        holder_binding: None,
    }
}

pub fn verify_sd_jwt_disclosures(sd_jwt_compact: &str) -> SdJwtVerificationResult {
    let parts: Vec<&str> = sd_jwt_compact.split('~').collect();
    let jwt_part = parts.first().copied().unwrap_or("");
    let disclosures: Vec<&str> = parts[1..].iter().copied().filter(|p| !p.is_empty()).collect();

    let jwt_segments: Vec<&str> = jwt_part.split('.').collect();
    let jwt_payload = if jwt_segments.len() >= 2 {
        URL_SAFE_NO_PAD
            .decode(jwt_segments[1])
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(serde_json::Value::Null)
    } else {
        serde_json::Value::Null
    };

    let expected_digests: Vec<String> = jwt_payload
        .get("_sd")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let mut disclosed_claims = HashMap::new();
    let mut verified_digests = Vec::new();
    let mut warnings = Vec::new();

    for disclosure in &disclosures {
        match URL_SAFE_NO_PAD.decode(disclosure) {
            Ok(decoded_bytes) => {
                if let Ok(arr) = serde_json::from_slice::<serde_json::Value>(&decoded_bytes) {
                    if let Some(array) = arr.as_array() {
                        if array.len() >= 3 {
                            let claim_name = array[1].as_str().unwrap_or("").to_string();
                            let claim_value = array[2].clone();

                            let computed_digest =
                                URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes()));

                            if expected_digests.contains(&computed_digest) {
                                verified_digests.push(computed_digest);
                                disclosed_claims.insert(claim_name, claim_value);
                            } else {
                                warnings.push(format!(
                                    "Disclosure digest not found in _sd array: {disclosure}"
                                ));
                            }
                        }
                    }
                }
            }
            Err(_) => {
                warnings.push(format!("Failed to decode disclosure: {disclosure}"));
            }
        }
    }

    let valid = !disclosures.is_empty()
        && warnings.is_empty()
        && verified_digests.len() == disclosures.len();

    SdJwtVerificationResult {
        valid,
        jwt_payload,
        disclosed_claims,
        sd_digests_verified: verified_digests,
        warnings,
    }
}
