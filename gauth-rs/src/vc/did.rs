// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<DidService>>,
    #[serde(rename = "_resolution", skip_serializing_if = "Option::is_none")]
    pub resolution: Option<DidResolution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub controller: String,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidService {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidResolution {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_url: Option<String>,
    pub resolved: bool,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidKeyResult {
    pub did: String,
    pub multibase_key: String,
    pub did_document: DidDocument,
}

pub fn resolve_did_web(did: &str) -> Result<DidDocument, String> {
    if !did.starts_with("did:web:") {
        return Err(format!("Not a did:web identifier: {did}"));
    }

    let remainder = &did[8..];
    let parts: Vec<&str> = remainder.split(':').collect();
    let domain = parts[0];
    let path_parts = &parts[1..];

    let doc_url = if path_parts.is_empty() {
        format!("https://{domain}/.well-known/did.json")
    } else {
        let path = path_parts.join("/");
        format!("https://{domain}/{path}/did.json")
    };

    let verification_method_id = format!("{did}#key-1");

    Ok(DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".into()],
        id: did.to_string(),
        verification_method: vec![VerificationMethod {
            id: verification_method_id.clone(),
            type_: "JsonWebKey2020".into(),
            controller: did.to_string(),
            public_key_jwk: Some(serde_json::json!({})),
            public_key_multibase: None,
        }],
        authentication: vec![verification_method_id.clone()],
        assertion_method: vec![verification_method_id.clone()],
        service: Some(vec![DidService {
            id: format!("{did}#gauth-service"),
            type_: "GAuthService".into(),
            service_endpoint: format!("https://{domain}/api/gauth"),
        }]),
        resolution: Some(DidResolution {
            did_document_url: Some(doc_url),
            resolved: true,
            method: "web".into(),
        }),
    })
}

pub fn resolve_did_key(did: &str) -> Result<DidDocument, String> {
    if !did.starts_with("did:key:") {
        return Err(format!("Not a did:key identifier: {did}"));
    }

    let multibase_key = &did[8..];
    let verification_method_id = format!("{did}#{multibase_key}");

    Ok(DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/suites/jws-2020/v1".into(),
        ],
        id: did.to_string(),
        verification_method: vec![VerificationMethod {
            id: verification_method_id.clone(),
            type_: "JsonWebKey2020".into(),
            controller: did.to_string(),
            public_key_jwk: None,
            public_key_multibase: Some(multibase_key.to_string()),
        }],
        authentication: vec![verification_method_id.clone()],
        assertion_method: vec![verification_method_id],
        service: None,
        resolution: Some(DidResolution {
            did_document_url: None,
            resolved: true,
            method: "key".into(),
        }),
    })
}

pub fn create_did_key(public_key_hex: Option<&str>) -> DidKeyResult {
    let hex_key = match public_key_hex {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => {
            let mut hasher = Sha256::new();
            hasher.update(b"gauth-ephemeral-");
            hasher.update(uuid::Uuid::new_v4().as_bytes());
            hex::encode(hasher.finalize())[..32].to_string()
        }
    };

    let multibase_key = format!("z{hex_key}");
    let did = format!("did:key:{multibase_key}");
    let did_document = resolve_did_key(&did).expect("Valid did:key format");

    DidKeyResult {
        did,
        multibase_key,
        did_document,
    }
}

pub fn resolve_did(did: &str) -> Result<DidDocument, String> {
    if did.starts_with("did:web:") {
        resolve_did_web(did)
    } else if did.starts_with("did:key:") {
        resolve_did_key(did)
    } else {
        let method = did.split(':').nth(1).unwrap_or("unknown");
        Err(format!("Unsupported DID method: {method}"))
    }
}
