// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::management::types::Mandate;

pub const W3C_CREDENTIALS_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
pub const GAUTH_VC_CONTEXT: &str = "https://gauth.gimel.foundation/ns/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    pub issuer: VcIssuer,
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: serde_json::Value,
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcIssuer {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "statusPurpose")]
    pub status_purpose: String,
    #[serde(rename = "statusListIndex")]
    pub status_list_index: usize,
    #[serde(rename = "statusListCredential")]
    pub status_list_credential: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "cryptosuite")]
    pub cryptosuite: String,
    pub created: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

pub fn poa_to_vc(
    mandate: &Mandate,
    issuer_did: &str,
    status_list_credential: &str,
    status_list_index: usize,
) -> VerifiableCredential {
    let issuer = if issuer_did.is_empty() {
        format!(
            "did:web:gauth.gimel.foundation:{}",
            mandate.parties.project_id
        )
    } else {
        issuer_did.to_string()
    };

    let subject_did = if mandate.parties.subject.is_empty() {
        String::new()
    } else {
        format!("did:key:{}", mandate.parties.subject)
    };

    let allowed_actions: Vec<String> = mandate
        .scope
        .core_verbs
        .iter()
        .filter(|(_, p)| p.allowed)
        .map(|(k, _)| k.clone())
        .collect();

    let valid_from = mandate.activated_at.map(|t| t.to_rfc3339());
    let valid_until = mandate.expires_at.map(|t| t.to_rfc3339());

    let credential_subject = serde_json::json!({
        "id": subject_did,
        "mandate_id": mandate.mandate_id,
        "governance_profile": format!("{:?}", mandate.scope.governance_profile),
        "phase": format!("{:?}", mandate.scope.phase),
        "approval_mode": format!("{:?}", mandate.requirements.approval_mode),
        "allowed_actions": allowed_actions,
        "allowed_regions": mandate.scope.allowed_regions.clone().unwrap_or_default(),
        "allowed_sectors": mandate.scope.allowed_sectors.clone().unwrap_or_default(),
        "budget": mandate.requirements.budget.as_ref().map(|b| serde_json::json!({
            "total_cents": b.total_cents,
            "remaining_cents": b.remaining_cents,
        })),
        "delegation_depth": mandate.delegation_chain.as_ref().map(|c| c.len()).unwrap_or(0),
        "scope_checksum": mandate.scope_checksum,
    });

    let credential_status = if !status_list_credential.is_empty() {
        Some(CredentialStatus {
            id: format!("{status_list_credential}#{status_list_index}"),
            type_: "BitstringStatusListEntry".into(),
            status_purpose: "revocation".into(),
            status_list_index,
            status_list_credential: status_list_credential.to_string(),
        })
    } else {
        None
    };

    VerifiableCredential {
        context: vec![
            W3C_CREDENTIALS_V2_CONTEXT.into(),
            GAUTH_VC_CONTEXT.into(),
        ],
        id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        type_: vec![
            "VerifiableCredential".into(),
            "GAuthPoACredential".into(),
        ],
        issuer: VcIssuer { id: issuer },
        valid_from,
        valid_until,
        credential_subject,
        credential_status,
        proof: None,
    }
}

pub fn vc_to_jwt_payload(vc: &VerifiableCredential) -> serde_json::Value {
    let issuer_id = &vc.issuer.id;
    let subject_id = vc
        .credential_subject
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut payload = serde_json::json!({
        "iss": issuer_id,
        "sub": subject_id,
        "vc": serde_json::to_value(vc).unwrap_or(serde_json::Value::Null),
    });

    if let Some(ref vf) = vc.valid_from {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(vf) {
            payload["iat"] = serde_json::json!(dt.timestamp());
            payload["nbf"] = serde_json::json!(dt.timestamp());
        }
    }

    if let Some(ref vu) = vc.valid_until {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(vu) {
            payload["exp"] = serde_json::json!(dt.timestamp());
        }
    }

    payload["jti"] = serde_json::json!(vc.id);

    payload
}

pub fn create_data_integrity_proof(
    document: &serde_json::Value,
    verification_method: &str,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> DataIntegrityProof {
    let canonical = crate::crypto::canonical_json(document);
    let hash = Sha256::digest(canonical.as_bytes());

    let proof_value = if let Some(key) = signing_key {
        use ed25519_dalek::Signer;
        let sig = key.sign(&hash);
        hex::encode(sig.to_bytes())
    } else {
        hex::encode(hash)
    };

    DataIntegrityProof {
        type_: "DataIntegrityProof".into(),
        cryptosuite: "eddsa-rdfc-2022".into(),
        created: chrono::Utc::now().to_rfc3339(),
        verification_method: verification_method.to_string(),
        proof_purpose: "assertionMethod".into(),
        proof_value,
    }
}

pub fn verify_data_integrity_proof(
    document: &serde_json::Value,
    proof: &DataIntegrityProof,
    verifying_key: Option<&ed25519_dalek::VerifyingKey>,
) -> bool {
    let canonical = crate::crypto::canonical_json(document);
    let hash = Sha256::digest(canonical.as_bytes());

    if let Some(key) = verifying_key {
        if let Ok(sig_bytes) = hex::decode(&proof.proof_value) {
            if sig_bytes.len() == 64 {
                if let Ok(sig) = ed25519_dalek::Signature::from_slice(&sig_bytes) {
                    use ed25519_dalek::Verifier;
                    return key.verify(&hash, &sig).is_ok();
                }
            }
        }
        false
    } else {
        let expected = hex::encode(hash);
        proof.proof_value == expected
    }
}
