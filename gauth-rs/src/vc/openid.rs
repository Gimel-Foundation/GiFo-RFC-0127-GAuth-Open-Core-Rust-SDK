// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::management::types::Mandate;
use crate::vc::serializer::{create_data_integrity_proof, poa_to_vc, verify_data_integrity_proof};
use crate::vc::status_list::BitstringStatusList;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    pub c_nonce: String,
    pub c_nonce_expires_in: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceValidation {
    pub valid: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: CredentialOfferGrants,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOfferGrants {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: PreAuthorizedCodeGrant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthorizedCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub c_nonce: String,
    pub c_nonce_expires_in: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    pub format: String,
    pub credential: serde_json::Value,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationRequest {
    pub presentation_definition: PresentationDefinition,
    pub nonce: String,
    pub response_uri: String,
    pub client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationDefinition {
    pub id: String,
    pub input_descriptors: Vec<InputDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDescriptor {
    pub id: String,
    pub name: String,
    pub purpose: String,
    pub format: serde_json::Value,
    pub constraints: InputDescriptorConstraints,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDescriptorConstraints {
    pub fields: Vec<ConstraintField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintField {
    pub path: Vec<String>,
    pub filter: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpSubmissionResult {
    pub verified: bool,
    pub holder_did: String,
    pub credential_type: Vec<String>,
    pub nonce_valid: bool,
    pub proof_valid: bool,
    pub status_check: Option<StatusCheckResult>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusCheckResult {
    pub checked: bool,
    pub revoked: bool,
    pub reason: String,
}

struct NonceStore {
    nonces: HashMap<String, u64>,
    used: std::collections::HashSet<String>,
    default_ttl: u64,
}

impl NonceStore {
    fn new(default_ttl: u64) -> Self {
        Self {
            nonces: HashMap::new(),
            used: std::collections::HashSet::new(),
            default_ttl,
        }
    }

    fn issue(&mut self, ttl: Option<u64>) -> NonceResponse {
        let nonce = format!("c_nonce_{}", uuid::Uuid::new_v4());
        let effective_ttl = ttl.unwrap_or(self.default_ttl);
        self.nonces.insert(nonce.clone(), now_secs() + effective_ttl);
        NonceResponse {
            c_nonce: nonce,
            c_nonce_expires_in: effective_ttl,
        }
    }

    fn validate_and_consume(&mut self, nonce: &str) -> NonceValidation {
        if self.used.contains(nonce) {
            return NonceValidation {
                valid: false,
                reason: Some("nonce_replay".into()),
            };
        }
        match self.nonces.get(nonce) {
            None => NonceValidation {
                valid: false,
                reason: Some("nonce_unknown".into()),
            },
            Some(&expiry) => {
                if now_secs() > expiry {
                    self.nonces.remove(nonce);
                    NonceValidation {
                        valid: false,
                        reason: Some("nonce_expired".into()),
                    }
                } else {
                    self.nonces.remove(nonce);
                    self.used.insert(nonce.to_string());
                    NonceValidation {
                        valid: true,
                        reason: None,
                    }
                }
            }
        }
    }
}

pub struct TrustedIssuerRegistry {
    keys: HashMap<String, ed25519_dalek::VerifyingKey>,
}

impl TrustedIssuerRegistry {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    pub fn register(&mut self, issuer_did: &str, public_key: ed25519_dalek::VerifyingKey) {
        self.keys.insert(issuer_did.to_string(), public_key);
    }

    pub fn resolve(&self, verification_method: &str) -> Option<&ed25519_dalek::VerifyingKey> {
        let did = verification_method
            .split('#')
            .next()
            .unwrap_or(verification_method);
        self.keys.get(did)
    }
}

impl Default for TrustedIssuerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct OpenID4VCIssuer {
    issuer_url: String,
    signing_key: ed25519_dalek::SigningKey,
    verification_method: String,
    nonces: NonceStore,
    codes: HashMap<String, serde_json::Value>,
    tokens: HashMap<String, serde_json::Value>,
    offers: HashMap<String, CredentialOffer>,
    status_list: BitstringStatusList,
    credential_index: usize,
}

impl OpenID4VCIssuer {
    pub fn new(
        issuer_url: &str,
        signing_key: ed25519_dalek::SigningKey,
        verification_method: &str,
        nonce_ttl: u64,
    ) -> Self {
        Self {
            issuer_url: issuer_url.to_string(),
            signing_key,
            verification_method: verification_method.to_string(),
            nonces: NonceStore::new(nonce_ttl),
            codes: HashMap::new(),
            tokens: HashMap::new(),
            offers: HashMap::new(),
            status_list: BitstringStatusList::with_default_size(),
            credential_index: 0,
        }
    }

    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn issuer_did(&self) -> String {
        let domain = self
            .issuer_url
            .replace("https://", "")
            .replace("http://", "");
        format!("did:web:{domain}")
    }

    pub fn create_credential_offer(&mut self, mandate_id: &str) -> CredentialOffer {
        let code = format!("pre_auth_{}", uuid::Uuid::new_v4());
        self.codes.insert(
            code.clone(),
            serde_json::json!({"mandate_id": mandate_id}),
        );

        let offer = CredentialOffer {
            credential_issuer: self.issuer_url.clone(),
            credential_configuration_ids: vec!["GAuthPoACredential".into()],
            grants: CredentialOfferGrants {
                pre_authorized_code: PreAuthorizedCodeGrant {
                    pre_authorized_code: code,
                },
            },
        };

        let offer_id = format!("offer_{}", uuid::Uuid::new_v4());
        self.offers.insert(offer_id, offer.clone());
        offer
    }

    pub fn exchange_token(&mut self, pre_authorized_code: &str) -> Option<TokenResponse> {
        let code_data = self.codes.remove(pre_authorized_code)?;
        let access_token = format!("at_{}", uuid::Uuid::new_v4());
        self.tokens
            .insert(access_token.clone(), code_data);

        let nonce_resp = self.nonces.issue(None);

        Some(TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in: 3600,
            c_nonce: nonce_resp.c_nonce,
            c_nonce_expires_in: nonce_resp.c_nonce_expires_in,
        })
    }

    pub fn issue_credential(
        &mut self,
        access_token: &str,
        mandate: &Mandate,
        c_nonce: &str,
    ) -> Option<CredentialResponse> {
        let _token_data = self.tokens.get(access_token)?;

        let nonce_result = self.nonces.validate_and_consume(c_nonce);
        if !nonce_result.valid {
            return None;
        }

        let index = self.credential_index;
        self.credential_index += 1;

        let status_cred_id = format!("{}/status/1", self.issuer_url);
        let mut vc = poa_to_vc(mandate, &self.issuer_did(), &status_cred_id, index);

        let doc_value = serde_json::to_value(&vc).unwrap_or_default();
        let proof = create_data_integrity_proof(
            &doc_value,
            &self.verification_method,
            Some(&self.signing_key),
        );
        vc.proof = Some(proof);

        let new_nonce = self.nonces.issue(None);

        Some(CredentialResponse {
            format: "ldp_vc".into(),
            credential: serde_json::to_value(&vc).unwrap_or_default(),
            c_nonce: Some(new_nonce.c_nonce),
            c_nonce_expires_in: Some(new_nonce.c_nonce_expires_in),
        })
    }

    pub fn revoke_credential(&mut self, index: usize, reason: &str) -> Result<(), String> {
        self.status_list.set_status(index, true, reason)
    }

    pub fn status_list_credential(&self) -> serde_json::Value {
        let cred = self.status_list.to_status_list_credential(
            &format!("{}/status/1", self.issuer_url),
            &self.issuer_did(),
        );
        serde_json::to_value(cred).unwrap_or_default()
    }
}

pub struct OpenID4VPVerifier {
    verifier_did: String,
    response_uri: String,
    nonces: NonceStore,
    trusted_issuers: TrustedIssuerRegistry,
    status_list: Option<BitstringStatusList>,
}

impl OpenID4VPVerifier {
    pub fn new(
        verifier_did: &str,
        response_uri: &str,
        nonce_ttl: u64,
    ) -> Self {
        Self {
            verifier_did: verifier_did.to_string(),
            response_uri: response_uri.to_string(),
            nonces: NonceStore::new(nonce_ttl),
            trusted_issuers: TrustedIssuerRegistry::new(),
            status_list: None,
        }
    }

    pub fn register_trusted_issuer(
        &mut self,
        issuer_did: &str,
        public_key: ed25519_dalek::VerifyingKey,
    ) {
        self.trusted_issuers.register(issuer_did, public_key);
    }

    pub fn set_status_list(&mut self, sl: BitstringStatusList) {
        self.status_list = Some(sl);
    }

    pub fn create_presentation_request(
        &mut self,
        required_actions: &[&str],
    ) -> PresentationRequest {
        let nonce_resp = self.nonces.issue(None);

        let fields: Vec<ConstraintField> = required_actions
            .iter()
            .map(|action| ConstraintField {
                path: vec![format!(
                    "$.credentialSubject.allowed_actions[?(@=='{action}')]"
                )],
                filter: serde_json::json!({"type": "string"}),
            })
            .collect();

        PresentationRequest {
            presentation_definition: PresentationDefinition {
                id: format!("pd_{}", uuid::Uuid::new_v4()),
                input_descriptors: vec![InputDescriptor {
                    id: "gauth_poa".into(),
                    name: "GAuth PoA Credential".into(),
                    purpose: "Verify agent authorization".into(),
                    format: serde_json::json!({"ldp_vc": {"proof_type": ["DataIntegrityProof"]}}),
                    constraints: InputDescriptorConstraints { fields },
                }],
            },
            nonce: nonce_resp.c_nonce,
            response_uri: self.response_uri.clone(),
            client_id: self.verifier_did.clone(),
        }
    }

    pub fn verify_presentation(
        &mut self,
        vp: &serde_json::Value,
        expected_nonce: &str,
    ) -> VpSubmissionResult {
        self.verify_presentation_with_constraints(vp, expected_nonce, &[])
    }

    pub fn verify_presentation_with_constraints(
        &mut self,
        vp: &serde_json::Value,
        expected_nonce: &str,
        required_actions: &[&str],
    ) -> VpSubmissionResult {
        let mut errors = Vec::new();

        let nonce_result = self.nonces.validate_and_consume(expected_nonce);
        if !nonce_result.valid {
            errors.push(format!(
                "Nonce validation failed: {}",
                nonce_result.reason.as_deref().unwrap_or("unknown")
            ));
        }

        let vp_nonce = vp
            .get("proof")
            .and_then(|p| p.get("challenge"))
            .and_then(|c| c.as_str());
        if let Some(vp_n) = vp_nonce {
            if vp_n != expected_nonce {
                errors.push("VP proof challenge does not match expected nonce".into());
            }
        }

        let vc = vp
            .get("verifiableCredential")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let holder_did = vp
            .get("holder")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let credential_type: Vec<String> = vc
            .get("type")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let proof_valid = if let Some(proof_val) = vc.get("proof") {
            if let Ok(proof) =
                serde_json::from_value::<crate::vc::serializer::DataIntegrityProof>(
                    proof_val.clone(),
                )
            {
                let mut vc_without_proof = vc.clone();
                if let Some(obj) = vc_without_proof.as_object_mut() {
                    obj.remove("proof");
                }
                let issuer_did = vc
                    .get("issuer")
                    .and_then(|i| i.get("id").or(Some(i)))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if let Some(key) = self.trusted_issuers.resolve(issuer_did) {
                    verify_data_integrity_proof(&vc_without_proof, &proof, Some(key))
                } else {
                    errors.push(format!("Untrusted issuer: {issuer_did}"));
                    false
                }
            } else {
                errors.push("Invalid proof format".into());
                false
            }
        } else {
            errors.push("No proof in credential".into());
            false
        };

        if !required_actions.is_empty() {
            let allowed_actions: Vec<String> = vc
                .get("credentialSubject")
                .and_then(|cs| cs.get("allowed_actions"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            for action in required_actions {
                if !allowed_actions.iter().any(|a| a == action) {
                    errors.push(format!(
                        "Required action '{action}' not in credential allowed_actions"
                    ));
                }
            }
        }

        let status_check = if let Some(ref sl) = self.status_list {
            if let Some(status) = vc.get("credentialStatus") {
                let index = status
                    .get("statusListIndex")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize;
                match sl.check_revocation(index) {
                    Ok(result) => {
                        if result.revoked {
                            errors.push(format!("Credential revoked at index {index}"));
                        }
                        Some(StatusCheckResult {
                            checked: true,
                            revoked: result.revoked,
                            reason: result.reason,
                        })
                    }
                    Err(e) => {
                        errors.push(format!("Status list check failed: {e}"));
                        Some(StatusCheckResult {
                            checked: false,
                            revoked: false,
                            reason: e,
                        })
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        let verified = nonce_result.valid && proof_valid && errors.is_empty();

        VpSubmissionResult {
            verified,
            holder_did,
            credential_type,
            nonce_valid: nonce_result.valid,
            proof_valid,
            status_check,
            errors,
        }
    }
}
