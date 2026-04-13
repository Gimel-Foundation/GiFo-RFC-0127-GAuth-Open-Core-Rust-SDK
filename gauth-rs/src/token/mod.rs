// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use chrono::{DateTime, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::{GAuthError, Result};
use crate::types::*;

const SCHEMA_VERSION: &str = "0116.2.2";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GAuthClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub nbf: i64,
    pub iat: i64,
    pub jti: String,

    #[serde(rename = "gauth_schema_version")]
    pub schema_version: String,
    #[serde(rename = "gauth_customer_id")]
    pub customer_id: String,
    #[serde(rename = "gauth_project_id")]
    pub project_id: String,
    #[serde(rename = "gauth_governance_profile")]
    pub governance_profile: GovernanceProfile,
    #[serde(rename = "gauth_phase")]
    pub phase: Phase,
    #[serde(rename = "gauth_scope_checksum")]
    pub scope_checksum: String,
    #[serde(rename = "gauth_tool_permissions_hash")]
    pub tool_permissions_hash: String,
    #[serde(rename = "gauth_platform_permissions_hash")]
    pub platform_permissions_hash: String,
    #[serde(rename = "gauth_approval_mode")]
    pub approval_mode: ApprovalMode,

    #[serde(rename = "gauth_budget", skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    #[serde(rename = "gauth_session_limits", skip_serializing_if = "Option::is_none")]
    pub session_limits: Option<SessionLimits>,
    #[serde(rename = "gauth_delegation_chain", skip_serializing_if = "Option::is_none")]
    pub delegation_chain: Option<DelegationChain>,

    #[serde(rename = "gauth_issued_by", skip_serializing_if = "Option::is_none")]
    pub issued_by: Option<String>,
    #[serde(rename = "gauth_approval_chain", skip_serializing_if = "Option::is_none")]
    pub approval_chain: Option<Vec<String>>,
}

pub struct TokenBuilder {
    poa: PoaCredential,
    audience: Vec<String>,
    ttl_seconds: i64,
    key_id: Option<String>,
}

impl TokenBuilder {
    pub fn new(poa: PoaCredential, audience: Vec<String>) -> Self {
        Self {
            ttl_seconds: poa.requirements.ttl_seconds.unwrap_or(43200),
            poa,
            audience,
            key_id: None,
        }
    }

    pub fn key_id(mut self, kid: String) -> Self {
        self.key_id = Some(kid);
        self
    }

    pub fn ttl_seconds(mut self, ttl: i64) -> Self {
        self.ttl_seconds = ttl;
        self
    }

    pub fn build_and_sign(self, key: &EncodingKey, algorithm: Algorithm) -> Result<String> {
        if !matches!(algorithm, Algorithm::RS256 | Algorithm::ES256) {
            return Err(GAuthError::Hs256Prohibited);
        }

        let now = Utc::now().timestamp();

        let scope_checksum = crypto::compute_scope_checksum(&self.poa.scope)?;
        let tool_permissions_hash = crypto::compute_permissions_hash(&self.poa.scope.core_verbs)?;
        let platform_permissions_hash = crypto::compute_platform_permissions_hash(
            self.poa
                .scope
                .platform_permissions
                .as_ref()
                .unwrap_or(&PlatformPermissions::default()),
        )?;

        let claims = GAuthClaims {
            iss: self.poa.parties.issuer.clone(),
            sub: self.poa.parties.subject.clone(),
            aud: self.audience,
            exp: now + self.ttl_seconds,
            nbf: now,
            iat: now,
            jti: uuid::Uuid::new_v4().to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            customer_id: self.poa.parties.customer_id.clone(),
            project_id: self.poa.parties.project_id.clone(),
            governance_profile: self.poa.scope.governance_profile.clone(),
            phase: self.poa.scope.phase.clone(),
            scope_checksum,
            tool_permissions_hash,
            platform_permissions_hash,
            approval_mode: self.poa.requirements.approval_mode.clone(),
            budget: self.poa.requirements.budget.clone(),
            session_limits: self.poa.requirements.session_limits.clone(),
            delegation_chain: self.poa.delegation_chain.clone(),
            issued_by: self.poa.parties.issued_by.clone(),
            approval_chain: self.poa.parties.approval_chain.clone(),
        };

        let mut header = Header::new(algorithm);
        header.kid = self.key_id;
        header.typ = Some("JWT".to_string());

        let token = encode(&header, &claims, key)?;
        Ok(token)
    }
}

pub fn validate_token(
    token: &str,
    key: &DecodingKey,
    expected_audiences: &[String],
    expected_issuer: &str,
) -> Result<TokenData<GAuthClaims>> {
    let header = jsonwebtoken::decode_header(token)?;

    if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256) {
        return Err(GAuthError::Hs256Prohibited);
    }

    let mut validation = Validation::new(header.alg);
    validation.set_audience(expected_audiences);
    validation.set_issuer(&[expected_issuer]);
    validation.set_required_spec_claims(&["exp", "nbf", "iat", "iss", "sub", "aud"]);

    let token_data = decode::<GAuthClaims>(token, key, &validation)?;

    if token_data.claims.schema_version != SCHEMA_VERSION {
        return Err(GAuthError::CredentialIntegrity(format!(
            "unsupported schema_version: {}, expected {}",
            token_data.claims.schema_version, SCHEMA_VERSION
        )));
    }

    Ok(token_data)
}

pub fn decode_unverified(token: &str) -> Result<GAuthClaims> {
    let header = jsonwebtoken::decode_header(token)?;
    if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256) {
        return Err(GAuthError::Hs256Prohibited);
    }

    let mut validation = Validation::new(header.alg);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.set_required_spec_claims::<String>(&[]);

    let key = DecodingKey::from_secret(&[]);
    let token_data = decode::<GAuthClaims>(token, &key, &validation)?;
    Ok(token_data.claims)
}

pub fn verify_scope_checksum(claims: &GAuthClaims, scope: &Scope) -> Result<bool> {
    let computed = crypto::compute_scope_checksum(scope)?;
    Ok(computed == claims.scope_checksum)
}

pub struct ExtendedTokenInfo {
    pub claims: GAuthClaims,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
}

impl ExtendedTokenInfo {
    pub fn from_claims(claims: GAuthClaims) -> Self {
        Self {
            issued_at: DateTime::from_timestamp(claims.iat, 0).unwrap_or_default(),
            expires_at: DateTime::from_timestamp(claims.exp, 0).unwrap_or_default(),
            not_before: DateTime::from_timestamp(claims.nbf, 0).unwrap_or_default(),
            claims,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_active(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now < self.expires_at
    }
}
