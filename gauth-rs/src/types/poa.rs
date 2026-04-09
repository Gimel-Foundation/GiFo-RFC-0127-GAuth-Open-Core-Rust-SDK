use serde::{Deserialize, Serialize};

use super::capabilities::{Budget, CoreVerbs, PlatformPermissions, SessionLimits};
use super::delegation::DelegationChain;
use super::governance::{ApprovalMode, GovernanceProfile, Phase};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoaCredential {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    pub parties: Parties,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_chain: Option<DelegationChain>,
    pub scope: Scope,
    pub requirements: Requirements,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parties {
    pub issuer: String,
    pub subject: String,
    pub customer_id: String,
    pub project_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_chain: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub governance_profile: GovernanceProfile,
    pub phase: Phase,
    pub core_verbs: CoreVerbs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_modules: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied_paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_sectors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_regions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_transactions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_matrix: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_decisions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_permissions: Option<PlatformPermissions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirements {
    pub approval_mode: ApprovalMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_limits: Option<SessionLimits>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i64>,
}
