use serde::{Deserialize, Serialize};

use crate::types::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MandateStatus {
    Draft,
    Active,
    Suspended,
    Expired,
    Revoked,
    BudgetExceeded,
    Superseded,
}

impl MandateStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            MandateStatus::Expired
                | MandateStatus::Revoked
                | MandateStatus::BudgetExceeded
                | MandateStatus::Superseded
        )
    }
}

impl std::fmt::Display for MandateStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MandateStatus::Draft => write!(f, "DRAFT"),
            MandateStatus::Active => write!(f, "ACTIVE"),
            MandateStatus::Suspended => write!(f, "SUSPENDED"),
            MandateStatus::Expired => write!(f, "EXPIRED"),
            MandateStatus::Revoked => write!(f, "REVOKED"),
            MandateStatus::BudgetExceeded => write!(f, "BUDGET_EXCEEDED"),
            MandateStatus::Superseded => write!(f, "SUPERSEDED"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mandate {
    pub mandate_id: String,
    pub status: MandateStatus,
    pub parties: Parties,
    pub scope: Scope,
    pub requirements: Requirements,
    pub scope_checksum: String,
    pub tool_permissions_hash: String,
    pub platform_permissions_hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activated_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_chain: Option<DelegationChain>,
    pub audit_trail: Vec<MandateAuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateAuditEntry {
    pub operation: MandateOperation,
    pub performed_by: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub mandate_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MandateOperation {
    Create,
    Activate,
    Suspend,
    Resume,
    Revoke,
    ExtendBudget,
    ExtendTtl,
    Delegate,
    Expire,
    BudgetExhaust,
    Supersede,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateCreationRequest {
    pub parties: Parties,
    pub scope: Scope,
    pub requirements: Requirements,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateCreationResponse {
    pub mandate_id: String,
    pub status: MandateStatus,
    pub scope_checksum: String,
    pub tool_permissions_hash: String,
    pub platform_permissions_hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub validation: ValidationResult,
    pub audit: MandateAuditEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateActivationRequest {
    pub mandate_id: String,
    pub activated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateActivationResponse {
    pub mandate_id: String,
    pub status: MandateStatus,
    pub activated_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_mandate_id: Option<String>,
    pub audit: MandateAuditEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateRevocationRequest {
    pub mandate_id: String,
    pub revoked_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateRevocationResponse {
    pub mandate_id: String,
    pub status: MandateStatus,
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    pub revoked_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub cascaded_revocations: Vec<String>,
    pub audit: MandateAuditEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateSuspensionRequest {
    pub mandate_id: String,
    pub suspended_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateResumptionRequest {
    pub mandate_id: String,
    pub resumed_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetExtensionRequest {
    pub mandate_id: String,
    pub additional_cents: i64,
    pub extended_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlExtensionRequest {
    pub mandate_id: String,
    pub additional_seconds: i64,
    pub extended_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRequest {
    pub parent_mandate_id: String,
    pub delegate_agent_id: String,
    pub scope_restriction: serde_json::Value,
    pub delegated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_errors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ceiling_violations: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consistency_errors: Option<Vec<String>>,
}
