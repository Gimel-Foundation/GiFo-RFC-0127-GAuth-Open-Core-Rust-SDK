// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementRequest {
    pub request_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub action: ActionDescriptor,
    pub agent: AgentIdentity,
    pub credential: CredentialReference,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<EnforcementContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDescriptor {
    pub verb: String,
    pub resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialReference {
    pub format: CredentialFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandate_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poa_snapshot: Option<crate::types::PoaCredential>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFormat {
    Jwt,
    W3cVc,
    SdJwt,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnforcementContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_state: Option<SessionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_mandate_state: Option<LiveMandateState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls_used: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines_committed: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_started_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_cost_cents: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveMandateState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_remaining_cents: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_permissions: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_permissions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    #[serde(rename = "PERMIT")]
    Permit,
    #[serde(rename = "DENY")]
    Deny,
    #[serde(rename = "CONSTRAIN")]
    Constrain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementDecision {
    pub request_id: String,
    pub decision: Decision,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub enforcement_mode: EnforcementMode,
    pub checks: Vec<CheckResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforced_constraints: Option<Vec<EnforcedConstraint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violations: Option<Vec<Violation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    Stateless,
    Stateful,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub check_id: String,
    pub check_name: String,
    pub result: CheckOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub failure_code: Option<String>,
}

impl CheckResult {
    pub fn with_failure_code(mut self, code: &str) -> Self {
        self.failure_code = Some(code.to_string());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckOutcome {
    Pass,
    Fail,
    Skip,
    Constrain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcedConstraint {
    pub constraint_type: String,
    pub check_id: String,
    pub requested: serde_json::Value,
    pub enforced: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub code: String,
    pub message: String,
    pub check_id: String,
    pub severity: ViolationSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViolationSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub processing_time_ms: f64,
    pub pep_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pep_interface_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandate_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_verb: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks_performed: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks_passed: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks_failed: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementError {
    pub error_code: PepErrorCode,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PepErrorCode {
    #[serde(rename = "PEP_INTERNAL_ERROR")]
    PepInternalError,
    #[serde(rename = "INVALID_REQUEST")]
    InvalidRequest,
    #[serde(rename = "CREDENTIAL_PARSE_ERROR")]
    CredentialParseError,
    #[serde(rename = "ISSUER_UNREACHABLE")]
    IssuerUnreachable,
    #[serde(rename = "EVALUATION_TIMEOUT")]
    EvaluationTimeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDecision {
    pub overall_decision: Decision,
    pub decisions: Vec<EnforcementDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchMode {
    AllOrNothing,
    Independent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementPolicy {
    pub governance_profile: String,
    pub phase: String,
    pub allowed_verbs: Vec<String>,
    pub denied_paths: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub permissions: serde_json::Value,
    pub budget: Option<crate::types::Budget>,
    pub session_limits: Option<serde_json::Value>,
    pub approval_mode: String,
    pub delegation: DelegationInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationInfo {
    pub allowed: bool,
    pub max_depth: u32,
}
