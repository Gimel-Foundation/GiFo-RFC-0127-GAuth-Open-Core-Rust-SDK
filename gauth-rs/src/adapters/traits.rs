use crate::error::Result;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdapterHealthResult {
    pub healthy: bool,
    pub latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violations: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CeilingValidation {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violations: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionDecision {
    pub allowed: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<serde_json::Value>,
}

pub trait PolicyDecisionAdapter: Send + Sync {
    fn evaluate_mandate(
        &self,
        mandate: &serde_json::Value,
        profile: &serde_json::Value,
    ) -> Result<PolicyDecision>;

    fn validate_ceilings(
        &self,
        mandate: &serde_json::Value,
        profile: &serde_json::Value,
    ) -> Result<CeilingValidation>;

    fn evaluate_action(
        &self,
        action: &serde_json::Value,
        mandate: &serde_json::Value,
    ) -> Result<ActionDecision>;

    fn adjust_severity(&self, base_severity: &str, profile: &serde_json::Value) -> String;

    fn health_check(&self) -> Result<AdapterHealthResult>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedJwt {
    pub token: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenValidation {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RevocationResult {
    pub revoked: bool,
    pub token_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntrospectionResult {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
}

pub trait OAuthEngineAdapter: Send + Sync {
    fn issue_token(
        &self,
        claims: &serde_json::Value,
        options: &serde_json::Value,
    ) -> Result<SignedJwt>;

    fn validate_token(&self, token: &str) -> Result<TokenValidation>;

    fn revoke_token(&self, token_id: &str, reason: &str) -> Result<RevocationResult>;

    fn get_jwks(&self) -> Result<serde_json::Value>;

    fn introspect(&self, token: &str) -> Result<IntrospectionResult>;

    fn before_token_issuance(
        &self,
        context: &serde_json::Value,
    ) -> Result<serde_json::Value>;

    fn after_token_issuance(
        &self,
        token: &SignedJwt,
        context: &serde_json::Value,
    ) -> Result<()>;

    fn health_check(&self) -> Result<AdapterHealthResult>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentCatalogEntry {
    pub id: String,
    pub name: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionReport {
    pub action_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxValidation {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issues: Option<Vec<String>>,
}

pub trait FoundryAdapter: Send + Sync {
    fn execute_action(
        &self,
        action: &serde_json::Value,
        mandate: &serde_json::Value,
    ) -> Result<ActionResult>;

    fn get_agent_catalog(&self) -> Result<Vec<AgentCatalogEntry>>;

    fn get_action_report(&self, action_id: &str) -> Result<ActionReport>;

    fn validate_sandbox(
        &self,
        agent_id: &str,
        requirements: &serde_json::Value,
    ) -> Result<SandboxValidation>;

    fn health_check(&self) -> Result<AdapterHealthResult>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageReceipt {
    pub id: String,
    pub stored: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CredentialSummary {
    pub id: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub issuer: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeletionReceipt {
    pub id: String,
    pub deleted: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SdJwt {
    pub token: String,
}

pub trait WalletAdapter: Send + Sync {
    fn store_credential(&self, credential: &serde_json::Value) -> Result<StorageReceipt>;

    fn present_credential(&self, query: &serde_json::Value) -> Result<serde_json::Value>;

    fn list_credentials(
        &self,
        filter: Option<&serde_json::Value>,
    ) -> Result<Vec<CredentialSummary>>;

    fn delete_credential(&self, credential_id: &str) -> Result<DeletionReceipt>;

    fn generate_selective_disclosure(
        &self,
        credential: &serde_json::Value,
        disclosure_frame: &serde_json::Value,
    ) -> Result<SdJwt>;

    fn health_check(&self) -> Result<AdapterHealthResult>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GovernanceCheckResponse {
    pub allowed: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendations: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GovernanceRecommendation {
    pub id: String,
    pub recommendation: String,
    pub severity: String,
}

pub trait GovernanceAdapter: Send + Sync {
    fn check_access(
        &self,
        request: &serde_json::Value,
    ) -> Result<GovernanceCheckResponse>;

    fn get_recommendations(
        &self,
        context: &serde_json::Value,
    ) -> Result<Vec<GovernanceRecommendation>>;

    fn health_check(&self) -> Result<AdapterHealthResult>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Web3Identity {
    pub identifier: String,
    pub resolved: bool,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationResult {
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

pub trait Web3IdentityAdapter: Send + Sync {
    fn resolve_identity(&self, identifier: &str) -> Result<Option<Web3Identity>>;

    fn verify_credential(&self, credential: &serde_json::Value) -> Result<VerificationResult>;

    fn health_check(&self) -> Result<AdapterHealthResult>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnaIdentity {
    pub identifier: String,
    pub resolved: bool,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

pub trait DnaIdentityAdapter: Send + Sync {
    fn resolve_identity(&self, identifier: &str) -> Result<Option<DnaIdentity>>;

    fn verify_biometric(&self, data: &serde_json::Value) -> Result<VerificationResult>;

    fn health_check(&self) -> Result<AdapterHealthResult>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreditCheckResult {
    pub allowed: bool,
    pub balance: i64,
    pub cost: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BalanceInfo {
    pub balance_cents: i64,
    pub currency: String,
}

pub trait BillingAdapter: Send + Sync {
    fn check_credits(&self, organization_id: &str, operation: &str) -> Result<CreditCheckResult>;

    fn record_usage(
        &self,
        organization_id: &str,
        operation: &str,
        metadata: Option<&serde_json::Value>,
    ) -> Result<()>;

    fn get_balance(&self, organization_id: &str) -> Result<BalanceInfo>;

    fn health_check(&self) -> Result<AdapterHealthResult>;
}

pub struct NoOpOAuthEngine;

impl OAuthEngineAdapter for NoOpOAuthEngine {
    fn issue_token(
        &self,
        _claims: &serde_json::Value,
        _options: &serde_json::Value,
    ) -> Result<SignedJwt> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No OAuth engine configured".into(),
        ))
    }

    fn validate_token(&self, _token: &str) -> Result<TokenValidation> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No OAuth engine configured".into(),
        ))
    }

    fn revoke_token(&self, _token_id: &str, _reason: &str) -> Result<RevocationResult> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No OAuth engine configured".into(),
        ))
    }

    fn get_jwks(&self) -> Result<serde_json::Value> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No OAuth engine configured".into(),
        ))
    }

    fn introspect(&self, _token: &str) -> Result<IntrospectionResult> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No OAuth engine configured".into(),
        ))
    }

    fn before_token_issuance(
        &self,
        _context: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        Ok(serde_json::json!({}))
    }

    fn after_token_issuance(
        &self,
        _token: &SignedJwt,
        _context: &serde_json::Value,
    ) -> Result<()> {
        Ok(())
    }

    fn health_check(&self) -> Result<AdapterHealthResult> {
        Ok(AdapterHealthResult {
            healthy: false,
            latency_ms: 0.0,
            details: Some("No OAuth engine configured".into()),
        })
    }
}

pub struct NoOpFoundry;

impl FoundryAdapter for NoOpFoundry {
    fn execute_action(
        &self,
        _action: &serde_json::Value,
        _mandate: &serde_json::Value,
    ) -> Result<ActionResult> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No foundry configured".into(),
        ))
    }

    fn get_agent_catalog(&self) -> Result<Vec<AgentCatalogEntry>> {
        Ok(vec![])
    }

    fn get_action_report(&self, _action_id: &str) -> Result<ActionReport> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No foundry configured".into(),
        ))
    }

    fn validate_sandbox(
        &self,
        _agent_id: &str,
        _requirements: &serde_json::Value,
    ) -> Result<SandboxValidation> {
        Ok(SandboxValidation {
            valid: true,
            issues: None,
        })
    }

    fn health_check(&self) -> Result<AdapterHealthResult> {
        Ok(AdapterHealthResult {
            healthy: false,
            latency_ms: 0.0,
            details: Some("No foundry configured".into()),
        })
    }
}

pub struct NoOpWallet;

impl WalletAdapter for NoOpWallet {
    fn store_credential(&self, _credential: &serde_json::Value) -> Result<StorageReceipt> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No wallet configured".into(),
        ))
    }

    fn present_credential(&self, _query: &serde_json::Value) -> Result<serde_json::Value> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No wallet configured".into(),
        ))
    }

    fn list_credentials(
        &self,
        _filter: Option<&serde_json::Value>,
    ) -> Result<Vec<CredentialSummary>> {
        Ok(vec![])
    }

    fn delete_credential(&self, _credential_id: &str) -> Result<DeletionReceipt> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No wallet configured".into(),
        ))
    }

    fn generate_selective_disclosure(
        &self,
        _credential: &serde_json::Value,
        _disclosure_frame: &serde_json::Value,
    ) -> Result<SdJwt> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No wallet configured".into(),
        ))
    }

    fn health_check(&self) -> Result<AdapterHealthResult> {
        Ok(AdapterHealthResult {
            healthy: false,
            latency_ms: 0.0,
            details: Some("No wallet configured".into()),
        })
    }
}

pub struct RuleBasedGovernance;

impl GovernanceAdapter for RuleBasedGovernance {
    fn check_access(
        &self,
        _request: &serde_json::Value,
    ) -> Result<GovernanceCheckResponse> {
        Ok(GovernanceCheckResponse {
            allowed: true,
            reason: "Rule-based evaluation only (no AI governance adapter)".into(),
            recommendations: None,
        })
    }

    fn get_recommendations(
        &self,
        _context: &serde_json::Value,
    ) -> Result<Vec<GovernanceRecommendation>> {
        Ok(vec![])
    }

    fn health_check(&self) -> Result<AdapterHealthResult> {
        Ok(AdapterHealthResult {
            healthy: true,
            latency_ms: 0.0,
            details: Some("Rule-based fallback (no AI governance)".into()),
        })
    }
}

pub struct NullWeb3Identity;

impl Web3IdentityAdapter for NullWeb3Identity {
    fn resolve_identity(&self, _identifier: &str) -> Result<Option<Web3Identity>> {
        Ok(None)
    }

    fn verify_credential(&self, _credential: &serde_json::Value) -> Result<VerificationResult> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "Web3 identity adapter not available (Phase 2)".into(),
        ))
    }

    fn health_check(&self) -> Result<AdapterHealthResult> {
        Ok(AdapterHealthResult {
            healthy: false,
            latency_ms: 0.0,
            details: Some("Web3 identity: Phase 2 placeholder".into()),
        })
    }
}

pub struct RuleBasedPolicyDecision;

impl PolicyDecisionAdapter for RuleBasedPolicyDecision {
    fn evaluate_mandate(
        &self,
        _mandate: &serde_json::Value,
        _profile: &serde_json::Value,
    ) -> Result<PolicyDecision> {
        Ok(PolicyDecision {
            allowed: true,
            reason: "Rule-based: default allow".into(),
            violations: None,
        })
    }

    fn validate_ceilings(
        &self,
        _mandate: &serde_json::Value,
        _profile: &serde_json::Value,
    ) -> Result<CeilingValidation> {
        Ok(CeilingValidation {
            valid: true,
            violations: None,
        })
    }

    fn evaluate_action(
        &self,
        _action: &serde_json::Value,
        _mandate: &serde_json::Value,
    ) -> Result<ActionDecision> {
        Ok(ActionDecision {
            allowed: true,
            reason: "Rule-based: default allow".into(),
            constraints: None,
        })
    }

    fn adjust_severity(&self, base_severity: &str, _profile: &serde_json::Value) -> String {
        base_severity.to_string()
    }

    fn health_check(&self) -> Result<AdapterHealthResult> {
        Ok(AdapterHealthResult {
            healthy: true,
            latency_ms: 0.0,
            details: Some("Rule-based PDP: embedded".into()),
        })
    }
}

pub struct NoOpBilling;

impl BillingAdapter for NoOpBilling {
    fn check_credits(
        &self,
        _organization_id: &str,
        _operation: &str,
    ) -> Result<CreditCheckResult> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No billing adapter configured".into(),
        ))
    }

    fn record_usage(
        &self,
        _organization_id: &str,
        _operation: &str,
        _metadata: Option<&serde_json::Value>,
    ) -> Result<()> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No billing adapter configured".into(),
        ))
    }

    fn get_balance(&self, _organization_id: &str) -> Result<BalanceInfo> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No billing adapter configured".into(),
        ))
    }

    fn health_check(&self) -> Result<AdapterHealthResult> {
        Ok(AdapterHealthResult {
            healthy: false,
            latency_ms: 0.0,
            details: Some("Billing adapter: not configured".into()),
        })
    }
}

pub struct NullDnaIdentity;

impl DnaIdentityAdapter for NullDnaIdentity {
    fn resolve_identity(&self, _identifier: &str) -> Result<Option<DnaIdentity>> {
        Ok(None)
    }

    fn verify_biometric(&self, _data: &serde_json::Value) -> Result<VerificationResult> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "DNA identity adapter not available (Phase 3)".into(),
        ))
    }

    fn health_check(&self) -> Result<AdapterHealthResult> {
        Ok(AdapterHealthResult {
            healthy: false,
            latency_ms: 0.0,
            details: Some("DNA identity: Phase 3 placeholder".into()),
        })
    }
}
