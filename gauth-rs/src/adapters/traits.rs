use crate::error::Result;
use crate::pep::{EnforcementDecision, EnforcementRequest};
use crate::types::PoaCredential;

pub trait OAuthEngineAdapter: Send + Sync {
    fn authorize(&self, client_id: &str, scope: &str, redirect_uri: &str) -> Result<String>;

    fn token(
        &self,
        grant_type: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<serde_json::Value>;

    fn introspect(&self, token: &str) -> Result<serde_json::Value>;

    fn revoke(&self, token: &str) -> Result<()>;

    fn jwks(&self) -> Result<serde_json::Value>;
}

pub trait FoundryAdapter: Send + Sync {
    fn execute(&self, command: &str, parameters: &serde_json::Value) -> Result<serde_json::Value>;

    fn validate_environment(&self) -> Result<bool>;
}

pub trait AIEnrichmentAdapter: Send + Sync {
    fn enrich_enforcement(
        &self,
        request: &EnforcementRequest,
        poa: &PoaCredential,
        decision: &EnforcementDecision,
    ) -> Result<EnforcementDecision>;

    fn score_risk(
        &self,
        request: &EnforcementRequest,
        poa: &PoaCredential,
    ) -> Result<f64>;
}

pub trait RiskScoringAdapter: Send + Sync {
    fn compute_composite_risk(
        &self,
        poa: &PoaCredential,
        context: &serde_json::Value,
    ) -> Result<RiskAssessment>;
}

pub trait RegulatoryReasoningAdapter: Send + Sync {
    fn evaluate_compliance(
        &self,
        poa: &PoaCredential,
        regulatory_context: &serde_json::Value,
    ) -> Result<ComplianceResult>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RiskAssessment {
    pub overall_score: f64,
    pub risk_factors: Vec<RiskFactor>,
    pub recommendation: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RiskFactor {
    pub name: String,
    pub score: f64,
    pub weight: f64,
    pub detail: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceResult {
    pub compliant: bool,
    pub findings: Vec<ComplianceFinding>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceFinding {
    pub regulation: String,
    pub requirement: String,
    pub status: ComplianceStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComplianceStatus {
    Satisfied,
    Violated,
    NotApplicable,
    Undetermined,
}

pub struct NoOpOAuthEngine;

impl OAuthEngineAdapter for NoOpOAuthEngine {
    fn authorize(&self, _client_id: &str, _scope: &str, _redirect_uri: &str) -> Result<String> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No OAuth engine configured".into(),
        ))
    }

    fn token(
        &self,
        _grant_type: &str,
        _code: &str,
        _redirect_uri: &str,
    ) -> Result<serde_json::Value> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No OAuth engine configured".into(),
        ))
    }

    fn introspect(&self, _token: &str) -> Result<serde_json::Value> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No OAuth engine configured".into(),
        ))
    }

    fn revoke(&self, _token: &str) -> Result<()> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No OAuth engine configured".into(),
        ))
    }

    fn jwks(&self) -> Result<serde_json::Value> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No OAuth engine configured".into(),
        ))
    }
}

pub struct NoOpFoundry;

impl FoundryAdapter for NoOpFoundry {
    fn execute(
        &self,
        _command: &str,
        _parameters: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        Err(crate::error::GAuthError::AdapterNotFound(
            "No foundry configured".into(),
        ))
    }

    fn validate_environment(&self) -> Result<bool> {
        Ok(true)
    }
}

pub struct RuleBasedEnrichment;

impl AIEnrichmentAdapter for RuleBasedEnrichment {
    fn enrich_enforcement(
        &self,
        _request: &EnforcementRequest,
        _poa: &PoaCredential,
        decision: &EnforcementDecision,
    ) -> Result<EnforcementDecision> {
        Ok(decision.clone())
    }

    fn score_risk(
        &self,
        _request: &EnforcementRequest,
        _poa: &PoaCredential,
    ) -> Result<f64> {
        Ok(0.0)
    }
}

pub struct RuleBasedRiskScoring;

impl RiskScoringAdapter for RuleBasedRiskScoring {
    fn compute_composite_risk(
        &self,
        _poa: &PoaCredential,
        _context: &serde_json::Value,
    ) -> Result<RiskAssessment> {
        Ok(RiskAssessment {
            overall_score: 0.0,
            risk_factors: vec![],
            recommendation: "No risk assessment available (rule-based fallback)".into(),
        })
    }
}

pub struct RuleBasedRegulatoryReasoning;

impl RegulatoryReasoningAdapter for RuleBasedRegulatoryReasoning {
    fn evaluate_compliance(
        &self,
        _poa: &PoaCredential,
        _regulatory_context: &serde_json::Value,
    ) -> Result<ComplianceResult> {
        Ok(ComplianceResult {
            compliant: true,
            findings: vec![],
        })
    }
}
