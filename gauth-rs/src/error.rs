// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GAuthError {
    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Credential integrity check failed: {0}")]
    CredentialIntegrity(String),

    #[error("Credential expired")]
    CredentialExpired,

    #[error("Credential revoked")]
    CredentialRevoked,

    #[error("Credential superseded")]
    CredentialSuperseded,

    #[error("Agent mismatch: expected {expected}, got {actual}")]
    AgentMismatch { expected: String, actual: String },

    #[error("Profile ceiling exceeded: {0}")]
    ProfileCeilingExceeded(String),

    #[error("Phase mismatch: action requires {required}, PoA phase is {actual}")]
    PhaseMismatch { required: String, actual: String },

    #[error("Sector mismatch: {0}")]
    SectorMismatch(String),

    #[error("Region mismatch: {0}")]
    RegionMismatch(String),

    #[error("Path denied: {0}")]
    PathDenied(String),

    #[error("Path not allowed: {0}")]
    PathNotAllowed(String),

    #[error("Verb not allowed: {0}")]
    VerbNotAllowed(String),

    #[error("Constraint violated: {0}")]
    ConstraintViolated(String),

    #[error("Platform permission denied: {0}")]
    PlatformPermissionDenied(String),

    #[error("Transaction not allowed: {0}")]
    TransactionNotAllowed(String),

    #[error("Decision not allowed: {0}")]
    DecisionNotAllowed(String),

    #[error("Budget exceeded: remaining {remaining} cents, required {required} cents")]
    BudgetExceeded { remaining: i64, required: i64 },

    #[error("Budget exhausted")]
    BudgetExhausted,

    #[error("Session limit exceeded: {0}")]
    SessionLimitExceeded(String),

    #[error("Approval required: {0}")]
    ApprovalRequired(String),

    #[error("Delegation depth exceeded: max {max}, actual {actual}")]
    DelegationDepthExceeded { max: u32, actual: u32 },

    #[error("Delegation scope exceeded: {0}")]
    DelegationScopeExceeded(String),

    #[error("Invalid mandate state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("Mandate not found: {0}")]
    MandateNotFound(String),

    #[error("Scope immutable: cannot modify scope of active mandate")]
    ScopeImmutable,

    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    #[error("Adapter registration failed: {0}")]
    AdapterRegistrationFailed(String),

    #[error("Cannot unregister mandatory slot: {0}")]
    MandatorySlotProtected(String),

    #[error("Adapter signature verification failed: {0}")]
    AdapterSignatureInvalid(String),

    #[error("Adapter not found: {0}")]
    AdapterNotFound(String),

    #[error("Only RS256 and ES256 algorithms are permitted by GAuth specification")]
    Hs256Prohibited,

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("License compliance violation: {0}")]
    LicenseComplianceViolation(String),

    #[error("Tariff downgrade: {0}")]
    TariffDowngrade(String),

    #[error("Delegation requires approval")]
    DelegationRequiresApproval,

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, GAuthError>;
