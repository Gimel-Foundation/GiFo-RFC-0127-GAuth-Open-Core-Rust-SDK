use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLink {
    pub delegator: String,
    pub delegate: String,
    pub scope_restriction: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_depth_remaining: Option<u32>,
}

pub type DelegationChain = Vec<DelegationLink>;
