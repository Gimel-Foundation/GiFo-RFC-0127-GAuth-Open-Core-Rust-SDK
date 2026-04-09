use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPolicy {
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_cents_base: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<ToolConstraints>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConstraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_commands: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied_commands: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_file_size_bytes: Option<u64>,
}

pub type CoreVerbs = HashMap<String, ToolPolicy>;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformPermissions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment: Option<DeploymentPermissions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<DatabasePermissions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<ShellPermissions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packages: Option<PackagePermissions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_apis: Option<ExternalApiPermissions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<SecretPermissions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentPermissions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_deploy: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabasePermissions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migrate: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub production_access: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellPermissions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<ShellMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denylist: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShellMode {
    Any,
    Denylist,
    Allowlist,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackagePermissions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalApiPermissions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPermissions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Budget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_cents: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_cents: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionLimits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tool_calls: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_tool_calls: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_lines_per_commit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
}
