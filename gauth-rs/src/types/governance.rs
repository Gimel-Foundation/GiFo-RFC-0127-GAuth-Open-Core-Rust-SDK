// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GovernanceProfile {
    Minimal,
    Standard,
    Strict,
    Enterprise,
    Behoerde,
}

impl GovernanceProfile {
    pub fn max_budget_cents(&self) -> Option<i64> {
        match self {
            GovernanceProfile::Minimal => Some(1_000),
            GovernanceProfile::Standard => Some(10_000),
            GovernanceProfile::Strict => Some(100_000),
            GovernanceProfile::Enterprise => Some(1_000_000),
            GovernanceProfile::Behoerde => None,
        }
    }

    pub fn allows_auto_deploy(&self) -> bool {
        matches!(self, GovernanceProfile::Minimal | GovernanceProfile::Standard)
    }

    pub fn allowed_deployment_targets(&self) -> Vec<&'static str> {
        match self {
            GovernanceProfile::Minimal => vec!["dev"],
            GovernanceProfile::Standard => vec!["dev", "staging"],
            GovernanceProfile::Strict => vec!["dev", "staging"],
            GovernanceProfile::Enterprise => vec!["dev", "staging", "prod"],
            GovernanceProfile::Behoerde => vec!["dev", "staging", "prod"],
        }
    }

    pub fn minimum_approval_mode(&self) -> ApprovalMode {
        match self {
            GovernanceProfile::Minimal => ApprovalMode::Autonomous,
            GovernanceProfile::Standard => ApprovalMode::Autonomous,
            GovernanceProfile::Strict => ApprovalMode::Supervised,
            GovernanceProfile::Enterprise => ApprovalMode::Supervised,
            GovernanceProfile::Behoerde => ApprovalMode::FourEyes,
        }
    }

    pub fn allows_delegation(&self) -> bool {
        matches!(
            self,
            GovernanceProfile::Standard
                | GovernanceProfile::Strict
                | GovernanceProfile::Enterprise
                | GovernanceProfile::Behoerde
        )
    }

    pub fn approval_required_for_delegation(&self) -> bool {
        matches!(
            self,
            GovernanceProfile::Strict
                | GovernanceProfile::Enterprise
                | GovernanceProfile::Behoerde
        )
    }

    pub fn max_delegation_depth(&self) -> u32 {
        match self {
            GovernanceProfile::Minimal => 0,
            GovernanceProfile::Standard => 1,
            GovernanceProfile::Strict => 2,
            GovernanceProfile::Enterprise => 3,
            GovernanceProfile::Behoerde => 2,
        }
    }

    pub fn requires_production_access_approval(&self) -> bool {
        matches!(
            self,
            GovernanceProfile::Strict | GovernanceProfile::Enterprise | GovernanceProfile::Behoerde
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Plan,
    Build,
    Run,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalMode {
    Autonomous,
    Supervised,
    #[serde(rename = "four-eyes")]
    FourEyes,
}
