// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::GovernanceProfile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeilingDefinition {
    pub profile: GovernanceProfile,
    pub max_budget_cents: i64,
    pub max_ttl_seconds: i64,
    pub max_delegation_depth: u32,
    pub allows_delegation: bool,
    pub allows_write_verbs: bool,
    pub allows_financial_verbs: bool,
    pub allowed_phases: Vec<String>,
    pub shell_mode: String,
    pub requires_approval: bool,
    pub max_active_mandates: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileInfo {
    pub name: String,
    pub description: String,
    pub ceiling: CeilingDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeilingViolation {
    pub field: String,
    pub ceiling_value: String,
    pub requested_value: String,
    pub message: String,
}

pub fn ceiling_table() -> HashMap<GovernanceProfile, CeilingDefinition> {
    let mut table = HashMap::new();

    table.insert(
        GovernanceProfile::Minimal,
        CeilingDefinition {
            profile: GovernanceProfile::Minimal,
            max_budget_cents: 1000,
            max_ttl_seconds: 3600,
            max_delegation_depth: 0,
            allows_delegation: false,
            allows_write_verbs: false,
            allows_financial_verbs: false,
            allowed_phases: vec!["plan".into(), "build".into()],
            shell_mode: "denylist".into(),
            requires_approval: false,
            max_active_mandates: 5,
        },
    );

    table.insert(
        GovernanceProfile::Standard,
        CeilingDefinition {
            profile: GovernanceProfile::Standard,
            max_budget_cents: 50000,
            max_ttl_seconds: 86400,
            max_delegation_depth: 2,
            allows_delegation: true,
            allows_write_verbs: true,
            allows_financial_verbs: false,
            allowed_phases: vec![
                "plan".into(),
                "build".into(),
                "deploy".into(),
                "maintain".into(),
            ],
            shell_mode: "denylist".into(),
            requires_approval: false,
            max_active_mandates: 20,
        },
    );

    table.insert(
        GovernanceProfile::Strict,
        CeilingDefinition {
            profile: GovernanceProfile::Strict,
            max_budget_cents: 500000,
            max_ttl_seconds: 604800,
            max_delegation_depth: 3,
            allows_delegation: true,
            allows_write_verbs: true,
            allows_financial_verbs: true,
            allowed_phases: vec![
                "plan".into(),
                "build".into(),
                "deploy".into(),
                "maintain".into(),
                "operate".into(),
            ],
            shell_mode: "allowlist".into(),
            requires_approval: true,
            max_active_mandates: 50,
        },
    );

    table.insert(
        GovernanceProfile::Enterprise,
        CeilingDefinition {
            profile: GovernanceProfile::Enterprise,
            max_budget_cents: 5000000,
            max_ttl_seconds: 2592000,
            max_delegation_depth: 5,
            allows_delegation: true,
            allows_write_verbs: true,
            allows_financial_verbs: true,
            allowed_phases: vec![
                "plan".into(),
                "build".into(),
                "deploy".into(),
                "maintain".into(),
                "operate".into(),
            ],
            shell_mode: "allowlist".into(),
            requires_approval: true,
            max_active_mandates: 200,
        },
    );

    table.insert(
        GovernanceProfile::Behoerde,
        CeilingDefinition {
            profile: GovernanceProfile::Behoerde,
            max_budget_cents: 50000000,
            max_ttl_seconds: 31536000,
            max_delegation_depth: 7,
            allows_delegation: true,
            allows_write_verbs: true,
            allows_financial_verbs: true,
            allowed_phases: vec![
                "plan".into(),
                "build".into(),
                "deploy".into(),
                "maintain".into(),
                "operate".into(),
            ],
            shell_mode: "allowlist".into(),
            requires_approval: true,
            max_active_mandates: 1000,
        },
    );

    table
}

pub fn get_ceiling(profile: &GovernanceProfile) -> Option<CeilingDefinition> {
    ceiling_table().get(profile).cloned()
}

pub fn get_profile_info(profile: &GovernanceProfile) -> ProfileInfo {
    let ceiling = get_ceiling(profile).unwrap_or_else(|| {
        get_ceiling(&GovernanceProfile::Minimal).unwrap()
    });

    let description = match profile {
        GovernanceProfile::Minimal => "Read-only, low-budget, no delegation",
        GovernanceProfile::Standard => "General-purpose with moderate limits",
        GovernanceProfile::Strict => "High-assurance with approval workflows",
        GovernanceProfile::Enterprise => "Enterprise-grade with extended limits",
        GovernanceProfile::Behoerde => "Government/regulatory with maximum authority",
    };

    ProfileInfo {
        name: format!("{profile:?}"),
        description: description.into(),
        ceiling,
    }
}

pub fn list_profiles() -> Vec<ProfileInfo> {
    vec![
        get_profile_info(&GovernanceProfile::Minimal),
        get_profile_info(&GovernanceProfile::Standard),
        get_profile_info(&GovernanceProfile::Strict),
        get_profile_info(&GovernanceProfile::Enterprise),
        get_profile_info(&GovernanceProfile::Behoerde),
    ]
}

pub fn validate_against_ceiling(
    profile: &GovernanceProfile,
    budget_cents: Option<i64>,
    ttl_seconds: Option<i64>,
    delegation_depth: Option<u32>,
) -> Vec<CeilingViolation> {
    let ceiling = match get_ceiling(profile) {
        Some(c) => c,
        None => return vec![CeilingViolation {
            field: "profile".into(),
            ceiling_value: "N/A".into(),
            requested_value: format!("{profile:?}"),
            message: "Unknown governance profile".into(),
        }],
    };

    let mut violations = Vec::new();

    if let Some(budget) = budget_cents {
        if budget > ceiling.max_budget_cents {
            violations.push(CeilingViolation {
                field: "budget_cents".into(),
                ceiling_value: ceiling.max_budget_cents.to_string(),
                requested_value: budget.to_string(),
                message: format!(
                    "Budget {budget} exceeds ceiling {} for {:?}",
                    ceiling.max_budget_cents, profile
                ),
            });
        }
    }

    if let Some(ttl) = ttl_seconds {
        if ttl > ceiling.max_ttl_seconds {
            violations.push(CeilingViolation {
                field: "ttl_seconds".into(),
                ceiling_value: ceiling.max_ttl_seconds.to_string(),
                requested_value: ttl.to_string(),
                message: format!(
                    "TTL {ttl} exceeds ceiling {} for {:?}",
                    ceiling.max_ttl_seconds, profile
                ),
            });
        }
    }

    if let Some(depth) = delegation_depth {
        if depth > ceiling.max_delegation_depth {
            violations.push(CeilingViolation {
                field: "delegation_depth".into(),
                ceiling_value: ceiling.max_delegation_depth.to_string(),
                requested_value: depth.to_string(),
                message: format!(
                    "Delegation depth {depth} exceeds ceiling {} for {:?}",
                    ceiling.max_delegation_depth, profile
                ),
            });
        }
    }

    violations
}
