// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use crate::types::*;
use super::types::*;

pub fn chk01_credential_integrity(
    credential: &CredentialReference,
    poa: &PoaCredential,
) -> CheckResult {
    if let Some(ref ver) = poa.schema_version {
        if ver != "0116.2.2" {
            return CheckResult {
                check_id: "CHK-01".into(),
                check_name: "Credential Integrity".into(),
                result: CheckOutcome::Fail,
                detail: Some(format!("Unsupported schema_version: {ver}")),
                failure_code: None,
            };
        }
    }

    if let Some(ref snapshot) = credential.poa_snapshot {
        if let (Ok(snapshot_checksum), Ok(live_checksum)) = (
            crate::crypto::compute_scope_checksum(&snapshot.scope),
            crate::crypto::compute_scope_checksum(&poa.scope),
        ) {
            if snapshot_checksum != live_checksum {
                return CheckResult {
                    check_id: "CHK-01".into(),
                    check_name: "Credential Integrity".into(),
                    result: CheckOutcome::Fail,
                    detail: Some(format!(
                        "scope_checksum mismatch: snapshot '{snapshot_checksum}' != live '{live_checksum}'"
                    )),
                    failure_code: None,
                };
            }
        }
    }

    CheckResult {
        check_id: "CHK-01".into(),
        check_name: "Credential Integrity".into(),
        result: CheckOutcome::Pass,
        detail: None,
        failure_code: None,
    }
}

pub fn chk02_temporal_status(
    agent: &AgentIdentity,
    poa: &PoaCredential,
    context: Option<&EnforcementContext>,
) -> CheckResult {
    if poa.parties.subject != agent.agent_id {
        return CheckResult {
            check_id: "CHK-02".into(),
            check_name: "Temporal & Status".into(),
            result: CheckOutcome::Fail,
            detail: Some(format!(
                "Agent mismatch: PoA subject '{}' != agent '{}'",
                poa.parties.subject, agent.agent_id
            )),
            failure_code: Some("AGENT_MISMATCH".into()),
        };
    }

    if let Some(ctx) = context {
        if let Some(ref live) = ctx.live_mandate_state {
            if let Some(ref status) = live.status {
                match status.as_str() {
                    "active" => {}
                    "revoked" => {
                        return CheckResult {
                            check_id: "CHK-02".into(),
                            check_name: "Temporal & Status".into(),
                            result: CheckOutcome::Fail,
                            detail: Some("Credential revoked".into()),
                            failure_code: Some("CREDENTIAL_REVOKED".into()),
                        };
                    }
                    "expired" => {
                        return CheckResult {
                            check_id: "CHK-02".into(),
                            check_name: "Temporal & Status".into(),
                            result: CheckOutcome::Fail,
                            detail: Some("Mandate expired".into()),
                            failure_code: Some("CREDENTIAL_EXPIRED".into()),
                        };
                    }
                    "superseded" => {
                        return CheckResult {
                            check_id: "CHK-02".into(),
                            check_name: "Temporal & Status".into(),
                            result: CheckOutcome::Fail,
                            detail: Some("Credential superseded".into()),
                            failure_code: Some("CREDENTIAL_SUPERSEDED".into()),
                        };
                    }
                    "budget_exceeded" => {
                        return CheckResult {
                            check_id: "CHK-02".into(),
                            check_name: "Temporal & Status".into(),
                            result: CheckOutcome::Fail,
                            detail: Some("Budget exhausted".into()),
                            failure_code: Some("BUDGET_EXCEEDED".into()),
                        };
                    }
                    "suspended" => {
                        return CheckResult {
                            check_id: "CHK-02".into(),
                            check_name: "Temporal & Status".into(),
                            result: CheckOutcome::Fail,
                            detail: Some("Mandate suspended".into()),
                            failure_code: Some("MANDATE_SUSPENDED".into()),
                        };
                    }
                    _ => {
                        return CheckResult {
                            check_id: "CHK-02".into(),
                            check_name: "Temporal & Status".into(),
                            result: CheckOutcome::Fail,
                            detail: Some(format!("Unknown mandate status: {status}")),
                            failure_code: Some("CREDENTIAL_EXPIRED".into()),
                        };
                    }
                }
            }
        }
    }

    CheckResult {
        check_id: "CHK-02".into(),
        check_name: "Temporal & Status".into(),
        result: CheckOutcome::Pass,
        detail: None,
        failure_code: None,
    }
}

pub fn chk03_governance_profile(
    action: &ActionDescriptor,
    poa: &PoaCredential,
) -> CheckResult {
    let profile = &poa.scope.governance_profile;

    if let Some(ref params) = action.parameters {
        if let Some(serde_json::Value::Bool(true)) = params.get("auto_deploy") {
            if !profile.allows_auto_deploy() {
                return CheckResult {
                    check_id: "CHK-03".into(),
                    check_name: "Governance Profile".into(),
                    result: CheckOutcome::Fail,
                    detail: Some(format!(
                        "Auto-deploy not allowed for profile {profile:?}"
                    )),
                    failure_code: None,
                };
            }
        }
    }

    if poa.requirements.approval_mode < profile.minimum_approval_mode() {
        return CheckResult {
            check_id: "CHK-03".into(),
            check_name: "Governance Profile".into(),
            result: CheckOutcome::Fail,
            detail: Some(format!(
                "Approval mode {:?} is less strict than profile minimum {:?}",
                poa.requirements.approval_mode,
                profile.minimum_approval_mode()
            )),
            failure_code: None,
        };
    }

    CheckResult {
        check_id: "CHK-03".into(),
        check_name: "Governance Profile".into(),
        result: CheckOutcome::Pass,
        detail: None,
        failure_code: None,
    }
}

pub fn chk04_phase(action: &ActionDescriptor, poa: &PoaCredential) -> CheckResult {
    let verb = &action.verb;
    let phase = &poa.scope.phase;

    let permitted = match phase {
        Phase::Plan => {
            verb.contains("read") || verb.contains("list") || verb.contains("get")
                || verb.contains("analyze") || verb.contains("plan")
        }
        Phase::Build => {
            !verb.contains("deploy") && !verb.contains("production")
        }
        Phase::Run => true,
    };

    if !permitted {
        return CheckResult {
            check_id: "CHK-04".into(),
            check_name: "Phase".into(),
            result: CheckOutcome::Fail,
            detail: Some(format!(
                "Verb '{verb}' not permitted in phase {phase:?}"
            )),
            failure_code: None,
        };
    }

    CheckResult {
        check_id: "CHK-04".into(),
        check_name: "Phase".into(),
        result: CheckOutcome::Pass,
        detail: None,
        failure_code: None,
    }
}

pub fn chk05_sector(action: &ActionDescriptor, poa: &PoaCredential) -> CheckResult {
    let allowed = match &poa.scope.allowed_sectors {
        Some(sectors) if !sectors.is_empty() => sectors,
        _ => {
            return CheckResult {
                check_id: "CHK-05".into(),
                check_name: "Sector".into(),
                result: CheckOutcome::Skip,
                detail: Some("No sector restriction".into()),
                failure_code: None,
            };
        }
    };

    match &action.sector {
        None => CheckResult {
            check_id: "CHK-05".into(),
            check_name: "Sector".into(),
            result: CheckOutcome::Fail,
            detail: Some("Sector-restricted PoA requires sector context on action".into()),
            failure_code: None,
        },
        Some(sector) => {
            if allowed.contains(sector) {
                CheckResult {
                    check_id: "CHK-05".into(),
                    check_name: "Sector".into(),
                    result: CheckOutcome::Pass,
                    detail: None,
                    failure_code: None,
                }
            } else {
                CheckResult {
                    check_id: "CHK-05".into(),
                    check_name: "Sector".into(),
                    result: CheckOutcome::Fail,
                    detail: Some(format!("Sector '{sector}' not in allowed sectors")),
                    failure_code: None,
                }
            }
        }
    }
}

static EU_MEMBERS: &[&str] = &[
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE",
];

fn region_matches(action_region: &str, allowed_region: &str) -> bool {
    if action_region == allowed_region {
        return true;
    }
    if allowed_region == "EU" && EU_MEMBERS.contains(&action_region) {
        return true;
    }
    false
}

pub fn chk06_region(action: &ActionDescriptor, poa: &PoaCredential) -> CheckResult {
    let allowed = match &poa.scope.allowed_regions {
        Some(regions) if !regions.is_empty() => regions,
        _ => {
            return CheckResult {
                check_id: "CHK-06".into(),
                check_name: "Region".into(),
                result: CheckOutcome::Skip,
                detail: Some("No region restriction".into()),
                failure_code: None,
            };
        }
    };

    match &action.region {
        None => CheckResult {
            check_id: "CHK-06".into(),
            check_name: "Region".into(),
            result: CheckOutcome::Fail,
            detail: Some("Region-restricted PoA requires region context on action".into()),
            failure_code: None,
        },
        Some(region) => {
            let matched = allowed.iter().any(|r| region_matches(region, r));
            if matched {
                CheckResult {
                    check_id: "CHK-06".into(),
                    check_name: "Region".into(),
                    result: CheckOutcome::Pass,
                    detail: None,
                    failure_code: None,
                }
            } else {
                CheckResult {
                    check_id: "CHK-06".into(),
                    check_name: "Region".into(),
                    result: CheckOutcome::Fail,
                    detail: Some(format!("Region '{region}' not in allowed regions")),
                    failure_code: None,
                }
            }
        }
    }
}

pub fn chk07_path(action: &ActionDescriptor, poa: &PoaCredential) -> CheckResult {
    if let Some(ref rt) = action.resource_type {
        if rt == "shell" || rt == "api" {
            return CheckResult {
                check_id: "CHK-07".into(),
                check_name: "Path".into(),
                result: CheckOutcome::Skip,
                detail: Some("Non-path resource type".into()),
                failure_code: None,
            };
        }
    }

    let resource = &action.resource;

    if let Some(ref denied) = poa.scope.denied_paths {
        for pattern in denied {
            if glob_match::glob_match(pattern, resource) {
                return CheckResult {
                    check_id: "CHK-07".into(),
                    check_name: "Path".into(),
                    result: CheckOutcome::Fail,
                    detail: Some(format!("Path '{resource}' matches denied pattern '{pattern}'")),
                    failure_code: None,
                };
            }
        }
    }

    if let Some(ref allowed) = poa.scope.allowed_paths {
        if allowed.is_empty() {
            return CheckResult {
                check_id: "CHK-07".into(),
                check_name: "Path".into(),
                result: CheckOutcome::Pass,
                detail: None,
                failure_code: None,
            };
        }
        let matched = allowed.iter().any(|p| glob_match::glob_match(p, resource));
        if !matched {
            return CheckResult {
                check_id: "CHK-07".into(),
                check_name: "Path".into(),
                result: CheckOutcome::Fail,
                detail: Some(format!("Path '{resource}' not in allowed paths")),
                failure_code: None,
            };
        }
    }

    CheckResult {
        check_id: "CHK-07".into(),
        check_name: "Path".into(),
        result: CheckOutcome::Pass,
        detail: None,
        failure_code: None,
    }
}

pub fn chk08_verb_permission(action: &ActionDescriptor, poa: &PoaCredential) -> CheckResult {
    let verb = &action.verb;

    match poa.scope.core_verbs.get(verb) {
        None => CheckResult {
            check_id: "CHK-08".into(),
            check_name: "Verb Permission".into(),
            result: CheckOutcome::Fail,
            detail: Some(format!("Verb '{verb}' not registered in core_verbs")),
            failure_code: None,
        },
        Some(policy) => {
            if policy.allowed {
                CheckResult {
                    check_id: "CHK-08".into(),
                    check_name: "Verb Permission".into(),
                    result: CheckOutcome::Pass,
                    detail: None,
                    failure_code: None,
                }
            } else {
                CheckResult {
                    check_id: "CHK-08".into(),
                    check_name: "Verb Permission".into(),
                    result: CheckOutcome::Fail,
                    detail: Some(format!("Verb '{verb}' is not allowed")),
                    failure_code: None,
                }
            }
        }
    }
}

pub fn chk09_verb_constraints(
    action: &ActionDescriptor,
    poa: &PoaCredential,
) -> (CheckResult, Vec<EnforcedConstraint>) {
    let verb = &action.verb;
    let mut constraints_applied = Vec::new();

    let policy = match poa.scope.core_verbs.get(verb) {
        Some(p) => p,
        None => {
            return (
                CheckResult {
                    check_id: "CHK-09".into(),
                    check_name: "Verb Constraints".into(),
                    result: CheckOutcome::Skip,
                    detail: Some("No verb entry (already handled by CHK-08)".into()),
                    failure_code: None,
                },
                constraints_applied,
            );
        }
    };

    let tc = match &policy.constraints {
        Some(c) => c,
        None => {
            return (
                CheckResult {
                    check_id: "CHK-09".into(),
                    check_name: "Verb Constraints".into(),
                    result: CheckOutcome::Pass,
                    detail: Some("No constraints defined".into()),
                    failure_code: None,
                },
                constraints_applied,
            );
        }
    };

    if let Some(ref patterns) = tc.path_patterns {
        if !patterns.is_empty() {
            let matched = patterns.iter().any(|p| glob_match::glob_match(p, &action.resource));
            if !matched {
                return (
                    CheckResult {
                        check_id: "CHK-09".into(),
                        check_name: "Verb Constraints".into(),
                        result: CheckOutcome::Fail,
                        detail: Some(format!(
                            "Resource '{}' does not match path_patterns",
                            action.resource
                        )),
                        failure_code: None,
                    },
                    constraints_applied,
                );
            }
            constraints_applied.push(EnforcedConstraint {
                constraint_type: "path_restricted".into(),
                check_id: "CHK-09".into(),
                requested: serde_json::Value::String(action.resource.clone()),
                enforced: serde_json::to_value(patterns).unwrap_or_default(),
            });
        }
    }

    if let Some(ref allowed_cmds) = tc.allowed_commands {
        if let Some(ref params) = action.parameters {
            if let Some(cmd_val) = params.get("command") {
                if let Some(cmd) = cmd_val.as_str() {
                    if !allowed_cmds.iter().any(|c| c == cmd) {
                        return (
                            CheckResult {
                                check_id: "CHK-09".into(),
                                check_name: "Verb Constraints".into(),
                                result: CheckOutcome::Fail,
                                detail: Some(format!("Command '{cmd}' not in allowed_commands")),
                                failure_code: None,
                            },
                            constraints_applied,
                        );
                    }
                }
            }
        }
    }

    if let Some(ref denied_cmds) = tc.denied_commands {
        if let Some(ref params) = action.parameters {
            if let Some(cmd_val) = params.get("command") {
                if let Some(cmd) = cmd_val.as_str() {
                    if denied_cmds.iter().any(|c| c == cmd) {
                        return (
                            CheckResult {
                                check_id: "CHK-09".into(),
                                check_name: "Verb Constraints".into(),
                                result: CheckOutcome::Fail,
                                detail: Some(format!("Command '{cmd}' in denied_commands")),
                                failure_code: None,
                            },
                            constraints_applied,
                        );
                    }
                }
            }
        }
    }

    if let Some(max_size) = tc.max_file_size_bytes {
        if let Some(ref params) = action.parameters {
            if let Some(size_val) = params.get("file_size_bytes") {
                if let Some(size) = size_val.as_u64() {
                    if size > max_size {
                        return (
                            CheckResult {
                                check_id: "CHK-09".into(),
                                check_name: "Verb Constraints".into(),
                                result: CheckOutcome::Fail,
                                detail: Some(format!(
                                    "File size {size} exceeds max {max_size}"
                                )),
                                failure_code: None,
                            },
                            constraints_applied,
                        );
                    }
                    constraints_applied.push(EnforcedConstraint {
                        constraint_type: "file_size_limited".into(),
                        check_id: "CHK-09".into(),
                        requested: serde_json::Value::Number(size.into()),
                        enforced: serde_json::Value::Number(max_size.into()),
                    });
                }
            }
        }
    }

    let outcome = if constraints_applied.is_empty() {
        CheckOutcome::Pass
    } else {
        CheckOutcome::Constrain
    };

    (
        CheckResult {
            check_id: "CHK-09".into(),
            check_name: "Verb Constraints".into(),
            result: outcome,
            detail: None,
            failure_code: None,
        },
        constraints_applied,
    )
}

pub fn chk10_platform_permissions(
    action: &ActionDescriptor,
    poa: &PoaCredential,
) -> CheckResult {
    let perms = match &poa.scope.platform_permissions {
        Some(p) => p,
        None => {
            return CheckResult {
                check_id: "CHK-10".into(),
                check_name: "Platform Permissions".into(),
                result: CheckOutcome::Skip,
                detail: Some("No platform permissions defined".into()),
                failure_code: None,
            };
        }
    };

    let rt = action.resource_type.as_deref().unwrap_or("");

    match rt {
        "deployment" => {
            if let Some(ref dp) = perms.deployment {
                if let Some(ref targets) = dp.targets {
                    if !targets.iter().any(|t| action.resource.contains(t)) {
                        return CheckResult {
                            check_id: "CHK-10".into(),
                            check_name: "Platform Permissions".into(),
                            result: CheckOutcome::Fail,
                            detail: Some(format!(
                                "Deployment target '{}' not in permitted targets",
                                action.resource
                            )),
                            failure_code: None,
                        };
                    }
                }
            }
        }
        "database" => {
            if let Some(ref db) = perms.database {
                let is_write = action.verb.contains("write") || action.verb.contains("create")
                    || action.verb.contains("delete") || action.verb.contains("modify");
                let is_migrate = action.verb.contains("migrate");
                let is_prod = action.resource.contains("prod");

                if is_write && db.write != Some(true) {
                    return CheckResult {
                        check_id: "CHK-10".into(),
                        check_name: "Platform Permissions".into(),
                        result: CheckOutcome::Fail,
                        detail: Some("Database write not permitted".into()),
                        failure_code: None,
                    };
                }
                if is_migrate && db.migrate != Some(true) {
                    return CheckResult {
                        check_id: "CHK-10".into(),
                        check_name: "Platform Permissions".into(),
                        result: CheckOutcome::Fail,
                        detail: Some("Database migration not permitted".into()),
                        failure_code: None,
                    };
                }
                if is_prod && db.production_access != Some(true) {
                    return CheckResult {
                        check_id: "CHK-10".into(),
                        check_name: "Platform Permissions".into(),
                        result: CheckOutcome::Fail,
                        detail: Some("Production database access not permitted".into()),
                        failure_code: None,
                    };
                }
            }
        }
        "secret" => {
            if let Some(ref sp) = perms.secrets {
                let is_create = action.verb.contains("create");
                let is_read = action.verb.contains("read");
                if is_create && sp.create != Some(true) {
                    return CheckResult {
                        check_id: "CHK-10".into(),
                        check_name: "Platform Permissions".into(),
                        result: CheckOutcome::Fail,
                        detail: Some("Secret creation not permitted".into()),
                        failure_code: None,
                    };
                }
                if is_read && sp.read != Some(true) {
                    return CheckResult {
                        check_id: "CHK-10".into(),
                        check_name: "Platform Permissions".into(),
                        result: CheckOutcome::Fail,
                        detail: Some("Secret read not permitted".into()),
                        failure_code: None,
                    };
                }
            }
        }
        _ => {}
    }

    CheckResult {
        check_id: "CHK-10".into(),
        check_name: "Platform Permissions".into(),
        result: CheckOutcome::Pass,
        detail: None,
        failure_code: None,
    }
}

pub fn chk11_transaction_type(
    action: &ActionDescriptor,
    poa: &PoaCredential,
) -> CheckResult {
    let has_allowed = poa.scope.allowed_transactions.is_some();
    let has_matrix = poa.scope.transaction_matrix.is_some();

    if !has_allowed && !has_matrix {
        return CheckResult {
            check_id: "CHK-11".into(),
            check_name: "Transaction Type".into(),
            result: CheckOutcome::Skip,
            detail: Some("No transaction restrictions".into()),
            failure_code: None,
        };
    }

    let transaction_type = match &action.transaction_type {
        None => {
            if has_allowed || has_matrix {
                return CheckResult {
                    check_id: "CHK-11".into(),
                    check_name: "Transaction Type".into(),
                    result: CheckOutcome::Fail,
                    detail: Some("Transaction-restricted PoA requires transaction_type".into()),
                    failure_code: None,
                };
            }
            return CheckResult {
                check_id: "CHK-11".into(),
                check_name: "Transaction Type".into(),
                result: CheckOutcome::Pass,
                detail: None,
                failure_code: None,
            };
        }
        Some(tt) => tt,
    };

    if let Some(ref allowed) = poa.scope.allowed_transactions {
        if !allowed.contains(transaction_type) {
            return CheckResult {
                check_id: "CHK-11".into(),
                check_name: "Transaction Type".into(),
                result: CheckOutcome::Fail,
                detail: Some(format!("Transaction type '{transaction_type}' not allowed")),
                failure_code: None,
            };
        }
    }

    if let Some(ref matrix) = poa.scope.transaction_matrix {
        if let Some(matrix_obj) = matrix.as_object() {
            match matrix_obj.get(transaction_type.as_str()) {
                None => {
                    return CheckResult {
                        check_id: "CHK-11".into(),
                        check_name: "Transaction Type".into(),
                        result: CheckOutcome::Fail,
                        detail: Some(format!(
                            "Transaction type '{transaction_type}' not found in transaction_matrix"
                        )),
                        failure_code: None,
                    };
                }
                Some(entry) => {
                    if let Some(allowed) = entry.get("allowed") {
                        if allowed == &serde_json::Value::Bool(false) {
                            return CheckResult {
                                check_id: "CHK-11".into(),
                                check_name: "Transaction Type".into(),
                                result: CheckOutcome::Fail,
                                detail: Some(format!(
                                    "Transaction type '{transaction_type}' explicitly denied in matrix"
                                )),
                                failure_code: None,
                            };
                        }
                    }

                    if let Some(max_amount) = entry.get("max_amount_cents") {
                        if let Some(max) = max_amount.as_i64() {
                            if let Some(ref params) = action.parameters {
                                if let Some(amount_val) = params.get("amount_cents") {
                                    if let Some(amount) = amount_val.as_i64() {
                                        if amount > max {
                                            return CheckResult {
                                                check_id: "CHK-11".into(),
                                                check_name: "Transaction Type".into(),
                                                result: CheckOutcome::Fail,
                                                detail: Some(format!(
                                                    "Transaction amount {amount} exceeds max {max} for type '{transaction_type}'"
                                                )),
                                                failure_code: None,
                                            };
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if let Some(required_approval) = entry.get("requires_approval") {
                        if required_approval == &serde_json::Value::Bool(true) {
                            return CheckResult {
                                check_id: "CHK-11".into(),
                                check_name: "Transaction Type".into(),
                                result: CheckOutcome::Constrain,
                                detail: Some(format!(
                                    "Transaction type '{transaction_type}' requires approval per matrix"
                                )),
                                failure_code: None,
                            };
                        }
                    }
                }
            }
        }
    }

    CheckResult {
        check_id: "CHK-11".into(),
        check_name: "Transaction Type".into(),
        result: CheckOutcome::Pass,
        detail: None,
        failure_code: None,
    }
}

pub fn chk12_decision_type(action: &ActionDescriptor, poa: &PoaCredential) -> CheckResult {
    let allowed = match &poa.scope.allowed_decisions {
        Some(d) if !d.is_empty() => d,
        _ => {
            return CheckResult {
                check_id: "CHK-12".into(),
                check_name: "Decision Type".into(),
                result: CheckOutcome::Skip,
                detail: Some("No decision-type restriction".into()),
                failure_code: None,
            };
        }
    };

    match &action.decision_type {
        None => CheckResult {
            check_id: "CHK-12".into(),
            check_name: "Decision Type".into(),
            result: CheckOutcome::Fail,
            detail: Some("Decision-restricted PoA requires decision_type".into()),
            failure_code: None,
        },
        Some(dt) => {
            if allowed.contains(dt) {
                CheckResult {
                    check_id: "CHK-12".into(),
                    check_name: "Decision Type".into(),
                    result: CheckOutcome::Pass,
                    detail: None,
                    failure_code: None,
                }
            } else {
                CheckResult {
                    check_id: "CHK-12".into(),
                    check_name: "Decision Type".into(),
                    result: CheckOutcome::Fail,
                    detail: Some(format!("Decision type '{dt}' not permitted")),
                    failure_code: None,
                }
            }
        }
    }
}

pub fn chk13_budget(
    action: &ActionDescriptor,
    poa: &PoaCredential,
    context: Option<&EnforcementContext>,
) -> CheckResult {
    let budget = match &poa.requirements.budget {
        Some(b) => b,
        None => {
            return CheckResult {
                check_id: "CHK-13".into(),
                check_name: "Budget".into(),
                result: CheckOutcome::Skip,
                detail: Some("No budget defined".into()),
                failure_code: None,
            };
        }
    };

    let remaining = if let Some(ctx) = context {
        if let Some(ref live) = ctx.live_mandate_state {
            live.budget_remaining_cents
        } else {
            budget.remaining_cents
        }
    } else {
        budget.remaining_cents
    };

    let remaining = match remaining {
        Some(r) => r,
        None => {
            return CheckResult {
                check_id: "CHK-13".into(),
                check_name: "Budget".into(),
                result: CheckOutcome::Pass,
                detail: Some("No remaining budget tracked".into()),
                failure_code: None,
            };
        }
    };

    if remaining <= 0 {
        return CheckResult {
            check_id: "CHK-13".into(),
            check_name: "Budget".into(),
            result: CheckOutcome::Fail,
            detail: Some("Budget exhausted".into()),
            failure_code: None,
        };
    }

    let explicit_cost = action
        .parameters
        .as_ref()
        .and_then(|p| p.get("amount_cents"))
        .and_then(|v| v.as_f64());

    let verb_base_cost = poa
        .scope
        .core_verbs
        .get(&action.verb)
        .and_then(|p| p.cost_cents_base);

    let effective_cost = explicit_cost.or(verb_base_cost);

    if let Some(cost) = effective_cost {
        if cost as i64 > remaining {
            return CheckResult {
                check_id: "CHK-13".into(),
                check_name: "Budget".into(),
                result: CheckOutcome::Fail,
                detail: Some(format!(
                    "Cost {cost} cents exceeds remaining {remaining} cents"
                )),
                failure_code: None,
            };
        }
    }

    CheckResult {
        check_id: "CHK-13".into(),
        check_name: "Budget".into(),
        result: CheckOutcome::Pass,
        detail: None,
        failure_code: None,
    }
}

pub fn chk14_session_limits(
    _action: &ActionDescriptor,
    poa: &PoaCredential,
    context: Option<&EnforcementContext>,
) -> CheckResult {
    let limits = match &poa.requirements.session_limits {
        Some(l) => l,
        None => {
            return CheckResult {
                check_id: "CHK-14".into(),
                check_name: "Session Limits".into(),
                result: CheckOutcome::Skip,
                detail: Some("No session limits defined".into()),
                failure_code: None,
            };
        }
    };

    if let Some(ctx) = context {
        if let Some(ref session) = ctx.session_state {
            if let (Some(max), Some(used)) = (limits.max_tool_calls, session.tool_calls_used) {
                if used >= max {
                    return CheckResult {
                        check_id: "CHK-14".into(),
                        check_name: "Session Limits".into(),
                        result: CheckOutcome::Fail,
                        detail: Some(format!(
                            "Tool calls used ({used}) >= max ({max})"
                        )),
                        failure_code: None,
                    };
                }
            }

            if let (Some(max_lines), Some(lines)) =
                (limits.max_lines_per_commit, session.lines_committed)
            {
                if lines >= max_lines {
                    return CheckResult {
                        check_id: "CHK-14".into(),
                        check_name: "Session Limits".into(),
                        result: CheckOutcome::Fail,
                        detail: Some(format!(
                            "Lines committed ({lines}) >= max ({max_lines})"
                        )),
                        failure_code: None,
                    };
                }
            }
        }
    }

    CheckResult {
        check_id: "CHK-14".into(),
        check_name: "Session Limits".into(),
        result: CheckOutcome::Pass,
        detail: None,
        failure_code: None,
    }
}

pub fn chk15_approval(
    _action: &ActionDescriptor,
    poa: &PoaCredential,
) -> CheckResult {
    match poa.requirements.approval_mode {
        ApprovalMode::Autonomous => CheckResult {
            check_id: "CHK-15".into(),
            check_name: "Approval".into(),
            result: CheckOutcome::Pass,
            detail: Some("Autonomous mode — no approval required".into()),
            failure_code: None,
        },
        ApprovalMode::Supervised => CheckResult {
            check_id: "CHK-15".into(),
            check_name: "Approval".into(),
            result: CheckOutcome::Constrain,
            detail: Some("Supervised mode — action logged for review".into()),
            failure_code: None,
        },
        ApprovalMode::FourEyes => {
            if let Some(ref chain) = poa.parties.approval_chain {
                if chain.len() >= 2 {
                    CheckResult {
                        check_id: "CHK-15".into(),
                        check_name: "Approval".into(),
                        result: CheckOutcome::Constrain,
                        detail: Some("Four-eyes approval chain present".into()),
                        failure_code: None,
                    }
                } else {
                    CheckResult {
                        check_id: "CHK-15".into(),
                        check_name: "Approval".into(),
                        result: CheckOutcome::Fail,
                        detail: Some(
                            "Four-eyes mode requires at least 2 approvers in chain".into(),
                        ),
                        failure_code: None,
                    }
                }
            } else {
                CheckResult {
                    check_id: "CHK-15".into(),
                    check_name: "Approval".into(),
                    result: CheckOutcome::Fail,
                    detail: Some("Four-eyes mode requires approval_chain".into()),
                    failure_code: None,
                }
            }
        }
    }
}

pub fn chk16_delegation_chain(poa: &PoaCredential) -> CheckResult {
    let chain = match &poa.delegation_chain {
        Some(c) if !c.is_empty() => c,
        _ => {
            return CheckResult {
                check_id: "CHK-16".into(),
                check_name: "Delegation Chain".into(),
                result: CheckOutcome::Skip,
                detail: Some("No delegation chain".into()),
                failure_code: None,
            };
        }
    };

    let max_depth = poa.scope.governance_profile.max_delegation_depth();
    let depth = chain.len() as u32;

    if depth > max_depth {
        return CheckResult {
            check_id: "CHK-16".into(),
            check_name: "Delegation Chain".into(),
            result: CheckOutcome::Fail,
            detail: Some(format!(
                "Delegation depth {} exceeds max {} for profile {:?}",
                depth, max_depth, poa.scope.governance_profile
            )),
            failure_code: None,
        };
    }

    for link in chain {
        if let Some(remaining) = link.max_depth_remaining {
            if remaining == 0 && depth > 1 {
                return CheckResult {
                    check_id: "CHK-16".into(),
                    check_name: "Delegation Chain".into(),
                    result: CheckOutcome::Fail,
                    detail: Some("Delegation depth remaining is 0".into()),
                    failure_code: None,
                };
            }
        }
    }

    CheckResult {
        check_id: "CHK-16".into(),
        check_name: "Delegation Chain".into(),
        result: CheckOutcome::Pass,
        detail: None,
        failure_code: None,
    }
}
