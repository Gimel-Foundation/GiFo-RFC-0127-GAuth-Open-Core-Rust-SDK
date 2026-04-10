use crate::types::*;
use super::types::ValidationResult;

pub fn validate_mandate_creation(
    parties: &Parties,
    scope: &Scope,
    requirements: &Requirements,
) -> ValidationResult {
    let mut schema_errors = Vec::new();
    let mut ceiling_violations = Vec::new();
    let mut consistency_errors = Vec::new();

    if parties.issuer.is_empty() {
        schema_errors.push("parties.issuer is required".into());
    }
    if parties.subject.is_empty() {
        schema_errors.push("parties.subject is required".into());
    }
    if parties.customer_id.is_empty() {
        schema_errors.push("parties.customer_id is required".into());
    }
    if parties.project_id.is_empty() {
        schema_errors.push("parties.project_id is required".into());
    }

    if scope.core_verbs.is_empty() {
        schema_errors.push("scope.core_verbs must contain at least one verb".into());
    }

    if let Some(ttl) = requirements.ttl_seconds {
        if ttl < 60 {
            schema_errors.push("requirements.ttl_seconds must be >= 60".into());
        }
    }

    let profile = &scope.governance_profile;

    if let Some(ref budget) = requirements.budget {
        if let (Some(total), Some(max)) = (budget.total_cents, profile.max_budget_cents()) {
            if total > max {
                ceiling_violations.push(format!(
                    "Budget {total} cents exceeds profile {profile:?} ceiling of {max} cents"
                ));
            }
        }
    }

    if requirements.approval_mode < profile.minimum_approval_mode() {
        ceiling_violations.push(format!(
            "Approval mode {:?} is less strict than profile {:?} minimum {:?}",
            requirements.approval_mode,
            profile,
            profile.minimum_approval_mode()
        ));
    }

    if let Some(ref dp) = scope.platform_permissions {
        if let Some(ref depl) = dp.deployment {
            if let Some(ref targets) = depl.targets {
                let allowed = profile.allowed_deployment_targets();
                for t in targets {
                    if !allowed.contains(&t.as_str()) {
                        ceiling_violations.push(format!(
                            "Deployment target '{t}' not allowed for profile {profile:?}"
                        ));
                    }
                }
            }
            if depl.auto_deploy == Some(true) && !profile.allows_auto_deploy() {
                ceiling_violations.push(format!(
                    "Auto-deploy not allowed for profile {profile:?}"
                ));
            }
        }
    }

    if let Some(ref chain) = scope.allowed_paths {
        if let Some(ref denied) = scope.denied_paths {
            for p in chain {
                if denied.contains(p) {
                    consistency_errors.push(format!(
                        "Path '{p}' appears in both allowed_paths and denied_paths"
                    ));
                }
            }
        }
    }

    if requirements.approval_mode == ApprovalMode::FourEyes
        && parties.approval_chain.as_ref().map(|c| c.len()).unwrap_or(0) < 2 {
            consistency_errors.push(
                "Four-eyes approval mode requires at least 2 members in approval_chain".into(),
            );
        }

    if scope.phase == Phase::Plan {
        for (verb, policy) in &scope.core_verbs {
            if policy.allowed
                && (verb.contains("create")
                    || verb.contains("modify")
                    || verb.contains("delete")
                    || verb.contains("deploy"))
            {
                consistency_errors.push(format!(
                    "Write verb '{verb}' is allowed but phase is 'plan' (read-only)"
                ));
            }
        }
    }

    if let Some(ref budget) = requirements.budget {
        if let (Some(remaining), Some(total)) = (budget.remaining_cents, budget.total_cents) {
            if remaining > total {
                consistency_errors.push(format!(
                    "remaining_cents ({remaining}) > total_cents ({total})"
                ));
            }
        }
    }

    if !profile.allows_delegation() {
        for (verb, policy) in &scope.core_verbs {
            if verb.contains("delegate") && policy.allowed {
                consistency_errors.push(format!(
                    "Delegation verb '{verb}' is allowed but profile {profile:?} does not allow delegation"
                ));
            }
        }
    }

    let accepted = schema_errors.is_empty()
        && ceiling_violations.is_empty()
        && consistency_errors.is_empty();

    ValidationResult {
        accepted,
        schema_errors: if schema_errors.is_empty() {
            None
        } else {
            Some(schema_errors)
        },
        ceiling_violations: if ceiling_violations.is_empty() {
            None
        } else {
            Some(ceiling_violations)
        },
        consistency_errors: if consistency_errors.is_empty() {
            None
        } else {
            Some(consistency_errors)
        },
    }
}
