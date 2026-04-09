use std::time::Instant;

use crate::types::PoaCredential;
use super::checks;
use super::types::*;

const PEP_VERSION: &str = "0.1.0";
const PEP_INTERFACE_VERSION: &str = "1.2";

pub struct PepEngine {
    pub mode: EnforcementMode,
}

impl Default for PepEngine {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::Stateless,
        }
    }
}

impl PepEngine {
    pub fn new(mode: EnforcementMode) -> Self {
        Self { mode }
    }

    pub fn enforce_action(
        &self,
        request: &EnforcementRequest,
        poa: &PoaCredential,
    ) -> EnforcementDecision {
        let start = Instant::now();
        let mut all_checks = Vec::new();
        let mut all_violations = Vec::new();
        let mut all_constraints = Vec::new();

        let chk01 = checks::chk01_credential_integrity(&request.credential, poa);
        collect_result(&chk01, &mut all_violations, "CREDENTIAL_INVALID");
        let has_fatal = chk01.result == CheckOutcome::Fail;
        all_checks.push(chk01);

        if !has_fatal {
            let chk02 = checks::chk02_temporal_status(
                &request.agent, poa, request.context.as_ref(),
            );
            collect_result(&chk02, &mut all_violations, "CREDENTIAL_EXPIRED");
            all_checks.push(chk02);

            let chk03 = checks::chk03_governance_profile(&request.action, poa);
            collect_result(&chk03, &mut all_violations, "PROFILE_CEILING_EXCEEDED");
            all_checks.push(chk03);

            let chk04 = checks::chk04_phase(&request.action, poa);
            collect_result(&chk04, &mut all_violations, "PHASE_MISMATCH");
            all_checks.push(chk04);

            let chk05 = checks::chk05_sector(&request.action, poa);
            collect_result(&chk05, &mut all_violations, "SECTOR_MISMATCH");
            all_checks.push(chk05);

            let chk06 = checks::chk06_region(&request.action, poa);
            collect_result(&chk06, &mut all_violations, "REGION_MISMATCH");
            all_checks.push(chk06);

            let chk07 = checks::chk07_path(&request.action, poa);
            collect_result(&chk07, &mut all_violations, "PATH_DENIED");
            all_checks.push(chk07);

            let chk08 = checks::chk08_verb_permission(&request.action, poa);
            collect_result(&chk08, &mut all_violations, "VERB_NOT_ALLOWED");
            all_checks.push(chk08);

            let (chk09, c09) = checks::chk09_verb_constraints(&request.action, poa);
            collect_result(&chk09, &mut all_violations, "CONSTRAINT_VIOLATED");
            all_constraints.extend(c09);
            all_checks.push(chk09);

            let chk10 = checks::chk10_platform_permissions(&request.action, poa);
            collect_result(&chk10, &mut all_violations, "PLATFORM_PERMISSION_DENIED");
            all_checks.push(chk10);

            let chk11 = checks::chk11_transaction_type(&request.action, poa);
            collect_result(&chk11, &mut all_violations, "TRANSACTION_NOT_ALLOWED");
            all_checks.push(chk11);

            let chk12 = checks::chk12_decision_type(&request.action, poa);
            collect_result(&chk12, &mut all_violations, "DECISION_NOT_ALLOWED");
            all_checks.push(chk12);

            let chk13 = checks::chk13_budget(
                &request.action, poa, request.context.as_ref(),
            );
            collect_result(&chk13, &mut all_violations, "BUDGET_EXCEEDED");
            all_checks.push(chk13);

            let chk14 = checks::chk14_session_limits(
                &request.action, poa, request.context.as_ref(),
            );
            collect_result(&chk14, &mut all_violations, "SESSION_LIMIT_EXCEEDED");
            all_checks.push(chk14);

            let chk15 = checks::chk15_approval(&request.action, poa);
            collect_result(&chk15, &mut all_violations, "APPROVAL_REQUIRED");
            if chk15.result == CheckOutcome::Constrain {
                all_constraints.push(EnforcedConstraint {
                    constraint_type: "approval_logged".into(),
                    check_id: "CHK-15".into(),
                    requested: serde_json::Value::String(
                        format!("{:?}", poa.requirements.approval_mode),
                    ),
                    enforced: serde_json::Value::String("supervised".into()),
                });
            }
            all_checks.push(chk15);

            let chk16 = checks::chk16_delegation_chain(poa);
            collect_result(&chk16, &mut all_violations, "DELEGATION_DEPTH_EXCEEDED");
            all_checks.push(chk16);
        }

        let elapsed = start.elapsed();
        let has_errors = all_violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Error);
        let has_constraints = all_checks.iter().any(|c| c.result == CheckOutcome::Constrain);

        let decision = if has_errors {
            Decision::Deny
        } else if has_constraints {
            Decision::Constrain
        } else {
            Decision::Permit
        };

        let checks_passed = all_checks
            .iter()
            .filter(|c| c.result == CheckOutcome::Pass || c.result == CheckOutcome::Skip)
            .count() as i32;
        let checks_failed = all_checks
            .iter()
            .filter(|c| c.result == CheckOutcome::Fail)
            .count() as i32;

        EnforcementDecision {
            request_id: request.request_id.clone(),
            decision,
            timestamp: chrono::Utc::now(),
            enforcement_mode: self.mode.clone(),
            checks: all_checks.clone(),
            enforced_constraints: if all_constraints.is_empty() {
                None
            } else {
                Some(all_constraints)
            },
            violations: if all_violations.is_empty() {
                None
            } else {
                Some(all_violations)
            },
            audit: Some(AuditRecord {
                processing_time_ms: elapsed.as_secs_f64() * 1000.0,
                pep_version: PEP_VERSION.into(),
                pep_interface_version: Some(PEP_INTERFACE_VERSION.into()),
                credential_jti: None,
                mandate_id: request.credential.mandate_id.clone(),
                agent_id: Some(request.agent.agent_id.clone()),
                action_verb: Some(request.action.verb.clone()),
                action_resource: Some(request.action.resource.clone()),
                checks_performed: Some(all_checks.len() as i32),
                checks_passed: Some(checks_passed),
                checks_failed: Some(checks_failed),
            }),
        }
    }

    pub fn batch_enforce(
        &self,
        requests: &[EnforcementRequest],
        poas: &[PoaCredential],
        mode: BatchMode,
    ) -> BatchDecision {
        assert_eq!(
            requests.len(),
            poas.len(),
            "requests and poas must have same length"
        );

        let decisions: Vec<EnforcementDecision> = requests
            .iter()
            .zip(poas.iter())
            .map(|(req, poa)| self.enforce_action(req, poa))
            .collect();

        let overall = match mode {
            BatchMode::AllOrNothing => {
                if decisions.iter().any(|d| d.decision == Decision::Deny) {
                    Decision::Deny
                } else if decisions.iter().any(|d| d.decision == Decision::Constrain) {
                    Decision::Constrain
                } else {
                    Decision::Permit
                }
            }
            BatchMode::Independent => {
                if decisions.iter().all(|d| d.decision == Decision::Permit) {
                    Decision::Permit
                } else if decisions.iter().any(|d| d.decision == Decision::Deny) {
                    Decision::Deny
                } else {
                    Decision::Constrain
                }
            }
        };

        BatchDecision {
            overall_decision: overall,
            decisions,
        }
    }

    pub fn get_enforcement_policy(
        &self,
        poa: &PoaCredential,
    ) -> EnforcementPolicy {
        let allowed_verbs: Vec<String> = poa
            .scope
            .core_verbs
            .iter()
            .filter(|(_, p)| p.allowed)
            .map(|(k, _)| k.clone())
            .collect();

        let profile = &poa.scope.governance_profile;

        EnforcementPolicy {
            governance_profile: serde_json::to_value(profile)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            phase: serde_json::to_value(&poa.scope.phase)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            allowed_verbs,
            denied_paths: poa.scope.denied_paths.clone().unwrap_or_default(),
            allowed_paths: poa.scope.allowed_paths.clone().unwrap_or_default(),
            permissions: serde_json::to_value(&poa.scope.platform_permissions)
                .unwrap_or(serde_json::Value::Null),
            budget: poa.requirements.budget.clone(),
            session_limits: poa
                .requirements
                .session_limits
                .as_ref()
                .and_then(|s| serde_json::to_value(s).ok()),
            approval_mode: serde_json::to_value(&poa.requirements.approval_mode)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            delegation: DelegationInfo {
                allowed: profile.allows_delegation(),
                max_depth: profile.max_delegation_depth(),
            },
        }
    }
}

fn collect_result(check: &CheckResult, violations: &mut Vec<Violation>, code: &str) {
    if check.result == CheckOutcome::Fail {
        violations.push(Violation {
            code: code.to_string(),
            message: check.detail.clone().unwrap_or_default(),
            check_id: check.check_id.clone(),
            severity: ViolationSeverity::Error,
        });
    }
}
