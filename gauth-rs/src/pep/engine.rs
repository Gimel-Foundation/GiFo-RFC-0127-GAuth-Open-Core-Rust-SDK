// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use std::sync::Arc;
use std::time::Instant;

use crate::adapters::{OAuthEngineAdapter, ConnectorSlotRegistry, LicenseComplianceViolation};
use crate::types::PoaCredential;
use super::checks;
use super::types::*;

const PEP_VERSION: &str = "0.92.0";
const PEP_INTERFACE_VERSION: &str = "1.2";

pub struct PepEngine {
    pub mode: EnforcementMode,
    oauth_adapter: Option<Arc<dyn OAuthEngineAdapter>>,
    registry: Option<Arc<ConnectorSlotRegistry>>,
}

impl Default for PepEngine {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::Stateless,
            oauth_adapter: None,
            registry: None,
        }
    }
}

impl PepEngine {
    pub fn new(mode: EnforcementMode) -> Self {
        Self {
            mode,
            oauth_adapter: None,
            registry: None,
        }
    }

    pub fn with_oauth_adapter(mut self, adapter: Arc<dyn OAuthEngineAdapter>) -> Self {
        self.oauth_adapter = Some(adapter);
        self
    }

    pub fn with_registry(mut self, registry: Arc<ConnectorSlotRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    pub fn check_compliance(registry: &ConnectorSlotRegistry) -> Vec<LicenseComplianceViolation> {
        registry.check_license_compliance()
    }

    pub fn enforce_compliance(registry: &ConnectorSlotRegistry) -> Option<EnforcementDecision> {
        let violations = registry.check_license_compliance();
        if violations.is_empty() {
            return None;
        }
        let violation_count = violations.len() as i32;
        let pep_violations: Vec<Violation> = violations
            .iter()
            .map(|v| Violation {
                code: v.violation_code.clone(),
                message: v.message.clone(),
                check_id: "LICENSE-COMPLIANCE".into(),
                severity: ViolationSeverity::Error,
            })
            .collect();
        let compliance_check = CheckResult {
            check_id: "LICENSE-COMPLIANCE".into(),
            check_name: "License Compliance".into(),
            result: CheckOutcome::Fail,
            detail: Some(format!(
                "{violation_count} license compliance violation(s) detected"
            )),
            failure_code: Some("LICENSE_COMPLIANCE_VIOLATION".into()),
        };
        Some(EnforcementDecision {
            request_id: String::new(),
            decision: Decision::Deny,
            timestamp: chrono::Utc::now(),
            enforcement_mode: EnforcementMode::Stateless,
            checks: vec![compliance_check],
            enforced_constraints: None,
            violations: Some(pep_violations),
            audit: Some(AuditRecord {
                processing_time_ms: 0.0,
                pep_version: PEP_VERSION.into(),
                pep_interface_version: Some(PEP_INTERFACE_VERSION.into()),
                credential_jti: None,
                mandate_id: None,
                agent_id: None,
                action_verb: None,
                action_resource: None,
                checks_performed: Some(1),
                checks_passed: Some(0),
                checks_failed: Some(violation_count),
            }),
        })
    }

    pub fn pre_validate_token(credential: &CredentialReference) -> Option<EnforcementDecision> {
        if credential.format == CredentialFormat::Jwt {
            if let Some(ref token) = credential.token {
                let parts: Vec<&str> = token.split('.').collect();
                if parts.len() != 3 {
                    return Some(Self::deny_early(
                        credential.mandate_id.as_deref(),
                        "INVALID_TOKEN_FORMAT",
                        "JWT must have exactly 3 parts (header.payload.signature)",
                    ));
                }

                if let Ok(header_bytes) = base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    parts[0],
                ) {
                    if let Ok(header) =
                        serde_json::from_slice::<serde_json::Value>(&header_bytes)
                    {
                        if let Some(alg) = header.get("alg").and_then(|a| a.as_str()) {
                            if alg != "RS256" && alg != "ES256" {
                                return Some(Self::deny_early(
                                    credential.mandate_id.as_deref(),
                                    "PROHIBITED_ALGORITHM",
                                    &format!(
                                        "Algorithm '{alg}' is prohibited; only RS256 and ES256 are allowed"
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn deny_early(
        mandate_id: Option<&str>,
        code: &str,
        message: &str,
    ) -> EnforcementDecision {
        EnforcementDecision {
            request_id: String::new(),
            decision: Decision::Deny,
            timestamp: chrono::Utc::now(),
            enforcement_mode: EnforcementMode::Stateless,
            checks: vec![],
            enforced_constraints: None,
            violations: Some(vec![Violation {
                code: code.to_string(),
                message: message.to_string(),
                check_id: "PRE-VALIDATE".into(),
                severity: ViolationSeverity::Error,
            }]),
            audit: Some(AuditRecord {
                processing_time_ms: 0.0,
                pep_version: PEP_VERSION.into(),
                pep_interface_version: Some(PEP_INTERFACE_VERSION.into()),
                credential_jti: None,
                mandate_id: mandate_id.map(String::from),
                agent_id: None,
                action_verb: None,
                action_resource: None,
                checks_performed: Some(0),
                checks_passed: Some(0),
                checks_failed: Some(0),
            }),
        }
    }

    pub fn enforce_action(
        &self,
        request: &EnforcementRequest,
        poa: &PoaCredential,
    ) -> EnforcementDecision {
        if let Some(ref registry) = self.registry {
            if let Some(mut deny) = Self::enforce_compliance(registry) {
                deny.request_id = request.request_id.clone();
                deny.enforcement_mode = self.mode.clone();
                return deny;
            }
        }

        if let Some(mut early_deny) = Self::pre_validate_token(&request.credential) {
            early_deny.request_id = request.request_id.clone();
            early_deny.enforcement_mode = self.mode.clone();
            return early_deny;
        }

        if let Some(ref oauth) = self.oauth_adapter {
            if let Some(ref token) = request.credential.token {
                match oauth.validate_token(token) {
                    Err(e) => {
                        let mut deny = Self::deny_early(
                            request.credential.mandate_id.as_deref(),
                            "TOKEN_VALIDATION_FAILED",
                            &format!("OAuth adapter token validation failed: {e}"),
                        );
                        deny.request_id = request.request_id.clone();
                        deny.enforcement_mode = self.mode.clone();
                        return deny;
                    }
                    Ok(validation) if !validation.valid => {
                        let reason = validation.error.unwrap_or_else(|| "Token invalid".into());
                        let mut deny = Self::deny_early(
                            request.credential.mandate_id.as_deref(),
                            "TOKEN_VALIDATION_FAILED",
                            &format!("OAuth token validation rejected: {reason}"),
                        );
                        deny.request_id = request.request_id.clone();
                        deny.enforcement_mode = self.mode.clone();
                        return deny;
                    }
                    Ok(_) => {}
                }
            }
        }

        let start = Instant::now();
        let mut all_checks = Vec::new();
        let mut all_violations = Vec::new();
        let mut all_constraints = Vec::new();
        let fail_fast = self.mode == EnforcementMode::Stateless;

        let chk01 = checks::chk01_credential_integrity(&request.credential, poa);
        collect_result(&chk01, &mut all_violations, "CREDENTIAL_INVALID");
        let has_fatal = chk01.result == CheckOutcome::Fail;
        all_checks.push(chk01);

        if !has_fatal {
            let chk02 = checks::chk02_temporal_status(
                &request.agent, poa, request.context.as_ref(),
            );
            if chk02.result == CheckOutcome::Fail {
                let code = chk02
                    .failure_code
                    .as_deref()
                    .unwrap_or("CREDENTIAL_EXPIRED");
                collect_result(&chk02, &mut all_violations, code);
            }
            all_checks.push(chk02);

            if !fail_fast || all_violations.is_empty() {
                run_simple_check(
                    checks::chk03_governance_profile(&request.action, poa),
                    "PROFILE_CEILING_EXCEEDED",
                    &mut all_checks,
                    &mut all_violations,
                );
            }
            if !fail_fast || all_violations.is_empty() {
                run_simple_check(
                    checks::chk04_phase(&request.action, poa),
                    "PHASE_MISMATCH",
                    &mut all_checks,
                    &mut all_violations,
                );
            }
            if !fail_fast || all_violations.is_empty() {
                run_simple_check(
                    checks::chk05_sector(&request.action, poa),
                    "SECTOR_MISMATCH",
                    &mut all_checks,
                    &mut all_violations,
                );
            }
            if !fail_fast || all_violations.is_empty() {
                run_simple_check(
                    checks::chk06_region(&request.action, poa),
                    "REGION_MISMATCH",
                    &mut all_checks,
                    &mut all_violations,
                );
            }
            if !fail_fast || all_violations.is_empty() {
                run_simple_check(
                    checks::chk07_path(&request.action, poa),
                    "PATH_DENIED",
                    &mut all_checks,
                    &mut all_violations,
                );
            }
            if !fail_fast || all_violations.is_empty() {
                run_simple_check(
                    checks::chk08_verb_permission(&request.action, poa),
                    "VERB_NOT_ALLOWED",
                    &mut all_checks,
                    &mut all_violations,
                );
            }
            if !fail_fast || all_violations.is_empty() {
                let (chk09, c09) = checks::chk09_verb_constraints(&request.action, poa);
                collect_result(&chk09, &mut all_violations, "CONSTRAINT_VIOLATED");
                all_constraints.extend(c09);
                all_checks.push(chk09);
            }
            if !fail_fast || all_violations.is_empty() {
                run_simple_check(
                    checks::chk10_platform_permissions(&request.action, poa),
                    "PLATFORM_PERMISSION_DENIED",
                    &mut all_checks,
                    &mut all_violations,
                );
            }
            if !fail_fast || all_violations.is_empty() {
                run_simple_check(
                    checks::chk11_transaction_type(&request.action, poa),
                    "TRANSACTION_NOT_ALLOWED",
                    &mut all_checks,
                    &mut all_violations,
                );
            }
            if !fail_fast || all_violations.is_empty() {
                run_simple_check(
                    checks::chk12_decision_type(&request.action, poa),
                    "DECISION_NOT_ALLOWED",
                    &mut all_checks,
                    &mut all_violations,
                );
            }
            if !fail_fast || all_violations.is_empty() {
                run_simple_check(
                    checks::chk13_budget(
                        &request.action, poa, request.context.as_ref(),
                    ),
                    "BUDGET_EXCEEDED",
                    &mut all_checks,
                    &mut all_violations,
                );
            }
            if !fail_fast || all_violations.is_empty() {
                run_simple_check(
                    checks::chk14_session_limits(
                        &request.action, poa, request.context.as_ref(),
                    ),
                    "SESSION_LIMIT_EXCEEDED",
                    &mut all_checks,
                    &mut all_violations,
                );
            }
            if !fail_fast || all_violations.is_empty() {
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
            }
            if !fail_fast || all_violations.is_empty() {
                run_simple_check(
                    checks::chk16_delegation_chain(poa),
                    "DELEGATION_DEPTH_EXCEEDED",
                    &mut all_checks,
                    &mut all_violations,
                );
            }
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

fn run_simple_check(
    check: CheckResult,
    code: &str,
    all_checks: &mut Vec<CheckResult>,
    all_violations: &mut Vec<Violation>,
) {
    collect_result(&check, all_violations, code);
    all_checks.push(check);
}

fn collect_result(check: &CheckResult, violations: &mut Vec<Violation>, code: &str) {
    if check.result == CheckOutcome::Fail {
        let effective_code = check
            .failure_code
            .as_deref()
            .unwrap_or(code)
            .to_string();
        violations.push(Violation {
            code: effective_code,
            message: check.detail.clone().unwrap_or_default(),
            check_id: check.check_id.clone(),
            severity: ViolationSeverity::Error,
        });
    }
}
