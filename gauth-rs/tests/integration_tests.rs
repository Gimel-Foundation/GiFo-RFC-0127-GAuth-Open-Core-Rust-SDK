use std::collections::HashMap;
use std::sync::Arc;

use gauth_rs::adapters::*;
use gauth_rs::crypto;
use gauth_rs::error::GAuthError;
use gauth_rs::management::*;
use gauth_rs::pep::*;
use gauth_rs::types::*;

fn make_standard_scope() -> Scope {
    let mut core_verbs = HashMap::new();
    core_verbs.insert(
        "file.read".to_string(),
        ToolPolicy {
            allowed: true,
            cost_cents_base: None,
            constraints: None,
        },
    );
    core_verbs.insert(
        "file.create".to_string(),
        ToolPolicy {
            allowed: true,
            cost_cents_base: Some(1.0),
            constraints: Some(ToolConstraints {
                path_patterns: Some(vec!["src/**".to_string()]),
                allowed_commands: None,
                denied_commands: None,
                max_delegation_depth: None,
                max_file_size_bytes: Some(1_000_000),
            }),
        },
    );
    core_verbs.insert(
        "command.run".to_string(),
        ToolPolicy {
            allowed: true,
            cost_cents_base: None,
            constraints: Some(ToolConstraints {
                path_patterns: None,
                allowed_commands: Some(vec!["cargo".to_string(), "npm".to_string()]),
                denied_commands: Some(vec!["rm".to_string()]),
                max_delegation_depth: None,
                max_file_size_bytes: None,
            }),
        },
    );
    core_verbs.insert(
        "deploy".to_string(),
        ToolPolicy {
            allowed: false,
            cost_cents_base: None,
            constraints: None,
        },
    );

    Scope {
        governance_profile: GovernanceProfile::Standard,
        phase: Phase::Build,
        core_verbs,
        active_modules: None,
        allowed_paths: Some(vec!["src/**".to_string(), "tests/**".to_string()]),
        denied_paths: Some(vec!["src/secrets/**".to_string()]),
        allowed_sectors: Some(vec!["Information and Communication".to_string()]),
        allowed_regions: Some(vec!["EU".to_string()]),
        allowed_transactions: None,
        transaction_matrix: None,
        allowed_decisions: None,
        platform_permissions: Some(PlatformPermissions {
            deployment: Some(DeploymentPermissions {
                targets: Some(vec!["dev".to_string(), "staging".to_string()]),
                auto_deploy: Some(true),
            }),
            database: Some(DatabasePermissions {
                read: Some(true),
                write: Some(true),
                migrate: Some(false),
                production_access: Some(false),
            }),
            shell: None,
            packages: None,
            external_apis: None,
            secrets: Some(SecretPermissions {
                read: Some(true),
                create: Some(false),
            }),
        }),
    }
}

fn make_standard_poa() -> PoaCredential {
    PoaCredential {
        schema_version: Some("0116.2.2".to_string()),
        parties: Parties {
            issuer: "platform:test".to_string(),
            subject: "agent:test-agent-001".to_string(),
            customer_id: "cust_test".to_string(),
            project_id: "proj_test".to_string(),
            issued_by: None,
            approval_chain: None,
        },
        delegation_chain: None,
        scope: make_standard_scope(),
        requirements: Requirements {
            approval_mode: ApprovalMode::Autonomous,
            budget: Some(Budget {
                total_cents: Some(5000),
                remaining_cents: Some(5000),
            }),
            session_limits: Some(SessionLimits {
                max_tool_calls: Some(100),
                remaining_tool_calls: Some(100),
                max_lines_per_commit: Some(500),
                session_id: None,
                started_at: None,
            }),
            ttl_seconds: Some(3600),
        },
    }
}

fn make_enforcement_request(
    verb: &str,
    resource: &str,
    agent_id: &str,
) -> EnforcementRequest {
    EnforcementRequest {
        request_id: format!("req_{}", uuid::Uuid::new_v4()),
        timestamp: chrono::Utc::now(),
        action: ActionDescriptor {
            verb: verb.to_string(),
            resource: resource.to_string(),
            resource_type: None,
            parameters: None,
            sector: Some("Information and Communication".to_string()),
            region: Some("DE".to_string()),
            transaction_type: None,
            decision_type: None,
        },
        agent: AgentIdentity {
            agent_id: agent_id.to_string(),
            service: None,
            session_id: None,
            did: None,
        },
        credential: CredentialReference {
            format: CredentialFormat::Jwt,
            token: None,
            mandate_id: None,
            poa_snapshot: None,
        },
        context: None,
    }
}

#[test]
fn test_pep_permit_basic_read() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let request = make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Permit);
    assert!(decision.violations.is_none() || decision.violations.as_ref().unwrap().is_empty());
}

#[test]
fn test_pep_deny_wrong_agent() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let request = make_enforcement_request("file.read", "src/main.rs", "agent:wrong-agent");
    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "AGENT_MISMATCH"));
}

#[test]
fn test_pep_deny_disallowed_verb() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let request = make_enforcement_request("deploy", "staging", "agent:test-agent-001");
    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "VERB_NOT_ALLOWED"));
}

#[test]
fn test_pep_deny_unknown_verb() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let request =
        make_enforcement_request("file.delete", "src/main.rs", "agent:test-agent-001");
    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "VERB_NOT_ALLOWED"));
}

#[test]
fn test_pep_deny_denied_path() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let request = make_enforcement_request(
        "file.read",
        "src/secrets/api_key.txt",
        "agent:test-agent-001",
    );
    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "PATH_DENIED"));
}

#[test]
fn test_pep_deny_path_not_in_allowed() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let request = make_enforcement_request(
        "file.read",
        "config/database.yml",
        "agent:test-agent-001",
    );
    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "PATH_DENIED"));
}

#[test]
fn test_pep_deny_wrong_region() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let mut request =
        make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    request.action.region = Some("US".to_string());

    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "REGION_MISMATCH"));
}

#[test]
fn test_pep_permit_eu_member_region() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    for country in &["DE", "FR", "IT", "ES", "NL", "SE", "AT"] {
        let mut request =
            make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
        request.action.region = Some(country.to_string());

        let decision = engine.enforce_action(&request, &poa);
        assert_eq!(
            decision.decision,
            Decision::Permit,
            "Expected PERMIT for EU member {}",
            country
        );
    }
}

#[test]
fn test_pep_deny_wrong_sector() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let mut request =
        make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    request.action.sector = Some("Agriculture".to_string());

    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "SECTOR_MISMATCH"));
}

#[test]
fn test_pep_deny_budget_exhausted() {
    let mut poa = make_standard_poa();
    poa.requirements.budget = Some(Budget {
        total_cents: Some(100),
        remaining_cents: Some(0),
    });

    let engine = PepEngine::default();
    let request =
        make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "BUDGET_EXCEEDED"));
}

#[test]
fn test_pep_deny_session_limits_exceeded() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let mut request =
        make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    request.context = Some(EnforcementContext {
        session_state: Some(SessionState {
            tool_calls_used: Some(100),
            lines_committed: None,
            session_started_at: None,
            session_cost_cents: None,
        }),
        live_mandate_state: None,
    });

    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "SESSION_LIMIT_EXCEEDED"));
}

#[test]
fn test_pep_deny_revoked_mandate() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let mut request =
        make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    request.context = Some(EnforcementContext {
        session_state: None,
        live_mandate_state: Some(LiveMandateState {
            status: Some("revoked".to_string()),
            budget_remaining_cents: None,
            tool_permissions: None,
            platform_permissions: None,
        }),
    });

    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
}

#[test]
fn test_pep_deny_schema_version_mismatch() {
    let mut poa = make_standard_poa();
    poa.schema_version = Some("0.0.1".to_string());

    let engine = PepEngine::default();
    let request =
        make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "CREDENTIAL_INVALID"));
}

#[test]
fn test_pep_verb_constraint_file_size_exceeded() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let mut request = make_enforcement_request(
        "file.create",
        "src/big_file.rs",
        "agent:test-agent-001",
    );
    let mut params = HashMap::new();
    params.insert(
        "file_size_bytes".to_string(),
        serde_json::Value::Number(2_000_000u64.into()),
    );
    request.action.parameters = Some(params);

    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "CONSTRAINT_VIOLATED"));
}

#[test]
fn test_pep_verb_constraint_denied_command() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let mut request = make_enforcement_request(
        "command.run",
        "shell",
        "agent:test-agent-001",
    );
    request.action.resource_type = Some("shell".to_string());
    let mut params = HashMap::new();
    params.insert(
        "command".to_string(),
        serde_json::Value::String("rm".to_string()),
    );
    request.action.parameters = Some(params);

    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
}

#[test]
fn test_pep_platform_permission_db_prod_denied() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let mut request = make_enforcement_request(
        "file.read",
        "prod-db",
        "agent:test-agent-001",
    );
    request.action.verb = "db.read".to_string();
    request.action.resource_type = Some("database".to_string());
    request.action.resource = "prod-database".to_string();

    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
}

#[test]
fn test_pep_batch_enforce_all_or_nothing() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let req1 = make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    let req2 = make_enforcement_request("deploy", "staging", "agent:test-agent-001");

    let batch = engine.batch_enforce(&[req1, req2], &[poa.clone(), poa], BatchMode::AllOrNothing);

    assert_eq!(batch.overall_decision, Decision::Deny);
    assert_eq!(batch.decisions.len(), 2);
}

#[test]
fn test_pep_get_enforcement_policy() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();
    let policy = engine.get_enforcement_policy(&poa);

    assert_eq!(policy.governance_profile, "standard");
    assert_eq!(policy.phase, "build");
    assert!(policy.allowed_verbs.contains(&"file.read".to_string()));
    assert!(policy.allowed_verbs.contains(&"file.create".to_string()));
    assert!(!policy.allowed_verbs.contains(&"deploy".to_string()));
    assert!(policy.delegation.allowed);
    assert_eq!(policy.delegation.max_depth, 1);
}

#[test]
fn test_pep_delegation_chain_depth() {
    let mut poa = make_standard_poa();
    poa.delegation_chain = Some(vec![
        DelegationLink {
            delegator: "agent:a".into(),
            delegate: "agent:b".into(),
            scope_restriction: serde_json::json!({}),
            delegated_at: None,
            max_depth_remaining: Some(1),
        },
        DelegationLink {
            delegator: "agent:b".into(),
            delegate: "agent:c".into(),
            scope_restriction: serde_json::json!({}),
            delegated_at: None,
            max_depth_remaining: Some(0),
        },
    ]);

    let engine = PepEngine::default();
    let request =
        make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
}

#[test]
fn test_pep_four_eyes_approval() {
    let mut poa = make_standard_poa();
    poa.requirements.approval_mode = ApprovalMode::FourEyes;
    poa.parties.approval_chain = Some(vec!["approver1".into(), "approver2".into()]);

    let engine = PepEngine::default();
    let request =
        make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Constrain);
}

#[test]
fn test_pep_four_eyes_insufficient_approvers() {
    let mut poa = make_standard_poa();
    poa.requirements.approval_mode = ApprovalMode::FourEyes;
    poa.parties.approval_chain = Some(vec!["approver1".into()]);

    let engine = PepEngine::default();
    let request =
        make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
}

#[test]
fn test_pep_transaction_matrix_enforcement() {
    let mut poa = make_standard_poa();
    poa.scope.allowed_transactions = Some(vec!["purchase".to_string(), "sale".to_string()]);
    poa.scope.transaction_matrix = Some(serde_json::json!({
        "purchase": {
            "allowed": true,
            "max_amount_cents": 5000
        },
        "sale": {
            "allowed": false
        }
    }));

    let engine = PepEngine::default();

    let mut req = make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    req.action.transaction_type = Some("purchase".to_string());
    let mut params = HashMap::new();
    params.insert(
        "amount_cents".to_string(),
        serde_json::Value::Number(3000.into()),
    );
    req.action.parameters = Some(params);

    let decision = engine.enforce_action(&req, &poa);
    assert_eq!(decision.decision, Decision::Permit);

    let mut req2 = make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    req2.action.transaction_type = Some("sale".to_string());
    let decision2 = engine.enforce_action(&req2, &poa);
    assert_eq!(decision2.decision, Decision::Deny);

    let mut req3 = make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    req3.action.transaction_type = Some("purchase".to_string());
    let mut params3 = HashMap::new();
    params3.insert(
        "amount_cents".to_string(),
        serde_json::Value::Number(10000.into()),
    );
    req3.action.parameters = Some(params3);
    let decision3 = engine.enforce_action(&req3, &poa);
    assert_eq!(decision3.decision, Decision::Deny);
}

#[test]
fn test_mandate_lifecycle_create_activate_revoke() {
    let mut manager = MandateManager::new();

    let scope = make_standard_scope();

    let create_resp = manager
        .create_mandate(MandateCreationRequest {
            parties: Parties {
                issuer: "platform:test".into(),
                subject: "agent:test-001".into(),
                customer_id: "cust_1".into(),
                project_id: "proj_1".into(),
                issued_by: None,
                approval_chain: None,
            },
            scope,
            requirements: Requirements {
                approval_mode: ApprovalMode::Autonomous,
                budget: Some(Budget {
                    total_cents: Some(5000),
                    remaining_cents: Some(5000),
                }),
                session_limits: None,
                ttl_seconds: Some(3600),
            },
        })
        .unwrap();

    assert_eq!(create_resp.status, MandateStatus::Draft);
    assert!(create_resp.scope_checksum.starts_with("sha256:"));

    let mandate = manager.get_mandate(&create_resp.mandate_id).unwrap();
    assert_eq!(mandate.status, MandateStatus::Draft);

    let activate_resp = manager
        .activate_mandate(MandateActivationRequest {
            mandate_id: create_resp.mandate_id.clone(),
            activated_by: "admin".into(),
        })
        .unwrap();

    assert_eq!(activate_resp.status, MandateStatus::Active);
    assert!(activate_resp.activated_at < activate_resp.expires_at);

    let poa = manager.to_poa_credential(&create_resp.mandate_id).unwrap();
    assert_eq!(poa.schema_version, Some("0116.2.2".to_string()));

    let revoke_resp = manager
        .revoke_mandate(MandateRevocationRequest {
            mandate_id: create_resp.mandate_id.clone(),
            revoked_by: "admin".into(),
            reason: Some("Test revocation".into()),
        })
        .unwrap();

    assert_eq!(revoke_resp.status, MandateStatus::Revoked);

    let poa_result = manager.to_poa_credential(&create_resp.mandate_id);
    assert!(poa_result.is_err());
}

#[test]
fn test_mandate_lifecycle_suspend_resume() {
    let mut manager = MandateManager::new();
    let scope = make_standard_scope();

    let create_resp = manager
        .create_mandate(MandateCreationRequest {
            parties: Parties {
                issuer: "platform:test".into(),
                subject: "agent:test-001".into(),
                customer_id: "cust_1".into(),
                project_id: "proj_1".into(),
                issued_by: None,
                approval_chain: None,
            },
            scope,
            requirements: Requirements {
                approval_mode: ApprovalMode::Autonomous,
                budget: Some(Budget {
                    total_cents: Some(1000),
                    remaining_cents: Some(1000),
                }),
                session_limits: None,
                ttl_seconds: Some(3600),
            },
        })
        .unwrap();

    manager
        .activate_mandate(MandateActivationRequest {
            mandate_id: create_resp.mandate_id.clone(),
            activated_by: "admin".into(),
        })
        .unwrap();

    manager
        .suspend_mandate(MandateSuspensionRequest {
            mandate_id: create_resp.mandate_id.clone(),
            suspended_by: "admin".into(),
            reason: Some("Under review".into()),
        })
        .unwrap();

    let mandate = manager.get_mandate(&create_resp.mandate_id).unwrap();
    assert_eq!(mandate.status, MandateStatus::Suspended);

    let poa_result = manager.to_poa_credential(&create_resp.mandate_id);
    assert!(poa_result.is_err());

    manager
        .resume_mandate(MandateResumptionRequest {
            mandate_id: create_resp.mandate_id.clone(),
            resumed_by: "admin".into(),
        })
        .unwrap();

    let mandate = manager.get_mandate(&create_resp.mandate_id).unwrap();
    assert_eq!(mandate.status, MandateStatus::Active);

    let poa = manager.to_poa_credential(&create_resp.mandate_id).unwrap();
    assert!(poa.scope.governance_profile == GovernanceProfile::Standard);
}

#[test]
fn test_mandate_budget_extension() {
    let mut manager = MandateManager::new();
    let scope = make_standard_scope();

    let create_resp = manager
        .create_mandate(MandateCreationRequest {
            parties: Parties {
                issuer: "platform:test".into(),
                subject: "agent:test-001".into(),
                customer_id: "cust_1".into(),
                project_id: "proj_1".into(),
                issued_by: None,
                approval_chain: None,
            },
            scope,
            requirements: Requirements {
                approval_mode: ApprovalMode::Autonomous,
                budget: Some(Budget {
                    total_cents: Some(1000),
                    remaining_cents: Some(1000),
                }),
                session_limits: None,
                ttl_seconds: Some(3600),
            },
        })
        .unwrap();

    manager
        .activate_mandate(MandateActivationRequest {
            mandate_id: create_resp.mandate_id.clone(),
            activated_by: "admin".into(),
        })
        .unwrap();

    manager
        .extend_budget(BudgetExtensionRequest {
            mandate_id: create_resp.mandate_id.clone(),
            additional_cents: 500,
            extended_by: "admin".into(),
        })
        .unwrap();

    let mandate = manager.get_mandate(&create_resp.mandate_id).unwrap();
    assert_eq!(
        mandate.requirements.budget.as_ref().unwrap().total_cents,
        Some(1500)
    );
    assert_eq!(
        mandate
            .requirements
            .budget
            .as_ref()
            .unwrap()
            .remaining_cents,
        Some(1500)
    );
}

#[test]
fn test_mandate_invalid_transition() {
    let mut manager = MandateManager::new();
    let scope = make_standard_scope();

    let create_resp = manager
        .create_mandate(MandateCreationRequest {
            parties: Parties {
                issuer: "platform:test".into(),
                subject: "agent:test-001".into(),
                customer_id: "cust_1".into(),
                project_id: "proj_1".into(),
                issued_by: None,
                approval_chain: None,
            },
            scope,
            requirements: Requirements {
                approval_mode: ApprovalMode::Autonomous,
                budget: Some(Budget {
                    total_cents: Some(1000),
                    remaining_cents: Some(1000),
                }),
                session_limits: None,
                ttl_seconds: Some(3600),
            },
        })
        .unwrap();

    let result = manager.suspend_mandate(MandateSuspensionRequest {
        mandate_id: create_resp.mandate_id.clone(),
        suspended_by: "admin".into(),
        reason: None,
    });
    assert!(result.is_err());

    let result = manager.resume_mandate(MandateResumptionRequest {
        mandate_id: create_resp.mandate_id.clone(),
        resumed_by: "admin".into(),
    });
    assert!(result.is_err());
}

#[test]
fn test_mandate_validation_ceiling_violation() {
    let mut manager = MandateManager::new();
    let mut scope = make_standard_scope();
    scope.governance_profile = GovernanceProfile::Minimal;

    let result = manager.create_mandate(MandateCreationRequest {
        parties: Parties {
            issuer: "platform:test".into(),
            subject: "agent:test-001".into(),
            customer_id: "cust_1".into(),
            project_id: "proj_1".into(),
            issued_by: None,
            approval_chain: None,
        },
        scope,
        requirements: Requirements {
            approval_mode: ApprovalMode::Autonomous,
            budget: Some(Budget {
                total_cents: Some(50000),
                remaining_cents: Some(50000),
            }),
            session_limits: None,
            ttl_seconds: Some(3600),
        },
    });

    assert!(result.is_err());
    if let Err(GAuthError::ValidationFailed(msg)) = result {
        assert!(msg.contains("ceiling") || msg.contains("Ceiling"));
    }
}

#[test]
fn test_mandate_expire_and_supersede() {
    let mut manager = MandateManager::new();
    let scope = make_standard_scope();

    let create_resp = manager
        .create_mandate(MandateCreationRequest {
            parties: Parties {
                issuer: "platform:test".into(),
                subject: "agent:test-001".into(),
                customer_id: "cust_1".into(),
                project_id: "proj_1".into(),
                issued_by: None,
                approval_chain: None,
            },
            scope: scope.clone(),
            requirements: Requirements {
                approval_mode: ApprovalMode::Autonomous,
                budget: Some(Budget {
                    total_cents: Some(1000),
                    remaining_cents: Some(1000),
                }),
                session_limits: None,
                ttl_seconds: Some(3600),
            },
        })
        .unwrap();

    manager
        .activate_mandate(MandateActivationRequest {
            mandate_id: create_resp.mandate_id.clone(),
            activated_by: "admin".into(),
        })
        .unwrap();

    manager
        .supersede_mandate(&create_resp.mandate_id, "new_mandate_id")
        .unwrap();

    let mandate = manager.get_mandate(&create_resp.mandate_id).unwrap();
    assert_eq!(mandate.status, MandateStatus::Superseded);

    let create_resp2 = manager
        .create_mandate(MandateCreationRequest {
            parties: Parties {
                issuer: "platform:test".into(),
                subject: "agent:test-001".into(),
                customer_id: "cust_1".into(),
                project_id: "proj_1".into(),
                issued_by: None,
                approval_chain: None,
            },
            scope,
            requirements: Requirements {
                approval_mode: ApprovalMode::Autonomous,
                budget: Some(Budget {
                    total_cents: Some(1000),
                    remaining_cents: Some(1000),
                }),
                session_limits: None,
                ttl_seconds: Some(3600),
            },
        })
        .unwrap();

    manager
        .activate_mandate(MandateActivationRequest {
            mandate_id: create_resp2.mandate_id.clone(),
            activated_by: "admin".into(),
        })
        .unwrap();

    manager
        .budget_exhaust_mandate(&create_resp2.mandate_id)
        .unwrap();

    let mandate2 = manager.get_mandate(&create_resp2.mandate_id).unwrap();
    assert_eq!(mandate2.status, MandateStatus::BudgetExceeded);
}

#[test]
fn test_adapter_registry_rejects_untrusted() {
    let mut registry = AdapterRegistry::new();

    let manifest = LegacyAdapterManifest {
        name: "test-adapter".into(),
        version: "1.0.0".into(),
        namespace: "gimel".into(),
        description: "Test adapter".into(),
        adapter_type: AdapterType::OAuthEngine,
    };

    let fake_signature = vec![0u8; 64];
    let adapter = Arc::new(NoOpOAuthEngine);

    let result = registry.register_oauth_engine(&manifest, &fake_signature, adapter);

    assert!(result.is_err());
    match result {
        Err(GAuthError::AdapterSignatureInvalid(_)) => {}
        other => panic!("Expected AdapterSignatureInvalid, got {:?}", other),
    }
}

#[test]
fn test_adapter_registry_rejects_wrong_namespace() {
    let mut registry = AdapterRegistry::new();

    let manifest = LegacyAdapterManifest {
        name: "evil-adapter".into(),
        version: "1.0.0".into(),
        namespace: "evil-corp".into(),
        description: "Evil adapter".into(),
        adapter_type: AdapterType::OAuthEngine,
    };

    let fake_signature = vec![0u8; 64];
    let adapter = Arc::new(NoOpOAuthEngine);

    let result = registry.register_oauth_engine(&manifest, &fake_signature, adapter);

    assert!(result.is_err());
    match result {
        Err(GAuthError::AdapterRegistrationFailed(msg)) => {
            assert!(msg.contains("namespace"));
        }
        other => panic!("Expected AdapterRegistrationFailed, got {:?}", other),
    }
}

#[test]
fn test_adapter_registry_signed_registration() {
    use ed25519_dalek::SigningKey;

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let mut registry = AdapterRegistry::new();
    registry.add_trusted_key(verifying_key);

    let manifest = LegacyAdapterManifest {
        name: "official-oauth".into(),
        version: "1.0.0".into(),
        namespace: "gimel".into(),
        description: "Official OAuth engine".into(),
        adapter_type: AdapterType::OAuthEngine,
    };

    let manifest_json = serde_json::to_vec(&manifest).unwrap();
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(&manifest_json);

    let adapter = Arc::new(NoOpOAuthEngine);
    let result =
        registry.register_oauth_engine(&manifest, &signature.to_bytes(), adapter);

    assert!(result.is_ok());
    assert!(registry.get_oauth_engine("official-oauth").is_some());
}

#[test]
fn test_adapter_registry_list_registered() {
    let registry = AdapterRegistry::new();
    let registered = registry.list_registered();

    assert_eq!(registered.len(), 2);
    for (_, names) in &registered {
        assert!(names.is_empty());
    }
}

#[test]
fn test_adapter_noop_implementations() {
    let oauth = NoOpOAuthEngine;
    assert!(oauth.issue_token(&serde_json::json!({}), &serde_json::json!({})).is_err());
    assert!(oauth.validate_token("token").is_err());
    assert!(oauth.introspect("token").is_err());
    assert!(oauth.revoke_token("token", "test").is_err());
    assert!(oauth.get_jwks().is_err());
    assert!(oauth.before_token_issuance(&serde_json::json!({})).is_ok());
    assert!(oauth.after_token_issuance(
        &SignedJwt { token: "t".into(), expires_at: "e".into() },
        &serde_json::json!({}),
    ).is_ok());
    let health = oauth.health_check().unwrap();
    assert!(!health.healthy);

    let foundry = NoOpFoundry;
    assert!(foundry.execute_action(&serde_json::json!({}), &serde_json::json!({})).is_err());
    let catalog = foundry.get_agent_catalog().unwrap();
    assert!(catalog.is_empty());
    let sandbox = foundry.validate_sandbox("agent_1", &serde_json::json!({})).unwrap();
    assert!(sandbox.valid);

    let wallet = NoOpWallet;
    assert!(wallet.store_credential(&serde_json::json!({})).is_err());
    assert!(wallet.present_credential(&serde_json::json!({})).is_err());
    let creds = wallet.list_credentials(None).unwrap();
    assert!(creds.is_empty());
    assert!(wallet.delete_credential("c1").is_err());
    assert!(wallet.generate_selective_disclosure(&serde_json::json!({}), &serde_json::json!({})).is_err());

    let governance = RuleBasedGovernance;
    let check = governance.check_access(&serde_json::json!({})).unwrap();
    assert!(check.allowed);
    let recs = governance.get_recommendations(&serde_json::json!({})).unwrap();
    assert!(recs.is_empty());

    let web3 = NullWeb3Identity;
    let resolved = web3.resolve_identity("did:example:123").unwrap();
    assert!(resolved.is_none());
    assert!(web3.verify_credential(&serde_json::json!({})).is_err());

    let dna = NullDnaIdentity;
    let resolved = dna.resolve_identity("dna:sample:456").unwrap();
    assert!(resolved.is_none());
    assert!(dna.verify_biometric(&serde_json::json!({})).is_err());
}

#[test]
fn test_crypto_scope_checksum_consistency() {
    let scope = make_standard_scope();
    let c1 = crypto::compute_scope_checksum(&scope).unwrap();
    let c2 = crypto::compute_scope_checksum(&scope).unwrap();
    assert_eq!(c1, c2);
    assert!(c1.starts_with("sha256:"));
    assert!(c1.len() > 10);
}

#[test]
fn test_crypto_permissions_hash() {
    let scope = make_standard_scope();
    let h1 = crypto::compute_permissions_hash(&scope.core_verbs).unwrap();
    let h2 = crypto::compute_permissions_hash(&scope.core_verbs).unwrap();
    assert_eq!(h1, h2);
    assert!(h1.starts_with("sha256:"));
}

#[test]
fn test_governance_profiles() {
    assert_eq!(GovernanceProfile::Minimal.max_budget_cents(), Some(1_000));
    assert_eq!(GovernanceProfile::Standard.max_budget_cents(), Some(10_000));
    assert_eq!(GovernanceProfile::Strict.max_budget_cents(), Some(100_000));
    assert_eq!(
        GovernanceProfile::Enterprise.max_budget_cents(),
        Some(1_000_000)
    );
    assert_eq!(GovernanceProfile::Behoerde.max_budget_cents(), None);

    assert!(GovernanceProfile::Minimal.allows_auto_deploy());
    assert!(GovernanceProfile::Standard.allows_auto_deploy());
    assert!(!GovernanceProfile::Strict.allows_auto_deploy());
    assert!(!GovernanceProfile::Enterprise.allows_auto_deploy());
    assert!(!GovernanceProfile::Behoerde.allows_auto_deploy());

    assert_eq!(GovernanceProfile::Minimal.max_delegation_depth(), 0);
    assert_eq!(GovernanceProfile::Standard.max_delegation_depth(), 1);
    assert_eq!(GovernanceProfile::Strict.max_delegation_depth(), 2);
    assert_eq!(GovernanceProfile::Enterprise.max_delegation_depth(), 3);
    assert_eq!(GovernanceProfile::Behoerde.max_delegation_depth(), 2);

    assert!(!GovernanceProfile::Minimal.allows_delegation());
    assert!(GovernanceProfile::Standard.allows_delegation());
    assert!(GovernanceProfile::Enterprise.allows_delegation());
}

#[test]
fn test_pep_audit_record_present() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();
    let request =
        make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    let decision = engine.enforce_action(&request, &poa);

    let audit = decision.audit.unwrap();
    assert_eq!(audit.pep_version, "0.1.0");
    assert_eq!(audit.pep_interface_version, Some("1.2".to_string()));
    assert!(audit.processing_time_ms >= 0.0);
    assert_eq!(audit.agent_id, Some("agent:test-agent-001".to_string()));
    assert_eq!(audit.action_verb, Some("file.read".to_string()));
    assert!(audit.checks_performed.unwrap() >= 16);
}

#[test]
fn test_mandate_audit_trail() {
    let mut manager = MandateManager::new();
    let scope = make_standard_scope();

    let create_resp = manager
        .create_mandate(MandateCreationRequest {
            parties: Parties {
                issuer: "platform:test".into(),
                subject: "agent:test-001".into(),
                customer_id: "cust_1".into(),
                project_id: "proj_1".into(),
                issued_by: None,
                approval_chain: None,
            },
            scope,
            requirements: Requirements {
                approval_mode: ApprovalMode::Autonomous,
                budget: Some(Budget {
                    total_cents: Some(1000),
                    remaining_cents: Some(1000),
                }),
                session_limits: None,
                ttl_seconds: Some(3600),
            },
        })
        .unwrap();

    manager
        .activate_mandate(MandateActivationRequest {
            mandate_id: create_resp.mandate_id.clone(),
            activated_by: "admin".into(),
        })
        .unwrap();

    manager
        .suspend_mandate(MandateSuspensionRequest {
            mandate_id: create_resp.mandate_id.clone(),
            suspended_by: "admin".into(),
            reason: Some("review".into()),
        })
        .unwrap();

    manager
        .resume_mandate(MandateResumptionRequest {
            mandate_id: create_resp.mandate_id.clone(),
            resumed_by: "admin".into(),
        })
        .unwrap();

    let mandate = manager.get_mandate(&create_resp.mandate_id).unwrap();
    assert_eq!(mandate.audit_trail.len(), 4);
    assert_eq!(mandate.audit_trail[0].operation, MandateOperation::Create);
    assert_eq!(mandate.audit_trail[1].operation, MandateOperation::Activate);
    assert_eq!(mandate.audit_trail[2].operation, MandateOperation::Suspend);
    assert_eq!(mandate.audit_trail[3].operation, MandateOperation::Resume);
}

#[test]
fn test_adapter_registry_rejects_collision() {
    use ed25519_dalek::SigningKey;

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let mut registry = AdapterRegistry::new();
    registry.add_trusted_key(verifying_key);

    let manifest = LegacyAdapterManifest {
        name: "collision-test".into(),
        version: "1.0.0".into(),
        namespace: "gimel".into(),
        description: "First adapter".into(),
        adapter_type: AdapterType::OAuthEngine,
    };

    let manifest_json = serde_json::to_vec(&manifest).unwrap();
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(&manifest_json);

    let adapter1 = Arc::new(NoOpOAuthEngine);
    registry
        .register_oauth_engine(&manifest, &signature.to_bytes(), adapter1)
        .unwrap();

    let adapter2 = Arc::new(NoOpOAuthEngine);
    let result = registry.register_oauth_engine(&manifest, &signature.to_bytes(), adapter2);
    assert!(result.is_err());
    match result {
        Err(GAuthError::AdapterRegistrationFailed(msg)) => {
            assert!(msg.contains("already registered"));
        }
        other => panic!("Expected AdapterRegistrationFailed collision, got {:?}", other),
    }
}

#[test]
fn test_pep_budget_uses_verb_cost_base() {
    let mut poa = make_standard_poa();
    poa.requirements.budget = Some(Budget {
        total_cents: Some(100),
        remaining_cents: Some(100),
    });

    poa.scope.core_verbs.insert(
        "expensive.op".to_string(),
        ToolPolicy {
            allowed: true,
            cost_cents_base: Some(200.0),
            constraints: None,
        },
    );

    let engine = PepEngine::default();
    let request = make_enforcement_request("expensive.op", "src/main.rs", "agent:test-agent-001");
    let decision = engine.enforce_action(&request, &poa);

    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "BUDGET_EXCEEDED"));
}

#[test]
fn test_pep_scope_checksum_mismatch_in_credential() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let mut tampered_poa = make_standard_poa();
    tampered_poa.scope.core_verbs.insert(
        "evil.verb".to_string(),
        ToolPolicy {
            allowed: true,
            cost_cents_base: None,
            constraints: None,
        },
    );

    let mut request = make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    request.credential.poa_snapshot = Some(tampered_poa);

    let decision = engine.enforce_action(&request, &poa);
    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "CREDENTIAL_INVALID"));
}

#[test]
fn test_pep_mandate_revoked_uses_correct_code() {
    let poa = make_standard_poa();
    let engine = PepEngine::default();

    let mut request = make_enforcement_request("file.read", "src/main.rs", "agent:test-agent-001");
    request.context = Some(EnforcementContext {
        session_state: None,
        live_mandate_state: Some(LiveMandateState {
            status: Some("revoked".to_string()),
            budget_remaining_cents: None,
            tool_permissions: None,
            platform_permissions: None,
        }),
    });

    let decision = engine.enforce_action(&request, &poa);
    assert_eq!(decision.decision, Decision::Deny);
    let violations = decision.violations.unwrap();
    assert!(violations.iter().any(|v| v.code == "MANDATE_REVOKED"));
}

#[test]
fn test_connector_slot_model_7_slots() {
    let all = ConnectorSlot::all();
    assert_eq!(all.len(), 7);

    assert_eq!(ConnectorSlot::Pdp.slot_number(), 1);
    assert_eq!(ConnectorSlot::OauthEngine.slot_number(), 2);
    assert_eq!(ConnectorSlot::Foundry.slot_number(), 3);
    assert_eq!(ConnectorSlot::Wallet.slot_number(), 4);
    assert_eq!(ConnectorSlot::AiGovernance.slot_number(), 5);
    assert_eq!(ConnectorSlot::Web3Identity.slot_number(), 6);
    assert_eq!(ConnectorSlot::DnaIdentity.slot_number(), 7);

    assert!(ConnectorSlot::Pdp.is_mandatory());
    assert!(ConnectorSlot::OauthEngine.is_mandatory());
    assert!(!ConnectorSlot::Foundry.is_mandatory());
    assert!(!ConnectorSlot::AiGovernance.is_mandatory());
}

#[test]
fn test_connector_slot_type_classification() {
    assert_eq!(
        ConnectorSlot::Pdp.adapter_type_class(),
        AdapterTypeClass::Internal
    );
    assert_eq!(
        ConnectorSlot::OauthEngine.adapter_type_class(),
        AdapterTypeClass::A
    );
    assert_eq!(
        ConnectorSlot::Foundry.adapter_type_class(),
        AdapterTypeClass::B
    );
    assert_eq!(
        ConnectorSlot::Wallet.adapter_type_class(),
        AdapterTypeClass::B
    );
    assert_eq!(
        ConnectorSlot::AiGovernance.adapter_type_class(),
        AdapterTypeClass::C
    );
    assert_eq!(
        ConnectorSlot::Web3Identity.adapter_type_class(),
        AdapterTypeClass::C
    );
    assert_eq!(
        ConnectorSlot::DnaIdentity.adapter_type_class(),
        AdapterTypeClass::C
    );
}

#[test]
fn test_connector_slot_attestation_required() {
    assert!(!ConnectorSlot::Pdp.requires_attestation());
    assert!(!ConnectorSlot::OauthEngine.requires_attestation());
    assert!(!ConnectorSlot::Foundry.requires_attestation());
    assert!(!ConnectorSlot::Wallet.requires_attestation());
    assert!(ConnectorSlot::AiGovernance.requires_attestation());
    assert!(ConnectorSlot::Web3Identity.requires_attestation());
    assert!(ConnectorSlot::DnaIdentity.requires_attestation());
}

#[test]
fn test_connector_slot_namespace() {
    assert_eq!(ConnectorSlot::Pdp.canonical_namespace(), "@gimel/pdp");
    assert_eq!(
        ConnectorSlot::OauthEngine.canonical_namespace(),
        "@gimel/oauth-engine"
    );
    assert_eq!(
        ConnectorSlot::DnaIdentity.canonical_namespace(),
        "@gimel/dna-identity"
    );
}

#[test]
fn test_tariff_gating_open_core() {
    let gate = check_tariff_gate(ConnectorSlot::OauthEngine, TariffCode::O);
    assert!(gate.allowed);

    let gate = check_tariff_gate(ConnectorSlot::Foundry, TariffCode::O);
    assert!(gate.allowed);

    let gate = check_tariff_gate(ConnectorSlot::AiGovernance, TariffCode::O);
    assert!(!gate.allowed);

    let gate = check_tariff_gate(ConnectorSlot::Web3Identity, TariffCode::O);
    assert!(!gate.allowed);

    let gate = check_tariff_gate(ConnectorSlot::DnaIdentity, TariffCode::O);
    assert!(!gate.allowed);
}

#[test]
fn test_tariff_gating_small_tier() {
    let gate = check_tariff_gate(ConnectorSlot::AiGovernance, TariffCode::S);
    assert!(!gate.allowed);

    let gate = check_tariff_gate(ConnectorSlot::DnaIdentity, TariffCode::S);
    assert!(!gate.allowed);
}

#[test]
fn test_tariff_gating_medium_tier() {
    let gate = check_tariff_gate(ConnectorSlot::AiGovernance, TariffCode::M);
    assert!(gate.allowed);

    let gate = check_tariff_gate(ConnectorSlot::Web3Identity, TariffCode::M);
    assert!(gate.allowed);

    let gate = check_tariff_gate(ConnectorSlot::DnaIdentity, TariffCode::M);
    assert!(!gate.allowed);
}

#[test]
fn test_tariff_gating_large_tier() {
    let gate = check_tariff_gate(ConnectorSlot::AiGovernance, TariffCode::L);
    assert!(gate.allowed);

    let gate = check_tariff_gate(ConnectorSlot::Web3Identity, TariffCode::L);
    assert!(gate.allowed);

    let gate = check_tariff_gate(ConnectorSlot::DnaIdentity, TariffCode::L);
    assert!(gate.allowed);
}

#[test]
fn test_tariff_gating_pdp_always_available() {
    for tariff in &[TariffCode::O, TariffCode::S, TariffCode::M, TariffCode::L] {
        let gate = check_tariff_gate(ConnectorSlot::Pdp, *tariff);
        assert!(gate.allowed);
    }
}

#[test]
fn test_slot_availability_matrix() {
    assert_eq!(
        slot_availability(ConnectorSlot::Pdp, TariffCode::O),
        SlotAvailability::ActiveAlways
    );
    assert_eq!(
        slot_availability(ConnectorSlot::OauthEngine, TariffCode::O),
        SlotAvailability::UserProvidedRequired
    );
    assert_eq!(
        slot_availability(ConnectorSlot::OauthEngine, TariffCode::S),
        SlotAvailability::GimelOrUser
    );
    assert_eq!(
        slot_availability(ConnectorSlot::Foundry, TariffCode::O),
        SlotAvailability::NullOrUser
    );
    assert_eq!(
        slot_availability(ConnectorSlot::AiGovernance, TariffCode::M),
        SlotAvailability::AttestedGimel
    );
    assert_eq!(
        slot_availability(ConnectorSlot::DnaIdentity, TariffCode::L),
        SlotAvailability::AttestedGimel
    );
    assert_eq!(
        slot_availability(ConnectorSlot::DnaIdentity, TariffCode::M),
        SlotAvailability::Null
    );
}

#[test]
fn test_license_state_machine_default() {
    let state = LicenseState::new();
    assert_eq!(state.license_type, LicenseType::Mpl2_0);
    assert!(!state.platform_tos_accepted());
    assert!(!state.can_activate_gimel_hosted());
}

#[test]
fn test_license_state_machine_accept_platform_tos() {
    let mut state = LicenseState::new();
    state.accept_platform_tos("1.0.0", "2025-01-01T00:00:00Z");

    assert_eq!(state.license_type, LicenseType::GimelTos);
    assert!(state.platform_tos_accepted());
    assert!(state.can_activate_gimel_hosted());
    assert_eq!(state.license_version, Some("1.0.0".to_string()));
}

#[test]
fn test_license_state_machine_service_tos() {
    let mut state = LicenseState::new();
    state.accept_platform_tos("1.0.0", "2025-01-01T00:00:00Z");

    assert!(!state.service_tos_accepted(ConnectorSlot::AiGovernance));
    assert!(!state.can_activate_type_c(ConnectorSlot::AiGovernance));

    assert_eq!(
        state.service_tos_status(ConnectorSlot::AiGovernance),
        ServiceTosStatus::Pending
    );

    state
        .accept_service_tos(ConnectorSlot::AiGovernance, "1.0.0", "2025-01-01T00:00:00Z")
        .unwrap();

    assert!(state.service_tos_accepted(ConnectorSlot::AiGovernance));
    assert!(state.can_activate_type_c(ConnectorSlot::AiGovernance));
    assert_eq!(
        state.service_tos_status(ConnectorSlot::AiGovernance),
        ServiceTosStatus::Accepted
    );

    assert!(!state.service_tos_accepted(ConnectorSlot::Web3Identity));
    assert!(!state.can_activate_type_c(ConnectorSlot::Web3Identity));
}

#[test]
fn test_license_state_machine_type_c_requires_platform_tos() {
    let mut state = LicenseState::new();

    state
        .accept_service_tos(ConnectorSlot::AiGovernance, "1.0.0", "2025-01-01T00:00:00Z")
        .unwrap();

    assert!(state.service_tos_accepted(ConnectorSlot::AiGovernance));
    assert!(!state.can_activate_type_c(ConnectorSlot::AiGovernance));
}

#[test]
fn test_license_state_service_tos_rejects_non_type_c() {
    let mut state = LicenseState::new();

    let result = state.accept_service_tos(
        ConnectorSlot::Foundry,
        "1.0.0",
        "2025-01-01T00:00:00Z",
    );
    assert!(result.is_err());

    assert_eq!(
        state.service_tos_status(ConnectorSlot::Foundry),
        ServiceTosStatus::NotRequired
    );

    assert!(!state.can_activate_type_c(ConnectorSlot::Foundry));
}

#[test]
fn test_license_state_service_tos_rejection() {
    let mut state = LicenseState::new();
    state.accept_platform_tos("1.0.0", "2025-01-01T00:00:00Z");

    state.reject_service_tos(ConnectorSlot::DnaIdentity).unwrap();
    assert_eq!(
        state.service_tos_status(ConnectorSlot::DnaIdentity),
        ServiceTosStatus::Rejected
    );
    assert!(!state.can_activate_type_c(ConnectorSlot::DnaIdentity));
}

#[test]
fn test_license_state_tos_reacceptance() {
    let mut state = LicenseState::new();
    state.accept_platform_tos("1.0.0", "2025-01-01T00:00:00Z");

    assert!(!state.requires_platform_tos_reacceptance("1.0.0"));
    assert!(state.requires_platform_tos_reacceptance("2.0.0"));

    assert!(!state.requires_platform_tos_reacceptance("0.9.0"));

    state
        .accept_service_tos(ConnectorSlot::Web3Identity, "1.0.0", "2025-01-01T00:00:00Z")
        .unwrap();
    assert!(!state.requires_service_tos_reacceptance(ConnectorSlot::Web3Identity, "1.0.0"));
    assert!(state.requires_service_tos_reacceptance(ConnectorSlot::Web3Identity, "2.0.0"));
    assert!(!state.requires_service_tos_reacceptance(ConnectorSlot::Web3Identity, "0.5.0"));
}

#[test]
fn test_license_state_semver_comparison() {
    let mut state = LicenseState::new();
    state.accept_platform_tos("2.0.0", "2025-01-01T00:00:00Z");

    assert!(!state.requires_platform_tos_reacceptance("2.0.0"));
    assert!(state.requires_platform_tos_reacceptance("10.0.0"));
    assert!(!state.requires_platform_tos_reacceptance("1.9.9"));
}

#[test]
fn test_license_type_serialization() {
    let mpl = LicenseType::Mpl2_0;
    let json = serde_json::to_string(&mpl).unwrap();
    assert_eq!(json, "\"mpl_2_0\"");

    let gimel = LicenseType::GimelTos;
    let json = serde_json::to_string(&gimel).unwrap();
    assert_eq!(json, "\"gimel_tos\"");

    let parsed: LicenseType = serde_json::from_str("\"mpl_2_0\"").unwrap();
    assert_eq!(parsed, LicenseType::Mpl2_0);

    let parsed: LicenseType = serde_json::from_str("\"gimel_tos\"").unwrap();
    assert_eq!(parsed, LicenseType::GimelTos);
}

#[test]
fn test_connector_slot_registry_init() {
    let registry = ConnectorSlotRegistry::new(TariffCode::O);
    let state = registry.slot_status(ConnectorSlot::Pdp);
    assert_eq!(state.status, SlotStatus::Active);

    let state = registry.slot_status(ConnectorSlot::OauthEngine);
    assert_eq!(state.status, SlotStatus::Null);

    let state = registry.slot_status(ConnectorSlot::AiGovernance);
    assert_eq!(state.status, SlotStatus::Null);

    assert!(registry.check_mandatory_slots().is_err());
    assert!(!registry.is_operational());
}

#[test]
fn test_connector_slot_registry_mandatory_enforcement() {
    let mut registry = ConnectorSlotRegistry::new(TariffCode::O);

    assert!(!registry.is_operational());

    registry.register(ConnectorSlot::OauthEngine, "user-oauth").unwrap();

    assert!(registry.is_operational());
    assert!(registry.check_mandatory_slots().is_ok());
}

#[test]
fn test_connector_slot_registry_tariff_enforcement() {
    let registry = ConnectorSlotRegistry::new(TariffCode::M);

    let state = registry.slot_status(ConnectorSlot::AiGovernance);
    assert_eq!(state.status, SlotStatus::Null);

    let gate = check_tariff_gate(ConnectorSlot::AiGovernance, TariffCode::M);
    assert!(gate.allowed);

    let gate = check_tariff_gate(ConnectorSlot::DnaIdentity, TariffCode::M);
    assert!(!gate.allowed);
}

#[test]
fn test_billing_adapter_noop() {
    let billing = NoOpBilling;
    assert!(billing.check_credits("tenant_1", "op").is_err());
    assert!(billing
        .record_usage("tenant_1", "op", None)
        .is_err());
    assert!(billing
        .get_balance("tenant_1")
        .is_err());
    let health = billing.health_check().unwrap();
    assert!(!health.healthy);
}

#[test]
fn test_pdp_adapter_rule_based() {
    let pdp = RuleBasedPolicyDecision;
    let result = pdp
        .evaluate_mandate(&serde_json::json!({}), &serde_json::json!({}))
        .unwrap();
    assert!(result.allowed);
    let action = pdp
        .evaluate_action(&serde_json::json!({}), &serde_json::json!({}))
        .unwrap();
    assert!(action.allowed);
    let ceilings = pdp
        .validate_ceilings(&serde_json::json!({}), &serde_json::json!({}))
        .unwrap();
    assert!(ceilings.valid);
    let health = pdp.health_check().unwrap();
    assert!(health.healthy);
}
