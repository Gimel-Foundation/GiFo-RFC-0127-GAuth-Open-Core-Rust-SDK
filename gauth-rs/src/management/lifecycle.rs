// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use chrono::Utc;

use crate::crypto;
use crate::error::{GAuthError, Result};
use crate::types::*;
use super::types::*;
use super::validation::validate_mandate_creation;

fn narrow_scope(parent: &Scope, restriction: &serde_json::Value) -> Scope {
    let mut scope = parent.clone();

    if let Some(obj) = restriction.as_object() {
        if let Some(verbs) = obj.get("core_verbs") {
            if let Some(verb_obj) = verbs.as_object() {
                for (verb, child_policy) in verb_obj {
                    if let Some(parent_policy) = scope.core_verbs.get_mut(verb) {
                        if let Some(false) = child_policy.get("allowed").and_then(|v| v.as_bool()) {
                            parent_policy.allowed = false;
                        }
                        if let Some(child_constraints) = child_policy.get("constraints") {
                            narrow_tool_constraints(parent_policy, child_constraints);
                        }
                    }
                }
                let allowed_keys: Vec<String> = verb_obj.keys().cloned().collect();
                let remove_keys: Vec<String> = scope
                    .core_verbs
                    .keys()
                    .filter(|k| !allowed_keys.contains(k))
                    .cloned()
                    .collect();
                for k in remove_keys {
                    if let Some(policy) = scope.core_verbs.get_mut(&k) {
                        policy.allowed = false;
                    }
                }
            }
        }

        if let Some(paths) = obj.get("allowed_paths") {
            if let Some(child_paths) = paths.as_array() {
                let child_strs: Vec<String> = child_paths
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                scope.allowed_paths = Some(match &scope.allowed_paths {
                    Some(parent_paths) => parent_paths
                        .iter()
                        .filter(|p| child_strs.contains(p))
                        .cloned()
                        .collect(),
                    None => child_strs,
                });
            }
        }

        if let Some(regions) = obj.get("allowed_regions") {
            if let Some(child_regions) = regions.as_array() {
                let child_strs: Vec<String> = child_regions
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                scope.allowed_regions = Some(match &scope.allowed_regions {
                    Some(parent_regions) => parent_regions
                        .iter()
                        .filter(|r| child_strs.contains(r))
                        .cloned()
                        .collect(),
                    None => child_strs,
                });
            }
        }

        if let Some(sectors) = obj.get("allowed_sectors") {
            if let Some(child_sectors) = sectors.as_array() {
                let child_strs: Vec<String> = child_sectors
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                scope.allowed_sectors = Some(match &scope.allowed_sectors {
                    Some(parent_sectors) => parent_sectors
                        .iter()
                        .filter(|s| child_strs.contains(s))
                        .cloned()
                        .collect(),
                    None => child_strs,
                });
            }
        }
    }

    scope
}

fn narrow_tool_constraints(policy: &mut ToolPolicy, child: &serde_json::Value) {
    let constraints = policy.constraints.get_or_insert(ToolConstraints {
        path_patterns: None,
        allowed_commands: None,
        denied_commands: None,
        max_delegation_depth: None,
        max_file_size_bytes: None,
    });

    if let Some(child_max_depth) = child.get("max_delegation_depth").and_then(|v| v.as_u64()) {
        constraints.max_delegation_depth = Some(match constraints.max_delegation_depth {
            Some(parent_depth) => parent_depth.min(child_max_depth as u32),
            None => child_max_depth as u32,
        });
    }

    if let Some(child_max_size) = child.get("max_file_size_bytes").and_then(|v| v.as_u64()) {
        constraints.max_file_size_bytes = Some(match constraints.max_file_size_bytes {
            Some(parent_size) => parent_size.min(child_max_size),
            None => child_max_size,
        });
    }

    if let Some(child_cmds) = child.get("allowed_commands").and_then(|v| v.as_array()) {
        let child_strs: Vec<String> = child_cmds
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        constraints.allowed_commands = Some(match &constraints.allowed_commands {
            Some(parent_cmds) => parent_cmds
                .iter()
                .filter(|c| child_strs.contains(c))
                .cloned()
                .collect(),
            None => child_strs,
        });
    }

    if let Some(child_patterns) = child.get("path_patterns").and_then(|v| v.as_array()) {
        let child_strs: Vec<String> = child_patterns
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        constraints.path_patterns = Some(match &constraints.path_patterns {
            Some(parent_patterns) => parent_patterns
                .iter()
                .filter(|p| child_strs.contains(p))
                .cloned()
                .collect(),
            None => child_strs,
        });
    }

    if let Some(child_denied) = child.get("denied_commands").and_then(|v| v.as_array()) {
        let child_strs: Vec<String> = child_denied
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        constraints.denied_commands = Some(match &constraints.denied_commands {
            Some(parent_denied) => parent_denied
                .iter()
                .filter(|c| child_strs.contains(c))
                .cloned()
                .collect(),
            None => child_strs,
        });
    }
}

pub struct MandateManager {
    mandates: std::collections::HashMap<String, Mandate>,
}

impl Default for MandateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MandateManager {
    pub fn new() -> Self {
        Self {
            mandates: std::collections::HashMap::new(),
        }
    }

    pub fn create_mandate(
        &mut self,
        request: MandateCreationRequest,
    ) -> Result<MandateCreationResponse> {
        let validation = validate_mandate_creation(
            &request.parties,
            &request.scope,
            &request.requirements,
        );

        if !validation.accepted {
            return Err(GAuthError::ValidationFailed(format!(
                "Schema: {:?}, Ceiling: {:?}, Consistency: {:?}",
                validation.schema_errors,
                validation.ceiling_violations,
                validation.consistency_errors
            )));
        }

        let mandate_id = format!("mdt_{}", uuid::Uuid::new_v4());
        let now = Utc::now();

        let scope_checksum = crypto::compute_scope_checksum(&request.scope)?;
        let tool_permissions_hash = crypto::compute_permissions_hash(&request.scope.core_verbs)?;
        let platform_permissions_hash = crypto::compute_platform_permissions_hash(
            request
                .scope
                .platform_permissions
                .as_ref()
                .unwrap_or(&PlatformPermissions::default()),
        )?;

        let issued_by = request
            .parties
            .issued_by
            .clone()
            .unwrap_or_else(|| request.parties.issuer.clone());

        let audit_entry = MandateAuditEntry {
            operation: MandateOperation::Create,
            performed_by: issued_by,
            timestamp: now,
            mandate_id: mandate_id.clone(),
            reason: None,
            details: None,
        };

        let mandate = Mandate {
            mandate_id: mandate_id.clone(),
            status: MandateStatus::Draft,
            parties: request.parties,
            scope: request.scope,
            requirements: request.requirements,
            scope_checksum: scope_checksum.clone(),
            tool_permissions_hash: tool_permissions_hash.clone(),
            platform_permissions_hash: platform_permissions_hash.clone(),
            created_at: now,
            activated_at: None,
            expires_at: None,
            revoked_at: None,
            suspended_at: None,
            delegation_chain: None,
            audit_trail: vec![audit_entry.clone()],
        };

        self.mandates.insert(mandate_id.clone(), mandate);

        Ok(MandateCreationResponse {
            mandate_id,
            status: MandateStatus::Draft,
            scope_checksum,
            tool_permissions_hash,
            platform_permissions_hash,
            created_at: now,
            validation,
            audit: audit_entry,
        })
    }

    pub fn activate_mandate(
        &mut self,
        request: MandateActivationRequest,
    ) -> Result<MandateActivationResponse> {
        let mandate = self
            .mandates
            .get_mut(&request.mandate_id)
            .ok_or_else(|| GAuthError::MandateNotFound(request.mandate_id.clone()))?;

        if mandate.status != MandateStatus::Draft {
            return Err(GAuthError::InvalidStateTransition {
                from: mandate.status.to_string(),
                to: "ACTIVE".into(),
            });
        }

        let revalidation = validate_mandate_creation(
            &mandate.parties,
            &mandate.scope,
            &mandate.requirements,
        );

        if !revalidation.accepted {
            return Err(GAuthError::ValidationFailed(
                "Mandate parameters no longer valid at activation time".into(),
            ));
        }

        let now = Utc::now();
        let ttl = mandate.requirements.ttl_seconds.unwrap_or(43200);
        let expires_at = now + chrono::Duration::seconds(ttl);

        mandate.status = MandateStatus::Active;
        mandate.activated_at = Some(now);
        mandate.expires_at = Some(expires_at);

        if let Some(ref mut budget) = mandate.requirements.budget {
            if budget.remaining_cents.is_none() {
                budget.remaining_cents = budget.total_cents;
            }
        }

        let audit_entry = MandateAuditEntry {
            operation: MandateOperation::Activate,
            performed_by: request.activated_by,
            timestamp: now,
            mandate_id: request.mandate_id.clone(),
            reason: None,
            details: None,
        };
        mandate.audit_trail.push(audit_entry.clone());

        Ok(MandateActivationResponse {
            mandate_id: request.mandate_id,
            status: MandateStatus::Active,
            activated_at: now,
            expires_at,
            superseded_mandate_id: None,
            audit: audit_entry,
        })
    }

    pub fn revoke_mandate(
        &mut self,
        request: MandateRevocationRequest,
    ) -> Result<MandateRevocationResponse> {
        let mandate = self
            .mandates
            .get_mut(&request.mandate_id)
            .ok_or_else(|| GAuthError::MandateNotFound(request.mandate_id.clone()))?;

        if mandate.status != MandateStatus::Active && mandate.status != MandateStatus::Suspended {
            return Err(GAuthError::InvalidStateTransition {
                from: mandate.status.to_string(),
                to: "REVOKED".into(),
            });
        }

        let now = Utc::now();
        mandate.status = MandateStatus::Revoked;
        mandate.revoked_at = Some(now);

        let audit_entry = MandateAuditEntry {
            operation: MandateOperation::Revoke,
            performed_by: request.revoked_by.clone(),
            timestamp: now,
            mandate_id: request.mandate_id.clone(),
            reason: request.reason.clone(),
            details: None,
        };
        mandate.audit_trail.push(audit_entry.clone());

        Ok(MandateRevocationResponse {
            mandate_id: request.mandate_id,
            status: MandateStatus::Revoked,
            revoked_at: now,
            revoked_by: request.revoked_by,
            reason: request.reason,
            cascaded_revocations: vec![],
            audit: audit_entry,
        })
    }

    pub fn suspend_mandate(
        &mut self,
        request: MandateSuspensionRequest,
    ) -> Result<()> {
        let mandate = self
            .mandates
            .get_mut(&request.mandate_id)
            .ok_or_else(|| GAuthError::MandateNotFound(request.mandate_id.clone()))?;

        if mandate.status != MandateStatus::Active {
            return Err(GAuthError::InvalidStateTransition {
                from: mandate.status.to_string(),
                to: "SUSPENDED".into(),
            });
        }

        let now = Utc::now();
        mandate.status = MandateStatus::Suspended;
        mandate.suspended_at = Some(now);

        mandate.audit_trail.push(MandateAuditEntry {
            operation: MandateOperation::Suspend,
            performed_by: request.suspended_by,
            timestamp: now,
            mandate_id: request.mandate_id,
            reason: request.reason,
            details: None,
        });

        Ok(())
    }

    pub fn resume_mandate(
        &mut self,
        request: MandateResumptionRequest,
    ) -> Result<()> {
        let mandate = self
            .mandates
            .get_mut(&request.mandate_id)
            .ok_or_else(|| GAuthError::MandateNotFound(request.mandate_id.clone()))?;

        if mandate.status != MandateStatus::Suspended {
            return Err(GAuthError::InvalidStateTransition {
                from: mandate.status.to_string(),
                to: "ACTIVE".into(),
            });
        }

        let now = Utc::now();
        if let Some(expires_at) = mandate.expires_at {
            if now >= expires_at {
                mandate.status = MandateStatus::Expired;
                mandate.audit_trail.push(MandateAuditEntry {
                    operation: MandateOperation::Expire,
                    performed_by: "system".into(),
                    timestamp: now,
                    mandate_id: request.mandate_id,
                    reason: Some("TTL elapsed while suspended".into()),
                    details: None,
                });
                return Err(GAuthError::CredentialExpired);
            }
        }

        mandate.status = MandateStatus::Active;
        mandate.suspended_at = None;

        mandate.audit_trail.push(MandateAuditEntry {
            operation: MandateOperation::Resume,
            performed_by: request.resumed_by,
            timestamp: now,
            mandate_id: request.mandate_id,
            reason: None,
            details: None,
        });

        Ok(())
    }

    pub fn extend_budget(
        &mut self,
        request: BudgetExtensionRequest,
    ) -> Result<()> {
        let mandate = self
            .mandates
            .get_mut(&request.mandate_id)
            .ok_or_else(|| GAuthError::MandateNotFound(request.mandate_id.clone()))?;

        if mandate.status != MandateStatus::Active && mandate.status != MandateStatus::Suspended {
            return Err(GAuthError::InvalidStateTransition {
                from: mandate.status.to_string(),
                to: "budget extension".into(),
            });
        }

        if let Some(ref mut budget) = mandate.requirements.budget {
            budget.total_cents =
                Some(budget.total_cents.unwrap_or(0) + request.additional_cents);
            budget.remaining_cents =
                Some(budget.remaining_cents.unwrap_or(0) + request.additional_cents);
        }

        let now = Utc::now();
        mandate.audit_trail.push(MandateAuditEntry {
            operation: MandateOperation::ExtendBudget,
            performed_by: request.extended_by,
            timestamp: now,
            mandate_id: request.mandate_id,
            reason: None,
            details: Some(serde_json::json!({
                "additional_cents": request.additional_cents
            })),
        });

        Ok(())
    }

    pub fn extend_ttl(
        &mut self,
        request: TtlExtensionRequest,
    ) -> Result<()> {
        let mandate = self
            .mandates
            .get_mut(&request.mandate_id)
            .ok_or_else(|| GAuthError::MandateNotFound(request.mandate_id.clone()))?;

        if mandate.status != MandateStatus::Active && mandate.status != MandateStatus::Suspended {
            return Err(GAuthError::InvalidStateTransition {
                from: mandate.status.to_string(),
                to: "TTL extension".into(),
            });
        }

        if let Some(ref mut ttl) = mandate.requirements.ttl_seconds {
            *ttl += request.additional_seconds;
        }

        if let Some(ref mut expires) = mandate.expires_at {
            *expires += chrono::Duration::seconds(request.additional_seconds);
        }

        let now = Utc::now();
        mandate.audit_trail.push(MandateAuditEntry {
            operation: MandateOperation::ExtendTtl,
            performed_by: request.extended_by,
            timestamp: now,
            mandate_id: request.mandate_id,
            reason: None,
            details: Some(serde_json::json!({
                "additional_seconds": request.additional_seconds
            })),
        });

        Ok(())
    }

    pub fn expire_mandate(&mut self, mandate_id: &str) -> Result<()> {
        let mandate = self
            .mandates
            .get_mut(mandate_id)
            .ok_or_else(|| GAuthError::MandateNotFound(mandate_id.to_string()))?;

        if mandate.status != MandateStatus::Active && mandate.status != MandateStatus::Suspended {
            return Err(GAuthError::InvalidStateTransition {
                from: mandate.status.to_string(),
                to: "EXPIRED".into(),
            });
        }

        let now = Utc::now();
        mandate.status = MandateStatus::Expired;
        mandate.audit_trail.push(MandateAuditEntry {
            operation: MandateOperation::Expire,
            performed_by: "system".into(),
            timestamp: now,
            mandate_id: mandate_id.to_string(),
            reason: Some("TTL expired".into()),
            details: None,
        });

        Ok(())
    }

    pub fn budget_exhaust_mandate(&mut self, mandate_id: &str) -> Result<()> {
        let mandate = self
            .mandates
            .get_mut(mandate_id)
            .ok_or_else(|| GAuthError::MandateNotFound(mandate_id.to_string()))?;

        if mandate.status != MandateStatus::Active {
            return Err(GAuthError::InvalidStateTransition {
                from: mandate.status.to_string(),
                to: "BUDGET_EXCEEDED".into(),
            });
        }

        let now = Utc::now();
        mandate.status = MandateStatus::BudgetExceeded;
        mandate.audit_trail.push(MandateAuditEntry {
            operation: MandateOperation::BudgetExhaust,
            performed_by: "system".into(),
            timestamp: now,
            mandate_id: mandate_id.to_string(),
            reason: Some("Budget exhausted".into()),
            details: None,
        });

        Ok(())
    }

    pub fn supersede_mandate(
        &mut self,
        old_mandate_id: &str,
        superseded_by: &str,
    ) -> Result<()> {
        let mandate = self
            .mandates
            .get_mut(old_mandate_id)
            .ok_or_else(|| GAuthError::MandateNotFound(old_mandate_id.to_string()))?;

        if mandate.status != MandateStatus::Active && mandate.status != MandateStatus::Suspended {
            return Err(GAuthError::InvalidStateTransition {
                from: mandate.status.to_string(),
                to: "SUPERSEDED".into(),
            });
        }

        let now = Utc::now();
        mandate.status = MandateStatus::Superseded;
        mandate.audit_trail.push(MandateAuditEntry {
            operation: MandateOperation::Supersede,
            performed_by: superseded_by.into(),
            timestamp: now,
            mandate_id: old_mandate_id.to_string(),
            reason: Some(format!("Superseded by {superseded_by}")),
            details: None,
        });

        Ok(())
    }

    pub fn check_and_expire_mandates(&mut self) {
        let now = Utc::now();
        let expired_ids: Vec<String> = self
            .mandates
            .iter()
            .filter(|(_, m)| {
                (m.status == MandateStatus::Active || m.status == MandateStatus::Suspended)
                    && m.expires_at.map(|e| now >= e).unwrap_or(false)
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired_ids {
            let _ = self.expire_mandate(&id);
        }
    }

    pub fn get_mandate(&self, mandate_id: &str) -> Option<&Mandate> {
        self.mandates.get(mandate_id)
    }

    pub fn list_mandates(&self) -> Vec<&Mandate> {
        self.mandates.values().collect()
    }

    pub fn delegate_mandate(
        &mut self,
        request: DelegationRequest,
    ) -> Result<String> {
        let parent = self
            .mandates
            .get(&request.parent_mandate_id)
            .ok_or_else(|| GAuthError::MandateNotFound(request.parent_mandate_id.clone()))?;

        if parent.status != MandateStatus::Active {
            return Err(GAuthError::InvalidStateTransition {
                from: parent.status.to_string(),
                to: "DELEGATE".into(),
            });
        }

        if !parent.scope.governance_profile.allows_delegation() {
            return Err(GAuthError::DelegationScopeExceeded(
                "Governance profile does not allow delegation".into(),
            ));
        }

        let current_depth = parent.delegation_chain.as_ref().map(|c| c.len()).unwrap_or(0) as u32;
        let max_depth = parent.scope.governance_profile.max_delegation_depth();
        if current_depth >= max_depth {
            return Err(GAuthError::DelegationDepthExceeded {
                max: max_depth,
                actual: current_depth + 1,
            });
        }

        let child_id = format!("mdt_{}", uuid::Uuid::new_v4());
        let now = Utc::now();

        let mut child_chain = parent.delegation_chain.clone().unwrap_or_default();
        child_chain.push(crate::types::DelegationLink {
            delegator: parent.parties.subject.clone(),
            delegate: request.delegate_agent_id.clone(),
            scope_restriction: request.scope_restriction.clone(),
            delegated_at: Some(now),
            max_depth_remaining: Some(max_depth - current_depth - 1),
        });

        let narrowed_scope = narrow_scope(&parent.scope, &request.scope_restriction);

        let requires_approval = parent.requirements.approval_mode >= ApprovalMode::Supervised
            || parent.scope.governance_profile.approval_required_for_delegation();

        let initial_status = if requires_approval {
            MandateStatus::PendingApproval
        } else {
            MandateStatus::Draft
        };

        let audit_entry = MandateAuditEntry {
            operation: MandateOperation::Delegate,
            performed_by: request.delegated_by,
            timestamp: now,
            mandate_id: child_id.clone(),
            reason: Some(format!("Delegated from {}", request.parent_mandate_id)),
            details: Some(request.scope_restriction),
        };

        let child = Mandate {
            mandate_id: child_id.clone(),
            status: initial_status,
            parties: Parties {
                issuer: parent.parties.issuer.clone(),
                subject: request.delegate_agent_id,
                customer_id: parent.parties.customer_id.clone(),
                project_id: parent.parties.project_id.clone(),
                issued_by: Some(parent.parties.subject.clone()),
                approval_chain: parent.parties.approval_chain.clone(),
            },
            scope: narrowed_scope,
            requirements: parent.requirements.clone(),
            scope_checksum: String::new(),
            tool_permissions_hash: String::new(),
            platform_permissions_hash: String::new(),
            created_at: now,
            activated_at: None,
            expires_at: parent.expires_at,
            revoked_at: None,
            suspended_at: None,
            delegation_chain: Some(child_chain),
            audit_trail: vec![audit_entry],
        };

        let checksum = crypto::compute_scope_checksum(&child.scope)?;
        let tool_hash = crypto::compute_permissions_hash(&child.scope.core_verbs)?;
        let plat_hash = crypto::compute_platform_permissions_hash(
            child.scope.platform_permissions.as_ref().unwrap_or(&PlatformPermissions::default()),
        )?;

        let mut child = child;
        child.scope_checksum = checksum;
        child.tool_permissions_hash = tool_hash;
        child.platform_permissions_hash = plat_hash;

        self.mandates.insert(child_id.clone(), child);
        Ok(child_id)
    }

    pub fn approve_delegation(
        &mut self,
        request: DelegationApprovalRequest,
    ) -> Result<DelegationApprovalResponse> {
        let mandate = self
            .mandates
            .get_mut(&request.mandate_id)
            .ok_or_else(|| GAuthError::MandateNotFound(request.mandate_id.clone()))?;

        if mandate.status != MandateStatus::PendingApproval {
            return Err(GAuthError::InvalidStateTransition {
                from: mandate.status.to_string(),
                to: "DRAFT (from PENDING_APPROVAL)".into(),
            });
        }

        if let Some(ref chain) = mandate.parties.approval_chain {
            if !chain.contains(&request.approved_by) {
                return Err(GAuthError::ValidationFailed(format!(
                    "Approver '{}' is not in the approval chain",
                    request.approved_by
                )));
            }
        }

        let now = Utc::now();
        mandate.status = MandateStatus::Draft;

        let audit_entry = MandateAuditEntry {
            operation: MandateOperation::ApproveDelegation,
            performed_by: request.approved_by.clone(),
            timestamp: now,
            mandate_id: request.mandate_id.clone(),
            reason: Some("Delegation approved".into()),
            details: None,
        };
        mandate.audit_trail.push(audit_entry.clone());

        Ok(DelegationApprovalResponse {
            mandate_id: request.mandate_id,
            status: MandateStatus::Draft,
            approved_by: request.approved_by,
            approved_at: now,
            audit: audit_entry,
        })
    }

    pub fn generate_poa_map(&self, mandate_id: &str) -> Result<PoaMapSummary> {
        let mandate = self
            .mandates
            .get(mandate_id)
            .ok_or_else(|| GAuthError::MandateNotFound(mandate_id.to_string()))?;

        let profile = &mandate.scope.governance_profile;

        let allowed_verbs: Vec<String> = mandate
            .scope
            .core_verbs
            .iter()
            .filter(|(_, p)| p.allowed)
            .map(|(k, _)| k.clone())
            .collect();

        let denied_verbs: Vec<String> = mandate
            .scope
            .core_verbs
            .iter()
            .filter(|(_, p)| !p.allowed)
            .map(|(k, _)| k.clone())
            .collect();

        let (budget_total, budget_remaining) = mandate
            .requirements
            .budget
            .as_ref()
            .map(|b| (b.total_cents, b.remaining_cents))
            .unwrap_or((None, None));

        Ok(PoaMapSummary {
            mandate_id: mandate.mandate_id.clone(),
            status: mandate.status.to_string(),
            governance_profile: format!("{profile:?}"),
            phase: format!("{:?}", mandate.scope.phase),
            allowed_verbs,
            denied_verbs,
            allowed_paths: mandate.scope.allowed_paths.clone().unwrap_or_default(),
            denied_paths: mandate.scope.denied_paths.clone().unwrap_or_default(),
            allowed_sectors: mandate.scope.allowed_sectors.clone().unwrap_or_default(),
            allowed_regions: mandate.scope.allowed_regions.clone().unwrap_or_default(),
            budget_total_cents: budget_total,
            budget_remaining_cents: budget_remaining,
            approval_mode: format!("{:?}", mandate.requirements.approval_mode),
            delegation_allowed: profile.allows_delegation(),
            max_delegation_depth: profile.max_delegation_depth(),
            delegation_chain_length: mandate
                .delegation_chain
                .as_ref()
                .map(|c| c.len())
                .unwrap_or(0),
            platform_permissions_summary: serde_json::to_value(
                &mandate.scope.platform_permissions,
            )
            .unwrap_or(serde_json::Value::Null),
            created_at: mandate.created_at,
            activated_at: mandate.activated_at,
            expires_at: mandate.expires_at,
        })
    }

    pub fn to_poa_credential(&self, mandate_id: &str) -> Result<PoaCredential> {
        let mandate = self
            .mandates
            .get(mandate_id)
            .ok_or_else(|| GAuthError::MandateNotFound(mandate_id.to_string()))?;

        if mandate.status != MandateStatus::Active {
            return Err(GAuthError::InvalidStateTransition {
                from: mandate.status.to_string(),
                to: "PoA credential extraction requires ACTIVE status".into(),
            });
        }

        if let Some(expires_at) = mandate.expires_at {
            if Utc::now() >= expires_at {
                return Err(GAuthError::CredentialExpired);
            }
        }

        Ok(PoaCredential {
            schema_version: Some("0116.2.2".into()),
            parties: mandate.parties.clone(),
            delegation_chain: mandate.delegation_chain.clone(),
            scope: mandate.scope.clone(),
            requirements: mandate.requirements.clone(),
        })
    }
}
