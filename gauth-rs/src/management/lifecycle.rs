// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use chrono::Utc;

use crate::crypto;
use crate::error::{GAuthError, Result};
use crate::types::*;
use super::types::*;
use super::validation::validate_mandate_creation;

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
