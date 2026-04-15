// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use crate::error::Result;
use crate::management::types::{Mandate, MandateAuditEntry};

pub trait MandateRepository: Send + Sync {
    fn save(&mut self, mandate: &Mandate) -> Result<()>;
    fn find_by_id(&self, mandate_id: &str) -> Result<Option<Mandate>>;
    fn find_by_subject(&self, subject: &str) -> Result<Vec<Mandate>>;
    fn find_by_customer(&self, customer_id: &str) -> Result<Vec<Mandate>>;
    fn find_active_by_subject(&self, subject: &str) -> Result<Vec<Mandate>>;
    fn delete(&mut self, mandate_id: &str) -> Result<bool>;
    fn list_all(&self) -> Result<Vec<Mandate>>;
    fn append_audit(&mut self, mandate_id: &str, entry: &MandateAuditEntry) -> Result<()>;
    fn count(&self) -> usize;
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryMandateRepository {
    mandates: std::collections::HashMap<String, Mandate>,
}

impl InMemoryMandateRepository {
    pub fn new() -> Self {
        Self::default()
    }
}

impl MandateRepository for InMemoryMandateRepository {
    fn save(&mut self, mandate: &Mandate) -> Result<()> {
        self.mandates
            .insert(mandate.mandate_id.clone(), mandate.clone());
        Ok(())
    }

    fn find_by_id(&self, mandate_id: &str) -> Result<Option<Mandate>> {
        Ok(self.mandates.get(mandate_id).cloned())
    }

    fn find_by_subject(&self, subject: &str) -> Result<Vec<Mandate>> {
        Ok(self
            .mandates
            .values()
            .filter(|m| m.parties.subject == subject)
            .cloned()
            .collect())
    }

    fn find_by_customer(&self, customer_id: &str) -> Result<Vec<Mandate>> {
        Ok(self
            .mandates
            .values()
            .filter(|m| m.parties.customer_id == customer_id)
            .cloned()
            .collect())
    }

    fn find_active_by_subject(&self, subject: &str) -> Result<Vec<Mandate>> {
        use crate::management::types::MandateStatus;
        Ok(self
            .mandates
            .values()
            .filter(|m| {
                m.parties.subject == subject && m.status == MandateStatus::Active
            })
            .cloned()
            .collect())
    }

    fn delete(&mut self, mandate_id: &str) -> Result<bool> {
        Ok(self.mandates.remove(mandate_id).is_some())
    }

    fn list_all(&self) -> Result<Vec<Mandate>> {
        Ok(self.mandates.values().cloned().collect())
    }

    fn append_audit(&mut self, mandate_id: &str, entry: &MandateAuditEntry) -> Result<()> {
        if let Some(mandate) = self.mandates.get_mut(mandate_id) {
            mandate.audit_trail.push(entry.clone());
        }
        Ok(())
    }

    fn count(&self) -> usize {
        self.mandates.len()
    }
}
