use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::adapters::ConnectorSlot;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseType {
    #[serde(rename = "mpl_2_0")]
    Mpl2_0,
    #[serde(rename = "gimel_tos")]
    GimelTos,
}

impl Default for LicenseType {
    fn default() -> Self {
        LicenseType::Mpl2_0
    }
}

impl std::fmt::Display for LicenseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseType::Mpl2_0 => write!(f, "mpl_2_0"),
            LicenseType::GimelTos => write!(f, "gimel_tos"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceTosStatus {
    NotRequired,
    Pending,
    Accepted,
    Rejected,
}

impl Default for ServiceTosStatus {
    fn default() -> Self {
        ServiceTosStatus::NotRequired
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceTosState {
    pub status: ServiceTosStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<String>,
}

impl Default for ServiceTosState {
    fn default() -> Self {
        Self {
            status: ServiceTosStatus::NotRequired,
            version: None,
            accepted_at: None,
        }
    }
}

impl ServiceTosState {
    pub fn pending() -> Self {
        Self {
            status: ServiceTosStatus::Pending,
            version: None,
            accepted_at: None,
        }
    }
}

fn parse_semver(v: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let major = parts[0].parse().ok()?;
    let minor = parts[1].parse().ok()?;
    let patch = parts[2].parse().ok()?;
    Some((major, minor, patch))
}

fn semver_less_than(current: &str, required: &str) -> bool {
    match (parse_semver(current), parse_semver(required)) {
        (Some(c), Some(r)) => c < r,
        _ => current < required,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseState {
    pub license_type: LicenseType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_accepted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_version: Option<String>,
    pub service_tos: HashMap<String, ServiceTosState>,
}

impl Default for LicenseState {
    fn default() -> Self {
        Self::new()
    }
}

impl LicenseState {
    pub fn new() -> Self {
        Self {
            license_type: LicenseType::Mpl2_0,
            license_accepted_at: None,
            license_version: None,
            service_tos: HashMap::new(),
        }
    }

    pub fn accept_platform_tos(&mut self, version: &str, timestamp: &str) {
        self.license_type = LicenseType::GimelTos;
        self.license_accepted_at = Some(timestamp.to_string());
        self.license_version = Some(version.to_string());
    }

    pub fn platform_tos_accepted(&self) -> bool {
        self.license_type == LicenseType::GimelTos && self.license_accepted_at.is_some()
    }

    pub fn init_service_tos(&mut self, slot: ConnectorSlot) {
        if !slot.requires_attestation() {
            return;
        }
        let key = slot.to_string();
        if !self.service_tos.contains_key(&key) {
            self.service_tos.insert(key, ServiceTosState::pending());
        }
    }

    pub fn accept_service_tos(
        &mut self,
        slot: ConnectorSlot,
        version: &str,
        timestamp: &str,
    ) -> Result<(), String> {
        if !slot.requires_attestation() {
            return Err(format!(
                "Slot {} does not require service ToS (not Type C)",
                slot
            ));
        }
        let key = slot.to_string();
        self.service_tos.insert(
            key,
            ServiceTosState {
                status: ServiceTosStatus::Accepted,
                version: Some(version.to_string()),
                accepted_at: Some(timestamp.to_string()),
            },
        );
        Ok(())
    }

    pub fn reject_service_tos(&mut self, slot: ConnectorSlot) -> Result<(), String> {
        if !slot.requires_attestation() {
            return Err(format!(
                "Slot {} does not require service ToS (not Type C)",
                slot
            ));
        }
        let key = slot.to_string();
        self.service_tos.insert(
            key,
            ServiceTosState {
                status: ServiceTosStatus::Rejected,
                version: None,
                accepted_at: None,
            },
        );
        Ok(())
    }

    pub fn service_tos_status(&self, slot: ConnectorSlot) -> ServiceTosStatus {
        if !slot.requires_attestation() {
            return ServiceTosStatus::NotRequired;
        }
        self.service_tos
            .get(&slot.to_string())
            .map(|s| s.status.clone())
            .unwrap_or(ServiceTosStatus::Pending)
    }

    pub fn service_tos_accepted(&self, slot: ConnectorSlot) -> bool {
        self.service_tos_status(slot) == ServiceTosStatus::Accepted
    }

    pub fn requires_platform_tos_reacceptance(&self, current_version: &str) -> bool {
        match &self.license_version {
            Some(v) => semver_less_than(v, current_version),
            None => self.license_type == LicenseType::GimelTos,
        }
    }

    pub fn requires_service_tos_reacceptance(
        &self,
        slot: ConnectorSlot,
        current_version: &str,
    ) -> bool {
        match self.service_tos.get(&slot.to_string()) {
            Some(state) if state.status == ServiceTosStatus::Accepted => {
                match &state.version {
                    Some(v) => semver_less_than(v, current_version),
                    None => true,
                }
            }
            _ => false,
        }
    }

    pub fn can_activate_gimel_hosted(&self) -> bool {
        self.platform_tos_accepted()
    }

    pub fn can_activate_type_c(&self, slot: ConnectorSlot) -> bool {
        if !slot.requires_attestation() {
            return false;
        }
        self.platform_tos_accepted() && self.service_tos_accepted(slot)
    }
}
