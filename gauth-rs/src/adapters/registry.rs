// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{GAuthError, Result};
use super::traits::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorSlot {
    Pdp,
    OauthEngine,
    Foundry,
    Wallet,
    AiGovernance,
    Web3Identity,
    DnaIdentity,
}

impl ConnectorSlot {
    pub fn slot_number(&self) -> u8 {
        match self {
            ConnectorSlot::Pdp => 1,
            ConnectorSlot::OauthEngine => 2,
            ConnectorSlot::Foundry => 3,
            ConnectorSlot::Wallet => 4,
            ConnectorSlot::AiGovernance => 5,
            ConnectorSlot::Web3Identity => 6,
            ConnectorSlot::DnaIdentity => 7,
        }
    }

    pub fn is_mandatory(&self) -> bool {
        matches!(self, ConnectorSlot::Pdp | ConnectorSlot::OauthEngine)
    }

    pub fn adapter_type_class(&self) -> AdapterTypeClass {
        match self {
            ConnectorSlot::Pdp => AdapterTypeClass::Internal,
            ConnectorSlot::OauthEngine => AdapterTypeClass::A,
            ConnectorSlot::Foundry | ConnectorSlot::Wallet => AdapterTypeClass::B,
            ConnectorSlot::AiGovernance
            | ConnectorSlot::Web3Identity
            | ConnectorSlot::DnaIdentity => AdapterTypeClass::C,
        }
    }

    pub fn requires_attestation(&self) -> bool {
        self.adapter_type_class() == AdapterTypeClass::C
    }

    pub fn canonical_namespace(&self) -> &'static str {
        match self {
            ConnectorSlot::Pdp => "@gimel/pdp",
            ConnectorSlot::OauthEngine => "@gimel/oauth-engine",
            ConnectorSlot::Foundry => "@gimel/foundry",
            ConnectorSlot::Wallet => "@gimel/wallet",
            ConnectorSlot::AiGovernance => "@gimel/ai-governance",
            ConnectorSlot::Web3Identity => "@gimel/web3-identity",
            ConnectorSlot::DnaIdentity => "@gimel/dna-identity",
        }
    }

    pub fn all() -> &'static [ConnectorSlot] {
        &[
            ConnectorSlot::Pdp,
            ConnectorSlot::OauthEngine,
            ConnectorSlot::Foundry,
            ConnectorSlot::Wallet,
            ConnectorSlot::AiGovernance,
            ConnectorSlot::Web3Identity,
            ConnectorSlot::DnaIdentity,
        ]
    }
}

impl std::fmt::Display for ConnectorSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectorSlot::Pdp => write!(f, "pdp"),
            ConnectorSlot::OauthEngine => write!(f, "oauth_engine"),
            ConnectorSlot::Foundry => write!(f, "foundry"),
            ConnectorSlot::Wallet => write!(f, "wallet"),
            ConnectorSlot::AiGovernance => write!(f, "ai_governance"),
            ConnectorSlot::Web3Identity => write!(f, "web3_identity"),
            ConnectorSlot::DnaIdentity => write!(f, "dna_identity"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdapterTypeClass {
    Internal,
    A,
    B,
    C,
    D,
}

impl std::fmt::Display for AdapterTypeClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterTypeClass::Internal => write!(f, "Internal"),
            AdapterTypeClass::A => write!(f, "A"),
            AdapterTypeClass::B => write!(f, "B"),
            AdapterTypeClass::C => write!(f, "C"),
            AdapterTypeClass::D => write!(f, "D"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TariffCode {
    O,
    S,
    M,
    L,
}

impl std::fmt::Display for TariffCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TariffCode::O => write!(f, "O"),
            TariffCode::S => write!(f, "S"),
            TariffCode::M => write!(f, "M"),
            TariffCode::L => write!(f, "L"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotAvailability {
    ActiveAlways,
    GimelOrUser,
    UserProvidedRequired,
    NullOrUser,
    AttestedGimel,
    NullOrAttestedGimel,
    Null,
}

pub fn slot_availability(slot: ConnectorSlot, tariff: TariffCode) -> SlotAvailability {
    match (slot, tariff) {
        (ConnectorSlot::Pdp, _) => SlotAvailability::ActiveAlways,

        (ConnectorSlot::OauthEngine, TariffCode::O) => SlotAvailability::UserProvidedRequired,
        (ConnectorSlot::OauthEngine, _) => SlotAvailability::GimelOrUser,

        (ConnectorSlot::Foundry, TariffCode::O) => SlotAvailability::NullOrUser,
        (ConnectorSlot::Foundry, _) => SlotAvailability::GimelOrUser,

        (ConnectorSlot::Wallet, TariffCode::O) => SlotAvailability::NullOrUser,
        (ConnectorSlot::Wallet, _) => SlotAvailability::GimelOrUser,

        (ConnectorSlot::AiGovernance, TariffCode::O | TariffCode::S) => SlotAvailability::Null,
        (ConnectorSlot::AiGovernance, TariffCode::M | TariffCode::L) => {
            SlotAvailability::AttestedGimel
        }

        (ConnectorSlot::Web3Identity, TariffCode::O | TariffCode::S) => SlotAvailability::Null,
        (ConnectorSlot::Web3Identity, TariffCode::M) => SlotAvailability::NullOrAttestedGimel,
        (ConnectorSlot::Web3Identity, TariffCode::L) => SlotAvailability::AttestedGimel,

        (ConnectorSlot::DnaIdentity, TariffCode::O | TariffCode::S | TariffCode::M) => {
            SlotAvailability::Null
        }
        (ConnectorSlot::DnaIdentity, TariffCode::L) => SlotAvailability::AttestedGimel,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TariffGateResult {
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub availability: SlotAvailability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
}

pub fn check_tariff_gate(slot: ConnectorSlot, tariff: TariffCode) -> TariffGateResult {
    let availability = slot_availability(slot, tariff);

    if availability == SlotAvailability::Null {
        return TariffGateResult {
            allowed: false,
            reason: Some(format!("Slot {slot} not available for tariff {tariff}")),
            availability,
            provenance: None,
        };
    }

    if slot.adapter_type_class() == AdapterTypeClass::C
        && matches!(tariff, TariffCode::O | TariffCode::S)
    {
        return TariffGateResult {
            allowed: false,
            reason: Some("Type C requires tariff M+O (Hybrid Service) or higher".into()),
            availability,
            provenance: None,
        };
    }

    let provenance = match availability {
        SlotAvailability::ActiveAlways => "gimel_managed",
        SlotAvailability::GimelOrUser => "gimel_or_user",
        SlotAvailability::UserProvidedRequired => "user_must_provide",
        SlotAvailability::NullOrUser => "user_optional",
        SlotAvailability::AttestedGimel => "attested_gimel",
        SlotAvailability::NullOrAttestedGimel => "null_fallback_until_attested",
        SlotAvailability::Null => unreachable!(),
    };

    TariffGateResult {
        allowed: true,
        reason: None,
        availability,
        provenance: Some(provenance.into()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Null,
    Pending,
    Active,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotState {
    pub slot: ConnectorSlot,
    pub status: SlotStatus,
    pub implementation_label: String,
    pub attestation_satisfied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterManifest {
    pub manifest_version: String,
    pub adapter_name: String,
    pub adapter_type: String,
    pub adapter_version: String,
    pub slot_name: String,
    pub namespace: String,
    pub issued_at: String,
    pub expires_at: String,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

pub struct ConnectorSlotRegistry {
    trusted_keys: Vec<VerifyingKey>,
    revoked_keys: Vec<String>,
    revoked_versions: Vec<String>,
    slot_states: HashMap<ConnectorSlot, SlotState>,
    tariff: TariffCode,
}

impl Default for ConnectorSlotRegistry {
    fn default() -> Self {
        Self::new(TariffCode::O)
    }
}

impl ConnectorSlotRegistry {
    pub fn new(tariff: TariffCode) -> Self {
        let mut slot_states = HashMap::new();
        for slot in ConnectorSlot::all() {
            let (status, label) = if *slot == ConnectorSlot::Pdp {
                (SlotStatus::Active, "embedded-rule-based".to_string())
            } else {
                (SlotStatus::Null, "None".to_string())
            };
            slot_states.insert(
                *slot,
                SlotState {
                    slot: *slot,
                    status,
                    implementation_label: label,
                    attestation_satisfied: *slot == ConnectorSlot::Pdp,
                },
            );
        }

        Self {
            trusted_keys: Vec::new(),
            revoked_keys: Vec::new(),
            revoked_versions: Vec::new(),
            slot_states,
            tariff,
        }
    }

    pub fn add_trusted_key(&mut self, key: VerifyingKey) {
        self.trusted_keys.push(key);
    }

    pub fn add_revoked_key(&mut self, key_hex: String) {
        self.revoked_keys.push(key_hex);
    }

    pub fn add_revoked_version(&mut self, version: String) {
        self.revoked_versions.push(version);
    }

    pub fn tariff(&self) -> TariffCode {
        self.tariff
    }

    pub fn register(
        &mut self,
        slot: ConnectorSlot,
        implementation_label: &str,
    ) -> Result<()> {
        if slot.requires_attestation() {
            return Err(GAuthError::AdapterRegistrationFailed(format!(
                "Type C slot {slot} requires sealed manifest registration via register_with_manifest()"
            )));
        }

        let gate = check_tariff_gate(slot, self.tariff);
        if !gate.allowed {
            return Err(GAuthError::AdapterRegistrationFailed(
                gate.reason.unwrap_or_else(|| "Tariff gate blocked".into()),
            ));
        }

        let state = self.slot_states.get_mut(&slot).unwrap();
        state.status = SlotStatus::Active;
        state.implementation_label = implementation_label.to_string();
        Ok(())
    }

    pub fn register_with_manifest(
        &mut self,
        slot: ConnectorSlot,
        manifest: &AdapterManifest,
        signature_bytes: &[u8],
    ) -> Result<()> {
        let gate = check_tariff_gate(slot, self.tariff);
        if !gate.allowed {
            return Err(GAuthError::AdapterRegistrationFailed(
                gate.reason.unwrap_or_else(|| "Tariff gate blocked".into()),
            ));
        }

        self.verify_manifest(slot, manifest, signature_bytes)?;

        let state = self.slot_states.get_mut(&slot).unwrap();
        state.status = SlotStatus::Active;
        state.attestation_satisfied = true;
        state.implementation_label = manifest.adapter_name.clone();
        Ok(())
    }

    pub fn verify_manifest(
        &self,
        slot: ConnectorSlot,
        manifest: &AdapterManifest,
        signature_bytes: &[u8],
    ) -> Result<()> {
        if manifest.manifest_version != "1.0" {
            return Err(GAuthError::AdapterRegistrationFailed(
                "manifest_version must be '1.0'".into(),
            ));
        }

        if manifest.adapter_type != "C" {
            return Err(GAuthError::AdapterRegistrationFailed(
                "adapter_type must be 'C' for sealed adapters".into(),
            ));
        }

        if manifest.slot_name != slot.to_string() {
            return Err(GAuthError::AdapterRegistrationFailed(format!(
                "Manifest slot_name '{}' does not match target slot '{}'",
                manifest.slot_name, slot
            )));
        }

        if manifest.namespace != slot.canonical_namespace() {
            return Err(GAuthError::AdapterRegistrationFailed(format!(
                "Namespace '{}' must match canonical namespace '{}' for slot {}",
                manifest.namespace,
                slot.canonical_namespace(),
                slot
            )));
        }

        if manifest.issuer != "gimel-foundation" {
            return Err(GAuthError::AdapterRegistrationFailed(format!(
                "Issuer must be 'gimel-foundation', got '{}'",
                manifest.issuer
            )));
        }

        if let (Ok(issued), Ok(expires)) = (
            chrono::DateTime::parse_from_rfc3339(&manifest.issued_at),
            chrono::DateTime::parse_from_rfc3339(&manifest.expires_at),
        ) {
            let now = chrono::Utc::now();
            if issued > now {
                return Err(GAuthError::AdapterRegistrationFailed(
                    "Manifest issued_at is in the future".into(),
                ));
            }
            if expires < now {
                return Err(GAuthError::AdapterRegistrationFailed(
                    "Manifest has expired (expires_at is in the past)".into(),
                ));
            }
            let max_validity = chrono::Duration::days(365);
            if expires - issued > max_validity {
                return Err(GAuthError::AdapterRegistrationFailed(
                    "Manifest validity exceeds maximum of 365 days".into(),
                ));
            }
        } else {
            return Err(GAuthError::AdapterRegistrationFailed(
                "issued_at and expires_at must be valid RFC3339 timestamps".into(),
            ));
        }

        if self.revoked_versions.contains(&manifest.adapter_version) {
            return Err(GAuthError::AdapterRegistrationFailed(format!(
                "Adapter version '{}' has been revoked",
                manifest.adapter_version
            )));
        }

        if self.revoked_keys.contains(&manifest.public_key) {
            return Err(GAuthError::AdapterRegistrationFailed(
                "Manifest public key has been revoked".into(),
            ));
        }

        let mut manifest_for_verify = manifest.clone();
        manifest_for_verify.signature = None;
        let canonical_json = crate::crypto::canonical_json(
            &serde_json::to_value(&manifest_for_verify)
                .map_err(|e| GAuthError::AdapterSignatureInvalid(e.to_string()))?,
        );
        let manifest_bytes = canonical_json.as_bytes();

        let signature = Signature::from_slice(signature_bytes)
            .map_err(|e| {
                GAuthError::AdapterSignatureInvalid(format!("Invalid signature format: {e}"))
            })?;

        let manifest_pub_key_hex = &manifest.public_key;
        let mut verified = false;
        for key in &self.trusted_keys {
            if key.verify(manifest_bytes, &signature).is_ok() {
                let key_hex = hex::encode(key.as_bytes());
                if key_hex == *manifest_pub_key_hex {
                    verified = true;
                    break;
                }
                return Err(GAuthError::AdapterSignatureInvalid(
                    "Signature valid but verifying key does not match manifest public_key".into(),
                ));
            }
        }

        if !verified {
            return Err(GAuthError::AdapterSignatureInvalid(
                "No trusted key verified the adapter manifest signature".into(),
            ));
        }

        Ok(())
    }

    pub fn unregister(&mut self, slot: ConnectorSlot) -> Result<()> {
        if slot.is_mandatory() {
            return Err(GAuthError::AdapterRegistrationFailed(format!(
                "Cannot unregister {slot} — it is mandatory"
            )));
        }

        let state = self.slot_states.get_mut(&slot).unwrap();
        state.status = SlotStatus::Null;
        state.implementation_label = "None".into();
        state.attestation_satisfied = false;
        Ok(())
    }

    pub fn satisfy_attestation(
        &mut self,
        slot: ConnectorSlot,
        manifest: &AdapterManifest,
        signature_bytes: &[u8],
    ) -> Result<()> {
        if !slot.requires_attestation() {
            return Err(GAuthError::AdapterRegistrationFailed(format!(
                "Slot {slot} does not require attestation"
            )));
        }

        self.verify_manifest(slot, manifest, signature_bytes)?;

        let state = self.slot_states.get_mut(&slot).unwrap();
        state.attestation_satisfied = true;

        if state.status == SlotStatus::Pending {
            state.status = SlotStatus::Active;
        }

        Ok(())
    }

    pub fn check_mandatory_slots(&self) -> Result<()> {
        for slot in ConnectorSlot::all() {
            if slot.is_mandatory() {
                let state = self.slot_states.get(slot).unwrap();
                if state.status == SlotStatus::Null {
                    return Err(GAuthError::AdapterRegistrationFailed(format!(
                        "Mandatory slot {slot} is not active"
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn is_operational(&self) -> bool {
        self.check_mandatory_slots().is_ok()
    }

    pub fn slot_status(&self, slot: ConnectorSlot) -> &SlotState {
        self.slot_states.get(&slot).unwrap()
    }

    pub fn all_slot_states(&self) -> Vec<&SlotState> {
        ConnectorSlot::all()
            .iter()
            .map(|s| self.slot_states.get(s).unwrap())
            .collect()
    }

    pub fn change_tariff(&mut self, new_tariff: TariffCode) -> Vec<TariffDowngradeEvent> {
        let old_tariff = self.tariff;
        self.tariff = new_tariff;
        let mut events = Vec::new();

        for slot in ConnectorSlot::all() {
            let state = self.slot_states.get(slot).unwrap();
            if state.status == SlotStatus::Active || state.status == SlotStatus::Pending {
                let gate = check_tariff_gate(*slot, new_tariff);
                if !gate.allowed {
                    let state = self.slot_states.get_mut(slot).unwrap();
                    state.status = SlotStatus::Null;
                    state.implementation_label = "None".into();
                    state.attestation_satisfied = false;
                    events.push(TariffDowngradeEvent {
                        slot: *slot,
                        old_tariff,
                        new_tariff,
                        action: "deactivated".into(),
                        reason: gate.reason.unwrap_or_default(),
                    });
                }
            }
        }

        events
    }

    pub fn check_license_compliance(&self) -> Vec<LicenseComplianceViolation> {
        let mut violations = Vec::new();

        for slot in ConnectorSlot::all() {
            let state = self.slot_states.get(slot).unwrap();
            if state.status == SlotStatus::Active || state.status == SlotStatus::Pending {
                let gate = check_tariff_gate(*slot, self.tariff);
                if !gate.allowed {
                    violations.push(LicenseComplianceViolation {
                        slot: *slot,
                        tariff: self.tariff,
                        violation_code: "LICENSE_COMPLIANCE_VIOLATION".into(),
                        message: format!(
                            "Slot {} is {:?} but not allowed for tariff {}",
                            slot, state.status, self.tariff
                        ),
                    });
                }
            }

            if slot.requires_attestation()
                && state.status == SlotStatus::Active
                && !state.attestation_satisfied
            {
                violations.push(LicenseComplianceViolation {
                    slot: *slot,
                    tariff: self.tariff,
                    violation_code: "LICENSE_COMPLIANCE_VIOLATION".into(),
                    message: format!(
                        "Type C slot {slot} is active but attestation not satisfied"
                    ),
                });
            }
        }

        violations
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TariffDowngradeEvent {
    pub slot: ConnectorSlot,
    pub old_tariff: TariffCode,
    pub new_tariff: TariffCode,
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseComplianceViolation {
    pub slot: ConnectorSlot,
    pub tariff: TariffCode,
    pub violation_code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterType {
    OAuthEngine,
    Foundry,
    AiEnrichment,
    RiskScoring,
    RegulatoryReasoning,
}

impl std::fmt::Display for AdapterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterType::OAuthEngine => write!(f, "oauth_engine"),
            AdapterType::Foundry => write!(f, "foundry"),
            AdapterType::AiEnrichment => write!(f, "ai_enrichment"),
            AdapterType::RiskScoring => write!(f, "risk_scoring"),
            AdapterType::RegulatoryReasoning => write!(f, "regulatory_reasoning"),
        }
    }
}

pub struct AdapterRegistry {
    trusted_keys: Vec<VerifyingKey>,
    trusted_namespaces: Vec<String>,
    oauth_engines: HashMap<String, Arc<dyn OAuthEngineAdapter>>,
    foundries: HashMap<String, Arc<dyn FoundryAdapter>>,
    ai_enrichments: HashMap<String, Arc<dyn AIEnrichmentAdapter>>,
    risk_scorings: HashMap<String, Arc<dyn RiskScoringAdapter>>,
    regulatory_reasonings: HashMap<String, Arc<dyn RegulatoryReasoningAdapter>>,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyAdapterManifest {
    pub name: String,
    pub version: String,
    pub namespace: String,
    pub description: String,
    pub adapter_type: AdapterType,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self {
            trusted_keys: Vec::new(),
            trusted_namespaces: vec!["gimel".to_string(), "gimelid".to_string()],
            oauth_engines: HashMap::new(),
            foundries: HashMap::new(),
            ai_enrichments: HashMap::new(),
            risk_scorings: HashMap::new(),
            regulatory_reasonings: HashMap::new(),
        }
    }

    pub fn add_trusted_key(&mut self, key: VerifyingKey) {
        self.trusted_keys.push(key);
    }

    pub fn add_trusted_namespace(&mut self, namespace: String) {
        self.trusted_namespaces.push(namespace);
    }

    pub fn verify_manifest(
        &self,
        manifest: &LegacyAdapterManifest,
        signature_bytes: &[u8],
    ) -> Result<()> {
        let manifest_json = serde_json::to_vec(manifest)
            .map_err(|e| GAuthError::AdapterSignatureInvalid(e.to_string()))?;

        let signature = Signature::from_slice(signature_bytes)
            .map_err(|e| {
                GAuthError::AdapterSignatureInvalid(format!("Invalid signature format: {e}"))
            })?;

        for key in &self.trusted_keys {
            if key.verify(&manifest_json, &signature).is_ok() {
                return Ok(());
            }
        }

        Err(GAuthError::AdapterSignatureInvalid(
            "No trusted key verified the adapter signature".into(),
        ))
    }

    fn check_namespace(&self, namespace: &str) -> Result<()> {
        if self.trusted_namespaces.contains(&namespace.to_string()) {
            Ok(())
        } else {
            Err(GAuthError::AdapterRegistrationFailed(format!(
                "Namespace '{namespace}' is not in the trusted namespaces list"
            )))
        }
    }

    fn check_no_collision(&self, name: &str, adapter_type: &AdapterType) -> Result<()> {
        let exists = match adapter_type {
            AdapterType::OAuthEngine => self.oauth_engines.contains_key(name),
            AdapterType::Foundry => self.foundries.contains_key(name),
            AdapterType::AiEnrichment => self.ai_enrichments.contains_key(name),
            AdapterType::RiskScoring => self.risk_scorings.contains_key(name),
            AdapterType::RegulatoryReasoning => self.regulatory_reasonings.contains_key(name),
        };
        if exists {
            Err(GAuthError::AdapterRegistrationFailed(format!(
                "Adapter '{name}' of type {adapter_type} is already registered; unregister it first"
            )))
        } else {
            Ok(())
        }
    }

    pub fn register_oauth_engine(
        &mut self,
        manifest: &LegacyAdapterManifest,
        signature: &[u8],
        adapter: Arc<dyn OAuthEngineAdapter>,
    ) -> Result<()> {
        if manifest.adapter_type != AdapterType::OAuthEngine {
            return Err(GAuthError::AdapterRegistrationFailed(
                "Manifest adapter_type mismatch".into(),
            ));
        }
        self.check_namespace(&manifest.namespace)?;
        self.check_no_collision(&manifest.name, &manifest.adapter_type)?;
        self.verify_manifest(manifest, signature)?;
        self.oauth_engines.insert(manifest.name.clone(), adapter);
        Ok(())
    }

    pub fn register_foundry(
        &mut self,
        manifest: &LegacyAdapterManifest,
        signature: &[u8],
        adapter: Arc<dyn FoundryAdapter>,
    ) -> Result<()> {
        if manifest.adapter_type != AdapterType::Foundry {
            return Err(GAuthError::AdapterRegistrationFailed(
                "Manifest adapter_type mismatch".into(),
            ));
        }
        self.check_namespace(&manifest.namespace)?;
        self.check_no_collision(&manifest.name, &manifest.adapter_type)?;
        self.verify_manifest(manifest, signature)?;
        self.foundries.insert(manifest.name.clone(), adapter);
        Ok(())
    }

    pub fn get_oauth_engine(&self, name: &str) -> Option<&Arc<dyn OAuthEngineAdapter>> {
        self.oauth_engines.get(name)
    }

    pub fn get_foundry(&self, name: &str) -> Option<&Arc<dyn FoundryAdapter>> {
        self.foundries.get(name)
    }

    pub fn register_ai_enrichment(
        &mut self,
        manifest: &LegacyAdapterManifest,
        signature: &[u8],
        adapter: Arc<dyn AIEnrichmentAdapter>,
    ) -> Result<()> {
        if manifest.adapter_type != AdapterType::AiEnrichment {
            return Err(GAuthError::AdapterRegistrationFailed(
                "Manifest adapter_type mismatch".into(),
            ));
        }
        self.check_namespace(&manifest.namespace)?;
        self.check_no_collision(&manifest.name, &manifest.adapter_type)?;
        self.verify_manifest(manifest, signature)?;
        self.ai_enrichments.insert(manifest.name.clone(), adapter);
        Ok(())
    }

    pub fn register_risk_scoring(
        &mut self,
        manifest: &LegacyAdapterManifest,
        signature: &[u8],
        adapter: Arc<dyn RiskScoringAdapter>,
    ) -> Result<()> {
        if manifest.adapter_type != AdapterType::RiskScoring {
            return Err(GAuthError::AdapterRegistrationFailed(
                "Manifest adapter_type mismatch".into(),
            ));
        }
        self.check_namespace(&manifest.namespace)?;
        self.check_no_collision(&manifest.name, &manifest.adapter_type)?;
        self.verify_manifest(manifest, signature)?;
        self.risk_scorings.insert(manifest.name.clone(), adapter);
        Ok(())
    }

    pub fn register_regulatory_reasoning(
        &mut self,
        manifest: &LegacyAdapterManifest,
        signature: &[u8],
        adapter: Arc<dyn RegulatoryReasoningAdapter>,
    ) -> Result<()> {
        if manifest.adapter_type != AdapterType::RegulatoryReasoning {
            return Err(GAuthError::AdapterRegistrationFailed(
                "Manifest adapter_type mismatch".into(),
            ));
        }
        self.check_namespace(&manifest.namespace)?;
        self.check_no_collision(&manifest.name, &manifest.adapter_type)?;
        self.verify_manifest(manifest, signature)?;
        self.regulatory_reasonings
            .insert(manifest.name.clone(), adapter);
        Ok(())
    }

    pub fn get_ai_enrichment(&self, name: &str) -> Option<&Arc<dyn AIEnrichmentAdapter>> {
        self.ai_enrichments.get(name)
    }

    pub fn get_risk_scoring(&self, name: &str) -> Option<&Arc<dyn RiskScoringAdapter>> {
        self.risk_scorings.get(name)
    }

    pub fn get_regulatory_reasoning(
        &self,
        name: &str,
    ) -> Option<&Arc<dyn RegulatoryReasoningAdapter>> {
        self.regulatory_reasonings.get(name)
    }

    pub fn list_registered(&self) -> Vec<(AdapterType, Vec<String>)> {
        vec![
            (
                AdapterType::OAuthEngine,
                self.oauth_engines.keys().cloned().collect(),
            ),
            (
                AdapterType::Foundry,
                self.foundries.keys().cloned().collect(),
            ),
            (
                AdapterType::AiEnrichment,
                self.ai_enrichments.keys().cloned().collect(),
            ),
            (
                AdapterType::RiskScoring,
                self.risk_scorings.keys().cloned().collect(),
            ),
            (
                AdapterType::RegulatoryReasoning,
                self.regulatory_reasonings.keys().cloned().collect(),
            ),
        ]
    }
}
