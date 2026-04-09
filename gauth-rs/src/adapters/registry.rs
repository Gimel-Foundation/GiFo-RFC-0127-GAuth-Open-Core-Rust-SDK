use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{GAuthError, Result};
use super::traits::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterManifest {
    pub name: String,
    pub version: String,
    pub namespace: String,
    pub description: String,
    pub adapter_type: AdapterType,
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
    risk_scorers: HashMap<String, Arc<dyn RiskScoringAdapter>>,
    regulatory_reasoners: HashMap<String, Arc<dyn RegulatoryReasoningAdapter>>,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self {
            trusted_keys: Vec::new(),
            trusted_namespaces: vec!["gimel".to_string(), "gimelfoundation".to_string()],
            oauth_engines: HashMap::new(),
            foundries: HashMap::new(),
            ai_enrichments: HashMap::new(),
            risk_scorers: HashMap::new(),
            regulatory_reasoners: HashMap::new(),
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
        manifest: &AdapterManifest,
        signature_bytes: &[u8],
    ) -> Result<()> {
        let manifest_json = serde_json::to_vec(manifest)
            .map_err(|e| GAuthError::AdapterSignatureInvalid(e.to_string()))?;

        let signature = Signature::from_slice(signature_bytes)
            .map_err(|e| GAuthError::AdapterSignatureInvalid(format!("Invalid signature format: {}", e)))?;

        for key in &self.trusted_keys {
            if key.verify(&manifest_json, &signature).is_ok() {
                return Ok(());
            }
        }

        Err(GAuthError::AdapterSignatureInvalid(
            "No trusted key verified the adapter signature".into(),
        ))
    }

    fn check_namespace(&self, manifest: &AdapterManifest) -> Result<()> {
        if self.trusted_namespaces.contains(&manifest.namespace) {
            Ok(())
        } else {
            Err(GAuthError::AdapterRegistrationFailed(format!(
                "Namespace '{}' is not in the trusted namespaces list",
                manifest.namespace
            )))
        }
    }

    fn check_no_collision(&self, name: &str, adapter_type: &AdapterType) -> Result<()> {
        let exists = match adapter_type {
            AdapterType::OAuthEngine => self.oauth_engines.contains_key(name),
            AdapterType::Foundry => self.foundries.contains_key(name),
            AdapterType::AiEnrichment => self.ai_enrichments.contains_key(name),
            AdapterType::RiskScoring => self.risk_scorers.contains_key(name),
            AdapterType::RegulatoryReasoning => self.regulatory_reasoners.contains_key(name),
        };
        if exists {
            Err(GAuthError::AdapterRegistrationFailed(format!(
                "Adapter '{}' of type {} is already registered; unregister it first",
                name, adapter_type
            )))
        } else {
            Ok(())
        }
    }

    pub fn register_oauth_engine(
        &mut self,
        manifest: &AdapterManifest,
        signature: &[u8],
        adapter: Arc<dyn OAuthEngineAdapter>,
    ) -> Result<()> {
        if manifest.adapter_type != AdapterType::OAuthEngine {
            return Err(GAuthError::AdapterRegistrationFailed(
                "Manifest adapter_type mismatch".into(),
            ));
        }
        self.check_namespace(manifest)?;
        self.check_no_collision(&manifest.name, &manifest.adapter_type)?;
        self.verify_manifest(manifest, signature)?;
        self.oauth_engines.insert(manifest.name.clone(), adapter);
        Ok(())
    }

    pub fn register_foundry(
        &mut self,
        manifest: &AdapterManifest,
        signature: &[u8],
        adapter: Arc<dyn FoundryAdapter>,
    ) -> Result<()> {
        if manifest.adapter_type != AdapterType::Foundry {
            return Err(GAuthError::AdapterRegistrationFailed(
                "Manifest adapter_type mismatch".into(),
            ));
        }
        self.check_namespace(manifest)?;
        self.check_no_collision(&manifest.name, &manifest.adapter_type)?;
        self.verify_manifest(manifest, signature)?;
        self.foundries.insert(manifest.name.clone(), adapter);
        Ok(())
    }

    pub fn register_ai_enrichment(
        &mut self,
        manifest: &AdapterManifest,
        signature: &[u8],
        adapter: Arc<dyn AIEnrichmentAdapter>,
    ) -> Result<()> {
        if manifest.adapter_type != AdapterType::AiEnrichment {
            return Err(GAuthError::AdapterRegistrationFailed(
                "Manifest adapter_type mismatch".into(),
            ));
        }
        self.check_namespace(manifest)?;
        self.check_no_collision(&manifest.name, &manifest.adapter_type)?;
        self.verify_manifest(manifest, signature)?;
        self.ai_enrichments.insert(manifest.name.clone(), adapter);
        Ok(())
    }

    pub fn register_risk_scoring(
        &mut self,
        manifest: &AdapterManifest,
        signature: &[u8],
        adapter: Arc<dyn RiskScoringAdapter>,
    ) -> Result<()> {
        if manifest.adapter_type != AdapterType::RiskScoring {
            return Err(GAuthError::AdapterRegistrationFailed(
                "Manifest adapter_type mismatch".into(),
            ));
        }
        self.check_namespace(manifest)?;
        self.check_no_collision(&manifest.name, &manifest.adapter_type)?;
        self.verify_manifest(manifest, signature)?;
        self.risk_scorers.insert(manifest.name.clone(), adapter);
        Ok(())
    }

    pub fn register_regulatory_reasoning(
        &mut self,
        manifest: &AdapterManifest,
        signature: &[u8],
        adapter: Arc<dyn RegulatoryReasoningAdapter>,
    ) -> Result<()> {
        if manifest.adapter_type != AdapterType::RegulatoryReasoning {
            return Err(GAuthError::AdapterRegistrationFailed(
                "Manifest adapter_type mismatch".into(),
            ));
        }
        self.check_namespace(manifest)?;
        self.check_no_collision(&manifest.name, &manifest.adapter_type)?;
        self.verify_manifest(manifest, signature)?;
        self.regulatory_reasoners
            .insert(manifest.name.clone(), adapter);
        Ok(())
    }

    pub fn get_oauth_engine(&self, name: &str) -> Option<&Arc<dyn OAuthEngineAdapter>> {
        self.oauth_engines.get(name)
    }

    pub fn get_foundry(&self, name: &str) -> Option<&Arc<dyn FoundryAdapter>> {
        self.foundries.get(name)
    }

    pub fn get_ai_enrichment(&self, name: &str) -> Option<&Arc<dyn AIEnrichmentAdapter>> {
        self.ai_enrichments.get(name)
    }

    pub fn get_risk_scoring(&self, name: &str) -> Option<&Arc<dyn RiskScoringAdapter>> {
        self.risk_scorers.get(name)
    }

    pub fn get_regulatory_reasoning(
        &self,
        name: &str,
    ) -> Option<&Arc<dyn RegulatoryReasoningAdapter>> {
        self.regulatory_reasoners.get(name)
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
                self.risk_scorers.keys().cloned().collect(),
            ),
            (
                AdapterType::RegulatoryReasoning,
                self.regulatory_reasoners.keys().cloned().collect(),
            ),
        ]
    }
}
