use std::collections::HashMap;

use gauth_rs::management::types::{Mandate, MandateAuditEntry, MandateOperation, MandateStatus};
use gauth_rs::profiles::{
    ceiling_table, get_ceiling, get_profile_info, list_profiles, validate_against_ceiling,
};
use gauth_rs::storage::{InMemoryMandateRepository, MandateRepository};
use gauth_rs::types::*;
use gauth_rs::vc::did::{create_did_key, resolve_did, resolve_did_key, resolve_did_web};
use gauth_rs::vc::openid::{OpenID4VCIssuer, OpenID4VPVerifier, TrustedIssuerRegistry};
use gauth_rs::vc::sd_jwt::{create_sd_jwt, verify_sd_jwt_disclosures};
use gauth_rs::vc::serializer::{
    create_data_integrity_proof, poa_to_vc, vc_to_jwt_payload, verify_data_integrity_proof,
    GAUTH_VC_CONTEXT, W3C_CREDENTIALS_V2_CONTEXT,
};
use gauth_rs::vc::status_list::BitstringStatusList;

fn make_test_mandate() -> Mandate {
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
            constraints: None,
        },
    );
    core_verbs.insert(
        "command.run".to_string(),
        ToolPolicy {
            allowed: false,
            cost_cents_base: None,
            constraints: None,
        },
    );

    let now = chrono::Utc::now();
    Mandate {
        mandate_id: "test-mandate-001".to_string(),
        status: MandateStatus::Active,
        parties: Parties {
            issuer: "did:web:gauth.gimel.foundation".to_string(),
            subject: "agent-1".to_string(),
            customer_id: "cust-1".to_string(),
            project_id: "proj-1".to_string(),
            issued_by: Some("admin".to_string()),
            approval_chain: None,
        },
        scope: Scope {
            governance_profile: GovernanceProfile::Standard,
            phase: Phase::Build,
            core_verbs,
            active_modules: None,
            allowed_paths: Some(vec!["src/**".to_string()]),
            denied_paths: None,
            allowed_sectors: Some(vec!["technology".to_string()]),
            allowed_regions: Some(vec!["EU".to_string()]),
            allowed_transactions: None,
            transaction_matrix: None,
            allowed_decisions: None,
            platform_permissions: None,
        },
        requirements: Requirements {
            approval_mode: ApprovalMode::Supervised,
            budget: Some(Budget {
                total_cents: Some(10000),
                remaining_cents: Some(10000),
            }),
            session_limits: None,
            ttl_seconds: Some(7200),
        },
        scope_checksum: "sha256:test".to_string(),
        tool_permissions_hash: "sha256:test_tools".to_string(),
        platform_permissions_hash: "sha256:test_platform".to_string(),
        created_at: now,
        activated_at: Some(now),
        expires_at: Some(now + chrono::Duration::hours(2)),
        revoked_at: None,
        suspended_at: None,
        delegation_chain: None,
        audit_trail: vec![],
    }
}

#[test]
fn ct_cf_001_poa_to_vc_produces_w3c_v2_context() {
    let mandate = make_test_mandate();
    let vc = poa_to_vc(&mandate, "", "", 0);
    assert!(vc.context.contains(&W3C_CREDENTIALS_V2_CONTEXT.to_string()));
    assert!(vc.context.contains(&GAUTH_VC_CONTEXT.to_string()));
}

#[test]
fn ct_cf_002_poa_to_vc_type_array() {
    let mandate = make_test_mandate();
    let vc = poa_to_vc(&mandate, "", "", 0);
    assert!(vc.type_.contains(&"VerifiableCredential".to_string()));
    assert!(vc.type_.contains(&"GAuthPoACredential".to_string()));
}

#[test]
fn ct_cf_003_poa_to_vc_issuer_did() {
    let mandate = make_test_mandate();
    let vc = poa_to_vc(&mandate, "did:web:example.com", "", 0);
    assert_eq!(vc.issuer.id, "did:web:example.com");
}

#[test]
fn ct_cf_004_poa_to_vc_default_issuer_from_project() {
    let mandate = make_test_mandate();
    let vc = poa_to_vc(&mandate, "", "", 0);
    assert_eq!(vc.issuer.id, "did:web:gauth.gimel.foundation:proj-1");
}

#[test]
fn ct_cf_005_poa_to_vc_subject_did_key() {
    let mandate = make_test_mandate();
    let vc = poa_to_vc(&mandate, "", "", 0);
    let subject_id = vc.credential_subject.get("id").unwrap().as_str().unwrap();
    assert!(subject_id.starts_with("did:key:"));
    assert!(subject_id.contains("agent-1"));
}

#[test]
fn ct_cf_006_poa_to_vc_allowed_actions() {
    let mandate = make_test_mandate();
    let vc = poa_to_vc(&mandate, "", "", 0);
    let actions = vc
        .credential_subject
        .get("allowed_actions")
        .unwrap()
        .as_array()
        .unwrap();
    let action_strings: Vec<&str> = actions.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(action_strings.contains(&"file.read"));
    assert!(action_strings.contains(&"file.create"));
    assert!(!action_strings.contains(&"command.run"));
}

#[test]
fn ct_cf_007_poa_to_vc_credential_status() {
    let mandate = make_test_mandate();
    let vc = poa_to_vc(
        &mandate,
        "did:web:example.com",
        "https://gauth.example.com/status/1",
        42,
    );
    let status = vc.credential_status.unwrap();
    assert_eq!(status.type_, "BitstringStatusListEntry");
    assert_eq!(status.status_purpose, "revocation");
    assert_eq!(status.status_list_index, 42);
    assert_eq!(
        status.status_list_credential,
        "https://gauth.example.com/status/1"
    );
}

#[test]
fn ct_cf_008_poa_to_vc_valid_from_until() {
    let mandate = make_test_mandate();
    let vc = poa_to_vc(&mandate, "", "", 0);
    assert!(vc.valid_from.is_some());
    assert!(vc.valid_until.is_some());
}

#[test]
fn ct_cf_009_vc_to_jwt_payload_roundtrip() {
    let mandate = make_test_mandate();
    let vc = poa_to_vc(&mandate, "did:web:example.com", "", 0);
    let jwt = vc_to_jwt_payload(&vc);

    assert_eq!(jwt.get("iss").unwrap().as_str().unwrap(), "did:web:example.com");
    assert!(jwt.get("sub").is_some());
    assert!(jwt.get("vc").is_some());
    assert!(jwt.get("jti").is_some());
    assert!(jwt.get("iat").is_some());
    assert!(jwt.get("exp").is_some());
}

#[test]
fn ct_cf_010_data_integrity_proof_create_verify_without_key() {
    let doc = serde_json::json!({"test": "document", "nested": {"key": "value"}});
    let proof = create_data_integrity_proof(&doc, "did:web:example.com#key-1", None);

    assert_eq!(proof.type_, "DataIntegrityProof");
    assert_eq!(proof.cryptosuite, "eddsa-rdfc-2022");
    assert_eq!(proof.proof_purpose, "assertionMethod");
    assert_eq!(proof.verification_method, "did:web:example.com#key-1");
    assert!(!proof.proof_value.is_empty());

    assert!(verify_data_integrity_proof(&doc, &proof, None));
}

#[test]
fn ct_cf_011_data_integrity_proof_create_verify_with_ed25519() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();

    let doc = serde_json::json!({"test": "signed-document"});
    let proof = create_data_integrity_proof(&doc, "did:key:z123#z123", Some(&signing_key));

    assert!(verify_data_integrity_proof(&doc, &proof, Some(&verifying_key)));
}

#[test]
fn ct_cf_012_data_integrity_proof_tampered_doc_fails() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();

    let doc = serde_json::json!({"test": "original"});
    let proof = create_data_integrity_proof(&doc, "did:key:z123#z123", Some(&signing_key));

    let tampered = serde_json::json!({"test": "tampered"});
    assert!(!verify_data_integrity_proof(&tampered, &proof, Some(&verifying_key)));
}

#[test]
fn ct_did_001_resolve_did_web_simple() {
    let doc = resolve_did_web("did:web:example.com").unwrap();
    assert_eq!(doc.id, "did:web:example.com");
    assert!(!doc.verification_method.is_empty());
    assert_eq!(doc.verification_method[0].type_, "JsonWebKey2020");
    let res = doc.resolution.unwrap();
    assert!(res.resolved);
    assert_eq!(res.method, "web");
    assert!(res.did_document_url.unwrap().contains("/.well-known/did.json"));
}

#[test]
fn ct_did_002_resolve_did_web_with_path() {
    let doc = resolve_did_web("did:web:example.com:project:abc").unwrap();
    assert_eq!(doc.id, "did:web:example.com:project:abc");
    let url = doc.resolution.unwrap().did_document_url.unwrap();
    assert!(url.contains("/project/abc/did.json"));
}

#[test]
fn ct_did_003_resolve_did_web_service() {
    let doc = resolve_did_web("did:web:gauth.gimel.foundation").unwrap();
    let service = doc.service.unwrap();
    assert!(!service.is_empty());
    assert_eq!(service[0].type_, "GAuthService");
    assert!(service[0].service_endpoint.contains("/api/gauth"));
}

#[test]
fn ct_did_004_resolve_did_web_invalid() {
    let result = resolve_did_web("did:key:z123");
    assert!(result.is_err());
}

#[test]
fn ct_did_005_resolve_did_key() {
    let doc = resolve_did_key("did:key:zABC123").unwrap();
    assert_eq!(doc.id, "did:key:zABC123");
    assert_eq!(doc.verification_method[0].type_, "JsonWebKey2020");
    assert_eq!(
        doc.verification_method[0].public_key_multibase.as_ref().unwrap(),
        "zABC123"
    );
    assert!(doc.service.is_none());
    let res = doc.resolution.unwrap();
    assert!(res.resolved);
    assert_eq!(res.method, "key");
}

#[test]
fn ct_did_006_resolve_did_key_invalid() {
    assert!(resolve_did_key("did:web:example.com").is_err());
}

#[test]
fn ct_did_007_create_did_key_with_hex() {
    let result = create_did_key(Some("abcdef0123456789"));
    assert!(result.did.starts_with("did:key:z"));
    assert_eq!(result.multibase_key, "zabcdef0123456789");
    assert_eq!(result.did_document.id, result.did);
}

#[test]
fn ct_did_008_create_did_key_ephemeral() {
    let r1 = create_did_key(None);
    let r2 = create_did_key(None);
    assert_ne!(r1.did, r2.did);
    assert!(r1.did.starts_with("did:key:z"));
}

#[test]
fn ct_did_009_resolve_did_router() {
    assert!(resolve_did("did:web:example.com").is_ok());
    assert!(resolve_did("did:key:zABC").is_ok());
    assert!(resolve_did("did:ion:xyz").is_err());
}

#[test]
fn ct_sdjwt_001_create_sd_jwt_no_redaction() {
    let payload = serde_json::json!({
        "credentialSubject": {
            "name": "Agent-1",
            "role": "builder"
        }
    });
    let result = create_sd_jwt(&payload, &[]);
    assert!(result.compact.ends_with('~'));
    assert!(result.disclosures.is_empty());
    assert!(result.sd_digests.is_empty());
}

#[test]
fn ct_sdjwt_002_create_sd_jwt_with_redaction() {
    let payload = serde_json::json!({
        "credentialSubject": {
            "name": "Agent-1",
            "role": "builder",
            "budget": 10000
        }
    });
    let result = create_sd_jwt(&payload, &["budget"]);
    assert!(!result.disclosures.is_empty());
    assert!(!result.sd_digests.is_empty());
    assert!(result.compact.contains('~'));
}

#[test]
fn ct_sdjwt_003_sd_jwt_header_alg() {
    let payload = serde_json::json!({"credentialSubject": {"name": "test"}});
    let result = create_sd_jwt(&payload, &[]);
    let parts: Vec<&str> = result.compact.split('~').collect();
    let jwt_part = parts[0];
    let header_b64 = jwt_part.split('.').next().unwrap();
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "vc+sd-jwt");
}

#[test]
fn ct_sdjwt_004_verify_sd_jwt_disclosures() {
    let payload = serde_json::json!({
        "credentialSubject": {
            "name": "Agent-1",
            "secret_field": "hidden-value"
        }
    });
    let result = create_sd_jwt(&payload, &["secret_field"]);
    let verification = verify_sd_jwt_disclosures(&result.compact);
    assert!(verification.valid);
    assert!(verification.disclosed_claims.contains_key("secret_field"));
    assert_eq!(
        verification.disclosed_claims["secret_field"],
        serde_json::json!("hidden-value")
    );
}

#[test]
fn ct_sdjwt_005_sd_jwt_multiple_redactions() {
    let payload = serde_json::json!({
        "credentialSubject": {
            "name": "Agent-1",
            "budget": 10000,
            "secret_key": "abc123"
        }
    });
    let result = create_sd_jwt(&payload, &["budget", "secret_key"]);
    assert_eq!(result.disclosures.len(), 2);
    assert_eq!(result.sd_digests.len(), 2);

    let verification = verify_sd_jwt_disclosures(&result.compact);
    assert!(verification.valid);
    assert_eq!(verification.disclosed_claims.len(), 2);
}

#[test]
fn ct_sl_001_bitstring_status_list_basic() {
    let sl = BitstringStatusList::with_default_size();
    assert_eq!(sl.size(), 131072);
    assert!(!sl.get_status(0).unwrap());
    assert!(!sl.get_status(100).unwrap());
}

#[test]
fn ct_sl_002_set_and_get_status() {
    let mut sl = BitstringStatusList::new(1024, 300);
    sl.set_status(42, true, "key-compromise").unwrap();
    assert!(sl.get_status(42).unwrap());
    assert!(!sl.get_status(41).unwrap());
    assert!(!sl.get_status(43).unwrap());
    assert_eq!(sl.get_revocation_reason(42), "key-compromise");
}

#[test]
fn ct_sl_003_unrevoke() {
    let mut sl = BitstringStatusList::new(1024, 300);
    sl.set_status(10, true, "test").unwrap();
    assert!(sl.get_status(10).unwrap());
    sl.set_status(10, false, "").unwrap();
    assert!(!sl.get_status(10).unwrap());
    assert_eq!(sl.get_revocation_reason(10), "");
}

#[test]
fn ct_sl_004_encode_decode_roundtrip() {
    let mut sl = BitstringStatusList::new(1024, 300);
    sl.set_status(0, true, "").unwrap();
    sl.set_status(42, true, "").unwrap();
    sl.set_status(1023, true, "").unwrap();

    let encoded = sl.encode();
    let decoded = BitstringStatusList::decode(&encoded, 1024).unwrap();
    assert!(decoded.get_status(0).unwrap());
    assert!(decoded.get_status(42).unwrap());
    assert!(decoded.get_status(1023).unwrap());
    assert!(!decoded.get_status(1).unwrap());
    assert!(!decoded.get_status(500).unwrap());
}

#[test]
fn ct_sl_005_to_status_list_credential() {
    let sl = BitstringStatusList::with_default_size();
    let cred = sl.to_status_list_credential(
        "https://gauth.example.com/status/1",
        "did:web:gauth.example.com",
    );
    assert_eq!(
        cred.context,
        vec!["https://www.w3.org/ns/credentials/v2".to_string()]
    );
    assert!(cred.type_.contains(&"BitstringStatusListCredential".to_string()));
    assert_eq!(cred.issuer.id, "did:web:gauth.example.com");
    assert_eq!(cred.credential_subject.status_purpose, "revocation");
    assert!(!cred.credential_subject.encoded_list.is_empty());
}

#[test]
fn ct_sl_006_check_revocation() {
    let mut sl = BitstringStatusList::new(1024, 300);
    sl.set_status(5, true, "expired-key").unwrap();

    let result = sl.check_revocation(5).unwrap();
    assert!(result.revoked);
    assert_eq!(result.reason, "expired-key");
    assert_eq!(result.index, 5);

    let result2 = sl.check_revocation(6).unwrap();
    assert!(!result2.revoked);
}

#[test]
fn ct_sl_007_out_of_range_returns_error() {
    let sl = BitstringStatusList::new(1024, 300);
    assert!(sl.get_status(9999).is_err());
    assert!(sl.check_revocation(9999).is_err());
}

#[test]
fn ct_storage_001_in_memory_save_and_find() {
    let mut repo = InMemoryMandateRepository::new();
    let mandate = make_test_mandate();
    repo.save(&mandate).unwrap();

    let found = repo.find_by_id("test-mandate-001").unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().mandate_id, "test-mandate-001");
}

#[test]
fn ct_storage_002_find_by_subject() {
    let mut repo = InMemoryMandateRepository::new();
    let mandate = make_test_mandate();
    repo.save(&mandate).unwrap();

    let results = repo.find_by_subject("agent-1").unwrap();
    assert_eq!(results.len(), 1);

    let results = repo.find_by_subject("agent-2").unwrap();
    assert!(results.is_empty());
}

#[test]
fn ct_storage_003_find_by_customer() {
    let mut repo = InMemoryMandateRepository::new();
    let mandate = make_test_mandate();
    repo.save(&mandate).unwrap();

    let results = repo.find_by_customer("cust-1").unwrap();
    assert_eq!(results.len(), 1);
}

#[test]
fn ct_storage_004_find_active_by_subject() {
    let mut repo = InMemoryMandateRepository::new();
    let mut m1 = make_test_mandate();
    m1.mandate_id = "m1".to_string();
    m1.status = MandateStatus::Active;
    repo.save(&m1).unwrap();

    let mut m2 = make_test_mandate();
    m2.mandate_id = "m2".to_string();
    m2.status = MandateStatus::Revoked;
    repo.save(&m2).unwrap();

    let active = repo.find_active_by_subject("agent-1").unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].mandate_id, "m1");
}

#[test]
fn ct_storage_005_delete() {
    let mut repo = InMemoryMandateRepository::new();
    let mandate = make_test_mandate();
    repo.save(&mandate).unwrap();
    assert_eq!(repo.count(), 1);

    let deleted = repo.delete("test-mandate-001").unwrap();
    assert!(deleted);
    assert_eq!(repo.count(), 0);

    let deleted2 = repo.delete("nonexistent").unwrap();
    assert!(!deleted2);
}

#[test]
fn ct_storage_006_list_all() {
    let mut repo = InMemoryMandateRepository::new();
    for i in 0..3 {
        let mut m = make_test_mandate();
        m.mandate_id = format!("m-{i}");
        repo.save(&m).unwrap();
    }
    let all = repo.list_all().unwrap();
    assert_eq!(all.len(), 3);
}

#[test]
fn ct_storage_007_append_audit() {
    let mut repo = InMemoryMandateRepository::new();
    let mandate = make_test_mandate();
    repo.save(&mandate).unwrap();

    let entry = MandateAuditEntry {
        operation: MandateOperation::Activate,
        performed_by: "admin".to_string(),
        timestamp: chrono::Utc::now(),
        mandate_id: "test-mandate-001".to_string(),
        reason: None,
        details: None,
    };
    repo.append_audit("test-mandate-001", &entry).unwrap();

    let found = repo.find_by_id("test-mandate-001").unwrap().unwrap();
    assert_eq!(found.audit_trail.len(), 1);
    assert_eq!(found.audit_trail[0].operation, MandateOperation::Activate);
}

#[test]
fn ct_profile_001_ceiling_table_has_all_profiles() {
    let table = ceiling_table();
    assert!(table.contains_key(&GovernanceProfile::Minimal));
    assert!(table.contains_key(&GovernanceProfile::Standard));
    assert!(table.contains_key(&GovernanceProfile::Strict));
    assert!(table.contains_key(&GovernanceProfile::Enterprise));
    assert!(table.contains_key(&GovernanceProfile::Behoerde));
}

#[test]
fn ct_profile_002_ceiling_hierarchy() {
    let minimal = get_ceiling(&GovernanceProfile::Minimal).unwrap();
    let standard = get_ceiling(&GovernanceProfile::Standard).unwrap();
    let strict = get_ceiling(&GovernanceProfile::Strict).unwrap();
    let enterprise = get_ceiling(&GovernanceProfile::Enterprise).unwrap();
    let behoerde = get_ceiling(&GovernanceProfile::Behoerde).unwrap();

    assert!(minimal.max_budget_cents < standard.max_budget_cents);
    assert!(standard.max_budget_cents < strict.max_budget_cents);
    assert!(strict.max_budget_cents < enterprise.max_budget_cents);
    assert!(enterprise.max_budget_cents < behoerde.max_budget_cents);
}

#[test]
fn ct_profile_003_minimal_no_delegation() {
    let minimal = get_ceiling(&GovernanceProfile::Minimal).unwrap();
    assert!(!minimal.allows_delegation);
    assert_eq!(minimal.max_delegation_depth, 0);
}

#[test]
fn ct_profile_004_strict_requires_approval() {
    let strict = get_ceiling(&GovernanceProfile::Strict).unwrap();
    assert!(strict.requires_approval);
    assert_eq!(strict.shell_mode, "allowlist");
}

#[test]
fn ct_profile_005_validate_within_ceiling() {
    let violations = validate_against_ceiling(
        &GovernanceProfile::Standard,
        Some(1000),
        Some(3600),
        Some(1),
    );
    assert!(violations.is_empty());
}

#[test]
fn ct_profile_006_validate_budget_exceeds_ceiling() {
    let violations = validate_against_ceiling(
        &GovernanceProfile::Minimal,
        Some(999999),
        None,
        None,
    );
    assert!(!violations.is_empty());
    assert_eq!(violations[0].field, "budget_cents");
}

#[test]
fn ct_profile_007_validate_ttl_exceeds_ceiling() {
    let violations = validate_against_ceiling(
        &GovernanceProfile::Minimal,
        None,
        Some(999999),
        None,
    );
    assert!(!violations.is_empty());
    assert_eq!(violations[0].field, "ttl_seconds");
}

#[test]
fn ct_profile_008_validate_delegation_exceeds_ceiling() {
    let violations = validate_against_ceiling(
        &GovernanceProfile::Minimal,
        None,
        None,
        Some(5),
    );
    assert!(!violations.is_empty());
    assert_eq!(violations[0].field, "delegation_depth");
}

#[test]
fn ct_profile_009_list_profiles() {
    let profiles = list_profiles();
    assert_eq!(profiles.len(), 5);
}

#[test]
fn ct_profile_010_profile_info() {
    let info = get_profile_info(&GovernanceProfile::Enterprise);
    assert!(!info.description.is_empty());
    assert!(info.ceiling.allows_financial_verbs);
}

#[test]
fn ct_openid_001_issuer_create_offer() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let mut issuer = OpenID4VCIssuer::new(
        "https://gauth.gimel.foundation",
        signing_key,
        "did:web:gauth.gimel.foundation#key-1",
        300,
    );

    let offer = issuer.create_credential_offer("mandate-001");
    assert_eq!(
        offer.credential_configuration_ids,
        vec!["GAuthPoACredential"]
    );
    assert!(offer
        .grants
        .pre_authorized_code
        .pre_authorized_code
        .starts_with("pre_auth_"));
}

#[test]
fn ct_openid_002_token_exchange() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let mut issuer = OpenID4VCIssuer::new(
        "https://gauth.gimel.foundation",
        signing_key,
        "did:web:gauth.gimel.foundation#key-1",
        300,
    );

    let offer = issuer.create_credential_offer("mandate-001");
    let code = &offer.grants.pre_authorized_code.pre_authorized_code;
    let token = issuer.exchange_token(code).unwrap();
    assert!(token.access_token.starts_with("at_"));
    assert_eq!(token.token_type, "Bearer");
    assert!(token.c_nonce.starts_with("c_nonce_"));
}

#[test]
fn ct_openid_003_token_exchange_invalid_code() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let mut issuer = OpenID4VCIssuer::new(
        "https://gauth.gimel.foundation",
        signing_key,
        "did:web:gauth.gimel.foundation#key-1",
        300,
    );
    assert!(issuer.exchange_token("invalid-code").is_none());
}

#[test]
fn ct_openid_004_full_issuance_flow() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let mut issuer = OpenID4VCIssuer::new(
        "https://gauth.gimel.foundation",
        signing_key,
        "did:web:gauth.gimel.foundation#key-1",
        300,
    );

    let offer = issuer.create_credential_offer("mandate-001");
    let code = &offer.grants.pre_authorized_code.pre_authorized_code;
    let token_resp = issuer.exchange_token(code).unwrap();

    let mandate = make_test_mandate();
    let cred_resp = issuer
        .issue_credential(&token_resp.access_token, &mandate, &token_resp.c_nonce)
        .unwrap();

    assert_eq!(cred_resp.format, "ldp_vc");
    assert!(cred_resp.credential.get("proof").is_some());
    assert!(cred_resp.c_nonce.is_some());
}

#[test]
fn ct_openid_005_issuer_revoke_credential() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let mut issuer = OpenID4VCIssuer::new(
        "https://gauth.gimel.foundation",
        signing_key,
        "did:web:gauth.gimel.foundation#key-1",
        300,
    );

    issuer.revoke_credential(0, "key-compromise").unwrap();
    let sl_cred = issuer.status_list_credential();
    assert!(sl_cred.get("credentialSubject").is_some());
}

#[test]
fn ct_openid_006_issuer_did_derivation() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let issuer = OpenID4VCIssuer::new(
        "https://gauth.gimel.foundation",
        signing_key,
        "",
        300,
    );
    assert_eq!(issuer.issuer_did(), "did:web:gauth.gimel.foundation");
}

#[test]
fn ct_openid_007_verifier_create_presentation_request() {
    let mut verifier = OpenID4VPVerifier::new(
        "did:web:verifier.example.com",
        "https://verifier.example.com/callback",
        300,
    );

    let req = verifier.create_presentation_request(&["file.read", "file.create"]);
    assert!(!req.nonce.is_empty());
    assert_eq!(req.client_id, "did:web:verifier.example.com");
    assert_eq!(req.presentation_definition.input_descriptors.len(), 1);
    let fields = &req.presentation_definition.input_descriptors[0].constraints.fields;
    assert_eq!(fields.len(), 2);
}

#[test]
fn ct_openid_008_full_issuance_and_verification_flow() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();

    let mut issuer = OpenID4VCIssuer::new(
        "https://gauth.gimel.foundation",
        signing_key,
        "did:web:gauth.gimel.foundation#key-1",
        300,
    );

    let offer = issuer.create_credential_offer("mandate-001");
    let code = &offer.grants.pre_authorized_code.pre_authorized_code;
    let token_resp = issuer.exchange_token(code).unwrap();

    let mandate = make_test_mandate();
    let cred_resp = issuer
        .issue_credential(&token_resp.access_token, &mandate, &token_resp.c_nonce)
        .unwrap();

    let mut verifier = OpenID4VPVerifier::new(
        "did:web:verifier.example.com",
        "https://verifier.example.com/callback",
        300,
    );
    verifier.register_trusted_issuer("did:web:gauth.gimel.foundation", verifying_key);

    let pres_req = verifier.create_presentation_request(&["file.read"]);

    let vp = serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": "did:key:agent-1",
        "verifiableCredential": [cred_resp.credential],
    });

    let result = verifier.verify_presentation(&vp, &pres_req.nonce);
    assert!(result.verified);
    assert!(result.nonce_valid);
    assert!(result.proof_valid);
    assert_eq!(result.holder_did, "did:key:agent-1");
}

#[test]
fn ct_openid_009_verification_fails_untrusted_issuer() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

    let mut issuer = OpenID4VCIssuer::new(
        "https://gauth.gimel.foundation",
        signing_key,
        "did:web:gauth.gimel.foundation#key-1",
        300,
    );

    let offer = issuer.create_credential_offer("mandate-001");
    let code = &offer.grants.pre_authorized_code.pre_authorized_code;
    let token_resp = issuer.exchange_token(code).unwrap();

    let mandate = make_test_mandate();
    let cred_resp = issuer
        .issue_credential(&token_resp.access_token, &mandate, &token_resp.c_nonce)
        .unwrap();

    let mut verifier = OpenID4VPVerifier::new(
        "did:web:verifier.example.com",
        "https://verifier.example.com/callback",
        300,
    );

    let pres_req = verifier.create_presentation_request(&["file.read"]);

    let vp = serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": "did:key:agent-1",
        "verifiableCredential": [cred_resp.credential],
    });

    let result = verifier.verify_presentation(&vp, &pres_req.nonce);
    assert!(!result.verified);
    assert!(!result.proof_valid);
    assert!(result.errors.iter().any(|e| e.contains("Untrusted issuer")));
}

#[test]
fn ct_openid_010_revoked_credential_fails_verification() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();

    let mut issuer = OpenID4VCIssuer::new(
        "https://gauth.gimel.foundation",
        signing_key,
        "did:web:gauth.gimel.foundation#key-1",
        300,
    );

    let offer = issuer.create_credential_offer("mandate-001");
    let code = &offer.grants.pre_authorized_code.pre_authorized_code;
    let token_resp = issuer.exchange_token(code).unwrap();

    let mandate = make_test_mandate();
    let cred_resp = issuer
        .issue_credential(&token_resp.access_token, &mandate, &token_resp.c_nonce)
        .unwrap();

    issuer.revoke_credential(0, "key-compromise").unwrap();

    let mut revoked_sl = BitstringStatusList::with_default_size();
    revoked_sl.set_status(0, true, "key-compromise").unwrap();

    let mut verifier = OpenID4VPVerifier::new(
        "did:web:verifier.example.com",
        "https://verifier.example.com/callback",
        300,
    );
    verifier.register_trusted_issuer("did:web:gauth.gimel.foundation", verifying_key);
    verifier.set_status_list(revoked_sl);

    let pres_req = verifier.create_presentation_request(&["file.read"]);

    let vp = serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": "did:key:agent-1",
        "verifiableCredential": [cred_resp.credential],
    });

    let result = verifier.verify_presentation(&vp, &pres_req.nonce);
    assert!(!result.verified);
    assert!(result.status_check.as_ref().unwrap().revoked);
}

#[test]
fn ct_openid_011_trusted_issuer_registry() {
    let mut registry = TrustedIssuerRegistry::new();
    let key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key();

    registry.register("did:web:example.com", key);
    assert!(registry.resolve("did:web:example.com").is_some());
    assert!(registry.resolve("did:web:example.com#key-1").is_some());
    assert!(registry.resolve("did:web:unknown.com").is_none());
}

#[test]
fn ct_openid_012_verify_with_required_actions_pass() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();

    let mut issuer = OpenID4VCIssuer::new(
        "https://gauth.gimel.foundation",
        signing_key,
        "did:web:gauth.gimel.foundation#key-1",
        300,
    );

    let offer = issuer.create_credential_offer("mandate-001");
    let code = &offer.grants.pre_authorized_code.pre_authorized_code;
    let token_resp = issuer.exchange_token(code).unwrap();

    let mandate = make_test_mandate();
    let cred_resp = issuer
        .issue_credential(&token_resp.access_token, &mandate, &token_resp.c_nonce)
        .unwrap();

    let mut verifier = OpenID4VPVerifier::new(
        "did:web:verifier.example.com",
        "https://verifier.example.com/callback",
        300,
    );
    verifier.register_trusted_issuer("did:web:gauth.gimel.foundation", verifying_key);

    let pres_req = verifier.create_presentation_request(&["file.read"]);

    let vp = serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": "did:key:agent-1",
        "verifiableCredential": [cred_resp.credential],
    });

    let result =
        verifier.verify_presentation_with_constraints(&vp, &pres_req.nonce, &["file.read"]);
    assert!(result.verified);
}

#[test]
fn ct_openid_013_verify_with_required_actions_fail() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();

    let mut issuer = OpenID4VCIssuer::new(
        "https://gauth.gimel.foundation",
        signing_key,
        "did:web:gauth.gimel.foundation#key-1",
        300,
    );

    let offer = issuer.create_credential_offer("mandate-001");
    let code = &offer.grants.pre_authorized_code.pre_authorized_code;
    let token_resp = issuer.exchange_token(code).unwrap();

    let mandate = make_test_mandate();
    let cred_resp = issuer
        .issue_credential(&token_resp.access_token, &mandate, &token_resp.c_nonce)
        .unwrap();

    let mut verifier = OpenID4VPVerifier::new(
        "did:web:verifier.example.com",
        "https://verifier.example.com/callback",
        300,
    );
    verifier.register_trusted_issuer("did:web:gauth.gimel.foundation", verifying_key);

    let pres_req = verifier.create_presentation_request(&["admin.delete"]);

    let vp = serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": "did:key:agent-1",
        "verifiableCredential": [cred_resp.credential],
    });

    let result =
        verifier.verify_presentation_with_constraints(&vp, &pres_req.nonce, &["admin.delete"]);
    assert!(!result.verified);
    assert!(result
        .errors
        .iter()
        .any(|e| e.contains("admin.delete") && e.contains("not in credential")));
}

#[test]
fn ct_openid_014_vp_challenge_binding() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();

    let mut issuer = OpenID4VCIssuer::new(
        "https://gauth.gimel.foundation",
        signing_key,
        "did:web:gauth.gimel.foundation#key-1",
        300,
    );

    let offer = issuer.create_credential_offer("mandate-001");
    let code = &offer.grants.pre_authorized_code.pre_authorized_code;
    let token_resp = issuer.exchange_token(code).unwrap();

    let mandate = make_test_mandate();
    let cred_resp = issuer
        .issue_credential(&token_resp.access_token, &mandate, &token_resp.c_nonce)
        .unwrap();

    let mut verifier = OpenID4VPVerifier::new(
        "did:web:verifier.example.com",
        "https://verifier.example.com/callback",
        300,
    );
    verifier.register_trusted_issuer("did:web:gauth.gimel.foundation", verifying_key);

    let pres_req = verifier.create_presentation_request(&["file.read"]);

    let vp = serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "holder": "did:key:agent-1",
        "verifiableCredential": [cred_resp.credential],
        "proof": {
            "type": "DataIntegrityProof",
            "challenge": "wrong-nonce"
        }
    });

    let result = verifier.verify_presentation(&vp, &pres_req.nonce);
    assert!(!result.verified);
    assert!(result
        .errors
        .iter()
        .any(|e| e.contains("challenge does not match")));
}

use base64::Engine;
