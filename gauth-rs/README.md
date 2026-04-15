# gauth-rs

**GAuth Open Core Rust SDK — Version 0.91 (Public Preview)**

AI authorization framework implementing the GiFo GAuth protocol.

[![License: MPL-2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Status: Public Preview](https://img.shields.io/badge/Status-Public%20Preview-blue.svg)]()

## Overview

`gauth-rs` implements the GiFo GAuth authorization protocol as specified in RFCs 0110-0118 and aligned with the SDK Implementation Guide. It enables AI systems — digital agents, agentic AI, humanoid robots — to carry, present, and enforce Power of Attorney (PoA) credentials under a structured governance framework.

This SDK is **free to use** under the Mozilla Public License 2.0. No Gimel account, subscription, license key, or billing integration is required. There is no telemetry, no phone-home, and no usage tracking. Download from GitHub and run independently on your own infrastructure.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    gauth-rs SDK Version 0.91                  │
│                        (Public Preview)                       │
├──────────────┬──────────┬────────────┬──────────────────────┤
│   types/     │  token/  │    pep/    │    management/       │
│  PoA schema  │Extended  │ 16-check   │  Mandate lifecycle   │
│  RBPC model  │  JWT     │ evaluation │  License state       │
│  Capability  │ RS256/   │ pipeline   │  machine             │
│  Delegation  │  ES256   │ fail-close │  Two-tier ToS        │
├──────────────┴──────────┴────────────┴──────────────────────┤
│                   adapters/ (7-Slot Connector Model)         │
│  ┌────────┬────────────┬─────────┬────────┐                 │
│  │ Slot 1 │  Slot 2    │ Slot 3  │ Slot 4 │ Type A/B        │
│  │  PDP   │  OAuth     │Foundry  │ Wallet │                 │
│  │(Int/A) │  Engine(A) │  (B)    │  (B)   │                 │
│  ├────────┼────────────┼─────────┴────────┘                 │
│  │ Slot 5 │  Slot 6    │ Slot 7           │ Type C          │
│  │  AI    │  Web3      │ DNA Identity     │ (Proprietary)   │
│  │  Gov   │  Identity  │ (L+O only)       │                 │
│  └────────┴────────────┴──────────────────┘                 │
│  Ed25519 signed manifests · Tariff gating (O/M+O/L+O)       │
├─────────────────────────────────────────────────────────────┤
│                       crypto/                                │
│  Canonical JSON · SHA-256 scope checksum · Ed25519           │
└─────────────────────────────────────────────────────────────┘
```

## Modules

| Module | Description |
|--------|-------------|
| `types` | PoA credential schema, governance profiles (Minimal/Standard/Strict/Enterprise/Behorde), three-layer capability model (core verbs, platform permissions, budget/session limits), delegation chain, Role-Based Power Control (RBPC) |
| `token` | Extended Token JWT encoding/decoding with RS256/ES256 (HS256 prohibited), schema version `0116.2.2`, scope checksum verification |
| `pep` | Policy Enforcement Point — 16-check evaluation pipeline (CHK-01 through CHK-16) with fail-closed default, stateless fail-fast / stateful collect-all modes, batch enforcement, audit records |
| `management` | Mandate lifecycle management (DRAFT → ACTIVE → SUSPENDED/EXPIRED/REVOKED/BUDGET_EXCEEDED/SUPERSEDED), license state machine (mpl_2_0 → gimel_tos), two-tier ToS model |
| `adapters` | 7-slot connector model with Type A/B/C/D classification, Ed25519 signed manifests, tariff gating (O/M+O/L+O), adapter lifecycle (null → pending → active → error) |
| `crypto` | Canonical JSON serialization, SHA-256 scope checksum, Ed25519 signature helpers |
| `error` | Comprehensive error hierarchy with typed variants for each failure mode |
| `vc` | W3C Verifiable Credentials v2.0 — DID resolution (did:web, did:key), SD-JWT selective disclosure, Bitstring Status List v2.0, PoA→VC serializer with Data Integrity Proofs (eddsa-rdfc-2022), OpenID4VCI/VP credential exchange |
| `storage` | Mandate repository trait abstraction with in-memory implementation. Plug-in interface for persistent backends (SQL, KV stores) |
| `profiles` | Governance profile ceiling table — budget, TTL, delegation depth limits. Ceiling validation for mandate creation |

## 7-Slot Connector Model

| Slot | Name | Type | Tariff | Description |
|------|------|------|--------|-------------|
| 1 | `pdp` | Internal | O (all tiers) | Policy Decision Point (SDK-embedded) |
| 2 | `oauth_engine` | A | O (all tiers) | OAuth 2.0 / JWT token engine |
| 3 | `foundry` | B | O (all tiers) | Agent foundry / sandbox management |
| 4 | `wallet` | B | O (all tiers) | Credential wallet / VC storage |
| 5 | `ai_governance` | C | M+O | AI-enabled governance (Exclusion 1) |
| 6 | `web3_identity` | C | M+O | Web3/DID identity (Exclusion 2) |
| 7 | `dna_identity` | C | L+O | DNA-based identity (Exclusion 3) |

## Adapter Type Classification

| Type | Category | Registration | Attestation | License |
|------|----------|-------------|-------------|---------|
| A | Open Core | Ed25519 signed manifest | Not required | MPL-2.0 |
| B | Open Core | Ed25519 signed manifest | Not required | MPL-2.0 |
| C | Proprietary | `@gimel/` namespace, `gimel-foundation` issuer | Required (Ed25519) | Proprietary |
| D | Reserved | Future use | TBD | TBD |

## Tariff Gating

| Tariff | Name | Type C Access | Description |
|--------|------|---------------|-------------|
| **O** | Open Core | None | Free SDK, self-hosted, no Gimel account needed |
| **M+O** | Hybrid Service | ai_governance, web3_identity | SDK + proprietary managed services |
| **L+O** | Hybrid Enterprise | ai_governance, web3_identity, dna_identity | SDK + enterprise managed services |

## Governance Profiles (RBPC)

GAuth uses **Role-Based Power Control (RBPC)** — a governance model that binds AI agent capabilities to structured power profiles rather than traditional access roles.

| Profile | Max Budget | Auto-Deploy | Deploy Targets | Min Approval | Delegation Depth |
|---------|-----------|-------------|----------------|--------------|-----------------|
| Minimal | 10 EUR | Yes | dev | Autonomous | 0 |
| Standard | 100 EUR | Yes | dev, staging | Autonomous | 1 |
| Strict | 1,000 EUR | No | dev, staging | Supervised | 2 |
| Enterprise | 10,000 EUR | No | dev, staging, prod | Supervised | 3 |
| Behorde | Unlimited | No | dev, staging, prod | Four-Eyes | 2 |

## PEP Evaluation Pipeline (16 Checks)

| Check | Name | Description |
|-------|------|-------------|
| CHK-01 | Credential Integrity | Schema version and structural validation |
| CHK-02 | Temporal & Status | Agent identity match, mandate status (active/revoked/expired/superseded) |
| CHK-03 | Governance Profile | Profile ceiling enforcement, approval mode minimum |
| CHK-04 | Phase | Plan/Build/Run phase verb restrictions |
| CHK-05 | Sector | Industry sector constraint |
| CHK-06 | Region | Geographic region constraint (EU member expansion) |
| CHK-07 | Path | File/resource path allow/deny with glob matching |
| CHK-08 | Verb Permission | Core verb allow/deny lookup |
| CHK-09 | Verb Constraints | Path patterns, command allow/deny lists, file size limits |
| CHK-10 | Platform Permissions | Deployment targets, database access, secrets, shell mode |
| CHK-11 | Transaction Type | Transaction type allow list and matrix |
| CHK-12 | Decision Type | Decision type allow list |
| CHK-13 | Budget | Budget remaining vs. action cost |
| CHK-14 | Session Limits | Tool call count, lines committed |
| CHK-15 | Approval | Autonomous/Supervised/Four-Eyes mode enforcement |
| CHK-16 | Delegation Chain | Depth limit per governance profile |

## Licensing Model

This SDK uses a **three-layer coexistence** licensing model:

| Layer | License | Scope | Revocable? |
|-------|---------|-------|------------|
| SDK source code | MPL-2.0 | File-level copyleft on SDK files; your own files in separate modules remain under your chosen license | No — irrevocable |
| Proprietary Gimel services | Gimel Technologies ToS | Governs access to Gimel-hosted services (AaaS, managed infrastructure, Type C adapters) | Yes — service relationship |
| Open specifications (RFCs) | Apache 2.0 | Interoperability protocols (RFC 0116, 0117, 0118) | No — irrevocable |

**In practice:** You may run the SDK in pure Open Core mode (MPL-2.0 only, self-hosted, no Gimel services) indefinitely. If you choose to use proprietary Gimel services, the Gimel Technologies ToS applies in addition to MPL-2.0 — not as a replacement. Your SDK code and modifications to SDK files remain MPL-2.0 regardless.

### License State Machine

```
mpl_2_0  ──(accept Platform ToS)──▶  gimel_tos
```

Per-service ToS (Tier-2) tracks independently for each Type C slot:
`not_required` → `pending` → `accepted` / `rejected`

## Exclusions Notice

The following features are **EXCLUDED** from this open-source SDK and from the MPL-2.0 license. They are subject to separate proprietary licensing by Gimel Foundation gGmbH i.G. / Gimel Technologies GmbH:

1. **AI-enabled Governance** — AI that controls, tracks, or assures authorization compliance, deployment lifecycles, or outcome quality.
2. **Web3 Integration** — Blockchain technology, web3 tokens, and smart contracts for extended tokens.
3. **DNA-based Identities and PQC associated** — Genetic-data-based identities, post-quantum cryptography seeds derived from DNA, and AI that tracks DNA identity quality or related risks.

Rule-based (non-AI) implementations of adapter interfaces are covered by MPL-2.0. AI-enabled implementations fall under the Exclusions. See [ADDITIONAL-TERMS.md](ADDITIONAL-TERMS.md) for full details.

## Quick Start

```rust
use gauth_rs::types::*;
use gauth_rs::pep::*;
use gauth_rs::management::*;
use std::collections::HashMap;

// 1. Create a mandate
let mut manager = MandateManager::new();

let mut core_verbs = HashMap::new();
core_verbs.insert("file.read".to_string(), ToolPolicy {
    allowed: true,
    cost_cents_base: None,
    constraints: None,
});

let response = manager.create_mandate(MandateCreationRequest {
    parties: Parties {
        issuer: "platform:replit".into(),
        subject: "agent:replit-agent-001".into(),
        customer_id: "cust_abc123".into(),
        project_id: "proj_xyz789".into(),
        issued_by: None,
        approval_chain: None,
    },
    scope: Scope {
        governance_profile: GovernanceProfile::Standard,
        phase: Phase::Build,
        core_verbs,
        active_modules: None,
        allowed_paths: Some(vec!["src/**".into()]),
        denied_paths: Some(vec!["src/secrets/**".into()]),
        allowed_sectors: None,
        allowed_regions: Some(vec!["EU".into()]),
        allowed_transactions: None,
        transaction_matrix: None,
        allowed_decisions: None,
        platform_permissions: None,
    },
    requirements: Requirements {
        approval_mode: ApprovalMode::Autonomous,
        budget: Some(Budget {
            total_cents: Some(5000),
            remaining_cents: Some(5000),
        }),
        session_limits: None,
        ttl_seconds: Some(3600),
    },
}).unwrap();

// 2. Enforce an action
let poa = manager.to_poa_credential(&response.mandate_id).unwrap();
let engine = PepEngine::default();

let decision = engine.enforce_action(
    &EnforcementRequest {
        request_id: "req_001".into(),
        timestamp: chrono::Utc::now(),
        action: ActionDescriptor {
            verb: "file.read".into(),
            resource: "src/main.rs".into(),
            resource_type: None,
            parameters: None,
            sector: None,
            region: Some("DE".into()),
            transaction_type: None,
            decision_type: None,
        },
        agent: AgentIdentity {
            agent_id: "agent:replit-agent-001".into(),
            service: None,
            session_id: None,
            did: None,
        },
        credential: CredentialReference {
            format: CredentialFormat::Jwt,
            token: None,
            mandate_id: Some(response.mandate_id.clone()),
            poa_snapshot: None,
        },
        context: None,
    },
    &poa,
);

assert_eq!(decision.decision, Decision::Permit);
```

## Verifiable Credentials Module (`vc`)

The `vc` module implements the W3C VC Data Model v2.0 translation layer specified in Gap Spec G-07:

| Sub-module | Description |
|-----------|-------------|
| `vc::did` | DID resolution for `did:web` and `did:key` methods. Produces W3C DID Documents with verificationMethod, authentication, and assertionMethod. Includes ephemeral key generation via `create_did_key()`. |
| `vc::sd_jwt` | SD-JWT (Selective Disclosure JWT) per draft-ietf-oauth-selective-disclosure-jwt. Creates compact SD-JWTs with redacted claims and SHA-256 disclosure digests. Verification reconstructs disclosed claims. |
| `vc::status_list` | Bitstring Status List v2.0 (W3C) for credential revocation. Zlib-compressed bitstring with base64url encoding. Supports revocation reasons and `to_status_list_credential()` for W3C VC format output. |
| `vc::serializer` | PoA mandate → W3C VC v2.0 serialization. Maps mandate fields to credentialSubject, generates CredentialStatus entries, and produces JWT payloads via `vc_to_jwt_payload()`. Data Integrity Proofs use `eddsa-rdfc-2022` cryptosuite with Ed25519 signing. |
| `vc::openid` | OpenID4VCI issuer (credential offer → token exchange → issuance) and OpenID4VP verifier (presentation request → VP submission → verification). Includes nonce management, trusted issuer registry, and status list integration. |

### Example: Issue and Verify a VC

```rust
use gauth_rs::vc::serializer::poa_to_vc;
use gauth_rs::vc::openid::{OpenID4VCIssuer, OpenID4VPVerifier};

// 1. Serialize mandate to W3C VC
let vc = poa_to_vc(&mandate, "did:web:example.com", "", 0);

// 2. Issue via OpenID4VCI
let mut issuer = OpenID4VCIssuer::new(
    "https://gauth.example.com",
    signing_key,
    "did:web:gauth.example.com#key-1",
    300,
);
let offer = issuer.create_credential_offer("mandate-001");
let token = issuer.exchange_token(&offer.grants.pre_authorized_code.pre_authorized_code).unwrap();
let credential = issuer.issue_credential(&token.access_token, &mandate, &token.c_nonce).unwrap();

// 3. Verify via OpenID4VP
let mut verifier = OpenID4VPVerifier::new("did:web:verifier.com", "https://verifier.com/cb", 300);
verifier.register_trusted_issuer("did:web:gauth.example.com", verifying_key);
let result = verifier.verify_presentation(&vp, &nonce);
assert!(result.verified);
```

## Storage Abstraction

The `storage` module provides a trait-based repository pattern for mandate persistence:

```rust
use gauth_rs::storage::{MandateRepository, InMemoryMandateRepository};

let mut repo = InMemoryMandateRepository::new();
repo.save(&mandate).unwrap();
let found = repo.find_by_id("mandate-001").unwrap();
let active = repo.find_active_by_subject("agent-1").unwrap();
```

Implement the `MandateRepository` trait to add your own backend (PostgreSQL, Redis, etc.).

## Profiles / Ceilings

The `profiles` module defines per-profile ceiling tables matching RFC 0115/0118 §9.2:

```rust
use gauth_rs::profiles::{get_ceiling, validate_against_ceiling};
use gauth_rs::types::GovernanceProfile;

let ceiling = get_ceiling(&GovernanceProfile::Standard).unwrap();
let violations = validate_against_ceiling(&GovernanceProfile::Standard, Some(99999), None, None);
// violations will flag budget exceeding Standard ceiling
```

## RFC References

- **RFC 0110** — GAuth Overview and Architecture
- **RFC 0111** — Power of Attorney Credential Schema
- **RFC 0115** — Three-Layer Capability Model
- **RFC 0116** — Extended Token Specification (Apache 2.0)
- **RFC 0117** — Policy Enforcement Point (PEP) Pipeline (Apache 2.0)
- **RFC 0118** — Management API and Adapter Architecture (Apache 2.0)
- **SDK Implementation Guide** — 7-Slot Connector Model, Tariff Gating, Adapter Classification

## Contact

Gimel Foundation gGmbH i.G.
Email: info@gimelid.com
Licensing: licensing@gimelid.com
Website: https://gimelid.com
