# gauth-rs

**GAuth Open Core Rust SDK** — AI authorization framework implementing the GiFo GAuth protocol.

[![License: MPL-2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

## Overview

`gauth-rs` implements the GiFo GAuth authorization protocol as specified in RFCs 0110-0118 and aligned with the SDK Implementation Guide v1.2. It enables AI systems — digital agents, agentic AI, humanoid robots — to carry, present, and enforce Power of Attorney (PoA) credentials under a structured governance framework.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       gauth-rs SDK                          │
├──────────────┬──────────┬────────────┬──────────────────────┤
│   types/     │  token/  │    pep/    │    management/       │
│  PoA schema  │Extended  │ 16-check   │  Mandate lifecycle   │
│  Governance  │  JWT     │ evaluation │  License state       │
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
│  │  Gov   │  Identity  │ (L-tier only)    │                 │
│  └────────┴────────────┴──────────────────┘                 │
│  Ed25519 signed manifests · Tariff gating (O/S/M/L)         │
├─────────────────────────────────────────────────────────────┤
│                       crypto/                                │
│  Canonical JSON · SHA-256 scope checksum · Ed25519           │
└─────────────────────────────────────────────────────────────┘
```

## Modules

| Module | Description |
|--------|-------------|
| `types` | PoA credential schema, governance profiles (Minimal/Standard/Strict/Enterprise/Behörde), three-layer capability model (core verbs, platform permissions, budget/session limits), delegation chain |
| `token` | Extended Token JWT encoding/decoding with RS256/ES256 (HS256 prohibited), schema version `0116.2.2`, scope checksum verification |
| `pep` | Policy Enforcement Point — 16-check evaluation pipeline (CHK-01 through CHK-16) with fail-closed default, batch enforcement, audit records |
| `management` | Mandate lifecycle management (DRAFT → ACTIVE → SUSPENDED/EXPIRED/REVOKED/BUDGET_EXCEEDED/SUPERSEDED), license state machine (mpl_2_0 → gimel_tos), two-tier ToS model |
| `adapters` | 7-slot connector model with Type A/B/C/D classification, Ed25519 signed manifests, tariff gating (O/S/M/L), adapter lifecycle (null → pending → active → error) |
| `crypto` | Canonical JSON serialization, SHA-256 scope checksum, Ed25519 signature helpers |
| `error` | Comprehensive error hierarchy with typed variants for each failure mode |

## 7-Slot Connector Model

Per SDK Implementation Guide v1.2 §4:

| Slot | Name | Type | Tariff | Description |
|------|------|------|--------|-------------|
| 1 | `pdp` | Internal | O+ | Policy Decision Point (SDK-embedded) |
| 2 | `oauth_engine` | A | O+ | OAuth 2.0 / JWT token engine |
| 3 | `foundry` | B | O+ | Agent foundry / sandbox management |
| 4 | `wallet` | B | O+ | Credential wallet / VC storage |
| 5 | `ai_governance` | C | M+ | AI-enabled governance (Exclusion 1) |
| 6 | `web3_identity` | C | M+ | Web3/DID identity (Exclusion 2) |
| 7 | `dna_identity` | C | L | DNA-based identity (Exclusion 3) |

## Adapter Type Classification

| Type | Category | Registration | Attestation | License |
|------|----------|-------------|-------------|---------|
| A | Open Core | Ed25519 signed manifest | Not required | MPL-2.0 |
| B | Open Core | Ed25519 signed manifest | Not required | MPL-2.0 |
| C | Proprietary | `@gimel/` namespace, `gimel-foundation` issuer | Required (Ed25519) | Proprietary |
| D | Reserved | Future use | TBD | TBD |

## Tariff Gating

| Tier | Name | Type C Access |
|------|------|---------------|
| O | Open Core | None |
| S | Small | None |
| M | Medium | ai_governance, web3_identity |
| L | Large | ai_governance, web3_identity, dna_identity |

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

## Governance Profiles

| Profile | Max Budget | Auto-Deploy | Deploy Targets | Min Approval | Delegation Depth |
|---------|-----------|-------------|----------------|--------------|-----------------|
| Minimal | 10 EUR | Yes | dev | Autonomous | 0 |
| Standard | 100 EUR | Yes | dev, staging | Autonomous | 1 |
| Strict | 1,000 EUR | No | dev, staging | Supervised | 2 |
| Enterprise | 10,000 EUR | No | dev, staging, prod | Supervised | 3 |
| Behörde | Unlimited | No | dev, staging, prod | Four-Eyes | 2 |

## License State Machine

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

## RFC References

- **RFC 0110** — GAuth Overview and Architecture
- **RFC 0111** — Power of Attorney Credential Schema
- **RFC 0115** — Three-Layer Capability Model
- **RFC 0116** — Extended Token Specification
- **RFC 0117** — Policy Enforcement Point (PEP) Pipeline
- **RFC 0118** — Management API and Adapter Architecture
- **SDK Implementation Guide v1.2** — 7-Slot Connector Model, Tariff Gating, Adapter Classification

## License

This project is licensed under the Mozilla Public License 2.0 — see the [LICENSE](LICENSE) file for details.

**Important:** The Exclusions described above (AI-enabled Governance, Web3 Integration, DNA-based Identities and PQC) are subject to separate proprietary licensing by Gimel Foundation gGmbH i.G. / Gimel Technologies GmbH. See [ADDITIONAL-TERMS.md](ADDITIONAL-TERMS.md).

## Contact

Gimel Foundation gGmbH i.G.  
Email: info@gimelid.com  
Website: https://gimelid.com
