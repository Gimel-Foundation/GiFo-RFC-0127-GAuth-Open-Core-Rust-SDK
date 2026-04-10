# Additional Terms — GAuth Open Core SDK

**Effective Date:** 2025-01-01  
**Issuer:** Gimel Foundation gGmbH i.G. / Gimel Technologies GmbH

This document supplements the Mozilla Public License 2.0 (MPL-2.0) under which the
GAuth Open Core SDK (`gauth-rs`) is licensed. These Additional Terms apply per §15.6
of the SDK Implementation Guide v1.2.

---

## 1. Exclusions Addendum

The following functionalities are **EXCLUDED** from the MPL-2.0 license grant
and are subject to separate proprietary licensing:

### 1.1 AI-Enabled Governance

Any AI technology that controls, tracks, manages, or assures authorization compliance,
deployment lifecycles, policy evaluation quality, or outcome governance. This includes
but is not limited to:

- AI-based policy decision points
- AI-driven enforcement engines
- Machine-learning-based risk scoring
- AI-powered compliance monitoring

**Note:** Rule-based (non-AI) implementations of adapter interfaces (e.g.,
`RuleBasedGovernance`, `RuleBasedPolicyDecision`) are covered by MPL-2.0.
AI-enabled implementations of the same interfaces fall under the Exclusions.

### 1.2 Web3 Integration

Any integration with blockchain technology, web3 tokens (fungible or non-fungible),
smart contracts, decentralized identifiers (DIDs) on public blockchains, or tokenized
credential systems for extended tokens.

**Note:** The `Web3IdentityAdapter` trait definition is part of the open-core SDK.
Implementations that connect to live blockchain networks require a proprietary license.

### 1.3 DNA-Based Identities and PQC

Any use of genetic-data-based identities, DNA-derived cryptographic seeds, post-quantum
cryptography (PQC) key material associated with biological identity, and any AI system
that tracks, evaluates, or assures DNA identity quality or related risk factors.

**Note:** The `DnaIdentityAdapter` trait definition is part of the open-core SDK.
Implementations that process real biometric/genetic data require a proprietary license.

---

## 2. Adapter Type Classification and Licensing

Per the SDK Implementation Guide v1.2 §4, adapters are classified by type:

| Type | Category | License Scope |
|------|----------|---------------|
| **A** | Open Core (standard) | MPL-2.0 — trait + implementation included |
| **B** | Open Core (extensible) | MPL-2.0 — trait + no-op/rule-based impl included |
| **C** | Proprietary / Gimel Services | Trait definition: MPL-2.0; Implementation: Proprietary |
| **D** | Future / Reserved | Not yet available |

### Type C Adapter Constraints

- Require `@gimel/` namespace prefix in adapter manifests
- Require `gimel-foundation` as manifest issuer
- Subject to tariff gating (Minimum tier: M for ai_governance/web3_identity; L for dna_identity)
- Require per-service Terms of Service acceptance (Tier-2 ToS)
- Require Ed25519 attestation satisfaction before activation

---

## 3. Tariff Gating

Access to certain adapter slots is gated by tariff tier:

| Tariff Code | Name | Type C Access |
|-------------|------|---------------|
| **O** | Open Core | No Type C adapters |
| **S** | Small | No Type C adapters |
| **M** | Medium | ai_governance, web3_identity |
| **L** | Large | ai_governance, web3_identity, dna_identity |

Tariff tier is determined by the deployment license and is enforced at adapter
registration time via `check_tariff_gate()`.

---

## 4. Two-Tier Terms of Service Model

### Tier 1 — Platform ToS

Acceptance of Gimel Foundation Platform Terms of Service transitions the license
state from `mpl_2_0` to `gimel_tos`. This is required for any Gimel-hosted
service integration.

### Tier 2 — Per-Service ToS

Each Type C adapter slot has independent Terms of Service that must be accepted
before the adapter can be activated. Service ToS states:

- `not_required` — Open/standard adapters (Type A/B)
- `pending` — ToS acceptance required but not yet given
- `accepted` — ToS accepted, adapter may proceed to activation
- `rejected` — ToS rejected, adapter cannot be activated

---

## 5. Contact

For licensing inquiries regarding Exclusions or proprietary adapter implementations:

**Gimel Foundation gGmbH i.G.**  
Email: info@gimelid.com  
Website: https://gimelid.com
