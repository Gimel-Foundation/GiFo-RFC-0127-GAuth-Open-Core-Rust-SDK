# Additional Terms — GAuth Open Core SDK

**Effective Date:** 2025-01-01
**Issuer:** Gimel Foundation gGmbH i.G. / Gimel Technologies GmbH

This document supplements the Mozilla Public License 2.0 (MPL-2.0) under which the
GAuth Open Core SDK (`gauth-rs`) is licensed. These Additional Terms apply per §15.6
of the SDK Implementation Guide.

---

## 1. Three-Layer Licensing Model

This SDK uses a three-layer coexistence licensing model:

| Layer | License | Scope | Revocable? |
|-------|---------|-------|------------|
| SDK source code | MPL-2.0 | File-level copyleft on SDK files; your own files in separate modules remain under your chosen license | No — irrevocable |
| Proprietary Gimel services | Gimel Technologies ToS | Governs access to Gimel-hosted services (AaaS, managed infrastructure, Type C adapters) | Yes — service relationship |
| Open specifications (RFCs) | Apache 2.0 | Interoperability protocols (RFC 0116, 0117, 0118) | No — irrevocable |

**Coexistence rule:** You may run the SDK in pure Open Core mode (MPL-2.0 only,
self-hosted, no Gimel services) indefinitely. If you choose to use proprietary Gimel
services, the Gimel Technologies ToS applies **in addition to** MPL-2.0 — not as a
replacement. Your SDK code and modifications to SDK files remain MPL-2.0 regardless.

**Downgrade protection:** If a hybrid customer later drops the proprietary platform,
the ToS terminates but the MPL-2.0 license is **not** revoked. The customer keeps all
SDK code and modifications.

---

## 2. Exclusions Addendum

The following functionalities are **EXCLUDED** from the MPL-2.0 license grant
and are subject to separate proprietary licensing:

### 2.1 AI-Enabled Governance

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

### 2.2 Web3 Integration

Any integration with blockchain technology, web3 tokens (fungible or non-fungible),
smart contracts, decentralized identifiers (DIDs) on public blockchains, or tokenized
credential systems for extended tokens.

**Note:** The `Web3IdentityAdapter` trait definition is part of the open-core SDK.
Implementations that connect to live blockchain networks require a proprietary license.

### 2.3 DNA-Based Identities and PQC

Any use of genetic-data-based identities, DNA-derived cryptographic seeds, post-quantum
cryptography (PQC) key material associated with biological identity, and any AI system
that tracks, evaluates, or assures DNA identity quality or related risk factors.

**Note:** The `DnaIdentityAdapter` trait definition is part of the open-core SDK.
Implementations that process real biometric/genetic data require a proprietary license.

---

## 3. Adapter Type Classification and Licensing

Adapters are classified by type:

| Type | Category | License Scope |
|------|----------|---------------|
| **A** | Open Core (standard) | MPL-2.0 — trait + implementation included |
| **B** | Open Core (extensible) | MPL-2.0 — trait + no-op/rule-based impl included |
| **C** | Proprietary / Gimel Services | Trait definition: MPL-2.0; Implementation: Proprietary |
| **D** | Future / Reserved | Not yet available |

### Type C Adapter Constraints

- Require `@gimel/` namespace prefix in adapter manifests
- Require `gimel-foundation` as manifest issuer
- Subject to tariff gating (Minimum tier: M+O for ai_governance/web3_identity; L+O for dna_identity)
- Require per-service Terms of Service acceptance (Tier-2 ToS)
- Require Ed25519 attestation satisfaction before activation

---

## 4. Tariff Gating

Access to certain adapter slots is gated by tariff tier:

| Tariff | Name | Type C Access |
|--------|------|---------------|
| **O** | Open Core | No Type C adapters |
| **M+O** | Hybrid Service | ai_governance, web3_identity |
| **L+O** | Hybrid Enterprise | ai_governance, web3_identity, dna_identity |

Tariff tier is determined by the deployment license and is enforced at adapter
registration time via `check_tariff_gate()`.

---

## 5. Two-Tier Terms of Service Model

### Tier 1 — Platform ToS

Acceptance of Gimel Technologies Terms of Service transitions the license
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

## 6. SDK Billing Boundary

The GAuth SDK has **no billing integration**. There is:

- No license key or activation requirement
- No usage tracking or metering
- No telemetry or phone-home mechanism
- No Gimel account requirement for Open Core (O) users

The SDK is free under MPL-2.0. Billing applies only to the proprietary Gimel
platform (G-Agents, Foundry, Wallet, and managed infrastructure), which is
entirely separate from the SDK.

---

## 7. Contact

For licensing inquiries regarding Exclusions or proprietary adapter implementations:

**Gimel Foundation gGmbH i.G.**
Email: info@gimelid.com
Licensing: licensing@gimelid.com
Website: https://gimelid.com
