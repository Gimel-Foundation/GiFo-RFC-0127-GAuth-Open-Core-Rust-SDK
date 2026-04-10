# GAuth SDK Monorepo

**Gimel Foundation gGmbH i.G.**

[![License: MPL-2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

The GAuth SDK implements the **GiFo GAuth authorization protocol** — a structured governance framework that enables AI systems (digital agents, agentic AI, humanoid robots) to carry, present, and enforce Power of Attorney (PoA) credentials.

This monorepo contains the official SDK implementations across multiple languages, all aligned with the [GAuth SDK Implementation Guide](https://gimelid.com) and GiFo RFCs 0110-0118.

---

## Repository Structure

```
.
├── gauth-rs/                    # Rust SDK (Open Core reference implementation)
│   ├── src/
│   │   ├── types/               # PoA credential schema, governance profiles, capabilities
│   │   ├── token/               # Extended Token JWT (RS256/ES256, HS256 prohibited)
│   │   ├── pep/                 # Policy Enforcement Point — 16-check pipeline
│   │   ├── management/          # Mandate lifecycle, license state machine, two-tier ToS
│   │   ├── adapters/            # 7-slot connector model with tariff gating
│   │   ├── crypto/              # Canonical JSON, SHA-256, Ed25519
│   │   └── error.rs             # Typed error hierarchy
│   ├── tests/                   # Integration test suite (76 tests)
│   ├── ADDITIONAL-TERMS.md      # Exclusions Addendum (§15.6)
│   ├── LICENSE                  # Mozilla Public License 2.0
│   └── README.md                # Rust SDK documentation
├── CONTRIBUTION-AND-RELEASE-POLICY.md   # Branch model, CI gates, release process
└── README.md                    # This file
```

---

## SDK Implementations

| Language | Directory | Status | Guide Version |
|----------|-----------|--------|---------------|
| **Rust** | [`gauth-rs/`](gauth-rs/) | Active | v1.2 |

Additional SDK implementations (TypeScript, Python, Go, Java, Swift, Kotlin) will follow the same architecture and conformance requirements.

---

## Protocol Overview

The GAuth protocol defines how AI systems operate under delegated authority:

1. **Power of Attorney (PoA)** credentials encode what an AI agent is permitted to do — verbs, resources, budget limits, governance profiles, and approval modes.
2. **Policy Enforcement Points (PEP)** evaluate every action against the PoA through a 16-check pipeline, producing Permit/Deny/Constrain decisions with full audit trails.
3. **Mandate lifecycle management** tracks credentials from creation through expiration, revocation, or supersession.
4. **Adapter connectors** extend the SDK through a 7-slot model with cryptographic attestation and tariff-based access control.

### 7-Slot Connector Model

| Slot | Name | Type | Tariff | Description |
|------|------|------|--------|-------------|
| 1 | `pdp` | Internal | O+ | Policy Decision Point (SDK-embedded) |
| 2 | `oauth_engine` | A | O+ | OAuth 2.0 / JWT token engine |
| 3 | `foundry` | B | O+ | Agent foundry / sandbox management |
| 4 | `wallet` | B | O+ | Credential wallet / VC storage |
| 5 | `ai_governance` | C | M+ | AI-enabled governance (Exclusion 1) |
| 6 | `web3_identity` | C | M+ | Web3/DID identity (Exclusion 2) |
| 7 | `dna_identity` | C | L | DNA-based identity (Exclusion 3) |

### Governance Profiles

| Profile | Max Budget | Auto-Deploy | Min Approval | Delegation Depth |
|---------|-----------|-------------|--------------|-----------------|
| Minimal | 10 EUR | Yes | Autonomous | 0 |
| Standard | 100 EUR | Yes | Autonomous | 1 |
| Strict | 1,000 EUR | No | Supervised | 2 |
| Enterprise | 10,000 EUR | No | Supervised | 3 |
| Behorde | Unlimited | No | Four-Eyes | 2 |

---

## Branch Model

```
main                <- protected release branch (all tags created here)
  ^ PR (reviewed)
  |
replit              <- architecture team integration branch
  ^ PR (reviewed)
  |
feature/*, fix/*    <- community branches
```

All changes enter `main` through reviewed pull requests. See [CONTRIBUTION-AND-RELEASE-POLICY.md](CONTRIBUTION-AND-RELEASE-POLICY.md) for the full contribution workflow, CI gates, and release process.

---

## Conformance Tests

Every PR triggers the full CI pipeline:

| Gate | Suites | Blocking |
|------|--------|----------|
| Conformance | CT-REG, CT-PEP, CT-MGMT, CT-LIC, CT-S2S | Yes |
| Unit/Integration | Language-specific test suite | Yes |
| Linting | `cargo clippy` (Rust), language-specific linters | Yes |
| License scan | No Excluded Component code in Open Core | Yes |
| Security scan | No credential leaks, no unsafe crypto | Yes |

---

## RFC References

| RFC | Title |
|-----|-------|
| 0110 | GAuth Overview and Architecture |
| 0111 | Power of Attorney Credential Schema |
| 0115 | Three-Layer Capability Model |
| 0116 | Extended Token Specification |
| 0117 | Policy Enforcement Point (PEP) Pipeline |
| 0118 | Management API and Adapter Architecture |

**SDK Implementation Guide:** v1.2 (current), v1.3 (in review)

---

## License

This project is licensed under the **Mozilla Public License 2.0** (MPL-2.0).

The following features are **excluded** from the MPL-2.0 license and subject to separate proprietary licensing by Gimel Foundation gGmbH i.G. / Gimel Technologies GmbH:

1. **AI-enabled Governance** — AI that controls, tracks, or assures authorization compliance, deployment lifecycles, or outcome quality.
2. **Web3 Integration** — Blockchain technology, web3 tokens, and smart contracts for extended tokens.
3. **DNA-based Identities and PQC** — Genetic-data-based identities, post-quantum cryptography seeds derived from DNA, and AI that tracks DNA identity quality or related risks.

Rule-based (non-AI) implementations of adapter interfaces are covered by MPL-2.0. AI-enabled implementations fall under the Exclusions.

See [ADDITIONAL-TERMS.md](gauth-rs/ADDITIONAL-TERMS.md) for full details.

---

## Contact

**Gimel Foundation gGmbH i.G.**
Email: info@gimelid.com
Licensing: licensing@gimelid.com
Website: https://gimelid.com
