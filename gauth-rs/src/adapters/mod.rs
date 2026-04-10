// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
//
// ADAPTER SYSTEM — 7-SLOT CONNECTOR MODEL
//
// This module defines the GAuth adapter interfaces per the SDK Implementation
// Guide §3–§5. The SDK uses a 7-slot connector model with four adapter type
// classes (Internal, A, B, C) plus an internal billing adapter (D).
//
// Type A/B adapter interfaces are open-source (MPL-2.0). Type C adapter
// *interfaces* are also MPL-2.0, but Type C *implementations* (AI Governance,
// Web3 Identity, DNA Identity) are proprietary to Gimel Foundation and require
// Ed25519 sealed manifest attestation before activation.
//
// EXCLUSIONS NOTICE:
// The following adapter categories fall under the Exclusions Addendum and are
// NOT covered by the MPL-2.0 license:
//
//   - Slot 5 (ai_governance): GovernanceAdapter — AI-enabled governance
//   - Slot 6 (web3_identity): Web3IdentityAdapter — Web3 identity integration
//   - Slot 7 (dna_identity): DNAIdentityAdapter — DNA-based identities / PQC
//
// These are subject to proprietary licensing by Gimel Foundation /
// Gimel Technologies GmbH. Rule-based (non-AI) fallback implementations
// of GovernanceAdapter ARE covered by MPL-2.0.

mod registry;
mod traits;

pub use registry::*;
pub use traits::*;
