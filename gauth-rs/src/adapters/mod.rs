// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
//
// ADAPTER SYSTEM — SEALED REGISTRATION
//
// This module defines abstract adapter interfaces for integrating external
// services with the GAuth runtime. The SDK ships with default no-op/rule-based
// implementations. Proprietary Gimel adapters (e.g., gauth-adapters-gimel) are
// distributed as a separate private package and must be cryptographically
// signed to be registered.
//
// EXCLUSIONS NOTICE:
// The following adapter categories, when implemented with AI capabilities,
// fall under the Exclusions and are NOT covered by the MPL-2.0 license:
//
//   - AIEnrichmentAdapter with trained AI models for governance
//   - RiskScoringAdapter with AI-based threat detection
//   - RegulatoryReasoningAdapter with AI-based compliance reasoning
//
// These are subject to proprietary licensing by Gimel Foundation /
// Gimel Technologies GmbH. Rule-based (non-AI) implementations of these
// adapters ARE covered by MPL-2.0.

mod registry;
mod traits;

pub use registry::*;
pub use traits::*;
