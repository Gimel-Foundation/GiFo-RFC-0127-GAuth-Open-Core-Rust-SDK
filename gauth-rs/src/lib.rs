// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
//
// IMPORTANT — EXCLUSIONS NOTICE
// The following features are EXCLUDED from this open-source SDK and from
// the MPL-2.0 license. They are subject to separate proprietary licensing
// by Gimel Foundation / Gimel Technologies GmbH:
//
//   1. AI-enabled Governance — AI that controls, tracks, or assures
//      authorization compliance, deployment lifecycles, or outcome quality.
//   2. Web3 Integration — Blockchain technology, web3 tokens, and smart
//      contracts for extended tokens.
//   3. DNA-based Identities and PQC associated — Genetic-data-based
//      identities, post-quantum cryptography seeds derived from DNA, and
//      AI that tracks DNA identity quality or related risks.
//
// Users MUST NOT integrate these Exclusions without a separate written
// license from Gimel Foundation. See the LICENSE file and RFC documents
// for full legal terms.

pub mod types;
pub mod token;
pub mod pep;
pub mod management;
pub mod adapters;
pub mod crypto;
pub mod error;

pub use types::*;
pub use error::GAuthError;
