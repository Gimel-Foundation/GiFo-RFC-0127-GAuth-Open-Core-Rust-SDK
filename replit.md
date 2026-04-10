# Workspace

## Overview

pnpm workspace monorepo using TypeScript. Each package manages its own dependencies.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.

## gauth-rs (Rust SDK)

**GAuth Open Core Rust SDK** implementing the GiFo GAuth authorization protocol (RFCs 0110-0118), aligned with SDK Implementation Guide v1.2.

### Structure
- `gauth-rs/src/types/` — PoA credential schema, governance profiles, capabilities, delegation
- `gauth-rs/src/token/` — Extended Token JWT (RS256/ES256, HS256 prohibited), schema version `0116.2.2`
- `gauth-rs/src/pep/` — Policy Enforcement Point with 16-check pipeline (CHK-01 through CHK-16), fail-closed
- `gauth-rs/src/management/` — Mandate lifecycle (DRAFT→ACTIVE→SUSPENDED/REVOKED/EXPIRED/BUDGET_EXCEEDED/SUPERSEDED), license state machine (mpl_2_0→gimel_tos), two-tier ToS model
- `gauth-rs/src/adapters/` — 7-slot connector model (Type A/B/C/D), Ed25519 signed manifests, tariff gating (O/S/M/L), adapter lifecycle (null→pending→active→error)
- `gauth-rs/src/crypto/` — Canonical JSON, SHA-256 scope checksum, Ed25519 helpers
- `gauth-rs/src/error.rs` — Typed error hierarchy

### Key Design Decisions
- **License**: MPL-2.0 with Exclusions Addendum (AI-enabled Governance, Web3 Integration, DNA-based Identities and PQC are proprietary); see ADDITIONAL-TERMS.md
- **Entity**: Gimel Foundation gGmbH i.G. / Gimel Technologies GmbH
- **HS256 prohibited**: Only RS256/ES256 allowed per RFC spec
- **Fail-closed**: Any error during PEP evaluation returns DENY
- **7-slot connector model**: pdp(1,Internal), oauth_engine(2,A), foundry(3,B), wallet(4,B), ai_governance(5,C), web3_identity(6,C), dna_identity(7,C)
- **Tariff gating**: O=Open Core, S=Small, M=Medium, L=Large; Type C adapters require M+; dna_identity requires L only
- **Adapter types**: 8 adapter trait interfaces (PolicyDecision, OAuthEngine, Foundry, Wallet, Governance, Web3Identity, DnaIdentity, Billing)
- **Two-tier ToS**: Tier1=Platform ToS (mpl_2_0→gimel_tos), Tier2=per-service for Type C slots
- **Attestation**: Type C adapters require @gimel/ namespace, gimel-foundation issuer, Ed25519 attestation
- **Governance profiles**: Minimal, Standard, Strict, Enterprise, Behörde — each with budget ceilings, deployment targets, approval modes, delegation depth
- **AdapterRegistry** (legacy, for backwards compat) preserved alongside new ConnectorSlotRegistry

### Commands
- `cd gauth-rs && cargo build` — build the SDK
- `cd gauth-rs && cargo test` — run tests (80 tests: 4 unit + 76 integration)
- `cd gauth-rs && cargo clippy` — lint check (zero warnings)

### Root-Level Files
- `README.md` — GitHub monorepo README with protocol overview, repo structure, branch model
- `CONTRIBUTION-AND-RELEASE-POLICY.md` — Normative contribution workflow, branch model (main/replit/feature), CI gates, release process (per SDK Implementation Guide §16)
- `gauth-rs/LICENSE` — Mozilla Public License 2.0 (full text)
- `gauth-rs/ADDITIONAL-TERMS.md` — Exclusions Addendum (§15.6)
- `gauth-rs/README.md` — Rust SDK documentation with architecture, quick start, full API reference
