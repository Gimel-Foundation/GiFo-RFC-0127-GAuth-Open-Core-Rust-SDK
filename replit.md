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

**GAuth Open Core Rust SDK** implementing the GiFo GAuth authorization protocol (RFCs 0110, 0111, 0115, 0116, 0117, 0118).

### Structure
- `gauth-rs/src/types/` — PoA credential schema, governance profiles, capabilities, delegation
- `gauth-rs/src/token/` — Extended Token JWT (RS256/ES256, HS256 prohibited), schema version `0116.2.2`
- `gauth-rs/src/pep/` — Policy Enforcement Point with 16-check pipeline (CHK-01 through CHK-16), fail-closed
- `gauth-rs/src/management/` — Mandate lifecycle (DRAFT→ACTIVE→SUSPENDED/REVOKED/EXPIRED/BUDGET_EXCEEDED/SUPERSEDED)
- `gauth-rs/src/adapters/` — Sealed adapter registry with Ed25519 signature-verified manifests
- `gauth-rs/src/crypto/` — Canonical JSON, SHA-256 scope checksum, Ed25519 helpers
- `gauth-rs/src/error.rs` — Typed error hierarchy

### Key Design Decisions
- **License**: MPL-2.0 with Exclusions Addendum (AI-enabled Governance, Web3 Integration, DNA-based Identities and PQC are proprietary)
- **HS256 prohibited**: Only RS256/ES256 allowed per RFC spec
- **Fail-closed**: Any error during PEP evaluation returns DENY
- **Sealed adapters**: Ed25519 signature over JSON-serialized AdapterManifest; trusted namespaces: `["gimel", "gimelfoundation"]`
- **Governance profiles**: Minimal, Standard, Strict, Enterprise, Behörde — each with budget ceilings, deployment targets, approval modes, delegation depth

### Commands
- `cd gauth-rs && cargo build` — build the SDK
- `cd gauth-rs && cargo test` — run tests
