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

**GAuth Open Core Rust SDK** Version 0.91 (Public Preview) implementing the GiFo GAuth authorization protocol (RFCs 0110-0118), aligned with SDK Implementation Guide.

### Structure
- `gauth-rs/src/types/` — PoA credential schema, governance profiles, capabilities, delegation
- `gauth-rs/src/token/` — Extended Token JWT (RS256/ES256, HS256 prohibited), schema version `0116.2.2`
- `gauth-rs/src/pep/` — Policy Enforcement Point with 16-check pipeline (CHK-01 through CHK-16), fail-closed, OAuth token pre-validation (PP-08), per-verb constraint keys (PP-06)
- `gauth-rs/src/management/` — Mandate lifecycle (DRAFT→ACTIVE→SUSPENDED/REVOKED/EXPIRED/BUDGET_EXCEEDED/SUPERSEDED/PENDING_APPROVAL), license state machine (mpl_2_0→gimel_tos), two-tier ToS model, delegation with approval gate (DC-01–DC-04), scope narrowing (PP-07), PoaMapSummary (MA-01/MA-02)
- `gauth-rs/src/adapters/` — 7-slot connector model (Type A/B/C/D), Ed25519 signed manifests, tariff gating (O/M+O/L+O), adapter lifecycle (null→pending→active→error), tariff downgrade re-evaluation (LB-08), license compliance detection (LB-09/LB-10)
- `gauth-rs/src/crypto/` — Canonical JSON, SHA-256 scope checksum, Ed25519 helpers
- `gauth-rs/src/error.rs` — Typed error hierarchy
- `gauth-rs/src/vc/` — W3C Verifiable Credentials v2.0: DID resolution (did:web, did:key), SD-JWT selective disclosure, Bitstring Status List v2.0, PoA→VC serializer with Data Integrity Proofs (eddsa-rdfc-2022), OpenID4VCI/VP credential exchange
- `gauth-rs/src/storage/` — MandateRepository trait + InMemoryMandateRepository
- `gauth-rs/src/profiles/` — Governance profile ceiling table, validate_against_ceiling()

### Key Design Decisions
- **License**: MPL-2.0 with Exclusions Addendum (AI-enabled Governance, Web3 Integration, DNA-based Identities and PQC are proprietary); see ADDITIONAL-TERMS.md
- **Entity**: Gimel Foundation gGmbH i.G. / Gimel Technologies GmbH
- **HS256 prohibited**: Only RS256/ES256 allowed per RFC spec
- **Fail-closed**: Any error during PEP evaluation returns DENY
- **7-slot connector model**: pdp(1,Internal), oauth_engine(2,A), foundry(3,B), wallet(4,B), ai_governance(5,C), web3_identity(6,C), dna_identity(7,C)
- **Tariff gating**: O=Open Core, M+O=Hybrid Service, L+O=Hybrid Enterprise; Type C adapters require M+O; dna_identity requires L+O only
- **RBPC**: Role-Based Power Control — governance model binding AI agent capabilities to structured power profiles
- **Three-layer licensing**: MPL-2.0 (SDK, irrevocable) + Gimel Technologies ToS (proprietary services, revocable) + Apache 2.0 (RFCs, irrevocable)
- **No billing/telemetry**: SDK is free, no phone-home, no license key, no usage tracking
- **Adapter types**: 8 adapter trait interfaces (PolicyDecision, OAuthEngine, Foundry, Wallet, Governance, Web3Identity, DnaIdentity, Billing)
- **Two-tier ToS**: Tier1=Platform ToS (mpl_2_0→gimel_tos), Tier2=per-service for Type C slots
- **Attestation**: Type C adapters require @gimel/ namespace, gimel-foundation issuer, Ed25519 attestation
- **Governance profiles**: Minimal, Standard, Strict, Enterprise, Behörde — each with budget ceilings, deployment targets, approval modes, delegation depth
- **AdapterRegistry** (legacy, for backwards compat) preserved alongside new ConnectorSlotRegistry

### Commands
- `cd gauth-rs && cargo build` — build the SDK
- `cd gauth-rs && cargo test` — run tests (173 tests: 109 Block A + 64 Block B conformance)
- `cd gauth-rs && cargo clippy` — lint check (zero warnings)

## Dashboard & API

**GAuth Dashboard** — React + Vite dashboard with 6 pages for managing GAuth mandates, profiles, and credentials.

### Architecture
- **Frontend**: React 19 + Vite, Tailwind CSS, shadcn/ui, wouter router, TanStack React Query
- **API**: Express 5, esbuild bundled, PostgreSQL via Drizzle ORM
- **Codegen**: Orval generates React Query hooks + Zod schemas from OpenAPI spec
- **Auth**: Simple password gate (empty or "gauth" grants access), session in `sessionStorage`

### Dashboard Pages
1. **Dashboard** (`/`) — Overview with mandate stats, status breakdown, recent activity
2. **Mandates** (`/mandates`) — List all mandates with filtering, status badges, actions
3. **Mandate Detail** (`/mandates/:id`) — Full mandate view with lifecycle actions (activate/suspend/resume/revoke) + audit history
4. **Profiles** (`/profiles`) — Governance profile comparison table with ceiling data (minimal/standard/strict/enterprise/behoerde)
5. **Credentials** (`/credentials`) — VCI issuer metadata viewer (OpenID4VCI format)
6. **PoA Map** (`/poa-map`) — Permission map visualization across all mandates

### API Endpoints
- `GET /api/healthz` — Health check
- `GET /api/mgmt/health` — Management health with version info
- `GET /api/mandates` — List mandates (with pagination/filtering)
- `POST /api/mandates` — Create mandate
- `GET /api/mandates/:id` — Get mandate detail
- `POST /api/mandates/:id/activate` — Activate mandate
- `POST /api/mandates/:id/suspend` — Suspend mandate (with reason)
- `POST /api/mandates/:id/resume` — Resume mandate
- `POST /api/mandates/:id/revoke` — Revoke mandate (with reason)
- `GET /api/mandates/:id/history` — Audit history
- `GET /api/mandates/:id/delegation-chain` — Delegation chain
- `GET /api/profiles` — List governance profiles
- `GET /api/profiles/:profile/ceilings` — Profile ceiling data
- `GET /api/vci/issuer-metadata` — VCI issuer metadata

### Database Tables
- `mandates` — Mandate records (id, status, governance_profile, parties, scope, budget, delegation, timestamps)
- `audit_entries` — Audit log (mandate_id, action, actor, metadata, timestamps)

### Seed Data
3 example mandates: enterprise/ACTIVE (agent-alpha-7), standard/DRAFT (research-bot-3), strict/SUSPENDED (audit-agent-1)

### Root-Level Files
- `README.md` — GitHub monorepo README with protocol overview, repo structure, branch model
- `CONTRIBUTION-AND-RELEASE-POLICY.md` — Normative contribution workflow, branch model (main/replit/feature), CI gates, release process (per SDK Implementation Guide §16)
- `gauth-rs/LICENSE` — Mozilla Public License 2.0 (full text)
- `gauth-rs/ADDITIONAL-TERMS.md` — Exclusions Addendum (§15.6)
- `gauth-rs/README.md` — Rust SDK documentation with architecture, quick start, full API reference
- `gauth-rs/CONTRIBUTING.md` — Contribution policy, code style, test requirements, exclusions
- `gauth-rs/tests/conformance_block_b.rs` — Block B conformance tests (VC, DID, SD-JWT, StatusList, OpenID4VP, storage, profiles)
