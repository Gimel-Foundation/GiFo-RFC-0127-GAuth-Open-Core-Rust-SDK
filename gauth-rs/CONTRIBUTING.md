# Contributing to gauth-rs

Thank you for your interest in contributing to the GAuth Open Core Rust SDK.

## License

By contributing to this project, you agree that your contributions will be licensed under the Mozilla Public License 2.0 (MPL-2.0), subject to the Exclusions Addendum described in [ADDITIONAL-TERMS.md](ADDITIONAL-TERMS.md).

## Getting Started

```bash
git clone https://github.com/Gimel-Foundation/gauth-rs.git
cd gauth-rs
cargo build
cargo test
cargo clippy --all-targets
```

## Project Structure

```
gauth-rs/
├── src/
│   ├── lib.rs            # Crate root
│   ├── types/            # PoA schema, governance profiles, capabilities, delegation
│   ├── token/            # Extended Token JWT (RS256/ES256, HS256 prohibited)
│   ├── pep/              # Policy Enforcement Point — 16-check pipeline
│   ├── management/       # Mandate lifecycle, license state machine
│   ├── adapters/         # 7-slot connector model, Type A/B/C/D classification
│   ├── crypto/           # Canonical JSON, SHA-256, Ed25519
│   ├── error.rs          # Error hierarchy
│   ├── vc/               # W3C Verifiable Credentials v2.0
│   │   ├── did.rs        #   DID resolution (did:web, did:key)
│   │   ├── sd_jwt.rs     #   SD-JWT selective disclosure
│   │   ├── status_list.rs#   Bitstring Status List v2.0
│   │   ├── serializer.rs #   PoA→VC serializer + Data Integrity Proofs
│   │   └── openid.rs     #   OpenID4VCI/VP credential exchange
│   ├── storage/          # Mandate repository trait + InMemory impl
│   └── profiles/         # Governance profile ceiling tables
├── tests/
│   ├── integration_tests.rs     # Block A integration tests (109 tests)
│   └── conformance_block_b.rs   # Block B conformance tests (60 tests)
├── Cargo.toml
├── LICENSE               # MPL-2.0
└── ADDITIONAL-TERMS.md   # Exclusions Addendum
```

## Contribution Guidelines

### Code Style

- Follow standard Rust formatting (`cargo fmt`).
- All code must pass `cargo clippy --all-targets` with zero warnings.
- All tests must pass (`cargo test`).
- Use `thiserror` for error types; never `unwrap()` in library code.
- Only RS256 and ES256 are permitted for signing. HS256 is strictly prohibited per RFC 0116.

### Test Requirements

- Every new public API must have corresponding tests.
- Conformance tests follow the naming convention `ct_{category}_{number}_{description}`.
- Block A tests cover the core SDK (types, token, pep, management, adapters).
- Block B tests cover the VC translation layer (did, sd_jwt, status_list, serializer, openid, storage, profiles).

### Commit Messages

Use conventional commits:

```
feat(vc): add SD-JWT selective disclosure
fix(pep): correct CHK-09 constraint evaluation
test(conformance): add CT-CF-010 proof verification
docs: update README with VC module documentation
```

### Pull Request Process

1. Fork the repository and create a feature branch.
2. Ensure all tests pass and clippy is clean.
3. Update documentation if adding new public APIs.
4. Submit a PR with a clear description of changes.
5. PRs require at least one reviewer approval.

### Exclusions

Do **not** contribute implementations of the following features — they are proprietary and excluded from MPL-2.0:

1. **AI-enabled Governance** (Slot 5 — `ai_governance`)
2. **Web3 Integration** (Slot 6 — `web3_identity`)
3. **DNA-based Identities** (Slot 7 — `dna_identity`)

Rule-based (non-AI) adapter implementations are welcome under MPL-2.0. See the Exclusions Addendum for detailed boundaries.

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests.
- Include the SDK version, Rust toolchain version, and minimal reproduction.
- Security vulnerabilities: email security@gimelid.com (do not file a public issue).

## Contact

Gimel Foundation gGmbH i.G.
Email: info@gimelid.com
Licensing: licensing@gimelid.com
Website: https://gimelid.com
