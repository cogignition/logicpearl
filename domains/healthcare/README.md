# Healthcare Domain Samples

This directory contains generic healthcare sample contracts for exercising
LogicPearl artifacts across a domain boundary.

The contracts are intentionally domain-specific, so they live under
`domains/healthcare/` instead of the generic `schema/` or `fixtures/contracts/`
roots. They are suitable for demos, examples, and external regression checks
that want healthcare-shaped request, response, routing, and review semantics
without making those semantics part of the generic LogicPearl contract surface.

Contents:

- `schema/`: healthcare request and response JSON schemas
- `contracts/healthcare_prior_auth/`: prior-authorization sample artifact bundles
- `contracts/revenue_recovery/`: revenue-recovery sample artifact bundles

The precommit regression suite exercises these samples against the public Rust
CLI:

```sh
cargo test --manifest-path domains/healthcare/Cargo.toml
```
