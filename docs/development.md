# Development

This page collects local contributor commands so the README can stay focused on the product loop.

## Local Setup

Install Rust and keep a solver available:

```bash
rustup toolchain install stable
cargo build --workspace
```

For source installs:

```bash
cargo install --path crates/logicpearl
```

Discovery workflows need `z3` on `PATH` unless you use a prebuilt LogicPearl release bundle that includes `z3`.

## Common Checks

Fast formatting and compile checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Full Rust tests:

```bash
cargo test --workspace --all-targets
```

Browser runtime tests:

```bash
node --test packages/logicpearl-browser/test/browser-runtime.test.mjs
```

## Xtask Verification

The repo uses `xtask` for the same check groups used by hooks and CI:

```bash
cargo xtask verify pre-commit
cargo xtask verify pre-push
cargo xtask verify ci
```

`pre-commit` is narrower and focused on fast local safety gates. `pre-push` and `ci` are broader and include workspace tests, browser runtime tests, installer smoke checks, publish readiness checks, and focused solver/discovery/observer verification.

## Release Readiness

Check publish metadata:

```bash
python3 scripts/release/check_publish_ready.py
```

Build a release CLI:

```bash
cargo build --release -p logicpearl
```

Package a release bundle:

```bash
cargo xtask package-release-bundle \
  --logicpearl-binary target/release/logicpearl \
  --z3-binary /usr/bin/z3 \
  --target-triple x86_64-unknown-linux-gnu \
  --output-dir dist
```

Generate a Homebrew formula from release bundle checksums:

```bash
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/logicpearl/Cargo.toml | head -1)
cargo xtask generate-homebrew-formula \
  --version "$VERSION" \
  --dist-dir dist \
  --output packaging/homebrew/Formula/logicpearl.rb
```

GitHub Release packaging is defined in [.github/workflows/release-bundles.yml](../.github/workflows/release-bundles.yml).

## Documentation Rules

Keep README focused on:

- install
- build
- inspect
- run
- verify
- diff
- trust boundaries
- open-core posture

Put reference material in topic docs:

- [artifacts.md](./artifacts.md)
- [provenance.md](./provenance.md)
- [plugins.md](./plugins.md)
- [pipelines.md](./pipelines.md)
- [browser-runtime.md](./browser-runtime.md)
- [conformance.md](./conformance.md)

When documenting examples, keep domain-specific semantics out of core crate docs. The core crates should describe feature contracts, schemas, manifests, and runtime behavior. Integrations own domain meanings.

## Git Notes

Commits can be SSH-signed. Confirm local signature status with:

```bash
git log -1 --format='%H %G? %s'
```

`G` means Git verified the signature locally.
