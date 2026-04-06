# Reserved Crates

These crates are intentionally minimal placeholders for realistic future `logicpearl-*` package names we may want on crates.io.

They are:
- outside the main Cargo workspace
- not part of the normal build or test flow
- meant only for clean namespace reservation when we are ready to publish them

Current reserved-name candidates:
- `logicpearl-explain`
- `logicpearl-policy`
- `logicpearl-schema`
- `logicpearl-wasm`

## Why These Exist

Crates.io does not reserve an entire prefix family automatically.

Owning `logicpearl` does **not** automatically protect future names like:
- `logicpearl-wasm`
- `logicpearl-schema`
- `logicpearl-policy`

If we believe a name is plausibly part of the long-term public product surface, the cleanest way to protect it is to publish a minimal placeholder crate before someone else claims it.

## Publish Intent

These placeholders should stay:
- small
- honest
- clearly documented

They should not pretend to be fully implemented libraries.

## Suggested Publish Flow

1. Check live availability.
2. Dry-run each placeholder crate.
3. Publish the placeholders you want to reserve.

Example:

```bash
cargo publish --manifest-path reserved-crates/logicpearl-schema/Cargo.toml --dry-run
cargo publish --manifest-path reserved-crates/logicpearl-schema/Cargo.toml
```

## Naming Rule

Only add a placeholder here if the name is:
- realistic
- product-aligned
- likely to matter later

Do not fill this directory with speculative junk crate names.
