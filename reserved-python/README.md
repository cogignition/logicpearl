# Python Packages

This directory holds Python-facing packages that are outside the Rust workspace.

They are:
- outside the Rust workspace
- not part of the normal build or test flow
- allowed to evolve independently when a real Python-facing surface makes sense

Current package:
- `logicpearl`

## Why This Exists

PyPI package names are first-come, first-served.

Publishing `logicpearl` on crates.io or npm does **not** protect the Python package name.

Now that `logicpearl-engine` exists, this directory can also hold real Python bridges to public Rust surfaces when that is cleaner than asking Python code to shell out to the CLI.

## Publish Intent

These packages should stay:
- honest
- clearly documented
- thin over the real Rust execution surface

## Suggested Publish Flow

1. Build the wheel/source distribution.
2. Smoke-test the resulting package.
3. Upload with Twine or the chosen release path.

Example:

```bash
maturin build --manifest-path reserved-python/logicpearl/Cargo.toml
python3 -m twine upload target/wheels/logicpearl-*
```

## Naming Rule

Only add packages here if the name is:
- realistic
- project-aligned
- clearly tied to a public Rust surface or a truly useful Python bridge
