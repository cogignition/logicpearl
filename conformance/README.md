# Conformance Harness

This directory contains cross-implementation checks for LogicPearl v3.

The main goal is simple:
- load the same gate fixture,
- run the same input cases through the discovery CLI and the runtime CLI,
- assert both implementations return the same bitmask,
- and assert that bitmask matches the shared expected value.

Run from `v3/`:

```bash
python3 conformance/run_parity.py
```
