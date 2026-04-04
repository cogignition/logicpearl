# LogicPearl Demo Shell

This is a reusable static frontend shell for LogicPearl demos.

It is manifest-driven:

- one shell
- one `demo_manifest.json` per demo
- one theme / vocabulary layer per customer or domain

## Run

From the repo root:

```bash
python3 -m http.server 8000
```

Then open:

```text
http://localhost:8000/logicpearl/demos/demo_shell/?manifest=../healthcare_policy/demo_manifest.json
```

Or use the OPA pack:

```text
http://localhost:8000/logicpearl/demos/demo_shell/?manifest=../opa_rego/demo_manifest.json
```

If you open the shell without changing anything, it also shows a small pack gallery so the entry path is obvious.

## Purpose

The shell is intended to stay mostly constant across demos.

Each demo manifest supplies:

- title / subtitle / tagline
- domain theme
- summary and non-goals
- source catalog
- artifact links
- case walkthrough data
- optional graph-oriented evidence metadata for static interactive views

Manifest validation helpers live in the private workspace tooling, not in the public proof-layer tree.

## Current Demo Pack

Current manifest-backed demos:

- `../healthcare_policy/demo_manifest.json`
- `../opa_rego/demo_manifest.json`

The healthcare pack shows a deterministic evidence-checklist workflow for an MHK-style conversation.

The OPA pack proves the shell can also carry a parity/import story without assuming healthcare-specific concepts.

Additional domain-heavy demo packs can live in the private workspace without changing the public shell itself.
