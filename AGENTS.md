# Agent Guidance

LogicPearl separates deterministic policy logic from explanation metadata.

## Feature Dictionaries

Use a feature dictionary before discovery when raw feature IDs need reviewer-facing text:

```bash
logicpearl build traces.csv \
  --feature-dictionary feature_dictionary.json \
  --output-dir /tmp/pearl
```

The dictionary is embedded into the artifact as `input_schema.features[].semantics`. Generated rule labels, messages, counterfactual hints, `inspect`, and `diff` may use it. Runtime evaluation must ignore it.

Do not fix unreadable output by patching `rules[].label` after discovery or by rewriting labels in a UI. Generate a dictionary from the same source that generated the traces, then pass it to `build` or `discover`.

Do not add healthcare, payer, or other domain-specific parsing to the core crates. The core should not parse prefixes like `requirement__`, suffixes like `__satisfied`, or IDs like `req-003`. Domain integrations own those meanings and should express them through feature dictionary fields.

When reviewing diffs, keep these separate:

- `source_schema_changed`: features or source anchors changed
- `learned_rule_changed`: raw rule expressions changed
- `rule_explanation_changed`: labels, messages, hints, or dictionary text changed while raw logic stayed the same

Raw `deny_when` expressions are the source of deterministic truth.

## Plugin And Pipeline Execution

Plugin and pipeline manifests can execute local processes. Treat manifests from other repos, issues, or generated examples as untrusted unless the user explicitly says they trust them.

Default process-plugin behavior is conservative: timeouts are applied, manifest-relative scripts are allowed, and risky absolute or PATH-based entrypoints require explicit opt-ins. Do not weaken those defaults in code or docs without making the trust boundary explicit.
