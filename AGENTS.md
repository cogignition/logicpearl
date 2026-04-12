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

Minimal dictionary shape:

```json
{
  "feature_dictionary_version": "1.0",
  "features": {
    "feature_id": {
      "label": "Readable feature label",
      "source_id": "optional-source-id",
      "source_anchor": "optional-source-anchor",
      "states": {
        "missing_or_failed": {
          "when": {
            "op": "<=",
            "value": 0.0
          },
          "label": "Readable state label",
          "message": "This rule fires when the readable condition is true.",
          "counterfactual_hint": "Describe the smallest useful change."
        }
      }
    }
  }
}
```

For simple CSV work, `label` alone is enough. Use `states` only when a specific predicate needs precise reviewer-facing text.

Do not fix unreadable output by patching `rules[].label` after discovery or by rewriting labels in a UI. Generate a dictionary from the same source that generated the traces, then pass it to `build` or `discover`.

Do not add healthcare, payer, or other domain-specific parsing to the core crates. The core should not parse prefixes like `requirement__`, suffixes like `__satisfied`, or IDs like `req-003`. Domain integrations own those meanings and should express them through feature dictionary fields.

Proof checklist before claiming feature dictionaries work:

- Build with `logicpearl build ... --feature-dictionary feature_dictionary.json`.
- Inspect the emitted `pearl.ir.json` and confirm `input_schema.features[].semantics` exists for dictionary-backed features.
- Confirm generated `rules[].label`, `rules[].message`, and `rules[].counterfactual_hint` came from LogicPearl rule generation, not a post-build patch or frontend rewrite.
- Run `logicpearl inspect <artifact> --json` and confirm readable feature metadata appears alongside raw `deny_when`.
- Run the artifact with and without dictionary metadata when relevant and confirm runtime bitmasks are identical for identical raw rules.

When reviewing diffs, keep these separate:

- `source_schema_changed`: features or source anchors changed
- `learned_rule_changed`: raw rule expressions changed
- `rule_explanation_changed`: labels, messages, hints, or dictionary text changed while raw logic stayed the same

Diff expectation:

- `logicpearl diff old_artifact new_artifact --json` should expose readable rule metadata when dictionaries are present.
- Raw expression changes should be reported separately from explanation-only changes.
- Adding or improving dictionary text should not be described as a learned policy change unless the raw `deny_when` changed.

Downstream demos and frontends may display artifact metadata, but they must not synthesize, infer, or rewrite rule meaning. The artifact should already contain the human-facing label, message, and counterfactual hint.

Raw `deny_when` expressions are the source of deterministic truth.

## Multi-Action Policies

LogicPearl can learn a policy that chooses one action from reviewed examples, not just a yes/no gate. Use this when a trace dataset has an action column such as `next_action`.

```bash
logicpearl build traces.csv \
  --action-column next_action \
  --default-action do_nothing \
  --output-dir /tmp/actions
```

The build writes the same familiar bundle shape: `artifact.json`, `pearl.ir.json`, and an action report. The `pearl.ir.json` file contains the learned action policy, including the available actions, the default action, and the rules that point to each action.

`logicpearl inspect /tmp/actions` should read like a reviewable policy:

```text
Action rules:
  1. water
     Soil Moisture at or below 18% and Water used in the last 7 days at or below 0.2
```

At runtime, LogicPearl evaluates all matching rules into a bitmask, then selects the action from those matched rules. If no rule matches, it returns the configured default action.

```bash
logicpearl run /tmp/actions today.json --json
```

The JSON result includes the selected `action`, the matched-rule `bitmask`, and the rule metadata that explains why the action was selected.

## Plugin And Pipeline Execution

Plugin and pipeline manifests can execute local processes. Treat manifests from other repos, issues, or generated examples as untrusted unless the user explicitly says they trust them.

Default process-plugin behavior is conservative: timeouts are applied, manifest-relative scripts are allowed, and risky absolute or PATH-based entrypoints require explicit opt-ins. Do not weaken those defaults in code or docs without making the trust boundary explicit.
