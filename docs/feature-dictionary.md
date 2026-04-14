# Feature Dictionaries

LogicPearl learns rules from feature IDs. A feature dictionary tells LogicPearl what those features mean, so artifacts, inspect output, and diffs are readable.

Feature dictionaries are metadata. They do not change runtime evaluation. The raw `deny_when` expression remains the deterministic rule.

## When To Use One

Use a feature dictionary when feature names are stable machine IDs, generated IDs, or domain-specific IDs that should not be shown to reviewers directly.

Common cases:
- generated policy requirements such as `requirement__req-003__satisfied`
- observer outputs such as `contains_xss_signature`
- payer, plan, region, or contract features that need source anchors
- CSV columns where a short label is enough for humans

You do not need a dictionary for simple datasets where the feature IDs are already readable.

## Build Flow

Pass the dictionary before discovery:

```bash
logicpearl build traces.csv \
  --feature-dictionary feature_dictionary.json \
  --output-dir /tmp/pearl
```

For multi-target discovery:

```bash
logicpearl discover traces.csv \
  --targets target_a,target_b \
  --feature-dictionary feature_dictionary.json \
  --output-dir /tmp/discovered
```

LogicPearl validates that dictionary keys reference known input or derived features. The emitted artifact embeds entries under `input_schema.features[].semantics`.

When `--feature-dictionary` is omitted, `logicpearl build` generates a starter dictionary from trace column names into the output bundle and uses it before discovery. Use `--raw-feature-ids` only when you want no generated explanation metadata.

Treat the generated dictionary as a starting point. Source-aware integrations should still emit precise labels, states, and anchors from the same source that emitted the traces.

## Minimal Dictionary

Most hand-written dictionaries should start with labels only:

```json
{
  "feature_dictionary_version": "1.0",
  "features": {
    "age": {
      "label": "Applicant age"
    },
    "is_member": {
      "label": "Active member"
    }
  }
}
```

This keeps generated text readable while preserving all existing behavior.

## State-Aware Dictionary

State text is optional. Add it when a particular predicate should have a precise reviewer-facing meaning.

```json
{
  "feature_dictionary_version": "1.0",
  "features": {
    "requirement__req-003-transcutaneous-electrical-nerve-stimulation-prn-p1-001__satisfied": {
      "label": "Failed conservative therapy",
      "source_id": "req-003-transcutaneous-electrical-nerve-stimulation-prn-p1-001",
      "source_anchor": "page-1",
      "states": {
        "missing": {
          "when": {
            "op": "<=",
            "value": 0.0
          },
          "label": "Failed conservative therapy is missing",
          "message": "This rule fires when the packet does not support failed conservative therapy.",
          "counterfactual_hint": "Add evidence showing failed conservative therapy."
        }
      }
    }
  }
}
```

If discovery learns this expression:

```json
{
  "feature": "requirement__req-003-transcutaneous-electrical-nerve-stimulation-prn-p1-001__satisfied",
  "op": "<=",
  "value": 0.0
}
```

the artifact can carry this readable rule text:

```json
{
  "label": "Failed conservative therapy is missing",
  "message": "This rule fires when the packet does not support failed conservative therapy.",
  "counterfactual_hint": "Add evidence showing failed conservative therapy."
}
```

The expression is unchanged.

## Diff Semantics

`logicpearl diff` separates three kinds of change:

- `source_schema_changed`: features or source anchors changed
- `learned_rule_changed`: raw learned expressions were added, removed, or changed
- `rule_explanation_changed`: rule text or dictionary explanation text changed while raw logic stayed the same

This distinction matters. A new source policy, a different learned threshold, and a better human label are different review events.

## Integration Guidance

Generate dictionaries from the same source that creates traces. Do not run discovery first and patch artifact labels afterward.

Recommended integration flow:

1. Parse source policy or domain config.
2. Emit stable feature IDs into traces.
3. Emit `feature_dictionary.json` with labels, optional states, and source anchors for those IDs.
4. Run `logicpearl build` or `logicpearl discover` with `--feature-dictionary`.
5. Let `inspect`, `diff`, and downstream UI read the artifact metadata.

Avoid these patterns:
- hard-coding domain prefixes in `logicpearl-discovery` or `logicpearl-runtime`
- parsing IDs such as `requirement__...` in the core engine
- rewriting rule labels in the frontend without artifact metadata
- changing runtime evaluation based on dictionary content

## Runtime Boundary

The runtime ignores feature dictionaries. Two artifacts with identical `rules` and different `input_schema.features[].semantics` evaluate the same input to the same bitmask.

Treat the dictionary as source-aware explanation metadata for humans and tooling, not as policy logic.
