# Golden Fan-Out Example: List Applicable Actions

This example learns one applicability gate per incident-response action. A
single row can label several actions as applicable, and the fan-out artifact
returns the full set that should fire for a new incident.

## Files

- [`traces.csv`](./traces.csv): reviewed multi-label action examples
- [`traces_v2.csv`](./traces_v2.csv): changed examples for the diff walkthrough
- [`feature_dictionary.json`](./feature_dictionary.json): reviewer-facing labels
- [`input.json`](./input.json): an incident to evaluate

## Build

```bash
logicpearl build examples/golden/fanout-applicable-actions/traces.csv \
  --feature-dictionary examples/golden/fanout-applicable-actions/feature_dictionary.json \
  --output-dir /tmp/lp-golden/fanout \
  --fanout-column applicable_actions
```

Expected shape:

```text
Built fan-out pipeline fanout_applicable_actions_traces

Metrics
  - Rows: 10
  - Exact set match: 100.0%

Top rules
  1. scale_workers: CPU utilization at or above 88.0
  2. clean_disk: Disk utilization at or above 83.0
  3. rollback_release: Error rate at or above 6.5
```

## Inspect

Fan-out builds emit a typed pipeline artifact, so use `pipeline inspect`:

```bash
logicpearl pipeline inspect /tmp/lp-golden/fanout/pipeline.json
```

Output:

```text
Fan-out Pipeline fanout_applicable_actions_traces
  Action scale_workers
  Action clean_disk
  Action rollback_release
  Action page_oncall
  Action renew_certificate
  Action monitor
```

## Run

```bash
logicpearl pipeline run /tmp/lp-golden/fanout/pipeline.json \
  examples/golden/fanout-applicable-actions/input.json \
  --json
```

Output excerpt:

```json
{
  "schema_version": "logicpearl.fanout_result.v1",
  "decision_kind": "fanout",
  "applicable_actions": [
    "scale_workers",
    "clean_disk",
    "rollback_release",
    "page_oncall",
    "renew_certificate"
  ]
}
```

## Diff

Build the changed trace set and compare one action gate. The full fan-out
pipeline is composed of per-action artifacts under `actions/`.

```bash
logicpearl build examples/golden/fanout-applicable-actions/traces_v2.csv \
  --feature-dictionary examples/golden/fanout-applicable-actions/feature_dictionary.json \
  --output-dir /tmp/lp-golden/fanout-v2 \
  --fanout-column applicable_actions

logicpearl diff \
  /tmp/lp-golden/fanout/actions/scale_workers/artifact.json \
  /tmp/lp-golden/fanout-v2/actions/scale_workers/artifact.json
```

Output excerpt:

```text
Rules changed=1 reordered=0 +0 -0
Change classes source_schema=false learned_rule=true rule_explanation=false rule_evidence=false

━━ Changed Rules ━━
  ~ semantic_change rule_000
    - CPU utilization at or above 88.0
    + CPU utilization at or above 84.0
```

## Native And Browser Compile

Native runner:

```bash
logicpearl compile /tmp/lp-golden/fanout/artifact.json
/tmp/lp-golden/fanout/fanout_applicable_actions_traces.pearl \
  examples/golden/fanout-applicable-actions/input.json
```

Output excerpt:

```json
{
  "schema_version": "logicpearl.fanout_result.v1",
  "applicable_actions": [
    "scale_workers",
    "clean_disk",
    "rollback_release",
    "page_oncall",
    "renew_certificate"
  ]
}
```

Browser Wasm bundle:

```bash
rustup target add wasm32-unknown-unknown
logicpearl compile /tmp/lp-golden/fanout/artifact.json --target wasm32-unknown-unknown
node examples/golden/browser-check.mjs \
  /tmp/lp-golden/fanout \
  examples/golden/fanout-applicable-actions/input.json
```

Output excerpt:

```json
{
  "schema_version": "logicpearl.fanout_result.v1",
  "decision_kind": "fanout",
  "applicable_actions": [
    "scale_workers",
    "clean_disk",
    "rollback_release",
    "page_oncall",
    "renew_certificate"
  ]
}
```

## Verify

```bash
logicpearl artifact verify /tmp/lp-golden/fanout/artifact.json
```
