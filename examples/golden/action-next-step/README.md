# Golden Action Example: Choose Next Step

This example learns a multi-action policy for customer support triage. Reviewed
traces contain one `next_action` per case, and the artifact chooses exactly one
route at runtime.

## Files

- [`traces.csv`](./traces.csv): reviewed next-step examples
- [`traces_v2.csv`](./traces_v2.csv): changed examples for the diff walkthrough
- [`feature_dictionary.json`](./feature_dictionary.json): reviewer-facing labels
- [`input.json`](./input.json): a support case to evaluate

## Build

The explicit action priority says fraud outranks missing-info and refund routes
when multiple rules could match.

```bash
logicpearl build examples/golden/action-next-step/traces.csv \
  --feature-dictionary examples/golden/action-next-step/feature_dictionary.json \
  --output-dir /tmp/lp-golden/action \
  --action-column next_action \
  --default-action close \
  --action-priority escalate_fraud,ask_for_info,refund
```

Expected shape:

```text
Built action artifact action_next_step_traces

Metrics
  - Rows: 12
  - Training parity: 100.0%
  - Priority: escalate_fraud, ask_for_info, refund

Top rules
  1. escalate_fraud: Suspicious account activity Is True
  2. ask_for_info: Order ID is missing Is True
  3. refund: Days since purchase at or below 30.0 and Refund requested Is True
```

## Inspect

```bash
logicpearl inspect /tmp/lp-golden/action/artifact.json
```

Output:

```text
LogicPearl Action Artifact
  Action policy action_next_step_traces
  Action column next_action
  Default action close
Action rules:
  1. escalate_fraud
     Suspicious account activity Is True
  2. ask_for_info
     Order ID is missing Is True
  3. refund
     Days since purchase at or below 30.0 and Refund requested Is True
  Training parity 100.0%
```

## Run

```bash
logicpearl run /tmp/lp-golden/action/artifact.json \
  examples/golden/action-next-step/input.json \
  --explain
```

Output:

```text
action: escalate_fraud
reason:
  - Suspicious account activity Is True
```

## Diff

Build the changed trace set and compare artifacts:

```bash
logicpearl build examples/golden/action-next-step/traces_v2.csv \
  --feature-dictionary examples/golden/action-next-step/feature_dictionary.json \
  --output-dir /tmp/lp-golden/action-v2 \
  --action-column next_action \
  --default-action close \
  --action-priority escalate_fraud,ask_for_info,refund

logicpearl diff /tmp/lp-golden/action/artifact.json \
  /tmp/lp-golden/action-v2/artifact.json
```

Output excerpt:

```text
Rules changed=1 reordered=0 +0 -0
Change classes source_schema=false action_set=false default_action=false no_match_action=false rule_predicate=true rule_priority=false learned_rule=true rule_explanation=false rule_evidence=true

━━ Changed Rules ━━
  ~ rule_predicate_changed rule_002
    - Days since purchase at or below 30.0 and Refund requested Is True
    + Days since purchase at or below 20.0 and Refund requested Is True
    Action refund (priority 2)
```

## Native And Browser Compile

Native runner:

```bash
logicpearl compile /tmp/lp-golden/action/artifact.json
/tmp/lp-golden/action/action_next_step_traces.pearl \
  examples/golden/action-next-step/input.json
```

Output excerpt:

```json
{
  "schema_version": "logicpearl.action_result.v1",
  "decision_kind": "action",
  "action": "escalate_fraud",
  "bitmask": 1
}
```

Browser Wasm bundle:

```bash
rustup target add wasm32-unknown-unknown
logicpearl compile /tmp/lp-golden/action/artifact.json --target wasm32-unknown-unknown
node examples/golden/browser-check.mjs \
  /tmp/lp-golden/action \
  examples/golden/action-next-step/input.json
```

Output excerpt:

```json
{
  "schema_version": "logicpearl.action_result.v1",
  "decision_kind": "action",
  "action": "escalate_fraud",
  "bitmask": "1"
}
```

## Verify

```bash
logicpearl artifact verify /tmp/lp-golden/action/artifact.json
```
