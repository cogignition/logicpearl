# Golden Gate Example: Approve Or Deny

This example learns a binary gate for expense approvals. Reviewed traces say
whether a purchase request was approved, and LogicPearl turns that behavior
slice into an artifact that returns allow/deny with matched rules.

## Files

- [`traces.csv`](./traces.csv): reviewed approve/deny examples
- [`traces_v2.csv`](./traces_v2.csv): changed examples for the diff walkthrough
- [`feature_dictionary.json`](./feature_dictionary.json): reviewer-facing labels
- [`input.json`](./input.json): a purchase request to evaluate

## Build

```bash
logicpearl build examples/golden/gate-approve-deny/traces.csv \
  --feature-dictionary examples/golden/gate-approve-deny/feature_dictionary.json \
  --output-dir /tmp/lp-golden/gate
```

Expected shape:

```text
Built gate gate_approve_deny_traces

Metrics
  - Rows: 16
  - Rules: 4
  - Training parity: 100.0%

Top rules
  1. Purchase amount at or above 4200.0
  2. Department budget remaining at or below 3900.0
  3. Receipt is missing Is True
```

## Inspect

```bash
logicpearl inspect /tmp/lp-golden/gate/artifact.json
```

Output excerpt:

```text
━━ Gate: gate_approve_deny_traces
  Features 6
  Rules 4
  Correctness scope training parity against 16 decision traces
  Feature dictionary 4

━━ Rules ━━
  ├─ bit 0 rule_000
  │   label: Purchase amount at or above 4200.0
  ├─ bit 1 rule_001
  │   label: Department budget remaining at or below 3900.0
  ├─ bit 2 rule_002
  │   label: Receipt is missing Is True
  └─ bit 3 rule_003
      label: Vendor risk score above 4.0
```

## Run

```bash
logicpearl run /tmp/lp-golden/gate/artifact.json \
  examples/golden/gate-approve-deny/input.json \
  --explain
```

Output:

```text
bitmask: 1
matched:
  bit 0: Purchase amount at or above 4200.0
```

## Diff

Build the changed trace set and compare artifacts:

```bash
logicpearl build examples/golden/gate-approve-deny/traces_v2.csv \
  --feature-dictionary examples/golden/gate-approve-deny/feature_dictionary.json \
  --output-dir /tmp/lp-golden/gate-v2

logicpearl diff /tmp/lp-golden/gate/artifact.json \
  /tmp/lp-golden/gate-v2/artifact.json
```

Output excerpt:

```text
Rules changed=0 reordered=0 +0 -0
Change classes source_schema=false learned_rule=false rule_explanation=false rule_evidence=true

━━ Evidence Changed Rules ━━
  ~ evidence_changed rule_001
    - Purchase amount at or above 4200.0
    + Purchase amount at or above 4200.0
```

## Native And Browser Compile

Native runner:

```bash
logicpearl compile /tmp/lp-golden/gate/artifact.json
/tmp/lp-golden/gate/gate_approve_deny_traces.pearl \
  examples/golden/gate-approve-deny/input.json
```

Output:

```text
1
```

Browser Wasm bundle:

```bash
rustup target add wasm32-unknown-unknown
logicpearl compile /tmp/lp-golden/gate/artifact.json --target wasm32-unknown-unknown
node examples/golden/browser-check.mjs \
  /tmp/lp-golden/gate \
  examples/golden/gate-approve-deny/input.json
```

Output excerpt:

```json
{
  "schema_version": "logicpearl.gate_result.v1",
  "decision_kind": "gate",
  "allow": false,
  "bitmask": "1"
}
```

## Verify

```bash
logicpearl artifact verify /tmp/lp-golden/gate/artifact.json
```
