# Loan Approval Demo

This demo learns a decision pearl from labeled loan-approval traces. Each row
captures a credit application with features like credit score, annual income,
debt-to-income ratio, and years of employment, along with an `approved` /
`denied` outcome.

## Quick start

```bash
logicpearl build traces.jsonl --output-dir out
logicpearl inspect out
```

## Input format

Traces are provided as JSONL (one JSON object per line) or CSV. Every record
must include the label column (`approved`). See `traces.jsonl` and `traces.csv`
for examples.
