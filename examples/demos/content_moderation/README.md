# Content Moderation Demo

This demo learns a decision pearl from labeled content-moderation traces. Each
record contains signal scores (toxicity, spam likelihood), account metadata
(age, verification status), recent report counts, and a `pass` / `flagged`
verdict.

## Quick start

```bash
logicpearl build traces_nested.json --output-dir out
logicpearl inspect out
```

## Input format

Traces are provided as a JSON array of nested objects (see `traces_nested.json`)
or as flat CSV (see `traces.csv`). Nested keys like `signals.toxicity_score` are
flattened automatically during ingestion.
