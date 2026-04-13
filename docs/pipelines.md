# Pipelines

Pipelines compose multiple stages into a "string of pearls." Use them when a decision needs explicit staged inputs, plugin observation, multiple pearls, or a verification stage.

Most first-time workflows do not need pipelines. Start with one artifact bundle unless you need composition.

## Validate, Inspect, Run

Validate a pipeline:

```bash
logicpearl pipeline validate examples/pipelines/authz/pipeline.json --json
```

Inspect stages and exports:

```bash
logicpearl pipeline inspect examples/pipelines/observer_membership_verify/pipeline.json --json
```

Run a pipeline:

```bash
logicpearl pipeline run examples/pipelines/authz/pipeline.json \
  examples/pipelines/authz/input.json \
  --json
```

Trace stage-by-stage execution:

```bash
logicpearl pipeline trace examples/pipelines/observer_membership_verify/pipeline.json \
  examples/pipelines/observer_membership_verify/input.json \
  --json
```

`pipeline run` also accepts stdin:

```bash
cat examples/pipelines/authz/input.json | \
  logicpearl pipeline run examples/pipelines/authz/pipeline.json --json
```

## Pipeline Shape

A pipeline defines an entrypoint, ordered stages, and final output exports:

```json
{
  "pipeline_version": "1.0",
  "pipeline_id": "authz_pipeline",
  "entrypoint": "input",
  "stages": [
    {
      "id": "authz",
      "kind": "pearl",
      "artifact": "../../../fixtures/ir/valid/auth-demo-v1.json",
      "input": {
        "action": "$.request.action",
        "resource_archived": "$.request.resource_archived",
        "user_role": "$.user.role",
        "failed_attempts": "$.user.failed_attempts"
      },
      "export": {
        "bitmask": "$.bitmask",
        "allow": "$.allow"
      }
    }
  ],
  "output": {
    "bitmask": "@authz.bitmask",
    "allow": "@authz.allow"
  }
}
```

See [examples/pipelines/authz/pipeline.json](../examples/pipelines/authz/pipeline.json).

## Stage References

Pipeline inputs use two reference styles:

- `$.path.to.value`
  Reads from the original pipeline input or the current stage result.
- `@stage_id.export_name`
  Reads a named export from an earlier stage.

Stages can export a small stable shape instead of passing a whole raw result to later stages.

## Stage Kinds

Common stage kinds:

- `pearl`
  Runs a LogicPearl gate or action-policy artifact.
- `observer_plugin`
  Runs an observer plugin and exports normalized features.
- `trace_source_plugin`
  Runs a trace-source plugin when a pipeline owns trace generation.
- `enricher_plugin`
  Runs an integration-specific enrichment step.
- `verify_plugin`
  Runs a verifier plugin after a pearl or pipeline decision.

Plugin-backed stages execute local programs declared by manifests. See [plugins.md](./plugins.md) before running untrusted pipelines.

## Runtime JSON

`logicpearl pipeline run --json` returns `logicpearl.pipeline_result.v1`. The schema lives at [schema/logicpearl-pipeline-result-v1.schema.json](../schema/logicpearl-pipeline-result-v1.schema.json).

Pearl stages preserve canonical gate/action runtime details in `stages[].raw_result` while still exporting stage fields such as `bitmask`, `allow`, or `action` for downstream use.

## Provenance

Plugin-backed pipeline stages include plugin run provenance with manifest hashes, entrypoint hashes, request/input/output hashes, timeout policy, capability posture, and redacted stdio hashes.

Pipeline artifact bundles use the same artifact manifest and verification commands as single-pearl bundles:

```bash
logicpearl artifact inspect path/to/pipeline-bundle --json
logicpearl artifact verify path/to/pipeline-bundle
```

## When To Use A Pipeline

Use a pipeline when the staging is part of the contract:

- normalize raw input through an observer, then run a pearl
- run several pearls and combine explicit outputs
- attach a verifier plugin after a decision
- preserve stage-level trace output for review

If the artifact is just one gate or action policy, keep it as one artifact bundle.
