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
      "artifact": "artifacts/auth-demo-v1.json",
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

Stage artifact and plugin manifest paths are bundle members: they must be
relative to the pipeline file directory and cannot escape it with `..` or
symlinks. The `compose` command packages input pearls under `artifacts/` so the
generated bundle verifies with the same policy used by runtime loading.

## Override Pipelines

Use an override pipeline when the contract is "run a base pearl, then let
ordered refinements replace that result only when their own rule fires." This is
the native shape for doctrine or policy layers where a statute, baseline gate,
or default action policy is refined by separate pearls with independent hashes.

```yaml
schema_version: logicpearl.override_pipeline.v1
pipeline_id: statute_with_case_law

base:
  id: statute
  artifact: artifacts/statute_exemptions
  input:
    applicant_age: $.applicant.age
    filing_status: $.filing.status

refinements:
  - id: klamath
    artifact: artifacts/klamath_refinement
    action: override_if_fires
    input:
      applicant_age: $.applicant.age
      tribal_status: $.applicant.tribal_status

  - id: hanson
    artifact: artifacts/hanson_refinement
    action: override_if_fires
    input:
      filing_status: $.filing.status
      notice_days: $.notice.days
```

Run it with the same commands:

```bash
logicpearl pipeline validate pipeline.yaml --json
logicpearl pipeline run pipeline.yaml input.json --json
logicpearl pipeline trace pipeline.yaml input.json --json
```

Override pipeline rules:

- `base` can be an artifact path string or an object with `id`, `artifact`, and `input`.
- Each refinement must set `action: override_if_fires`.
- The default conflict mode is `first_match`.
- All refinements are evaluated for attribution, but only the first fired
  refinement applies its result.
- If no refinement fires, the base result passes through unchanged.
- `input` maps runtime fields from the original pipeline input with `$.path`
  references. A top-level `input` map can be used as the default for every
  referenced artifact, and a stage-level `input` map overrides it.
- Override-pipeline object forms use `artifact` as the path key. The old
  `pearl` alias is not accepted.

`logicpearl pipeline run --json` returns
`logicpearl.override_pipeline_result.v1` for override pipelines. The selected
artifact's runtime result is exposed as `output`, and the response also includes
`base`, `refinements`, `stages`, `selected`, and `selection` for per-artifact
attribution.

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

`logicpearl pipeline run --json` returns `logicpearl.pipeline_result.v1` for
staged pipelines and `logicpearl.override_pipeline_result.v1` for override
pipelines. The schemas live at
[schema/logicpearl-pipeline-result-v1.schema.json](../schema/logicpearl-pipeline-result-v1.schema.json)
and
[schema/logicpearl-override-pipeline-result-v1.schema.json](../schema/logicpearl-override-pipeline-result-v1.schema.json).

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
