# Observation Schemas

Observation schemas describe the feature values an upstream observer, parser,
or extraction plugin can emit before review and build. They are a discovery
contract for feature availability, not policy logic.

The v1 schema lives at
[schema/logicpearl-observation-schema-v1.schema.json](../schema/logicpearl-observation-schema-v1.schema.json).

## Boundary

Use an observation schema between source extraction and reviewed traces:

```text
source documents -> candidate observations -> reviewed traces -> logicpearl build
```

The schema can help reviewers and tooling understand which raw feature IDs are
available, which operators make sense for them, and where source-grounded
labels or anchors came from. Runtime evaluation still uses only raw input
features and learned rule expressions.

Do not use observation schemas to infer or rewrite rule meaning after build.
If reviewer-facing text should appear in artifacts, emit a feature dictionary
from the same source and pass it to `logicpearl build` or `logicpearl discover`.

## Shape

```json
{
  "schema_version": "logicpearl.observation_schema.v1",
  "features": [
    {
      "feature_id": "notification_sent_on_time",
      "type": "boolean",
      "label": "Notification sent on time",
      "source_id": "policy_manual_2026_04",
      "source_anchor": "section-3.2",
      "operators": ["eq"],
      "description": "Whether the notification was sent within the required window."
    }
  ]
}
```

Required fields:

- `schema_version`: must be `logicpearl.observation_schema.v1`.
- `features`: non-empty list of observable feature declarations.
- `feature_id`: stable raw feature ID emitted into candidate rows and traces.
- `type`: one of `boolean`, `integer`, `number`, `string`, or `enum`.
- `operators`: non-empty list of supported reviewer/query operators.

Optional fields:

- `label` and `description`: reviewer-facing metadata.
- `source_id` and `source_anchor`: source links aligned with source manifests
  and feature dictionaries.
- `required` and `nullable`: availability hints for extraction/review tooling.
- `values`: allowed scalar values. Required for `enum` features.

## Inspect

Validate and summarize a schema with:

```bash
logicpearl traces observation-schema fixtures/observations/valid/notification-observation-schema-v1.json --json
```

This reports the normalized feature list and rejects duplicate feature IDs,
empty metadata fields, missing enum values, duplicate operators, and
type/operator mismatches such as `gt` on a boolean.

## Relation To Feature Dictionaries

Observation schemas answer: "What can an observer emit?"

Feature dictionaries answer: "How should already-selected artifact features be
explained to reviewers?"

A source-aware integration may generate both. The observation schema can be
used before review to inspect candidate feature availability; the feature
dictionary is passed into build so readable metadata is embedded into the
artifact.
