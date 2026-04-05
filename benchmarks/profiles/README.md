# Benchmark Adapter Profiles

LogicPearl benchmark adapters should move toward human-authored profile files plus a generic Rust adapter engine.

Current state:
- `salad-base-set.yaml` and `salad-attack-enhanced-set.yaml` are loaded by the Rust benchmark crate
- `alert.yaml` is a real built-in adapter profile loaded by the Rust benchmark crate
- `pint.yaml` is also loaded by the Rust benchmark crate
- other benchmark adapters are still procedural and should migrate only when the format can be expressed honestly

Use YAML for profile authoring:
- easier to read than JSON
- comments and nested mappings are clearer
- still strict enough once deserialized into the Rust schema

Keep benchmark case output as JSONL:
- one case per line
- efficient for streaming
- stable machine interchange format

## Profile Schema

Top-level fields:

- `version`
  - string schema version, currently `"1"`
- `id`
  - stable adapter profile id used in registry output
- `description`
  - short human-readable description
- `source_format`
  - human-readable description of the expected raw dataset shape
- `default_route`
  - the route this adapter usually emits, for example `allow` or `deny`
- `source`
  - how to read records from the raw dataset
- `output`
  - how to map records into LogicPearl benchmark cases

`source` fields:

- `parser`
  - currently supported:
    - `json-object-rows`
- `prompt_fields`
  - ordered candidate field names to search for the raw prompt text
- `id_fields`
  - ordered candidate field names to search for a stable row id
- `category_fields`
  - ordered candidate field names to search for category metadata
- `label_fields`
  - ordered candidate field names to search for a boolean label when routes are derived from a label column

`output` fields:

- `expected_route`
  - optional fixed route label written into each emitted benchmark case
- `id_prefix`
  - prefix used when constructing emitted case ids
- `static_input`
  - JSON object merged into every emitted benchmark case input payload
- `boolean_label_routes`
  - optional mapping for datasets where a boolean label determines the expected route
  - fields:
    - `true_route`
    - `false_route`

Exactly one of these output modes should be used:
- fixed route via `expected_route`
- boolean-derived route via `boolean_label_routes`

## Example

```yaml
version: "1"
id: "alert"
description: "Adapt ALERT adversarial instruction rows into deny benchmark cases."
source_format: "JSON array or JSONL of prompt-like objects"
default_route: "deny"

source:
  parser: "json-object-rows"
  prompt_fields: ["prompt", "instruction", "text"]
  id_fields: ["id", "aid"]
  category_fields: ["category", "label"]

output:
  expected_route: "deny"
  id_prefix: "alert"
  static_input:
    document_instructions_present: false
```

Boolean-labeled YAML example:

```yaml
version: "1"
id: "pint"
description: "Adapt PINT YAML rows into allow or deny benchmark cases for proof-only scoring."
source_format: "PINT YAML list with text/category/label"
default_route: "mixed"

source:
  parser: "yaml-object-rows"
  prompt_fields: ["text"]
  category_fields: ["category"]
  label_fields: ["label"]

output:
  id_prefix: "pint"
  boolean_label_routes:
    true_route: "deny"
    false_route: "allow"
  static_input:
    document_instructions_present: false
```

## Design Rule

Use profiles when the dataset can be described as:
- parser shape
- field lookup order
- route mapping
- static input enrichment

Keep a procedural Rust adapter when the dataset needs:
- complex nested unpacking
- multi-shape parsing
- nontrivial normalization logic
- format-specific validation that would be misleading in config
