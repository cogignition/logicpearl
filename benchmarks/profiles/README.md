# Benchmark Adapter Profiles

LogicPearl benchmark adapters should move toward human-authored profile files plus a generic Rust adapter engine.

Current state:
- `squad.yaml` is loaded by the Rust benchmark crate through a hybrid parser + profile path
- `salad-base-set.yaml` and `salad-attack-enhanced-set.yaml` are loaded by the Rust benchmark crate
- `alert.yaml` is a real built-in adapter profile loaded by the Rust benchmark crate
- `chatgpt-jailbreak-prompts.yaml`, `vigil.yaml`, and `noeti-toxicqa.yaml` are built-in adapter profiles too
- `openagentsafety-s26.yaml` and `mcpmark.yaml` are built-in adapter profiles too
- `safearena-safe.yaml` and `safearena-harm.yaml` are built-in adapter profiles too
- `jailbreakbench.yaml`, `promptshield.yaml`, and `rogue-security-prompt-injections.yaml` are built-in adapter profiles too
- all current built-in benchmark adapters are now profile-backed

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
    - `yaml-object-rows`
    - `squad-questions`
- `prompt_fields`
  - ordered candidate field names to search for the raw prompt text
- `id_fields`
  - ordered candidate field names to search for a stable row id
- `category_fields`
  - ordered candidate field names to search for category metadata
- `label_fields`
  - ordered candidate field names to search for a boolean label when routes are derived from a label column
- `input_fields`
  - optional list of fields to copy from the parsed row into the emitted benchmark-case input object
  - each entry contains:
    - `source`
    - `target`
    - optional `mode`
      - `raw` (default)
      - `first-string` for list-valued fields where the first string should become the emitted value

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
- `default_category`
  - optional fallback category if none of the configured category fields are present

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

Boolean-labeled profile example:

```yaml
version: "1"
id: "promptshield"
description: "Adapt normalized PromptShield rows into allow or deny benchmark cases."
source_format: "Normalized PromptShield JSON array with prompt/label rows"
default_route: "mixed"

source:
  parser: "json-object-rows"
  prompt_fields: ["prompt", "text"]
  category_fields: ["category", "source"]
  label_fields: ["label"]

output:
  id_prefix: "promptshield"
  boolean_label_routes:
    true_route: "deny"
    false_route: "allow"
  static_input:
    document_instructions_present: false
```

Hybrid parser + profile example:

```yaml
version: "1"
id: "squad"
description: "Adapt SQuAD-style benign question rows into allow benchmark cases."
source_format: "SQuAD-style JSON with data[].paragraphs[].qas[]"
default_route: "allow"

source:
  parser: "squad-questions"
  prompt_fields: ["question"]
  id_fields: ["id"]
  category_fields: ["title"]
  input_fields:
    - source: "context"
      target: "context"

output:
  expected_route: "allow"
  id_prefix: "squad"
  default_category: "benign_negative"
  static_input:
    document_instructions_present: false
```

## Design Rule

Use profiles when the dataset can be described as:
- parser shape
- field lookup order
- route mapping
- static input enrichment

Use a hybrid parser + profile when the dataset needs:
- a small structural unpacking step
- but the emitted row-to-case mapping is still generic and worth expressing in YAML
