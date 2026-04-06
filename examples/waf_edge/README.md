# WAF Edge Guardrail Demo

This example shows the public LogicPearl shape for an AI-aware edge or WAF deployment:

- raw HTTP request in
- a custom observer plugin extracts WAF and prompt-risk features
- grouped pearls evaluate independent denial reasons
- a final route pearl decides `allow`, `deny_*`, or `review_*`

The important boundary is intentional:

- generic predicate/runtime behavior stays in the LogicPearl engine
- WAF semantics live in custom plugins under [`plugins/`](./plugins)

## Why This Demo Exists

This is the cleanest public story for LogicPearl when the input is messy:

- teams can inspect the raw request boundary
- the extracted features are explicit
- each pearl carries one denial family
- the final route is deterministic and explainable

It is also a better deployment story than "just ship a binary".

What you version and share across a team is the artifact bundle:

- [`waf_edge.pipeline.json`](./waf_edge.pipeline.json)
- the pearl IR files
- plugin manifests and plugin code
- optional compiled outputs if you choose to generate native or WASM artifacts later

That means updates are handled the same way teams already handle config and policy bundles:

- review in git
- CI validation
- staged rollout
- explicit version changes

## Files

- [`waf_edge.pipeline.json`](./waf_edge.pipeline.json)
- [`request_abuse.pearl.ir.json`](./request_abuse.pearl.ir.json)
- [`instruction_boundary.pearl.ir.json`](./instruction_boundary.pearl.ir.json)
- [`data_exfiltration.pearl.ir.json`](./data_exfiltration.pearl.ir.json)
- [`route_status.pearl.ir.json`](./route_status.pearl.ir.json)
- [`plugins/observer/`](./plugins/observer)
- [`plugins/route_audit/`](./plugins/route_audit)
- [`dev_cases.jsonl`](./dev_cases.jsonl)
- [`demo/`](./demo)

## Run The Pipeline

Validate:

```bash
logicpearl pipeline validate examples/waf_edge/waf_edge.pipeline.json
```

Allow case:

```bash
logicpearl pipeline run \
  examples/waf_edge/waf_edge.pipeline.json \
  examples/waf_edge/input_allow.json \
  --json
```

Prompt-injection block:

```bash
logicpearl pipeline run \
  examples/waf_edge/waf_edge.pipeline.json \
  examples/waf_edge/input_block_prompt.json \
  --json
```

Admin export block:

```bash
logicpearl pipeline run \
  examples/waf_edge/waf_edge.pipeline.json \
  examples/waf_edge/input_block_export.json \
  --json
```

Suspicious review case:

```bash
logicpearl pipeline run \
  examples/waf_edge/waf_edge.pipeline.json \
  examples/waf_edge/input_review_probe.json \
  --json
```

Trace the full execution:

```bash
logicpearl pipeline trace \
  examples/waf_edge/waf_edge.pipeline.json \
  examples/waf_edge/input_block_prompt.json \
  --json
```

## Score The Demo Slice

```bash
logicpearl benchmark run \
  examples/waf_edge/waf_edge.pipeline.json \
  examples/waf_edge/dev_cases.jsonl \
  --json
```

The benchmark slice is intentionally tiny and human-readable. It is there to prove:

- the grouped pearl evaluates collectively
- the plugin boundary is explicit
- the example behavior is reproducible

## Open The Walkthrough Page

From the repo root:

```bash
python3 -m http.server 8000
```

Then open:

```text
http://localhost:8000/examples/waf_edge/demo/
```
