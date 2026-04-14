# WAF Edge Demo

This example shows a true web-application-firewall workflow in LogicPearl:

- raw HTTP request in
- a custom observer plugin extracts WAF features from real request fields and audit metadata
- grouped pearls evaluate independent denial families
- a final route pearl decides `allow`, `deny_*`, or `review_*`

The boundary is intentional:

- generic predicate/runtime behavior stays in the LogicPearl engine
- WAF semantics live in custom plugins under [`plugins/`](./plugins)

This example demonstrates:

- deterministic edge policy
- versioned artifact bundles
- human-review lanes
- team-friendly rollout without hiding logic in ad hoc code

## Why This Is Better Than "Just Ship A Binary"

The deployable unit is a versioned artifact bundle:

- [`waf_edge.pipeline.json`](./waf_edge.pipeline.json)
- pearl IR files
- plugin manifests
- plugin code
- optional compiled outputs if you choose to generate native or WASM artifacts later

So team usage looks like:

- review changes in git
- validate in CI
- promote the artifact bundle through environments
- update the route policy or plugin without pretending the whole system is one opaque executable

## Files

- [`waf_edge.pipeline.json`](./waf_edge.pipeline.json)
- [`injection_payload.pearl.ir.json`](./injection_payload.pearl.ir.json)
- [`sensitive_surface.pearl.ir.json`](./sensitive_surface.pearl.ir.json)
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

SQL injection block:

```bash
logicpearl pipeline run \
  examples/waf_edge/waf_edge.pipeline.json \
  examples/waf_edge/input_block_sqli.json \
  --json
```

Restricted-resource block:

```bash
logicpearl pipeline run \
  examples/waf_edge/waf_edge.pipeline.json \
  examples/waf_edge/input_block_sensitive.json \
  --json
```

Scanner review case:

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
  examples/waf_edge/input_block_sqli.json \
  --json
```

## Score The Demo Slice

```bash
logicpearl benchmark run \
  examples/waf_edge/waf_edge.pipeline.json \
  examples/waf_edge/dev_cases.jsonl \
  --json
```

The checked-in slice is intentionally small and readable. It is generated from the adapted public corpora and proves:

- the grouped pearl evaluates collectively
- route reasoning stays explicit
- the demo remains reproducible in CI

## Public Datasets To Scale This Demo

This checked-in slice is for clarity. To scale it with public corpora, use:

1. **ModSecurity 2025 production malicious HTTP traffic**
   - real blocked malicious requests from a production server
   - best public malicious WAF corpus for realism
   - Zenodo: <https://zenodo.org/records/17178461>
   - Paper: <https://www.mdpi.com/2306-5729/10/11/186>

2. **CSIC 2010 HTTP dataset**
   - classic labeled normal vs anomalous HTTP requests
   - old, but still useful for balanced reproducible WAF benchmarking
   - overview PDF mirror: <https://petescully.co.uk/wp-content/uploads/2018/04/http_dataset_csic_2010.pdf>

The intended scaling path is:

- use adapters or parsers to normalize those corpora into benchmark cases
- keep WAF meaning in plugins
- keep the grouped pearl and route logic inspectable

Build the larger benchmark cases with:

```bash
cargo xtask waf-cases \
  --output-dir /tmp/waf_benchmark
```

Then regenerate the checked-in readable slice with:

```bash
python3 scripts/waf/build_waf_demo_slice.py \
  --input /tmp/waf_benchmark/dev.jsonl
```

That second command is still an example-maintenance helper. The public corpus-adaptation surface is the Rust CLI.

## Open The Walkthrough Page

From the project root:

```bash
python3 -m http.server 8000
```

Then open:

```text
http://localhost:8000/examples/waf_edge/demo/
```
