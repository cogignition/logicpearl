# WAF Benchmark

This folder defines the public LogicPearl benchmark shape for classic web-application-firewall work.

The intended benchmark stack is:

1. **CSIC HTTP 2010**
   - balanced request-level corpus with benign and anomalous HTTP requests
   - useful for exact allow/deny benchmarking

2. **OWASP ModSecurity 2025 production audit logs**
   - real blocked or flagged malicious HTTP traffic
   - useful for realism, automation probes, and restricted-resource attacks

The public story should stay honest:

- use real request corpora
- keep WAF semantics in plugins and adapters
- keep route families explicit and inspectable
- report both exact route quality and collapsed allow-vs-deny quality

## Dataset Staging

Set `LOGICPEARL_DATASETS` to the public dataset root you want the helper scripts to use.

Recommended layout:

```text
$LOGICPEARL_DATASETS/
  waf/
    csic-http-2010/
      normalTrafficTraining.txt
      anomalousTrafficTest.txt
    modsecurity-owasp-2025/
      24-Aug-2025/
        modsec_audit.anon.log
      25-Aug-2025/
        modsec_audit.anon.log
      ...
```

## Build Adapted Cases

```bash
python3 scripts/waf/build_waf_benchmark_cases.py \
  --output-dir /tmp/waf_benchmark
```

That emits:

- adapted source JSONL files
- merged full benchmark cases
- `dev.jsonl`
- `final_holdout.jsonl`

## Evaluate A Pipeline

Exact-route evaluation:

```bash
logicpearl benchmark run \
  examples/waf_edge/waf_edge.pipeline.json \
  /tmp/waf_benchmark/final_holdout.jsonl \
  --json
```

Collapsed allow-vs-deny evaluation:

```bash
logicpearl benchmark run \
  examples/waf_edge/waf_edge.pipeline.json \
  /tmp/waf_benchmark/final_holdout.jsonl \
  --collapse-non-allow-to-deny \
  --json
```

That second form is the easier apples-to-apples comparison lane when you want to compare LogicPearl against conventional WAFs that only expose block vs pass.
