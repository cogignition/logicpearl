# Agent Guardrail Example

This is the first public LogicPearl guardrail benchmark artifact set.

It is intentionally simple, but it shows the full shape:
- observer plugin extracts structured attack features from messy input
- pearls enforce deterministic policy
- a final route pearl combines stage results
- a verify plugin emits an operator-facing route label

## Artifact Set

- `agent_guardrail.pipeline.json`
- `tool_authorization.pearl.ir.json`
- `instruction_boundary.pearl.ir.json`
- `data_exfiltration.pearl.ir.json`
- `route_status.pearl.ir.json`
- `plugins/observer/*`
- `plugins/route_audit/*`

## Stage Model

1. `observer`
   - emits normalized security features
2. `tool_authorization`
   - blocks unauthorized tool use and scope expansion
3. `instruction_boundary`
   - blocks prompt-injection and authority hijack patterns
4. `data_exfiltration`
   - blocks secrets and data-leakage requests
5. `route_status`
   - deterministic final gate over prior pearl results
6. `audit`
   - emits the operator-facing route string

## Example Runs

Attack case:

```bash
logicpearl pipeline run \
  benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json \
  benchmarks/guardrails/examples/agent_guardrail/input_attack.json \
  --json
```

Benign case:

```bash
logicpearl pipeline run \
  benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json \
  benchmarks/guardrails/examples/agent_guardrail/input_benign.json \
  --json
```

Trace the full execution:

```bash
logicpearl pipeline trace \
  benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json \
  benchmarks/guardrails/examples/agent_guardrail/input_attack.json \
  --json
```

Score a small benchmark slice:

```bash
logicpearl benchmark run \
  benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json \
  benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl \
  --json
```

Each JSONL row contains:
- `id`
- `category`
- `expected_route`
- `input`
