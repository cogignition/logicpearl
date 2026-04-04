# Agent Guardrail Discovery Traces

These CSVs are the first normalized discovery inputs for the public agent guardrail example.

They are not the final benchmark datasets. They are the bridge between:
- raw prompt corpora
- observer feature extraction
- learned deterministic pearls

Each CSV follows the public `logicpearl build` shape:
- scalar feature columns
- `allowed` label column

Use them like this:

```bash
logicpearl build benchmarks/guardrails/examples/agent_guardrail/discovery/instruction_boundary_traces.csv --output-dir /tmp/instruction_boundary
logicpearl build benchmarks/guardrails/examples/agent_guardrail/discovery/tool_authorization_traces.csv --output-dir /tmp/tool_authorization
logicpearl build benchmarks/guardrails/examples/agent_guardrail/discovery/data_exfiltration_traces.csv --output-dir /tmp/data_exfiltration
logicpearl build benchmarks/guardrails/examples/agent_guardrail/discovery/route_status_traces.csv --output-dir /tmp/route_status
```

For the generalized multi-target path:

```bash
logicpearl discover \
  benchmarks/guardrails/examples/agent_guardrail/discovery/multi_target_demo.csv \
  --targets target_instruction_boundary,target_exfiltration,target_tool_use \
  --output-dir /tmp/guardrail_artifact_set
```

That emits:
- one pearl per target
- `artifact_set.json`
- `discover_report.json`

The broader plan is:
1. run a large raw corpus through the observer
2. emit normalized traces in this shape
3. learn pearls from those traces
4. score held-out and proof datasets with the resulting pipeline
