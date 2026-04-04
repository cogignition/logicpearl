# Guardrail Discovery

This folder defines how LogicPearl should learn guardrail pearls from benchmark data.

The important separation is:
- raw datasets such as Salad-Data or ALERT contain messy text
- pearls should be learned from normalized security features, not from raw text directly
- the observer is responsible for converting raw prompts into the feature contract in [feature_contract.json](../feature_contract.json)

## Discovery Shape

1. Raw benchmark prompt
2. Observer emits normalized features
3. Feature rows are written as decision traces
4. `logicpearl build` discovers deterministic pearls from those traces
5. Held-out `dev` checks false positives and route quality
6. `PINT` stays untouched until final proof

## Recommended Pearl Split

Learn separate pearls for:
- `instruction_boundary`
- `tool_authorization`
- `data_exfiltration`
- `route_status`

This is better than trying to learn one giant unsafe/safe pearl from raw prompts.

## Public Starter Traces

Starter trace CSVs live in:
- [../examples/agent_guardrail/discovery](../examples/agent_guardrail/discovery)

They are intentionally small and human-readable so you can see the shape before wiring in large corpora.

## Example

```bash
logicpearl build \
  benchmarks/guardrails/examples/agent_guardrail/discovery/instruction_boundary_traces.csv \
  --output-dir /tmp/guardrail_instruction_boundary
```

That is the public discovery loop we want to scale up onto Salad-Data, ALERT, SQuAD, and later PINT.

The generic builder direction behind this is documented in:
- [internal `logicpearl discover` design](/Users/missingno/Documents/LogicPearl/internal_docs/logicpearl/discover-cli-design.md)
