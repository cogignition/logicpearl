# Guardrail Benchmark Layout

This folder defines the public LogicPearl shape for guardrail benchmarking.

The goal is not to train on a benchmark and then brag about the benchmark. The goal is:
- build on broad public corpora
- tune on a held-out development slice
- prove generalization on an untouched proof set

Dataset source links, expected local staging paths, and the checked-in split/build/eval commands live in:
- [DATASETS.md](../../DATASETS.md)

## Dataset Roles

Development corpora:
- `Salad-Data` (`base_set`, `attack_enhanced_set`)
- `ALERT` (`ALERT`, `ALERT_Adv`)
- `ChatGPT-Jailbreak-Prompts`
- `OpenAgentSafety S26`
- `MCPMark`
- `SafeArena` (`safe`, `harm`)
- `Vigil`
- `NOETI ToxicQAFinal`
- `SQuAD 2.0`

Access-gated corpus outside the default public lane:
- `MT-AgentRisk`

## Directory Shape

```text
benchmarks/guardrails/
  README.md
  guardrail_benchmark.manifest.json
  datasets/
    train/
      prompt_injection/
      moderation/
      benign_negative/
    dev/
      prompt_injection/
      moderation/
      benign_negative/
  examples/
    agent_guardrail/
```

## Category Intent

- `prompt_injection/`: jailbreaks, indirect injections, instruction hijacks, tool-misuse prompts
- `moderation/`: harmful-content pressure that should still map to explicit route policy
- `benign_negative/`: false-positive control traffic that should mostly pass

## Post-Freeze External Checks

After the guardrail bundle is frozen, run separate external checks instead of recycling those corpora back into development.

Recommended open external checks:
- `JailbreakBench`
- `PromptShield`
- `rogue-security/prompt-injections-benchmark`

Non-proof preparation:
- [prep/README.md](./prep/README.md)
- [../profiles/README.md](../profiles/README.md)

## Recommended LogicPearl Metrics

- `attack_catch_rate`
- `false_positive_rate`
- `benign_pass_rate`
- `review_rate`
- `observer_extraction_success_rate`
- `deterministic_route_coverage`

## Feature Contract

Public normalized feature contract:
- [feature_contract.json](./feature_contract.json)

Discovery notes:
- [discovery/README.md](./discovery/README.md)

## Recommended Public Example

The first flagship benchmark should be an agent guardrail pipeline:

- observer extracts tool intent, source trust, and side effects
- pearls enforce authorization, injection boundary, and exfiltration policy
- final route is `allow`, `deny`, or `needs_human_review`

That shape is where LogicPearl is strongest.

See:
- [examples/agent_guardrail/README.md](./examples/agent_guardrail/README.md)
- [examples/agent_guardrail/discovery/README.md](./examples/agent_guardrail/discovery/README.md)

To score a dataset slice against a pipeline, use:

```bash
logicpearl benchmark run \
  benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json \
  benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl
```
