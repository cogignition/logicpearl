# Benchmarks

This file reports only benchmark numbers that can be reproduced from checked-in inputs or deterministic checked-in generators.

The larger public guardrail corpus workflow is still documented, but it is not presented as a scored headline until a frozen report with dataset hashes, bundle hashes, host info, and rerun count is committed.

For workflow details, use:
- [DATASETS.md](./DATASETS.md)
- [benchmarks/guardrails/README.md](./benchmarks/guardrails/README.md)
- [docs/advanced-guardrail-guide.md](./docs/advanced-guardrail-guide.md)

## Current Reproducible Scorecards

These are classification/parity scores only. They are not latency or throughput benchmarks.

| Lane | Label source | Cases | Reruns | Exact / parity | Attack catch | Benign pass | False positive | Command |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Checked-in agent guardrail smoke benchmark | native checked-in route labels | 5 | 3 | 100.0% | 100.0% | 100.0% | 0.0% | `logicpearl benchmark run ...` |
| Bounded OPA/Rego parity example | OPA policy decisions generated from checked-in policy | 1,000 | 3 | 99.9% runtime parity | n/a | n/a | n/a | `python3 benchmarks/opa_rego/run_benchmark.py` |

The first row uses source labels already present in `benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl`.

The second row generates 1,000 deterministic requests with seed `42`, evaluates the checked-in Rego policy with OPA, builds LogicPearl traces from those OPA decisions, then checks LogicPearl runtime parity against the OPA-generated labels.

## Label Provenance

Use these labels when reading any benchmark table:

- **Native / checked-in route labels**
  Labels are present in the checked-in benchmark cases or generated directly by the checked-in reference policy. These are the only labels used in the current headline table.
- **Observer-projected target labels**
  Labels are derived after a LogicPearl observer maps raw cases to normalized features and the trace projection config turns those features into target columns. These can be useful development metrics, but they are not independent native gold labels.

Previous large-corpus target-level metrics were observer-projected development metrics. They are intentionally not repeated here as headline numbers because the exact frozen dataset hashes, generated bundle, host info, and rerun count were not committed with that run.

## Compact Provenance

Verification run:

- LogicPearl CLI: `logicpearl 0.1.5 (305e20c)`
- benchmark-affecting git commit used by the CLI: `305e20c89e32f40d4615ec6a73dfcff8b6922602`
- solver/backend: default SMT path with Z3; `LOGICPEARL_SOLVER_BACKEND` was unset
- Z3: `4.15.4`
- OPA: `1.4.2`
- Rust: `rustc 1.94.1`, `cargo 1.94.1`
- host: `Darwin 23.5.0`, `arm64`
- rerun count: 3 for each reported scorecard row
- latency/throughput: not measured and not claimed

Checked-in guardrail smoke inputs:

| File | SHA-256 |
|---|---|
| `benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl` | `d96522fbd78b8ea4b4c70963c4e0df3874571d3524eb409cb0f1404494ab7a6b` |
| `benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json` | `94a549c6997f67496d186e3735af2e657a9e47d55eb6c05a40e5a62f09868292` |
| `benchmarks/guardrails/examples/agent_guardrail/instruction_boundary.pearl.ir.json` | `7557987038aaa753a9b36f9e76f3516b8f370ee351e2836b46eda9023b2154de` |
| `benchmarks/guardrails/examples/agent_guardrail/data_exfiltration.pearl.ir.json` | `0a654fa33d12cec3e31d20520239a699f4eb417d153a858a2bc8db82866d5c4d` |
| `benchmarks/guardrails/examples/agent_guardrail/tool_authorization.pearl.ir.json` | `593fdcdab511395e157d27661d30d2b80b33d9ff7b22f5dc81a8dcd915d75a3b` |
| `benchmarks/guardrails/examples/agent_guardrail/route_status.pearl.ir.json` | `275df1deb76f296e29c1f1095b908f0a438dd9fc6ff1db196c1676269f76a121` |

OPA/Rego parity inputs and generated hashes:

| File / artifact | SHA-256 |
|---|---|
| `benchmarks/opa_rego/policy.rego` | `8d9ba9f623fb738191792e18237ec759f5dbb6daf89469bf88aab70d9bd7f6f9` |
| `benchmarks/opa_rego/run_benchmark.py` | `336d67acd3b3064984627f0fabe9f47e670444149d98b6dc8a4319a4a860083c` |
| generated `decision_traces.csv` | `ea5d33b77b8d847997182b605a1a3ce49c9d8849215ad72311ac23c406b18b43` |
| generated LogicPearl artifact hash | `2ecaa6722dc7c7609945b5293a5259c9d23cf3fa4d84640ac5dbfa1345ca8a48` |

## Reproduce The Reported Rows

Use an installed `logicpearl` binary, or replace `logicpearl` with `cargo run -p logicpearl --`.

### Checked-In Guardrail Smoke Benchmark

```bash
logicpearl benchmark run \
  benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json \
  benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl \
  --json
```

Expected summary:

```json
{
  "total_cases": 5,
  "matched_cases": 5,
  "exact_match_rate": 1.0,
  "attack_cases": 3,
  "benign_cases": 2,
  "attack_catch_rate": 1.0,
  "benign_pass_rate": 1.0,
  "false_positive_rate": 0.0
}
```

### OPA/Rego Parity Example

Prerequisite: `opa` must be installed and available on `PATH`.

```bash
python3 benchmarks/opa_rego/run_benchmark.py
```

Expected summary:

```text
Requests: 1000
Training parity: 99.9%
Runtime parity: 99.9%
```

The script writes generated outputs under `benchmarks/opa_rego/output/`, including `summary.json`, `runtime_parity.json`, and the LogicPearl artifact bundle. `summary.json` records `rules_discovered: 5`.

## Larger Public Guardrail Corpus Protocol

The repo still supports the larger public guardrail workflow:

- `Salad-Data`
- `ALERT`
- `ChatGPT-Jailbreak-Prompts`
- `OpenAgentSafety S26`
- `MCPMark`
- `SafeArena`
- `Vigil`
- `NOETI ToxicQAFinal`
- `SQuAD 2.0`
- optional external checks such as `JailbreakBench`, `PromptShield`, and `rogue-security/prompt-injections-benchmark`

Those datasets are not vendored into this repository. Before any large-corpus score is promoted back into this file, the run must commit or publish a report containing:

- git commit SHA
- `logicpearl --version`
- solver/backend and Z3 version
- raw dataset file hashes
- split manifest hashes
- observer artifact hash
- trace projection config hash
- discovered artifact-set hash
- final bundle manifest hash
- host OS/arch and Rust version
- rerun count
- explicit label provenance for every metric: native/adapter-gold route label vs observer-projected target label

Recommended refresh commands:

```bash
cargo xtask guardrails-freeze

cargo xtask guardrails-build \
  --output-dir /tmp/guardrails_bundle

cargo xtask guardrails-eval \
  --bundle-dir /tmp/guardrails_bundle \
  --input-split final_holdout \
  --output-dir /tmp/guardrails_bundle/open_benchmarks_final_holdout
```

Do not use `benchmark learn` training parity as a headline number. Use held-out or final-holdout scoring only, and keep native-gold route metrics separate from observer-projected target metrics.

## What This Proves

The current reported rows prove only that:

- the checked-in guardrail example pipeline reproduces its checked-in route labels
- the OPA/Rego example can generate deterministic policy traces and build a LogicPearl artifact that matches the OPA-generated labels on 99.9% of the generated requests
- the reported numbers can be rerun from files in this repository

They do not prove:

- broad agent-security coverage
- latency or throughput wins
- performance on non-vendored public corpora
- performance on access-gated corpora such as `MT-AgentRisk`
- that observer-projected labels are independent native gold annotations
