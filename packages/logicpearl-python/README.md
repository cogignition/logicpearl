# `logicpearl`

Official Python bindings for `logicpearl-engine`.

Use this package when:
- Python code needs to execute a pearl artifact or pipeline directly
- you want a real bridge to the Rust execution surface
- you do not want to shell out to the CLI for every request

Do not use it as a reason to bake observers into pearls.
The intended split is still:
- observer/plugin: messy input interpretation
- pearl: deterministic policy artifact
- verify/response: operational interpretation

## Example

```python
from logicpearl import LogicPearlEngine

engine = LogicPearlEngine.from_artifact_path("/path/to/logicpearl-bundle")
result = engine.evaluate({
    "age": 34,
    "member": True,
    "country": "US",
})

print(result["decision_kind"])
print(result["allow"])
```

For pipeline execution, use `LogicPearlEngine.from_pipeline_path("/path/to/pipeline.json")`.
The installed Python package does not bundle the repository examples under `examples/`.

## Scope

This package exposes local execution through `logicpearl-engine`.

It is:
- a local evaluation library, not a service client
- not a reimplementation of runtime semantics in Python
- not a wrapper around `logicpearl` CLI subprocess calls

## API Shape

`LogicPearlEngine.from_path(path)` loads an artifact or pipeline once. Reuse the
engine object for request-time evaluation.

- `evaluate(input)` returns the runtime result payload directly. For gate and
  action artifacts, this matches `logicpearl run --json`.
- `evaluate_batch(inputs)` returns a list of runtime result payloads.
- `run(input)` returns the full engine envelope with the artifact kind included.
- `run_single(input)` and `run_batch(inputs)` expose the same envelope shape for
  callers that need dispatch metadata.

Inputs must be JSON-compatible Python values: dict, list, tuple, str, int,
float, bool, or None. Evaluation runs in Rust without spawning the CLI.
